"""Customizable Antigravity CLI Harbor adapter supporting local OAuth subscriptions and offline web-tool lockdown."""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import tarfile
import tempfile
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, Literal, override

from pydantic import Field

from harbor.agents.agent_auth_resolution import (
    ResolvedModelConnection,
    parse_model_name,
)
from harbor.agents.installed.antigravity_cli import (
    AntigravityCli,
    AntigravityCliOptions,
    _REASONING_EFFORT_CHOICES,
)
from harbor.agents.installed.base import with_prompt_template
from harbor.environments.base import BaseEnvironment
from harbor.models.agent.context import AgentContext

from harnesses.custom_claude import parse_preload_directive

_AuthMode = Literal["oauth", "gemini", "gateway", "adc"]
_DEFAULT_OAUTH_HOME = "~/.agy-eval"
_DEFAULT_LOCAL_BINARY = "~/.local/bin/agy"
_OAUTH_INFERRED_BASE_URL = "https://daily-cloudcode-pa.googleapis.com"
_OAUTH_TOKEN_REL_PATH = Path(".gemini/antigravity-cli/antigravity-oauth-token")
_OAUTH_OPTIONAL_REL_PATHS: tuple[Path, ...] = (
    Path(".config/antigravity/credential-user-scope"),
    Path(".gemini/antigravity-cli/cache/onboarding.json"),
    Path(".gemini/antigravity-cli/jetski_state.pbtxt"),
)
_EFFORT_SUFFIXES: tuple[str, ...] = ("-minimal", "-low", "-medium", "-high", "-xhigh", "-max")

# PreToolUse matcher verified on agy 1.5.13 to deterministically block web/browser tools
# even when running under --dangerously-skip-permissions.
_WEB_TOOL_HOOK_MATCHER = (
    "search_web|read_url_content|open_browser_url|browser_.*|read_browser_page|"
    "click_browser_pixel|execute_browser_javascript|capture_browser_.*|"
    "list_browser_pages|search_marketplace"
)
_WEB_TOOL_PERMISSIONS_DENY: tuple[str, ...] = (
    "read_url(*)",
    "execute_url(*)",
    "search_web(*)",
    "tool(search_web)",
    "tool(read_url_content)",
)


def resolve_oauth_home(
    kwargs: Mapping[str, Any] | None = None,
    env: Mapping[str, str] | None = None,
) -> Path:
    raw = (
        (kwargs.get("oauth_home") if kwargs else None)
        or (env.get("AGY_OAUTH_HOME") if env else None)
        or os.environ.get("AGY_OAUTH_HOME")
        or _DEFAULT_OAUTH_HOME
    )
    return Path(os.path.expanduser(os.path.expandvars(str(raw)))).resolve()


def resolve_oauth_token_file(
    kwargs: Mapping[str, Any] | None = None,
    env: Mapping[str, str] | None = None,
) -> Path:
    raw_token_path = (
        (kwargs.get("oauth_token_path") if kwargs else None)
        or (env.get("AGY_OAUTH_TOKEN_PATH") if env else None)
        or os.environ.get("AGY_OAUTH_TOKEN_PATH")
    )
    if raw_token_path:
        return Path(os.path.expanduser(os.path.expandvars(str(raw_token_path)))).resolve()
    return resolve_oauth_home(kwargs, env) / _OAUTH_TOKEN_REL_PATH


def _resolve_auth_mode(
    kwargs: Mapping[str, Any] | None = None,
    env: Mapping[str, str] | None = None,
) -> _AuthMode:
    explicit = kwargs.get("auth_mode") if kwargs else None
    if explicit in ("oauth", "gemini", "gateway", "adc"):
        return explicit
    env_mode = (env.get("AGY_AUTH_MODE") if env else None) or os.environ.get("AGY_AUTH_MODE")
    if env_mode in ("oauth", "gemini", "gateway", "adc"):
        return env_mode  # type: ignore[return-value]
    return "oauth"


def _strip_provider_prefix(model_name: str, skip_model_parsing: bool = False) -> str:
    if skip_model_parsing or "/" not in model_name:
        return model_name
    _, model = model_name.split("/", 1)
    return model


def _model_has_effort_suffix(model: str) -> bool:
    lowered = model.lower()
    return any(lowered.endswith(suffix) for suffix in _EFFORT_SUFFIXES)


def build_web_lockdown_hooks_payload() -> dict[str, Any]:
    return {
        "vulnhunter-no-web": {
            "PreToolUse": [
                {
                    "matcher": _WEB_TOOL_HOOK_MATCHER,
                    "hooks": [
                        {
                            "type": "command",
                            "command": (
                                'printf \'{"decision":"deny","reason":'
                                '"Web and browser tools are disabled in offline benchmark mode."}\''
                            ),
                        }
                    ],
                }
            ]
        }
    }


class CustomAntigravityCliOptions(AntigravityCliOptions):
    auth_mode: _AuthMode = Field(
        default="oauth",
        description="Authentication mode: 'oauth' (local subscription token), 'gemini', 'gateway', or 'adc'.",
    )
    oauth_home: str | None = Field(
        default=None,
        description="Host profile directory created via `./scripts/agy_oauth_login.sh` (default: ~/.agy-eval).",
    )
    oauth_token_path: str | None = Field(
        default=None,
        description="Optional explicit host path to an `antigravity-oauth-token` file.",
    )
    preload: list[str] | str | None = Field(
        default=None,
        description="Ordered preload directives ('upload <host_src> <container_dst>', 'host: <cmd>', or container cmd).",
    )
    disable_web_search: bool = Field(
        default=True,
        description="Disable built-in web search/fetch and browser tools via PreToolUse hooks and settings.json.",
    )


class CustomAntigravityCli(AntigravityCli):
    """Harbor Antigravity CLI adapter supporting local OAuth subscriptions and offline web-tool lockdown."""

    capabilities = AntigravityCli.capabilities.model_copy(
        update={"native_web_tools": True}
    )
    options_model = CustomAntigravityCliOptions
    options: CustomAntigravityCliOptions

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self._auth_mode: _AuthMode = _resolve_auth_mode(kwargs)
        super().__init__(*args, **kwargs)
        self._auth_mode = self.options.auth_mode

        raw_preload = self.options.preload
        if isinstance(raw_preload, str):
            self._preload_steps: list[str] = [raw_preload]
        elif isinstance(raw_preload, list):
            self._preload_steps = [str(item) for item in raw_preload]
        else:
            self._preload_steps = []

        if self._auth_mode == "oauth":
            # Prevent host/trial GEMINI_API_KEY or base URLs from leaking into OAuth subscription runs.
            for key in (
                "GEMINI_API_KEY",
                "GOOGLE_API_KEY",
                "GOOGLE_GEMINI_BASE_URL",
                "AGY_LLM_GATEWAY_URL",
                "AGY_LLM_GATEWAY_API_KEY",
                "AGY_ADC_AUTH",
            ):
                self._extra_env.pop(key, None)

    @classmethod
    @override
    def resolve_model_connection_config(
        cls,
        model_name: str | None,
        resolve_env: Callable[..., tuple[str, str] | None],
        **connection_kwargs: Any,
    ) -> ResolvedModelConnection:
        kwargs = connection_kwargs.get("kwargs") or {}
        resolved_mode = resolve_env("AGY_AUTH_MODE")
        env_map = {"AGY_AUTH_MODE": resolved_mode[1]} if resolved_mode and resolved_mode[1] else {}
        auth_mode = _resolve_auth_mode(kwargs, env_map)
        if auth_mode == "oauth":
            if any(
                connection_kwargs.get(name) is not None
                for name in ("base_url", "model_api_key_name", "model_api_format")
            ):
                raise ValueError(
                    "Antigravity OAuth subscription mode does not accept base_url / model_api_key_name / "
                    "model_api_format overrides; set auth_mode='gemini' or auth_mode='gateway' instead."
                )
            skip_parsing = bool(connection_kwargs.get("skip_model_parsing", False))
            model_id: str | None = None
            if model_name:
                _, parsed_model = parse_model_name(model_name, skip_model_parsing=skip_parsing)
                model_id = parsed_model or _strip_provider_prefix(model_name, skip_parsing)
            return ResolvedModelConnection(
                provider="antigravity-oauth",
                model_id=model_id,
                inferred_base_url=_OAUTH_INFERRED_BASE_URL,
                can_configure_base_url=False,
            )
        return super().resolve_model_connection_config(model_name, resolve_env, **connection_kwargs)

    @classmethod
    @override
    def check_model_credentials(
        cls,
        connection: ResolvedModelConnection,
        *,
        kwargs: dict[str, Any],
        env: Mapping[str, str],
        explicit_env: Mapping[str, str] | None = None,
    ) -> None:
        auth_mode = _resolve_auth_mode(kwargs, env)
        if auth_mode != "oauth":
            super().check_model_credentials(
                connection, kwargs=kwargs, env=env, explicit_env=explicit_env
            )
            return

        token_file = resolve_oauth_token_file(kwargs, env)
        if not token_file.is_file():
            oauth_home = resolve_oauth_home(kwargs, env)
            raise ValueError(
                f"Antigravity OAuth token file not found at {token_file}.\n"
                "To use your local Antigravity subscription inside Docker containers without a host keyring, "
                "run the one-time login helper on the host first:\n"
                f"  AGY_OAUTH_HOME={shlex.quote(str(oauth_home))} ./scripts/agy_oauth_login.sh"
            )

    @staticmethod
    @override
    def _validate_reasoning_effort(
        reasoning_effort: Any,
        model_name: str | None,
        *,
        gateway: bool = False,
    ) -> None:
        # In OAuth subscription mode, non-flash models (e.g. gemini-4-neon, gemini-4-carbon,
        # claude-opus-5-5) support low/medium/high/xhigh/max.
        if reasoning_effort is not None and reasoning_effort not in _REASONING_EFFORT_CHOICES:
            raise ValueError(
                f"Invalid value for 'reasoning_effort': '{reasoning_effort}'. "
                f"Valid values: {', '.join(sorted(_REASONING_EFFORT_CHOICES))}"
            )

    @property
    @override
    def extra_env(self) -> dict[str, str]:
        env = super().extra_env
        env["AGY_CLI_DISABLE_AUTO_UPDATE"] = "true"
        if self._auth_mode == "oauth":
            env["DBUS_SESSION_BUS_ADDRESS"] = "unix:path=/nonexistent"
        return env

    async def _upload_host_path(
        self, environment: BaseEnvironment, raw_src: str, container_dst: str
    ) -> None:
        host_src = Path(os.path.expanduser(os.path.expandvars(raw_src))).resolve()
        if not host_src.exists():
            raise FileNotFoundError(f"Preload source path does not exist on host: {host_src}")

        if host_src.is_file():
            parent = str(Path(container_dst).parent)
            await self.exec_as_root(environment, command=f"mkdir -p {shlex.quote(parent)}")
            await environment.upload_file(source_path=host_src, target_path=container_dst)
            return

        with tempfile.NamedTemporaryFile(prefix="vh_agy_preload_", suffix=".tar", delete=False) as tmp_f:
            tar_path = Path(tmp_f.name)
        try:
            with tarfile.open(tar_path, mode="w", dereference=False) as tf:
                for entry in host_src.iterdir():
                    tf.add(entry, arcname=entry.name, recursive=True)
            remote_tar = "/tmp/.vh_agy_preload.tar"
            await environment.upload_file(source_path=tar_path, target_path=remote_tar)
            await self.exec_as_root(
                environment,
                command=(
                    f"mkdir -p {shlex.quote(container_dst)} "
                    f"&& tar -xf {shlex.quote(remote_tar)} -C {shlex.quote(container_dst)} "
                    f"&& rm -f {shlex.quote(remote_tar)}"
                ),
            )
        finally:
            tar_path.unlink(missing_ok=True)

    async def _install_agent_file(
        self,
        environment: BaseEnvironment,
        host_src: Path,
        rel_target: Path,
        mode: str = "600",
    ) -> None:
        tmp_path = f"/tmp/.vh_agy_{rel_target.name}"
        await environment.upload_file(source_path=host_src, target_path=tmp_path)
        uid_res = await self.exec_as_agent(environment, command="id -u")
        agent_uid = (uid_res.stdout or "").strip()
        if agent_uid.isdigit():
            await self.exec_as_root(
                environment,
                command=(
                    f"chown {agent_uid} {shlex.quote(tmp_path)} && "
                    f"chmod 600 {shlex.quote(tmp_path)}"
                ),
            )
        else:
            await self.exec_as_root(
                environment, command=f"chmod 600 {shlex.quote(tmp_path)}"
            )
        await self.exec_as_agent(
            environment,
            command=(
                f'install -D -m {shlex.quote(mode)} {shlex.quote(tmp_path)} '
                f'"$HOME/{rel_target.as_posix()}" && rm -f {shlex.quote(tmp_path)}'
            ),
        )

    async def _run_preload(self, environment: BaseEnvironment) -> None:
        for step in self._preload_steps:
            kind, payload = parse_preload_directive(step)
            if kind == "noop":
                continue
            if kind == "host":
                subprocess.run(payload[0], shell=True, check=True)
            elif kind == "upload":
                await self._upload_host_path(environment, payload[0], payload[1])
            elif kind == "container":
                await self.exec_as_root(environment, command=payload[0])

    async def _install_web_lockdown_hooks(self, environment: BaseEnvironment) -> None:
        if not self.options.disable_web_search:
            return
        payload = json.dumps(build_web_lockdown_hooks_payload(), indent=2) + "\n"
        escaped = shlex.quote(payload)
        await self.exec_as_agent(
            environment,
            command=(
                "mkdir -p ~/.gemini/antigravity-cli ~/.gemini/config && "
                "rm -f ~/.gemini/antigravity-cli/hooks.json ~/.gemini/config/hooks.json && "
                f"printf %s {escaped} > ~/.gemini/antigravity-cli/hooks.json && "
                f"printf %s {escaped} > ~/.gemini/config/hooks.json && "
                "chmod 0444 ~/.gemini/antigravity-cli/hooks.json ~/.gemini/config/hooks.json"
            ),
        )

    @override
    async def _refresh_web_tool_config(self, environment: BaseEnvironment) -> None:
        await self._install_web_lockdown_hooks(environment)

    @override
    async def install(self, environment: BaseEnvironment) -> None:
        if not self.options.binary_path:
            default_bin = Path(os.path.expanduser(_DEFAULT_LOCAL_BINARY))
            if default_bin.is_file():
                self.options = self.options.model_copy(
                    update={"binary_path": str(default_bin)}
                )
        await super().install(environment)

    @override
    async def configure(self, environment: BaseEnvironment) -> None:
        await super().configure(environment)
        await self._run_preload(environment)

        if self._auth_mode == "oauth":
            token_file = resolve_oauth_token_file(
                {
                    "oauth_home": self.options.oauth_home,
                    "oauth_token_path": self.options.oauth_token_path,
                },
                self._extra_env,
            )
            if not token_file.is_file():
                raise FileNotFoundError(
                    f"Antigravity OAuth token file not found on host: {token_file}. "
                    "Run `./scripts/agy_oauth_login.sh` first."
                )
            await self._install_agent_file(
                environment, token_file, _OAUTH_TOKEN_REL_PATH, mode="600"
            )

            oauth_home = resolve_oauth_home(
                {"oauth_home": self.options.oauth_home}, self._extra_env
            )
            for rel_path in _OAUTH_OPTIONAL_REL_PATHS:
                candidate = oauth_home / rel_path
                if candidate.is_file():
                    await self._install_agent_file(
                        environment, candidate, rel_path, mode="600"
                    )

        await self._install_web_lockdown_hooks(environment)

    @override
    def _build_settings_config(
        self, model: str | None = None, register_model: bool = True
    ) -> dict[str, Any]:
        if self._auth_mode == "oauth":
            config = super()._build_settings_config(model=model, register_model=False)
            config.pop("modelProvider", None)
            config.pop("customModelsConfig", None)
        else:
            config = super()._build_settings_config(
                model=model, register_model=register_model
            )

        if self.options.disable_web_search:
            perms = dict(config.get("permissions") or {})
            deny = list(perms.get("deny") or [])
            for rule in _WEB_TOOL_PERMISSIONS_DENY:
                if rule not in deny:
                    deny.append(rule)
            perms["deny"] = deny
            config["permissions"] = perms

        return config

    @with_prompt_template
    @override
    async def run(
        self,
        instruction: str,
        environment: BaseEnvironment,
        context: AgentContext,
    ) -> None:
        if self._auth_mode != "oauth":
            await self._install_web_lockdown_hooks(environment)
            await super().run(instruction, environment, context)
            return

        if not self.model_name:
            raise ValueError("Model name is required")

        model = _strip_provider_prefix(self.model_name, self.skip_model_parsing)
        escaped_instruction = shlex.quote(instruction)

        env: dict[str, str] = {
            "GEMINI_CLI_TRUST_WORKSPACE": "true",
            "AGY_CLI_DISABLE_AUTO_UPDATE": "true",
            "DBUS_SESSION_BUS_ADDRESS": "unix:path=/nonexistent",
        }
        env.update(self._forwarded_cli_env())

        skills_command = self._build_register_skills_command()
        if skills_command:
            await self.exec_as_agent(environment, command=skills_command)

        await self.exec_as_agent(
            environment,
            command=self._build_settings_command(
                model, register_model=False, activate_mcp=True
            ),
        )
        await self._install_web_lockdown_hooks(environment)

        cli_flags = self.build_cli_flags()
        extra_flags = (cli_flags + " ") if cli_flags else ""
        model_flag = f"--model {shlex.quote(model)} " if model else ""
        effort_flag = (
            f"--effort {shlex.quote(self.options.reasoning_effort)} "
            if self.options.reasoning_effort and not _model_has_effort_suffix(model)
            else ""
        )

        marker_created = False
        try:
            await self.exec_as_agent(environment, command=f"touch {self._RUN_MARKER}")
            marker_created = True
        except Exception:
            self.logger.debug("run marker creation failed; collecting unscoped")

        try:
            await self.exec_as_agent(
                environment,
                command=(
                    f"$HOME/.local/bin/agy --dangerously-skip-permissions "
                    f"--print-timeout {self._PRINT_TIMEOUT} "
                    f"--output-format stream-json "
                    f'--add-dir "$PWD" '
                    f"{model_flag}{effort_flag}{extra_flags}--prompt={escaped_instruction} "
                    f"2>/logs/agent/{self._STDERR_LOG_FILENAME} </dev/null "
                    f"| stdbuf -oL tee /logs/agent/{self._STREAM_LOG_FILENAME}; "
                    f"rc=$?; if [ $rc -ne 0 ]; then "
                    f"tail -c {self._STDERR_REPLAY_BYTES} "
                    f"/logs/agent/{self._STDERR_LOG_FILENAME} >&2; fi; "
                    f"exit $rc"
                ),
                env=env,
            )
        finally:
            try:
                await self.exec_as_agent(
                    environment,
                    command=self._build_collect_trajectory_command(
                        scoped=marker_created
                    ),
                )
            except Exception:
                pass
