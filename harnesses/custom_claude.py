"""Customizable Claude Code Harbor adapter supporting custom binary names and preload steps."""

from __future__ import annotations

import os
import re
import shlex
import subprocess
import tarfile
import tempfile
from pathlib import Path
from typing import Any

try:
    from harbor.agents.installed.claude_code import ClaudeCode as _HarborClaudeCode
except ImportError:  # Allows importing/testing helper logic before `pip install harbor`
    class _HarborClaudeCode:  # type: ignore[no-redef]
        options_model = None

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass


_CUSTOM_KWARG_KEYS = ("binary_name", "preload", "skip_install")


def rewrite_claude_command(command: str, binary_name: str) -> str:
    """Rewrite Harbor's `claude <flags>` CLI invocation to use `binary_name`."""
    if not binary_name or binary_name == "claude":
        return command
    quoted_bin = shlex.quote(binary_name)
    pattern = re.compile(r"(^|[;&|]\s*|\bexec\s+)(?:[\w./-]+/)?claude(?=\s+-)", flags=re.MULTILINE)
    return pattern.sub(rf"\1{quoted_bin}", command)


def parse_preload_directive(step: str) -> tuple[str, tuple[str, ...]]:
    """Classify a preload string into ('upload', (src, dst)), ('host', (cmd,)), or ('container', (cmd,))."""
    stripped = step.strip()
    if not stripped:
        return ("noop", ())

    if stripped.startswith("host:"):
        return ("host", (stripped[len("host:") :].strip(),))

    tokens = shlex.split(stripped)
    if len(tokens) == 3 and tokens[0] in ("upload", "copy"):
        return ("upload", (tokens[1], tokens[2]))

    return ("container", (stripped,))


class _CommandRewriteEnvironment:
    """Proxy around Harbor BaseEnvironment rewriting `claude` invocations and injecting PATH."""

    def __init__(self, inner: Any, binary_name: str, extra_paths: list[str]) -> None:
        self._inner = inner
        self._binary_name = binary_name
        self._extra_paths = extra_paths

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    async def exec(self, command: str, *args: Any, **kwargs: Any) -> Any:
        rewritten = rewrite_claude_command(command, self._binary_name)
        if self._extra_paths:
            prefix = ":".join(shlex.quote(p) for p in self._extra_paths)
            rewritten = f"export PATH={prefix}:$PATH; {rewritten}"
        return await self._inner.exec(rewritten, *args, **kwargs)


def _build_options_model(base_cls: Any) -> Any:
    """If Harbor's ClaudeCode declares a Pydantic `options_model`, extend it with our fields."""
    base_opts = getattr(base_cls, "options_model", None)
    if base_opts is None:
        return None
    try:
        from pydantic import Field

        return type(
            "CustomClaudeCodeOptions",
            (base_opts,),
            {
                "__annotations__": {
                    "binary_name": str,
                    "preload": list[str] | str | None,
                    "skip_install": bool,
                },
                "binary_name": Field(default="claude", description="CLI binary name to invoke (e.g. claude-2.1.322)"),
                "preload": Field(
                    default=None,
                    description="Ordered preload directives ('upload <host_src> <container_dst>', 'host: <cmd>', or container shell cmd)",
                ),
                "skip_install": Field(
                    default=False,
                    description="Skip Harbor's online official claude installation when binary is provided via preload",
                ),
            },
        )
    except Exception:
        return base_opts


class CustomClaudeCode(_HarborClaudeCode):
    """Harbor ClaudeCode wrapper supporting custom binary names (e.g. `claude-2.1.322`) and `preload` hooks."""

    options_model = _build_options_model(_HarborClaudeCode)

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        extracted: dict[str, Any] = {}
        if self.options_model is None:
            for k in _CUSTOM_KWARG_KEYS:
                if k in kwargs:
                    extracted[k] = kwargs.pop(k)

        super().__init__(*args, **kwargs)

        opts = getattr(self, "options", None)
        self._binary_name: str = (
            extracted.get("binary_name")
            or getattr(opts, "binary_name", None)
            or kwargs.get("binary_name")
            or "claude"
        )
        raw_preload = (
            extracted.get("preload")
            if "preload" in extracted
            else (getattr(opts, "preload", None) if opts is not None else kwargs.get("preload"))
        )
        if isinstance(raw_preload, str):
            self._preload_steps: list[str] = [raw_preload]
        elif isinstance(raw_preload, list):
            self._preload_steps = [str(item) for item in raw_preload]
        else:
            self._preload_steps = []

        self._skip_install: bool = bool(
            extracted.get("skip_install")
            if "skip_install" in extracted
            else (getattr(opts, "skip_install", False) if opts is not None else kwargs.get("skip_install", False))
        )
        self._extra_paths: list[str] = [
            f"/root/.{self._binary_name}",
            f"/root/.{self._binary_name}/bin",
            "/usr/local/bin",
        ]

    async def _upload_host_path(self, environment: Any, raw_src: str, container_dst: str) -> None:
        host_src = Path(os.path.expanduser(os.path.expandvars(raw_src))).resolve()
        if not host_src.exists():
            raise FileNotFoundError(f"Preload source path does not exist on host: {host_src}")

        if host_src.is_file():
            parent = str(Path(container_dst).parent)
            await environment.exec(f"mkdir -p {shlex.quote(parent)}")
            await environment.upload_file(source_path=host_src, target_path=container_dst)
            return

        # Archive directory on host (preserving symlinks, dotfiles, and +x permissions) and extract in container
        with tempfile.NamedTemporaryFile(prefix="vh_preload_", suffix=".tar", delete=False) as tmp_f:
            tar_path = Path(tmp_f.name)

        try:
            with tarfile.open(tar_path, mode="w", dereference=False) as tf:
                for entry in host_src.iterdir():
                    tf.add(entry, arcname=entry.name, recursive=True)

            remote_tar = "/tmp/.vh_preload_bundle.tar"
            await environment.upload_file(source_path=tar_path, target_path=remote_tar)
            res = await environment.exec(
                f"mkdir -p {shlex.quote(container_dst)} "
                f"&& tar -xf {shlex.quote(remote_tar)} -C {shlex.quote(container_dst)} "
                f"&& rm -f {shlex.quote(remote_tar)}"
            )
            if getattr(res, "return_code", 0) != 0:
                raise RuntimeError(f"Failed extracting preload archive into {container_dst}: {getattr(res, 'stderr', '')}")
        finally:
            tar_path.unlink(missing_ok=True)

        if container_dst not in self._extra_paths:
            self._extra_paths.insert(0, container_dst)

    async def _run_preload(self, environment: Any) -> None:
        for step in self._preload_steps:
            kind, payload = parse_preload_directive(step)
            if kind == "noop":
                continue
            if kind == "host":
                subprocess.run(payload[0], shell=True, check=True)
            elif kind == "upload":
                await self._upload_host_path(environment, payload[0], payload[1])
            elif kind == "container":
                res = await environment.exec(payload[0])
                if getattr(res, "return_code", 0) != 0:
                    raise RuntimeError(
                        f"Container preload command failed ({payload[0]!r}): {getattr(res, 'stderr', '')}"
                    )

        # Ensure WebSearch/WebFetch lockdown also covers custom Claude wrappers (e.g. /etc/claude-2.1.322)
        if self._binary_name != "claude":
            cfg_dir = f"/etc/{re.sub(r'[^a-zA-Z0-9_-]', '', self._binary_name)}"
            await environment.exec(
                f"mkdir -p {shlex.quote(cfg_dir)} /installed-agent "
                f"&& printf '%s\\n' '{{\"permissions\":{{\"deny\":[\"WebSearch\",\"WebFetch\"]}}}}' "
                f"> {shlex.quote(cfg_dir)}/managed-settings.json "
                f"&& chmod 0444 {shlex.quote(cfg_dir)}/managed-settings.json"
            )

    async def setup(self, environment: Any) -> None:
        await self._run_preload(environment)
        if not self._skip_install:
            await super().setup(environment)
        else:
            await environment.exec("mkdir -p /installed-agent /logs/agent")

    def create_run_agent_commands(self, instruction: str) -> list[Any]:
        """Compatibility hook for Harbor versions using `create_run_agent_commands`."""
        cmds = super().create_run_agent_commands(instruction)  # type: ignore[misc]
        if self._binary_name == "claude":
            return cmds
        for item in cmds:
            if hasattr(item, "command") and isinstance(item.command, str):
                prefix = ":".join(shlex.quote(p) for p in self._extra_paths)
                item.command = f"export PATH={prefix}:$PATH; " + rewrite_claude_command(
                    item.command, self._binary_name
                )
        return cmds

    async def run(self, instruction: str, environment: Any, context: Any) -> None:
        wrapped_env = _CommandRewriteEnvironment(environment, self._binary_name, self._extra_paths)
        await super().run(instruction, wrapped_env, context)
