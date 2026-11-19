FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    PATH="/root/.local/bin:${PATH}"

# Preinstall common harness runtime tools so agent_setup runs offline in <1s
RUN apt-get -o Acquire::Retries=5 -o Acquire::http::Timeout=30 update \
    && apt-get -o Acquire::Retries=5 -o Acquire::http::Timeout=30 install -y --no-install-recommends \
        ca-certificates \
        curl \
        git \
        procps \
        ripgrep \
    && rm -rf /var/lib/apt/lists/*

# Preinstall Node.js 22 LTS, OpenAI Codex CLI, and Claude Code CLI into the image
ARG NODE_VERSION=22.14.0
RUN arch="$(dpkg --print-architecture)" \
    && case "$arch" in amd64) node_arch=x64 ;; arm64) node_arch=arm64 ;; *) echo "Unsupported arch: $arch" >&2; exit 1 ;; esac \
    && curl -fsSL --connect-timeout 20 --speed-time 30 --speed-limit 1024 --retry 5 --retry-all-errors \
       "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-${node_arch}.tar.gz" -o /tmp/node.tar.gz \
    && tar -xzf /tmp/node.tar.gz --strip-components=1 -C /usr/local \
    && rm -f /tmp/node.tar.gz \
    && node --version && npm --version

RUN npm install -g --no-audit --no-fund @openai/codex@latest \
    && npm cache clean --force \
    && codex --version

RUN curl -fsSL --connect-timeout 20 --speed-time 30 --speed-limit 1024 --retry 5 --retry-all-errors \
       https://downloads.claude.ai/claude-code-releases/bootstrap.sh -o /tmp/claude-bootstrap.sh \
    && bash /tmp/claude-bootstrap.sh \
    && rm -f /tmp/claude-bootstrap.sh \
    && ln -sf /root/.local/bin/claude /usr/local/bin/claude \
    && claude --version

# Disable built-in web search/fetch tools across vendor CLI harnesses
RUN mkdir -p /etc/claude-code /etc/codex /etc/gemini-cli \
    && printf '%s\n' '{"permissions":{"deny":["WebSearch","WebFetch"]}}' > /etc/claude-code/managed-settings.json \
    && printf '%s\n' 'web_search = "disabled"' > /etc/codex/config.toml \
    && printf '%s\n' 'allowed_web_search_modes = ["disabled"]' > /etc/codex/requirements.toml \
    && printf '%s\n' '{"excludeTools":["google_web_search","web_fetch"]}' > /etc/gemini-cli/settings.json \
    && printf '%s\n' '{"excludeTools":["google_web_search","web_fetch"]}' > /etc/gemini-cli/system-defaults.json \
    && chmod 0444 /etc/claude-code/managed-settings.json /etc/codex/config.toml /etc/codex/requirements.toml /etc/gemini-cli/settings.json /etc/gemini-cli/system-defaults.json

WORKDIR /app
COPY app/ /app/

RUN rm -rf /app/.git
