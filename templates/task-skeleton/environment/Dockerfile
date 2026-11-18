FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    python3 \
    ca-certificates \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

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

# Strip git history so official CLI harnesses cannot inspect commit logs
RUN rm -rf /app/.git
