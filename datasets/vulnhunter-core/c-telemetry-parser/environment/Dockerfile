FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gdb \
    python3 \
    ca-certificates \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY app/ /app/

# Ensure no git history or hidden metadata leaks into the sandbox
RUN rm -rf /app/.git && make -C /app clean all
