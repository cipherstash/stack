FROM node:22-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates strace socat python3 util-linux git && rm -rf /var/lib/apt/lists/*
# A bind mount's root can appear root-owned (Colima virtiofs on macOS) while the
# actor runs as the host uid; Git would then refuse /workspace as dubious ownership.
RUN git config --system --add safe.directory /workspace
COPY supervise.py startup.mjs /harness/
ENTRYPOINT ["python3", "-u", "/harness/supervise.py"]
