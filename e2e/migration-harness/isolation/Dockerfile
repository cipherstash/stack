FROM node:22-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends strace socat python3 util-linux && rm -rf /var/lib/apt/lists/*
COPY supervise.py startup.mjs /harness/
ENTRYPOINT ["python3", "-u", "/harness/supervise.py"]
