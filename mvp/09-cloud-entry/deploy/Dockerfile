# Build from the repository root:
#   docker build -f mvp/09-cloud-entry/deploy/Dockerfile -t mcp-guard-gateway .
FROM python:3.13-slim

WORKDIR /app
# The only third-party package: the ASGI server for --server asgi (D6-28).
RUN pip install --no-cache-dir uvicorn==0.54.0
ARG MCP_GUARD_WITH_CLASSIFIER=0
RUN if [ "$MCP_GUARD_WITH_CLASSIFIER" = "1" ]; then \
      pip install --no-cache-dir transformers huggingface_hub onnxruntime; \
    fi
COPY src ./src
COPY mvp ./mvp
COPY configs ./configs

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HF_HOME=/data/hf-cache \
    PYTHONPATH=/app/src:/app/mvp/01-policy-engine-cleanup:/app/mvp/02-remote-gateway-mcp:/app/mvp/03-server-registration-config:/app/mvp/04-tools-list-relay:/app/mvp/05-indirect-injection-throttle:/app/mvp/06-http-gateway-server:/app/mvp/07-tools-call-upstream-relay:/app/mvp/08-decision-controls:/app/mvp/09-cloud-entry:/app/mvp/11-b-classifier

# /data/state is the gateway's private state folder (state_storage.py): owned by the
# gateway account with mode 0700 inside a parent nobody else can write.
RUN useradd --create-home --uid 10001 guard && mkdir -p /data/state && chown -R guard /data \
    && chmod 0755 /data && chmod 0700 /data/state
USER guard
VOLUME ["/data"]
EXPOSE 8080

ENTRYPOINT ["python", "-m", "http_gateway.server"]
