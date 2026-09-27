FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/opt/crucible \
    HOME=/work

RUN groupadd --gid 10001 crucible && \
    useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin crucible

COPY crucible/__init__.py /opt/crucible/crucible/__init__.py
COPY crucible/worker.py /opt/crucible/crucible/worker.py
COPY crucible/safe_commands.py /opt/crucible/crucible/safe_commands.py
COPY crucible/network_policy.py /opt/crucible/crucible/network_policy.py
COPY crucible/network_probe.py /opt/crucible/crucible/network_probe.py
COPY crucible/secret_scan.py /opt/crucible/crucible/secret_scan.py
COPY infra/extract-scenario.py /opt/crucible/extract-scenario.py
COPY infra/wall-probe.py /opt/crucible/wall-probe.py
COPY infra/gap-sink.py /opt/crucible/gap-sink.py

WORKDIR /work
USER 10001:10001
CMD ["python", "-m", "crucible.worker", "--action-file", "/work/scenario/action.json"]
