# OPLIA control plane image (Red Hat UBI 9, Python 3.12, non-root, OpenShift-compatible).
# Pin the base image by digest in your build pipeline (e.g. Tekton) for reproducible builds.
FROM registry.access.redhat.com/ubi9/python-312 AS build
WORKDIR /opt/app-root/src
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir --upgrade pip \
 && pip wheel --no-cache-dir --wheel-dir /tmp/wheels ".[postgres]"

FROM registry.access.redhat.com/ubi9/python-312
WORKDIR /opt/app-root/src
COPY --from=build /tmp/wheels /tmp/wheels
RUN pip install --no-cache-dir --no-index /tmp/wheels/*.whl && rm -rf /tmp/wheels
COPY alembic.ini ./
COPY migrations ./migrations
# UBI images run as UID 1001 and support OpenShift's arbitrary UIDs (group 0).
USER 1001
ENV PYTHONUNBUFFERED=1 \
    OPLIA_ENVIRONMENT=prod
EXPOSE 8080
CMD ["uvicorn", "oplia_ctl.main:app", "--host", "0.0.0.0", "--port", "8080", "--proxy-headers", "--no-server-header"]
