# OPLIA control plane image (Red Hat UBI 9, Python 3.12, non-root, OpenShift-compatible).
# Pin the base image by digest in your build pipeline (e.g. Tekton) for reproducible builds.
FROM registry.access.redhat.com/ubi9/python-312 AS build
WORKDIR /opt/app-root/src
COPY --chown=1001:0 pyproject.toml README.md ./
COPY --chown=1001:0 src ./src
# python-ldap (Active Directory driver) is a C extension without wheels: build it against OpenLDAP
USER 0
RUN dnf install -y --setopt=install_weak_deps=0 openldap-devel cyrus-sasl-devel && dnf clean all
USER 1001
RUN pip install --no-cache-dir --upgrade pip \
 && pip wheel --no-cache-dir --wheel-dir /tmp/wheels ".[postgres,gcp,ad,dr,warehouse]"

FROM registry.access.redhat.com/ubi9/python-312
WORKDIR /opt/app-root/src
# runtime libraries for python-ldap
USER 0
RUN dnf install -y --setopt=install_weak_deps=0 openldap cyrus-sasl-lib && dnf clean all
# Microsoft ODBC Driver 18 for SQL Server, used by pyodbc for the Synapse / Fabric Warehouse MERGE writer.
# Its licence (EULA) is Microsoft's and must be accepted explicitly by whoever builds the image:
#   docker build --build-arg ACCEPT_MSODBCSQL18_EULA=Y ...
# Without that the image is built without the driver (everything else works; the warehouse writer then fails
# with "Can't open lib 'ODBC Driver 18 for SQL Server'"). Repository and package per Microsoft's
# "Install the Microsoft ODBC driver for SQL Server (Linux)" and "sqlcmd and bcp on Linux" (RHEL 9) pages.
ARG ACCEPT_MSODBCSQL18_EULA=""
ARG MSODBCSQL18_VERSION=18.7.1.1-1
RUN if [ "$ACCEPT_MSODBCSQL18_EULA" = "Y" ]; then \
      curl -fsSL https://packages.microsoft.com/config/rhel/9/prod.repo -o /etc/yum.repos.d/mssql-release.repo \
      && ACCEPT_EULA=Y dnf install -y --setopt=install_weak_deps=0 "msodbcsql18-${MSODBCSQL18_VERSION}" \
      && dnf clean all \
      && odbcinst -q -d -n "ODBC Driver 18 for SQL Server"; \
    else \
      echo "Microsoft ODBC Driver 18 not installed (build with --build-arg ACCEPT_MSODBCSQL18_EULA=Y to accept its EULA)"; \
    fi
USER 1001
COPY --from=build --chown=1001:0 /tmp/wheels /tmp/wheels
RUN pip install --no-cache-dir --no-index /tmp/wheels/*.whl && rm -rf /tmp/wheels
COPY --chown=1001:0 alembic.ini ./
COPY --chown=1001:0 migrations ./migrations
# UBI images run as UID 1001 and support OpenShift's arbitrary UIDs (group 0).
USER 1001
ENV PYTHONUNBUFFERED=1 \
    OPLIA_ENVIRONMENT=prod
EXPOSE 8080
CMD ["uvicorn", "oplia_ctl.main:app", "--host", "0.0.0.0", "--port", "8080", "--proxy-headers", "--no-server-header"]
