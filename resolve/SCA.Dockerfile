FROM python:3.12-slim AS base

RUN apt-get update && apt-get install -y \
    curl \
    ca-certificates \
    git \
    jq \
    openjdk-17-jre-headless \
    && rm -rf /var/lib/apt/lists/*

RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \ # Trivy
    | sh -s -- -b /usr/local/bin

ENV DC_VERSION=10.0.4 # Dependency-Check (CLI)
RUN mkdir -p /opt && \
    curl -L "https://github.com/jeremylong/DependencyCheck/releases/download/v${DC_VERSION}/dependency-check-${DC_VERSION}-release.zip" \
    -o /tmp/dc.zip && \
    apt-get update && apt-get install -y unzip && \
    unzip /tmp/dc.zip -d /opt && \
    mv /opt/dependency-check /opt/dependency-check-${DC_VERSION} && \
    ln -s /opt/dependency-check-${DC_VERSION}/bin/dependency-check.sh /usr/local/bin/dependency-check && \
    rm -rf /var/lib/apt/lists/* /tmp/dc.zip

RUN curl -L "https://github.com/quay/clair/releases/latest/download/clairctl-linux-amd64" \ # Clairctl
    -o /usr/local/bin/clairctl || true && \
    chmod +x /usr/local/bin/clairctl || true

WORKDIR /workspace

ENV DEP_CHECK_DATA=/workspace/.dependency-check-data
RUN mkdir -p "${DEP_CHECK_DATA}"

COPY secgensbom/sca_entrypoint.sh /usr/local/bin/sca_entrypoint.sh # SCA
RUN chmod +x /usr/local/bin/sca_entrypoint.sh

ENTRYPOINT ["/usr/local/bin/sca_entrypoint.sh"]
