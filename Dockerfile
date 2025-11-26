FROM python:3.12-slim AS base
RUN apt-get update && apt-get install -y \
    curl \
    ca-certificates \
    git \
    jq \
    && rm -rf /var/lib/apt/lists/*

RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin # Trivy

RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \ # Node LTS + cdxgen через npx
    && apt-get update && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . /app

WORKDIR /app/script
RUN python -m pip install --upgrade pip && \
    if [ -f requirements.txt ]; then pip install -r requirements.txt; fi

RUN curl -L https://github.com/CycloneDX/cyclonedx-cli/releases/latest/download/cyclonedx-linux-x64 \ # CycloneDX CLI
    -o /usr/local/bin/cyclonedx && \
    chmod +x /usr/local/bin/cyclonedx

WORKDIR /app/secgensbom
RUN chmod +x *.sh

ENV REPO_ROOT=/app \
    PROJECT_DIR=/app/script \
    IMAGE_NAME=sbom-formatter:inside \
    OUTPUT_DIR=/app/secgensbom_out \
    SBOM_DIR=/app/sbom \
    REPORTS_DIR=/app/reports

WORKDIR /app
ENTRYPOINT ["/bin/bash"]