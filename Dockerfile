FROM python:3.11-slim

LABEL org.opencontainers.image.title="BugBounty-Toolkit"
LABEL org.opencontainers.image.description="Authorized security testing toolkit"
LABEL org.opencontainers.image.source="https://github.com/user/BugBounty-Toolkit"

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    wget \
    git \
    jq \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /toolkit

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy toolkit files
COPY . .

# Security: run as non-root user
RUN useradd -m -s /bin/bash toolkituser && \
    chown -R toolkituser:toolkituser /toolkit
USER toolkituser

ENTRYPOINT ["/bin/bash"]
