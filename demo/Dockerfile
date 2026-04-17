FROM ubuntu:24.04

RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        iproute2 \
        iputils-ping \
        dnsutils \
        curl \
        ffmpeg \
        ttyd \
        libnss3 \
        libatk1.0-0 \
        libatk-bridge2.0-0 \
        libcups2 \
        libdrm2 \
        libxkbcommon0 \
        libxcomposite1 \
        libxdamage1 \
        libxfixes3 \
        libxrandr2 \
        libgbm1 \
        libasound2t64 \
    && rm -rf /var/lib/apt/lists/*

# Install VHS for recording
RUN curl -L https://github.com/charmbracelet/vhs/releases/download/v0.11.0/vhs_0.11.0_Linux_x86_64.tar.gz \
    | tar -xz --strip-components=1 -C /usr/local/bin vhs_0.11.0_Linux_x86_64/vhs && chmod +x /usr/local/bin/vhs

# Real jip binary (pre-built release)
COPY target/release/jip /usr/local/bin/jip-real

# Fake output files and wrapper script
COPY demo/fake-output/ /demo/fake-output/
COPY demo/scripts/jip-wrapper /usr/local/bin/jip
RUN chmod +x /usr/local/bin/jip /usr/local/bin/jip-real

WORKDIR /root
CMD ["/bin/bash"]
