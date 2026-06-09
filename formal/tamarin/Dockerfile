FROM ubuntu:22.04

ARG TAMARIN_VERSION=1.12.0


ENV DEBIAN_FRONTEND=noninteractive

ENV LANG=en_US.UTF-8
ENV LC_ALL=en_US.UTF-8

ENV BOOTSTRAP_HASKELL_NONINTERACTIVE=1
ENV BOOTSTRAP_HASKELL_GHC_VERSION=9.6.7
ENV BOOTSTRAP_HASKELL_INSTALL_HLS=0
ENV BOOTSTRAP_HASKELL_INSTALL_STACK=1
ENV PATH=/root/.ghcup/bin:/root/.local/bin:/usr/local/bin:/usr/bin:/bin:$PATH

SHELL ["/bin/bash", "-lc"]

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    gnupg \
    git \
    make \
    gcc \
    g++ \
    libc6-dev \
    libgmp-dev \
    libtinfo6 \
    libncurses-dev \
    zlib1g-dev \
    xz-utils \
    tar \
    unzip \
    locales \
    graphviz \
    maude \
    && locale-gen en_US.UTF-8 \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get update \
    && apt-get install -y --no-install-recommends nodejs \
    && node --version \
    && npm --version \
    && rm -rf /var/lib/apt/lists/*

RUN curl --proto '=https' --tlsv1.2 -sSf https://get-ghcup.haskell.org | sh \
    && ghcup install ghc 9.6.7 --set \
    && ghcup install stack --set \
    && ghc --version \
    && stack --version

RUN mkdir -p /root/.stack \
    && printf "system-ghc: true\ninstall-ghc: false\n" > /root/.stack/config.yaml

RUN locale \
    && node --version \
    && npm --version \
    && ghc --version \
    && stack --version

RUN git clone --depth 1 --branch "${TAMARIN_VERSION}" \
        https://github.com/tamarin-prover/tamarin-prover.git /opt/tamarin-prover \
    && cd /opt/tamarin-prover \
    && make default \
    && tamarin-prover --version

WORKDIR /workspace

CMD ["tamarin-prover", "--help"]