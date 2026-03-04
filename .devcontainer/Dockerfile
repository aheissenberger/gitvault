FROM mcr.microsoft.com/devcontainers/base:bookworm

ARG USERNAME=vscode
ARG RUST_VERSION=stable

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        file \
        git \
        jq \
        libssl-dev \
        lld \
        make \
        openssh-client \
        pkg-config \
        unzip \
        xz-utils \
        zip \
    && rm -rf /var/lib/apt/lists/*

USER ${USERNAME}

ENV CARGO_HOME=/home/${USERNAME}/.cargo
ENV RUSTUP_HOME=/home/${USERNAME}/.rustup
ENV PATH=/home/${USERNAME}/.cargo/bin:${PATH}

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain ${RUST_VERSION} \
    && rustup component add clippy rustfmt \
    && rustup target add aarch64-apple-darwin x86_64-apple-darwin \
    && cargo install --locked rust-script