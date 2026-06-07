# syntax=docker/dockerfile:1.7

FROM --platform=$BUILDPLATFORM rust:1-bookworm AS build

ARG TARGETARCH
ARG BUILDARCH

WORKDIR /app

RUN set -eux; \
    cross_packages=""; \
    case "$TARGETARCH" in \
        amd64) \
            if [ "$BUILDARCH" != "amd64" ]; then \
                cross_packages="gcc-x86-64-linux-gnu libc6-dev-amd64-cross"; \
            fi; \
            rustup target add x86_64-unknown-linux-gnu; \
            ;; \
        arm64) \
            if [ "$BUILDARCH" != "arm64" ]; then \
                cross_packages="gcc-aarch64-linux-gnu libc6-dev-arm64-cross"; \
            fi; \
            rustup target add aarch64-unknown-linux-gnu; \
            ;; \
        *) \
            echo "unsupported TARGETARCH: $TARGETARCH"; \
            exit 1; \
            ;; \
    esac; \
    if [ -n "$cross_packages" ]; then \
        apt-get update; \
        apt-get install -y --no-install-recommends $cross_packages; \
        rm -rf /var/lib/apt/lists/*; \
    fi

COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN set -eux; \
    case "$TARGETARCH" in \
        amd64) \
            rust_target=x86_64-unknown-linux-gnu; \
            if [ "$BUILDARCH" != "amd64" ]; then \
                export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=x86_64-linux-gnu-gcc; \
            fi; \
            ;; \
        arm64) \
            rust_target=aarch64-unknown-linux-gnu; \
            if [ "$BUILDARCH" != "arm64" ]; then \
                export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc; \
            fi; \
            ;; \
        *) \
            echo "unsupported TARGETARCH: $TARGETARCH"; \
            exit 1; \
            ;; \
    esac; \
    cargo build --release --locked --target "$rust_target"; \
    mkdir -p /app/out; \
    cp "target/$rust_target/release/cloudflare-ddns-rfc2136" /app/out/cloudflare-ddns-rfc2136

FROM gcr.io/distroless/cc-debian12:nonroot

COPY --from=build /app/out/cloudflare-ddns-rfc2136 /usr/local/bin/cloudflare-ddns-rfc2136

USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/cloudflare-ddns-rfc2136"]
