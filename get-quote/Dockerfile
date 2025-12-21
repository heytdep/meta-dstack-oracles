# ---- Build Stage ----
# Uses Rust 1.86, consistent with the project's toolchain.
FROM rust:1.86 AS builder

WORKDIR /usr/src/app

COPY . .

RUN cargo build --release

# ---- Runtime Stage ----
# Use Debian Bookworm (slim variant) as the base, which includes OpenSSL 3.x.
FROM debian:bookworm-slim

# Install essential runtime dependencies:
# - libssl3: OpenSSL libraries.
# - ca-certificates: For HTTPS communication.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libssl3 \
        ca-certificates && \
    # Clean up apt cache to reduce image size.
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /usr/src/app/target/release/get-quote /usr/local/bin/get-quote


ENV RUST_LOG="debug"

CMD ["/usr/local/bin/get-quote"]
