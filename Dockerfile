# Enlil — the source-available control and audit plane for AI agent actions.
#
#   docker build -t enlil .
#   docker run -p 8080:8080 -v enlil-data:/data enlil
#
# Then point your OpenAI-compatible client at http://localhost:8080 and open
# http://localhost:8080 in a browser to see what your agents actually did.

FROM rust:slim-bookworm AS builder
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /build

# Manifest first so dependency compilation caches independently of source edits.
COPY Cargo.toml Cargo.lock* ./
RUN mkdir -p src/bin \
    && echo "" > src/lib.rs \
    && echo "fn main() {}" > src/bin/enlil.rs \
    && cargo build --release 2>/dev/null || true

COPY src/ src/
RUN find src -name '*.rs' -exec touch {} + && cargo build --release --bin enlil

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates curl && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/enlil /usr/local/bin/enlil
RUN mkdir -p /data

ENV PORT=8080
ENV RUST_LOG=info
# Local trace/audit storage. Mount a volume here to persist across restarts.
ENV DATA_DIR=/data
VOLUME ["/data"]

EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s CMD curl -f http://localhost:8080/health || exit 1
CMD ["enlil"]
