# ntok-web — all-in-one image for hosted deployments (Fly.io, Railway, a VM).
# Connect scans work unprivileged; raw -sS/ICMP techniques need the
# `privileged` feature plus NET_RAW — not built here (see README → Deploying).

FROM rust:slim AS build
# aws-lc-rs (rustls) needs cmake + a C compiler.
RUN apt-get update && apt-get install -y --no-install-recommends \
        cmake clang \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN cargo build --release -p ntok-web

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 ntok \
    && mkdir -p /data && chown ntok:ntok /data
COPY --from=build /src/target/release/ntok-web /usr/local/bin/ntok-web

# /data is the persistence volume: WORKDIR puts reports/ + ntok.db there and
# HOME puts config.json (AI settings) under /data/.config/ntok.
ENV HOST=0.0.0.0 PORT=8080 HOME=/data
WORKDIR /data
USER ntok
EXPOSE 8080
CMD ["ntok-web"]
