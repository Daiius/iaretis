FROM rust:1.85-bookworm AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
RUN cargo build --release

FROM debian:bookworm-slim
RUN useradd -r -s /bin/false iaretis
COPY --from=builder /app/target/release/iaretis /usr/local/bin/
USER iaretis
EXPOSE 53/udp 53/tcp
ENV LISTEN_ADDR=0.0.0.0:53
ENV FILTER_FILE=/etc/iaretis/blocklist.txt
CMD ["iaretis"]
