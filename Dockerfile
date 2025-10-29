# Build image
FROM rust:1.90-bookworm AS build

COPY ./ /opt/src

RUN cd /opt/src \
  && cargo build --release

# Runtime image
FROM debian:bookworm-slim

RUN groupadd sentrymirror --gid 1000 && useradd --gid sentrymirror --uid 1000 taskbroker

RUN apt-get update && \
  apt-get install -y openssl ca-certificates libssl-dev

EXPOSE 3000

COPY --from=build /opt/src/target/release/sentry-mirror /opt/sentry-mirror
COPY --from=build /opt/src/VERSION /opt/VERSION

WORKDIR /opt

CMD ["/opt/sentry-mirror"]
