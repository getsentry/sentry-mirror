# Build image
FROM ghcr.io/getsentry/image-mirror-library-rust:1.96.1-trixie AS build

COPY ./ /opt/src

RUN cd /opt/src \
  && cargo build --release

# Runtime image
FROM debian:trixie-slim

RUN groupadd sentrymirror --gid 1000 && useradd --gid sentrymirror --uid 1000 sentrymirror

RUN apt-get update && \
  apt-get install -y openssl ca-certificates libssl-dev curl xz-utils

EXPOSE 3000

COPY --from=build /opt/src/target/release/sentry-mirror /opt/sentry-mirror
COPY --from=build /opt/src/VERSION /opt/VERSION

WORKDIR /opt

ENTRYPOINT ["/opt/sentry-mirror"]
