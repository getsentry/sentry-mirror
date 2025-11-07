# Build image
FROM rust:1.90-bookworm AS build

COPY ./ /opt/src

RUN cd /opt/src \
  && cargo build --release

# Runtime image
FROM debian:bookworm-slim

RUN groupadd sentrymirror --gid 1000 && useradd --gid sentrymirror --uid 1000 taskbroker

RUN apt-get update && \
  apt-get install -y openssl ca-certificates libssl-dev curl xz-utils && \
  curl -Lo /tmp/ddprof-linux.tar.xz https://github.com/DataDog/ddprof/releases/latest/download/ddprof-amd64-linux.tar.xz && \
  cd /tmp && tar xvf /tmp/ddprof-linux.tar.xz && \
  mv /tmp/ddprof/bin/ddprof /opt/ddprof

EXPOSE 3000

COPY endpoint.sh /opt/endpoint.sh
COPY --from=build /opt/src/target/release/sentry-mirror /opt/sentry-mirror
COPY --from=build /opt/src/VERSION /opt/VERSION

WORKDIR /opt

ENTRYPOINT ["/opt/endpoint.sh"]
