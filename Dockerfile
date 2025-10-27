# Build image
FROM rust:1.90-bullseye AS build

COPY ./ /opt/src

RUN cd /opt/src \
  && cargo build --release

# Runtime image
FROM debian:bullseye

RUN apt-get update && \
  apt-get install -y ca-certificates

EXPOSE 3000

COPY --from=build /opt/src/target/release/sentry-mirror /opt/sentry-mirror
ENTRYPOINT ["/opt/sentry-mirror"]
