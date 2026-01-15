# Sentry Mirror

This application helps customers create data-continuity for ingest traffic
during a region relocation, or self-hosted to saas relocation. This application
will accept inbound ingest traffic on a configured DSN and forward events to one
or more outbound DSNs.

Events will be mirrored in a *best-effort* fashion. Delivery to outbound DSNs
will not be buffered, and events in each of the destination organizations may be
sampled differently.

## Configuration

sentry-mirror is primary configured through a YAML file. A simple example is:

```yaml
ip: 0.0.0.0
port: 3000
keys:
  - inbound: http://public-key@sentry-mirror.acme.org/1847101
    outbound:
      - https://public-key-red@o123.ingest.de.sentry.io/123456
      - https://public-key-blue@o456.ingest.us.sentry.io/654321
```

You can also enable selective forwarding to an outbound DSN based on envelope item categories:

```yaml
ip: 0.0.0.0
port: 3000
keys:
  - inbound: http://public-key@sentry-mirror.acme.org/1847101
    outbound:
      - https://public-key-red@o123.ingest.de.sentry.io/123456
      - dsn: https://public-key-blue@o456.ingest.us.sentry.io/654321
        categories: [error, transaction, profile]
```

When categories is a non-empty list only those categories will be forwarded. If
the category list is empty or undefined *all categories* will be forwarded.

## Request rewriting

When events are mirrored to outbound DSNs the following modifications may be made the received requests:

1. `sentry_key` component of `Authorization` and `X-Sentry-Auth` headers will be replaced.
2. `dsn` in envelope headers will be replaced.
3. `trace.public_key` in envelope headers will be replaced.
4. Content-Length, Content-Encoding, Host, X-Forwarded-For headers will be removed.

sentry-mirror will send outbound requests concurrently and respond with the response 
body of the first outbound key.

## Compatible Data Types

sentry-mirror has been tested to work with the following data categories:

- Errors
- Transactions/Tracing
- Replays
- Metrics
- Profiling
- Minidumps

## Unsupported Features

- The [Crash Report Modal](https://docs.sentry.io/product/user-feedback/#crash-report-modal) does not work with mirrored events. Getting the crash report modal fetches HTML from sentry's servers and that request cannot be mirrored.

## Deployment

[sentry mirror](sentry-mirror) is packaged as a Docker container that can be deployed and operated in customer environments. sentry-mirror needs to have SSL terminated externally and should be put behind a load-balancer or reverse proxy.

### Build

```shell
# Build the image
docker build -f Dockerfile -t sentry-mirror .
```

### Run

```
# Mount your configuration file into the container and run the application
docker run --name sentry-mirror -v ./config.yml:/opt/config.yml -p 3000:3000 sentry-mirror /opt/sentry-mirror -c /opt/config.yml
```

If you map the application to a port that isn't 3000 you'll also need to expose the port in the container.
sentry-mirror will need to be operated behind a load balancer as it cannot terminate SSL connections

