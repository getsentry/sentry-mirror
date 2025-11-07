#!/bin/bash

if [ -n "$DD_PROFILING_ENABLED" ]; then
  exec /opt/ddprof /opt/sentry-mirror "$@"
else
  exec /opt/sentry-mirror "$@"
fi