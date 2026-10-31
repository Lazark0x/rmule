FROM ubuntu:24.04@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852
# `org.rmule.bench=1` scopes the bench-image cleanup to harness images
# Every harness final stage carries it.
LABEL org.rmule.bench=1

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends tcpdump ca-certificates \
    && rm -rf /var/lib/apt/lists/*
