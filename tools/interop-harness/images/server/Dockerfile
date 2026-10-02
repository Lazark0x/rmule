FROM --platform=linux/amd64 debian:bookworm-slim
# `org.rmule.bench=1` scopes the bench-image cleanup to harness images
# Every harness final stage carries it.
LABEL org.rmule.bench=1

ARG ESERVER_URL=https://lugdunum.shortypower.org/files/eserver-17.15.x86_64-linux.nptl.gz
ARG ESERVER_SHA256=5b9a6db55348537a9379c5bedd3aaf1c8fa59c2ddb532c2b4aa25b8df2c2419f

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl gzip \
    && rm -rf /var/lib/apt/lists/*
RUN curl --http1.1 -fsSL "${ESERVER_URL}" -o /tmp/eserver.gz \
    && echo "${ESERVER_SHA256}  /tmp/eserver.gz" | sha256sum -c - \
    && gunzip /tmp/eserver.gz \
    && install -m 0755 /tmp/eserver /usr/local/bin/eserver \
    && rm -f /tmp/eserver
# The eserver reads donkey.ini from its CWD (/). Without it the UDP port is left
# at -1 and the server intermittently drops client logins once >1 client connects.
COPY donkey.ini /donkey.ini
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
