# eNode — native Node.js eD2k/eMule server (the ADR-0040/0046 server-replacement candidate evaluated
# by a feasibility spike).
#
# eNode (github.com/petermrg/eNode, MIT) is an INDEPENDENT, third-party eD2k
# server. Under ADR-0045 only an independent counterparty's bytes count as
# evidence, so this recipe builds eNode's own unmodified sources — we never
# author or patch its protocol code. The source is cloned at a pinned commit at
# build time and is intentionally NOT vendored in this repository (same posture
# as the Lugdunum eserver image, which downloads its binary by pinned URL).
#
# eNode targets the 2013-era Node 0.10 runtime and a MySQL/MongoDB backing store
# (see README.md); the base image is therefore node:0.10 under amd64 emulation on
# ARM hosts, and a MySQL sidecar is required (this image self-initialises the
# schema on start). Dependencies are the four pure-JS modules eNode requires
# (no native compilation), installed from the npm registry.
FROM --platform=linux/amd64 node:0.10
# `org.rmule.bench=1` scopes the bench-image cleanup to harness images
# Every harness final stage carries it.
LABEL org.rmule.bench=1

# Pinned eNode revision (repo HEAD at spike time, 2013-03-30 "check for valid
# string in get extension"). A tag would be preferable but eNode publishes none.
ARG ENODE_REPO=https://github.com/petermrg/eNode
ARG ENODE_COMMIT=59b81f7

RUN mkdir -p /opt/enode
WORKDIR /opt/enode

# Clone eNode's unmodified sources at the pinned commit.
RUN git clone "${ENODE_REPO}" src \
    && cd src \
    && git checkout "${ENODE_COMMIT}" \
    && rm -rf .git

# eNode ships no package.json — install its documented dependency set explicitly,
# every version pinned so the build is reproducible (no floating "latest"). hexy is
# pinned to a 0.10-era release (newer hexy declares node>=14 and changed its export
# shape); colors is pinned to the era-appropriate 0.6.2 and MUST stay <=1.4.0 —
# colors 1.4.1+ carries the Jan-2022 author sabotage (an infinite loop on require).
# mysql and tinylogger are pinned to their 2013-era releases; all four resolve on npm 2.x.
RUN npm install --prefix /opt/enode/src \
      mysql@2.16.0 hexy@0.2.10 tinylogger@0.1.1 colors@0.6.2

COPY entrypoint.sh /opt/enode/entrypoint.sh
COPY init-schema.js /opt/enode/init-schema.js
RUN chmod +x /opt/enode/entrypoint.sh

ENTRYPOINT ["/opt/enode/entrypoint.sh"]
