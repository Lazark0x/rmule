# Patched aMule daemon for PRIVATE Kad interop evidence capture only.
#
# Builds amuled from the Ubuntu amule source package with a single documented
# patch (disable-lan-kad-filter.patch) that lets a fully private, air-gapped Kad
# mesh form. The patch relaxes only a LAN-address deployment guard; no Kad
# protocol/wire logic is changed, so captured datagrams are genuine aMule output.
#
# This image must NEVER be pointed at the public Kad network.
#
# Build:
#   docker build -t rmule/interop-amule-kad-patched:local \
#     tools/interop-harness/images/amule-kad-patched
#
# It overlays the patched binaries onto the standard interop aMule image, so
# build that first:
#   docker build -t rmule/interop-amule:local tools/interop-harness/images/amule
#
# The `build` stage below is labeled `org.rmule.bench.stage=1`:
# under the legacy builder every stage commits as its own image and only the
# final one gets `-t`, so this one is dangling the instant the build
# succeeds — the label is what the harness's post-run `docker image prune`
# scopes to. The final stage carries `org.rmule.bench=1` by inheriting it
# from `rmule/interop-amule:local`, not by re-declaring it here.

FROM ubuntu:24.04 AS build
LABEL org.rmule.bench.stage=1
ENV DEBIAN_FRONTEND=noninteractive
# Enable deb-src, install the build toolchain and aMule's build dependencies.
RUN sed -i 's/Types: deb/Types: deb deb-src/' /etc/apt/sources.list.d/ubuntu.sources \
    && apt-get update \
    && apt-get install -y --no-install-recommends dpkg-dev \
    && apt-get build-dep -y amule
WORKDIR /build
# Fetch and unpack the amule source package (version is whatever noble ships).
RUN apt-get source amule \
    && dpkg-source --no-check -x amule_*.dsc amule-src
COPY disable-lan-kad-filter.patch /build/
# Return-filter relaxation so a private mesh's KADEMLIA2_RES is non-empty
# (ADR-0043). Ordering is untouched; see the patch header.
COPY relax-kad-routing-return-filter.patch /build/
# Apply the private-only patches, then build a daemon-only aMule (no GUI) to
# keep the build fast. amuled + amulecmd are the only binaries the harness uses.
RUN cd amule-src \
    && patch -p1 < /build/disable-lan-kad-filter.patch \
    && patch -p1 < /build/relax-kad-routing-return-filter.patch \
    && ./configure \
        --enable-amule-daemon --enable-amulecmd --enable-ed2k \
        --disable-monolithic --disable-amule-gui --disable-webserver \
        --disable-cas --disable-wxcas --disable-alc --disable-alcc \
        --disable-embedded-crypto --disable-geoip --enable-upnp \
        --disable-debug --with-boost --with-denoise-level=0 \
    && make -j"$(nproc)"

# Overlay the patched binaries onto the standard interop aMule image (which
# already carries the runtime libraries and the kad-node entrypoint).
FROM rmule/interop-amule:local
COPY --from=build /build/amule-src/src/amuled /usr/bin/amuled
COPY --from=build /build/amule-src/src/amulecmd /usr/bin/amulecmd
