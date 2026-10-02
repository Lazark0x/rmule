FROM ubuntu:24.04
# `org.rmule.bench=1`: scopes the bench-image cleanup to
# rmule bench images — every `rmule/interop-amule-debug` tag inherits this
# from here — and never touches an unrelated image on the host. Single
# stage, so no dangling build-stage image to also label.
LABEL org.rmule.bench=1

ENV DEBIAN_FRONTEND=noninteractive
# `iptables` backs the AMULE_FORCE_LOW_ID toggle (ADR-0039 callback interop):
# the entrypoint drops inbound TCP so the server assigns this aMule a Low ID.
#
# AMULE_DEBUG (build arg, default 0): Ubuntu's packaged
# `amule-daemon` is release-mode — `Preferences.cpp` compiles the debug
# category load out and `Logger.h` makes `CLogger::IsEnabled` a literal
# `false`, both under `#ifdef __DEBUG__` — so no `AddDebugLogLineN` call, Kad
# or otherwise, can ever reach the logfile, whatever `amule.conf` says.
# `AMULE_DEBUG=1` instead rebuilds the EXACT SAME Debian source package
# (`apt-get source amule-daemon`, pinned by AMULE_SRC_VERSION) — the same
# pristine upstream 2.3.3 tree (`amule_2.3.3.orig.tar.xz`, the tree
# `amule-project/amule`'s `2.3.3` tag / commit
# `4e8f2b3c3f90cda23765730546b04c684a92e4f5` resolves to) plus Debian's own
# small build patches (default config paths, an xdg-open preview default, a
# version-check string, a wx3.2 header compat shim — no protocol-relevant
# code) — with `debian/rules`' own `confflags`, ONE flag flipped:
# `--disable-debug` -> `--enable-debug`. Same source, same packaging, the
# ONE bit the packager (not upstream) turns off. `acinclude.m4`:
# `MULE_ARG_ENABLE([debug], [yes], ...)` — enabled is upstream's own default —
# adds `-D__DEBUG__` plus `-g`; `Logger.h`/`Preferences.cpp` gate everything
# on that macro. This is a build from the SAME pin, per ADR-0045, not a
# different counterparty.
#
# A raw `git clone` of the tag was tried first and rejected: the checked-out
# tree ships no pre-generated `configure` (that is a release-tarball
# artifact), and re-running `autogen.sh` needs GNU Autoconf 2.69 specifically
# — `configure.ac` refuses 2.71, all Ubuntu 24.04 has. The packaged source
# already carries the 2.69-generated `configure`; CMake was tried after that
# and also rejected — `cmake/wx.cmake` unconditionally links a
# `wxWidgets::CORE` target that a GUI-less (`wx_NEED_GUI=OFF`) configuration
# never creates, a genuine upstream defect in the daemon-only CMake path, not
# something this recipe should route around with a source patch.
#
# This produces a distinct image only when the caller passes
# `--build-arg AMULE_DEBUG=1` and a separate `--amule-image` tag; the default
# build (AMULE_DEBUG=0, the apt package) is byte-for-byte unchanged.
ARG AMULE_DEBUG=0
ARG AMULE_SRC_VERSION=1:2.3.3-3build5
# `set -eux` runs FIRST, before any `if`, and every statement below is
# `;`-sequenced rather than `&&`-chained: a compound command that is the
# non-final element of a top-level `&&`/`||` list is exempt from `errexit`
# (POSIX/dash), which silently swallowed a real build failure here once
# already — every statement must be the shell's top-level unit for `-e` to
# apply.
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates iproute2 iptables; \
    if [ "$AMULE_DEBUG" = "1" ]; then \
        sed -i 's/^Types: deb$/Types: deb deb-src/' /etc/apt/sources.list.d/ubuntu.sources; \
        apt-get update; \
        apt-get build-dep -y amule-daemon; \
        apt-get install -y --no-install-recommends dpkg-dev; \
        mkdir -p /usr/src/amule-build; \
        cd /usr/src/amule-build; \
        apt-get source "amule-daemon=$AMULE_SRC_VERSION"; \
        cd amule-2.3.3; \
        ./configure --prefix=/usr --mandir=/usr/share/man --infodir=/usr/share/info \
            --disable-dependency-tracking --disable-ccache --enable-debug \
            --enable-amule-daemon --enable-amulecmd --enable-ed2k \
            --disable-amule-gui --disable-cas --disable-wxcas --disable-alc --disable-alcc \
            --disable-webserver --disable-embedded-crypto --enable-geoip --enable-upnp \
            --with-denoise-level=0 --with-boost; \
        make -j"$(nproc)"; \
        make install; \
        cd /; \
        rm -rf /usr/src/amule-build; \
    else \
        apt-get install -y --no-install-recommends amule-daemon amule-utils; \
    fi; \
    rm -rf /var/lib/apt/lists/*
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
