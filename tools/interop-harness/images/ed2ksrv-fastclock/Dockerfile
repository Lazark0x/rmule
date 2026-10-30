# The pinned ed2k-server on a sped-up clock, for debug runs only. The binary is
# the one in rmule/interop-ed2ksrv:local, untouched, and its pin labels carry
# over; see ../amule-fastclock/README.md.
FROM rmule/interop-ed2ksrv:local
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends libfaketime >/dev/null
RUN mv /usr/local/bin/ed2k-server /usr/local/bin/ed2k-server.stock
COPY ed2k-server-wrap /usr/local/bin/ed2k-server
RUN chmod +x /usr/local/bin/ed2k-server
