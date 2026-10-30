# Stock aMule on a sped-up clock, for debug runs only. The binary is the one in
# rmule/interop-amule:local, untouched; see README.md.
FROM rmule/interop-amule:local
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends libfaketime >/dev/null
RUN mv /usr/bin/amuled /usr/bin/amuled.stock
COPY amuled-wrap /usr/bin/amuled
RUN chmod +x /usr/bin/amuled
