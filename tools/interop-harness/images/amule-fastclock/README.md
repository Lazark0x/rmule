# amule-fastclock

The stock aMule binary under libfaketime, so its hard-coded timers pass faster
while a flow is being debugged. A run on this image never fills a row: a row
counts only from a run on `rmule/interop-amule:local` at real speed.

    docker build -t rmule/interop-amule-fastclock:local tools/interop-harness/images/amule-fastclock
    peer-crossing --skip-build --amule-image rmule/interop-amule-fastclock:local \
        --amule-env AMULE_CLOCK_SCALE=10 --leg serve-reask --hold 2

`AMULE_CLOCK_SCALE` is unset or `1` for real speed. A flow that sleeps a timer
of aMule's own reads the scale from `amule_env`, as `peer-crossing` does.

Measured on stock 2.3.3: the connect timeout loop runs at exactly ×10 and ×20,
and keeps its 28 s in aMule's seconds. `serve-reask` took 3.2 minutes against
29.6 and moved 1,326 parts, but rmule's clock stays real, so the 3 s crossing
bound took the other branch: the grant landed on W's own link, not the dial.
Use it for legs that wait on a timer, not to judge a race.
