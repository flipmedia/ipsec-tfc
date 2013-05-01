## Parameters:
## pkg rate, size, buffer warn, buffer drop
##
## Benchmarks:
## VPN throughput, VPN transaction rate
##
## Trade-off algorithm logic:
## - use token bucket filter to manage mode switches
## - always keep some tokens for switching to max rate
## - over-estimate usage to provide good service
## - be conservative in reducing channel usage
##
## Test Procedures:
##
## Find max size/rate:
## - disable dummy, fragm/mplex/pad, max qlen
## -> Max VPN throughput: increase rate at max size, find max throughput
## -> Max Pkt rate:       increase rate at min size, find max rate
## -> validate with enabled mplex/frag/padding
##
## Queue sizes:
## - measure input/output rates directly at he source, not queue status
## - queue limits: at rate x, reduce qlen y til rate drop -> find y = f(x)
## - replace soft limit by RED?
## - use queue limit + margin as hard limit
##
## Min size/rate:
## -> Min size: tcp hdr + avg overhead
## -> Min rate = queue_len / reaction time => z = y/200ms
##
