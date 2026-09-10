# DNSTwist integration

DNSTwist is an optional deep permutation collector, not the whole monitoring system. It runs only against official domains in approved profiles and requires explicit `--network` plus a locally installed `dnstwist` binary. Its registered/resolving findings are normalized as brand findings, then unioned with the broader candidate set before scoring.

DNSTwist resolution is a discovery signal, not an abuse conclusion. Keep its fuzzer type and raw result as evidence. Use it alongside semantic brand-word candidates, CT/RDAP/DNS evidence, and internal review.
