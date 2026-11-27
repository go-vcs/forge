# Benchmarks

`internal/githttp` `BenchmarkClone` clones one repository with the real git
client (protocol v2) through this server and through `git http-backend` (CGI,
via `net/http/cgi`), both over plain HTTP on loopback. Each iteration does one
clone through each, the order alternating, and reports both times and their
ratio (`forge/git`, below 1 means forge is faster).

```
FORGE_BENCH_REPO=<clone> gotest -run '^$' -bench BenchmarkClone -benchmem -benchtime 20x -count 6 ./internal/githttp/
```

`forge-B/op` and `forge-allocs/op` are everything the process allocated during
a forge clone: the handler plus the Go side of the harness (starting and reaping
the git client). The plain `B/op` and `allocs/op` columns cover both servers'
iterations and are not comparable between them. The git client and `git
http-backend` run as child processes and are not counted.

## Input

`go-fleettools/fleettools` repacked: 5312 objects in 2 packs, 16.9 MB, no loose
object. A different repository, or the same one before a repack, is another
input and its numbers do not compare. Apple M4 Max, Go 1.27.4.

## 2026-11-27, forge main fedd0ed (before)

Taken by the coordinator, load 1-min 5.4-6.6 / 5-min 4.1-4.5. Not interleaved:
`forge` ran its iterations, then `git-http-backend` ran its own, so a drift in
machine load between the two halves falls on one side only.

| | ms/op (6 runs) | B/op | allocs/op |
|---|---|---|---|
| forge | 287.7, 291.3, 283.2, 334.5, 299.3, 285.7 | 11.42-11.45 MB | 5433-5438 |
| git http-backend | 332.1, 345.3, 353.5, 344.8, 478.0, 357.0 | not comparable | not comparable |

Allocation profile (`-memprofile`, `-memprofilerate 1`): 86 % of the bytes came
from one site, `gitproto/pktline.(*Writer).Sideband`, which allocated a fresh
buffer for every sideband frame of the pack. The remainder was the harness
(`os.RemoveAll` of the clone directories, `os.ReadDir`) and ref reading in
`gitproto`. Nothing in `internal/githttp` itself was a significant source.

## After: gitproto 4952844 (reused sideband frame buffer, packed-refs read in one block)

The fix is a dependency bump (go-vcs/gitproto#8), with `TestFetchAllocationsDoNotScaleWithThePack`
as the regression test: one fetch of a 4 MiB incompressible pack allocated
5 090 240 bytes before and 351 672 bytes in 279 allocations after (bound: an
eighth of the reply; 2500 allocations as a sanity bound, since Windows takes 1103
where macOS takes 279).

Interleaved run, the order alternating, 20 clones per run, 6 runs. The load rose
during the run, from 1-min 6.6 / 5-min 7.2 at the start to 1-min 16 at the end,
so the later runs are noisy; the allocation columns are exact, the times are not
a reference measurement.

| run | forge ms/op | git http-backend ms/op | forge/git | forge-B/op | forge-allocs/op |
|---|---|---|---|---|---|
| 1 | 291.6 | 346.8 | 0.841 | 1 160 254 | 2824 |
| 2 | 446.8 | 505.3 | 0.884 | 1 162 691 | 2827 |
| 3 | 320.7 | 363.2 | 0.883 | 1 160 220 | 2824 |
| 4 | 340.6 | 407.6 | 0.836 | 1 161 752 | 2823 |
| 5 | 463.0 | 471.4 | 0.982 | 1 160 937 | 2824 |
| 6 | 301.6 | 357.5 | 0.844 | 1 161 902 | 2822 |

The 1.16 MB and 2824 allocations per clone count the whole process, so they
include the harness (`os/exec`, process wait, output capture). The handler's own
share, measured without a client process, is the 279 allocations of the
regression test; the split inside the 2824 was not profiled again after the fix.
