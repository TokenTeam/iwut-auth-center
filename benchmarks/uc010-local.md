# UC010 local bounded measurement

Measured 2026-09-23 while implementing UC010. This is a repeatable smoke
measurement, not a production benchmark or a basis for a 1-core capacity claim.

Environment: Go 1.26.0 linux/amd64, Linux 7.0.0-31-generic, Intel Core i7-12700H,
20 visible logical CPUs. MongoDB 8.2.12 runs in the test Docker single-member
replica set with snapshot transactions, majority commit, primary reads and the
production shared authentication fence. No explicit CPU quota was imposed.

Command (no race instrumentation):

```sh
MONGODB_INTEGRATION_PORT=27040 ./scripts/test-mongo-integration.sh \
  -run 'TestE2E_IdentityIssuance|TestProductionSigner' -v
```

| Measurement | Result |
| --- | --- |
| Production RSA-2048 signer, 30 sequential signatures | Mean 714.255 microseconds |
| Production Wire/native gRPC/Mongo/RS256, 20 sequential calls | Total 216.648 ms |
| Same RPC sample, nearest-rank p50 | 9.482 ms |
| Same RPC sample, nearest-rank p95 | 16.232 ms |

RPC samples include test Gateway RSA service-JWS signing, native loopback gRPC,
service verification, current Session/credential/principal reads, candidate
signing and transaction commit with the synchronous LRU update. They exclude
registration and setup. The isolated signer sample excludes key generation and
constructor/precomputation. The suite also verifies the resulting JWS with the
real Auth verifier and profile RPC. RSA timing and total RPC timing are measured
separately; their difference is not an isolated Mongo transaction benchmark.

The full real-Mongo suite also passed with race detection. Its simultaneous
packages and instrumentation produced slower measurements and are deliberately
not used as performance estimates here. Production measurement must use the
actual host, durability configuration, request mix and concurrency, including
fence contention, percentiles over a much larger sample and error rates. No
Redis, positive Session cache or cached user identity was used.
