# DARKPOOL program

The Solana program behind [DARKPOOL](https://darkpool.ag): a shielded pool for Solana coins. Users shield coins into
private notes, send them privately, swap them through Jupiter without revealing who traded, and unshield to any
address. Every spend is authorized by a Groth16 proof checked on chain.

This repository holds exactly the source of the deployed program, so anyone can rebuild it and check that the bytes
on chain match.

| | |
|---|---|
| Program | `Gj6tgwJ8bKMUUoSxWrk57APLZbk6gJ17yFnQy8HA2qoK` |
| Upgrade authority | Squads v4 vault `AAY6AwzCPFsfAp5JZCHTG8pTfsyvHWnuWTR4nHqVk79z` (multisig `EZxqJP5HKWcQ8FxZQ1yrSd8M83kssy2hVVhb78SmhZiT`, 2 of 3, 3-day timelock) |
| Audit package | [darkpoolsol/darkpool-audit](https://github.com/darkpoolsol/darkpool-audit) at `c9932e1` |

## What changed from the audited source

The program source here is the audit package's `solana/` directory at commit `c9932e1`, unchanged except for:

1. `programs/darkpool/src/lib.rs`: `declare_id!` set to the mainnet program id (the audit package keeps a local
   test id).
2. `programs/darkpool/src/verifying_key.rs`: the Groth16 verifying key from the public proving-key ceremony
   (`ceremony/`), in place of the audit package's local test key. Only the key's `delta` changes, as expected for
   additional phase-2 contributions.
3. The fixes from ContractWolf's audit (October 2026), in `lib.rs`, `crypto.rs` and `funds.rs`:
   - SOL-SYNC-DOS: a SOL shield needs the reserve to rise by at least the amount, so lamports sent straight to the
     reserve stay as surplus instead of blocking every later SOL shield.
   - RCW-011: a coin is listed only if its mint has no freeze authority (USDC and USDT excepted), on every path.
   - ROUTER-LAMPORTS: the router must come back from a route with the same lamports.
   - ROUTE-FLAGS: the route digest binds each account's writable flag, and the route is invoked with exactly those
     flags and the router as its only signer.

```
git diff --no-index <darkpool-audit>/solana/programs programs
```

## Rebuild and verify

Built with [solana-verify](https://github.com/Ellipsis-Labs/solana-verifiable-build) in Docker:

```
solana-verify build --arch v3 --library-name darkpool --base-image solanafoundation/solana-verifiable-build:4.1.0
solana-verify get-executable-hash target/deploy/darkpool.so
solana-verify get-program-hash Gj6tgwJ8bKMUUoSxWrk57APLZbk6gJ17yFnQy8HA2qoK
```

The two hashes are equal once this version is deployed. This version (with the audit fixes) builds to
`a39b38471783c1cd1939b9097c988ede4932db751898df5bb4fb7c5c2df8015e`. The base image is pinned because the default image for
`solana-program 2.3` ships Cargo 1.84, which cannot build the locked dependencies.

## Proving key

`ceremony/` holds the ceremony's transcript, the final verifying key, the final proving key and the circuit's
constraint file. See [ceremony/README.md](ceremony/README.md) to check every contribution yourself.
