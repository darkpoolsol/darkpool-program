# Proving-key ceremony

DARKPOOL's Groth16 keys for the `transact` circuit come from a two-phase trusted setup. The keys are sound as long as
at least one contributor discarded their randomness.

- **Phase 1:** the public [Perpetual Powers of Tau](https://github.com/privacy-scaling-explorations/perpetualpowersoftau),
  contribution 0080, prepared for 2^16 constraints (`ppot_0080_16.ptau`, blake2b in `transcript.json`).
- **Phase 2:** specific to this circuit. One contribution and a Bitcoin beacon at launch, then contributions from
  anyone on darkpool.ag/ceremony, each checked against the whole chain before it was accepted. The ceremony closed on
  2026-10-14 at 22:04:04 UTC. The final beacon is Bitcoin block 971471, the first block mined after the close.

## Files

| File | |
|---|---|
| `transcript.json` | Every step: kind, time, the contribution's fingerprint (snarkjs contribution hash), the key's SHA-256 after it, and for beacons the block and its hash |
| `transact.zkey` | The final proving key (SHA-256 `d85cfcdf18c204bcbb5a961d5f8b1cf876f48667c76d7a7b48904d28bd97fcab`) |
| `transact-vk.json` | Its verifying key, the one in `programs/darkpool/src/verifying_key.rs` |
| `transact.r1cs` | The circuit's constraints (SHA-256 `ab667e45ff4fbfbcdcaf33464dc09eac3b5c65d979537b5704de4f6e9abfb333`); the circuit source is in the audit package |

## Check it

Download the phase-1 file, then:

```
curl -O https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/ppot_0080_16.ptau
npx snarkjs zkey verify transact.r1cs ppot_0080_16.ptau transact.zkey
npx snarkjs zkey export verificationkey transact.zkey vk.json   # same key as transact-vk.json
```

`zkey verify` lists every contribution with its hash. They match `contributionHash` in `transcript.json`, and the
last one is the beacon from Bitcoin block 971471
(`000000000000000000007ddc6294e5654d45a8e69ea1752770d2e338bd12e8b5`).
