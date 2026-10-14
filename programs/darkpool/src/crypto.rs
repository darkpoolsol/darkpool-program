//! Hashing and proof checks shared by every instruction. Field elements are 32-byte big-endian.
use anchor_lang::prelude::*;
use groth16_solana::groth16::Groth16Verifier;
use solana_keccak_hasher as keccak;
use solana_poseidon::{hashv, Endianness, Parameters};

use crate::errors::DpError;
use crate::verifying_key::TRANSACT;

pub type Fe = [u8; 32];

/// An ASCII tag right-aligned in a field element ("dp/note" is the integer 0x64702f6e6f7465).
pub const fn tag(name: &[u8]) -> Fe {
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < name.len() {
        out[32 - name.len() + i] = name[i];
        i += 1;
    }
    out
}
pub const NOTE: Fe = tag(b"dp/note");

pub fn poseidon(inputs: &[&[u8]]) -> Result<Fe> {
    Ok(hashv(Parameters::Bn254X5, Endianness::BigEndian, inputs).map_err(|_| DpError::HashInput)?.to_bytes())
}

/// A note commitment from its public parts (used where the program, not a proof, makes the note).
pub fn commitment(coin: &Fe, amount: u64, hide: &Fe) -> Result<Fe> {
    poseidon(&[&NOTE, coin, &be(amount), hide])
}

/// keccak of the parts with the top byte cleared: always a valid field element.
pub fn keccak_fe(parts: &[&[u8]]) -> Fe {
    let mut h = keccak::hashv(parts).0;
    h[0] = 0;
    h
}

pub fn coin_id(mint: &Pubkey) -> Fe {
    keccak_fe(&[b"DARKPOOL/coin", mint.as_ref()])
}

/// The vault coin's notes with fine shares (vault version 2).
pub fn coin_id_v2(mint: &Pubkey) -> Fe {
    keccak_fe(&[b"DARKPOOL/coin/v2", mint.as_ref()])
}

pub fn be(x: u64) -> Fe {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&x.to_be_bytes());
    out
}

/// Checks a transact proof. The holder's client sends A already negated, so the pairing check is direct.
/// Public signals: 4 spent markers, 2 new notes, root, public coin, public amount, bound data.
pub fn verify(proof: &[u8; 256], signals: &[Fe; 10]) -> Result<()> {
    let a: [u8; 64] = proof[..64].try_into().unwrap();
    let b: [u8; 128] = proof[64..192].try_into().unwrap();
    let c: [u8; 64] = proof[192..].try_into().unwrap();
    Groth16Verifier::new(&a, &b, &c, signals, &TRANSACT)
        .and_then(|mut v| v.verify())
        .map(|_| ())
        .map_err(|_| error!(DpError::InvalidProof))
}

/// The route as one hash: the routing program, data length and data, then every account address in order.
/// (Writability is left out: it is decided by the whole transaction, and granting it never gives a program authority
/// it lacks.)
pub fn route_digest(program: &Pubkey, data: &[u8], accounts: &[AccountInfo]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(32 + 4 + data.len() + accounts.len() * 32);
    buf.extend_from_slice(program.as_ref());
    buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
    buf.extend_from_slice(data);
    for a in accounts {
        buf.extend_from_slice(a.key.as_ref());
    }
    keccak::hash(&buf).0
}
