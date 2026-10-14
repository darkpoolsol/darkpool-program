use anchor_lang::prelude::*;

use crate::crypto::{poseidon, Fe};
use crate::errors::DpError;

pub const DEPTH: usize = 20;
pub const HISTORY: usize = 100;
pub const RECORD: usize = 128;
/// Trees kept: when one fills, its final root is archived and a fresh tree starts (notes in any of them stay spendable).
pub const TREES: usize = 128;
/// Notes per tree. A test build ("small-trees") fills trees after 8 notes to exercise the rollover.
#[cfg(not(feature = "small-trees"))]
pub const CAPACITY: u64 = 1 << DEPTH;
#[cfg(feature = "small-trees")]
pub const CAPACITY: u64 = 8;

/// The shielded pool: append-only note trees of depth 20 (about a million notes each; 128 of them), the current
/// tree's recent roots, and every filled tree's final root.
#[account(zero_copy)]
pub struct State {
    pub root: Fe,
    /// empty[d]: the root of an empty subtree of height d (empty[0] is the empty leaf).
    pub empty: [Fe; DEPTH],
    /// The left nodes still needed to extend the current tree, one per level.
    pub edge: [Fe; DEPTH],
    pub history: [Fe; HISTORY],
    pub archive: [Fe; TREES],
    /// Notes ever added (a note's number is its leaf; its tree is leaf / capacity).
    pub leaves: u64,
    pub history_pos: u64,
    pub tree: u64,
    pub capacity: u64,
    /// Receives 80% of collected fees (bought back and burned off-chain by the keeper).
    pub fee_wallet: Pubkey,
    /// Receives 20% of collected fees.
    pub builder: Pubkey,
    pub bump: u8,
    pub router_bump: u8,
    pub _reserved: [u8; 6],
    /// The vault coin (its notes are shares), or the default key while none is set.
    pub vault_mint: Pubkey,
    /// Approved routing programs for swaps (empty slots are the default key). Jupiter from `configure`.
    pub routers: [Pubkey; 8],
}

impl State {
    pub fn start(&mut self, empty_leaf: Fe) -> Result<()> {
        self.empty[0] = empty_leaf;
        for d in 1..DEPTH {
            self.empty[d] = poseidon(&[&self.empty[d - 1], &self.empty[d - 1]])?;
        }
        self.capacity = CAPACITY;
        self.set_root(self.empty_root()?);
        Ok(())
    }

    fn empty_root(&self) -> Result<Fe> {
        poseidon(&[&self.empty[DEPTH - 1], &self.empty[DEPTH - 1]])
    }

    /// Adds a leaf and returns its number (leaves count across trees; its position in its tree is number % capacity).
    pub fn append(&mut self, leaf: &Fe) -> Result<u64> {
        let number = self.leaves;
        let pos = number - self.tree * self.capacity;
        require!(pos < self.capacity && (self.tree as usize) < TREES, DpError::TreeFull);
        let mut node = *leaf;
        for d in 0..DEPTH {
            node = if (pos >> d) & 1 == 0 {
                self.edge[d] = node;
                poseidon(&[&node, &self.empty[d]])?
            } else {
                poseidon(&[&self.edge[d], &node])?
            };
        }
        self.leaves = number + 1;
        self.set_root(node);
        if pos + 1 == self.capacity {
            // This tree is full: keep its final root for proofs about its notes, and start an empty one.
            self.archive[self.tree as usize] = node;
            self.tree += 1;
            if (self.tree as usize) < TREES {
                let fresh = self.empty_root()?;
                self.set_root(fresh);
            }
        }
        Ok(number)
    }

    fn set_root(&mut self, root: Fe) {
        self.root = root;
        self.history[(self.history_pos % HISTORY as u64) as usize] = root;
        self.history_pos += 1;
    }

    pub fn knows(&self, root: &Fe) -> bool {
        *root != [0u8; 32] && (self.history.iter().any(|r| r == root) || self.archive[..(self.tree as usize).min(TREES)].iter().any(|r| r == root))
    }
}

/// A listed coin: its reserve, how much of it the notes are owed, and fees not yet collected.
#[account]
pub struct TokenEntry {
    pub coin: Fe,
    pub mint: Pubkey,
    pub reserve: Pubkey,
    pub token_program: Pubkey,
    pub decimals: u8,
    pub bump: u8,
    pub shielded: u64,
    /// Uncollected swap fees (all of them, for the reserve check), and the builder's part of them.
    pub fees: u64,
    pub builder_fees: u64,
    /// The vault coin only: tokens behind all its shares (then `shielded` counts shares, not tokens).
    pub backing: u64,
    /// 0: an ordinary coin. 1: the vault coin, shares as first launched. 2: the vault coin with fine shares: `shielded`
    /// counts fine shares (VAULT_SCALE per first-launch share), `coin` is the coin of new notes, and notes made before
    /// the change (under `coin_id(mint)`) count VAULT_SCALE fine shares per unit.
    pub vault: u8,
}
impl TokenEntry {
    pub const SPACE: usize = 8 + 32 * 4 + 2 + 8 * 4 + 1;
}

/// Proof and records staged across transactions (too large for one), owned by the relayer that opened it.
#[account]
pub struct Stage {
    pub relayer: Pubkey,
    pub bytes: Vec<u8>,
}

/// The part every staged spend starts with.
pub struct SpendHead {
    pub proof: [u8; 256],
    pub root: Fe,
    pub public_amount: u64,
    pub markers: [Fe; 4],
    pub outputs: [Fe; 2],
    pub fee: u64,
    pub expiry: i64,
}

pub struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Reader { bytes, at: 0 }
    }
    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        require!(self.at + n <= self.bytes.len(), DpError::BadStage);
        let s = &self.bytes[self.at..self.at + n];
        self.at += n;
        Ok(s)
    }
    pub fn fe(&mut self) -> Result<Fe> {
        Ok(self.take(32)?.try_into().unwrap())
    }
    pub fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    pub fn head(&mut self) -> Result<SpendHead> {
        let proof: [u8; 256] = self.take(256)?.try_into().unwrap();
        let root = self.fe()?;
        let public_amount = self.u64()?;
        let markers = [self.fe()?, self.fe()?, self.fe()?, self.fe()?];
        let outputs = [self.fe()?, self.fe()?];
        let fee = self.u64()?;
        let expiry = self.u64()? as i64;
        Ok(SpendHead { proof, root, public_amount, markers, outputs, fee, expiry })
    }
    pub fn done(&self) -> Result<()> {
        require!(self.at == self.bytes.len(), DpError::BadStage);
        Ok(())
    }
}
