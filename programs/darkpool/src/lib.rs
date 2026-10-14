//! DARKPOOL. Shield any Solana coin into private notes, send them privately, swap them through Jupiter without
//! revealing who traded, and unshield to any address.
//!
//! - One circuit (`transact`) spends up to four notes of a coin and makes up to two; whatever leaves the pool is its
//!   public amount. Shielding needs no proof: the program builds the note from the deposited amount itself.
//! - Anyone can relay. Each action binds its relayer (the transaction's fee payer) and the relayer's fee into the
//!   proof, so a copied proof is worthless to anyone else and nobody has to trust one operator.
//! - Viewing keys: a note's owner address is a hash of two keys derived from the spend key, so an address's notes
//!   and spends can be shown to someone without giving them the power to spend.
//! - Admin powers, all the upgrade authority's (a multisig with a timelock after the launch window): `set_vault` once,
//!   and `set_router` to approve routing programs. No pause, no freeze, no blocklist; fees change only by an upgrade.
//!   Fees (0.5% of each private swap) are paid out by anyone calling `collect_fees`: 80% to the fee wallet (bought
//!   back: half burned, half to the vault coin's holders), 20% to the builder.
//!   A swap may name a referrer (bound in its proof): the referrer then gets 10% of that swap's fee as a private note,
//!   taken from the builder's share, so the fee wallet's 80% never changes.
//! - One coin may be the vault coin ($DARKPOOL, set once by the upgrade authority before it is listed). Its notes
//!   hold shares of everything shielded in it, not token amounts. `donate` adds tokens without adding shares, so
//!   every private holder's notes are worth more, and nobody learns who holds what. Conversions round in the vault's
//!   favour, and virtual shares make inflating an early share price cost more than it could take.
//!
//! Swaps run through an approved routing program (Jupiter from the start; the upgrade authority can approve another
//! aggregator or a DEX without an upgrade), named in the proof like the route itself. The router address signs for
//! the route, so only approved programs get to use it; and after every route the router and its accounts must come
//! back exactly as they were, the output must reach the proven minimum, and it only ever holds the trade in progress.
//!
//! Amounts are measured from real balance changes, every reserve must cover its notes plus uncollected fees after
//! each action, and swaps run as a separate router address that only ever holds the one trade in progress.
use anchor_lang::prelude::*;
use anchor_lang::solana_program::{
    bpf_loader_upgradeable,
    instruction::{AccountMeta, Instruction},
    program::invoke_signed,
};
use anchor_spl::associated_token::{get_associated_token_address_with_program_id, AssociatedToken};
use anchor_spl::token_interface::{self as ti, Mint, TokenAccount, TokenInterface, TransferChecked};

mod crypto;
mod errors;
mod funds;
mod state;
mod verifying_key;

use crypto::{be, coin_id, coin_id_v2, commitment, keccak_fe, route_digest, verify, Fe};
use errors::DpError;
use funds::*;
use state::*;

declare_id!("Gj6tgwJ8bKMUUoSxWrk57APLZbk6gJ17yFnQy8HA2qoK");

pub const SWAP_FEE_BPS: u64 = 50;
pub const BUILDER_SHARE_BPS: u64 = 2_000;
/// The referrer's part of a referred swap's fee; it comes out of the builder's share.
pub const REFERRAL_SHARE_BPS: u64 = 1_000;
pub const WSOL: Pubkey = pubkey!("So11111111111111111111111111111111111111112");
const STAGE_MAX: u32 = 1_300;
pub const JUPITER: Pubkey = pubkey!("JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4");
/// Virtual shares and one virtual token behind the vault coin's shares (as in OpenZeppelin's ERC-4626).
const VIRTUAL_SHARES: u128 = 1_000;
/// Vault version 2: fine shares per first-launch share (a note made before the change counts this many per unit).
pub const VAULT_SCALE: u64 = 1_000_000;
/// Vault version 2: a gift may never make one fine share worth more than this many token units, so gifts cannot
/// coarsen the shares (a vault with few or no holders accepts only small gifts).
const MAX_UNITS_PER_SHARE: u128 = 1_000_000;
const ZERO: Fe = [0u8; 32];

/// Jupiter's routed CPI needs far more than Solana's default 32 KB heap. Every transaction that calls this program
/// requests a 256 KB heap frame; this arena allocator hands it out and never frees (each call is short-lived).
#[cfg(all(target_os = "solana", not(feature = "no-entrypoint")))]
mod arena {
    use core::alloc::{GlobalAlloc, Layout};
    const BASE: usize = 0x3_0000_0000;
    const SIZE: usize = 256 * 1024;
    pub struct Arena;
    unsafe impl GlobalAlloc for Arena {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            // The first word of the heap holds the next free address.
            let next = BASE as *mut usize;
            if *next == 0 {
                *next = BASE + core::mem::size_of::<usize>();
            }
            let start = (*next + layout.align() - 1) & !(layout.align() - 1);
            let end = match start.checked_add(layout.size()) {
                Some(e) if e <= BASE + SIZE => e,
                _ => return core::ptr::null_mut(),
            };
            *next = end;
            start as *mut u8
        }
        unsafe fn dealloc(&self, _: *mut u8, _: Layout) {}
    }
    #[global_allocator]
    static HEAP: Arena = Arena;
}

#[program]
pub mod darkpool {
    use super::*;

    /// One-time setup by the upgrade authority: the empty tree and the two fee recipients.
    pub fn configure(ctx: Context<Configure>, fee_wallet: Pubkey, builder: Pubkey) -> Result<()> {
        upgrade_authority_is(&ctx.accounts.program_data, ctx.accounts.authority.key)?;
        let mut s = ctx.accounts.state.load_init()?;
        s.start(keccak_fe(&[b"DARKPOOL/empty-leaf"]))?;
        s.fee_wallet = fee_wallet;
        s.builder = builder;
        s.bump = ctx.bumps.state;
        s.router_bump = Pubkey::find_program_address(&[ROUTER_SEED], &crate::ID).1;
        s.routers[0] = JUPITER;
        Ok(())
    }

    /// By the upgrade authority: approves (or withdraws) a routing program for swaps. Approved programs act with the
    /// router address's signature, so only known aggregators and DEXes belong here.
    pub fn set_router(ctx: Context<SetRouter>, program: Pubkey, approved: bool) -> Result<()> {
        upgrade_authority_is(&ctx.accounts.program_data, ctx.accounts.authority.key)?;
        require!(program != crate::ID && program != Pubkey::default(), DpError::RouteRejected);
        let mut s = ctx.accounts.state.load_mut()?;
        let at = s.routers.iter().position(|r| *r == program);
        match (approved, at) {
            (true, None) => { let free = s.routers.iter().position(|r| *r == Pubkey::default()).ok_or(DpError::RouteRejected)?; s.routers[free] = program; }
            (false, Some(i)) => s.routers[i] = Pubkey::default(),
            _ => {}
        }
        Ok(())
    }

    /// One-time, by the upgrade authority: which coin's notes are vault shares. Only before that coin is listed, so
    /// no note of it was ever made in plain amounts. The mint need not exist yet (a launchpad coin's address is known
    /// before it is launched), so it can be set before anyone could list the coin.
    pub fn set_vault(ctx: Context<SetVault>) -> Result<()> {
        upgrade_authority_is(&ctx.accounts.program_data, ctx.accounts.authority.key)?;
        let (at, _) = Pubkey::find_program_address(&[b"coin", ctx.accounts.mint.key().as_ref()], &crate::ID);
        require_keys_eq!(ctx.accounts.entry.key(), at, DpError::BadAccount);
        require!(ctx.accounts.entry.data_is_empty(), DpError::BadAccount);
        let mut s = ctx.accounts.state.load_mut()?;
        require_keys_eq!(s.vault_mint, Pubkey::default(), DpError::Unauthorized);
        s.vault_mint = ctx.accounts.mint.key();
        Ok(())
    }

    /// Adds tokens of the vault coin to the vault (anyone may): every share is then worth more; no shares are made.
    pub fn donate(mut ctx: Context<Donate>, amount: u64) -> Result<()> {
        require!(amount > 0 && ctx.accounts.entry.vault != 0, DpError::BadAmount);
        let a = &mut ctx.accounts;
        let before = a.reserve.amount;
        ti::transfer_checked(CpiContext::new(a.token_program.to_account_info(), TransferChecked { from: a.donor_token.to_account_info(), mint: a.mint.to_account_info(), to: a.reserve.to_account_info(), authority: a.donor.to_account_info() }), amount, a.mint.decimals)?;
        a.reserve.reload()?;
        require!(a.reserve.amount.checked_sub(before) == Some(amount), DpError::TransferMismatch);
        a.entry.backing = a.entry.backing.checked_add(amount).ok_or(DpError::BadAmount)?;
        if a.entry.vault == 2 {
            require!(a.entry.backing as u128 + 1 <= MAX_UNITS_PER_SHARE * (a.entry.shielded as u128 + VIRTUAL_SHARES), DpError::GiftTooLarge);
        }
        covered(&a.entry, a.reserve.amount)?;
        emit_cpi!(Donated { amount });
        Ok(())
    }

    /// Lists a coin (anyone may): its reserve and its accounting.
    pub fn list_coin(ctx: Context<ListCoin>) -> Result<()> {
        listable(&ctx.accounts.mint.to_account_info())?;
        let vault = ctx.accounts.state.load()?.vault_mint == ctx.accounts.mint.key();
        let e = &mut ctx.accounts.entry;
        e.vault = if vault { 2 } else { 0 };
        e.mint = ctx.accounts.mint.key();
        e.coin = if vault { coin_id_v2(&e.mint) } else { coin_id(&e.mint) };
        e.reserve = ctx.accounts.reserve.key();
        e.token_program = ctx.accounts.token_program.key();
        e.decimals = ctx.accounts.mint.decimals;
        e.bump = ctx.bumps.entry;
        Ok(())
    }

    /// One-time, by the upgrade authority: moves the vault coin listed as first launched (version 1) to fine shares
    /// (version 2). Every share becomes VAULT_SCALE fine shares, so no holder's notes change in number, and new notes
    /// use a new coin with fine shares. Notes made before stay spendable (each unit counts VAULT_SCALE fine shares).
    pub fn upgrade_vault(ctx: Context<UpgradeVault>) -> Result<()> {
        upgrade_authority_is(&ctx.accounts.program_data, ctx.accounts.authority.key)?;
        let vault_mint = ctx.accounts.state.load()?.vault_mint;
        let e = &mut ctx.accounts.entry;
        require_keys_eq!(e.mint, vault_mint, DpError::BadAccount);
        require!(e.vault == 1, DpError::Unauthorized);
        e.shielded = e.shielded.checked_mul(VAULT_SCALE).ok_or(DpError::BadAmount)?;
        e.vault = 2;
        e.coin = coin_id_v2(&e.mint);
        Ok(())
    }

    /// Shield: `amount` of the coin (lamports for SOL) becomes one note with the holder's hidden part `hide`.
    pub fn shield(mut ctx: Context<Shield>, amount: u64, hide: [u8; 32], record: [u8; RECORD]) -> Result<()> {
        require!(amount > 0, DpError::BadAmount);
        let a = &mut ctx.accounts;
        let before = a.reserve.amount;
        if a.entry.mint == WSOL {
            send_lamports(&a.depositor.to_account_info(), &a.reserve.to_account_info(), &a.system_program.to_account_info(), amount)?;
            ti::sync_native(CpiContext::new(a.token_program.to_account_info(), ti::SyncNative { account: a.reserve.to_account_info() }))?;
        } else {
            let from = a.depositor_token.as_ref().ok_or(DpError::MissingAccount)?;
            ti::transfer_checked(
                CpiContext::new(a.token_program.to_account_info(), TransferChecked { from: from.to_account_info(), mint: a.mint.to_account_info(), to: a.reserve.to_account_info(), authority: a.depositor.to_account_info() }),
                amount,
                a.mint.decimals,
            )?;
        }
        a.reserve.reload()?;
        require!(a.reserve.amount.checked_sub(before) == Some(amount), DpError::TransferMismatch);
        // The note holds the deposit itself, or, for the vault coin, the shares it buys.
        let units = enter(&mut a.entry, amount)?;
        let c = commitment(&a.entry.coin, units, &hide)?;
        let leaf = a.state.load_mut()?.append(&c)?;
        covered(&a.entry, a.reserve.amount)?;
        emit!(Shielded { mint: a.entry.mint, amount });
        emit_cpi!(NoteAdded { leaf, commitment: c, amount: units, record });
        Ok(())
    }

    /// Proofs and records are larger than one transaction, so a relayer stages them first.
    pub fn stage_open(ctx: Context<StageOpen>, _stage_id: u64, len: u32) -> Result<()> {
        require!(len <= STAGE_MAX, DpError::BadStage);
        ctx.accounts.stage.relayer = ctx.accounts.relayer.key();
        ctx.accounts.stage.bytes = vec![0; len as usize];
        Ok(())
    }
    pub fn stage_write(ctx: Context<StageWrite>, _stage_id: u64, offset: u32, data: Vec<u8>) -> Result<()> {
        let bytes = &mut ctx.accounts.stage.bytes;
        let end = (offset as usize).checked_add(data.len()).ok_or(DpError::BadStage)?;
        require!(end <= bytes.len(), DpError::BadStage);
        bytes[offset as usize..end].copy_from_slice(&data);
        Ok(())
    }
    pub fn stage_discard(_ctx: Context<StageDiscard>, _stage_id: u64) -> Result<()> {
        Ok(())
    }

    /// A private send, an unshield, or both, from a staged proof:
    ///   head | 2 records, where head = proof(256) root public_amount markers[4] outputs[2] fee expiry.
    /// `public_amount` leaves the pool: `fee` to the relayer, the rest to the recipient. A fully private send has a
    /// public amount of 0 and names no coin.
    pub fn transact<'info>(mut ctx: Context<'_, '_, 'info, 'info, Transact<'info>>, _stage_id: u64) -> Result<()> {
        let bytes = core::mem::take(&mut ctx.accounts.stage.bytes);
        let mut r = Reader::new(&bytes);
        let h = r.head()?;
        let records = [r.take(RECORD)?, r.take(RECORD)?];
        r.done()?;
        require!(h.fee <= h.public_amount, DpError::FeeTooHigh);
        let payout = h.public_amount - h.fee;
        let a = &ctx.accounts;
        let to = if payout > 0 { a.recipient.as_ref().ok_or(DpError::MissingAccount)?.key() } else { Pubkey::default() };
        let ext = keccak_fe(&[b"DARKPOOL/transact/v1", crate::ID.as_ref(), a.relayer.key.as_ref(), to.as_ref(), &h.fee.to_le_bytes(), &h.expiry.to_le_bytes(), records[0], records[1]]);
        let legacy = if h.public_amount > 0 {
            check_spend_coin(&*a.state.load()?, &h, a.entry.as_ref().ok_or(DpError::MissingAccount)?, ext)?
        } else {
            check_spend(&*a.state.load()?, &h, ZERO, ext)?;
            false
        };
        let markers = [&a.marker0, &a.marker1, &a.marker2, &a.marker3].map(|m| m.to_account_info());
        mark_spent(&a.relayer.to_account_info(), &markers, &a.system_program.to_account_info(), &h.markers)?;
        let notes = append_outputs(&mut *a.state.load_mut()?, &h.outputs, &records)?;
        if h.public_amount > 0 {
            release(&mut ctx, &h, payout, legacy)?;
        }
        for n in notes {
            emit_cpi!(n);
        }
        Ok(())
    }

    /// A private swap through Jupiter from a staged proof:
    ///   head | min_out | out_hide | refund_hide | ref_hide | 5 records (two outputs, the bought note, the refund
    ///   note, the referral note). `ref_hide` is zero when no referrer is named.
    /// `route` is Jupiter's instruction data; its accounts follow as remaining accounts. Fees are taken on the SOL
    /// side: from the output when buying SOL, otherwise from the input.
    pub fn swap<'info>(mut ctx: Context<'_, '_, 'info, 'info, Swap<'info>>, _stage_id: u64, route: Vec<u8>) -> Result<()> {
        let bytes = core::mem::take(&mut ctx.accounts.stage.bytes);
        let mut r = Reader::new(&bytes);
        let h = r.head()?;
        let min_out = r.u64()?;
        let (out_hide, refund_hide, ref_hide) = (r.fe()?, r.fe()?, r.fe()?);
        let records = [r.take(RECORD)?, r.take(RECORD)?, r.take(RECORD)?, r.take(RECORD)?, r.take(RECORD)?];
        r.done()?;
        let a = &ctx.accounts;
        require_keys_neq!(a.in_entry.mint, a.out_entry.mint, DpError::SameCoin);
        require!(h.public_amount > 0, DpError::BadAmount);
        let on_output = a.out_entry.mint == WSOL;
        // The vault coin is only sold for SOL (its fees are then taken in SOL, never in shares).
        require!(a.in_entry.vault == 0 || on_output, DpError::RouteRejected);
        let digest = route_digest(a.route_program.key, &route, ctx.remaining_accounts);
        let ext = keccak_fe(&[b"DARKPOOL/swap/v2", crate::ID.as_ref(), a.relayer.key.as_ref(), a.out_entry.mint.as_ref(), &min_out.to_le_bytes(), &out_hide, &refund_hide, &ref_hide,
            &h.fee.to_le_bytes(), &h.expiry.to_le_bytes(), &digest, records[0], records[1], records[2], records[3], records[4]]);
        let legacy = check_spend_coin(&*a.state.load()?, &h, &a.in_entry, ext)?;
        // What leaves the pool, in tokens: the shares spent are worth this much of the vault coin.
        let spent_units = spend_units(&a.in_entry, legacy, h.public_amount)?;
        let tokens_in = if a.in_entry.vault != 0 { to_assets(&a.in_entry, spent_units)? } else { h.public_amount };
        let markers = [&a.marker0, &a.marker1, &a.marker2, &a.marker3].map(|m| m.to_account_info());
        mark_spent(&a.relayer.to_account_info(), &markers, &a.system_program.to_account_info(), &h.markers)?;

        // Input side: the relayer's fee and the swap fee come off before trading when the output is not SOL.
        let fee_in = if on_output { 0 } else { h.fee };
        let trade = tokens_in.checked_sub(fee_in).ok_or(DpError::FeeTooHigh)?;
        let cut_in = if on_output { 0 } else { bps(trade, SWAP_FEE_BPS) };
        let trade_in = trade - cut_in;
        let state_bump = a.state.load()?.bump;
        let state_seeds: &[&[u8]] = &[STATE_SEED, &[state_bump]];
        if fee_in > 0 {
            let to = relayer_account(&a.relayer_token, a.relayer.key, &a.in_entry.mint)?;
            pay(&a.in_token_program.to_account_info(), &a.in_reserve.to_account_info(), &a.in_mint.to_account_info(), &to, &a.state.to_account_info(), state_seeds, fee_in, a.in_mint.decimals)?;
        }
        let (spent, got) = run_route(&ctx, trade_in, &route, state_seeds)?;
        let a = &ctx.accounts;
        let cut_out = if on_output { bps(got, SWAP_FEE_BPS) } else { 0 };
        let fee_out = if on_output { h.fee } else { 0 };
        let bought = got.checked_sub(cut_out + fee_out).ok_or(DpError::BelowMinimum)?;
        require!(cut_in + cut_out > 0 && bought > 0 && bought >= min_out, DpError::BelowMinimum);
        if fee_out > 0 {
            let to = relayer_account(&a.relayer_token, a.relayer.key, &a.out_entry.mint)?;
            pay(&a.out_token_program.to_account_info(), &a.out_reserve.to_account_info(), &a.out_mint.to_account_info(), &to, &a.state.to_account_info(), state_seeds, fee_out, a.out_mint.decimals)?;
        }
        let refund = trade_in - spent;
        let (in_coin, out_coin) = (a.in_entry.coin, a.out_entry.coin);
        // The swap fee: 80% to the fee wallet always; the rest to the builder, or split with a named referrer.
        let cut = cut_in + cut_out;
        let referral = if ref_hide != ZERO { bps(cut, REFERRAL_SHARE_BPS) } else { 0 };
        let to_builder = bps(cut, BUILDER_SHARE_BPS) - referral;
        let a = &mut ctx.accounts;
        a.in_entry.shielded = a.in_entry.shielded.checked_sub(spent_units).ok_or(DpError::BadAmount)?;
        if a.in_entry.vault != 0 {
            a.in_entry.backing = a.in_entry.backing.checked_sub(tokens_in).ok_or(DpError::BadAmount)?;
        }
        // Unspent input comes back as a refund note; the bought coin as a note (both as shares for the vault coin).
        // A refund worth less than one vault share is dust: it stays in the vault (every holder's), with no note.
        let refund_units = if refund > 0 { enter_or_dust(&mut a.in_entry, refund)? } else { 0 };
        let bought_units = enter(&mut a.out_entry, bought)?;
        let fee_entry = if on_output { &mut a.out_entry } else { &mut a.in_entry };
        fee_entry.fees += cut - referral;
        fee_entry.builder_fees += to_builder;
        fee_entry.shielded += referral;
        let fee_coin = fee_entry.coin;
        let mut notes = append_outputs(&mut *a.state.load_mut()?, &h.outputs, &[records[0], records[1]])?;
        {
            let mut s = a.state.load_mut()?;
            let c = commitment(&out_coin, bought_units, &out_hide)?;
            notes.push(NoteAdded { leaf: s.append(&c)?, commitment: c, amount: bought_units, record: records[2].try_into().unwrap() });
            if refund_units > 0 {
                let c = commitment(&in_coin, refund_units, &refund_hide)?;
                notes.push(NoteAdded { leaf: s.append(&c)?, commitment: c, amount: refund_units, record: records[3].try_into().unwrap() });
            }
            if referral > 0 {
                let c = commitment(&fee_coin, referral, &ref_hide)?;
                notes.push(NoteAdded { leaf: s.append(&c)?, commitment: c, amount: referral, record: records[4].try_into().unwrap() });
            }
        }
        a.in_reserve.reload()?;
        a.out_reserve.reload()?;
        covered(&a.in_entry, a.in_reserve.amount)?;
        covered(&a.out_entry, a.out_reserve.amount)?;
        emit!(Swapped { in_mint: a.in_entry.mint, out_mint: a.out_entry.mint, amount_in: tokens_in, spent, bought, fee: cut, refund });
        for n in notes {
            emit_cpi!(n);
        }
        if referral > 0 {
            emit_cpi!(Referred { amount: referral });
        }
        Ok(())
    }

    /// Pays out a coin's accrued swap fees: the builder's share (20%, or 10% of referred swaps) to the builder, the rest
    /// (80% of every swap's fee) to the fee wallet. Anyone may call it.
    pub fn collect_fees(mut ctx: Context<CollectFees>) -> Result<()> {
        let (fee_wallet, builder, bump) = {
            let s = ctx.accounts.state.load()?;
            (s.fee_wallet, s.builder, s.bump)
        };
        let a = &mut ctx.accounts;
        // Only the two wallets' associated accounts: every collection then shows up in one account's history.
        require_keys_eq!(a.fee_token.key(), get_associated_token_address_with_program_id(&fee_wallet, &a.entry.mint, &a.entry.token_program), DpError::BadAccount);
        require_keys_eq!(a.builder_token.key(), get_associated_token_address_with_program_id(&builder, &a.entry.mint, &a.entry.token_program), DpError::BadAccount);
        let (amount, to_builder) = (a.entry.fees, a.entry.builder_fees);
        require!(amount > 0 && to_builder <= amount, DpError::BadAmount);
        a.entry.fees = 0;
        a.entry.builder_fees = 0;
        let seeds: &[&[u8]] = &[STATE_SEED, &[bump]];
        let (tp, reserve, mint, state) = (a.token_program.to_account_info(), a.reserve.to_account_info(), a.mint.to_account_info(), a.state.to_account_info());
        pay(&tp, &reserve, &mint, &a.builder_token.to_account_info(), &state, seeds, to_builder, a.mint.decimals)?;
        pay(&tp, &reserve, &mint, &a.fee_token.to_account_info(), &state, seeds, amount - to_builder, a.mint.decimals)?;
        a.reserve.reload()?;
        covered(&a.entry, a.reserve.amount)?;
        let mint = a.entry.mint;
        // Recorded as a self-call (like notes): only this program can produce it, and logs cannot truncate it.
        emit_cpi!(FeesCollected { mint, amount, to_builder });
        Ok(())
    }
}

/// `amount` × `rate` / 10 000, computed wide so no amount can overflow.
fn bps(amount: u64, rate: u64) -> u64 {
    (amount as u128 * rate as u128 / 10_000) as u64
}

/* ---------- checks shared by spends ---------- */

fn upgrade_authority_is(program_data: &AccountInfo, who: &Pubkey) -> Result<()> {
    let expected = Pubkey::find_program_address(&[crate::ID.as_ref()], &bpf_loader_upgradeable::ID).0;
    require_keys_eq!(*program_data.key, expected, DpError::Unauthorized);
    let d = program_data.try_borrow_data()?;
    // UpgradeableLoaderState::ProgramData { slot: u64, upgrade_authority_address: Option<Pubkey> } after a u32 tag 3.
    let ok = d.len() >= 45 && d[..4] == 3u32.to_le_bytes() && d[12] == 1 && d[13..45] == who.to_bytes();
    require!(ok, DpError::Unauthorized);
    Ok(())
}

fn check_spend(state: &State, h: &SpendHead, coin: Fe, ext: Fe) -> Result<()> {
    require!(state.knows(&h.root), DpError::UnknownRoot);
    require!(Clock::get()?.unix_timestamp <= h.expiry, DpError::Expired);
    let public_coin = if h.public_amount > 0 { coin } else { ZERO };
    let signals = [h.markers[0], h.markers[1], h.markers[2], h.markers[3], h.outputs[0], h.outputs[1], h.root, public_coin, be(h.public_amount), ext];
    verify(&h.proof, &signals)
}

/// Checks a spend of `entry`'s coin. For the vault coin with fine shares, a proof over the coin of notes made before
/// the change is accepted too; returns true then (its amounts count VAULT_SCALE fine shares per unit).
fn check_spend_coin(state: &State, h: &SpendHead, entry: &TokenEntry, ext: Fe) -> Result<bool> {
    match check_spend(state, h, entry.coin, ext) {
        Ok(()) => Ok(false),
        Err(e) if entry.vault == 2 && is_invalid_proof(&e) => check_spend(state, h, coin_id(&entry.mint), ext).map(|_| true),
        Err(e) => Err(e),
    }
}

fn is_invalid_proof(e: &anchor_lang::error::Error) -> bool {
    matches!(e, anchor_lang::error::Error::AnchorError(ae) if ae.error_code_number == u32::from(DpError::InvalidProof))
}

/// A spent amount in the entry's own units: fine shares for the vault coin with fine shares.
fn spend_units(_entry: &TokenEntry, legacy: bool, units: u64) -> Result<u64> {
    if legacy { units.checked_mul(VAULT_SCALE).ok_or(error!(DpError::BadAmount)) } else { Ok(units) }
}

/// Each spent marker becomes an empty account owned by this program at ["spent", marker]; a note can only be spent
/// once because that account can only be created once. Zero markers are unused input slots.
fn mark_spent<'i>(payer: &AccountInfo<'i>, accounts: &[AccountInfo<'i>; 4], system: &AccountInfo<'i>, markers: &[Fe; 4]) -> Result<()> {
    require!(markers.iter().any(|m| *m != ZERO), DpError::NothingSpent);
    for i in 0..4 {
        let m = &markers[i];
        if *m == ZERO {
            continue;
        }
        require!(markers[..i].iter().all(|x| x != m), DpError::DuplicateNote);
        let (at, bump) = Pubkey::find_program_address(&[b"spent", m], &crate::ID);
        require_keys_eq!(*accounts[i].key, at, DpError::BadAccount);
        require!(*accounts[i].owner != crate::ID, DpError::AlreadySpent);
        create_at(payer, &accounts[i], system, &[b"spent", m, &[bump]], 0, &crate::ID)?;
    }
    Ok(())
}

fn append_outputs(state: &mut State, outputs: &[Fe; 2], records: &[&[u8]; 2]) -> Result<Vec<NoteAdded>> {
    let mut out = Vec::with_capacity(4);
    for (c, rec) in outputs.iter().zip(records) {
        if *c == ZERO {
            continue;
        }
        out.push(NoteAdded { leaf: state.append(c)?, commitment: *c, amount: 0, record: (*rec).try_into().unwrap() });
    }
    Ok(out)
}

/// What the reserve owes: the notes' tokens (for the vault coin, its backing) plus uncollected fees.
fn covered(entry: &TokenEntry, reserve_amount: u64) -> Result<()> {
    let owed = if entry.vault != 0 { entry.backing } else { entry.shielded };
    require!(reserve_amount as u128 >= owed as u128 + entry.fees as u128, DpError::Undercollateralized);
    Ok(())
}

/// Vault coin: shares worth `assets` tokens, rounded down. `shielded` counts shares, `backing` the tokens behind them.
fn to_shares(e: &TokenEntry, assets: u64) -> Result<u64> {
    u64::try_from(assets as u128 * (e.shielded as u128 + VIRTUAL_SHARES) / (e.backing as u128 + 1)).map_err(|_| error!(DpError::BadAmount))
}
/// Vault coin: tokens `shares` are worth, rounded down.
fn to_assets(e: &TokenEntry, shares: u64) -> Result<u64> {
    u64::try_from(shares as u128 * (e.backing as u128 + 1) / (e.shielded as u128 + VIRTUAL_SHARES)).map_err(|_| error!(DpError::BadAmount))
}
/// `tokens` enter the pool as a note: returns the note's amount (the tokens, or the vault coin's shares for them)
/// and books both.
fn enter(e: &mut TokenEntry, tokens: u64) -> Result<u64> {
    let units = if e.vault != 0 { to_shares(e, tokens)? } else { tokens };
    require!(units > 0 || tokens == 0, DpError::BadAmount);
    if e.vault != 0 {
        e.backing = e.backing.checked_add(tokens).ok_or(DpError::BadAmount)?;
    }
    e.shielded = e.shielded.checked_add(units).ok_or(DpError::BadAmount)?;
    Ok(units)
}

/// Like `enter`, except that tokens worth less than one vault share are added to the vault's backing (no note).
fn enter_or_dust(e: &mut TokenEntry, tokens: u64) -> Result<u64> {
    if e.vault != 0 && to_shares(e, tokens)? == 0 {
        e.backing = e.backing.checked_add(tokens).ok_or(DpError::BadAmount)?;
        return Ok(0);
    }
    enter(e, tokens)
}

/// A relayer's token account for `mint`, owned by the relayer.
fn relayer_account<'i>(acc: &Option<UncheckedAccount<'i>>, relayer: &Pubkey, mint: &Pubkey) -> Result<AccountInfo<'i>> {
    let acc = acc.as_ref().ok_or(DpError::MissingAccount)?.to_account_info();
    require_keys_eq!(token_owner(&acc)?, *relayer, DpError::BadAccount);
    require_keys_eq!(token_mint(&acc)?, *mint, DpError::BadAccount);
    Ok(acc)
}

/// Pays what leaves the pool in a transact: `payout` to the recipient and the fee to the relayer.
fn release<'info>(ctx: &mut Context<'_, '_, 'info, 'info, Transact<'info>>, h: &SpendHead, payout: u64, legacy: bool) -> Result<()> {
    let state_bump = ctx.accounts.state.load()?.bump;
    let a = &mut ctx.accounts;
    let entry = a.entry.as_mut().ok_or(DpError::MissingAccount)?;
    let mint = a.mint.as_ref().ok_or(DpError::MissingAccount)?;
    let reserve = a.reserve.as_mut().ok_or(DpError::MissingAccount)?;
    let tp = a.token_program.as_ref().ok_or(DpError::MissingAccount)?;
    require_keys_eq!(entry.mint, mint.key(), DpError::BadAccount);
    require_keys_eq!(entry.reserve, reserve.key(), DpError::BadAccount);
    require_keys_eq!(entry.token_program, tp.key(), DpError::BadAccount);
    // For the vault coin, the spent shares are paid out as the tokens they are worth (the fee likewise).
    let spent_units = spend_units(entry, legacy, h.public_amount)?;
    let (total, payout, fee) = if entry.vault != 0 {
        let total = to_assets(entry, spent_units)?;
        let fee = to_assets(entry, spend_units(entry, legacy, h.fee)?)?;
        (total, total - fee, fee)
    } else {
        (h.public_amount, payout, h.fee)
    };
    if entry.vault != 0 {
        entry.backing = entry.backing.checked_sub(total).ok_or(DpError::BadAmount)?;
    }
    entry.shielded = entry.shielded.checked_sub(spent_units).ok_or(DpError::BadAmount)?;
    let (relayer, system, state) = (a.relayer.to_account_info(), a.system_program.to_account_info(), a.state.to_account_info());
    let seeds: &[&[u8]] = &[STATE_SEED, &[state_bump]];
    if entry.mint == WSOL {
        // All of it arrives at the relayer as lamports; the recipient's part is passed straight on.
        let tmp = a.sol_tmp.as_ref().ok_or(DpError::MissingAccount)?.to_account_info();
        unwrap_to_payer(&relayer, &tmp, &reserve.to_account_info(), &mint.to_account_info(), &state, &tp.to_account_info(), &system, state_bump, total)?;
        if payout > 0 {
            send_lamports(&relayer, &a.recipient.as_ref().ok_or(DpError::MissingAccount)?.to_account_info(), &system, payout)?;
        }
    } else {
        if payout > 0 {
            let recipient = a.recipient.as_ref().ok_or(DpError::MissingAccount)?;
            let ata = a.recipient_token.as_ref().ok_or(DpError::MissingAccount)?;
            require_keys_eq!(ata.key(), get_associated_token_address_with_program_id(recipient.key, &entry.mint, &entry.token_program), DpError::BadAccount);
            if ata.data_is_empty() {
                let atp = a.associated_token_program.as_ref().ok_or(DpError::MissingAccount)?;
                anchor_spl::associated_token::create(CpiContext::new(atp.to_account_info(), anchor_spl::associated_token::Create {
                    payer: relayer.clone(), associated_token: ata.to_account_info(), authority: recipient.to_account_info(), mint: mint.to_account_info(), system_program: system.clone(), token_program: tp.to_account_info() }))?;
            }
            pay(&tp.to_account_info(), &reserve.to_account_info(), &mint.to_account_info(), &ata.to_account_info(), &state, seeds, payout, mint.decimals)?;
        }
        if fee > 0 {
            let to = relayer_account(&a.relayer_token, a.relayer.key, &entry.mint)?;
            pay(&tp.to_account_info(), &reserve.to_account_info(), &mint.to_account_info(), &to, &state, seeds, fee, mint.decimals)?;
        }
    }
    reserve.reload()?;
    covered(entry, reserve.amount)?;
    emit!(Unshielded { mint: entry.mint, amount: payout, fee });
    Ok(())
}

/// Moves the trade input to the router's account, runs Jupiter signed as the router, measures what was spent and
/// received, and returns everything the router holds to the reserves.
fn run_route<'info>(ctx: &Context<'_, '_, 'info, 'info, Swap<'info>>, trade_in: u64, route: &[u8], state_seeds: &[&[u8]]) -> Result<(u64, u64)> {
    let a = &ctx.accounts;
    let router_bump = a.state.load()?.router_bump;
    require_keys_eq!(a.router_in.key(), get_associated_token_address_with_program_id(&a.router.key(), &a.in_entry.mint, &a.in_entry.token_program), DpError::BadAccount);
    require_keys_eq!(a.router_out.key(), get_associated_token_address_with_program_id(&a.router.key(), &a.out_entry.mint, &a.out_entry.token_program), DpError::BadAccount);
    let guarded = [a.state.key(), a.in_reserve.key(), a.out_reserve.key(), a.stage.key()];
    require!(ctx.remaining_accounts.iter().all(|x| !guarded.contains(x.key)), DpError::RouteRejected);
    let (in_info, out_info, router) = (a.router_in.to_account_info(), a.router_out.to_account_info(), a.router.to_account_info());
    pay(&a.in_token_program.to_account_info(), &a.in_reserve.to_account_info(), &a.in_mint.to_account_info(), &in_info, &a.state.to_account_info(), state_seeds, trade_in, a.in_mint.decimals)?;
    let (in0, out0) = (token_amount(&in_info)?, token_amount(&out_info)?);
    let metas = ctx.remaining_accounts.iter().map(|x| AccountMeta { pubkey: *x.key, is_signer: x.is_signer || *x.key == router.key(), is_writable: x.is_writable }).collect();
    let mut infos = ctx.remaining_accounts.to_vec();
    let program = a.route_program.to_account_info();
    require!(program.executable && *program.key != crate::ID && a.state.load()?.routers.contains(program.key), DpError::RouteRejected);
    infos.push(program.clone());
    let router_seeds: &[&[u8]] = &[ROUTER_SEED, &[router_bump]];
    invoke_signed(&Instruction { program_id: *program.key, accounts: metas, data: route.to_vec() }, &infos, &[router_seeds])?;
    // Whatever the routing program did with the router's signature, the router must be left as it was: a plain system
    // account, and token accounts it still owns with no delegate and no close authority.
    require!(router.owner == &anchor_lang::system_program::ID && router.data_is_empty(), DpError::RouteRejected);
    router_account_intact(&in_info, &router.key())?;
    router_account_intact(&out_info, &router.key())?;
    let (in1, out1) = (token_amount(&in_info)?, token_amount(&out_info)?);
    let spent = in0.checked_sub(in1).ok_or(DpError::RouteRejected)?;
    let got = out1.checked_sub(out0).ok_or(DpError::RouteRejected)?;
    require!(spent <= trade_in, DpError::RouteOverspent);
    pay(&a.in_token_program.to_account_info(), &in_info, &a.in_mint.to_account_info(), &a.in_reserve.to_account_info(), &router, router_seeds, in1, a.in_mint.decimals)?;
    pay(&a.out_token_program.to_account_info(), &out_info, &a.out_mint.to_account_info(), &a.out_reserve.to_account_info(), &router, router_seeds, out1, a.out_mint.decimals)?;
    Ok((spent, got))
}

/* ---------- accounts ---------- */

#[derive(Accounts)]
pub struct Configure<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,
    #[account(init, payer = authority, space = 8 + core::mem::size_of::<State>(), seeds = [STATE_SEED], bump)]
    pub state: AccountLoader<'info, State>,
    /// CHECK: this program's ProgramData account, read for its upgrade authority.
    pub program_data: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct SetVault<'info> {
    pub authority: Signer<'info>,
    #[account(mut, seeds = [STATE_SEED], bump)]
    pub state: AccountLoader<'info, State>,
    /// CHECK: the vault coin's mint address (it may not exist yet; only its address is recorded).
    pub mint: UncheckedAccount<'info>,
    /// CHECK: the coin's (not yet created) entry address, checked in set_vault.
    pub entry: UncheckedAccount<'info>,
    /// CHECK: this program's ProgramData account, read for its upgrade authority.
    pub program_data: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct UpgradeVault<'info> {
    pub authority: Signer<'info>,
    #[account(seeds = [STATE_SEED], bump)]
    pub state: AccountLoader<'info, State>,
    #[account(mut)]
    pub entry: Box<Account<'info, TokenEntry>>,
    /// CHECK: this program's ProgramData account, read for its upgrade authority.
    pub program_data: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct SetRouter<'info> {
    pub authority: Signer<'info>,
    #[account(mut, seeds = [STATE_SEED], bump)]
    pub state: AccountLoader<'info, State>,
    /// CHECK: this program's ProgramData account, read for its upgrade authority.
    pub program_data: UncheckedAccount<'info>,
}

#[event_cpi]
#[derive(Accounts)]
pub struct Donate<'info> {
    pub donor: Signer<'info>,
    #[account(mut, has_one = mint @ DpError::BadAccount, has_one = reserve @ DpError::BadAccount)]
    pub entry: Box<Account<'info, TokenEntry>>,
    pub mint: Box<InterfaceAccount<'info, Mint>>,
    #[account(mut)]
    pub reserve: Box<InterfaceAccount<'info, TokenAccount>>,
    #[account(mut, token::mint = mint, token::authority = donor)]
    pub donor_token: Box<InterfaceAccount<'info, TokenAccount>>,
    #[account(address = entry.token_program @ DpError::BadAccount)]
    pub token_program: Interface<'info, TokenInterface>,
}

#[derive(Accounts)]
pub struct ListCoin<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(seeds = [STATE_SEED], bump)]
    pub state: AccountLoader<'info, State>,
    pub mint: Box<InterfaceAccount<'info, Mint>>,
    #[account(init, payer = payer, space = TokenEntry::SPACE, seeds = [b"coin", mint.key().as_ref()], bump)]
    pub entry: Box<Account<'info, TokenEntry>>,
    #[account(init, payer = payer, seeds = [b"reserve", mint.key().as_ref()], bump, token::mint = mint, token::authority = state, token::token_program = token_program)]
    pub reserve: Box<InterfaceAccount<'info, TokenAccount>>,
    pub token_program: Interface<'info, TokenInterface>,
    pub system_program: Program<'info, System>,
}

#[event_cpi]
#[derive(Accounts)]
pub struct Shield<'info> {
    #[account(mut)]
    pub depositor: Signer<'info>,
    #[account(mut, seeds = [STATE_SEED], bump)]
    pub state: AccountLoader<'info, State>,
    #[account(mut, has_one = mint @ DpError::BadAccount, has_one = reserve @ DpError::BadAccount)]
    pub entry: Box<Account<'info, TokenEntry>>,
    pub mint: Box<InterfaceAccount<'info, Mint>>,
    #[account(mut)]
    pub reserve: Box<InterfaceAccount<'info, TokenAccount>>,
    #[account(mut, token::mint = mint, token::authority = depositor)]
    pub depositor_token: Option<Box<InterfaceAccount<'info, TokenAccount>>>,
    #[account(address = entry.token_program @ DpError::BadAccount)]
    pub token_program: Interface<'info, TokenInterface>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(stage_id: u64, len: u32)]
pub struct StageOpen<'info> {
    #[account(mut)]
    pub relayer: Signer<'info>,
    #[account(init, payer = relayer, space = 8 + 32 + 4 + len as usize, seeds = [b"stage", relayer.key().as_ref(), &stage_id.to_le_bytes()], bump)]
    pub stage: Box<Account<'info, Stage>>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(stage_id: u64)]
pub struct StageWrite<'info> {
    pub relayer: Signer<'info>,
    #[account(mut, seeds = [b"stage", relayer.key().as_ref(), &stage_id.to_le_bytes()], bump)]
    pub stage: Box<Account<'info, Stage>>,
}

#[derive(Accounts)]
#[instruction(stage_id: u64)]
pub struct StageDiscard<'info> {
    #[account(mut)]
    pub relayer: Signer<'info>,
    #[account(mut, close = relayer, seeds = [b"stage", relayer.key().as_ref(), &stage_id.to_le_bytes()], bump)]
    pub stage: Box<Account<'info, Stage>>,
}

#[event_cpi]
#[derive(Accounts)]
#[instruction(stage_id: u64)]
pub struct Transact<'info> {
    #[account(mut)]
    pub relayer: Signer<'info>,
    #[account(mut, seeds = [STATE_SEED], bump)]
    pub state: AccountLoader<'info, State>,
    #[account(mut, close = relayer, seeds = [b"stage", relayer.key().as_ref(), &stage_id.to_le_bytes()], bump)]
    pub stage: Box<Account<'info, Stage>>,
    /// CHECK: spent-marker addresses (checked and created in mark_spent); unused slots may be any account.
    pub marker0: UncheckedAccount<'info>,
    /// CHECK: as marker0.
    pub marker1: UncheckedAccount<'info>,
    /// CHECK: as marker0.
    pub marker2: UncheckedAccount<'info>,
    /// CHECK: as marker0.
    pub marker3: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
    // Only when something leaves the pool (an unshield or a relayer fee):
    #[account(mut)]
    pub entry: Option<Box<Account<'info, TokenEntry>>>,
    pub mint: Option<Box<InterfaceAccount<'info, Mint>>>,
    #[account(mut)]
    pub reserve: Option<Box<InterfaceAccount<'info, TokenAccount>>>,
    /// CHECK: the unshield recipient, bound by the proof.
    #[account(mut)]
    pub recipient: Option<UncheckedAccount<'info>>,
    /// CHECK: the recipient's associated token account (checked in release; created if missing).
    #[account(mut)]
    pub recipient_token: Option<UncheckedAccount<'info>>,
    /// CHECK: the relayer's token account for a fee paid in a token (checked in relayer_account).
    #[account(mut)]
    pub relayer_token: Option<UncheckedAccount<'info>>,
    /// CHECK: the temporary account SOL is unwrapped through (checked in unwrap_to_payer).
    #[account(mut)]
    pub sol_tmp: Option<UncheckedAccount<'info>>,
    pub token_program: Option<Interface<'info, TokenInterface>>,
    pub associated_token_program: Option<Program<'info, AssociatedToken>>,
}

#[event_cpi]
#[derive(Accounts)]
#[instruction(stage_id: u64)]
pub struct Swap<'info> {
    #[account(mut)]
    pub relayer: Signer<'info>,
    #[account(mut, seeds = [STATE_SEED], bump)]
    pub state: AccountLoader<'info, State>,
    #[account(mut, close = relayer, seeds = [b"stage", relayer.key().as_ref(), &stage_id.to_le_bytes()], bump)]
    pub stage: Box<Account<'info, Stage>>,
    /// CHECK: spent-marker addresses (checked and created in mark_spent); unused slots may be any account.
    pub marker0: UncheckedAccount<'info>,
    /// CHECK: as marker0.
    pub marker1: UncheckedAccount<'info>,
    /// CHECK: as marker0.
    pub marker2: UncheckedAccount<'info>,
    /// CHECK: as marker0.
    pub marker3: UncheckedAccount<'info>,
    #[account(mut, constraint = in_entry.mint == in_mint.key() @ DpError::BadAccount)]
    pub in_entry: Box<Account<'info, TokenEntry>>,
    #[account(mut, constraint = out_entry.mint == out_mint.key() @ DpError::BadAccount)]
    pub out_entry: Box<Account<'info, TokenEntry>>,
    pub in_mint: Box<InterfaceAccount<'info, Mint>>,
    pub out_mint: Box<InterfaceAccount<'info, Mint>>,
    #[account(mut, address = in_entry.reserve @ DpError::BadAccount)]
    pub in_reserve: Box<InterfaceAccount<'info, TokenAccount>>,
    #[account(mut, address = out_entry.reserve @ DpError::BadAccount)]
    pub out_reserve: Box<InterfaceAccount<'info, TokenAccount>>,
    /// CHECK: the router address, which signs Jupiter's instruction and holds only the trade in progress.
    #[account(seeds = [ROUTER_SEED], bump)]
    pub router: UncheckedAccount<'info>,
    /// CHECK: the router's associated token accounts for the two coins (checked in run_route).
    #[account(mut)]
    pub router_in: UncheckedAccount<'info>,
    /// CHECK: as router_in.
    #[account(mut)]
    pub router_out: UncheckedAccount<'info>,
    /// CHECK: the relayer's token account for its fee (checked in relayer_account); needed when the fee is not 0.
    #[account(mut)]
    pub relayer_token: Option<UncheckedAccount<'info>>,
    #[account(address = in_entry.token_program @ DpError::BadAccount)]
    pub in_token_program: Interface<'info, TokenInterface>,
    #[account(address = out_entry.token_program @ DpError::BadAccount)]
    pub out_token_program: Interface<'info, TokenInterface>,
    /// CHECK: the routing program, bound by the proof (checked executable and not this program in run_route).
    pub route_program: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[event_cpi]
#[derive(Accounts)]
pub struct CollectFees<'info> {
    #[account(seeds = [STATE_SEED], bump)]
    pub state: AccountLoader<'info, State>,
    #[account(mut, has_one = mint @ DpError::BadAccount, has_one = reserve @ DpError::BadAccount)]
    pub entry: Box<Account<'info, TokenEntry>>,
    pub mint: Box<InterfaceAccount<'info, Mint>>,
    #[account(mut)]
    pub reserve: Box<InterfaceAccount<'info, TokenAccount>>,
    #[account(mut, token::mint = mint)]
    pub fee_token: Box<InterfaceAccount<'info, TokenAccount>>,
    #[account(mut, token::mint = mint)]
    pub builder_token: Box<InterfaceAccount<'info, TokenAccount>>,
    #[account(address = entry.token_program @ DpError::BadAccount)]
    pub token_program: Interface<'info, TokenInterface>,
}

/* ---------- events ---------- */

#[event]
pub struct NoteAdded {
    pub leaf: u64,
    pub commitment: [u8; 32],
    /// Public already for notes the program makes itself (shields, bought and refund notes); 0 otherwise.
    pub amount: u64,
    pub record: [u8; RECORD],
}
#[event]
pub struct Shielded {
    pub mint: Pubkey,
    pub amount: u64,
}
#[event]
pub struct Unshielded {
    pub mint: Pubkey,
    pub amount: u64,
    pub fee: u64,
}
#[event]
pub struct Swapped {
    pub in_mint: Pubkey,
    pub out_mint: Pubkey,
    pub amount_in: u64,
    pub spent: u64,
    pub bought: u64,
    pub fee: u64,
    pub refund: u64,
}
/// Tokens added to the vault (a self-call record): the vault coin's shares are worth more.
#[event]
pub struct Donated {
    pub amount: u64,
}
/// A referred swap's referral note (a self-call record, like notes): its amount in the fee's coin.
#[event]
pub struct Referred {
    pub amount: u64,
}
#[event]
pub struct FeesCollected {
    pub mint: Pubkey,
    pub amount: u64,
    pub to_builder: u64,
}
