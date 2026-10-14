//! Moving tokens and SOL in and out of reserves.
use anchor_lang::prelude::*;
use anchor_lang::solana_program::{program::invoke, program::invoke_signed, system_instruction, system_program};
use anchor_spl::token_interface::{self as ti, TransferChecked};

use crate::errors::DpError;

pub const STATE_SEED: &[u8] = b"darkpool";
pub const ROUTER_SEED: &[u8] = b"router";
pub const SOL_TMP_SEED: &[u8] = b"sol-tmp";

/// A token transfer signed by a program address.
#[allow(clippy::too_many_arguments)]
pub fn pay<'i>(token_program: &AccountInfo<'i>, from: &AccountInfo<'i>, mint: &AccountInfo<'i>, to: &AccountInfo<'i>, authority: &AccountInfo<'i>,
               seeds: &[&[u8]], amount: u64, decimals: u8) -> Result<()> {
    if amount == 0 {
        return Ok(());
    }
    ti::transfer_checked(
        CpiContext::new_with_signer(token_program.clone(), TransferChecked { from: from.clone(), mint: mint.clone(), to: to.clone(), authority: authority.clone() }, &[seeds]),
        amount,
        decimals,
    )
}

/// The token amount field of a token account (SPL or Token-2022 layout).
pub fn token_amount(acc: &AccountInfo) -> Result<u64> {
    let d = acc.try_borrow_data()?;
    require!(d.len() >= 72, DpError::BadAccount);
    Ok(u64::from_le_bytes(d[64..72].try_into().unwrap()))
}
pub fn token_owner(acc: &AccountInfo) -> Result<Pubkey> {
    let d = acc.try_borrow_data()?;
    require!(d.len() >= 72, DpError::BadAccount);
    Ok(Pubkey::try_from(&d[32..64]).unwrap())
}
/// A router token account after a route: still owned by the router, no delegate, no close authority (SPL token
/// layout: delegate option at 72, close authority option at 129; Token-2022 shares the base layout).
pub fn router_account_intact(acc: &AccountInfo, router: &Pubkey) -> Result<()> {
    let d = acc.try_borrow_data()?;
    require!(d.len() >= 165, DpError::RouteRejected);
    require!(d[32..64] == router.to_bytes() && d[72..76] == [0u8; 4] && d[129..133] == [0u8; 4], DpError::RouteRejected);
    Ok(())
}
pub fn token_mint(acc: &AccountInfo) -> Result<Pubkey> {
    let d = acc.try_borrow_data()?;
    require!(d.len() >= 72, DpError::BadAccount);
    Ok(Pubkey::try_from(&d[0..32]).unwrap())
}

/// Creates a program address account, also when someone has already sent lamports to it (which would make a plain
/// create fail): tops it up to rent, then allocates and assigns it.
pub fn create_at<'i>(payer: &AccountInfo<'i>, target: &AccountInfo<'i>, system: &AccountInfo<'i>, seeds: &[&[u8]], space: usize, owner: &Pubkey) -> Result<()> {
    let need = Rent::get()?.minimum_balance(space);
    let have = target.lamports();
    if have == 0 {
        return invoke_signed(&system_instruction::create_account(payer.key, target.key, need, space as u64, owner), &[payer.clone(), target.clone(), system.clone()], &[seeds])
            .map_err(Into::into);
    }
    require_keys_eq!(*target.owner, system_program::ID, DpError::AlreadySpent);
    if need > have {
        invoke(&system_instruction::transfer(payer.key, target.key, need - have), &[payer.clone(), target.clone(), system.clone()])?;
    }
    invoke_signed(&system_instruction::allocate(target.key, space as u64), &[target.clone(), system.clone()], &[seeds])?;
    invoke_signed(&system_instruction::assign(target.key, owner), &[target.clone(), system.clone()], &[seeds])?;
    Ok(())
}

/// Turns `amount` of wrapped SOL in the reserve into lamports for the payer: a temporary token account is filled
/// and closed into the payer, who is then charged for what the payer does not keep (`to_others`, paid by the caller
/// with system transfers). Rent for the temporary account comes back to the payer in the close.
#[allow(clippy::too_many_arguments)]
pub fn unwrap_to_payer<'i>(payer: &AccountInfo<'i>, tmp: &AccountInfo<'i>, reserve: &AccountInfo<'i>, mint: &AccountInfo<'i>, state: &AccountInfo<'i>,
                           token_program: &AccountInfo<'i>, system: &AccountInfo<'i>, state_bump: u8, amount: u64) -> Result<()> {
    let (expected, bump) = Pubkey::find_program_address(&[SOL_TMP_SEED], &crate::ID);
    require_keys_eq!(*tmp.key, expected, DpError::BadAccount);
    create_at(payer, tmp, system, &[SOL_TMP_SEED, &[bump]], 165, token_program.key)?;
    ti::initialize_account3(CpiContext::new(token_program.clone(), ti::InitializeAccount3 { account: tmp.clone(), mint: mint.clone(), authority: state.clone() }))?;
    let seeds: &[&[u8]] = &[STATE_SEED, &[state_bump]];
    pay(token_program, reserve, mint, tmp, state, seeds, amount, 9)?;
    ti::close_account(CpiContext::new_with_signer(token_program.clone(), ti::CloseAccount { account: tmp.clone(), destination: payer.clone(), authority: state.clone() }, &[seeds]))
}

pub fn send_lamports<'i>(payer: &AccountInfo<'i>, to: &AccountInfo<'i>, system: &AccountInfo<'i>, lamports: u64) -> Result<()> {
    if lamports == 0 {
        return Ok(());
    }
    invoke(&system_instruction::transfer(payer.key, to.key, lamports), &[payer.clone(), to.clone(), system.clone()]).map_err(Into::into)
}

/// Classic SPL mints, or Token-2022 mints whose extensions are only metadata or groups. Anything able to move,
/// freeze or tax tokens in a reserve (permanent delegate, transfer fee or hook, default-frozen...) is refused.
pub fn listable(mint: &AccountInfo) -> Result<()> {
    if *mint.owner == anchor_spl::token::ID {
        return Ok(());
    }
    require_keys_eq!(*mint.owner, anchor_spl::token_2022::ID, DpError::UnsupportedCoin);
    let data = mint.try_borrow_data()?;
    if data.len() <= 82 {
        return Ok(());
    }
    // Extensions start after the 165-byte base (padded) and the account-type byte (1 = mint).
    require!(data.len() > 166 && data[165] == 1, DpError::UnsupportedCoin);
    let mut at = 166;
    while at + 4 <= data.len() {
        let kind = u16::from_le_bytes([data[at], data[at + 1]]);
        let len = u16::from_le_bytes([data[at + 2], data[at + 3]]) as usize;
        if kind == 0 {
            break;
        }
        // 18 metadata pointer, 19 metadata, 20 group pointer, 21 group, 22 member pointer, 23 member
        require!(matches!(kind, 18..=23), DpError::UnsupportedCoin);
        at += 4 + len;
    }
    Ok(())
}
