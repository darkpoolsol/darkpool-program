use anchor_lang::prelude::*;

/// Order matters: clients map codes 6000 + n to these.
#[error_code]
pub enum DpError {
    #[msg("signer is not the program's upgrade authority")]
    Unauthorized,
    #[msg("this coin cannot be listed")]
    UnsupportedCoin,
    #[msg("amount is zero or out of range")]
    BadAmount,
    #[msg("the token transfer moved a different amount")]
    TransferMismatch,
    #[msg("an account does not match")]
    BadAccount,
    #[msg("an account this action needs is missing")]
    MissingAccount,
    #[msg("staged data has the wrong layout")]
    BadStage,
    #[msg("proof did not verify")]
    InvalidProof,
    #[msg("hash input out of range")]
    HashInput,
    #[msg("the note tree is full")]
    TreeFull,
    #[msg("proof refers to an unknown tree root")]
    UnknownRoot,
    #[msg("the action expired")]
    Expired,
    #[msg("the action spends no note")]
    NothingSpent,
    #[msg("a note appears twice")]
    DuplicateNote,
    #[msg("a note is already spent")]
    AlreadySpent,
    #[msg("relayer fee exceeds the amount")]
    FeeTooHigh,
    #[msg("coin does not match the proof")]
    CoinMismatch,
    #[msg("a swap needs two different coins")]
    SameCoin,
    #[msg("route rejected")]
    RouteRejected,
    #[msg("the route spent more than its input")]
    RouteOverspent,
    #[msg("output below the holder's minimum")]
    BelowMinimum,
    #[msg("a reserve would hold less than its notes")]
    Undercollateralized,
    #[msg("the gift would make one vault share worth too much")]
    GiftTooLarge,
}
