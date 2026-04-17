use super::expr::Expr;

/// An nftables rule and its decoded expressions.
#[derive(Debug, Clone)]
pub struct NftRule {
    pub table: String,
    pub chain: String,
    pub handle: u64,
    pub exprs: Vec<Expr>,
}
