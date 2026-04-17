/// An nftables table.
#[derive(Debug, Clone)]
pub struct NftTable {
    pub family: u8,
    pub name: String,
    pub handle: u64,
}
