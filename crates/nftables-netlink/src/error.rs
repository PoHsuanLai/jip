use thiserror::Error;

#[derive(Debug, Error)]
pub enum NftError {
    #[error("failed to open NETLINK_NETFILTER socket: {0}")]
    Socket(std::io::Error),

    #[error(
        "missing capability — CAP_NET_ADMIN required for write; read requires Linux 5.2+ for unprivileged access"
    )]
    MissingCapability,

    #[error("netlink send failed: {0}")]
    Send(std::io::Error),

    #[error("netlink recv failed: {0}")]
    Recv(std::io::Error),

    #[error("kernel returned netlink error: errno {0}")]
    KernelError(i32),

    #[error("malformed netlink message: {0}")]
    Parse(String),
}

impl From<NftError> for netcore::Error {
    fn from(e: NftError) -> Self {
        netcore::Error::Backend(e.to_string())
    }
}
