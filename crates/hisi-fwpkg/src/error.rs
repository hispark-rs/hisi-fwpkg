//! Error types for `ws63-fwpkg`.

/// Result alias used throughout the crate.
pub type Result<T> = core::result::Result<T, Error>;

/// Errors produced while building WS63 images and fwpkg packages.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An I/O error occurred.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// A partition name was too long for the fwpkg V1 32-byte name field.
    #[error("partition name {name:?} is {len} bytes, max is {max} (V1 fwpkg)")]
    NameTooLong {
        /// The offending name.
        name: String,
        /// Its length in bytes.
        len: usize,
        /// Maximum allowed length.
        max: usize,
    },

    /// The fwpkg would contain no partitions.
    #[error("fwpkg must contain at least one partition")]
    EmptyPackage,

    /// The fwpkg bytes are malformed or internally inconsistent.
    #[error("invalid fwpkg: {0}")]
    InvalidFwpkg(String),

    /// ELF parsing/flattening failed.
    #[error("elf error: {0}")]
    Elf(String),

    /// A field value did not fit the on-disk layout.
    #[error("value out of range: {0}")]
    OutOfRange(String),
}
