/// Crate's result
pub type Result<T> = std::result::Result<T, Error>;

macro_rules! create_error {
    ($($(#[$attr:meta])* $error:ty => $name:ident)*) => {
        /// Crate's auto generated error
        #[derive(Debug)]
        pub enum Error {
            /// Indicates a static error message
            Message(&'static str),
            $(
            $(#[$attr])*
            $name($error)
            ),*
        }
        $(
            impl From<$error> for Error {
                fn from(x: $error) -> Self {
                    Error::$name(x)
                }
            }
        )*
    };
}

create_error! {
    std::io::Error => Io
    block_modes::InvalidKeyIvLength => Iv
    block_modes::BlockModeError => BlockMode
}
