/// Crate's result
pub type Result<T> = std::result::Result<T, Error>;

macro_rules! create_error {
    ($($error:ty => $name:ident)*) => {
        /// Crate's auto generated error
        #[derive(Debug)]
        pub enum Error {
            /// Indicates a static error message
            Message(&'static str),
            $(
            /// An auto-generated error entry
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
    ring::error::Unspecified => RingUnspecified
}
