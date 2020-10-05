pub type Result<T> = std::result::Result<T, Error>;

macro_rules! create_error {
    ($($error:ty => $name:ident)*) => {
        #[derive(Debug)]
        pub enum Error {
            Message(&'static str),
            $(
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
    crypto::symmetriccipher::SymmetricCipherError => Cipher
}
