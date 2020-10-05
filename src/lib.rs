mod decrypt;
mod error;

pub use error::*;
pub use decrypt::*;

#[cfg(test)]
mod tests {
    use crate::decrypt::decrypt;

    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }

    #[test]
    fn a() {

    }
}
