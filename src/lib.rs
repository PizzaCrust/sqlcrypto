mod decrypt;
mod error;

pub use error::*;
pub use decrypt::*;

#[cfg(test)]
mod tests {

    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }

}
