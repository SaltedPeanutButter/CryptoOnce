//! # CryptoOnce
//!
//! [`CryptoOnce`](crate) provides a simple interface for lay users to implement encryption, but
//! with special tweaks. Encryption keys are a group of unordered, commonly used English words.
//! But of course, users may choose to use a different key altogether.
//!
//! Anything can be used as key as long as it implements the trait [`CKey`]. The trait is implements
//! for common types like [`String`], slices of [`str`], and collections of such types.
//!
//! Internally, the key is converted to an 256-bit key using PBKDF2, then data is encrypted using
//! AES-256 algorithm. Do note that all operations occur in-memory, so the size of data is limited
//! by the amount of memory available.
//!
//! Warning: This default method is vulnerable to bruteforce attacks. Therefore, users are
//! encouraged to use their own passphrase with numbers, special characters, etc.

mod kdf;

pub fn add(left: usize, right: usize) -> usize {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
