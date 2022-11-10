use crate::SigningError;
use ::ring::rand::SecureRandom;
use ::ring::signature as ring_signature;

mod ring;

/// Cryptography backend
pub trait Backend {
    fn sign_rsa(
        key: &ring_signature::RsaKeyPair,
        padding_alg: &'static dyn ring_signature::RsaEncoding,
        rng: &dyn SecureRandom,
        msg: &[u8],
    ) -> Result<Vec<u8>, SigningError>;
}

pub struct Ring;

impl Backend for Ring {
    fn sign_rsa(
        key: &ring_signature::RsaKeyPair,
        padding_alg: &'static dyn ring_signature::RsaEncoding,
        rng: &dyn SecureRandom,
        msg: &[u8],
    ) -> Result<Vec<u8>, SigningError> {
        ring::sign_rsa(key, padding_alg, rng, msg)
    }
}
