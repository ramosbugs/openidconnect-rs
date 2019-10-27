use ring::hmac;
use ring::rand::SecureRandom;
use ring::signature as ring_signature;

use crate::types::Base64UrlEncodedBytes;
use crate::{JsonWebKey, SignatureVerificationError, SigningError};

use super::{CoreJsonWebKey, CoreJsonWebKeyType};

use std::ops::Deref;

pub fn sign_hmac(
    key: &[u8],
    hmac_alg: hmac::Algorithm,
    msg: &[u8],
) -> hmac::Tag {
    let signing_key = hmac::Key::new(hmac_alg, key);
    hmac::sign(&signing_key, msg)
}

pub fn verify_hmac(
    key: &CoreJsonWebKey,
    hmac_alg: hmac::Algorithm,
    msg: &[u8],
    signature: &[u8],
) -> Result<(), SignatureVerificationError> {
    let k = key.k.as_ref().ok_or_else(|| {
        SignatureVerificationError::InvalidKey("Symmetric key `k` is missing".to_string())
    })?;
    let verification_key = hmac::Key::new(hmac_alg, k);
    hmac::verify(&verification_key, msg, signature)
        .map_err(|_| SignatureVerificationError::CryptoError("bad HMAC".to_string()))
}

pub fn sign_rsa(
    key: &ring_signature::RsaKeyPair,
    padding_alg: &'static dyn ring_signature::RsaEncoding,
    rng: &dyn SecureRandom,
    msg: &[u8],
) -> Result<Vec<u8>, SigningError> {
    let sig_len = key.public_modulus_len();
    let mut sig = vec![0; sig_len];
    key.sign(padding_alg, rng, msg, &mut sig)
        .map_err(|_| SigningError::CryptoError)?;
    Ok(sig)
}

fn rsa_public_key(
    key: &CoreJsonWebKey,
) -> Result<(&Base64UrlEncodedBytes, &Base64UrlEncodedBytes), String> {
    if *key.key_type() != CoreJsonWebKeyType::RSA {
        Err("RSA key required".to_string())
    } else if let Some(n) = key.n.as_ref() {
        if let Some(e) = key.e.as_ref() {
            Ok((n, e))
        } else {
            Err("RSA exponent `e` is missing".to_string())
        }
    } else {
        Err("RSA modulus `n` is missing".to_string())
    }
}

pub fn verify_rsa_signature(
    key: &CoreJsonWebKey,
    params: &ring_signature::RsaParameters,
    msg: &[u8],
    signature: &[u8],
) -> Result<(), SignatureVerificationError> {
    let (n, e) = rsa_public_key(&key).map_err(SignatureVerificationError::InvalidKey)?;
    let public_key = ring_signature::RsaPublicKeyComponents { n: n.deref(), e: e.deref() };

    public_key
        .verify(params, msg, signature)
        .map_err(|_| SignatureVerificationError::CryptoError("bad signature".to_string()))
}
