use ring::hmac;
use ring::rand::SecureRandom;
use ring::signature as ring_signature;

use crate::types::Base64UrlEncodedBytes;
use crate::{JsonWebKey, SignatureVerificationError, SigningError};

use super::{jwk::CoreJsonCurveType, CoreJsonWebKey, CoreJsonWebKeyType};

use std::ops::Deref;

pub fn sign_hmac(key: &[u8], hmac_alg: hmac::Algorithm, msg: &[u8]) -> hmac::Tag {
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
    } else{
        let n = key.n.as_ref().ok_or_else(|| "RSA modulus `n` is missing".to_string())?;
        let e = key.e.as_ref().ok_or_else(|| "RSA exponent `e` is missing".to_string())?;
        Ok((n,e))
    }
}

fn ec_public_key(
    key: &CoreJsonWebKey,
) -> Result<(&Base64UrlEncodedBytes, &Base64UrlEncodedBytes, &CoreJsonCurveType), String> {
    if *key.key_type() != CoreJsonWebKeyType::EllipticCurve {
        Err("EC key required".to_string())
    } else {
        let x = key.x.as_ref().ok_or_else(|| "EC `x` part is missing".to_string())?;
        let y = key.y.as_ref().ok_or_else(|| "EC `y` part is missing".to_string())?;
        let crv = key.crv.as_ref().ok_or_else(|| "EC `crv` part is missing".to_string())?;
        Ok((x, y, crv))
    }
}

pub fn verify_rsa_signature(
    key: &CoreJsonWebKey,
    params: &ring_signature::RsaParameters,
    msg: &[u8],
    signature: &[u8],
) -> Result<(), SignatureVerificationError> {
    let (n, e) = rsa_public_key(&key).map_err(SignatureVerificationError::InvalidKey)?;
    let public_key = ring_signature::RsaPublicKeyComponents {
        n: n.deref(),
        e: e.deref(),
    };

    public_key
        .verify(params, msg, signature)
        .map_err(|_| SignatureVerificationError::CryptoError("bad signature".to_string()))
}

pub fn verify_ec_signature(
    key: &CoreJsonWebKey,
    params: &'static ring_signature::EcdsaVerificationAlgorithm,
    msg: &[u8],
    signature: &[u8],
) -> Result<(), SignatureVerificationError> {
    let (x, y, crv) = ec_public_key(&key).map_err(SignatureVerificationError::InvalidKey)?;
    if *crv == CoreJsonCurveType::P521{
        return Err(SignatureVerificationError::UnsupportedAlg("Only P256 and P384 are supported for now".to_string()));
    }
    let mut pk = vec![0x04];
    pk.extend(x.deref());
    pk.extend(y.deref());
    let public_key = ring_signature::UnparsedPublicKey::new(params, pk);
    public_key.verify(msg, signature)
    .map_err(|_| SignatureVerificationError::CryptoError("EC Signature was wrong".to_string()))
}