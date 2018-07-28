
use ring::digest;
use ring::hmac;
use ring::signature as ring_signature;
use untrusted::Input;

use super::super::{
    JsonWebKey,
    SignatureVerificationError
};
use super::{
    CoreJsonWebKey,
    CoreJsonWebKeyType,
};

pub fn verify_hmac(
    key: &CoreJsonWebKey,
    digest_alg: &'static digest::Algorithm,
    msg: &str,
    signature: &[u8]
) -> Result<(), SignatureVerificationError> {
    if let Some(k) = key.k.as_ref() {
        let verification_key = hmac::VerificationKey::new(digest_alg, k);
        hmac::verify(&verification_key, msg.as_bytes(), signature)
            .map_err(|_| SignatureVerificationError::CryptoError("bad HMAC".to_string()))
    } else {
        Err(
            SignatureVerificationError::InvalidKey("Symmetric key `k` is missing".to_string())
        )
    }
}

pub fn verify_rsa_signature(
    key: &CoreJsonWebKey,
    params: &ring_signature::RSAParameters,
    msg: &str,
    signature: &[u8]
) -> Result<(), SignatureVerificationError> {
    if *key.key_type() != CoreJsonWebKeyType::RSA {
        return Err(SignatureVerificationError::InvalidKey("RSA key required".to_string()))
    }

    if let Some(n) = key.n.as_ref() {
        if let Some(e) = key.e.as_ref() {
            ring_signature::primitive::verify_rsa(
                params,
                (Input::from(n), Input::from(e)),
                Input::from(msg.as_bytes()),
                Input::from(signature),
            )
                .map_err(|_|
                    SignatureVerificationError::CryptoError(
                        "bad signature".to_string()
                    )
                )
        } else {
            Err(
                SignatureVerificationError::InvalidKey(
                    "RSA exponent `e` is missing".to_string()
                )
            )
        }
    } else {
        Err(
            SignatureVerificationError::InvalidKey(
                "RSA modulus `n` is missing".to_string()
            )
        )
    }
}
