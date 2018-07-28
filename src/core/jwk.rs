use oauth2::helpers::variant_name;
use oauth2::prelude::*;
use ring::digest;
use ring::signature as ring_signature;

use super::super::{
    Base64UrlEncodedBytes,
    JsonWebKey,
    JsonWebKeyId,
    JsonWebKeyType,
    JsonWebKeyUse,
    JwsSigningAlgorithm,
    SignatureVerificationError,
};
use super::{
    CoreJwsSigningAlgorithm,
    crypto,
};

// Other than the 'kty' (key type) parameter, which must be present in all JWKs, Section 4 of RFC
// 7517 states that "member names used for representing key parameters for different keys types
// need not be distinct." Therefore, it's possible that future or non-standard key types will supply
// some of the following parameters but with different types, causing deserialization to fail. To
// support such key types, we'll need to define a new impl for JsonWebKey. Deserializing the new
// impl would probably need to involve first deserializing the raw values to access the 'kty'
// parameter, and then deserializing the fields and types appropriate for that key type.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct CoreJsonWebKey {
    pub(crate) kty: CoreJsonWebKeyType,
    #[serde(rename = "use")]
    pub(crate) use_: Option<CoreJsonWebKeyUse>,
    pub(crate) kid: Option<JsonWebKeyId>,

    // FIXME: if this doesn't successfully decode as base64url-encoded, make it None
    // also FIXME: define a custom deserializer for this that takes a string, parses it as
    // base64url, and either fails or sets it to none if that fails (check the spec)
    pub(crate) n: Option<Base64UrlEncodedBytes>,
    pub(crate) e: Option<Base64UrlEncodedBytes>,

    // Used for symmetric keys, which we only generate internally from the client secret; these
    // are never part of the JWK set.
    pub(crate) k: Option<Base64UrlEncodedBytes>,
}
impl JsonWebKey<CoreJwsSigningAlgorithm, CoreJsonWebKeyType, CoreJsonWebKeyUse> for CoreJsonWebKey {
    fn key_id(&self) -> Option<&JsonWebKeyId> { self.kid.as_ref() }
    fn key_type(&self) -> &CoreJsonWebKeyType { &self.kty }
    fn key_use(&self) -> Option<&CoreJsonWebKeyUse> { self.use_.as_ref() }

    fn new_symmetric(key: Vec<u8>) -> Self {
        return Self {
            kty: CoreJsonWebKeyType::Symmetric,
            use_: None,
            kid: None,
            n: None,
            e: None,
            k: Some(Base64UrlEncodedBytes::new(key)),
        }
    }

    fn verify_signature(
        &self,
        signature_alg: &CoreJwsSigningAlgorithm,
        msg: &str,
        signature: &[u8]
    ) -> Result<(), SignatureVerificationError> {
        if let Some(key_use) = self.key_use() {
            if *key_use != CoreJsonWebKeyUse::Signature {
                return Err(
                    SignatureVerificationError::InvalidKey(
                        "key usage not permitted for digital signatures".to_string()
                    )
                )
            }
        }

        let key_type = signature_alg.key_type().map_err(SignatureVerificationError::Other)?;
        if *self.key_type() != key_type {
            return Err(
                SignatureVerificationError::InvalidKey(
                    "key type does not match signature algorithm".to_string()
                )
            )
        }

        // FIXME: add test cases for each of these
        match *signature_alg {
            CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256 =>
                crypto::verify_rsa_signature(
                    self,
                    &ring_signature::RSA_PKCS1_2048_8192_SHA256,
                    msg,
                    signature
                ),
            CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha384 =>
                crypto::verify_rsa_signature(
                    self,
                    &ring_signature::RSA_PKCS1_2048_8192_SHA384,
                    msg,signature
                ),
            CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha512 =>
                crypto::verify_rsa_signature(
                    self,
                    &ring_signature::RSA_PKCS1_2048_8192_SHA512,
                    msg,
                    signature
                ),
            CoreJwsSigningAlgorithm::RsaSsaPssSha256 =>
                crypto::verify_rsa_signature(
                    self,
                    &ring_signature::RSA_PSS_2048_8192_SHA256,
                    msg,
                    signature
                ),
            CoreJwsSigningAlgorithm::RsaSsaPssSha384 =>
                crypto::verify_rsa_signature(
                    self,
                    &ring_signature::RSA_PSS_2048_8192_SHA384,
                    msg,
                    signature
                ),
            CoreJwsSigningAlgorithm::RsaSsaPssSha512 =>
                crypto::verify_rsa_signature(
                    self,
                    &ring_signature::RSA_PSS_2048_8192_SHA512,
                    msg,
                    signature
                ),
            CoreJwsSigningAlgorithm::HmacSha256 =>
                crypto::verify_hmac(self, &digest::SHA256, msg, signature),
            CoreJwsSigningAlgorithm::HmacSha384 =>
                crypto::verify_hmac(self, &digest::SHA384, msg, signature),
            CoreJwsSigningAlgorithm::HmacSha512 =>
                crypto::verify_hmac(self, &digest::SHA512, msg, signature),
            ref other => Err(
                SignatureVerificationError::UnsupportedAlg(variant_name(other).to_string())
            )
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum CoreJsonWebKeyType {
    #[serde(rename = "EC")]
    EllipticCurve,
    #[serde(rename = "RSA")]
    RSA,
    #[serde(rename = "oct")]
    Symmetric,
}
impl JsonWebKeyType for CoreJsonWebKeyType {}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum CoreJsonWebKeyUse {
    #[serde(rename = "sig")]
    Signature,
    #[serde(rename = "enc")]
    Encryption,
}
impl JsonWebKeyUse for CoreJsonWebKeyUse {
    fn allows_signature(&self) -> bool {
        if let CoreJsonWebKeyUse::Signature = *self {
            true
        } else {
            false
        }
    }
    fn allows_encryption(&self) -> bool {
        if let CoreJsonWebKeyUse::Encryption = *self {
            true
        } else {
            false
        }
    }
}
