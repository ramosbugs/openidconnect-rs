use ed25519_dalek::pkcs8::DecodePrivateKey;
use ed25519_dalek::Signer;
use rsa::pkcs1::DecodeRsaPrivateKey;
use sha2::Digest;

use super::{crypto, CoreJwsSigningAlgorithm};
use crate::types::{check_key_compatibility, Base64UrlEncodedBytes};
use crate::types::{helpers::deserialize_option_or_none, JsonCurveType};
use crate::{
    JsonWebKey, JsonWebKeyId, JsonWebKeyType, JsonWebKeyUse, PrivateSigningKey,
    SignatureVerificationError, SigningError,
};

#[cfg(feature = "jwk-alg")]
use crate::{
    core::CoreJweContentEncryptionAlgorithm, jwt::JsonWebTokenAlgorithm, types::JsonWebKeyAlgorithm,
};

// Other than the 'kty' (key type) parameter, which must be present in all JWKs, Section 4 of RFC
// 7517 states that "member names used for representing key parameters for different keys types
// need not be distinct." Therefore, it's possible that future or non-standard key types will supply
// some of the following parameters but with different types, causing deserialization to fail. To
// support such key types, we'll need to define a new impl for JsonWebKey. Deserializing the new
// impl would probably need to involve first deserializing the raw values to access the 'kty'
// parameter, and then deserializing the fields and types appropriate for that key type.
///
/// Public or symmetric key expressed as a JSON Web Key.
///
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct CoreJsonWebKey {
    pub(crate) kty: CoreJsonWebKeyType,
    #[serde(rename = "use", skip_serializing_if = "Option::is_none")]
    pub(crate) use_: Option<CoreJsonWebKeyUse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) kid: Option<JsonWebKeyId>,

    /// The algorithm intended to be used with this key (https://www.rfc-editor.org/rfc/rfc7517#section-4.4)
    /// It can either be an algorithm intended for use with JWS or JWE, or something different.
    #[cfg(feature = "jwk-alg")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) alg: Option<
        JsonWebTokenAlgorithm<
            CoreJweContentEncryptionAlgorithm,
            CoreJwsSigningAlgorithm,
            CoreJsonWebKeyType,
        >,
    >,

    // From RFC 7517, Section 4: "Additional members can be present in the JWK; if not understood
    // by implementations encountering them, they MUST be ignored.  Member names used for
    // representing key parameters for different keys types need not be distinct."
    // Hence, we set fields we fail to deserialize (understand) as None.
    #[serde(
        default,
        deserialize_with = "deserialize_option_or_none",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) n: Option<Base64UrlEncodedBytes>,
    #[serde(
        default,
        deserialize_with = "deserialize_option_or_none",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) e: Option<Base64UrlEncodedBytes>,

    //Elliptic Curve
    #[serde(
        default,
        deserialize_with = "deserialize_option_or_none",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) crv: Option<CoreJsonCurveType>,
    #[serde(
        default,
        deserialize_with = "deserialize_option_or_none",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) x: Option<Base64UrlEncodedBytes>,
    #[serde(
        default,
        deserialize_with = "deserialize_option_or_none",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) y: Option<Base64UrlEncodedBytes>,

    #[serde(
        default,
        deserialize_with = "deserialize_option_or_none",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) d: Option<Base64UrlEncodedBytes>,

    // Used for symmetric keys, which we only generate internally from the client secret; these
    // are never part of the JWK set.
    #[serde(
        default,
        deserialize_with = "deserialize_option_or_none",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) k: Option<Base64UrlEncodedBytes>,
}
impl CoreJsonWebKey {
    /// Instantiate a new RSA public key from the raw modulus (`n`) and public exponent (`e`),
    /// along with an optional (but recommended) key ID.
    ///
    /// The key ID is used for matching signed JSON Web Tokens with the keys used for verifying
    /// their signatures.
    pub fn new_rsa(n: Vec<u8>, e: Vec<u8>, kid: Option<JsonWebKeyId>) -> Self {
        Self {
            kty: CoreJsonWebKeyType::RSA,
            use_: Some(CoreJsonWebKeyUse::Signature),
            kid,
            n: Some(Base64UrlEncodedBytes::new(n)),
            e: Some(Base64UrlEncodedBytes::new(e)),
            k: None,
            crv: None,
            x: None,
            y: None,
            d: None,
            #[cfg(feature = "jwk-alg")]
            alg: None,
        }
    }
    /// Instantiate a new EC public key from the raw x (`x`) and y(`y`) part of the curve,
    /// along with an optional (but recommended) key ID.
    ///
    /// The key ID is used for matching signed JSON Web Tokens with the keys used for verifying
    /// their signatures.
    pub fn new_ec(
        x: Vec<u8>,
        y: Vec<u8>,
        crv: CoreJsonCurveType,
        kid: Option<JsonWebKeyId>,
    ) -> Self {
        Self {
            kty: CoreJsonWebKeyType::EllipticCurve,
            use_: Some(CoreJsonWebKeyUse::Signature),
            kid,
            n: None,
            e: None,
            k: None,
            crv: Some(crv),
            x: Some(Base64UrlEncodedBytes::new(x)),
            y: Some(Base64UrlEncodedBytes::new(y)),
            d: None,
            #[cfg(feature = "jwk-alg")]
            alg: None,
        }
    }

    /// Instantiate a new Octet Key-Pair public key from the raw x (`x`) part of the curve,
    /// along with an optional (but recommended) key ID.
    ///
    /// The key ID is used for matching signed JSON Web Tokens with the keys used for verifying
    /// their signatures.
    pub fn new_okp(x: Vec<u8>, crv: CoreJsonCurveType, kid: Option<JsonWebKeyId>) -> Self {
        Self {
            kty: CoreJsonWebKeyType::OctetKeyPair,
            use_: Some(CoreJsonWebKeyUse::Signature),
            kid,
            n: None,
            e: None,
            k: None,
            crv: Some(crv),
            x: Some(Base64UrlEncodedBytes::new(x)),
            y: None,
            d: None,
            #[cfg(feature = "jwk-alg")]
            alg: None,
        }
    }
}

impl JsonWebKey<CoreJwsSigningAlgorithm, CoreJsonWebKeyType, CoreJsonWebKeyUse> for CoreJsonWebKey {
    fn key_id(&self) -> Option<&JsonWebKeyId> {
        self.kid.as_ref()
    }
    fn key_type(&self) -> &CoreJsonWebKeyType {
        &self.kty
    }
    fn key_use(&self) -> Option<&CoreJsonWebKeyUse> {
        self.use_.as_ref()
    }

    fn new_symmetric(key: Vec<u8>) -> Self {
        Self {
            kty: CoreJsonWebKeyType::Symmetric,
            use_: None,
            kid: None,
            n: None,
            e: None,
            k: Some(Base64UrlEncodedBytes::new(key)),
            crv: None,
            x: None,
            y: None,
            d: None,
            #[cfg(feature = "jwk-alg")]
            alg: None,
        }
    }

    fn verify_signature(
        &self,
        signature_alg: &CoreJwsSigningAlgorithm,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), SignatureVerificationError> {
        use hmac::Mac;

        check_key_compatibility(self, signature_alg)
            .map_err(|e| SignatureVerificationError::InvalidKey(e.to_owned()))?;

        match *signature_alg {
            CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256 => {
                let message = {
                    let mut hasher = sha2::Sha256::new();
                    hasher.update(message);
                    &hasher.finalize()
                };
                crypto::verify_rsa_signature(
                    self,
                    rsa::Pkcs1v15Sign::new::<sha2::Sha256>(),
                    message,
                    signature,
                )
            }
            CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha384 => {
                let message = {
                    let mut hasher = sha2::Sha384::new();
                    hasher.update(message);
                    &hasher.finalize()
                };
                crypto::verify_rsa_signature(
                    self,
                    rsa::Pkcs1v15Sign::new::<sha2::Sha384>(),
                    message,
                    signature,
                )
            }
            CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha512 => {
                let message = {
                    let mut hasher = sha2::Sha512::new();
                    hasher.update(message);
                    &hasher.finalize()
                };
                crypto::verify_rsa_signature(
                    self,
                    rsa::Pkcs1v15Sign::new::<sha2::Sha512>(),
                    message,
                    signature,
                )
            }
            CoreJwsSigningAlgorithm::RsaSsaPssSha256 => {
                let message = {
                    let mut hasher = sha2::Sha256::new();
                    hasher.update(message);
                    &hasher.finalize()
                };
                crypto::verify_rsa_signature(
                    self,
                    rsa::Pss::new::<sha2::Sha256>(),
                    message,
                    signature,
                )
            }
            CoreJwsSigningAlgorithm::RsaSsaPssSha384 => {
                let message = {
                    let mut hasher = sha2::Sha384::new();
                    hasher.update(message);
                    &hasher.finalize()
                };
                crypto::verify_rsa_signature(
                    self,
                    rsa::Pss::new::<sha2::Sha384>(),
                    message,
                    signature,
                )
            }
            CoreJwsSigningAlgorithm::RsaSsaPssSha512 => {
                let message = {
                    let mut hasher = sha2::Sha512::new();
                    hasher.update(message);
                    &hasher.finalize()
                };
                crypto::verify_rsa_signature(
                    self,
                    rsa::Pss::new::<sha2::Sha512>(),
                    message,
                    signature,
                )
            }
            CoreJwsSigningAlgorithm::HmacSha256 => {
                let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(
                    self.k.as_ref().ok_or_else(|| {
                        SignatureVerificationError::InvalidKey(
                            "Symmetric key `k` is missing".to_string(),
                        )
                    })?,
                )
                .map_err(|e| {
                    SignatureVerificationError::Other(format!("Could not create key: {}", e))
                })?;
                mac.update(message);
                mac.verify(signature.into())
                    .map_err(|_| SignatureVerificationError::CryptoError("bad HMAC".to_string()))
            }
            CoreJwsSigningAlgorithm::HmacSha384 => {
                let mut mac = hmac::Hmac::<sha2::Sha384>::new_from_slice(
                    self.k.as_ref().ok_or_else(|| {
                        SignatureVerificationError::InvalidKey(
                            "Symmetric key `k` is missing".to_string(),
                        )
                    })?,
                )
                .map_err(|e| {
                    SignatureVerificationError::Other(format!("Could not create key: {}", e))
                })?;
                mac.update(message);
                mac.verify(signature.into())
                    .map_err(|_| SignatureVerificationError::CryptoError("bad HMAC".to_string()))
            }
            CoreJwsSigningAlgorithm::HmacSha512 => {
                let mut mac = hmac::Hmac::<sha2::Sha512>::new_from_slice(
                    self.k.as_ref().ok_or_else(|| {
                        SignatureVerificationError::InvalidKey(
                            "Symmetric key `k` is missing".to_string(),
                        )
                    })?,
                )
                .map_err(|e| {
                    SignatureVerificationError::Other(format!("Could not create key: {}", e))
                })?;
                mac.update(message);
                mac.verify(signature.into())
                    .map_err(|_| SignatureVerificationError::CryptoError("bad HMAC".to_string()))
            }
            CoreJwsSigningAlgorithm::EcdsaP256Sha256 => {
                if matches!(self.crv, Some(CoreJsonCurveType::P256)) {
                    crypto::verify_ec_signature(self, message, signature)
                } else {
                    Err(SignatureVerificationError::InvalidKey(
                        "Key uses different CRV than JWT".to_string(),
                    ))
                }
            }
            CoreJwsSigningAlgorithm::EcdsaP384Sha384 => {
                if matches!(self.crv, Some(CoreJsonCurveType::P384)) {
                    crypto::verify_ec_signature(self, message, signature)
                } else {
                    Err(SignatureVerificationError::InvalidKey(
                        "Key uses different CRV than JWT".to_string(),
                    ))
                }
            }
            CoreJwsSigningAlgorithm::EdDsaEd25519 => {
                if matches!(self.crv, Some(CoreJsonCurveType::Ed25519)) {
                    crypto::verify_ed_signature(self, message, signature)
                } else {
                    Err(SignatureVerificationError::InvalidKey(
                        "Key uses different CRV than JWT".to_string(),
                    ))
                }
            }
            ref other => Err(SignatureVerificationError::UnsupportedAlg(
                serde_plain::to_string(other).unwrap_or_else(|err| {
                    panic!(
                        "signature alg {:?} failed to serialize to a string: {}",
                        other, err
                    )
                }),
            )),
        }
    }

    #[cfg(feature = "jwk-alg")]
    fn signing_alg(&self) -> JsonWebKeyAlgorithm<&CoreJwsSigningAlgorithm> {
        match self.alg {
            None => JsonWebKeyAlgorithm::Unspecified,
            Some(JsonWebTokenAlgorithm::Signature(ref alg, _)) => {
                JsonWebKeyAlgorithm::Algorithm(alg)
            }
            Some(_) => JsonWebKeyAlgorithm::Unsupported,
        }
    }
}

///
/// HMAC secret key.
///
/// This key can be used for signing messages, or converted to a `CoreJsonWebKey` for verifying
/// them.
///
#[derive(Clone)]
pub struct CoreHmacKey {
    secret: Vec<u8>,
}
impl CoreHmacKey {
    ///
    /// Instantiate a new key from the specified secret bytes.
    ///
    pub fn new<T>(secret: T) -> Self
    where
        T: Into<Vec<u8>>,
    {
        Self {
            secret: secret.into(),
        }
    }
}
impl
    PrivateSigningKey<
        CoreJwsSigningAlgorithm,
        CoreJsonWebKeyType,
        CoreJsonWebKeyUse,
        CoreJsonWebKey,
    > for CoreHmacKey
{
    fn sign(
        &self,
        signature_alg: &CoreJwsSigningAlgorithm,
        message: &[u8],
    ) -> Result<Vec<u8>, SigningError> {
        use hmac::Mac;
        match *signature_alg {
            CoreJwsSigningAlgorithm::HmacSha256 => {
                let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(&self.secret)
                    .map_err(|e| SigningError::Other(format!("Could not create key: {}", e)))?;
                mac.update(message);
                let result = mac.finalize();
                Ok(result.into_bytes().as_slice().to_vec())
            }
            CoreJwsSigningAlgorithm::HmacSha384 => {
                let mut mac = hmac::Hmac::<sha2::Sha384>::new_from_slice(&self.secret)
                    .map_err(|e| SigningError::Other(format!("Could not create key: {}", e)))?;
                mac.update(message);
                let result = mac.finalize();
                Ok(result.into_bytes().as_slice().to_vec())
            }
            CoreJwsSigningAlgorithm::HmacSha512 => {
                let mut mac = hmac::Hmac::<sha2::Sha512>::new_from_slice(&self.secret)
                    .map_err(|e| SigningError::Other(format!("Could not create key: {}", e)))?;
                mac.update(message);
                let result = mac.finalize();
                Ok(result.into_bytes().as_slice().to_vec())
            }
            ref other => Err(SigningError::UnsupportedAlg(
                serde_plain::to_string(other).unwrap_or_else(|err| {
                    panic!(
                        "signature alg {:?} failed to serialize to a string: {}",
                        other, err
                    )
                }),
            )),
        }
    }

    fn as_verification_key(&self) -> CoreJsonWebKey {
        CoreJsonWebKey::new_symmetric(self.secret.clone())
    }
}

enum EdDsaSigningKey {
    Ed25519(ed25519_dalek::SigningKey),
}

impl EdDsaSigningKey {
    fn from_ed25519_pem(pem: &str) -> Result<Self, String> {
        Ok(Self::Ed25519(
            ed25519_dalek::SigningKey::from_pkcs8_pem(pem).map_err(|err| err.to_string())?,
        ))
    }

    fn sign(&self, message: &[u8]) -> Vec<u8> {
        match self {
            Self::Ed25519(key) => {
                let signature = key.sign(message);

                signature.to_vec()
            }
        }
    }
}

///
/// EdDSA Private Key.
///
/// This key can be used for signing messages, or converted to a `CoreJsonWebKey` for verifying
/// them.
///
pub struct CoreEdDsaPrivateSigningKey {
    kid: Option<JsonWebKeyId>,
    key_pair: EdDsaSigningKey,
}
impl CoreEdDsaPrivateSigningKey {
    ///
    /// Converts an EdDSA private key (in PEM format) to a JWK representing its public key.
    ///
    pub fn from_ed25519_pem(pem: &str, kid: Option<JsonWebKeyId>) -> Result<Self, String> {
        Ok(Self {
            kid,
            key_pair: EdDsaSigningKey::from_ed25519_pem(pem)?,
        })
    }
}
impl
    PrivateSigningKey<
        CoreJwsSigningAlgorithm,
        CoreJsonWebKeyType,
        CoreJsonWebKeyUse,
        CoreJsonWebKey,
    > for CoreEdDsaPrivateSigningKey
{
    fn sign(
        &self,
        signature_alg: &CoreJwsSigningAlgorithm,
        message: &[u8],
    ) -> Result<Vec<u8>, SigningError> {
        match *signature_alg {
            CoreJwsSigningAlgorithm::EdDsaEd25519 => Ok(self.key_pair.sign(message)),
            ref other => Err(SigningError::UnsupportedAlg(
                serde_plain::to_string(other).unwrap_or_else(|err| {
                    panic!(
                        "signature alg {:?} failed to serialize to a string: {}",
                        other, err
                    )
                }),
            )),
        }
    }

    fn as_verification_key(&self) -> CoreJsonWebKey {
        match &self.key_pair {
            EdDsaSigningKey::Ed25519(key) => CoreJsonWebKey {
                kty: CoreJsonWebKeyType::OctetKeyPair,
                use_: Some(CoreJsonWebKeyUse::Signature),
                kid: self.kid.clone(),
                n: None,
                e: None,
                crv: Some(CoreJsonCurveType::Ed25519),
                x: Some(Base64UrlEncodedBytes::new(
                    key.verifying_key().as_bytes().to_vec(),
                )),
                y: None,
                d: None,
                k: None,
                #[cfg(feature = "jwk-alg")]
                alg: None,
            },
        }
    }
}

/// Trait used to allow testing with an alternative RNG.
/// Clone is necessary to get a mutable version of the RNG.
pub(crate) trait RngClone: dyn_clone::DynClone + rand::RngCore + rand::CryptoRng {}
dyn_clone::clone_trait_object!(RngClone);
impl<T> RngClone for T where T: rand::RngCore + rand::CryptoRng + Clone {}

///
/// RSA private key.
///
/// This key can be used for signing messages, or converted to a `CoreJsonWebKey` for verifying
/// them.
///
pub struct CoreRsaPrivateSigningKey {
    key_pair: rsa::RsaPrivateKey,
    rng: Box<dyn RngClone + Send + Sync>,
    kid: Option<JsonWebKeyId>,
}
impl CoreRsaPrivateSigningKey {
    ///
    /// Converts an RSA private key (in PEM format) to a JWK representing its public key.
    ///
    pub fn from_pem(pem: &str, kid: Option<JsonWebKeyId>) -> Result<Self, String> {
        Self::from_pem_internal(pem, Box::new(rand::rngs::OsRng), kid)
    }

    pub(crate) fn from_pem_internal(
        pem: &str,
        rng: Box<dyn RngClone + Send + Sync>,
        kid: Option<JsonWebKeyId>,
    ) -> Result<Self, String> {
        let key_pair = rsa::RsaPrivateKey::from_pkcs1_pem(pem).map_err(|err| err.to_string())?;
        Ok(Self { key_pair, rng, kid })
    }
}
impl
    PrivateSigningKey<
        CoreJwsSigningAlgorithm,
        CoreJsonWebKeyType,
        CoreJsonWebKeyUse,
        CoreJsonWebKey,
    > for CoreRsaPrivateSigningKey
{
    fn sign(
        &self,
        signature_alg: &CoreJwsSigningAlgorithm,
        msg: &[u8],
    ) -> Result<Vec<u8>, SigningError> {
        match *signature_alg {
            CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256 => {
                let mut hasher = sha2::Sha256::new();
                hasher.update(msg);
                let hash = hasher.finalize().to_vec();

                self.key_pair
                    .sign_with_rng(
                        &mut dyn_clone::clone_box(&self.rng),
                        rsa::Pkcs1v15Sign::new::<sha2::Sha256>(),
                        &hash,
                    )
                    .map_err(|_| SigningError::CryptoError)
            }
            CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha384 => {
                let mut hasher = sha2::Sha384::new();
                hasher.update(msg);
                let hash = hasher.finalize().to_vec();

                self.key_pair
                    .sign_with_rng(
                        &mut dyn_clone::clone_box(&self.rng),
                        rsa::Pkcs1v15Sign::new::<sha2::Sha384>(),
                        &hash,
                    )
                    .map_err(|_| SigningError::CryptoError)
            }
            CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha512 => {
                let mut hasher = sha2::Sha512::new();
                hasher.update(msg);
                let hash = hasher.finalize().to_vec();

                self.key_pair
                    .sign_with_rng(
                        &mut dyn_clone::clone_box(&self.rng),
                        rsa::Pkcs1v15Sign::new::<sha2::Sha512>(),
                        &hash,
                    )
                    .map_err(|_| SigningError::CryptoError)
            }
            CoreJwsSigningAlgorithm::RsaSsaPssSha256 => {
                let mut hasher = sha2::Sha256::new();
                hasher.update(msg);
                let hash = hasher.finalize().to_vec();

                self.key_pair
                    .sign_with_rng(
                        &mut dyn_clone::clone_box(&self.rng),
                        rsa::Pss::new_with_salt::<sha2::Sha256>(hash.len()),
                        &hash,
                    )
                    .map_err(|_| SigningError::CryptoError)
            }
            CoreJwsSigningAlgorithm::RsaSsaPssSha384 => {
                let mut hasher = sha2::Sha384::new();
                hasher.update(msg);
                let hash = hasher.finalize().to_vec();

                self.key_pair
                    .sign_with_rng(
                        &mut dyn_clone::clone_box(&self.rng),
                        rsa::Pss::new_with_salt::<sha2::Sha384>(hash.len()),
                        &hash,
                    )
                    .map_err(|_| SigningError::CryptoError)
            }
            CoreJwsSigningAlgorithm::RsaSsaPssSha512 => {
                let mut hasher = sha2::Sha512::new();
                hasher.update(msg);
                let hash = hasher.finalize().to_vec();

                self.key_pair
                    .sign_with_rng(
                        &mut dyn_clone::clone_box(&self.rng),
                        rsa::Pss::new_with_salt::<sha2::Sha512>(hash.len()),
                        &hash,
                    )
                    .map_err(|_| SigningError::CryptoError)
            }
            ref other => Err(SigningError::UnsupportedAlg(
                serde_plain::to_string(other).unwrap_or_else(|err| {
                    panic!(
                        "signature alg {:?} failed to serialize to a string: {}",
                        other, err
                    )
                }),
            )),
        }
    }

    fn as_verification_key(&self) -> CoreJsonWebKey {
        use rsa::traits::PublicKeyParts;

        let public_key = self.key_pair.to_public_key();
        CoreJsonWebKey {
            kty: CoreJsonWebKeyType::RSA,
            use_: Some(CoreJsonWebKeyUse::Signature),
            kid: self.kid.clone(),
            n: Some(Base64UrlEncodedBytes::new(public_key.n().to_bytes_be())),
            e: Some(Base64UrlEncodedBytes::new(public_key.e().to_bytes_be())),
            k: None,
            crv: None,
            x: None,
            y: None,
            d: None,
            #[cfg(feature = "jwk-alg")]
            alg: None,
        }
    }
}

///
/// Type of JSON Web Key.
///
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub enum CoreJsonWebKeyType {
    ///
    /// Elliptic Curve Cryptography (ECC) key.
    ///
    /// ECC algorithms such as ECDSA are currently unsupported.
    ///
    #[serde(rename = "EC")]
    EllipticCurve,
    ///
    /// RSA key.
    ///
    #[serde(rename = "RSA")]
    RSA,
    ///
    /// EdDSA key.
    ///
    #[serde(rename = "OKP")]
    OctetKeyPair,
    ///
    /// Symmetric key.
    ///
    #[serde(rename = "oct")]
    Symmetric,
}
impl JsonWebKeyType for CoreJsonWebKeyType {}

///
/// Type of EC-Curve
///
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub enum CoreJsonCurveType {
    ///
    /// P-256 Curve
    ///
    #[serde(rename = "P-256")]
    P256,
    ///
    /// P-384 Curve
    ///
    #[serde(rename = "P-384")]
    P384,
    ///
    /// P-521 Curve (currently not supported)
    ///
    #[serde(rename = "P-521")]
    P521,
    ///
    /// Ed25519 Curve
    ///
    #[serde(rename = "Ed25519")]
    Ed25519,
}
impl JsonCurveType for CoreJsonWebKeyType {}

///
/// Usage restriction for a JSON Web key.
///
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CoreJsonWebKeyUse {
    ///
    /// Key may be used for digital signatures.
    ///
    Signature,

    ///
    /// Key may be used for encryption.
    ///
    Encryption,

    ///
    /// Fallback case for other key uses not understood by this library.
    ///
    Other(String),
}
impl CoreJsonWebKeyUse {
    fn from_str(s: &str) -> Self {
        match s {
            "sig" => Self::Signature,
            "enc" => Self::Encryption,
            other => Self::Other(other.to_string()),
        }
    }
}
impl AsRef<str> for CoreJsonWebKeyUse {
    fn as_ref(&self) -> &str {
        match self {
            CoreJsonWebKeyUse::Signature => "sig",
            CoreJsonWebKeyUse::Encryption => "enc",
            CoreJsonWebKeyUse::Other(other) => other.as_str(),
        }
    }
}
impl JsonWebKeyUse for CoreJsonWebKeyUse {
    fn allows_signature(&self) -> bool {
        matches!(*self, CoreJsonWebKeyUse::Signature)
    }
    fn allows_encryption(&self) -> bool {
        matches!(*self, CoreJsonWebKeyUse::Encryption)
    }
}
// FIXME: Once https://github.com/serde-rs/serde/issues/912 is resolved, use #[serde(other)] instead
// of custom serializer/deserializers. Right now this isn't possible because serde(other) only
// supports unit variants.
deserialize_from_str!(CoreJsonWebKeyUse);
serialize_as_str!(CoreJsonWebKeyUse);

#[cfg(test)]
mod tests {
    use crate::core::CoreJsonWebKeySet;
    #[cfg(feature = "jwk-alg")]
    use crate::{core::CoreJweContentEncryptionAlgorithm, jwt::JsonWebTokenAlgorithm};
    use rand::rngs::mock::StepRng;
    use rand::{CryptoRng, RngCore};
    use rsa::rand_core;

    use crate::jwt::tests::{
        TEST_EC_PUB_KEY_P256, TEST_EC_PUB_KEY_P384, TEST_ED_PUB_KEY_ED25519, TEST_RSA_PUB_KEY,
    };
    use crate::types::Base64UrlEncodedBytes;
    use crate::types::{JsonWebKey, JsonWebKeyId};
    use crate::verification::SignatureVerificationError;

    use super::{
        CoreEdDsaPrivateSigningKey, CoreHmacKey, CoreJsonWebKey, CoreJsonWebKeyType,
        CoreJsonWebKeyUse, CoreJwsSigningAlgorithm, CoreRsaPrivateSigningKey, PrivateSigningKey,
    };
    use super::{CoreJsonCurveType, SigningError};

    #[test]
    fn test_core_jwk_deserialization_rsa() {
        let json = "{
            \"kty\": \"RSA\",
            \"use\": \"sig\",
            \"kid\": \"2011-04-29\",
            \"n\": \"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhD\
                     R1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6C\
                     f0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1\
                     n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1\
                     jF44-csFCur-kEgU8awapJzKnqDKgw\",
            \"e\": \"AQAB\"
        }";

        let key: CoreJsonWebKey = serde_json::from_str(json).expect("deserialization failed");
        assert_eq!(key.kty, CoreJsonWebKeyType::RSA);
        assert_eq!(key.use_, Some(CoreJsonWebKeyUse::Signature));
        assert_eq!(key.kid, Some(JsonWebKeyId::new("2011-04-29".to_string())));
        assert_eq!(
            key.n,
            Some(Base64UrlEncodedBytes::new(vec![
                210, 252, 123, 106, 10, 30, 108, 103, 16, 74, 235, 143, 136, 178, 87, 102, 155, 77,
                246, 121, 221, 173, 9, 155, 92, 74, 108, 217, 168, 128, 21, 181, 161, 51, 191, 11,
                133, 108, 120, 113, 182, 223, 0, 11, 85, 79, 206, 179, 194, 237, 81, 43, 182, 143,
                20, 92, 110, 132, 52, 117, 47, 171, 82, 161, 207, 193, 36, 64, 143, 121, 181, 138,
                69, 120, 193, 100, 40, 133, 87, 137, 247, 162, 73, 227, 132, 203, 45, 159, 174, 45,
                103, 253, 150, 251, 146, 108, 25, 142, 7, 115, 153, 253, 200, 21, 192, 175, 9, 125,
                222, 90, 173, 239, 244, 77, 231, 14, 130, 127, 72, 120, 67, 36, 57, 191, 238, 185,
                96, 104, 208, 71, 79, 197, 13, 109, 144, 191, 58, 152, 223, 175, 16, 64, 200, 156,
                2, 214, 146, 171, 59, 60, 40, 150, 96, 157, 134, 253, 115, 183, 116, 206, 7, 64,
                100, 124, 238, 234, 163, 16, 189, 18, 249, 133, 168, 235, 159, 89, 253, 212, 38,
                206, 165, 178, 18, 15, 79, 42, 52, 188, 171, 118, 75, 126, 108, 84, 214, 132, 2,
                56, 188, 196, 5, 135, 165, 158, 102, 237, 31, 51, 137, 69, 119, 99, 92, 71, 10,
                247, 92, 249, 44, 32, 209, 218, 67, 225, 191, 196, 25, 226, 34, 166, 240, 208, 187,
                53, 140, 94, 56, 249, 203, 5, 10, 234, 254, 144, 72, 20, 241, 172, 26, 164, 156,
                202, 158, 160, 202, 131,
            ]))
        );
        assert_eq!(key.e, Some(Base64UrlEncodedBytes::new(vec![1, 0, 1])));
        assert_eq!(key.k, None);
    }
    #[test]
    fn test_core_jwk_deserialization_ec() {
        let json = "{
            \"kty\": \"EC\",
            \"use\": \"sig\",
            \"kid\": \"2011-04-29\",
            \"crv\": \"P-256\",
            \"x\": \"kXCGZIr3oI6sKbnT6rRsIdxFXw3_VbLk_cveajgqXk8\",
            \"y\": \"StDvKIgXqAxJ6DuebREh-1vgvZRW3dfrOxSIKzBtRI0\"
        }";

        let key: CoreJsonWebKey = serde_json::from_str(json).expect("deserialization failed");
        assert_eq!(key.kty, CoreJsonWebKeyType::EllipticCurve);
        assert_eq!(key.use_, Some(CoreJsonWebKeyUse::Signature));
        assert_eq!(key.kid, Some(JsonWebKeyId::new("2011-04-29".to_string())));
        assert_eq!(key.crv, Some(CoreJsonCurveType::P256));
        assert_eq!(
            key.y,
            Some(Base64UrlEncodedBytes::new(vec![
                0x4a, 0xd0, 0xef, 0x28, 0x88, 0x17, 0xa8, 0x0c, 0x49, 0xe8, 0x3b, 0x9e, 0x6d, 0x11,
                0x21, 0xfb, 0x5b, 0xe0, 0xbd, 0x94, 0x56, 0xdd, 0xd7, 0xeb, 0x3b, 0x14, 0x88, 0x2b,
                0x30, 0x6d, 0x44, 0x8d
            ]))
        );
        assert_eq!(
            key.x,
            Some(Base64UrlEncodedBytes::new(vec![
                0x91, 0x70, 0x86, 0x64, 0x8a, 0xf7, 0xa0, 0x8e, 0xac, 0x29, 0xb9, 0xd3, 0xea, 0xb4,
                0x6c, 0x21, 0xdc, 0x45, 0x5f, 0x0d, 0xff, 0x55, 0xb2, 0xe4, 0xfd, 0xcb, 0xde, 0x6a,
                0x38, 0x2a, 0x5e, 0x4f
            ]))
        );
    }

    #[test]
    fn test_core_jwk_deserialization_ed() {
        let json = "{
            \"alg\": \"Ed25519\",
            \"crv\": \"Ed25519\",
            \"kty\": \"OKP\",
            \"use\": \"sig\",
            \"x\": \"vZ3CX884r0qNJ18pgXUTvFufK3ZmDzQfvMROJz6CLBc\"
        }";

        let key: CoreJsonWebKey = serde_json::from_str(json).expect("deserialization failed");
        assert_eq!(key.kty, CoreJsonWebKeyType::OctetKeyPair);
        assert_eq!(key.use_, Some(CoreJsonWebKeyUse::Signature));
        assert_eq!(key.crv, Some(CoreJsonCurveType::Ed25519));
        assert_eq!(
            key.x,
            Some(Base64UrlEncodedBytes::new(vec![
                0xBD, 0x9D, 0xC2, 0x5F, 0xCF, 0x38, 0xAF, 0x4A, 0x8D, 0x27, 0x5F, 0x29, 0x81, 0x75,
                0x13, 0xBC, 0x5B, 0x9F, 0x2B, 0x76, 0x66, 0x0F, 0x34, 0x1F, 0xBC, 0xC4, 0x4E, 0x27,
                0x3E, 0x82, 0x2C, 0x17
            ]))
        );
    }

    #[test]
    fn test_core_jwk_deserialization_symmetric() {
        let json = "{\
            \"kty\":\"oct\",
            \"alg\":\"A128GCM\",
            \"k\":\"GawgguFyGrWKav7AX4VKUg\"
        }";

        let key: CoreJsonWebKey = serde_json::from_str(json).expect("deserialization failed");
        assert_eq!(key.kty, CoreJsonWebKeyType::Symmetric);
        assert_eq!(key.use_, None);
        assert_eq!(key.kid, None);
        assert_eq!(key.n, None);
        assert_eq!(key.e, None);
        #[cfg(feature = "jwk-alg")]
        assert_eq!(
            key.alg,
            Some(JsonWebTokenAlgorithm::Encryption(
                CoreJweContentEncryptionAlgorithm::Aes128Gcm
            ))
        );
        assert_eq!(
            key.k,
            Some(Base64UrlEncodedBytes::new(vec![
                25, 172, 32, 130, 225, 114, 26, 181, 138, 106, 254, 192, 95, 133, 74, 82,
            ]))
        );
    }

    #[test]
    fn test_core_jwk_deserialization_no_optional() {
        let json = "{\"kty\":\"oct\"}";
        let key: CoreJsonWebKey = serde_json::from_str(json).expect("deserialization failed");
        assert_eq!(key.kty, CoreJsonWebKeyType::Symmetric);
        assert_eq!(key.use_, None);
        assert_eq!(key.kid, None);
        assert_eq!(key.n, None);
        assert_eq!(key.e, None);
        assert_eq!(key.k, None);
    }

    #[test]
    fn test_core_jwk_deserialization_unrecognized() {
        // Unrecognized fields should be ignored during deserialization
        let json = "{\
            \"kty\": \"oct\",
            \"unrecognized\": 1234
        }";
        let key: CoreJsonWebKey = serde_json::from_str(json).expect("deserialization failed");
        assert_eq!(key.kty, CoreJsonWebKeyType::Symmetric);
    }

    #[test]
    fn test_core_jwk_deserialization_dupe_fields() {
        // From RFC 7517, Section 4:
        //   "The member names within a JWK MUST be unique; JWK parsers MUST either
        //   reject JWKs with duplicate member names or use a JSON parser that
        //   returns only the lexically last duplicate member name, as specified
        //   in Section 15.12 (The JSON Object) of ECMAScript 5.1 [ECMAScript]."
        let json = "{\
            \"kty\":\"oct\",
            \"k\":\"GawgguFyGrWKav7AX4VKUg\",
            \"k\":\"GawgguFyGrWKav7AX4VKVg\"
        }";

        assert!(serde_json::from_str::<CoreJsonWebKey>(json)
            .expect_err("deserialization must fail when duplicate fields are present")
            .to_string()
            // This is probably not ideal since the serde/serde_json contracts don't guarantee this
            // error message. However, we want to be sure that this fails for the expected reason
            // and not by happenstance, so this is fine for now.
            .contains("duplicate field"));
    }

    fn verify_signature(
        key: &CoreJsonWebKey,
        alg: &CoreJwsSigningAlgorithm,
        signing_input: &str,
        signature_base64: &str,
    ) {
        let signature =
            base64::decode_config(signature_base64, crate::core::base64_url_safe_no_pad())
                .expect("failed to base64url decode");
        key.verify_signature(alg, signing_input.as_bytes(), &signature)
            .expect("signature verification failed");
        match key
            .verify_signature(
                alg,
                (signing_input.to_string() + "foobar").as_bytes(),
                &signature,
            )
            .expect_err("signature verification should fail")
        {
            SignatureVerificationError::CryptoError(_) => {}
            other => panic!("unexpected error: {:?}", other),
        }
    }

    fn verify_invalid_signature(
        key: &CoreJsonWebKey,
        alg: &CoreJwsSigningAlgorithm,
        signing_input: &str,
        signature_base64: &str,
    ) {
        let signature =
            base64::decode_config(signature_base64, crate::core::base64_url_safe_no_pad())
                .expect("failed to base64url decode");
        match key
            .verify_signature(alg, signing_input.as_bytes(), &signature)
            .expect_err("signature verification should fail")
        {
            SignatureVerificationError::CryptoError(_) => {}
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn test_eddsa_verification() {
        let key_ed25519: CoreJsonWebKey =
            serde_json::from_str(TEST_ED_PUB_KEY_ED25519).expect("deserialization failed");
        let pkcs1_signing_input = "eyJhbGciOiJFZDI1NTE5IiwidHlwIjoiSldUIn0.eyJpc3MiOiJqb2UifQ";
        let signature_ed25519 = "Augr7UH6hUbWVN0PHqSD5U0bb8y9UOw_eef09ZS5d5haUar_qAto8gyLJxUhNF5wHPoXhdvSGowkPvjiKsEsCQ";

        let signature_ed25519_other = "xb4NH-q33sCaRXf1ZhnzQxd4o5ZkBWKd9vGibacqPMAblW_mIJLm9kGerqHX08SPoeDY-dYUmZQz9ls6csfvAw";
        let signature_ed448 = "xxXVMyaYYePdGfMOdU0nENuc70pKwP3vJuc_jBA0rCW-RtbvBLSsc0D9iCPzhrPmQ2X1nTjPkGiAXJ0_NslDBvy3sHu88N64YhnnYBWwwHttBU0jijn_ikbBUHzUwzGuasRFb1ESG_PwedhEcMi-YAwA";

        // test ed25519
        verify_signature(
            &key_ed25519,
            &CoreJwsSigningAlgorithm::EdDsaEd25519,
            pkcs1_signing_input,
            signature_ed25519,
        );

        // signature from ed448 variant
        verify_invalid_signature(
            &key_ed25519,
            &CoreJwsSigningAlgorithm::EdDsaEd25519,
            pkcs1_signing_input,
            signature_ed448,
        );

        // different signature
        verify_invalid_signature(
            &key_ed25519,
            &CoreJwsSigningAlgorithm::EdDsaEd25519,
            pkcs1_signing_input,
            signature_ed25519_other,
        );

        // non-EdDsa key
        if let Some(err) = key_ed25519
            .verify_signature(
                &CoreJwsSigningAlgorithm::EcdsaP256Sha256,
                pkcs1_signing_input.as_bytes(),
                signature_ed25519.as_bytes(),
            )
            .err()
        {
            let error_msg = "key type does not match signature algorithm".to_string();
            match err {
                SignatureVerificationError::InvalidKey(msg) => {
                    if msg != error_msg {
                        panic!("The error should be about key type")
                    }
                }
                _ => panic!("We should fail before actual validation"),
            }
        }
    }

    #[test]
    fn test_ecdsa_verification() {
        let key_p256: CoreJsonWebKey =
            serde_json::from_str(TEST_EC_PUB_KEY_P256).expect("deserialization failed");
        let key_p384: CoreJsonWebKey =
            serde_json::from_str(TEST_EC_PUB_KEY_P384).expect("deserialization failed");
        let pkcs1_signing_input = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZX\
                                   hhbXBsZSJ9.\
                                   SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IH\
                                   lvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBk\
                                   b24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcm\
                                   UgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4";
        let signature_p256 = "EnKCtAHhzhqxV2GTr1VEurse2kQ7oHpFoVqM66sYGlmahDRGSlfrVAsGCzdLv66OS2Qf1zt6OPHX-5ZAkMgzlA";
        let signature_p384 = "B_9oDAabMasZ2Yt_cnAS21owaN0uWSInQBPxTqqiM3N3XjkksBRMGqguJLV5WoSMcvqgXwHTTQtbHGuh0Uf4g6LEr7XtO1T2KCttQR27d5YbvVZdORrzCm0Nsm1zkV-i";

        //test p256
        verify_signature(
            &key_p256,
            &CoreJwsSigningAlgorithm::EcdsaP256Sha256,
            pkcs1_signing_input,
            signature_p256,
        );

        //wrong algo should fail before ring validation
        if let Some(err) = key_p256
            .verify_signature(
                &CoreJwsSigningAlgorithm::EcdsaP384Sha384,
                pkcs1_signing_input.as_bytes(),
                signature_p256.as_bytes(),
            )
            .err()
        {
            let error_msg = "Key uses different CRV than JWT".to_string();
            match err {
                SignatureVerificationError::InvalidKey(msg) => {
                    if msg != error_msg {
                        panic!("The error should be about different CRVs")
                    }
                }
                _ => panic!("We should fail before actual validation"),
            }
        }
        // suppose we have alg specified correctly, but the signature given is actually a p384
        verify_invalid_signature(
            &key_p256,
            &CoreJwsSigningAlgorithm::EcdsaP256Sha256,
            pkcs1_signing_input,
            signature_p384,
        );

        //test p384
        verify_signature(
            &key_p384,
            &CoreJwsSigningAlgorithm::EcdsaP384Sha384,
            pkcs1_signing_input,
            signature_p384,
        );

        // suppose we have alg specified correctly, but the signature given is actually a p256
        verify_invalid_signature(
            &key_p384,
            &CoreJwsSigningAlgorithm::EcdsaP384Sha384,
            pkcs1_signing_input,
            signature_p256,
        );

        //wrong algo should fail before ring validation
        if let Some(err) = key_p384
            .verify_signature(
                &CoreJwsSigningAlgorithm::EcdsaP256Sha256,
                pkcs1_signing_input.as_bytes(),
                signature_p384.as_bytes(),
            )
            .err()
        {
            let error_msg = "Key uses different CRV than JWT".to_string();
            match err {
                SignatureVerificationError::InvalidKey(msg) => {
                    if msg != error_msg {
                        panic!("The error should be about different CRVs")
                    }
                }
                _ => panic!("We should fail before actual validation"),
            }
        }
    }

    #[test]
    fn test_rsa_pkcs1_verification() {
        let key: CoreJsonWebKey =
            serde_json::from_str(TEST_RSA_PUB_KEY).expect("deserialization failed");

        // Source: https://tools.ietf.org/html/rfc7520#section-4.1
        let pkcs1_signing_input = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZX\
                                   hhbXBsZSJ9.\
                                   SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IH\
                                   lvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBk\
                                   b24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcm\
                                   UgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4";

        verify_signature(
            &key,
            &CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
            pkcs1_signing_input,
            "MRjdkly7_-oTPTS3AXP41iQIGKa80A0ZmTuV5MEaHoxnW2e5CZ5NlKtainoFmK\
             ZopdHM1O2U4mwzJdQx996ivp83xuglII7PNDi84wnB-BDkoBwA78185hX-Es4J\
             IwmDLJK3lfWRa-XtL0RnltuYv746iYTh_qHRD68BNt1uSNCrUCTJDt5aAE6x8w\
             W1Kt9eRo4QPocSadnHXFxnt8Is9UzpERV0ePPQdLuW3IS_de3xyIrDaLGdjluP\
             xUAhb6L2aXic1U12podGU0KLUQSE_oI-ZnmKJ3F4uOZDnd6QZWJushZ41Axf_f\
             cIe8u9ipH84ogoree7vjbU5y18kDquDg",
        );

        verify_signature(
            &key,
            &CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha384,
            pkcs1_signing_input,
            "dgTHNAePceEDFodrPybExGb2aF4fHb4bRpb_4bgYHq78fUdHFCScg0bZP51zjB\
             joH-4fr0P7Y8-Sns0GuXRy_itY2Yh0mEdXVn6HwZVOGIVRAuBkY0cAgSXGKU40\
             1G-GhamiNyNDfN2bwHftPPvCdsChtsLeAUvhWUKSLgIfT-jvMr9iZ5d0SQrUvv\
             G1ReEoBDyKUzqGQehO3CNGJ-QkI8p-fBTa2KHQxct6cU5_anSXCd-kC2rtEQS9\
             E8AcMFLA2Bv9IXsURBRU_bwMgxTG8c6ATDJM8k-zJSSP5a44EFKHUtH1xspYFo\
             KV6Za-frCV8kcFCILMf-4ATlj5Z62o1A",
        );

        verify_signature(
            &key,
            &CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha512,
            pkcs1_signing_input,
            "hIRFVu3hlbIM9Xt2V9xldCoF_94BEDg-6kVetoceakgD-9hicX0BnOI3YxR-JQ\
             0to4saNEdGP1ulvanfa5uK3PnltQr1sJ1l1x_TPNh8vdvZ5WmAtkQcZvRiK580\
             hliHV1l65yLyGH4ckDicOg5VF4BASkBw6sUO_LCB8pMJotK5jQxDbNkPmSGbFV\
             nzVXXy6QI_r6nqmguo5DMFlPeploS-aQ7ArfYqR3gKEp3l5gWWKn86lwVKRGjv\
             zeRMf3ubhKxvHUyU8cE5p1VPpOzTJ3cPwUe68s24Ehf2jpgZIIXb9XQv4L0Unf\
             GAXTBY7Rszx9LvGByoFx3eOpbMvtLQxA",
        );

        // Wrong key type
        match key
            .verify_signature(
                &CoreJwsSigningAlgorithm::EcdsaP256Sha256,
                pkcs1_signing_input.as_bytes(),
                &Vec::new(),
            )
            .expect_err("signature verification should fail")
        {
            SignatureVerificationError::InvalidKey(_) => {}
            other => panic!("unexpected error: {:?}", other),
        }

        // Wrong key usage
        let enc_key_json = "{
            \"kty\": \"RSA\",
            \"kid\": \"bilbo.baggins@hobbiton.example\",
            \"use\": \"enc\",
            \"n\": \"n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT\
                     -O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqV\
                     wGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-\
                     oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde\
                     3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuC\
                     LqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5g\
                     HdrNP5zw\",
            \"e\": \"AQAB\"
        }";
        let enc_key: CoreJsonWebKey =
            serde_json::from_str(enc_key_json).expect("deserialization failed");
        match enc_key
            .verify_signature(
                &CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
                pkcs1_signing_input.as_bytes(),
                &Vec::new(),
            )
            .expect_err("signature verification should fail")
        {
            SignatureVerificationError::InvalidKey(_) => {}
            other => panic!("unexpected error: {:?}", other),
        }

        // Key without usage specified should work
        let nousage_key_json = "{
            \"kty\": \"RSA\",
            \"kid\": \"bilbo.baggins@hobbiton.example\",
            \"n\": \"n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT\
                     -O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqV\
                     wGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-\
                     oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde\
                     3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuC\
                     LqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5g\
                     HdrNP5zw\",
            \"e\": \"AQAB\"
        }";
        let nousage_key: CoreJsonWebKey =
            serde_json::from_str(nousage_key_json).expect("deserialization failed");
        verify_signature(
            &nousage_key,
            &CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
            pkcs1_signing_input,
            "MRjdkly7_-oTPTS3AXP41iQIGKa80A0ZmTuV5MEaHoxnW2e5CZ5NlKtainoFmK\
             ZopdHM1O2U4mwzJdQx996ivp83xuglII7PNDi84wnB-BDkoBwA78185hX-Es4J\
             IwmDLJK3lfWRa-XtL0RnltuYv746iYTh_qHRD68BNt1uSNCrUCTJDt5aAE6x8w\
             W1Kt9eRo4QPocSadnHXFxnt8Is9UzpERV0ePPQdLuW3IS_de3xyIrDaLGdjluP\
             xUAhb6L2aXic1U12podGU0KLUQSE_oI-ZnmKJ3F4uOZDnd6QZWJushZ41Axf_f\
             cIe8u9ipH84ogoree7vjbU5y18kDquDg",
        );
    }

    #[test]
    fn test_rsa_pss_verification() {
        let key: CoreJsonWebKey =
            serde_json::from_str(TEST_RSA_PUB_KEY).expect("deserialization failed");
        // Source: https://tools.ietf.org/html/rfc7520#section-4.2
        let pss_signing_input =
            "eyJhbGciOiJQUzM4NCIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZXhhbXBsZSJ9.\
             SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IH\
             lvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBk\
             b24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcm\
             UgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4";

        verify_signature(
            &key,
            &CoreJwsSigningAlgorithm::RsaSsaPssSha256,
            pss_signing_input,
            "Y62we_hs07d0qJ2cT_QpbrodwDhPK9rEpNX2b3GqLHFM18YtDlPCr40Xf_yLIosIrt\
             mMP4NgDSCkn2qOcRJBD8zrHumER4JIkGZbRIwU8gYms8xKX2HaveK9vrOjbHoWLjOU\
             nyNpprYUFGdRZ6oebT61bqU2CZrJG_GcqR87W8FOn7kqrCPI7B8oNHgliMke49hOpz\
             mluL20BKN5Mb3O42nwgmiONZK0Pjm2GTIAYRUvNQ741aCWVJ3rnWvo99qWhe86ap_H\
             v40SUSaMwJig5AqC-wHIzYaYU0PlQbi83Dgw7Zft9kL2dGB0vMWY_h2HDgZU0teAcK\
             SkhyH8ZDRyYQ",
        );

        verify_signature(
            &key,
            &CoreJwsSigningAlgorithm::RsaSsaPssSha384,
            pss_signing_input,
            "cu22eBqkYDKgIlTpzDXGvaFfz6WGoz7fUDcfT0kkOy42miAh2qyBzk1xEsnk2I\
             pN6-tPid6VrklHkqsGqDqHCdP6O8TTB5dDDItllVo6_1OLPpcbUrhiUSMxbbXU\
             vdvWXzg-UD8biiReQFlfz28zGWVsdiNAUf8ZnyPEgVFn442ZdNqiVJRmBqrYRX\
             e8P_ijQ7p8Vdz0TTrxUeT3lm8d9shnr2lfJT8ImUjvAA2Xez2Mlp8cBE5awDzT\
             0qI0n6uiP1aCN_2_jLAeQTlqRHtfa64QQSUmFAAjVKPbByi7xho0uTOcbH510a\
             6GYmJUAfmWjwZ6oD4ifKo8DYM-X72Eaw",
        );

        verify_signature(
            &key,
            &CoreJwsSigningAlgorithm::RsaSsaPssSha512,
            pss_signing_input,
            "G8vtysTFbSXht_PU6NdXeYDOSIQhxcp6zFWuvtx2NCtgsm-J22CKqlapp1zjPkXTo4\
             xrYlIgFjQVQZ9Cr7KWJXK7qYUkdfJNkB1E96EQR32ocx_9RQDS_eQNlGWjoDRduD9z\
             2hKs-S0EhOy39wUeUYbcKA1MpkW71hUPI56Ou5kzclNbe22slB4mYd6Mx0dLOeFDF2\
             C7ZUDxso-cHMh4hU2E8vlp-TZUf9eqAri9T1F_pjRF8WNBj-vrqwy3bCROgIslYA8u\
             c_FEXn6fZ21up5mU9vg5_LdeBoSh4Idmz8HLn5rpVd57AsQ2PbLMsKXcpVUhwP_ID1\
             7zsAFuCEFJqA",
        );
    }

    #[test]
    fn test_hmac_sha256_verification() {
        // the original spec example also has alg=HS256, which was removed to test other signing algorithms
        let key_json = "{
            \"kty\": \"oct\",
            \"kid\": \"018c0ae5-4d9b-471b-bfd6-eef314bc7037\",
            \"use\": \"sig\",
            \"k\": \"hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg\"
        }";

        let key: CoreJsonWebKey = serde_json::from_str(key_json).expect("deserialization failed");
        // Source: https://tools.ietf.org/html/rfc7520#section-4.4
        let signing_input = "eyJhbGciOiJIUzI1NiIsImtpZCI6IjAxOGMwYWU1LTRkOWItNDcxYi1iZmQ2LW\
                             VlZjMxNGJjNzAzNyJ9.\
                             SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IH\
                             lvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBk\
                             b24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcm\
                             UgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4";

        verify_signature(
            &key,
            &CoreJwsSigningAlgorithm::HmacSha256,
            signing_input,
            "s0h6KThzkfBBBkLspW1h84VsJZFTsPPqMDA7g1Md7p0",
        );

        verify_signature(
            &key,
            &CoreJwsSigningAlgorithm::HmacSha384,
            signing_input,
            "O1jhTTHkuaiubwDZoIBLv6zjEarXHc22NNu05IdYh_yzIKGYXJQcaI2WnF4BCq7j",
        );

        verify_signature(
            &key,
            &CoreJwsSigningAlgorithm::HmacSha512,
            signing_input,
            "rdWYqzXuAJp4OW-exqIwrO8HJJQDYu0_fkTIUBHmyHMFJ0pVe7fjP7QtE7BaX-7FN5\
             YiyiM11MwIEAxzxBj6qw",
        );
    }

    fn expect_hmac(
        secret_key: &CoreHmacKey,
        message: &[u8],
        alg: &CoreJwsSigningAlgorithm,
        expected_sig_base64: &str,
    ) {
        let sig = secret_key.sign(alg, message).unwrap();
        assert_eq!(expected_sig_base64, base64::encode(&sig));

        secret_key
            .as_verification_key()
            .verify_signature(alg, message, &sig)
            .unwrap();
    }

    #[test]
    fn test_hmac_signing() {
        let secret_key = CoreHmacKey::new("my_secret_key");
        let message = "hello HMAC".as_ref();
        expect_hmac(
            &secret_key,
            message,
            &CoreJwsSigningAlgorithm::HmacSha256,
            "Pm6UhOcfx6D8LeCG4taMQNQXDTHwnVOSEcB7tidkM2M=",
        );

        expect_hmac(
            &secret_key,
            message,
            &CoreJwsSigningAlgorithm::HmacSha384,
            "BiYrxF0XjImSnfqT2n+Tu3EspstKZmVtUHbK77LHerfKNwCikuClNJDAVwr2xMLp",
        );

        expect_hmac(
            &secret_key,
            message,
            &CoreJwsSigningAlgorithm::HmacSha512,
            "glKjDMXBhB6sSKGCdLW4QeBOJ3vOgOlbMJjbeus8/KQ3dk7dtsqtrpfoDoW8lrU+rncd2jBWaKnp1zKdpEfSn\
             A==",
        );

        assert_eq!(
            secret_key.sign(&CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256, message),
            Err(SigningError::UnsupportedAlg("RS256".to_string())),
        );
        assert_eq!(
            secret_key.sign(&CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha384, message),
            Err(SigningError::UnsupportedAlg("RS384".to_string())),
        );
        assert_eq!(
            secret_key.sign(&CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha512, message),
            Err(SigningError::UnsupportedAlg("RS512".to_string())),
        );
        assert_eq!(
            secret_key.sign(&CoreJwsSigningAlgorithm::RsaSsaPssSha256, message),
            Err(SigningError::UnsupportedAlg("PS256".to_string())),
        );
        assert_eq!(
            secret_key.sign(&CoreJwsSigningAlgorithm::RsaSsaPssSha384, message),
            Err(SigningError::UnsupportedAlg("PS384".to_string())),
        );
        assert_eq!(
            secret_key.sign(&CoreJwsSigningAlgorithm::RsaSsaPssSha512, message),
            Err(SigningError::UnsupportedAlg("PS512".to_string())),
        );
        assert_eq!(
            secret_key.sign(&CoreJwsSigningAlgorithm::EcdsaP256Sha256, message),
            Err(SigningError::UnsupportedAlg("ES256".to_string())),
        );
        assert_eq!(
            secret_key.sign(&CoreJwsSigningAlgorithm::EcdsaP384Sha384, message),
            Err(SigningError::UnsupportedAlg("ES384".to_string())),
        );
        assert_eq!(
            secret_key.sign(&CoreJwsSigningAlgorithm::EcdsaP521Sha512, message),
            Err(SigningError::UnsupportedAlg("ES512".to_string())),
        );
        assert_eq!(
            secret_key.sign(&CoreJwsSigningAlgorithm::None, message),
            Err(SigningError::UnsupportedAlg("none".to_string())),
        );
    }

    const TEST_ED25519_KEY: &str = "\
        -----BEGIN PRIVATE KEY-----\n\
        MC4CAQAwBQYDK2VwBCIEICWeYPLxoZKHZlQ6rkBi11E9JwchynXtljATLqym/XS9\n\
        -----END PRIVATE KEY-----\
        ";

    // This is just a test key that isn't used for anything else.
    const TEST_RSA_KEY: &str = "\
                               -----BEGIN RSA PRIVATE KEY-----\n\
                                MIIEowIBAAKCAQEAsRMj0YYjy7du6v1gWyKSTJx3YjBzZTG0XotRP0IaObw0k+68\n\
                                30dXadjL5jVhSWNdcg9OyMyTGWfdNqfdrS6ppBqlQNgjZJdloIqL9zOLBZrDm7G4\n\
                                +qN4KeZ4/5TyEilq2zOHHGFEzXpOq/UxqVnm3J4fhjqCNaS2nKd7HVVXGBQQ+4+F\n\
                                dVT+MyJXemw5maz2F/h324TQi6XoUPEwUddxBwLQFSOlzWnHYMc4/lcyZJ8MpTXC\n\
                                MPe/YJFNtb9CaikKUdf8x4mzwH7usSf8s2d6R4dQITzKrjrEJ0u3w3eGkBBapoMV\n\
                                FBGPjP3Haz5FsVtHc5VEN3FZVIDF6HrbJH1C4QIDAQABAoIBAHSS3izM+3nc7Bel\n\
                                8S5uRxRKmcm5je6b11u6qiVUFkHWJmMRc6QmqmSThkCq+b4/vUAe1cYZ7+l02Exo\n\
                                HOcrZiEULaDP6hUKGqyjKVv3wdlRtt8kFFxlC/HBufzAiNDuFVvzw0oquwnvMCXC\n\
                                yQvtlK+/JY/PqvM32cSt+b4o9apySsHqAtdsoHHohK82jsQqIfCi1v8XYV/xRBJB\n\
                                cQMCaA0Ls3tFpmJv3JdikyyQxio4kZ5tswghC63znCp1iL+qDq1wjjKzjick9MDb\n\
                                Qzb95X09QQP201l1FPWN7Kbhj4ybg6PJGz/VHQcvILcBCoYIc0UY/OMSBt9VN9yD\n\
                                wr1WlbECgYEA37difsTMcLmUEN57sicFe1q4lxH6eqnUBjmoKBflx4oMIIyRnfjF\n\
                                Jwsu9yIiBkJfBCP85nl2tZdcV0wfZLf6amxB/KMtdfW6r8eoTDzE472OYxSIg1F5\n\
                                dI4qn2nBI0Dou0g58xj+Kv0iLaym0pxtyJkSg/rxZGwKb9a+x5WAs50CgYEAyqC0\n\
                                NcZs2BRIiT5kEOF6+MeUvarbKh1mangKHKcTdXRrvoJ+Z5izm7FifBixo/79MYpt\n\
                                0VofW0IzYKtAI9KZDq2JcozEbZ+lt/ZPH5QEXO4T39QbDoAG8BbOmEP7l+6m+7QO\n\
                                PiQ0WSNjDnwk3W7Zihgg31DH7hyxsxQCapKLcxUCgYAwERXPiPcoDSd8DGFlYK7z\n\
                                1wUsKEe6DT0p7T9tBd1v5wA+ChXLbETn46Y+oQ3QbHg/yn+vAU/5KkFD3G4uVL0w\n\
                                Gnx/DIxa+OYYmHxXjQL8r6ClNycxl9LRsS4FPFKsAWk/u///dFI/6E1spNjfDY8k\n\
                                94ab5tHwsqn3Z5tsBHo3nQKBgFUmxbSXh2Qi2fy6+GhTqU7k6G/wXhvLsR9rBKzX\n\
                                1YiVfTXZNu+oL0ptd/q4keZeIN7x0oaY/fZm0pp8PP8Q4HtXmBxIZb+/yG+Pld6q\n\
                                YE8BSd7VDu3ABapdm0JHx3Iou4mpOBcLNeiDw3vx1bgsfkTXMPFHzE0XR+H+tak9\n\
                                nlalAoGBALAmAF7WBGdOt43Rj8hPaKOM/ahj+6z3CNwVreToNsVBHoyNmiO8q7MC\n\
                                +tRo4jgdrzk1pzs66OIHfbx5P1mXKPtgPZhvI5omAY8WqXEgeNqSL1Ksp6LZ2ql/\n\
                                ouZns5xwKc9+aRL+GWoAGNzwzcjE8cP52sBy/r0rYXTs/sZo5kgV\n\
                                -----END RSA PRIVATE KEY-----\
                                ";

    fn expect_ed_sig(
        private_key: &CoreEdDsaPrivateSigningKey,
        message: &[u8],
        alg: &CoreJwsSigningAlgorithm,
        expected_sig_base64: &str,
    ) {
        let sig = private_key.sign(alg, message).unwrap();
        assert_eq!(expected_sig_base64, base64::encode(&sig));

        let public_key = private_key.as_verification_key();
        public_key.verify_signature(alg, message, &sig).unwrap();
    }

    fn expect_rsa_sig(
        private_key: &CoreRsaPrivateSigningKey,
        message: &[u8],
        alg: &CoreJwsSigningAlgorithm,
        expected_sig_base64: &str,
    ) {
        let sig = private_key.sign(alg, message).unwrap();
        assert_eq!(expected_sig_base64, base64::encode(&sig));

        let public_key = private_key.as_verification_key();
        public_key.verify_signature(alg, message, &sig).unwrap();
    }

    #[derive(Clone)]
    struct TestRng(StepRng);

    impl CryptoRng for TestRng {}
    impl RngCore for TestRng {
        fn next_u32(&mut self) -> u32 {
            self.0.next_u32()
        }
        fn next_u64(&mut self) -> u64 {
            self.0.next_u64()
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            self.0.fill_bytes(dest)
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.0.try_fill_bytes(dest)
        }
    }

    #[test]
    fn test_ed_signing() {
        let private_key = CoreEdDsaPrivateSigningKey::from_ed25519_pem(
            TEST_ED25519_KEY,
            Some(JsonWebKeyId::new("test_key".to_string())),
        )
        .unwrap();

        let public_key_jwk = private_key.as_verification_key();
        let public_key_jwk_str = serde_json::to_string(&public_key_jwk).unwrap();

        assert_eq!(
            "{\
            \"kty\":\"OKP\",\
            \"use\":\"sig\",\
            \"kid\":\"test_key\",\
            \"crv\":\"Ed25519\",\
            \"x\":\"E6lXdyel1n9C1lcr3FK8OsfsfO2ZgcWhPflJ6yIf7e8\"\
            }",
            public_key_jwk_str
        );

        let message = "hello EdDsa".as_ref();
        expect_ed_sig(
            &private_key,
            message,
            &CoreJwsSigningAlgorithm::EdDsaEd25519,
            "XqP8sXaPrQa37+2lw+aiXv+6pegjioYUgo1/ShcX6kRhD2Vxh8DrQUbQlaGbljLJTNNc453E2Axp+Mxm+4OVAQ=="
        );

        assert_eq!(
            private_key.sign(&CoreJwsSigningAlgorithm::HmacSha256, message),
            Err(SigningError::UnsupportedAlg("HS256".to_string())),
        );

        assert_eq!(
            private_key.sign(&CoreJwsSigningAlgorithm::None, message),
            Err(SigningError::UnsupportedAlg("none".to_string())),
        );
    }

    #[test]
    fn test_rsa_signing() {
        let private_key = CoreRsaPrivateSigningKey::from_pem_internal(
            TEST_RSA_KEY,
            // Constant salt used for PSS test vectors below.
            Box::new(TestRng(StepRng::new(127, 0))),
            Some(JsonWebKeyId::new("test_key".to_string())),
        )
        .unwrap();

        let public_key_jwk = private_key.as_verification_key();
        let public_key_jwk_str = serde_json::to_string(&public_key_jwk).unwrap();
        assert_eq!(
            "{\
             \"kty\":\"RSA\",\
             \"use\":\"sig\",\
             \"kid\":\"test_key\",\
             \"n\":\"sRMj0YYjy7du6v1gWyKSTJx3YjBzZTG0XotRP0IaObw0k-6830dXadjL5jVhSWNdcg9OyMyTGWfdNq\
             fdrS6ppBqlQNgjZJdloIqL9zOLBZrDm7G4-qN4KeZ4_5TyEilq2zOHHGFEzXpOq_UxqVnm3J4fhjqCNaS2nKd7\
             HVVXGBQQ-4-FdVT-MyJXemw5maz2F_h324TQi6XoUPEwUddxBwLQFSOlzWnHYMc4_lcyZJ8MpTXCMPe_YJFNtb\
             9CaikKUdf8x4mzwH7usSf8s2d6R4dQITzKrjrEJ0u3w3eGkBBapoMVFBGPjP3Haz5FsVtHc5VEN3FZVIDF6Hrb\
             JH1C4Q\",\
             \"e\":\"AQAB\"\
             }",
            public_key_jwk_str
        );

        let message = "hello RSA".as_ref();
        expect_rsa_sig(
            &private_key,
            message,
            &CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
            "KBvV+F7Xofg4i4qUA0JEqfhQQdjZ7ralUYTPKRIitaKL4a6ni+abagsHs5V63+bmQF5t6DM4aRH2ZC943Tonkr\
            AUY1mpaqic2vqtrtWk3cyrcHtkPCLNKzFf/6xvHPjeKH1Bu/qTQ0mn+hN6taOgw3ORbm6P9MkelX1RVEia98uwB\
            Zn2BxKeqNYm11vqKDyS5ZFzHwpPrC4rri/uTIcXsQEXB+Lbb+naDpQn8qJqP+S+uM2LGWIXp5ExAJ55A111nIqE\
            Ap0aKwf2U8Q81DWI8lbHbL1dd7FRDtZKm+ainO5ck4L/axtH7C4GIZd+TiXL3iYpiWmNkqlwv9WsNPe8Rg==",
        );

        expect_rsa_sig(
            &private_key,
            message,
            &CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha384,
            "YsyhW9DkIoNJPqTNY7pidJi5wWtQGr4xety+2Zt1DKNMG0ENFkxCGPLCYcL9vGSS9kfkrPtQ3Eve7g9DKfg1fg\
            071SXJHxAlK0iC8mVYfQrxxyFlQDIPEhvCJx6VkWVm2jJhN+vByGRJLTo2n3gtYtMREfz+c5xnXWeIy+JQ0LXOy\
            SyOZl0qHxn1VteczH79uCK0Vv8ZH3IfbQMU+2HjbVeUYRzCoAhlT4V2GY4U1pCrZBlfEyhr0ncHz90FRvvhLT3y\
            SlHa7yY7CRJ+z1CLBOzBiH1Eko4tIJKy/qO9M6EGeFtXhqd4td5g2oY/mUZYjHYjgcDO+wAXrZ9lP/ZVUg==",
        );

        expect_rsa_sig(
            &private_key,
            message,
            &CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha512,
            "GXN3rmZhlJw46FHoqiuELcIi6iUr3cVC0HZpjBJhrTVfta/8a4PpzmLbQxjdb1cdU/56XDXkqDSNvzRn4PwAOL\
            460n0Eg8d8mxwPRHQuyypze9240FEw3lyjp5uPJHn5PrmeelczJ1Xseinmp+JwpKHiHhmxp7FjgJc/o3J/hlz0n\
            G1cgTndtrlp5JPJOJNt4XfgIgqoobH5Wk3ML35C50mD93Ld6V6nn6rK72wgecK1SDXeF4ztQUAjg4VTEojLm5VF\
            kfR7kXV0dIbAvZXDa1uuIOlVDIRfF93rxme1Ze46Dywan+zfsGCcpFfFAsnGLsgNDmATB8IS1lTf1SGMoA==",
        );

        expect_rsa_sig(
            &private_key,
            message,
            &CoreJwsSigningAlgorithm::RsaSsaPssSha256,
            "sPwTRDAOGOZr0ofAL/lMSXaR5L5aoFANLei4bqAQFHiFxDDrWZZ28MZiunwCGakOM8Itwas+sIX6vo3VTy9d5Bh\
            Cotb/gY5DhMX/iZJubfS8U1fB8rFWXDpREeAegGvXPjBd0A4M6z9it9Tss43dYqO12mYEpz6rFvbHJKSR9Hnmak4\
            F8TcuZswYtjhHhiib05PGjeJTo/5F15WtR7RYK4slYGOU4mf5wzZSpfgifJ2XjyQQe6oCFvVXftVtiQhEljHiEGv\
            GZH5y4FA7h06PqkHMwQEnRsBhVm4pUqRi641tglZ3HZcoxYUE8AdMX7ltJzy/vpOew2bVGoF3mUnlZw==",
        );

        expect_rsa_sig(
            &private_key,
            message,
            &CoreJwsSigningAlgorithm::RsaSsaPssSha384,
            "m0EsYFpNa5YjvEYPcfUpXPMqAWmWmkTaQiyK2HZ9Ejt+cBO/S5jcVqd0y2rCDMV1DpSb/JI8uhwp+qYm/2YKpIa\
            zp+u9PpjlL3jvYn19WbwJTCztJ9XSjcEbtkf1fS/d/BU7FgQzYIE0k++QqHjgzkTI5+2XLYX2WP5dc0r67Or5xaF\
            0ixL1edpEDKfgF3jiKuLmR2dv4MWHPLYRb1I0zm5C/E7g57DfJT4uNzmLX9gTGr4xe6CxVEYy4eFdE+q1O5J6RXd\
            FZnl4qFK9+x1pk0dhWkpIEaKhweI7YP79iFPnAiUnRM6BsdY+puwjGlaaGtYVFcuPO4uXEXtB1AnsEQ==",
        );

        expect_rsa_sig(
            &private_key,
            message,
            &CoreJwsSigningAlgorithm::RsaSsaPssSha512,
            "N8BMNKm1dMOm0/BLzAjtnzvRlVtzgO8fUeKnfvUtK8XWeII5nk74hE3AoAJNPLuTninYtfaF68Supu5CsCJAqO9\
            1JnVvG8P1DX19iCTzJ83o69+kluBIz7x0l796RysDhqcjybGC+fj0M5MpgkNNcKlNwRixus3sfgCgh3mEB+E1Q11\
            hQKjCTdyOcqzGoima+Na17VBWzU3XXLvB328UfkV2nswBlLUsZMT3I4n/aIziENQCLVPlLdX8z+1NjHSAgd9rZMf\
            gfy0eMsjNuQpqPzVW3mbxlCMMVWpd8LKBprfa291xEk1wwvJCuU9EK7QmQPmYa1HAh+E+R2Dw3ibHdA==",
        );

        assert_eq!(
            private_key.sign(&CoreJwsSigningAlgorithm::HmacSha256, message),
            Err(SigningError::UnsupportedAlg("HS256".to_string())),
        );
        assert_eq!(
            private_key.sign(&CoreJwsSigningAlgorithm::HmacSha384, message),
            Err(SigningError::UnsupportedAlg("HS384".to_string())),
        );
        assert_eq!(
            private_key.sign(&CoreJwsSigningAlgorithm::HmacSha512, message),
            Err(SigningError::UnsupportedAlg("HS512".to_string())),
        );
        assert_eq!(
            private_key.sign(&CoreJwsSigningAlgorithm::EcdsaP256Sha256, message),
            Err(SigningError::UnsupportedAlg("ES256".to_string())),
        );
        assert_eq!(
            private_key.sign(&CoreJwsSigningAlgorithm::EcdsaP384Sha384, message),
            Err(SigningError::UnsupportedAlg("ES384".to_string())),
        );
        assert_eq!(
            private_key.sign(&CoreJwsSigningAlgorithm::EcdsaP521Sha512, message),
            Err(SigningError::UnsupportedAlg("ES512".to_string())),
        );
        assert_eq!(
            private_key.sign(&CoreJwsSigningAlgorithm::None, message),
            Err(SigningError::UnsupportedAlg("none".to_string())),
        );
    }

    #[test]
    fn test_rsa_pss_signing() {
        let private_key = CoreRsaPrivateSigningKey::from_pem(TEST_RSA_KEY, None).unwrap();

        const MESSAGE: &str = "This is a probabilistic signature scheme";
        let sig1 = private_key
            .sign(
                &CoreJwsSigningAlgorithm::RsaSsaPssSha256,
                MESSAGE.as_bytes(),
            )
            .unwrap();
        let sig2 = private_key
            .sign(
                &CoreJwsSigningAlgorithm::RsaSsaPssSha256,
                MESSAGE.as_bytes(),
            )
            .unwrap();

        assert_ne!(sig1, sig2);
    }

    // Tests that JsonWebKeySet ignores unsupported keys during deserialization so that clients can
    // use providers that include unsupported keys as long as they only use supported ones to sign
    // payloads.
    #[test]
    fn test_jwks_unsupported_key() {
        let jwks_json = "{
            \"keys\": [
                {
                    \"kty\": \"RSA\",
                    \"use\": \"sig\",
                    \"kid\": \"2011-04-29\",
                    \"n\": \"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhD\
                             R1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6C\
                             f0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1\
                             n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1\
                             jF44-csFCur-kEgU8awapJzKnqDKgw\",
                    \"e\": \"AQAB\"
                },
                {
                    \"kty\": \"MAGIC\",
                    \"use\": \"sig\",
                    \"kid\": \"2040-01-01\",
                    \"magic\": \"magic\"
                },
                {
                    \"kty\": \"EC\",
                    \"use\": \"sig\",
                    \"kid\": \"2011-05-01\",
                    \"crv\": \"P-256\",
                    \"x\": \"kXCGZIr3oI6sKbnT6rRsIdxFXw3_VbLk_cveajgqXk8\",
                    \"y\": \"StDvKIgXqAxJ6DuebREh-1vgvZRW3dfrOxSIKzBtRI0\"
                }
            ]
        }";
        let jwks = serde_json::from_str::<CoreJsonWebKeySet>(jwks_json)
            .expect("deserialization should succeed");

        assert_eq!(jwks.keys().len(), 2);

        assert_eq!(jwks.keys()[0].kty, CoreJsonWebKeyType::RSA);
        assert_eq!(jwks.keys()[0].use_, Some(CoreJsonWebKeyUse::Signature));
        assert_eq!(
            jwks.keys()[0].kid,
            Some(JsonWebKeyId::new("2011-04-29".to_string()))
        );

        assert_eq!(jwks.keys()[1].kty, CoreJsonWebKeyType::EllipticCurve);
        assert_eq!(jwks.keys()[1].use_, Some(CoreJsonWebKeyUse::Signature));
        assert_eq!(
            jwks.keys()[1].kid,
            Some(JsonWebKeyId::new("2011-05-01".to_string()))
        );
        assert_eq!(jwks.keys()[1].crv, Some(CoreJsonCurveType::P256));
    }

    // Tests that JsonWebKeySet ignores keys with unsupported algorithms
    #[cfg(feature = "jwk-alg")]
    #[test]
    fn test_jwks_unsupported_alg() {
        let jwks_json = "{
            \"keys\": [
                {
                    \"kty\": \"EC\",
                    \"alg\": \"MAGIC\",
                    \"crv\": \"P-256\",
                    \"x\": \"kXCGZIr3oI6sKbnT6rRsIdxFXw3_VbLk_cveajgqXk8\",
                    \"y\": \"StDvKIgXqAxJ6DuebREh-1vgvZRW3dfrOxSIKzBtRI0\"
                },
                {
                    \"kty\": \"EC\",
                    \"alg\": \"ES256\",
                    \"kid\": \"2011-05-01\",
                    \"crv\": \"P-256\",
                    \"x\": \"kXCGZIr3oI6sKbnT6rRsIdxFXw3_VbLk_cveajgqXk8\",
                    \"y\": \"StDvKIgXqAxJ6DuebREh-1vgvZRW3dfrOxSIKzBtRI0\"
                }
            ]
        }";
        let jwks = serde_json::from_str::<CoreJsonWebKeySet>(jwks_json)
            .expect("deserialization should succeed");
        assert_eq!(jwks.keys().len(), 1);
        let key = &jwks.keys()[0];
        assert_eq!(&key.kid, &Some(JsonWebKeyId::new("2011-05-01".to_string())));
    }

    // Test filtering keys by algorithm
    #[cfg(feature = "jwk-alg")]
    #[test]
    fn test_jwks_same_kid_different_alg() {
        let jwks_json = "{
            \"keys\": [
                {
                    \"kty\": \"RSA\",
                    \"use\": \"sig\",
                    \"kid\": \"2011-04-29\",
                    \"alg\": \"PS256\",
                    \"n\": \"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhD\
                             R1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6C\
                             f0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1\
                             n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1\
                             jF44-csFCur-kEgU8awapJzKnqDKgw\",
                    \"e\": \"AQAB\"
                },
                {
                    \"kty\": \"RSA\",
                    \"use\": \"sig\",
                    \"kid\": \"2011-04-29\",
                    \"alg\": \"PS384\",
                    \"n\": \"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhD\
                             R1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6C\
                             f0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1\
                             n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1\
                             jF44-csFCur-kEgU8awapJzKnqDKgw\",
                    \"e\": \"AQAB\"
                }
            ]
        }";
        let jwks = serde_json::from_str::<CoreJsonWebKeySet>(jwks_json)
            .expect("deserialization should succeed");
        assert_eq!(jwks.keys().len(), 2);

        {
            let keys = jwks.filter_keys(
                &Some(JsonWebKeyId::new("2011-04-29".to_string())),
                &CoreJwsSigningAlgorithm::RsaSsaPssSha384,
            );
            assert_eq!(keys.len(), 1);
            assert_eq!(
                keys[0].alg,
                Some(crate::jwt::JsonWebTokenAlgorithm::Signature(
                    CoreJwsSigningAlgorithm::RsaSsaPssSha384,
                    std::marker::PhantomData
                ))
            );
        }

        {
            let keys = jwks.filter_keys(
                &Some(JsonWebKeyId::new("2011-04-29".to_string())),
                &CoreJwsSigningAlgorithm::RsaSsaPssSha512,
            );
            assert_eq!(keys.len(), 0);
        }
    }
}
