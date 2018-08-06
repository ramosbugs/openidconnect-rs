use oauth2::helpers::variant_name;
use oauth2::prelude::*;
use ring::digest;
use ring::signature as ring_signature;

use super::super::types::helpers::deserialize_option_or_none;
use super::super::{
    Base64UrlEncodedBytes, JsonWebKey, JsonWebKeyId, JsonWebKeyType, JsonWebKeyUse,
    JwsSigningAlgorithm, SignatureVerificationError,
};
use super::{crypto, CoreJwsSigningAlgorithm};

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

    // From RFC 7517, Section 4: "Additional members can be present in the JWK; if not understood
    // by implementations encountering them, they MUST be ignored.  Member names used for
    // representing key parameters for different keys types need not be distinct."
    // Hence, we set fields we fail to deserialize (understand) as None.
    #[serde(default, deserialize_with = "deserialize_option_or_none")]
    pub(crate) n: Option<Base64UrlEncodedBytes>,
    #[serde(default, deserialize_with = "deserialize_option_or_none")]
    pub(crate) e: Option<Base64UrlEncodedBytes>,

    // Used for symmetric keys, which we only generate internally from the client secret; these
    // are never part of the JWK set.
    #[serde(default, deserialize_with = "deserialize_option_or_none")]
    pub(crate) k: Option<Base64UrlEncodedBytes>,
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
        return Self {
            kty: CoreJsonWebKeyType::Symmetric,
            use_: None,
            kid: None,
            n: None,
            e: None,
            k: Some(Base64UrlEncodedBytes::new(key)),
        };
    }

    fn verify_signature(
        &self,
        signature_alg: &CoreJwsSigningAlgorithm,
        msg: &str,
        signature: &[u8],
    ) -> Result<(), SignatureVerificationError> {
        if let Some(key_use) = self.key_use() {
            if *key_use != CoreJsonWebKeyUse::Signature {
                return Err(SignatureVerificationError::InvalidKey(
                    "key usage not permitted for digital signatures".to_string(),
                ));
            }
        }

        let key_type = signature_alg
            .key_type()
            .map_err(SignatureVerificationError::Other)?;
        if *self.key_type() != key_type {
            return Err(SignatureVerificationError::InvalidKey(
                "key type does not match signature algorithm".to_string(),
            ));
        }

        // FIXME: add test cases for each of these
        match *signature_alg {
            CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256 => crypto::verify_rsa_signature(
                self,
                &ring_signature::RSA_PKCS1_2048_8192_SHA256,
                msg,
                signature,
            ),
            CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha384 => crypto::verify_rsa_signature(
                self,
                &ring_signature::RSA_PKCS1_2048_8192_SHA384,
                msg,
                signature,
            ),
            CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha512 => crypto::verify_rsa_signature(
                self,
                &ring_signature::RSA_PKCS1_2048_8192_SHA512,
                msg,
                signature,
            ),
            CoreJwsSigningAlgorithm::RsaSsaPssSha256 => crypto::verify_rsa_signature(
                self,
                &ring_signature::RSA_PSS_2048_8192_SHA256,
                msg,
                signature,
            ),
            CoreJwsSigningAlgorithm::RsaSsaPssSha384 => crypto::verify_rsa_signature(
                self,
                &ring_signature::RSA_PSS_2048_8192_SHA384,
                msg,
                signature,
            ),
            CoreJwsSigningAlgorithm::RsaSsaPssSha512 => crypto::verify_rsa_signature(
                self,
                &ring_signature::RSA_PSS_2048_8192_SHA512,
                msg,
                signature,
            ),
            CoreJwsSigningAlgorithm::HmacSha256 => {
                crypto::verify_hmac(self, &digest::SHA256, msg, signature)
            }
            CoreJwsSigningAlgorithm::HmacSha384 => {
                crypto::verify_hmac(self, &digest::SHA384, msg, signature)
            }
            CoreJwsSigningAlgorithm::HmacSha512 => {
                crypto::verify_hmac(self, &digest::SHA512, msg, signature)
            }
            ref other => Err(SignatureVerificationError::UnsupportedAlg(
                variant_name(other).to_string(),
            )),
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

#[cfg(test)]
mod tests {
    use oauth2::prelude::*;
    use serde_json;

    use super::super::super::{Base64UrlEncodedBytes, JsonWebKeyId};
    use super::{CoreJsonWebKey, CoreJsonWebKeyType, CoreJsonWebKeyUse};

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
    fn test_core_jwk_deserialization_symmetric() {
        let json = "{\
            \"kty\":\"oct\",
            \"alg\":\"A128KW\",
            \"k\":\"GawgguFyGrWKav7AX4VKUg\"
        }";

        let key: CoreJsonWebKey = serde_json::from_str(json).expect("deserialization failed");
        assert_eq!(key.kty, CoreJsonWebKeyType::Symmetric);
        assert_eq!(key.use_, None);
        assert_eq!(key.kid, None);
        assert_eq!(key.n, None);
        assert_eq!(key.e, None);
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

        assert!(
            serde_json::from_str::<CoreJsonWebKey>(json)
            .expect_err("deserialization must fail when duplicate fields are present")
            .to_string()
            // This is probably not ideal since the serde/serde_json contracts don't guarantee this
            // error message. However, we want to be sure that this fails for the expected reason
            // and not by happenstance, so this is fine for now.
            .contains("duplicate field")
        );
    }
}
