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
    use base64;
    use oauth2::prelude::*;
    use serde_json;

    use super::super::super::{Base64UrlEncodedBytes, JsonWebKey, JsonWebKeyId};
    use super::{CoreJsonWebKey, CoreJsonWebKeyType, CoreJsonWebKeyUse, CoreJwsSigningAlgorithm};

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

    const RFC7520_RSA_KEY: &str = "{
        \"kty\": \"RSA\",
        \"kid\": \"bilbo.baggins@hobbiton.example\",
        \"use\": \"sig\",
        \"n\": \"n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT\
                 -O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqV\
                 wGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-\
                 oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde\
                 3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuC\
                 LqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5g\
                 HdrNP5zw\",
        \"e\": \"AQAB\"
    }";

    const RFC7520_HMAC_KEY: &str = "{
        \"kty\": \"oct\",
        \"kid\": \"018c0ae5-4d9b-471b-bfd6-eef314bc7037\",
        \"use\": \"sig\",
        \"alg\": \"HS256\",
        \"k\": \"hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg\"
    }";

    fn verify_signature(
        key: &CoreJsonWebKey,
        alg: &CoreJwsSigningAlgorithm,
        signing_input: &str,
        signature_base64: &str,
    ) {
        let signature =
            base64::decode_config(signature_base64, base64::URL_SAFE_NO_PAD)
                .expect("failed to base64url decode");
        key.verify_signature(
            alg,
            signing_input,
            &signature,
        ).expect("signature verification failed");
        key.verify_signature(
            alg,
            &(signing_input.to_string() + "foobar"),
            &signature,
        ).expect_err("signature verification should fail");
    }

    #[test]
    fn test_rsa_verification() {
        let key: CoreJsonWebKey = serde_json::from_str(RFC7520_RSA_KEY)
            .expect("deserialization failed");

        // Source: https://tools.ietf.org/html/rfc7520#section-4.1
        let pkcs1_signing_input =
            "eyJhbGciOiJSUzI1NiIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZX\
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

        // Source: https://tools.ietf.org/html/rfc7520#section-4.2
        let pss_signing_input =
            "eyJhbGciOiJQUzM4NCIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZX\
             hhbXBsZSJ9.\
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
        let key: CoreJsonWebKey = serde_json::from_str(RFC7520_HMAC_KEY)
            .expect("deserialization failed");
        // Source: https://tools.ietf.org/html/rfc7520#section-4.4
        let signing_input =
            "eyJhbGciOiJIUzI1NiIsImtpZCI6IjAxOGMwYWU1LTRkOWItNDcxYi1iZmQ2LW\
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
}
