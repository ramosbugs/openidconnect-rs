use std::fmt::{Debug, Formatter, Result as FormatterResult};
use std::marker::PhantomData;
use std::ops::Deref;
use std::str;

use base64;
use oauth2::prelude::NewType;
use serde::de::{DeserializeOwned, Error as DeserializeError, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json;

use super::{
    JsonWebKey, JsonWebKeyId, JsonWebKeyType, JsonWebKeyUse, JweContentEncryptionAlgorithm,
    JwsSigningAlgorithm, SignatureVerificationError,
};

new_type![#[derive(
    Deserialize, Eq, Hash, Ord, PartialOrd, Serialize,
)]
JsonWebTokenContentType(String)];

new_type![#[derive(
    Deserialize, Eq, Hash, Ord, PartialOrd, Serialize,
)]
JsonWebTokenType(String)];

#[derive(Clone, Debug, PartialEq)]
pub enum JsonWebTokenAlgorithm<JE, JS, JT>
where
    JE: JweContentEncryptionAlgorithm,
    JS: JwsSigningAlgorithm<JT>,
    JT: JsonWebKeyType,
{
    Encryption(JE),
    // This is ugly, but we don't expose this module via the public API, so it's fine.
    Signature(JS, PhantomData<JT>),
    ///
    /// No digital signature or MAC performed.
    ///
    /// # Security Warning
    ///
    /// This algorithm provides no security over the integrity of the JSON Web Token. Clients
    /// should be careful not to rely on unsigned JWT's for security purposes. See
    /// [Critical vulnerabilities in JSON Web Token libraries](
    ///     https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/) for
    /// further discussion.
    ///
    None,
}
impl<'de, JE, JS, JT> Deserialize<'de> for JsonWebTokenAlgorithm<JE, JS, JT>
where
    JE: JweContentEncryptionAlgorithm,
    JS: JwsSigningAlgorithm<JT>,
    JT: JsonWebKeyType,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value: serde_json::Value = Deserialize::deserialize(deserializer)?;
        // TODO: get rid of this clone() (see below)
        let s: String = serde_json::from_value(value.clone()).map_err(D::Error::custom)?;

        // NB: These comparisons are case sensitive. Section 4.1.1 of RFC 7515 states: "The "alg"
        // value is a case-sensitive ASCII string containing a StringOrURI value."
        if s == "none" {
            Ok(JsonWebTokenAlgorithm::None)
        // TODO: Figure out a way to deserialize the enums without giving up ownership
        } else if let Ok(val) = serde_json::from_value::<JE>(value.clone()) {
            Ok(JsonWebTokenAlgorithm::Encryption(val))
        } else if let Ok(val) = serde_json::from_value::<JS>(value.clone()) {
            Ok(JsonWebTokenAlgorithm::Signature(val, PhantomData))
        } else {
            Err(D::Error::custom(format!(
                "unrecognized JSON Web Algorithm `{}`",
                s
            )))
        }
    }
}
impl<JE, JS, JT> Serialize for JsonWebTokenAlgorithm<JE, JS, JT>
where
    JE: JweContentEncryptionAlgorithm,
    JS: JwsSigningAlgorithm<JT>,
    JT: JsonWebKeyType,
{
    fn serialize<SE>(&self, serializer: SE) -> Result<SE::Ok, SE::Error>
    where
        SE: Serializer,
    {
        match self {
            JsonWebTokenAlgorithm::Encryption(ref enc) => enc.serialize(serializer),
            JsonWebTokenAlgorithm::Signature(ref sig, _) => sig.serialize(serializer),
            JsonWebTokenAlgorithm::None => serializer.serialize_str("none"),
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct JsonWebTokenHeader<JE, JS, JT>
where
    JE: JweContentEncryptionAlgorithm,
    JS: JwsSigningAlgorithm<JT>,
    JT: JsonWebKeyType,
{
    #[serde(
        bound = "JE: JweContentEncryptionAlgorithm, JS: JwsSigningAlgorithm<JT>, JT: JsonWebKeyType"
    )]
    pub alg: JsonWebTokenAlgorithm<JE, JS, JT>,
    // Additional critical header parameters that must be understood by this implementation. Since
    // we don't understand any such extensions, we reject any JWT with this value present (the
    // spec specifically prohibits including public (standard) headers in this field).
    // See https://tools.ietf.org/html/rfc7515#section-4.1.11.
    pub crit: Option<Vec<String>>,
    pub cty: Option<JsonWebTokenContentType>,
    pub kid: Option<JsonWebKeyId>,
    pub typ: Option<JsonWebTokenType>,
    // Other JOSE header fields are omitted since the OpenID Connect spec specifically says that
    // the "x5u", "x5c", "jku", "jwk" header parameter fields SHOULD NOT be used.
    // See http://openid.net/specs/openid-connect-core-1_0-final.html#IDToken.
    #[serde(skip)]
    _phantom_jt: PhantomData<JT>,
}

pub trait JsonWebTokenPayloadDeserialize<C>: Clone + Debug + PartialEq
where
    C: Debug + DeserializeOwned + Serialize,
{
    fn deserialize<E: DeserializeError>(payload: &str) -> Result<C, E>;
}

#[derive(Clone, Debug, PartialEq)]
pub struct JsonWebTokenJsonPayloadDeserializer;
impl<C> JsonWebTokenPayloadDeserialize<C> for JsonWebTokenJsonPayloadDeserializer
where
    C: Debug + DeserializeOwned + Serialize,
{
    fn deserialize<E: DeserializeError>(payload: &str) -> Result<C, E> {
        serde_json::from_str(payload).map_err(|err| {
            DeserializeError::custom(format!("Failed to parse claims JSON: {:?}", err))
        })
    }
}

// Helper trait so that we can get borrowed claims when we have a reference to the JWT and owned
// claims when we own the JWT.
pub trait JsonWebTokenAccess<C, JE, JS, JT>
where
    C: Debug + DeserializeOwned + Serialize,
    JE: JweContentEncryptionAlgorithm,
    JS: JwsSigningAlgorithm<JT>,
    JT: JsonWebKeyType,
{
    type ReturnType;

    fn unverified_header(&self) -> &JsonWebTokenHeader<JE, JS, JT>;
    fn unverified_claims(self) -> Self::ReturnType;
    fn unverified_claims_ref(&self) -> &C;

    fn claims<JU, JW>(
        self,
        signature_alg: &JS,
        key: &JW,
    ) -> Result<Self::ReturnType, SignatureVerificationError>
    where
        JU: JsonWebKeyUse,
        JW: JsonWebKey<JS, JT, JU>;
}

#[derive(Clone, Debug, PartialEq)]
pub struct JsonWebToken<C, JE, JS, JT, P>
where
    C: Debug + DeserializeOwned + Serialize,
    JE: JweContentEncryptionAlgorithm,
    JS: JwsSigningAlgorithm<JT>,
    JT: JsonWebKeyType,
    P: JsonWebTokenPayloadDeserialize<C>,
{
    header: JsonWebTokenHeader<JE, JS, JT>,
    claims: C,
    signature: Vec<u8>,
    signing_input: String,
    raw_token: String,
    _phantom: PhantomData<P>,
}
// Owned JWT.
impl<C, JE, JS, JT, P> JsonWebTokenAccess<C, JE, JS, JT> for JsonWebToken<C, JE, JS, JT, P>
where
    C: Debug + DeserializeOwned + Serialize,
    JE: JweContentEncryptionAlgorithm,
    JS: JwsSigningAlgorithm<JT>,
    JT: JsonWebKeyType,
    P: JsonWebTokenPayloadDeserialize<C>,
{
    type ReturnType = C;
    fn unverified_header(&self) -> &JsonWebTokenHeader<JE, JS, JT> {
        &self.header
    }
    fn unverified_claims(self) -> Self::ReturnType {
        self.claims
    }
    fn unverified_claims_ref(&self) -> &C {
        &self.claims
    }
    fn claims<JU, JW>(
        self,
        signature_alg: &JS,
        key: &JW,
    ) -> Result<Self::ReturnType, SignatureVerificationError>
    where
        JU: JsonWebKeyUse,
        JW: JsonWebKey<JS, JT, JU>,
    {
        key.verify_signature(signature_alg, &self.signing_input, &self.signature)?;
        Ok(self.claims)
    }
}
// Borrowed JWT.
impl<'a, C, JE, JS, JT, P> JsonWebTokenAccess<C, JE, JS, JT> for &'a JsonWebToken<C, JE, JS, JT, P>
where
    C: Debug + DeserializeOwned + Serialize,
    JE: JweContentEncryptionAlgorithm,
    JS: JwsSigningAlgorithm<JT>,
    JT: JsonWebKeyType,
    P: JsonWebTokenPayloadDeserialize<C>,
{
    type ReturnType = &'a C;
    fn unverified_header(&self) -> &JsonWebTokenHeader<JE, JS, JT> {
        &self.header
    }
    fn unverified_claims(self) -> Self::ReturnType {
        &self.claims
    }
    fn unverified_claims_ref(&self) -> &C {
        &self.claims
    }
    fn claims<JU, JW>(
        self,
        signature_alg: &JS,
        key: &JW,
    ) -> Result<Self::ReturnType, SignatureVerificationError>
    where
        JU: JsonWebKeyUse,
        JW: JsonWebKey<JS, JT, JU>,
    {
        key.verify_signature(signature_alg, &self.signing_input, &self.signature)?;
        Ok(&self.claims)
    }
}
impl<'de, C, JE, JS, JT, P> Deserialize<'de> for JsonWebToken<C, JE, JS, JT, P>
where
    C: Debug + DeserializeOwned + Serialize,
    JE: JweContentEncryptionAlgorithm,
    JS: JwsSigningAlgorithm<JT>,
    JT: JsonWebKeyType,
    P: JsonWebTokenPayloadDeserialize<C>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct JsonWebTokenVisitor<
            C: Debug + DeserializeOwned + Serialize,
            JE: JweContentEncryptionAlgorithm,
            JS: JwsSigningAlgorithm<JT>,
            JT: JsonWebKeyType,
            P: JsonWebTokenPayloadDeserialize<C>,
        >(
            PhantomData<C>,
            PhantomData<JE>,
            PhantomData<JS>,
            PhantomData<JT>,
            PhantomData<P>,
        );
        impl<'de, C, JE, JS, JT, P> Visitor<'de> for JsonWebTokenVisitor<C, JE, JS, JT, P>
        where
            C: Debug + DeserializeOwned + Serialize,
            JE: JweContentEncryptionAlgorithm,
            JS: JwsSigningAlgorithm<JT>,
            JT: JsonWebKeyType,
            P: JsonWebTokenPayloadDeserialize<C>,
        {
            type Value = JsonWebToken<C, JE, JS, JT, P>;

            fn expecting(&self, formatter: &mut Formatter) -> FormatterResult {
                formatter.write_str("JsonWebToken")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: DeserializeError,
            {
                let raw_token = v.to_string();
                let header: JsonWebTokenHeader<JE, JS, JT>;
                let claims: C;
                let signature;
                let signing_input;

                {
                    let parts = raw_token.split('.').collect::<Vec<_>>();

                    // NB: We avoid including the full claims encoding in the error output to avoid
                    // clients potentially logging sensitive values.
                    if parts.len() != 3 {
                        return Err(DeserializeError::custom(format!(
                            "Invalid JSON web token: found {} parts (expected 3)",
                            parts.len()
                        )));
                    }

                    let header_json_raw = base64::decode_config(parts[0], base64::URL_SAFE_NO_PAD)
                        .map_err(|err| {
                            DeserializeError::custom(format!(
                                "Invalid base64url header encoding: {:?}",
                                err
                            ))
                        })?;
                    let header_json = &str::from_utf8(&header_json_raw).map_err(|err| {
                        DeserializeError::custom(format!(
                            "Invalid UTF-8 header encoding: {:?}",
                            err
                        ))
                    })?;
                    header = serde_json::from_str(header_json).map_err(|err| {
                        DeserializeError::custom(format!("Failed to parse header JSON: {:?}", err))
                    })?;

                    let claims_json_raw = base64::decode_config(parts[1], base64::URL_SAFE_NO_PAD)
                        .map_err(|err| {
                            DeserializeError::custom(format!(
                                "Invalid base64url claims encoding: {:?}",
                                err
                            ))
                        })?;
                    let claims_json = &str::from_utf8(&claims_json_raw).map_err(|err| {
                        DeserializeError::custom(format!("Invalid UTF-8 encoding: {:?}", err))
                    })?;
                    claims = P::deserialize::<E>(claims_json)?;

                    signature = base64::decode_config(parts[2], base64::URL_SAFE_NO_PAD).map_err(
                        |err| {
                            DeserializeError::custom(format!(
                                "Invalid base64url signature encoding: {:?}",
                                err
                            ))
                        },
                    )?;

                    signing_input = format!("{}.{}", parts[0], parts[1]);
                }

                Ok(JsonWebToken {
                    header,
                    claims,
                    signature,
                    signing_input,
                    raw_token,
                    _phantom: PhantomData,
                })
            }
        }
        deserializer.deserialize_str(JsonWebTokenVisitor(
            PhantomData,
            PhantomData,
            PhantomData,
            PhantomData,
            PhantomData,
        ))
    }
}
impl<C, JE, JS, JT, P> Serialize for JsonWebToken<C, JE, JS, JT, P>
where
    C: Debug + DeserializeOwned + Serialize,
    JE: JweContentEncryptionAlgorithm,
    JS: JwsSigningAlgorithm<JT>,
    JT: JsonWebKeyType,
    P: JsonWebTokenPayloadDeserialize<C>,
{
    fn serialize<SE>(&self, serializer: SE) -> Result<SE::Ok, SE::Error>
    where
        SE: Serializer,
    {
        serializer.serialize_str(&self.raw_token)
    }
}

#[cfg(test)]
mod tests {
    use std::marker::PhantomData;
    use std::string::ToString;

    use oauth2::prelude::NewType;
    use serde::de::Error as DeserializeError;
    use serde_json;

    use super::super::core::{
        CoreJsonWebKey, CoreJsonWebKeyType, CoreJweContentEncryptionAlgorithm,
        CoreJwsSigningAlgorithm,
    };
    use super::super::JsonWebKeyId;
    use super::{
        JsonWebToken, JsonWebTokenAccess, JsonWebTokenAlgorithm, JsonWebTokenPayloadDeserialize,
    };

    type CoreAlgorithm = JsonWebTokenAlgorithm<
        CoreJweContentEncryptionAlgorithm,
        CoreJwsSigningAlgorithm,
        CoreJsonWebKeyType,
    >;

    const TEST_JWT: &str =
        "eyJhbGciOiJSUzI1NiIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZXhhbXBsZSJ9.SXTigJlzIGEgZ\
         GFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGU\
         gcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlc\
         mUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4.MRjdkly7_-oTPTS3AXP41iQIGKa80A0ZmTuV5MEaHoxnW2e\
         5CZ5NlKtainoFmKZopdHM1O2U4mwzJdQx996ivp83xuglII7PNDi84wnB-BDkoBwA78185hX-Es4JIwmDLJK3l\
         fWRa-XtL0RnltuYv746iYTh_qHRD68BNt1uSNCrUCTJDt5aAE6x8wW1Kt9eRo4QPocSadnHXFxnt8Is9UzpERV\
         0ePPQdLuW3IS_de3xyIrDaLGdjluPxUAhb6L2aXic1U12podGU0KLUQSE_oI-ZnmKJ3F4uOZDnd6QZWJushZ41\
         Axf_fcIe8u9ipH84ogoree7vjbU5y18kDquDg";

    const TEST_RSA_PUB_KEY: &str = "{
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

    #[test]
    fn test_jwt_algorithm_deserialization() {
        assert_eq!(
            serde_json::from_str::<CoreAlgorithm>("\"A128CBC-HS256\"")
                .expect("failed to deserialize"),
            JsonWebTokenAlgorithm::Encryption(
                CoreJweContentEncryptionAlgorithm::Aes128CbcHmacSha256
            ),
        );
        assert_eq!(
            serde_json::from_str::<CoreAlgorithm>("\"A128GCM\"").expect("failed to deserialize"),
            JsonWebTokenAlgorithm::Encryption(CoreJweContentEncryptionAlgorithm::Aes128Gcm),
        );
        assert_eq!(
            serde_json::from_str::<CoreAlgorithm>("\"HS256\"").expect("failed to deserialize"),
            JsonWebTokenAlgorithm::Signature(CoreJwsSigningAlgorithm::HmacSha256, PhantomData),
        );
        assert_eq!(
            serde_json::from_str::<CoreAlgorithm>("\"RS256\"").expect("failed to deserialize"),
            JsonWebTokenAlgorithm::Signature(
                CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
                PhantomData,
            ),
        );
        assert_eq!(
            serde_json::from_str::<CoreAlgorithm>("\"none\"").expect("failed to deserialize"),
            JsonWebTokenAlgorithm::None,
        );
    }

    #[test]
    fn test_jwt_algorithm_serialization() {
        assert_eq!(
            serde_json::to_string::<CoreAlgorithm>(&JsonWebTokenAlgorithm::Encryption(
                CoreJweContentEncryptionAlgorithm::Aes128CbcHmacSha256
            )).expect("failed to serialize"),
            "\"A128CBC-HS256\"",
        );
        assert_eq!(
            serde_json::to_string::<CoreAlgorithm>(&JsonWebTokenAlgorithm::Encryption(
                CoreJweContentEncryptionAlgorithm::Aes128Gcm
            )).expect("failed to serialize"),
            "\"A128GCM\"",
        );
        assert_eq!(
            serde_json::to_string::<CoreAlgorithm>(&JsonWebTokenAlgorithm::Signature(
                CoreJwsSigningAlgorithm::HmacSha256,
                PhantomData,
            )).expect("failed to serialize"),
            "\"HS256\"",
        );
        assert_eq!(
            serde_json::to_string::<CoreAlgorithm>(&JsonWebTokenAlgorithm::Signature(
                CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
                PhantomData,
            )).expect("failed to serialize"),
            "\"RS256\"",
        );
        assert_eq!(
            serde_json::to_string::<CoreAlgorithm>(&JsonWebTokenAlgorithm::None)
                .expect("failed to serialize"),
            "\"none\"",
        );
    }

    #[derive(Clone, Debug, PartialEq)]
    pub struct JsonWebTokenStringPayloadDeserializer;
    impl JsonWebTokenPayloadDeserialize<String> for JsonWebTokenStringPayloadDeserializer {
        fn deserialize<E: DeserializeError>(payload: &str) -> Result<String, E> {
            Ok(payload.to_string())
        }
    }

    #[test]
    fn test_jwt() {
        fn verify_jwt<A>(jwt_access: A)
        where
            A: JsonWebTokenAccess<
                String,
                CoreJweContentEncryptionAlgorithm,
                CoreJwsSigningAlgorithm,
                CoreJsonWebKeyType,
            >,
            A::ReturnType: ToString,
        {
            let key: CoreJsonWebKey =
                serde_json::from_str(TEST_RSA_PUB_KEY).expect("deserialization failed");
            let expected_payload = "It\u{2019}s a dangerous business, Frodo, going out your \
                                    door. You step onto the road, and if you don't keep your feet, \
                                    there\u{2019}s no knowing where you might be swept off \
                                    to.";
            {
                let header = jwt_access.unverified_header();
                assert_eq!(
                    header.alg,
                    JsonWebTokenAlgorithm::Signature(
                        CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
                        PhantomData,
                    )
                );
                assert_eq!(header.crit, None);
                assert_eq!(header.cty, None);
                assert_eq!(
                    header.kid,
                    Some(JsonWebKeyId::new(
                        "bilbo.baggins@hobbiton.example".to_string()
                    ))
                );
                assert_eq!(header.typ, None);
            }
            assert_eq!(jwt_access.unverified_claims_ref(), expected_payload);

            assert_eq!(
                jwt_access
                    .claims(&CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256, &key)
                    .expect("failed to validate claims")
                    .to_string(),
                expected_payload
            );
        }

        let jwt: JsonWebToken<
            String,
            CoreJweContentEncryptionAlgorithm,
            CoreJwsSigningAlgorithm,
            CoreJsonWebKeyType,
            JsonWebTokenStringPayloadDeserializer,
        > = serde_json::from_value(serde_json::Value::String(TEST_JWT.to_string()))
            .expect("failed to deserialize");

        verify_jwt(&jwt);
        verify_jwt(jwt);
    }

    #[test]
    fn test_invalid_signature() {
        let corrupted_jwt_str = TEST_JWT
            .to_string()
            .chars()
            .take(TEST_JWT.len() - 1)
            .collect::<String>()
            + "f";
        let jwt: JsonWebToken<
            String,
            CoreJweContentEncryptionAlgorithm,
            CoreJwsSigningAlgorithm,
            CoreJsonWebKeyType,
            JsonWebTokenStringPayloadDeserializer,
        > = serde_json::from_value(serde_json::Value::String(corrupted_jwt_str))
            .expect("failed to deserialize");
        let key: CoreJsonWebKey =
            serde_json::from_str(TEST_RSA_PUB_KEY).expect("deserialization failed");

        jwt.claims(&CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256, &key)
            .expect_err("signature verification should have failed");
    }
}
