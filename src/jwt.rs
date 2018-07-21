
extern crate base64;
extern crate failure;
extern crate ring;
extern crate serde;
extern crate serde_json;
extern crate untrusted;

use std::fmt::{Debug, Formatter, Result as FormatterResult};
use std::marker::PhantomData;
use std::ops::Deref;
use std::str;

use oauth2::prelude::NewType;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde::de::{DeserializeOwned, Error as DeserializeError, Visitor};

use super::{
    JsonWebKey,
    JsonWebKeyId,
    JsonWebKeyType,
    JsonWebKeyUse,
    JweContentEncryptionAlgorithm,
    JwsSigningAlgorithm,
    SignatureVerificationError,
};

new_type![
    #[derive(Deserialize, Serialize)]
    JsonWebTokenContentType(String)
];

new_type![
    #[derive(Deserialize, Serialize)]
    JsonWebTokenType(String)
];

#[derive(Clone, Debug, PartialEq)]
pub enum JsonWebTokenAlgorithm<JE, JS, JT>
where JE: JweContentEncryptionAlgorithm, JS: JwsSigningAlgorithm<JT>, JT: JsonWebKeyType {
    Encryption(JE),
    // This is ugly, but we don't expose this module via the public API, so it's fine.
    Signature(JS, PhantomData<JT>),
    None,
}

mod serde_jwt_algorithm {
    use std::marker::PhantomData;

    use serde::{Deserialize, Deserializer, Serializer};
    use serde::de::Error;
    use serde_json::{from_value, Value};

    use super::{
        JsonWebKeyType,
        JsonWebTokenAlgorithm,
        JweContentEncryptionAlgorithm,
        JwsSigningAlgorithm,
    };

    pub fn deserialize<'de, D, JE, JS, JT>(
        deserializer: D
    ) -> Result<JsonWebTokenAlgorithm<JE, JS, JT>, D::Error>
    where D: Deserializer<'de>,
            JE: JweContentEncryptionAlgorithm,
            JS: JwsSigningAlgorithm<JT>,
            JT: JsonWebKeyType {
        let value: Value = Deserialize::deserialize(deserializer)?;
        // TODO: get rid of this clone() (see below)
        let s: String = from_value(value.clone()).map_err(D::Error::custom)?;

        // NB: These comparisons are case sensitive. Section 4.1.1 of RFC 7515 states: "The "alg"
        // value is a case-sensitive ASCII string containing a StringOrURI value."
        if s == "none" {
            Ok(JsonWebTokenAlgorithm::None)
        // TODO: Figure out a way to deserialize the enums without giving up ownership
        } else if let Ok(val) = from_value::<JE>(value.clone()) {
            Ok(JsonWebTokenAlgorithm::Encryption(val))
        } else if let Ok(val) = from_value::<JS>(value.clone()) {
            Ok(JsonWebTokenAlgorithm::Signature(val, PhantomData))
        } else {
            Err(D::Error::custom(format!("unrecognized JSON Web Algorithm `{}`", s)))
        }
    }

    pub fn serialize<JE, JS, JT, S>(
        alg: &JsonWebTokenAlgorithm<JE, JS, JT>,
        serializer: S
    ) -> Result<S::Ok, S::Error>
    where JE: JweContentEncryptionAlgorithm,
            JS: JwsSigningAlgorithm<JT>,
            JT: JsonWebKeyType,
            S: Serializer {
        match *alg {
            JsonWebTokenAlgorithm::Encryption(ref enc) => enc.serialize(serializer),
            JsonWebTokenAlgorithm::Signature(ref sig, _) => sig.serialize(serializer),
            JsonWebTokenAlgorithm::None => serializer.serialize_str("none"),
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct JsonWebTokenHeader<JE, JS, JT>
where JE: JweContentEncryptionAlgorithm,
        JS: JwsSigningAlgorithm<JT>,
        JT: JsonWebKeyType {
    #[serde(bound = "JE: JweContentEncryptionAlgorithm, JS: JwsSigningAlgorithm<JT>, JT: JsonWebKeyType")]
    #[serde(with = "serde_jwt_algorithm")]
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

// Helper trait so that we can get borrowed claims when we have a reference to the JWT and owned
// claims when we own the JWT.
pub trait JsonWebTokenAccess<C, JE, JS, JT>
where C: Debug + DeserializeOwned + Serialize,
        JE: JweContentEncryptionAlgorithm,
        JS: JwsSigningAlgorithm<JT>,
        JT: JsonWebKeyType {
    type ReturnType;

    fn unverified_header(&self) -> &JsonWebTokenHeader<JE, JS, JT>;
    fn unverified_claims(self) -> Self::ReturnType;
    fn unverified_claims_ref(&self) -> &C;

    fn claims<JU, JW>(
        self,
        signature_alg: &JS,
        key: &JW
    ) -> Result<Self::ReturnType, SignatureVerificationError>
    where JU: JsonWebKeyUse, JW: JsonWebKey<JS, JT, JU>;
}

#[derive(Clone, Debug, PartialEq)]
pub struct JsonWebToken<C, JE, JS, JT>
where C: Debug + DeserializeOwned + Serialize,
        JE: JweContentEncryptionAlgorithm,
        JS: JwsSigningAlgorithm<JT>,
        JT: JsonWebKeyType {
    header: JsonWebTokenHeader<JE, JS, JT>,
    claims: C,
    signature: Vec<u8>,
    signing_input: String,
    raw_token: String,
}
// FIXME: add methods or remove
impl<C, JE, JS, JT> JsonWebToken<C, JE, JS, JT>
where C: Debug + DeserializeOwned + Serialize,
        JE: JweContentEncryptionAlgorithm,
        JS: JwsSigningAlgorithm<JT>,
        JT: JsonWebKeyType {
}
// Owned JWT.
impl<C, JE, JS, JT> JsonWebTokenAccess<C, JE, JS, JT>
for JsonWebToken<C, JE, JS, JT>
where C: Debug + DeserializeOwned + Serialize,
        JE: JweContentEncryptionAlgorithm,
        JS: JwsSigningAlgorithm<JT>,
        JT: JsonWebKeyType {
    type ReturnType = C;
    fn unverified_header(&self) -> &JsonWebTokenHeader<JE, JS, JT> { &self.header }
    fn unverified_claims(self) -> Self::ReturnType { self.claims }
    fn unverified_claims_ref(&self) -> &C { &self.claims }
    fn claims<JU, JW>(
        self,
        signature_alg: &JS,
        key: &JW
    ) -> Result<Self::ReturnType, SignatureVerificationError>
    where JU: JsonWebKeyUse, JW: JsonWebKey<JS, JT, JU> {
        key.verify_signature(signature_alg, &self.signing_input, &self.signature)?;
        Ok(self.claims)
    }
}
// Borrowed JWT.
impl<'a, C, JE, JS, JT> JsonWebTokenAccess<C, JE, JS, JT> for &'a JsonWebToken<C, JE, JS, JT>
where C: Debug + DeserializeOwned + Serialize,
        JE: JweContentEncryptionAlgorithm,
        JS: JwsSigningAlgorithm<JT>,
        JT: JsonWebKeyType {
    type ReturnType = &'a C;
    fn unverified_header(&self) -> &JsonWebTokenHeader<JE, JS, JT> { &self.header }
    fn unverified_claims(self) -> Self::ReturnType { &self.claims }
    fn unverified_claims_ref(&self) -> &C { &self.claims }
    fn claims<JU, JW>(
        self,
        signature_alg: &JS,
        key: &JW
    ) -> Result<Self::ReturnType, SignatureVerificationError>
    where JU: JsonWebKeyUse, JW: JsonWebKey<JS, JT, JU> {
        key.verify_signature(signature_alg, &self.signing_input, &self.signature)?;
        Ok(&self.claims)
    }
}
impl<'de, C, JE, JS, JT> Deserialize<'de> for JsonWebToken<C, JE, JS, JT>
where C: Debug + DeserializeOwned + Serialize,
        JE: JweContentEncryptionAlgorithm,
        JS: JwsSigningAlgorithm<JT>,
        JT: JsonWebKeyType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: Deserializer<'de> {
        struct JsonWebTokenVisitor<
            C: Debug + DeserializeOwned + Serialize,
            JE: JweContentEncryptionAlgorithm,
            JS: JwsSigningAlgorithm<JT>,
            JT: JsonWebKeyType
        >(
            PhantomData<C>,
            PhantomData<JE>,
            PhantomData<JS>,
            PhantomData<JT>,
        );
        impl<'de, C, JE, JS, JT> Visitor<'de> for JsonWebTokenVisitor<C, JE, JS, JT>
        where C: Debug + DeserializeOwned + Serialize,
                JE: JweContentEncryptionAlgorithm,
                JS: JwsSigningAlgorithm<JT>,
                JT: JsonWebKeyType {
            type Value = JsonWebToken<C, JE, JS, JT>;

            fn expecting(&self, formatter: &mut Formatter) -> FormatterResult {
                formatter.write_str("JsonWebToken")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E> 
            where E: DeserializeError {
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
                        return Err(
                            DeserializeError::custom(
                                format!(
                                    "Invalid JSON web token: found {} parts (expected 3)",
                                    parts.len()
                                )
                            )
                        )
                    }

                    let header_json_raw =
                        base64::decode_config(parts[0], base64::URL_SAFE_NO_PAD)
                            .map_err(|err|
                                DeserializeError::custom(
                                    format!("Invalid base64url header encoding: {:?}", err)
                                )
                            )?;
                    let header_json =
                        &str::from_utf8(&header_json_raw)
                            .map_err(|err|
                                DeserializeError::custom(
                                    format!("Invalid UTF-8 header encoding: {:?}", err)
                                )
                            )?;
                    header =
                        serde_json::from_str(header_json)
                            .map_err(|err|
                                DeserializeError::custom(
                                    format!("Failed to parse header JSON: {:?}", err)
                                )
                            )?;

                    let claims_json_raw =
                        base64::decode_config(parts[1], base64::URL_SAFE_NO_PAD)
                            .map_err(|err|
                                DeserializeError::custom(
                                    format!("Invalid base64url claims encoding: {:?}", err)
                                )
                            )?;
                    let claims_json =
                        &str::from_utf8(&claims_json_raw)
                            .map_err(|err|
                                DeserializeError::custom(
                                    format!("Invalid UTF-8 encoding: {:?}", err)
                                )
                            )?;
                    claims =
                        serde_json::from_str(claims_json)
                            .map_err(|err|
                                DeserializeError::custom(
                                    format!("Failed to parse claims JSON: {:?}", err)
                                )
                            )?;

                    signature =
                        base64::decode_config(parts[2], base64::URL_SAFE_NO_PAD)
                            .map_err(|err|
                                DeserializeError::custom(
                                    format!("Invalid base64url signature encoding: {:?}", err)
                                )
                            )?;

                    signing_input = format!("{}.{}", parts[0], parts[1]);
                }

                Ok(
                    JsonWebToken {
                        header,
                        claims,
                        signature,
                        signing_input,
                        raw_token,
                    }
                )
            }
        }
        deserializer
            .deserialize_str(
                JsonWebTokenVisitor(PhantomData, PhantomData, PhantomData, PhantomData)
            )
    }
}
impl<C, JE, JS, JT> Serialize for JsonWebToken<C, JE, JS, JT>
where C: Debug + DeserializeOwned + Serialize,
        JE: JweContentEncryptionAlgorithm,
        JS: JwsSigningAlgorithm<JT>,
        JT: JsonWebKeyType {
    fn serialize<SE>(&self, serializer: SE) -> Result<SE::Ok, SE::Error> where SE: Serializer {
        serializer.serialize_str(&self.raw_token)
    }
}
