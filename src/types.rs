use std::fmt::{Debug, Display, Error as FormatterError, Formatter};
use std::hash::Hash;
use std::marker::PhantomData;
use std::ops::Deref;

use base64;
use oauth2;
use oauth2::helpers::deserialize_space_delimited_vec;
use oauth2::prelude::*;
use rand::{thread_rng, Rng};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json;
use url;
use url::Url;

use super::SignatureVerificationError;

pub trait ApplicationType: Clone + Debug + DeserializeOwned + PartialEq + Serialize {}

///
/// How the Authorization Server displays the authentication and consent user interface pages to
/// the End-User.
///
pub trait AuthDisplay: Clone + Debug + DeserializeOwned + PartialEq + Serialize {
    fn to_str(&self) -> &str;
}

///
/// Whether the Authorization Server should prompt the End-User for reauthentication and consent.
///
pub trait AuthPrompt: AsRef<str> + Display + PartialEq {
    fn to_str(&self) -> &str;
}

pub trait ClaimName: Clone + Debug + DeserializeOwned + PartialEq + Serialize {}
pub trait ClaimType: Clone + Debug + DeserializeOwned + PartialEq + Serialize {}

pub trait ClientAuthMethod: Clone + Debug + DeserializeOwned + PartialEq + Serialize {}
pub trait GrantType: Clone + Debug + DeserializeOwned + PartialEq + Serialize {}

pub trait JsonWebKey<JS, JT, JU>: Clone + Debug + DeserializeOwned + PartialEq + Serialize
where
    JS: JwsSigningAlgorithm<JT>,
    JT: JsonWebKeyType,
    JU: JsonWebKeyUse,
{
    fn key_id(&self) -> Option<&JsonWebKeyId>;
    fn key_type(&self) -> &JT;
    fn key_use(&self) -> Option<&JU>;
    fn new_symmetric(key: Vec<u8>) -> Self;
    fn verify_signature(
        &self,
        signature_alg: &JS,
        msg: &str,
        signature: &[u8],
    ) -> Result<(), SignatureVerificationError>;
}

pub trait JsonWebKeyType: Clone + Debug + DeserializeOwned + PartialEq + Serialize {}
pub trait JsonWebKeyUse: Clone + Debug + DeserializeOwned + PartialEq + Serialize {
    fn allows_signature(&self) -> bool;
    fn allows_encryption(&self) -> bool;
}
// FIXME: add a key_type() method
pub trait JweContentEncryptionAlgorithm:
    Clone + Debug + DeserializeOwned + Eq + Hash + PartialEq + Serialize
{
}
// FIXME: add a key_type() method?
pub trait JweKeyManagementAlgorithm:
    Clone + Debug + DeserializeOwned + Eq + Hash + PartialEq + Serialize
{
}

pub trait JwsSigningAlgorithm<JT>:
    Clone + Debug + DeserializeOwned + Eq + Hash + PartialEq + Serialize
where
    JT: JsonWebKeyType,
{
    // FIXME: return a real error
    fn key_type(&self) -> Result<JT, String>;
    fn is_symmetric(&self) -> bool;
    fn rsa_sha_256() -> Self;
}

pub trait ResponseMode: Clone + Debug + DeserializeOwned + PartialEq + Serialize {}
pub trait ResponseType:
    AsRef<str> + Clone + Debug + DeserializeOwned + PartialEq + Serialize
{
    fn to_oauth2(&self) -> oauth2::ResponseType;
}
pub trait SubjectIdentifierType: Clone + Debug + DeserializeOwned + PartialEq + Serialize {}

// FIXME: make this a trait so that callers can add their own enums if desired
new_type![#[derive(
    Deserialize, Eq, Hash, Ord, PartialOrd, Serialize,
)]
AuthenticationContextClass(String)];
impl AsRef<str> for AuthenticationContextClass {
    fn as_ref(&self) -> &str {
        self
    }
}

// FIXME: make this a trait so that callers can add their own enums if desired
new_type![#[derive(
    Deserialize, Eq, Hash, Ord, PartialOrd, Serialize,
)]
AuthenticationMethodReference(String)];

new_type![#[derive(
    Deserialize, Eq, Hash, Ord, PartialOrd, Serialize,
)]
AccessTokenHash(String)];

new_type![#[derive(
    Deserialize, Eq, Hash, Ord, PartialOrd, Serialize,
)]
AddressCountry(String)];

new_type![#[derive(
    Deserialize, Eq, Hash, Ord, PartialOrd, Serialize,
)]
AddressLocality(String)];

new_type![#[derive(
    Deserialize, Eq, Hash, Ord, PartialOrd, Serialize,
)]
AddressPostalCode(String)];

new_type![#[derive(
    Deserialize, Eq, Hash, Ord, PartialOrd, Serialize,
)]
AddressRegion(String)];

new_type![#[derive(
    Deserialize, Eq, Hash, Ord, PartialOrd, Serialize,
)]
Audience(String)];

new_type![#[derive(
    Deserialize, Eq, Hash, Ord, PartialOrd, Serialize,
)]
AuthorizationCodeHash(String)];

new_type![
    #[derive(Deserialize, Eq, Hash, Serialize)]
    Base64UrlEncodedBytes(
        #[serde(with = "serde_base64url_byte_array")]
        Vec<u8>
    )
];

new_type![#[derive(
    Deserialize, Eq, Hash, Ord, PartialOrd, Serialize,
)]
ClientName(String)];

new_url_type![ClientConfigUrl];

new_url_type![ClientUrl];

new_type![#[derive(
    Deserialize, Eq, Hash, Ord, PartialOrd, Serialize,
)]
ContactEmail(String)];

new_type![#[derive(
    Deserialize, Eq, Hash, Ord, PartialOrd, Serialize,
)]
EndUserBirthday(String)];

new_type![#[derive(
    Deserialize, Eq, Hash, Ord, PartialOrd, Serialize,
)]
EndUserEmail(String)];

new_type![#[derive(
    Deserialize, Eq, Hash, Ord, PartialOrd, Serialize,
)]
EndUserFamilyName(String)];

new_type![#[derive(
    Deserialize, Eq, Hash, Ord, PartialOrd, Serialize,
)]
EndUserGivenName(String)];

new_type![#[derive(
    Deserialize, Eq, Hash, Ord, PartialOrd, Serialize,
)]
EndUserMiddleName(String)];

new_type![#[derive(
    Deserialize, Eq, Hash, Ord, PartialOrd, Serialize,
)]
EndUserName(String)];

new_type![#[derive(
    Deserialize, Eq, Hash, Ord, PartialOrd, Serialize,
)]
EndUserNickname(String)];

new_type![#[derive(
    Deserialize, Eq, Hash, Ord, PartialOrd, Serialize,
)]
EndUserPhoneNumber(String)];

new_url_type![EndUserPictureUrl];

new_url_type![EndUserProfileUrl];

new_type![#[derive(
    Deserialize, Eq, Hash, Ord, PartialOrd, Serialize,
)]
EndUserTimezone(String)];

new_url_type![EndUserWebsiteUrl];

new_type![#[derive(
    Deserialize, Eq, Hash, Ord, PartialOrd, Serialize,
)]
EndUserUsername(String)];

new_type![#[derive(
    Deserialize, Eq, Hash, Ord, PartialOrd, Serialize,
)]
FormattedAddress(String)];

new_url_type![InitiateLoginUrl];

new_url_type![
    IssuerUrl
    impl {
        pub fn join(&self, suffix: &str) -> Result<Url, url::ParseError> {
            if let Some('/') = self.1.chars().next_back() {
                Url::parse(&(self.1.clone() + suffix))
            } else {
                Url::parse(&(self.1.clone() + "/" + suffix))
            }
        }
    }
];

new_type![#[derive(
    Deserialize, Eq, Hash, Ord, PartialOrd, Serialize,
)]
JsonWebKeyId(String)];

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct JsonWebKeySet<JS, JT, JU, K>
where
    JS: JwsSigningAlgorithm<JT>,
    JT: JsonWebKeyType,
    JU: JsonWebKeyUse,
    K: JsonWebKey<JS, JT, JU>,
{
    // FIXME: write a test that ensures duplicate object member names cause an error
    // (see https://tools.ietf.org/html/rfc7517#section-5)
    // FIXME: add a deserializer that optionally ignores invalid keys rather than failing. That way,
    // clients can function using the keys that they do understand, which is fine if they only ever
    // get JWTs signed with those keys. See what other places we might want to be more tolerant of
    // deserialization errors.
    #[serde(bound = "K: JsonWebKey<JS, JT, JU>")]
    keys: Vec<K>,
    #[serde(skip)]
    _phantom_js: PhantomData<JS>,
    #[serde(skip)]
    _phantom_jt: PhantomData<JT>,
    #[serde(skip)]
    _phantom_ju: PhantomData<JU>,
}
impl<JS, JT, JU, K> JsonWebKeySet<JS, JT, JU, K>
where
    JS: JwsSigningAlgorithm<JT>,
    JT: JsonWebKeyType,
    JU: JsonWebKeyUse,
    K: JsonWebKey<JS, JT, JU>,
{
    pub fn keys(&self) -> &Vec<K> {
        &self.keys
    }
}

new_type![#[derive(
    Deserialize, Eq, Hash, Ord, PartialOrd, Serialize,
)]
LanguageTag(String)];
impl AsRef<str> for LanguageTag {
    fn as_ref(&self) -> &str {
        self
    }
}

new_secret_type![#[derive(
    Deserialize, Eq, Hash, Ord, PartialOrd, Serialize,
)]
LoginHint(String)];

new_url_type![LogoUrl];

new_secret_type![
    #[derive(Deserialize, Eq, Hash, Ord, PartialOrd, Serialize)]
    Nonce(String)
    impl {
        ///
        /// Generate a new random, base64-encoded 128-bit nonce.
        ///
        pub fn new_random() -> Self {
            Nonce::new_random_len(16)
        }
        ///
        /// Generate a new random, base64-encoded nonce of the specified length.
        ///
        /// # Arguments
        ///
        /// * `num_bytes` - Number of random bytes to generate, prior to base64-encoding.
        ///
        pub fn new_random_len(num_bytes: u32) -> Self {
            let random_bytes: Vec<u8> = (0..num_bytes).map(|_| thread_rng().gen::<u8>()).collect();
            Nonce::new(base64::encode(&random_bytes))
        }
    }
];

new_url_type![OpPolicyUrl];

new_url_type![OpTosUrl];

new_url_type![PolicyUrl];

new_secret_type![#[derive(
    Deserialize, Eq, Hash, Ord, PartialOrd, Serialize,
)]
RegistrationAccessToken(String)];

new_url_type![RegistrationUrl];

new_url_type![RequestUrl];

///
/// Informs the Authorization Server of the desired authorization processing flow, including what
/// parameters are returned from the endpoints used.  
///
/// See [OAuth 2.0 Multiple Response Type Encoding Practices](
///     http://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#ResponseTypesAndModes)
/// for further details.
///
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ResponseTypes<RT: ResponseType>(
    #[serde(
        deserialize_with = "deserialize_space_delimited_vec",
        serialize_with = "helpers::serialize_space_delimited_vec"
    )]
    Vec<RT>,
);
impl<RT: ResponseType> ResponseTypes<RT> {
    ///
    /// Create a new ResponseTypes<RT> to wrap the given Vec<RT>.
    ///
    pub fn new(s: Vec<RT>) -> Self {
        ResponseTypes::<RT>(s)
    }
}
impl<RT: ResponseType> Deref for ResponseTypes<RT> {
    type Target = Vec<RT>;
    fn deref(&self) -> &Vec<RT> {
        &self.0
    }
}

new_type![#[derive(Deserialize, Serialize)]
pub(crate) Seconds(serde_json::Number)];

new_url_type![SectorIdentifierUrl];

new_url_type![ServiceDocUrl];

new_type![#[derive(
    Deserialize, Eq, Hash, Ord, PartialOrd, Serialize,
)]
StreetAddress(String)];

new_type![#[derive(
    Deserialize, Eq, Hash, Ord, PartialOrd, Serialize,
)]
SubjectIdentifier(String)];

new_url_type![ToSUrl];

// FIXME: Add tests
pub(crate) mod helpers {
    use chrono::{DateTime, TimeZone, Utc};
    use oauth2::prelude::*;
    use serde::de::DeserializeOwned;
    use serde::{Deserialize, Deserializer, Serializer};
    use serde_json::{from_value, Value};

    use super::{LanguageTag, Seconds};

    pub fn deserialize_string_or_vec<'de, T, D>(deserializer: D) -> Result<Vec<T>, D::Error>
    where
        T: DeserializeOwned,
        D: Deserializer<'de>,
    {
        use serde::de::Error;

        let value: Value = Deserialize::deserialize(deserializer)?;
        match from_value::<Vec<T>>(value.clone()) {
            Ok(val) => Ok(val),
            Err(_) => {
                let single_val: T = from_value(value).map_err(Error::custom)?;
                Ok(vec![single_val])
            }
        }
    }

    // Attempt to deserialize the value; if the value is null or an error occurs, return None.
    // This is useful when deserializing fields that may mean different things in different
    // contexts, and where we would rather ignore the result than fail to deserialize. For example,
    // the fields in JWKs are not well defined; extensions could theoretically define their own
    // field names that overload field names used by other JWK types.
    pub fn deserialize_option_or_none<'de, T, D>(deserializer: D) -> Result<Option<T>, D::Error>
    where
        T: DeserializeOwned,
        D: Deserializer<'de>,
    {
        let value: Value = Deserialize::deserialize(deserializer)?;
        match from_value::<Option<T>>(value) {
            Ok(val) => Ok(val),
            Err(_) => Ok(None),
        }
    }

    ///
    /// Serde space-delimited string serializer for an `Option<Vec<String>>`.
    ///
    /// This function serializes a string vector into a single space-delimited string.
    /// If `string_vec_opt` is `None`, the function serializes it as `None` (e.g., `null`
    /// in the case of JSON serialization).
    ///
    pub fn serialize_space_delimited_vec<T, S>(vec: &[T], serializer: S) -> Result<S::Ok, S::Error>
    where
        T: AsRef<str>,
        S: Serializer,
    {
        let space_delimited = vec
            .iter()
            .map(AsRef::<str>::as_ref)
            .collect::<Vec<_>>()
            .join(" ");

        serializer.serialize_str(&space_delimited)
    }

    pub fn split_language_tag_key(key: &str) -> (&str, Option<LanguageTag>) {
        let mut lang_tag_sep = key.splitn(2, '#');

        // String::splitn(2) always returns at least one element.
        let field_name = lang_tag_sep.next().unwrap();

        let language_tag = lang_tag_sep
            .next()
            .filter(|language_tag| !language_tag.is_empty())
            .map(|language_tag| LanguageTag::new(language_tag.to_string()));

        (field_name, language_tag)
    }

    pub(crate) fn seconds_to_utc(seconds: &Seconds) -> Result<DateTime<Utc>, ()> {
        let (secs, nsecs) = if seconds.is_i64() {
            (seconds.as_i64().ok_or(())?, 0u32)
        } else {
            let secs_f64 = seconds.as_f64().ok_or(())?;
            let secs = secs_f64.floor();
            (
                secs as i64,
                ((secs_f64 - secs) * 1000000000.).floor() as u32,
            )
        };
        Utc.timestamp_opt(secs, nsecs).single().ok_or(())
    }
}

mod serde_base64url_byte_array {
    use base64;
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serializer};
    use serde_json::{from_value, Value};

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value: Value = Deserialize::deserialize(deserializer)?;
        let base64_encoded: String = from_value(value).map_err(D::Error::custom)?;

        base64::decode_config(&base64_encoded, base64::URL_SAFE_NO_PAD).map_err(|err| {
            D::Error::custom(format!(
                "invalid base64url encoding `{}`: {:?}",
                base64_encoded, err
            ))
        })
    }

    pub fn serialize<S>(v: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let base64_encoded = base64::encode_config(v, base64::URL_SAFE_NO_PAD);
        serializer.serialize_str(&base64_encoded)
    }
}

#[cfg(test)]
mod tests {
    use serde_json;

    use super::super::IssuerUrl;

    #[test]
    fn test_issuer_url_append() {
        assert_eq!(
            "http://example.com/.well-known/openid-configuration",
            IssuerUrl::new("http://example.com".to_string())
                .unwrap()
                .join(".well-known/openid-configuration")
                .unwrap()
                .to_string()
        );
        assert_eq!(
            "http://example.com/.well-known/openid-configuration",
            IssuerUrl::new("http://example.com/".to_string())
                .unwrap()
                .join(".well-known/openid-configuration")
                .unwrap()
                .to_string()
        );
        assert_eq!(
            "http://example.com/x/.well-known/openid-configuration",
            IssuerUrl::new("http://example.com/x".to_string())
                .unwrap()
                .join(".well-known/openid-configuration")
                .unwrap()
                .to_string()
        );
        assert_eq!(
            "http://example.com/x/.well-known/openid-configuration",
            IssuerUrl::new("http://example.com/x/".to_string())
                .unwrap()
                .join(".well-known/openid-configuration")
                .unwrap()
                .to_string()
        );
    }

    #[test]
    fn test_url_serialize() {
        let issuer_url =
            IssuerUrl::new("http://example.com/.well-known/openid-configuration".to_string())
                .unwrap();
        let serialized_url = serde_json::to_string(&issuer_url).unwrap();

        assert_eq!(
            "\"http://example.com/.well-known/openid-configuration\"",
            serialized_url
        );

        let deserialized_url = serde_json::from_str(&serialized_url).unwrap();
        assert_eq!(issuer_url, deserialized_url);

        assert_eq!(
            serde_json::to_string(&IssuerUrl::new("http://example.com".to_string()).unwrap())
                .unwrap(),
            "\"http://example.com\"",
        );
    }
}
