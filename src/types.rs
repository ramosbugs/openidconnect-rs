
extern crate base64;
extern crate jsonwebtoken;
extern crate oauth2;
extern crate rand;
extern crate serde_json;
extern crate url;

use std::fmt::{Debug, Display, Error as FormatterError, Formatter};
use std::ops::Deref;

use oauth2::helpers::{deserialize_space_delimited_vec, deserialize_url, serialize_url};
use oauth2::prelude::*;
use rand::{thread_rng, Rng};
use serde::Serialize;
use serde::de::DeserializeOwned;
use url::Url;


pub trait AdditionalClaims: Clone + Debug + DeserializeOwned + PartialEq + Serialize {}
pub trait ApplicationType : Clone + Debug + DeserializeOwned + PartialEq + Serialize {}

///
/// How the Authorization Server displays the authentication and consent user interface pages to
/// the End-User.
///
pub trait AuthDisplay : Clone + Debug + DeserializeOwned + PartialEq + Serialize {
    fn to_str(&self) -> &str;
}

///
/// Whether the Authorization Server should prompt the End-User for reauthentication and consent.
///
pub trait AuthPrompt : AsRef<str> + Display + PartialEq {
    fn to_str(&self) -> &str;
}

pub trait ClaimName : Clone + Debug + DeserializeOwned + PartialEq + Serialize {}
pub trait ClaimType : Clone + Debug + DeserializeOwned + PartialEq + Serialize {}

pub trait ClientAuthMethod : Clone + Debug + DeserializeOwned + PartialEq + Serialize {}
pub trait GenderClaim : Clone + Debug + DeserializeOwned + PartialEq + Serialize {}
pub trait GrantType : Clone + Debug + DeserializeOwned + PartialEq + Serialize {}
pub trait JsonWebKeyType : Clone + Debug + DeserializeOwned + PartialEq + Serialize {
    fn is_symmetric(&self) -> bool;
}
pub trait JsonWebKeyUse : Clone + Debug + DeserializeOwned + PartialEq + Serialize {
    fn allows_signature(&self) -> bool;
    fn allows_encryption(&self) -> bool;
}
// FIXME: add a key_type() method
pub trait JweContentEncryptionAlgorithm
    : Clone + Debug + DeserializeOwned + PartialEq + Serialize {}
// FIXME: add a key_type() method?
pub trait JweKeyManagementAlgorithm : Clone + Debug + DeserializeOwned + PartialEq + Serialize {}

pub trait JwsSigningAlgorithm<JT> : Clone + Debug + DeserializeOwned + PartialEq + Serialize
where JT: JsonWebKeyType {
    // FIXME: return a real error
    // FIXME: don't return jsonwebtoken types via public interface
    fn from_jwt(alg: &jsonwebtoken::Algorithm) -> Result<Self, String>;
    // FIXME: return a real error
    // FIXME: don't return jsonwebtoken types via public interface
    fn to_jwt(&self) -> Result<jsonwebtoken::Algorithm, String>;
    // FIXME: return a real error
    fn key_type(&self) -> Result<JT, String>;
    fn is_symmetric(&self) -> bool;
}

pub trait ResponseMode : Clone + Debug + DeserializeOwned + PartialEq + Serialize {}
pub trait ResponseType : AsRef<str> + Clone + Debug + DeserializeOwned + PartialEq + Serialize {
    fn to_oauth2(&self) -> oauth2::ResponseType;
}
pub trait SubjectIdentifierType : Clone + Debug + DeserializeOwned + PartialEq + Serialize {}

// FIXME: make this a trait so that callers can add their own enums if desired
new_type![
    #[derive(Deserialize, Serialize)]
    AuthenticationContextClass(String)
];
impl AsRef<str> for AuthenticationContextClass {
    fn as_ref(&self) -> &str{ self }
}

// FIXME: make this a trait so that callers can add their own enums if desired
new_type![
    #[derive(Deserialize, Serialize)]
    AuthenticationMethodReference(String)
];

new_type![
    #[derive(Deserialize, Serialize)]
    AccessTokenHash(String)
];

new_type![
    #[derive(Deserialize, Serialize)]
    AddressCountry(String)
];

new_type![
    #[derive(Deserialize, Serialize)]
    AddressLocality(String)
];

new_type![
    #[derive(Deserialize, Serialize)]
    AddressPostalCode(String)
];

new_type![
    #[derive(Deserialize, Serialize)]
    AddressRegion(String)
];

new_type![
    #[derive(Deserialize, Serialize)]
    Audience(String)
];

new_type![
    #[derive(Deserialize, Serialize)]
    AuthorizationCodeHash(String)
];

new_type![
    #[derive(Deserialize, Serialize)]
    Base64UrlEncodedBytes(
        #[serde(with = "serde_base64url_byte_array")]
        Vec<u8>
    )
];

new_type![
    #[derive(Deserialize, Serialize)]
    ClientName(String)
];

new_type![
    #[derive(Deserialize, Serialize)]
    ClientConfigUrl(
        #[serde(
            deserialize_with = "deserialize_url",
            serialize_with = "serialize_url"
        )]
        Url
    )
];

new_type![
    #[derive(Deserialize, Serialize)]
    ClientUrl(
        #[serde(
            deserialize_with = "deserialize_url",
            serialize_with = "serialize_url"
        )]
        Url
    )
];

new_type![
    #[derive(Deserialize, Serialize)]
    ContactEmail(String)
];

new_type![
    #[derive(Deserialize, Serialize)]
    EndUserBirthday(String)
];

new_type![
    #[derive(Deserialize, Serialize)]
    EndUserEmail(String)
];

new_type![
    #[derive(Deserialize, Serialize)]
    EndUserGivenName(String)
];

new_type![
    #[derive(Deserialize, Serialize)]
    EndUserMiddleName(String)
];

new_type![
    #[derive(Deserialize, Serialize)]
    EndUserName(String)
];

new_type![
    #[derive(Deserialize, Serialize)]
    EndUserNickname(String)
];

new_type![
    #[derive(Deserialize, Serialize)]
    EndUserPhoneNumber(String)
];

new_type![
    #[derive(Deserialize, Serialize)]
    EndUserPictureUrl(
        #[serde(
            deserialize_with = "deserialize_url",
            serialize_with = "serialize_url"
        )]
        Url
    )
];

new_type![
    #[derive(Deserialize, Serialize)]
    EndUserProfileUrl(
        #[serde(
            deserialize_with = "deserialize_url",
            serialize_with = "serialize_url"
        )]
        Url
    )
];

new_type![
    #[derive(Deserialize, Serialize)]
    EndUserTimezone(String)
];

new_type![
    #[derive(Deserialize, Serialize)]
    EndUserWebsiteUrl(
        #[serde(
            deserialize_with = "deserialize_url",
            serialize_with = "serialize_url"
        )]
        Url
    )
];

new_type![
    #[derive(Deserialize, Serialize)]
    EndUserUsername(String)
];

new_type![
    #[derive(Deserialize, Serialize)]
    FormattedAddress(String)
];

new_type![
    #[derive(Deserialize, Serialize)]
    InitiateLoginUrl(
        #[serde(
            deserialize_with = "deserialize_url",
            serialize_with = "serialize_url"
        )]
        Url
    )
];

new_type![
    #[derive(Deserialize, Serialize)]
    IssuerUrl(
        #[serde(
            deserialize_with = "deserialize_url",
            serialize_with = "serialize_url"
        )]
        Url
    )
    impl {
        pub fn join(&self, suffix: &str) -> Result<Url, url::ParseError> {
            let prefix = self.0.as_str().to_string();
            if let Some('/') = prefix.chars().next_back() {
                Url::parse(&(prefix + suffix))
            } else {
                Url::parse(&(prefix + "/" + suffix))
            }
        }
    }
];

new_type![
    #[derive(Deserialize, Serialize)]
    JsonWebKeyId(String)
];

new_type![
    #[derive(Deserialize, Serialize)]
    LanguageTag(String)
];
impl AsRef<str> for LanguageTag {
    fn as_ref(&self) -> &str{ self }
}

new_secret_type![
    #[derive(Deserialize, Serialize)]
    LoginHint(String)
];

new_type![
    #[derive(Deserialize, Serialize)]
    LogoUrl(
        #[serde(
            deserialize_with = "deserialize_url",
            serialize_with = "serialize_url"
        )]
        Url
    )
];

new_secret_type![
    #[derive(Deserialize, Serialize)]
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

new_type![
    #[derive(Deserialize, Serialize)]
    OpPolicyUrl(
        #[serde(
            deserialize_with = "deserialize_url",
            serialize_with = "serialize_url"
        )]
        Url
    )
];

new_type![
    #[derive(Deserialize, Serialize)]
    OpTosUrl(
        #[serde(
            deserialize_with = "deserialize_url",
            serialize_with = "serialize_url"
        )]
        Url
    )
];

new_type![
    #[derive(Deserialize, Serialize)]
    PolicyUrl(
        #[serde(
            deserialize_with = "deserialize_url",
            serialize_with = "serialize_url"
        )]
        Url
    )
];

new_secret_type![
    #[derive(Deserialize, Serialize)]
    RegistrationAccessToken(String)
];

new_type![
    #[derive(Deserialize, Serialize)]
    RegistrationUrl(
        #[serde(
            deserialize_with = "deserialize_url",
            serialize_with = "serialize_url"
        )]
        Url
    )
];

new_type![
    #[derive(Deserialize, Serialize)]
    RequestUrl(
        #[serde(
            deserialize_with = "deserialize_url",
            serialize_with = "serialize_url"
        )]
        Url
    )
];

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
    Vec<RT>
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

new_type![
    #[derive(Deserialize, Serialize)]
    Seconds(u64)
];

new_type![
    #[derive(Deserialize, Serialize)]
    SectorIdentifierUrl(
        #[serde(
            deserialize_with = "deserialize_url",
            serialize_with = "serialize_url"
        )]
        Url
    )
];

new_type![
    #[derive(Deserialize, Serialize)]
    ServiceDocUrl(
        #[serde(
            deserialize_with = "deserialize_url",
            serialize_with = "serialize_url"
        )]
        Url
    )
];

new_type![
    #[derive(Deserialize, Serialize)]
    StreetAddress(String)
];

new_type![
    #[derive(Deserialize, Serialize)]
    SubjectIdentifier(String)
];

new_type![
    #[derive(Deserialize, Serialize)]
    ToSUrl(
        #[serde(
            deserialize_with = "deserialize_url",
            serialize_with = "serialize_url"
        )]
        Url
    )
];

pub mod helpers {
    use oauth2::prelude::*;
    use serde::Serializer;

    use super::LanguageTag;

    ///
    /// Serde space-delimited string serializer for an `Option<Vec<String>>`.
    ///
    /// This function serializes a string vector into a single space-delimited string.
    /// If `string_vec_opt` is `None`, the function serializes it as `None` (e.g., `null`
    /// in the case of JSON serialization).
    ///
    pub fn serialize_space_delimited_vec<T, S>(
        vec: &[T],
        serializer: S
    ) -> Result<S::Ok, S::Error>
    where T: AsRef<str>, S: Serializer {
        let space_delimited = vec.iter().map(AsRef::<str>::as_ref).collect::<Vec<_>>().join(" ");

        serializer.serialize_str(&space_delimited)
    }

    pub fn split_language_tag_key(key: &str) -> (&str, Option<LanguageTag>) {
        let mut lang_tag_sep = key.splitn(2, '#');

        // String::splitn(2) always returns at least one element.
        let field_name = lang_tag_sep.next().unwrap();

        // TODO: rewrite using Option::filter after
        // https://github.com/rust-lang/rust/pull/49575 is released.
        let language_tag =
            if let Some(language_tag) = lang_tag_sep.next() {
                if !language_tag.is_empty() {
                    Some(LanguageTag::new(language_tag.to_string()))
                } else {
                    None
                }
            } else {
                None
            };

        (field_name, language_tag)
    }
}

mod serde_base64url_byte_array {
    extern crate base64;

    use serde::{Deserialize, Deserializer, Serializer};
    use serde::de::Error;
    use serde_json::{from_value, Value};

    pub fn deserialize<'de, D>(
        deserializer: D
    ) -> Result<Vec<u8>, D::Error>
    where D: Deserializer<'de> {
        let value: Value = Deserialize::deserialize(deserializer)?;
        let base64_encoded: String = from_value(value).map_err(D::Error::custom)?;

        base64::decode_config(&base64_encoded, base64::URL_SAFE_NO_PAD)
            .map_err(|err|
                D::Error::custom(
                    format!(
                        "invalid base64url encoding `{}`: {:?}",
                        base64_encoded,
                        err
                    )
                )
            )
    }

    pub fn serialize<S>(
        v: &[u8],
        serializer: S
    ) -> Result<S::Ok, S::Error>
    where S: Serializer {
        let base64_encoded = base64::encode_config(v, base64::URL_SAFE_NO_PAD);
        serializer.serialize_str(&base64_encoded)
    }
}
