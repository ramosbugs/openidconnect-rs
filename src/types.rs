extern crate url;

use std::fmt::{Debug, Display, Error as FormatterError, Formatter};
use std::ops::Deref;

use oauth2;
use oauth2::helpers::{deserialize_space_delimited_vec, deserialize_url, serialize_url};
use oauth2::prelude::*;
use serde::Serialize;
use serde::de::DeserializeOwned;
use url::Url;

///
/// How the Authorization Server displays the authentication and consent user interface pages to
/// the End-User.
///
pub trait AuthDisplay : Debug + DeserializeOwned + PartialEq + Serialize {
    fn to_str(&self) -> &str;
}

///
/// Whether the Authorization Server should prompt the End-User for reauthentication and consent.
///
pub trait AuthPrompt : AsRef<str> + Display + PartialEq {
    fn to_str(&self) -> &str;
}

pub trait ClaimName : Debug + DeserializeOwned + PartialEq + Serialize {}
pub trait ClaimType : Debug + DeserializeOwned + PartialEq + Serialize {}

pub trait ClientAuthMethod : Debug + DeserializeOwned + PartialEq + Serialize {}
pub trait GrantType : Debug + DeserializeOwned + PartialEq + Serialize {}
pub trait JweContentEncryptionAlgorithm : Debug + DeserializeOwned + PartialEq + Serialize {}
pub trait JweKeyManagementAlgorithm : Debug + DeserializeOwned + PartialEq + Serialize {}
pub trait JwsSigningAlgorithm : Debug + DeserializeOwned + PartialEq + Serialize {}
pub trait ResponseMode : Debug + DeserializeOwned + PartialEq + Serialize {}
pub trait ResponseType : AsRef<str> + Debug + DeserializeOwned + PartialEq + Serialize {
    fn to_oauth2(&self) -> oauth2::ResponseType;
}
pub trait SubjectIdentifierType : Debug + DeserializeOwned + PartialEq + Serialize {}

new_type![
    #[derive(Deserialize, Serialize)]
    AuthenticationContextClass(String)
];
impl AsRef<str> for AuthenticationContextClass {
    fn as_ref(&self) -> &str{ self }
}

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
        pub fn join(self, suffix: &str) -> Result<Url, url::ParseError> {
            let prefix = self.0.into_string();
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
    JwkSetUrl(
        #[serde(
            deserialize_with = "deserialize_url",
            serialize_with = "serialize_url"
        )]
        Url
    )
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

new_secret_type![
    #[derive(Deserialize, Serialize)]
    Nonce(String)
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
    RegistrationUrl(
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
#[derive(Debug, Deserialize, PartialEq, Serialize)]
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
    UserInfoUrl(
        #[serde(
            deserialize_with = "deserialize_url",
            serialize_with = "serialize_url"
        )]
        Url
    )
];

pub mod helpers {
    use serde::{Serialize, Serializer};

    ///
    /// Serde space-delimited string serializer for an `Option<Vec<String>>`.
    ///
    /// This function serializes a string vector into a single space-delimited string.
    /// If `string_vec_opt` is `None`, the function serializes it as `None` (e.g., `null`
    /// in the case of JSON serialization).
    ///
    pub fn serialize_space_delimited_vec<T, S>(
        vec: &Vec<T>,
        serializer: S
    ) -> Result<S::Ok, S::Error>
    where T: AsRef<str>, S: Serializer {
        let space_delimited = vec.iter().map(AsRef::<str>::as_ref).collect::<Vec<_>>().join(" ");

        serializer.serialize_str(&space_delimited)
    }
}
