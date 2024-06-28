use crate::types::jwk::JsonWebKey;
use crate::{AccessToken, AuthorizationCode};

use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use base64::Engine;
use oauth2::helpers::deserialize_space_delimited_vec;
use rand::{thread_rng, Rng};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

use std::fmt::Debug;
use std::hash::Hash;
use std::ops::Deref;

pub(crate) mod jwk;
pub(crate) mod jwks;
pub(crate) mod localized;

#[cfg(test)]
mod tests;

/// Client application type.
pub trait ApplicationType: Debug + DeserializeOwned + Serialize + 'static {}

/// How the Authorization Server displays the authentication and consent user interface pages to
/// the End-User.
pub trait AuthDisplay: AsRef<str> + Debug + DeserializeOwned + Serialize + 'static {}

/// Whether the Authorization Server should prompt the End-User for reauthentication and consent.
pub trait AuthPrompt: AsRef<str> + 'static {}

/// Claim name.
pub trait ClaimName: Debug + DeserializeOwned + Serialize + 'static {}

/// Claim type (e.g., normal, aggregated, or distributed).
pub trait ClaimType: Debug + DeserializeOwned + Serialize + 'static {}

/// Client authentication method.
pub trait ClientAuthMethod: Debug + DeserializeOwned + Serialize + 'static {}

/// Grant type.
pub trait GrantType: Debug + DeserializeOwned + Serialize + 'static {}

/// Error signing a message.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum SigningError {
    /// Failed to sign the message using the given key and parameters.
    #[error("Crypto error")]
    CryptoError,
    /// Unsupported signature algorithm.
    #[error("Unsupported signature algorithm: {0}")]
    UnsupportedAlg(String),
    /// An unexpected error occurred.
    #[error("Other error: {0}")]
    Other(String),
}

/// Response mode indicating how the OpenID Connect Provider should return the Authorization
/// Response to the Relying Party (client).
pub trait ResponseMode: Debug + DeserializeOwned + Serialize + 'static {}

/// Response type indicating the desired authorization processing flow, including what
/// parameters are returned from the endpoints used.
pub trait ResponseType: AsRef<str> + Debug + DeserializeOwned + Serialize + 'static {
    /// Converts this OpenID Connect response type to an [`oauth2::ResponseType`] used by the
    /// underlying [`oauth2`] crate.
    fn to_oauth2(&self) -> oauth2::ResponseType;
}

/// Subject identifier type returned by an OpenID Connect Provider to uniquely identify its users.
pub trait SubjectIdentifierType: Debug + DeserializeOwned + Serialize + 'static {}

new_type![
    /// Set of authentication methods or procedures that are considered to be equivalent to each
    /// other in a particular context.
    #[derive(Deserialize, Hash, Ord, PartialOrd, Serialize)]
    #[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
    AuthenticationContextClass(String)
];
impl AsRef<str> for AuthenticationContextClass {
    fn as_ref(&self) -> &str {
        self
    }
}

new_type![
    /// Identifier for an authentication method (e.g., `password` or `totp`).
    ///
    /// Defining specific AMR identifiers is beyond the scope of the OpenID Connect Core spec.
    #[derive(Deserialize, Hash, Ord, PartialOrd, Serialize)]
    #[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
    AuthenticationMethodReference(String)
];

new_type![
    /// Access token hash.
    #[derive(Deserialize, Hash, Ord, PartialOrd, Serialize)]
    #[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
    AccessTokenHash(String)
    impl {
        /// Initialize a new access token hash from an [`AccessToken`] and signature algorithm.
        pub fn from_token<K>(
            access_token: &AccessToken,
            alg: &K::SigningAlgorithm,
            key: &K,
        ) -> Result<Self, SigningError>
        where
            K: JsonWebKey,
        {
            key.hash_bytes(access_token.secret().as_bytes(), alg)
                .map(|hash| Self::new(BASE64_URL_SAFE_NO_PAD.encode(&hash[0..hash.len() / 2])))
                .map_err(SigningError::UnsupportedAlg)
        }
    }
];

new_type![
    /// Country portion of address.
    #[derive(Deserialize, Hash, Ord, PartialOrd, Serialize)]
    #[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
    AddressCountry(String)
];

new_type![
    /// Locality portion of address.
    #[derive(Deserialize, Hash, Ord, PartialOrd, Serialize)]
    #[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
    AddressLocality(String)
];

new_type![
    /// Postal code portion of address.
    #[derive(Deserialize, Hash, Ord, PartialOrd, Serialize)]
    #[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
    AddressPostalCode(String)
];

new_type![
    /// Region portion of address.
    #[derive(Deserialize, Hash, Ord, PartialOrd, Serialize)]
    #[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
    AddressRegion(String)
];

new_type![
    /// Audience claim value.
    #[derive(Deserialize, Hash, Ord, PartialOrd, Serialize)]
    #[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
    Audience(String)
];

new_type![
    /// Authorization code hash.
    #[derive(Deserialize, Hash, Ord, PartialOrd, Serialize)]
    #[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
    AuthorizationCodeHash(String)
    impl {
        /// Initialize a new authorization code hash from an [`AuthorizationCode`] and signature
        /// algorithm.
        pub fn from_code<K>(
            code: &AuthorizationCode,
            alg: &K::SigningAlgorithm,
            key: &K,
        ) -> Result<Self, SigningError>
        where
            K: JsonWebKey,
        {
            key.hash_bytes(code.secret().as_bytes(), alg)
                .map(|hash| Self::new(BASE64_URL_SAFE_NO_PAD.encode(&hash[0..hash.len() / 2])))
                .map_err(SigningError::UnsupportedAlg)
        }
    }
];

new_type![
    /// OpenID Connect client name.
    #[derive(Deserialize, Hash, Ord, PartialOrd, Serialize)]
    #[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
    ClientName(String)
];

new_url_type![
    /// Client configuration endpoint URL.
    ClientConfigUrl
];

new_url_type![
    /// Client homepage URL.
    ClientUrl
];

new_type![
    /// Client contact e-mail address.
    #[derive(Deserialize, Hash, Ord, PartialOrd, Serialize)]
    #[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
    ClientContactEmail(String)
];

new_url_type![
    /// URL for the [OpenID Connect RP-Initiated Logout 1.0](
    /// https://openid.net/specs/openid-connect-rpinitiated-1_0.html) end session endpoint.
    EndSessionUrl
];

new_type![
    /// End user's birthday, represented as an
    /// [ISO 8601:2004](https://www.iso.org/standard/40874.html) `YYYY-MM-DD` format.
    ///
    /// The year MAY be `0000`, indicating that it is omitted. To represent only the year, `YYYY`
    /// format is allowed. Note that depending on the underlying platform's date related function,
    /// providing just year can result in varying month and day, so the implementers need to take
    /// this factor into account to correctly process the dates.
    #[derive(Deserialize, Hash, Ord, PartialOrd, Serialize)]
    #[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
    EndUserBirthday(String)
];

new_type![
    /// End user's e-mail address.
    #[derive(Deserialize, Hash, Ord, PartialOrd, Serialize)]
    #[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
    EndUserEmail(String)
];

new_type![
    /// End user's family name.
    #[derive(Deserialize, Hash, Ord, PartialOrd, Serialize)]
    #[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
    EndUserFamilyName(String)
];

new_type![
    /// End user's given name.
    #[derive(Deserialize, Hash, Ord, PartialOrd, Serialize)]
    #[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
    EndUserGivenName(String)
];

new_type![
    /// End user's middle name.
    #[derive(Deserialize, Hash, Ord, PartialOrd, Serialize)]
    #[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
    EndUserMiddleName(String)
];

new_type![
    /// End user's name.
    #[derive(Deserialize, Hash, Ord, PartialOrd, Serialize)]
    #[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
    EndUserName(String)
];

new_type![
    /// End user's nickname.
    #[derive(Deserialize, Hash, Ord, PartialOrd, Serialize)]
    #[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
    EndUserNickname(String)
];

new_type![
    /// End user's phone number.
    #[derive(Deserialize, Hash, Ord, PartialOrd, Serialize)]
    #[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
    EndUserPhoneNumber(String)
];

new_type![
    /// URL of end user's profile picture.
    #[derive(Deserialize, Hash, Ord, PartialOrd, Serialize)]
    #[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
    EndUserPictureUrl(String)
];

new_type![
    /// URL of end user's profile page.
    #[derive(Deserialize, Hash, Ord, PartialOrd, Serialize)]
    #[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
    EndUserProfileUrl(String)
];

new_type![
    /// End user's time zone as a string from the
    /// [time zone database](https://www.iana.org/time-zones).
    #[derive(Deserialize, Hash, Ord, PartialOrd, Serialize)]
    #[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
    EndUserTimezone(String)
];

new_type![
    /// URL of end user's website.
    #[derive(Deserialize, Hash, Ord, PartialOrd, Serialize)]
    #[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
    EndUserWebsiteUrl(String)
];

new_type![
    /// End user's username.
    #[derive(Deserialize, Hash, Ord, PartialOrd, Serialize)]
    #[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
    EndUserUsername(String)
];

new_type![
    /// Full mailing address, formatted for display or use on a mailing label.
    ///
    /// This field MAY contain multiple lines, separated by newlines. Newlines can be represented
    /// either as a carriage return/line feed pair (`"\r\n"`) or as a single line feed character
    /// (`"\n"`).
    #[derive(Deserialize, Hash, Ord, PartialOrd, Serialize)]
    #[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
    FormattedAddress(String)
];

new_url_type![
    /// URI using the `https` scheme that a third party can use to initiate a login by the Relying
    /// Party.
    InitiateLoginUrl
];

new_url_type![
    /// URL using the `https` scheme with no query or fragment component that the OP asserts as its
    /// Issuer Identifier.
    IssuerUrl
    impl {
        /// Parse a string as a URL, with this URL as the base URL.
        ///
        /// See [`Url::parse`].
        pub fn join(&self, suffix: &str) -> Result<Url, url::ParseError> {
            if let Some('/') = self.1.chars().next_back() {
                Url::parse(&(self.1.clone() + suffix))
            } else {
                Url::parse(&(self.1.clone() + "/" + suffix))
            }
        }
    }
];

new_secret_type![
    /// Hint about the login identifier the End-User might use to log in.
    ///
    /// The use of this parameter is left to the OpenID Connect Provider's discretion.
    #[derive(Clone, Deserialize, Serialize)]
    LoginHint(String)
];

new_secret_type![
    /// Hint about the logout identifier the End-User might use to log out.
    ///
    /// The use of this parameter is left to the OpenID Connect Provider's discretion.
    #[derive(Clone, Deserialize, Serialize)]
    LogoutHint(String)
];

new_url_type![
    /// URL that references a logo for the Client application.
    LogoUrl
];

new_secret_type![
    /// String value used to associate a client session with an ID Token, and to mitigate replay
    /// attacks.
    #[derive(Clone, Deserialize, Serialize)]
    Nonce(String)
    impl {
        /// Generate a new random, base64-encoded 128-bit nonce.
        pub fn new_random() -> Self {
            Nonce::new_random_len(16)
        }
        /// Generate a new random, base64-encoded nonce of the specified length.
        ///
        /// # Arguments
        ///
        /// * `num_bytes` - Number of random bytes to generate, prior to base64-encoding.
        pub fn new_random_len(num_bytes: u32) -> Self {
            let random_bytes: Vec<u8> = (0..num_bytes).map(|_| thread_rng().gen::<u8>()).collect();
            Nonce::new(BASE64_URL_SAFE_NO_PAD.encode(random_bytes))
        }
    }
];

new_url_type![
    /// URL providing the OpenID Connect Provider's data usage policies for client applications.
    OpPolicyUrl
];

new_url_type![
    /// URL providing the OpenID Connect Provider's Terms of Service.
    OpTosUrl
];

new_url_type![
    /// URL providing a client application's data usage policy.
    PolicyUrl
];

new_url_type![
    /// The post logout redirect URL, which should be passed to the end session endpoint
    /// of providers implementing [OpenID Connect RP-Initiated Logout 1.0](
    /// https://openid.net/specs/openid-connect-rpinitiated-1_0.html).
    PostLogoutRedirectUrl
];

new_secret_type![
    /// Access token used by a client application to access the Client Registration endpoint.
    #[derive(Clone, Deserialize, Serialize)]
    RegistrationAccessToken(String)
];

new_url_type![
    /// URL of the Client Registration endpoint.
    RegistrationUrl
];

new_url_type![
    /// URL used to pass request parameters as JWTs by reference.
    RequestUrl
];

/// Informs the Authorization Server of the desired authorization processing flow, including what
/// parameters are returned from the endpoints used.
///
/// See [OAuth 2.0 Multiple Response Type Encoding Practices](
///     http://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#ResponseTypesAndModes)
/// for further details.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ResponseTypes<RT: ResponseType>(
    #[serde(
        deserialize_with = "deserialize_space_delimited_vec",
        serialize_with = "crate::helpers::serialize_space_delimited_vec"
    )]
    Vec<RT>,
);
impl<RT: ResponseType> ResponseTypes<RT> {
    /// Create a new [`ResponseTypes<RT>`] to wrap the given [`Vec<RT>`].
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

new_url_type![
    /// URL for retrieving redirect URIs that should receive identical pairwise subject identifiers.
    SectorIdentifierUrl
];

new_url_type![
    /// URL for developer documentation for an OpenID Connect Provider.
    ServiceDocUrl
];

new_type![
    /// A user's street address.
    ///
    /// Full street address component, which MAY include house number, street name, Post Office Box,
    /// and multi-line extended street address information. This field MAY contain multiple lines,
    /// separated by newlines. Newlines can be represented either as a carriage return/line feed
    /// pair (`\r\n`) or as a single line feed character (`\n`).
    #[derive(Deserialize, Hash, Ord, PartialOrd, Serialize)]
    #[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
    StreetAddress(String)
];

new_type![
    /// Locally unique and never reassigned identifier within the Issuer for the End-User, which is
    /// intended to be consumed by the client application.
    #[derive(Deserialize, Hash, Ord, PartialOrd, Serialize)]
    #[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
    SubjectIdentifier(String)
];

new_url_type![
    /// URL for the relying party's Terms of Service.
    ToSUrl
];
