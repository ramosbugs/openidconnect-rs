use std::fmt::{Display, Error as FormatterError, Formatter, Result as FormatterResult};
use std::ops::Deref;

pub use oauth2::basic::{
    BasicErrorResponseType as CoreErrorResponseType,
    BasicRequestTokenError as CoreRequestTokenError, BasicTokenType as CoreTokenType,
};
use oauth2::helpers::variant_name;
use oauth2::{
    EmptyExtraTokenFields, ErrorResponseType, ResponseType as OAuth2ResponseType,
    StandardErrorResponse, StandardTokenResponse,
};
use serde::de::{Error as DeserializeError, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::registration::{
    ClientMetadata, ClientRegistrationRequest, ClientRegistrationResponse,
    EmptyAdditionalClientMetadata, EmptyAdditionalClientRegistrationResponse,
    RegisterErrorResponseType,
};
use super::{
    ApplicationType, AuthDisplay, AuthPrompt, ClaimName, ClaimType, Client, ClientAuthMethod,
    EmptyAdditionalClaims, EmptyAdditionalProviderMetadata, GenderClaim, GrantType, IdToken,
    IdTokenClaims, IdTokenFields, IdTokenVerifier, JsonWebKeySet, JweContentEncryptionAlgorithm,
    JweKeyManagementAlgorithm, JwsSigningAlgorithm, ProviderMetadata, RefreshIdTokenFields,
    ResponseMode, ResponseType, SubjectIdentifierType, UserInfoClaims, UserInfoJsonWebToken,
    UserInfoVerifier,
};

pub use self::jwk::{
    CoreHmacKey, CoreJsonWebKey, CoreJsonWebKeyType, CoreJsonWebKeyUse, CoreRsaPrivateSigningKey,
};

mod crypto;

// Private purely for organizational reasons; exported publicly above.
mod jwk;

#[cfg(feature = "nightly")]
use super::AuthenticationFlow;

///
/// OpenID Connect Core authentication flows.
///
/// Requires the `nightly` feature flag to be enabled.
///
#[cfg(feature = "nightly")]
pub type CoreAuthenticationFlow = AuthenticationFlow<CoreResponseType>;

///
/// OpenID Connect Core client.
///
pub type CoreClient = Client<
    EmptyAdditionalClaims,
    CoreAuthDisplay,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
    CoreJsonWebKeyType,
    CoreJsonWebKeyUse,
    CoreJsonWebKey,
    CoreAuthPrompt,
    CoreRefreshTokenResponse,
    StandardErrorResponse<CoreErrorResponseType>,
    CoreTokenResponse,
    CoreTokenType,
>;

///
/// OpenID Connect Core client metadata.
///
pub type CoreClientMetadata = ClientMetadata<
    EmptyAdditionalClientMetadata,
    CoreApplicationType,
    CoreClientAuthMethod,
    CoreGrantType,
    CoreJweContentEncryptionAlgorithm,
    CoreJweKeyManagementAlgorithm,
    CoreJwsSigningAlgorithm,
    CoreJsonWebKeyType,
    CoreJsonWebKeyUse,
    CoreJsonWebKey,
    CoreResponseType,
    CoreSubjectIdentifierType,
>;

///
/// OpenID Connect Core client registration request.
///
pub type CoreClientRegistrationRequest = ClientRegistrationRequest<
    EmptyAdditionalClientMetadata,
    EmptyAdditionalClientRegistrationResponse,
    CoreApplicationType,
    CoreClientAuthMethod,
    CoreRegisterErrorResponseType,
    CoreGrantType,
    CoreJweContentEncryptionAlgorithm,
    CoreJweKeyManagementAlgorithm,
    CoreJwsSigningAlgorithm,
    CoreJsonWebKeyType,
    CoreJsonWebKeyUse,
    CoreJsonWebKey,
    CoreResponseType,
    CoreSubjectIdentifierType,
>;

///
/// OpenID Connect Core client registration response.
///
pub type CoreClientRegistrationResponse = ClientRegistrationResponse<
    EmptyAdditionalClientMetadata,
    EmptyAdditionalClientRegistrationResponse,
    CoreApplicationType,
    CoreClientAuthMethod,
    CoreGrantType,
    CoreJweContentEncryptionAlgorithm,
    CoreJweKeyManagementAlgorithm,
    CoreJwsSigningAlgorithm,
    CoreJsonWebKeyType,
    CoreJsonWebKeyUse,
    CoreJsonWebKey,
    CoreResponseType,
    CoreSubjectIdentifierType,
>;

///
/// OpenID Connect Core ID token.
///
pub type CoreIdToken = IdToken<
    EmptyAdditionalClaims,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
    CoreJsonWebKeyType,
>;

///
/// OpenID Connect Core ID token claims.
///
pub type CoreIdTokenClaims = IdTokenClaims<EmptyAdditionalClaims, CoreGenderClaim>;

///
/// OpenID Connect Core ID token fields.
///
pub type CoreIdTokenFields = IdTokenFields<
    EmptyAdditionalClaims,
    EmptyExtraTokenFields,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
    CoreJsonWebKeyType,
>;

///
/// OpenID Connect Core ID token refresh token exchange fields.
///
pub type CoreRefreshIdTokenFields = RefreshIdTokenFields<
    EmptyAdditionalClaims,
    EmptyExtraTokenFields,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
    CoreJsonWebKeyType,
>;

///
/// OpenID Connect Core ID token verifier.
///
pub type CoreIdTokenVerifier<'a> = IdTokenVerifier<
    'a,
    CoreJwsSigningAlgorithm,
    CoreJsonWebKeyType,
    CoreJsonWebKeyUse,
    CoreJsonWebKey,
>;

///
/// OpenID Connect Core token response.
///
pub type CoreTokenResponse = StandardTokenResponse<CoreIdTokenFields, CoreTokenType>;

///
/// OpenID Connect Core refresh token response.
///
pub type CoreRefreshTokenResponse = StandardTokenResponse<CoreRefreshIdTokenFields, CoreTokenType>;

///
/// OpenID Connect Core JSON Web Key Set.
///
pub type CoreJsonWebKeySet =
    JsonWebKeySet<CoreJwsSigningAlgorithm, CoreJsonWebKeyType, CoreJsonWebKeyUse, CoreJsonWebKey>;

///
/// OpenID Connect Core provider metadata.
///
pub type CoreProviderMetadata = ProviderMetadata<
    EmptyAdditionalProviderMetadata,
    CoreAuthDisplay,
    CoreClientAuthMethod,
    CoreClaimName,
    CoreClaimType,
    CoreGrantType,
    CoreJweContentEncryptionAlgorithm,
    CoreJweKeyManagementAlgorithm,
    CoreJwsSigningAlgorithm,
    CoreJsonWebKeyType,
    CoreJsonWebKeyUse,
    CoreJsonWebKey,
    CoreResponseMode,
    CoreResponseType,
    CoreSubjectIdentifierType,
>;

///
/// OpenID Connect Core user info claims.
///
pub type CoreUserInfoClaims = UserInfoClaims<EmptyAdditionalClaims, CoreGenderClaim>;

///
/// OpenID Connect Core user info JSON Web Token.
///
pub type CoreUserInfoJsonWebToken = UserInfoJsonWebToken<
    EmptyAdditionalClaims,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
    CoreJsonWebKeyType,
>;

///
/// OpenID Connect Core user info verifier.
///
pub type CoreUserInfoVerifier<'a> = UserInfoVerifier<
    'a,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
    CoreJsonWebKeyType,
    CoreJsonWebKeyUse,
    CoreJsonWebKey,
>;

///
/// OpenID Connect Core client application type.
///
/// These values are defined in
/// [Section 2 of OpenID Connect Dynamic Client Registration 1.0](
///     http://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata).
///
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CoreApplicationType {
    ///
    /// Native Clients MUST only register `redirect_uri`s using custom URI schemes or URLs using
    /// the `http` scheme with `localhost` as the hostname. Authorization Servers MAY place
    /// additional constraints on Native Clients.
    ///
    Native,
    ///
    /// Web Clients using the OAuth Implicit Grant Type MUST only register URLs using the `https`
    /// scheme as `redirect_uri`s; they MUST NOT use `localhost` as the hostname.
    ///
    Web,
}
impl ApplicationType for CoreApplicationType {}

///
/// How the Authorization Server displays the authentication and consent user interface pages
/// to the End-User.
///
/// These values are defined in
/// [Section 3.1.2.1](http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest).
///
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CoreAuthDisplay {
    ///
    /// The Authorization Server SHOULD display the authentication and consent UI consistent
    /// with a full User Agent page view. If the display parameter is not specified, this is
    /// the default display mode.
    ///
    Page,
    ///
    /// The Authorization Server SHOULD display the authentication and consent UI consistent
    /// with a popup User Agent window. The popup User Agent window should be of an appropriate
    /// size for a login-focused dialog and should not obscure the entire window that it is
    /// popping up over.
    ///
    Popup,
    ///
    /// The Authorization Server SHOULD display the authentication and consent UI consistent
    /// with a device that leverages a touch interface.
    ///
    Touch,
    ///
    /// The Authorization Server SHOULD display the authentication and consent UI consistent
    /// with a "feature phone" type display.
    ///
    Wap,
}

impl AsRef<str> for CoreAuthDisplay {
    fn as_ref(&self) -> &str {
        match *self {
            CoreAuthDisplay::Page => "page",
            CoreAuthDisplay::Popup => "popup",
            CoreAuthDisplay::Touch => "touch",
            CoreAuthDisplay::Wap => "wap",
        }
    }
}
impl AuthDisplay for CoreAuthDisplay {}

impl Display for CoreAuthDisplay {
    fn fmt(&self, f: &mut Formatter) -> Result<(), FormatterError> {
        write!(f, "{}", self.as_ref())
    }
}

///
/// Whether the Authorization Server should prompt the End-User for reauthentication and
/// consent.
///
/// These values are defined in
/// [Section 3.1.2.1](http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest).
///
#[derive(PartialEq)]
pub enum CoreAuthPrompt {
    ///
    /// The Authorization Server MUST NOT display any authentication or consent user interface
    /// pages. An error is returned if an End-User is not already authenticated or the Client
    /// does not have pre-configured consent for the requested Claims or does not fulfill other
    /// conditions for processing the request. The error code will typically be
    /// `login_required,` `interaction_required`, or another code defined in
    /// [Section 3.1.2.6](http://openid.net/specs/openid-connect-core-1_0.html#AuthError).
    /// This can be used as a method to check for existing authentication and/or consent.
    ///
    None,
    ///
    /// The Authorization Server SHOULD prompt the End-User for reauthentication. If it cannot
    /// reauthenticate the End-User, it MUST return an error, typically `login_required`.
    ///
    Login,
    ///
    /// The Authorization Server SHOULD prompt the End-User for consent before returning
    /// information to the Client. If it cannot obtain consent, it MUST return an error,
    /// typically `consent_required`.
    ///
    Consent,
    ///
    /// The Authorization Server SHOULD prompt the End-User to select a user account. This
    /// enables an End-User who has multiple accounts at the Authorization Server to select
    /// amongst the multiple accounts that they might have current sessions for. If it cannot
    /// obtain an account selection choice made by the End-User, it MUST return an error,
    /// typically `account_selection_required`.
    ///
    SelectAccount,
}

impl AsRef<str> for CoreAuthPrompt {
    fn as_ref(&self) -> &str {
        match *self {
            CoreAuthPrompt::None => "none",
            CoreAuthPrompt::Login => "login",
            CoreAuthPrompt::Consent => "consent",
            CoreAuthPrompt::SelectAccount => "select_account",
        }
    }
}
impl AuthPrompt for CoreAuthPrompt {}

impl Display for CoreAuthPrompt {
    fn fmt(&self, f: &mut Formatter) -> Result<(), FormatterError> {
        write!(f, "{}", self.as_ref())
    }
}

new_type![
    ///
    /// OpenID Connect Core claim name.
    ///
    #[derive(Deserialize, Eq, Hash, Ord, PartialOrd, Serialize)]
    CoreClaimName(String)
];
impl ClaimName for CoreClaimName {}

///
/// Representation of a Claim Value.
///
/// See [Section 5.6](http://openid.net/specs/openid-connect-core-1_0.html#ClaimTypes) for
/// further information.
///
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CoreClaimType {
    ///
    /// Normal Claims are represented as members in a JSON object. The Claim Name is the member
    /// name and the Claim Value is the member value.
    ///
    Normal,
    ///
    /// Aggregated Claim Type.
    ///
    /// See [Section 5.6.2](
    ///     http://openid.net/specs/openid-connect-core-1_0.html#AggregatedDistributedClaims)
    /// for details.
    ///
    Aggregated,
    ///
    /// Distributed Claim Type.
    ///
    /// See [Section 5.6.2](
    ///     http://openid.net/specs/openid-connect-core-1_0.html#AggregatedDistributedClaims)
    /// for details.
    ///
    Distributed,
}
impl ClaimType for CoreClaimType {}

///
/// OpenID Connect Core client authentication method.
///
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CoreClientAuthMethod {
    ///
    /// Client secret passed via the HTTP Basic authentication scheme.
    ///
    ClientSecretBasic,
    ///
    /// Client authentication using a JSON Web Token signed with the client secret used as an HMAC
    /// key.
    ///
    ClientSecretJwt,
    ///
    /// Client secret passed via the POST request body.
    ///
    ClientSecretPost,
    ///
    /// JSON Web Token signed with a private key whose public key has been previously registered
    /// with the OpenID Connect provider.
    ///
    PrivateKeyJwt,
}
impl ClientAuthMethod for CoreClientAuthMethod {}

///
/// OpenID Connect Core gender claim.
///
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CoreGenderClaim {
    ///
    /// Female
    ///
    Female,
    ///
    /// Male
    ///
    Male,
}
impl GenderClaim for CoreGenderClaim {}

///
/// OpenID Connect Core grant type.
///
// These are defined in various specs, including the Client Registration spec:
//   http://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CoreGrantType {
    ///
    /// Authorization code grant.
    ///
    AuthorizationCode,
    ///
    /// Client credentials grant.
    ///
    ClientCredentials,
    ///
    /// Implicit grant.
    ///
    Implicit,
    ///
    /// End user password grant.
    ///
    Password,
    ///
    /// Refresh token grant.
    ///
    RefreshToken,
}
impl GrantType for CoreGrantType {}
impl<'de> Deserialize<'de> for CoreGrantType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct CoreGrantTypeVisitor;
        impl<'de> Visitor<'de> for CoreGrantTypeVisitor {
            type Value = CoreGrantType;

            fn expecting(&self, formatter: &mut Formatter) -> FormatterResult {
                formatter.write_str("CoreGrantType")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: DeserializeError,
            {
                Ok(match v {
                    "authorization_code" => CoreGrantType::AuthorizationCode,
                    "client_credentials" => CoreGrantType::ClientCredentials,
                    "implicit" => CoreGrantType::Implicit,
                    "password" => CoreGrantType::Password,
                    "refresh_token" => CoreGrantType::RefreshToken,
                    other => {
                        return Err(E::custom(format!("unknown grant type `{}`", other)));
                    }
                })
            }
        }
        deserializer.deserialize_str(CoreGrantTypeVisitor {})
    }
}
impl Serialize for CoreGrantType {
    fn serialize<SE>(&self, serializer: SE) -> Result<SE::Ok, SE::Error>
    where
        SE: Serializer,
    {
        let grant_type_str = match *self {
            CoreGrantType::AuthorizationCode => "authorization_code",
            CoreGrantType::ClientCredentials => "client_credentials",
            CoreGrantType::Implicit => "implicit",
            CoreGrantType::Password => "password",
            CoreGrantType::RefreshToken => "refresh_token",
        };
        serializer.serialize_str(grant_type_str)
    }
}

///
/// OpenID Connect Core JWE encryption algorithms.
///
/// These algorithms represent the `enc` header parameter values for JSON Web Encryption.
/// The values are described in
/// [Section 5.1 of RFC 7518](https://tools.ietf.org/html/rfc7518#section-5.1).
///
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum CoreJweContentEncryptionAlgorithm {
    ///
    /// AES-128 CBC HMAC SHA-256 authenticated encryption.
    ///
    #[serde(rename = "A128CBC-HS256")]
    Aes128CbcHmacSha256,
    ///
    /// AES-192 CBC HMAC SHA-384 authenticated encryption.
    ///
    #[serde(rename = "A192CBC-HS384")]
    Aes192CbcHmacSha384,
    ///
    /// AES-256 CBC HMAC SHA-512 authenticated encryption.
    ///
    #[serde(rename = "A256CBC-HS512")]
    Aes256CbcHmacSha512,
    ///
    /// AES-128 GCM.
    ///
    #[serde(rename = "A128GCM")]
    Aes128Gcm,
    ///
    /// AES-192 GCM.
    ///
    #[serde(rename = "A192GCM")]
    Aes192Gcm,
    ///
    /// AES-256 GCM.
    ///
    #[serde(rename = "A256GCM")]
    Aes256Gcm,
}
impl JweContentEncryptionAlgorithm<CoreJsonWebKeyType> for CoreJweContentEncryptionAlgorithm {
    fn key_type(&self) -> Result<CoreJsonWebKeyType, String> {
        Ok(CoreJsonWebKeyType::Symmetric)
    }
}

///
/// OpenID Connect Core JWE key management algorithms.
///
/// These algorithms represent the `alg` header parameter values for JSON Web Encryption.
/// They are used to encrypt the Content Encryption Key (CEK) to produce the JWE Encrypted Key, or
/// to use key agreement to agree upon the CEK. The values are described in
/// [Section 4.1 of RFC 7518](https://tools.ietf.org/html/rfc7518#section-4.1).
///
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum CoreJweKeyManagementAlgorithm {
    ///
    /// RSAES-PKCS1-V1_5.
    ///
    #[serde(rename = "RSA1_5")]
    RsaPkcs1V15,
    ///
    /// RSAES OAEP using default parameters.
    ///
    #[serde(rename = "RSA-OAEP")]
    RsaOaep,
    ///
    /// RSAES OAEP using SHA-256 and MGF1 with SHA-256.
    ///
    #[serde(rename = "RSA-OAEP-256")]
    RsaOaepSha256,
    ///
    /// AES-128 Key Wrap.
    ///
    #[serde(rename = "A128KW")]
    AesKeyWrap128,
    ///
    /// AES-192 Key Wrap.
    ///
    #[serde(rename = "A192KW")]
    AesKeyWrap192,
    ///
    /// AES-256 Key Wrap.
    ///
    #[serde(rename = "A256KW")]
    AesKeyWrap256,
    ///
    /// Direct use of a shared symmetric key as the Content Encryption Key (CEK).
    ///
    #[serde(rename = "dir")]
    Direct,
    ///
    /// Elliptic Curve Diffie-Hellman Ephemeral Static key agreement using Concat KDF.
    ///
    #[serde(rename = "ECDH-ES")]
    EcdhEs,
    ///
    /// ECDH-ES using Concat KDF and CEK wrapped with AES-128 Key Wrap.
    ///
    #[serde(rename = "ECDH-ES+A128KW")]
    EcdhEsAesKeyWrap128,
    ///
    /// ECDH-ES using Concat KDF and CEK wrapped with AES-192 Key Wrap.
    ///
    #[serde(rename = "ECDH-ES+A192KW")]
    EcdhEsAesKeyWrap192,
    ///
    /// ECDH-ES using Concat KDF and CEK wrapped with AES-256 Key Wrap.
    ///
    #[serde(rename = "ECDH-ES+A256KW")]
    EcdhEsAesKeyWrap256,
    ///
    /// Key wrapping with AES GCM using 128 bit key.
    ///
    #[serde(rename = "A128GCMKW")]
    Aes128Gcm,
    ///
    /// Key wrapping with AES GCM using 192 bit key.
    ///
    #[serde(rename = "A192GCMKW")]
    Aes192Gcm,
    ///
    /// Key wrapping with AES GCM using 256 bit key.
    ///
    #[serde(rename = "A256GCMKW")]
    Aes256Gcm,
    ///
    /// PBES2 with HMAC SHA-256 wrapped with AES-128 Key Wrap.
    ///
    #[serde(rename = "PBES2-HS256+A128KW")]
    PbEs2HmacSha256AesKeyWrap128,
    ///
    /// PBES2 with HMAC SHA-384 wrapped with AES-192 Key Wrap.
    ///
    #[serde(rename = "PBES2-HS384+A192KW")]
    PbEs2HmacSha384AesKeyWrap192,
    ///
    /// PBES2 with HMAC SHA-512 wrapped with AES-256 Key Wrap.
    ///
    #[serde(rename = "PBES2-HS512+A256KW")]
    PbEs2HmacSha512AesKeyWrap256,
}
impl JweKeyManagementAlgorithm for CoreJweKeyManagementAlgorithm {}

///
/// OpenID Connect Core JWS signing algorithms.
///
/// These algorithms represent the `alg` header parameter values for JSON Web Signature.
/// They are used to digitally sign or create a MAC of the contents of the JWS Protected Header and
/// the JWS Payload. The values are described in
/// [Section 3.1 of RFC 7518](https://tools.ietf.org/html/rfc7518#section-3.1).
///
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum CoreJwsSigningAlgorithm {
    ///
    /// HMAC using SHA-256 (currently unsupported).
    ///
    #[serde(rename = "HS256")]
    HmacSha256,
    ///
    /// HMAC using SHA-384 (currently unsupported).
    ///
    #[serde(rename = "HS384")]
    HmacSha384,
    ///
    /// HMAC using SHA-512 (currently unsupported).
    ///
    #[serde(rename = "HS512")]
    HmacSha512,
    ///
    /// RSA SSA PKCS#1 v1.5 using SHA-256.
    ///
    #[serde(rename = "RS256")]
    RsaSsaPkcs1V15Sha256,
    ///
    /// RSA SSA PKCS#1 v1.5 using SHA-384.
    ///
    #[serde(rename = "RS384")]
    RsaSsaPkcs1V15Sha384,
    ///
    /// RSA SSA PKCS#1 v1.5 using SHA-512.
    ///
    #[serde(rename = "RS512")]
    RsaSsaPkcs1V15Sha512,
    ///
    /// ECDSA using P-256 and SHA-256 (currently unsupported).
    ///
    #[serde(rename = "ES256")]
    EcdsaP256Sha256,
    ///
    /// ECDSA using P-384 and SHA-384 (currently unsupported).
    ///
    #[serde(rename = "ES384")]
    EcdsaP384Sha384,
    ///
    /// ECDSA using P-521 and SHA-512 (currently unsupported).
    ///
    #[serde(rename = "ES512")]
    EcdsaP521Sha512,
    ///
    /// RSA SSA-PSS using SHA-256 and MGF1 with SHA-256.
    ///
    #[serde(rename = "PS256")]
    RsaSsaPssSha256,
    ///
    /// RSA SSA-PSS using SHA-384 and MGF1 with SHA-384.
    ///
    #[serde(rename = "PS384")]
    RsaSsaPssSha384,
    ///
    /// RSA SSA-PSS using SHA-512 and MGF1 with SHA-512.
    ///
    #[serde(rename = "PS512")]
    RsaSsaPssSha512,
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
    #[serde(rename = "none")]
    None,
}
impl JwsSigningAlgorithm<CoreJsonWebKeyType> for CoreJwsSigningAlgorithm {
    fn key_type(&self) -> Result<CoreJsonWebKeyType, String> {
        Ok(match *self {
            CoreJwsSigningAlgorithm::HmacSha256 => CoreJsonWebKeyType::Symmetric,
            CoreJwsSigningAlgorithm::HmacSha384 => CoreJsonWebKeyType::Symmetric,
            CoreJwsSigningAlgorithm::HmacSha512 => CoreJsonWebKeyType::Symmetric,
            CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256 => CoreJsonWebKeyType::RSA,
            CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha384 => CoreJsonWebKeyType::RSA,
            CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha512 => CoreJsonWebKeyType::RSA,
            CoreJwsSigningAlgorithm::EcdsaP256Sha256 => CoreJsonWebKeyType::EllipticCurve,
            CoreJwsSigningAlgorithm::EcdsaP384Sha384 => CoreJsonWebKeyType::EllipticCurve,
            CoreJwsSigningAlgorithm::EcdsaP521Sha512 => CoreJsonWebKeyType::EllipticCurve,
            CoreJwsSigningAlgorithm::RsaSsaPssSha256 => CoreJsonWebKeyType::RSA,
            CoreJwsSigningAlgorithm::RsaSsaPssSha384 => CoreJsonWebKeyType::RSA,
            CoreJwsSigningAlgorithm::RsaSsaPssSha512 => CoreJsonWebKeyType::RSA,
            CoreJwsSigningAlgorithm::None => {
                return Err("signature algorithm `none` has no corresponding key type".to_string());
            }
        })
    }

    fn is_symmetric(&self) -> bool {
        if let Ok(kty) = self.key_type() {
            kty == CoreJsonWebKeyType::Symmetric
        } else {
            false
        }
    }

    fn rsa_sha_256() -> Self {
        CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256
    }
}

///
/// OpenID Connect Core registration error response type.
///
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CoreRegisterErrorResponseType {
    ///
    /// The value of one or more `redirect_uri`s is invalid.
    ///
    InvalidRedirectUri,
    ///
    /// The value of one of the Client Metadata fields is invalid and the server has rejected this
    /// request. Note that an Authorization Server MAY choose to substitute a valid value for any
    /// requested parameter of a Client's Metadata.
    ///
    InvalidClientMetadata,
}
impl ErrorResponseType for CoreRegisterErrorResponseType {}
impl RegisterErrorResponseType for CoreRegisterErrorResponseType {}
impl Display for CoreRegisterErrorResponseType {
    fn fmt(&self, f: &mut Formatter) -> Result<(), FormatterError> {
        write!(f, "{}", variant_name(self))
    }
}

///
/// OpenID Connect Core response mode.
///
/// Informs the Authorization Server of the mechanism to be used for returning Authorization
/// Response parameters from the Authorization Endpoint.
///
/// The default Response Mode for the OAuth 2.0 `code` Response Type is the `query` encoding.
/// The default Response Mode for the OAuth 2.0 `token` Response Type is the `fragment` encoding.
/// These values are defined in
/// [OAuth 2.0 Multiple Response Type Encoding Practices](
///     http://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#ResponseTypesAndModes)
/// and [OAuth 2.0 Form Post Response Mode](
///     http://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html#FormPostResponseMode).
///
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CoreResponseMode {
    ///
    /// In this mode, Authorization Response parameters are encoded in the query string added to
    /// the `redirect_uri` when redirecting back to the Client.
    ///
    Query,
    ///
    /// In this mode, Authorization Response parameters are encoded in the fragment added to the
    /// `redirect_uri` when redirecting back to the Client.
    ///
    Fragment,
    ///
    /// In this mode, Authorization Response parameters are encoded as HTML form values that are
    /// auto-submitted in the User Agent, and thus are transmitted via the HTTP `POST` method to the
    /// Client, with the result parameters being encoded in the body using the
    /// `application/x-www-form-urlencoded` format. The `action` attribute of the form MUST be the
    /// Client's Redirection URI. The method of the form attribute MUST be `POST`. Because the
    /// Authorization Response is intended to be used only once, the Authorization Server MUST
    /// instruct the User Agent (and any intermediaries) not to store or reuse the content of the
    /// response.
    ///
    /// Any technique supported by the User Agent MAY be used to cause the submission of the form,
    /// and any form content necessary to support this MAY be included, such as submit controls and
    /// client-side scripting commands. However, the Client MUST be able to process the message
    /// without regard for the mechanism by which the form submission was initiated.
    ///
    /// See [OAuth 2.0 Form Post Response Mode](
    ///     http://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html#FormPostResponseMode)
    /// for further information.
    ///
    FormPost,
}
impl ResponseMode for CoreResponseMode {}

///
/// OpenID Connect Core response type.
///
/// Informs the Authorization Server of the desired authorization processing flow, including what
/// parameters are returned from the endpoints used.  
///
/// This type represents a single Response Type. Multiple Response Types are represented via the
/// `ResponseTypes` type, which wraps a `Vec<ResponseType>`.
///
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CoreResponseType {
    ///
    /// Used by the OAuth 2.0 Authorization Code Flow.
    ///
    Code,
    ///
    /// When supplied as the `response_type` parameter in an OAuth 2.0 Authorization Request, a
    /// successful response MUST include the parameter `id_token`.
    ///
    IdToken,
    ///
    /// When supplied as the `response_type` parameter in an OAuth 2.0 Authorization Request, the
    /// Authorization Server SHOULD NOT return an OAuth 2.0 Authorization Code, Access Token, Access
    /// Token Type, or ID Token in a successful response to the grant request. If a `redirect_uri`
    /// is supplied, the User Agent SHOULD be redirected there after granting or denying access.
    /// The request MAY include a `state` parameter, and if so, the Authorization Server MUST echo
    /// its value as a response parameter when issuing either a successful response or an error
    /// response. The default Response Mode for this Response Type is the query encoding. Both
    /// successful and error responses SHOULD be returned using the supplied Response Mode, or if
    /// none is supplied, using the default Response Mode.
    ///
    /// This Response Type is not generally used with OpenID Connect but may be supported by the
    /// Authorization Server.
    ///
    None,
    ///
    /// Used by the OAuth 2.0 Implicit Flow.
    ///
    Token,
}
impl ResponseType for CoreResponseType {
    fn to_oauth2(&self) -> OAuth2ResponseType {
        OAuth2ResponseType::new(self.as_ref().to_string())
    }
}
impl AsRef<str> for CoreResponseType {
    fn as_ref(&self) -> &str {
        variant_name(self)
    }
}

///
/// OpenID Connect Core Subject Identifier type.
///
/// A Subject Identifier is a locally unique and never reassigned identifier within the Issuer for
/// the End-User, which is intended to be consumed by the Client.
///
/// See [Section 8](http://openid.net/specs/openid-connect-core-1_0.html#SubjectIDTypes) for
/// further information.
///
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CoreSubjectIdentifierType {
    ///
    /// This provides a different `sub` value to each Client, so as not to enable Clients to
    /// correlate the End-User's activities without permission.
    ///
    Pairwise,
    ///
    /// This provides the same `sub` (subject) value to all Clients. It is the default if the
    /// provider has no `subject_types_supported` element in its discovery document.
    ///
    Public,
}
impl SubjectIdentifierType for CoreSubjectIdentifierType {}

#[cfg(test)]
mod tests;
