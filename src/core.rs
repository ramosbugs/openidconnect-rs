
use std::fmt::{Display, Error as FormatterError, Formatter};
use std::ops::Deref;

use oauth2::{
    ErrorResponseType,
    ResponseType as OAuth2ResponseType,
};
use oauth2::basic::{
    BasicErrorResponseType,
    BasicTokenType,
};
use oauth2::helpers::variant_name;
use oauth2::prelude::*;
use ring::digest;
use ring::signature as ring_signature;

use super::{
    ApplicationType,
    AuthDisplay,
    AuthPrompt,
    Base64UrlEncodedBytes,
    ClaimName,
    ClaimType,
    Client,
    ClientAuthMethod,
    EmptyAdditionalClaims,
    GenderClaim,
    GrantType,
    IdToken,
    IdTokenClaims,
    IdTokenVerifier,
    JsonWebKey,
    JsonWebKeyId,
    JsonWebKeySet,
    JsonWebKeyType,
    JsonWebKeyUse,
    JweContentEncryptionAlgorithm,
    JweKeyManagementAlgorithm,
    JwsSigningAlgorithm,
    ResponseMode,
    ResponseType,
    SignatureVerificationError,
    SubjectIdentifierType,
    UserInfoClaims,
    UserInfoVerifier,
};
use super::discovery::Discovery10ProviderMetadata;
use super::registration::{
    RegisterErrorResponseType,
    Registration10ClientMetadata,
    Registration10ClientRegistrationRequest,
    Registration10ClientRegistrationResponse
};

pub type CoreClient =
    Client<
        // FIXME: mixing these OAuth2 and OIDC types is a little messy. See if it makes sense
        // to use type aliases to make this cleaner.
        EmptyAdditionalClaims,
        CoreAuthDisplay,
        CoreGenderClaim,
        CoreJweContentEncryptionAlgorithm,
        CoreJwsSigningAlgorithm,
        CoreJsonWebKeyType,
        CoreAuthPrompt,
// FIXME: use the right error types for the token response
        BasicErrorResponseType,
        BasicTokenType
    >;

pub type CoreClientMetadata =
    Registration10ClientMetadata<
        CoreApplicationType,
        CoreClientAuthMethod,
        CoreGrantTypeWrapper,
        CoreJweContentEncryptionAlgorithm,
        CoreJweKeyManagementAlgorithm,
        CoreJwsSigningAlgorithm,
        CoreJsonWebKeyType,
        CoreJsonWebKeyUse,
        CoreJsonWebKey,
        CoreResponseType,
        CoreSubjectIdentifierType
    >;

pub type CoreClientRegistrationRequest =
    Registration10ClientRegistrationRequest<
        CoreApplicationType,
        CoreClientAuthMethod,
        CoreClientRegistrationResponse,
        CoreRegisterErrorResponseType,
        CoreGrantTypeWrapper,
        CoreJweContentEncryptionAlgorithm,
        CoreJweKeyManagementAlgorithm,
        CoreJwsSigningAlgorithm,
        CoreJsonWebKeyType,
        CoreJsonWebKeyUse,
        CoreJsonWebKey,
        CoreResponseType,
        CoreSubjectIdentifierType
    >;

pub type CoreClientRegistrationResponse =
    Registration10ClientRegistrationResponse<
        CoreApplicationType,
        CoreClientAuthMethod,
        CoreClientMetadata,
        CoreGrantTypeWrapper,
        CoreJweContentEncryptionAlgorithm,
        CoreJweKeyManagementAlgorithm,
        CoreJwsSigningAlgorithm,
        CoreJsonWebKeyType,
        CoreJsonWebKeyUse,
        CoreJsonWebKey,
        CoreResponseType,
        CoreSubjectIdentifierType
    >;

pub type CoreIdToken =
    IdToken<
        EmptyAdditionalClaims,
        CoreGenderClaim,
        CoreJweContentEncryptionAlgorithm,
        CoreJwsSigningAlgorithm,
        CoreJsonWebKeyType
    >;

pub type CoreIdTokenClaims = IdTokenClaims<EmptyAdditionalClaims, CoreGenderClaim>;

pub type CoreIdTokenVerifier<'a> =
    IdTokenVerifier<
        'a,
        CoreJwsSigningAlgorithm,
        CoreJsonWebKeyType,
        CoreJsonWebKeyUse,
        CoreJsonWebKey
    >;

pub type CoreJsonWebKeySet =
    JsonWebKeySet<
        CoreJwsSigningAlgorithm,
        CoreJsonWebKeyType,
        CoreJsonWebKeyUse,
        CoreJsonWebKey
    >;

pub type CoreProviderMetadata =
    Discovery10ProviderMetadata<
        CoreAuthDisplay,
        CoreClientAuthMethod,
        CoreClaimName,
        CoreClaimType,
        CoreGrantTypeWrapper,
        CoreJweContentEncryptionAlgorithm,
        CoreJweKeyManagementAlgorithm,
        CoreJwsSigningAlgorithm,
        CoreJsonWebKeyType,
        CoreResponseMode,
        CoreResponseType,
        CoreSubjectIdentifierType,
    >;

pub type CoreUserInfoClaims = UserInfoClaims<EmptyAdditionalClaims, CoreGenderClaim>;
pub type CoreUserInfoVerifier<'a> =
    UserInfoVerifier<
        'a,
        CoreJweContentEncryptionAlgorithm,
        CoreJwsSigningAlgorithm,
        CoreJsonWebKeyType,
        CoreJsonWebKeyUse,
        CoreJsonWebKey,
    >;

///
/// Kind of client application.
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

impl AuthDisplay for CoreAuthDisplay {
    fn to_str(&self) -> &str {
        match *self {
            CoreAuthDisplay::Page => "page",
            CoreAuthDisplay::Popup => "popup",
            CoreAuthDisplay::Touch => "touch",
            CoreAuthDisplay::Wap => "wap",
        }
    }
}

impl Display for CoreAuthDisplay {
    fn fmt(&self, f: &mut Formatter) -> Result<(), FormatterError> {
        write!(f, "{}", self.to_str())
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

impl AuthPrompt for CoreAuthPrompt {
    fn to_str(&self) -> &str {
        match *self {
            CoreAuthPrompt::None => "none",
            CoreAuthPrompt::Login => "login",
            CoreAuthPrompt::Consent => "consent",
            CoreAuthPrompt::SelectAccount => "select_account",
        }
    }
}
impl AsRef<str> for CoreAuthPrompt {
    fn as_ref(&self) -> &str { self.to_str() }
}

impl Display for CoreAuthPrompt {
    fn fmt(&self, f: &mut Formatter) -> Result<(), FormatterError> {
        write!(f, "{}", self.to_str())
    }
}

new_type![
    #[derive(Deserialize, Serialize)]
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
    Distributed
}
impl ClaimType for CoreClaimType {}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CoreClientAuthMethod {
    ClientSecretPost,
    ClientSecretBasic,
    ClientSecretJwt,
    PrivateKeyJwt,
}
impl ClientAuthMethod for CoreClientAuthMethod {}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CoreGenderClaim{
    Female,
    Male,
}
impl GenderClaim for CoreGenderClaim {}

// This `enum` intentionally does not implement the `GrantType` trait. Instead, the
// `CoreGrantTypeWrapper` type should be used to ensure proper serialization/deserialization
// of extensions.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CoreGrantType {
    AuthorizationCode,
    ClientCredentials,
    Implicit,
    Password,
    RefreshToken,
    #[serde(skip_deserializing)]
    #[serde(skip_serializing)]
    Extension(String),
}
impl From<CoreGrantTypeWrapper> for CoreGrantType {
    fn from(grant_type_wrapper: CoreGrantTypeWrapper) -> Self {
        grant_type_wrapper.0
    }
}
impl PartialEq<CoreGrantTypeWrapper> for CoreGrantType {
    fn eq(&self, rhs: &CoreGrantTypeWrapper) -> bool {
        *self == rhs.0
    }
}

new_type![
    #[derive(Deserialize, Serialize)]
    CoreGrantTypeWrapper(
        #[serde(with = "serde_core_grant_type")]
        CoreGrantType
    )
];
impl GrantType for CoreGrantTypeWrapper {}
impl From<CoreGrantType> for CoreGrantTypeWrapper {
    fn from(grant_type: CoreGrantType) -> Self {
        CoreGrantTypeWrapper(grant_type)
    }
}
impl PartialEq<CoreGrantType> for CoreGrantTypeWrapper {
    fn eq(&self, rhs: &CoreGrantType) -> bool {
        self.0 == *rhs
    }
}

pub mod serde_core_grant_type {
    use oauth2::helpers::variant_name;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use serde::de::Error;
    use serde_json::{from_value, Value};

    use super::CoreGrantType;

    pub fn deserialize<'de, D>(
        deserializer: D
    ) -> Result<CoreGrantType, D::Error>
    where D: Deserializer<'de> {
        let value: Value = Deserialize::deserialize(deserializer)?;

        match from_value::<CoreGrantType>(value.clone()) {
            Ok(val) => Ok(val),
            Err(_) => {
                let extension: String = from_value(value).map_err(D::Error::custom)?;
                Ok(CoreGrantType::Extension(extension))
            }
        }
    }

    pub fn serialize<S>(
        grant_type: &CoreGrantType,
        serializer: S
    ) -> Result<S::Ok, S::Error>
    where S: Serializer {
        match *grant_type {
            CoreGrantType::Extension(ref extension) => serializer.serialize_str(extension),
            ref variant => variant_name(variant).serialize(serializer)
        }
    }
}

///
/// Core JWE encryption algorithms.
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
impl JweContentEncryptionAlgorithm for CoreJweContentEncryptionAlgorithm {}

///
/// Core JWE key management algorithms.
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

// Other than the 'kty' (key type) parameter, which must be present in all JWKs, Section 4 of RFC
// 7517 states that "member names used for representing key parameters for different keys types
// need not be distinct." Therefore, it's possible that future or non-standard key types will supply
// some of the following parameters but with different types, causing deserialization to fail. To
// support such key types, we'll need to define a new impl for JsonWebKey. Deserializing the new
// impl would probably need to involve first deserializing the raw values to access the 'kty'
// parameter, and then deserializing the fields and types appropriate for that key type.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct CoreJsonWebKey {
    kty: CoreJsonWebKeyType,
    #[serde(rename = "use")]
    use_: Option<CoreJsonWebKeyUse>,
    kid: Option<JsonWebKeyId>,

    // FIXME: if this doesn't successfully decode as base64url-encoded, make it None
    // also FIXME: define a custom deserializer for this that takes a string, parses it as
    // base64url, and either fails or sets it to none if that fails (check the spec)
    n: Option<Base64UrlEncodedBytes>,
    e: Option<Base64UrlEncodedBytes>,

    // Used for symmetric keys, which we only generate internally from the client secret; these
    // are never part of the JWK set.
    k: Option<Base64UrlEncodedBytes>,
}
impl JsonWebKey<CoreJwsSigningAlgorithm, CoreJsonWebKeyType, CoreJsonWebKeyUse> for CoreJsonWebKey {
    fn key_id(&self) -> Option<&JsonWebKeyId> { self.kid.as_ref() }
    fn key_type(&self) -> &CoreJsonWebKeyType { &self.kty }
    fn key_use(&self) -> Option<&CoreJsonWebKeyUse> { self.use_.as_ref() }

    fn new_symmetric(key: Vec<u8>) -> Self {
        return Self {
            kty: CoreJsonWebKeyType::Symmetric,
            use_: None,
            kid: None,
            n: None,
            e: None,
            k: Some(Base64UrlEncodedBytes::new(key)),
        }
    }

    fn verify_signature(
        &self,
        signature_alg: &CoreJwsSigningAlgorithm,
        msg: &str,
        signature: &[u8]
    ) -> Result<(), SignatureVerificationError> {
        if let Some(key_use) = self.key_use() {
            if *key_use != CoreJsonWebKeyUse::Signature {
                return Err(
                    SignatureVerificationError::InvalidKey(
                        "key usage not permitted for digital signatures".to_string()
                    )
                )
            }
        }

        let key_type = signature_alg.key_type().map_err(SignatureVerificationError::Other)?;
        if *self.key_type() != key_type {
            return Err(
                SignatureVerificationError::InvalidKey(
                    "key type does not match signature algorithm".to_string()
                )
            )
        }

        // FIXME: add test cases for each of these
        match *signature_alg {
            CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256 =>
                crypto::verify_rsa_signature(
                    self,
                    &ring_signature::RSA_PKCS1_2048_8192_SHA256,
                    msg,
                    signature
                ),
            CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha384 =>
                crypto::verify_rsa_signature(
                    self,
                    &ring_signature::RSA_PKCS1_2048_8192_SHA384,
                    msg,signature
                ),
            CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha512 =>
                crypto::verify_rsa_signature(
                    self,
                    &ring_signature::RSA_PKCS1_2048_8192_SHA512,
                    msg,
                    signature
                ),
            CoreJwsSigningAlgorithm::RsaSsaPssSha256 =>
                crypto::verify_rsa_signature(
                    self,
                    &ring_signature::RSA_PSS_2048_8192_SHA256,
                    msg,
                    signature
                ),
            CoreJwsSigningAlgorithm::RsaSsaPssSha384 =>
                crypto::verify_rsa_signature(
                    self,
                    &ring_signature::RSA_PSS_2048_8192_SHA384,
                    msg,
                    signature
                ),
            CoreJwsSigningAlgorithm::RsaSsaPssSha512 =>
                crypto::verify_rsa_signature(
                    self,
                    &ring_signature::RSA_PSS_2048_8192_SHA512,
                    msg,
                    signature
                ),
            CoreJwsSigningAlgorithm::HmacSha256 =>
                crypto::verify_hmac(self, &digest::SHA256, msg, signature),
            CoreJwsSigningAlgorithm::HmacSha384 =>
                crypto::verify_hmac(self, &digest::SHA384, msg, signature),
            CoreJwsSigningAlgorithm::HmacSha512 =>
                crypto::verify_hmac(self, &digest::SHA512, msg, signature),
            ref other => Err(
                SignatureVerificationError::UnsupportedAlg(variant_name(other).to_string())
            )
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

///
/// Core JWS signing algorithms.
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
impl<> JwsSigningAlgorithm<CoreJsonWebKeyType> for CoreJwsSigningAlgorithm {
    fn key_type(&self) -> Result<CoreJsonWebKeyType, String> {
        Ok(
            match *self {
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
                    return Err(
                        "signature algorithm `none` has no corresponding key type".to_string()
                    );
                },
            }
        )
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
    fn as_ref(&self) -> &str { variant_name(self) }
}

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
    Public
}
impl SubjectIdentifierType for CoreSubjectIdentifierType {}

// This module is currently not part of the public API. If a use case arises for exposing it
// publicly, we'll probably need to think through this API some more.
mod crypto {
    use ring::digest;
    use ring::hmac;
    use ring::signature as ring_signature;
    use untrusted::Input;

    use super::super::{
        JsonWebKey,
        SignatureVerificationError
    };
    use super::{
        CoreJsonWebKey,
        CoreJsonWebKeyType,
    };

    pub fn verify_hmac(
        key: &CoreJsonWebKey,
        digest_alg: &'static digest::Algorithm,
        msg: &str,
        signature: &[u8]
    ) -> Result<(), SignatureVerificationError> {
        if let Some(k) = key.k.as_ref() {
            let verification_key = hmac::VerificationKey::new(digest_alg, k);
            hmac::verify(&verification_key, msg.as_bytes(), signature)
                .map_err(|_| SignatureVerificationError::CryptoError("bad HMAC".to_string()))
        } else {
            Err(
                SignatureVerificationError::InvalidKey("Symmetric key `k` is missing".to_string())
            )
        }
    }

    pub fn verify_rsa_signature(
        key: &CoreJsonWebKey,
        params: &ring_signature::RSAParameters,
        msg: &str,
        signature: &[u8]
    ) -> Result<(), SignatureVerificationError> {
        if *key.key_type() != CoreJsonWebKeyType::RSA {
            return Err(SignatureVerificationError::InvalidKey("RSA key required".to_string()))
        }

        if let Some(n) = key.n.as_ref() {
            if let Some(e) = key.e.as_ref() {
                ring_signature::primitive::verify_rsa(
                    params,
                    (Input::from(n), Input::from(e)),
                    Input::from(msg.as_bytes()),
                    Input::from(signature),
                )
                    .map_err(|_|
                        SignatureVerificationError::CryptoError(
                            "bad signature".to_string()
                        )
                    )
            } else {
                Err(
                    SignatureVerificationError::InvalidKey(
                        "RSA exponent `e` is missing".to_string()
                    )
                )
            }
        } else {
            Err(
                SignatureVerificationError::InvalidKey(
                    "RSA modulus `n` is missing".to_string()
                )
            )
        }
    }
}
