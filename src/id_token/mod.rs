use crate::helpers::{
    deserialize_string_or_vec, serde_utc_seconds, serde_utc_seconds_opt, FilteredFlatten,
};
use crate::jwt::JsonWebTokenAccess;
use crate::jwt::{JsonWebTokenError, JsonWebTokenJsonPayloadSerde};
use crate::types::jwk::{JsonWebKeyType, JwsSigningAlgorithm};
use crate::{
    AccessToken, AccessTokenHash, AdditionalClaims, AddressClaim, Audience, AudiencesClaim,
    AuthenticationContextClass, AuthenticationMethodReference, AuthorizationCode,
    AuthorizationCodeHash, ClaimsVerificationError, ClientId, EndUserBirthday, EndUserEmail,
    EndUserFamilyName, EndUserGivenName, EndUserMiddleName, EndUserName, EndUserNickname,
    EndUserPhoneNumber, EndUserPictureUrl, EndUserProfileUrl, EndUserTimezone, EndUserUsername,
    EndUserWebsiteUrl, ExtraTokenFields, GenderClaim, IdTokenVerifier, IssuerClaim, IssuerUrl,
    JsonWebKey, JsonWebKeyUse, JsonWebToken, JsonWebTokenAlgorithm, JweContentEncryptionAlgorithm,
    LanguageTag, LocalizedClaim, Nonce, NonceVerifier, PrivateSigningKey, SigningError,
    StandardClaims, SubjectIdentifier,
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use std::fmt::Debug;
use std::marker::PhantomData;
use std::str::FromStr;

#[cfg(test)]
mod tests;

// This wrapper layer exists instead of directly verifying the JWT and returning the claims so that
// we can pass it around and easily access a serialized JWT representation of it (e.g., for passing
// to the authorization endpoint as an id_token_hint).
/// OpenID Connect ID token.
#[cfg_attr(
    any(test, feature = "timing-resistant-secret-traits"),
    derive(PartialEq)
)]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IdToken<
    AC: AdditionalClaims,
    GC: GenderClaim,
    JE: JweContentEncryptionAlgorithm<JT>,
    JS: JwsSigningAlgorithm<JT>,
    JT: JsonWebKeyType,
>(
    #[serde(bound = "AC: AdditionalClaims")]
    JsonWebToken<JE, JS, JT, IdTokenClaims<AC, GC>, JsonWebTokenJsonPayloadSerde>,
);

impl<AC, GC, JE, JS, JT> FromStr for IdToken<AC, GC, JE, JS, JT>
where
    AC: AdditionalClaims,
    GC: GenderClaim,
    JE: JweContentEncryptionAlgorithm<JT>,
    JS: JwsSigningAlgorithm<JT>,
    JT: JsonWebKeyType,
{
    type Err = serde_json::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_value(Value::String(s.to_string()))
    }
}

impl<AC, GC, JE, JS, JT> IdToken<AC, GC, JE, JS, JT>
where
    AC: AdditionalClaims,
    GC: GenderClaim,
    JE: JweContentEncryptionAlgorithm<JT>,
    JS: JwsSigningAlgorithm<JT>,
    JT: JsonWebKeyType,
{
    /// Initializes an ID token with the specified claims, signed using the given signing key and
    /// algorithm.
    ///
    /// If an `access_token` and/or `code` are provided, this method sets the `at_hash` and/or
    /// `c_hash` claims using the given signing algorithm, respectively. Otherwise, those claims are
    /// unchanged from the values specified in `claims`.
    pub fn new<JU, K, S>(
        claims: IdTokenClaims<AC, GC>,
        signing_key: &S,
        alg: JS,
        access_token: Option<&AccessToken>,
        code: Option<&AuthorizationCode>,
    ) -> Result<Self, JsonWebTokenError>
    where
        JU: JsonWebKeyUse,
        K: JsonWebKey<JS, JT, JU>,
        S: PrivateSigningKey<JS, JT, JU, K>,
    {
        let at_hash = access_token
            .map(|at| {
                AccessTokenHash::from_token(at, &alg).map_err(JsonWebTokenError::SigningError)
            })
            .transpose()?
            .or_else(|| claims.access_token_hash.clone());
        let c_hash = code
            .map(|c| {
                AuthorizationCodeHash::from_code(c, &alg).map_err(JsonWebTokenError::SigningError)
            })
            .transpose()?
            .or_else(|| claims.code_hash.clone());

        JsonWebToken::new(
            IdTokenClaims {
                access_token_hash: at_hash,
                code_hash: c_hash,
                ..claims
            },
            signing_key,
            &alg,
        )
        .map(Self)
    }

    /// Verifies and returns a reference to the ID token claims.
    pub fn claims<'a, JU, K, N>(
        &'a self,
        verifier: &IdTokenVerifier<JS, JT, JU, K>,
        nonce_verifier: N,
    ) -> Result<&'a IdTokenClaims<AC, GC>, ClaimsVerificationError>
    where
        JU: JsonWebKeyUse,
        K: JsonWebKey<JS, JT, JU>,
        N: NonceVerifier,
    {
        verifier.verified_claims(&self.0, nonce_verifier)
    }

    /// Verifies and returns the ID token claims.
    pub fn into_claims<JU, K, N>(
        self,
        verifier: &IdTokenVerifier<JS, JT, JU, K>,
        nonce_verifier: N,
    ) -> Result<IdTokenClaims<AC, GC>, ClaimsVerificationError>
    where
        JU: JsonWebKeyUse,
        K: JsonWebKey<JS, JT, JU>,
        N: NonceVerifier,
    {
        verifier.verified_claims_owned(self.0, nonce_verifier)
    }

    /// Returns the [`JwsSigningAlgorithm`] used to sign this ID token.
    ///
    /// This function returns an error if the token is unsigned or utilizes JSON Web Encryption
    /// (JWE).
    pub fn signing_alg(&self) -> Result<JS, SigningError> {
        match self.0.unverified_header().alg {
            JsonWebTokenAlgorithm::Signature(ref signing_alg, _) => Ok(signing_alg.clone()),
            JsonWebTokenAlgorithm::Encryption(ref other) => Err(SigningError::UnsupportedAlg(
                serde_plain::to_string(other).unwrap_or_else(|err| {
                    panic!(
                        "encryption alg {:?} failed to serialize to a string: {}",
                        other, err
                    )
                }),
            )),
            JsonWebTokenAlgorithm::None => Err(SigningError::UnsupportedAlg("none".to_string())),
        }
    }
}
impl<AC, GC, JE, JS, JT> ToString for IdToken<AC, GC, JE, JS, JT>
where
    AC: AdditionalClaims,
    GC: GenderClaim,
    JE: JweContentEncryptionAlgorithm<JT>,
    JS: JwsSigningAlgorithm<JT>,
    JT: JsonWebKeyType,
{
    fn to_string(&self) -> String {
        serde_json::to_value(self)
            // This should never arise, since we're just asking serde_json to serialize the
            // signing input concatenated with the signature, both of which are precomputed.
            .expect("ID token serialization failed")
            .as_str()
            // This should also never arise, since our IdToken serializer always calls serialize_str
            .expect("ID token serializer did not produce a str")
            .to_owned()
    }
}

/// OpenID Connect ID token claims.
#[cfg_attr(
    any(test, feature = "timing-resistant-secret-traits"),
    derive(PartialEq)
)]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IdTokenClaims<AC, GC>
where
    AC: AdditionalClaims,
    GC: GenderClaim,
{
    #[serde(rename = "iss")]
    issuer: IssuerUrl,
    // We always serialize as an array, which is valid according to the spec. This sets the
    // 'default' attribute to be compatible with non-spec compliant OIDC providers that omit this
    // field.
    #[serde(
        default,
        rename = "aud",
        deserialize_with = "deserialize_string_or_vec"
    )]
    audiences: Vec<Audience>,
    #[serde(rename = "exp", with = "serde_utc_seconds")]
    expiration: DateTime<Utc>,
    #[serde(rename = "iat", with = "serde_utc_seconds")]
    issue_time: DateTime<Utc>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "serde_utc_seconds_opt"
    )]
    auth_time: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<Nonce>,
    #[serde(rename = "acr", skip_serializing_if = "Option::is_none")]
    auth_context_ref: Option<AuthenticationContextClass>,
    #[serde(rename = "amr", skip_serializing_if = "Option::is_none")]
    auth_method_refs: Option<Vec<AuthenticationMethodReference>>,
    #[serde(rename = "azp", skip_serializing_if = "Option::is_none")]
    authorized_party: Option<ClientId>,
    #[serde(rename = "at_hash", skip_serializing_if = "Option::is_none")]
    access_token_hash: Option<AccessTokenHash>,
    #[serde(rename = "c_hash", skip_serializing_if = "Option::is_none")]
    code_hash: Option<AuthorizationCodeHash>,

    #[serde(bound = "GC: GenderClaim")]
    #[serde(flatten)]
    standard_claims: StandardClaims<GC>,

    #[serde(bound = "AC: AdditionalClaims")]
    #[serde(flatten)]
    additional_claims: FilteredFlatten<StandardClaims<GC>, AC>,
}
impl<AC, GC> IdTokenClaims<AC, GC>
where
    AC: AdditionalClaims,
    GC: GenderClaim,
{
    /// Initializes new ID token claims.
    pub fn new(
        issuer: IssuerUrl,
        audiences: Vec<Audience>,
        expiration: DateTime<Utc>,
        issue_time: DateTime<Utc>,
        standard_claims: StandardClaims<GC>,
        additional_claims: AC,
    ) -> Self {
        Self {
            issuer,
            audiences,
            expiration,
            issue_time,
            auth_time: None,
            nonce: None,
            auth_context_ref: None,
            auth_method_refs: None,
            authorized_party: None,
            access_token_hash: None,
            code_hash: None,
            standard_claims,
            additional_claims: additional_claims.into(),
        }
    }

    field_getters_setters![
        pub self [self] ["claim"] {
            set_issuer -> issuer[IssuerUrl] ["iss"],
            set_audiences -> audiences[Vec<Audience>] ["aud"],
            set_expiration -> expiration[DateTime<Utc>] ["exp"],
            set_issue_time -> issue_time[DateTime<Utc>] ["iat"],
            set_auth_time -> auth_time[Option<DateTime<Utc>>],
            set_nonce -> nonce[Option<Nonce>],
            set_auth_context_ref -> auth_context_ref[Option<AuthenticationContextClass>] ["acr"],
            set_auth_method_refs -> auth_method_refs[Option<Vec<AuthenticationMethodReference>>] ["amr"],
            set_authorized_party -> authorized_party[Option<ClientId>] ["azp"],
            set_access_token_hash -> access_token_hash[Option<AccessTokenHash>] ["at_hash"],
            set_code_hash -> code_hash[Option<AuthorizationCodeHash>] ["c_hash"],
        }
    ];

    /// Returns the `sub` claim.
    pub fn subject(&self) -> &SubjectIdentifier {
        &self.standard_claims.sub
    }
    /// Sets the `sub` claim.
    pub fn set_subject(mut self, subject: SubjectIdentifier) -> Self {
        self.standard_claims.sub = subject;
        self
    }

    field_getters_setters![
        pub self [self.standard_claims] ["claim"] {
            set_name -> name[Option<LocalizedClaim<EndUserName>>],
            set_given_name -> given_name[Option<LocalizedClaim<EndUserGivenName>>],
            set_family_name ->
                family_name[Option<LocalizedClaim<EndUserFamilyName>>],
            set_middle_name ->
                middle_name[Option<LocalizedClaim<EndUserMiddleName>>],
            set_nickname -> nickname[Option<LocalizedClaim<EndUserNickname>>],
            set_preferred_username -> preferred_username[Option<EndUserUsername>],
            set_profile -> profile[Option<LocalizedClaim<EndUserProfileUrl>>],
            set_picture -> picture[Option<LocalizedClaim<EndUserPictureUrl>>],
            set_website -> website[Option<LocalizedClaim<EndUserWebsiteUrl>>],
            set_email -> email[Option<EndUserEmail>],
            set_email_verified -> email_verified[Option<bool>],
            set_gender -> gender[Option<GC>],
            set_birthday -> birthday[Option<EndUserBirthday>],
            set_birthdate -> birthdate[Option<EndUserBirthday>],
            set_zoneinfo -> zoneinfo[Option<EndUserTimezone>],
            set_locale -> locale[Option<LanguageTag>],
            set_phone_number -> phone_number[Option<EndUserPhoneNumber>],
            set_phone_number_verified -> phone_number_verified[Option<bool>],
            set_address -> address[Option<AddressClaim>],
            set_updated_at -> updated_at[Option<DateTime<Utc>>],
        }
    ];

    /// Returns additional ID token claims.
    pub fn additional_claims(&self) -> &AC {
        self.additional_claims.as_ref()
    }
    /// Returns mutable additional ID token claims.
    pub fn additional_claims_mut(&mut self) -> &mut AC {
        self.additional_claims.as_mut()
    }
}
impl<AC, GC> AudiencesClaim for IdTokenClaims<AC, GC>
where
    AC: AdditionalClaims,
    GC: GenderClaim,
{
    fn audiences(&self) -> Option<&Vec<Audience>> {
        Some(IdTokenClaims::audiences(self))
    }
}
impl<'a, AC, GC> AudiencesClaim for &'a IdTokenClaims<AC, GC>
where
    AC: AdditionalClaims,
    GC: GenderClaim,
{
    fn audiences(&self) -> Option<&Vec<Audience>> {
        Some(IdTokenClaims::audiences(self))
    }
}
impl<AC, GC> IssuerClaim for IdTokenClaims<AC, GC>
where
    AC: AdditionalClaims,
    GC: GenderClaim,
{
    fn issuer(&self) -> Option<&IssuerUrl> {
        Some(IdTokenClaims::issuer(self))
    }
}
impl<'a, AC, GC> IssuerClaim for &'a IdTokenClaims<AC, GC>
where
    AC: AdditionalClaims,
    GC: GenderClaim,
{
    fn issuer(&self) -> Option<&IssuerUrl> {
        Some(IdTokenClaims::issuer(self))
    }
}

/// Extends the base OAuth2 token response with an ID token.
#[cfg_attr(
    any(test, feature = "timing-resistant-secret-traits"),
    derive(PartialEq)
)]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IdTokenFields<AC, EF, GC, JE, JS, JT>
where
    AC: AdditionalClaims,
    EF: ExtraTokenFields,
    GC: GenderClaim,
    JE: JweContentEncryptionAlgorithm<JT>,
    JS: JwsSigningAlgorithm<JT>,
    JT: JsonWebKeyType,
{
    #[serde(bound = "AC: AdditionalClaims")]
    id_token: Option<IdToken<AC, GC, JE, JS, JT>>,
    #[serde(bound = "EF: ExtraTokenFields", flatten)]
    extra_fields: EF,
    #[serde(skip)]
    _phantom: PhantomData<JT>,
}
impl<AC, EF, GC, JE, JS, JT> IdTokenFields<AC, EF, GC, JE, JS, JT>
where
    AC: AdditionalClaims,
    EF: ExtraTokenFields,
    GC: GenderClaim,
    JE: JweContentEncryptionAlgorithm<JT>,
    JS: JwsSigningAlgorithm<JT>,
    JT: JsonWebKeyType,
{
    /// Initializes new ID token fields containing the specified [`IdToken`] and extra fields.
    pub fn new(id_token: Option<IdToken<AC, GC, JE, JS, JT>>, extra_fields: EF) -> Self {
        Self {
            id_token,
            extra_fields,
            _phantom: PhantomData,
        }
    }

    /// Returns the [`IdToken`] contained in the OAuth2 token response.
    pub fn id_token(&self) -> Option<&IdToken<AC, GC, JE, JS, JT>> {
        self.id_token.as_ref()
    }
    /// Returns the extra fields contained in the OAuth2 token response.
    pub fn extra_fields(&self) -> &EF {
        &self.extra_fields
    }
}
impl<AC, EF, GC, JE, JS, JT> ExtraTokenFields for IdTokenFields<AC, EF, GC, JE, JS, JT>
where
    AC: AdditionalClaims,
    EF: ExtraTokenFields,
    GC: GenderClaim,
    JE: JweContentEncryptionAlgorithm<JT>,
    JS: JwsSigningAlgorithm<JT>,
    JT: JsonWebKeyType,
{
}
