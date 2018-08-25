use std::collections::HashMap;
use std::marker::PhantomData;

use chrono::{DateTime, Utc};
use oauth2::ClientId;

use super::claims::StandardClaimsImpl;
use super::jwt::JsonWebTokenJsonPayloadDeserializer;
use super::types::helpers::{deserialize_string_or_vec, seconds_to_utc};
use super::types::Seconds;
use super::{
    AccessTokenHash, AdditionalClaims, AddressClaim, Audience, AudiencesClaim,
    AuthenticationContextClass, AuthenticationMethodReference, AuthorizationCodeHash,
    ClaimsVerificationError, EndUserBirthday, EndUserEmail, EndUserGivenName, EndUserMiddleName,
    EndUserName, EndUserNickname, EndUserPhoneNumber, EndUserPictureUrl, EndUserProfileUrl,
    EndUserTimezone, EndUserUsername, EndUserWebsiteUrl, ExtraTokenFields, GenderClaim,
    IdTokenVerifier, IssuerClaim, IssuerUrl, JsonWebKey, JsonWebKeyType, JsonWebKeyUse,
    JsonWebToken, JweContentEncryptionAlgorithm, JwsSigningAlgorithm, LanguageTag, Nonce,
    StandardClaims, SubjectIdentifier,
};

// This wrapper layer exists instead of directly verifying the JWT and returning the claims so that
// we can pass it around and easily access a serialized JWT representation of it (e.g., for passing
// to the authorization endpoint as an id_token_hint).
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct IdToken<
    AC: AdditionalClaims,
    GC: GenderClaim,
    JE: JweContentEncryptionAlgorithm,
    JS: JwsSigningAlgorithm<JT>,
    JT: JsonWebKeyType,
>(
    #[serde(bound = "AC: AdditionalClaims")]
    JsonWebToken<IdTokenClaims<AC, GC>, JE, JS, JT, JsonWebTokenJsonPayloadDeserializer>,
);
impl<AC, GC, JE, JS, JT> IdToken<AC, GC, JE, JS, JT>
where
    AC: AdditionalClaims,
    GC: GenderClaim,
    JE: JweContentEncryptionAlgorithm,
    JS: JwsSigningAlgorithm<JT>,
    JT: JsonWebKeyType,
{
    pub fn claims<JU, K>(
        &self,
        verifier: &IdTokenVerifier<JS, JT, JU, K>,
        nonce: &Nonce,
    ) -> Result<&IdTokenClaims<AC, GC>, ClaimsVerificationError>
    where
        JU: JsonWebKeyUse,
        K: JsonWebKey<JS, JT, JU>,
    {
        verifier.verified_claims(&self.0, Some(nonce))
    }
}

// FIXME: document at the module level that we do not support aggregated or distributed claims,
// which are OPTIONAL in the spec:
// http://openid.net/specs/openid-connect-core-1_0.html#AggregatedDistributedClaims
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct IdTokenClaims<AC, GC>
where
    AC: AdditionalClaims,
    GC: GenderClaim,
{
    iss: IssuerUrl,
    #[serde(deserialize_with = "deserialize_string_or_vec")]
    aud: Vec<Audience>,
    exp: Seconds,
    iat: Seconds,
    auth_time: Option<Seconds>,
    nonce: Option<Nonce>,
    acr: Option<AuthenticationContextClass>,
    amr: Option<Vec<AuthenticationMethodReference>>,
    azp: Option<ClientId>,
    at_hash: Option<AccessTokenHash>,
    c_hash: Option<AuthorizationCodeHash>,

    #[serde(bound = "GC: GenderClaim")]
    #[serde(flatten)]
    standard_claims: StandardClaimsImpl<GC>,

    #[serde(bound = "AC: AdditionalClaims")]
    #[serde(flatten)]
    additional_claims: AC,
}
// FIXME: see what other structs should have friendlier trait interfaces like this one
impl<AC, GC> IdTokenClaims<AC, GC>
where
    AC: AdditionalClaims,
    GC: GenderClaim,
{
    pub fn issuer(&self) -> &IssuerUrl {
        &self.iss
    }
    pub fn audiences(&self) -> &Vec<Audience> {
        &self.aud
    }
    pub fn expiration(&self) -> Result<DateTime<Utc>, ()> {
        seconds_to_utc(&self.exp)
    }
    pub fn issue_time(&self) -> Result<DateTime<Utc>, ()> {
        seconds_to_utc(&self.iat)
    }
    pub fn auth_time(&self) -> Option<Result<DateTime<Utc>, ()>> {
        self.auth_time.as_ref().map(seconds_to_utc)
    }
    pub fn nonce(&self) -> Option<&Nonce> {
        self.nonce.as_ref()
    }
    pub fn auth_context_ref(&self) -> Option<&AuthenticationContextClass> {
        self.acr.as_ref()
    }
    pub fn auth_methods_refs(&self) -> Option<&Vec<AuthenticationMethodReference>> {
        self.amr.as_ref()
    }
    pub fn authorized_party(&self) -> Option<&ClientId> {
        self.azp.as_ref()
    }
    pub fn access_token_hash(&self) -> Option<&AccessTokenHash> {
        self.at_hash.as_ref()
    }
    pub fn code_hash(&self) -> Option<&AuthorizationCodeHash> {
        self.c_hash.as_ref()
    }

    pub fn additional_claims(&self) -> &AC {
        &self.additional_claims
    }
}
impl<AC, GC> StandardClaims<GC> for IdTokenClaims<AC, GC>
where
    AC: AdditionalClaims,
    GC: GenderClaim,
{
    field_getters![
        self [self.standard_claims] {
            sub[&SubjectIdentifier],
            name[Option<&HashMap<Option<LanguageTag>, EndUserName>>],
            given_name[Option<&HashMap<Option<LanguageTag>, EndUserGivenName>>],
            family_name[Option<&HashMap<Option<LanguageTag>, EndUserGivenName>>],
            middle_name[Option<&HashMap<Option<LanguageTag>, EndUserMiddleName>>],
            nickname[Option<&HashMap<Option<LanguageTag>, EndUserNickname>>],
            preferred_username[Option<&EndUserUsername>],
            profile[Option<&HashMap<Option<LanguageTag>, EndUserProfileUrl>>],
            picture[Option<&HashMap<Option<LanguageTag>, EndUserPictureUrl>>],
            website[Option<&HashMap<Option<LanguageTag>, EndUserWebsiteUrl>>],
            email[Option<&EndUserEmail>],
            email_verified[Option<bool>],
            gender[Option<&GC>],
            birthday[Option<&EndUserBirthday>],
            zoneinfo[Option<&EndUserTimezone>],
            locale[Option<&LanguageTag>],
            phone_number[Option<&EndUserPhoneNumber>],
            phone_number_verified[Option<bool>],
            address[Option<&AddressClaim>],
            updated_at[Option<Result<DateTime<Utc>, ()>> {
                self.standard_claims.updated_at.as_ref().map(seconds_to_utc)
            }],
        }
    ];
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

///
/// OpenID Connect authorization token.
///
/// The fields in this struct are defined in
/// [Section 3.1.3.3](http://openid.net/specs/openid-connect-core-1_0.html#TokenResponse).
///
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct IdTokenFields<AC, GC, JE, JS, JT>
where
    AC: AdditionalClaims,
    GC: GenderClaim,
    JE: JweContentEncryptionAlgorithm,
    JS: JwsSigningAlgorithm<JT>,
    JT: JsonWebKeyType,
{
    #[serde(bound = "AC: AdditionalClaims")]
    id_token: IdToken<AC, GC, JE, JS, JT>,
    #[serde(skip)]
    _phantom_jt: PhantomData<JT>,
}
impl<AC, GC, JE, JS, JT> IdTokenFields<AC, GC, JE, JS, JT>
where
    AC: AdditionalClaims,
    GC: GenderClaim,
    JE: JweContentEncryptionAlgorithm,
    JS: JwsSigningAlgorithm<JT>,
    JT: JsonWebKeyType,
{
    pub fn id_token(&self) -> &IdToken<AC, GC, JE, JS, JT> {
        &self.id_token
    }
    // FIXME: add extra_fields here to enable further extensibility by clients
}
impl<AC, GC, JE, JS, JT> ExtraTokenFields for IdTokenFields<AC, GC, JE, JS, JT>
where
    AC: AdditionalClaims,
    GC: GenderClaim,
    JE: JweContentEncryptionAlgorithm,
    JS: JwsSigningAlgorithm<JT>,
    JT: JsonWebKeyType,
{}
