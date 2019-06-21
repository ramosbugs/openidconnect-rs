use std::ops::Deref;
use std::str;

use chrono::{DateTime, Utc};
use failure::Fail;
use futures::{Future, IntoFuture};
use http_::header::{HeaderValue, ACCEPT, CONTENT_TYPE};
use http_::method::Method;
use http_::status::StatusCode;
use oauth2::AccessToken;
use serde_json;
use url::Url;

use super::http::{auth_bearer, MIME_TYPE_JSON, MIME_TYPE_JWT};
use super::jwt::{JsonWebTokenError, JsonWebTokenJsonPayloadSerde};
use super::types::helpers::deserialize_string_or_vec_opt;
use super::types::LocalizedClaim;
use super::verification::UserInfoVerifier;
use super::{
    AdditionalClaims, AddressClaim, Audience, AudiencesClaim, ClaimsVerificationError,
    EndUserBirthday, EndUserEmail, EndUserFamilyName, EndUserGivenName, EndUserMiddleName,
    EndUserName, EndUserNickname, EndUserPhoneNumber, EndUserPictureUrl, EndUserProfileUrl,
    EndUserTimezone, EndUserUsername, EndUserWebsiteUrl, GenderClaim, HttpRequest, HttpResponse,
    IssuerClaim, IssuerUrl, JsonWebKey, JsonWebKeyType, JsonWebKeyUse, JsonWebToken,
    JweContentEncryptionAlgorithm, JwsSigningAlgorithm, LanguageTag, PrivateSigningKey,
    StandardClaims, SubjectIdentifier,
};

pub struct UserInfoRequest<JE, JS, JT, JU, K>
where
    JE: JweContentEncryptionAlgorithm<JT>,
    JS: JwsSigningAlgorithm<JT>,
    JT: JsonWebKeyType,
    JU: JsonWebKeyUse,
    K: JsonWebKey<JS, JT, JU>,
{
    pub(super) url: UserInfoUrl,
    pub(super) access_token: AccessToken,
    pub(super) require_signed_response: bool,
    pub(super) signed_response_verifier: UserInfoVerifier<'static, JE, JS, JT, JU, K>,
}
impl<JE, JS, JT, JU, K> UserInfoRequest<JE, JS, JT, JU, K>
where
    JE: JweContentEncryptionAlgorithm<JT>,
    JS: JwsSigningAlgorithm<JT>,
    JT: JsonWebKeyType,
    JU: JsonWebKeyUse,
    K: JsonWebKey<JS, JT, JU>,
{
    pub fn request<AC, GC, HC, RE>(
        self,
        http_client: HC,
    ) -> Result<UserInfoClaims<AC, GC>, UserInfoError<RE>>
    where
        AC: AdditionalClaims,
        GC: GenderClaim,
        HC: FnOnce(HttpRequest) -> Result<HttpResponse, RE>,
        RE: Fail,
    {
        http_client(self.prepare_request())
            .map_err(UserInfoError::Request)
            .and_then(|http_response| self.user_info_response(http_response))
    }

    pub fn request_async<AC, C, F, GC, HC, RE>(
        self,
        http_client: C,
    ) -> impl Future<Item = UserInfoClaims<AC, GC>, Error = UserInfoError<RE>>
    where
        AC: AdditionalClaims,
        C: FnOnce(HttpRequest) -> F,
        F: Future<Item = HttpResponse, Error = RE>,
        GC: GenderClaim,
        HC: FnOnce(HttpRequest) -> Result<HttpResponse, RE>,
        RE: Fail,
    {
        http_client(self.prepare_request())
            .map_err(UserInfoError::Request)
            .and_then(|http_response| self.user_info_response(http_response).into_future())
    }

    fn prepare_request(&self) -> HttpRequest {
        let (auth_header, auth_value) = auth_bearer(&self.access_token);
        HttpRequest {
            url: self.url.url().clone(),
            method: Method::GET,
            headers: vec![
                (ACCEPT, HeaderValue::from_static(MIME_TYPE_JSON)),
                (auth_header, auth_value),
            ]
            .into_iter()
            .collect(),
            body: Vec::new(),
        }
    }

    fn user_info_response<AC, GC, RE>(
        self,
        http_response: HttpResponse,
    ) -> Result<UserInfoClaims<AC, GC>, UserInfoError<RE>>
    where
        AC: AdditionalClaims,
        GC: GenderClaim,
        RE: Fail,
    {
        if http_response.status_code != StatusCode::OK {
            return Err(UserInfoError::Response(
                http_response.status_code,
                http_response.body.clone(),
                "unexpected HTTP status code".to_string(),
            ));
        }

        match http_response
            .headers
            .get(CONTENT_TYPE)
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| HeaderValue::from_static(MIME_TYPE_JSON))
        {
            ref content_type if content_type == HeaderValue::from_static(MIME_TYPE_JSON) => {
                if self.require_signed_response {
                    return Err(UserInfoError::ClaimsVerification(
                        ClaimsVerificationError::NoSignature,
                    ));
                }
                UserInfoClaims::from_json(
                    &http_response.body,
                    self.signed_response_verifier.expected_subject(),
                )
            }
            ref content_type if content_type == HeaderValue::from_static(MIME_TYPE_JWT) => {
                let jwt_str = String::from_utf8(http_response.body).map_err(|_| {
                    UserInfoError::Other("response body has invalid UTF-8 encoding".to_string())
                })?;
                serde_json::from_value::<UserInfoJsonWebToken<AC, GC, JE, JS, JT>>(
                    serde_json::Value::String(jwt_str),
                )
                .map_err(UserInfoError::Parse)?
                .claims(&self.signed_response_verifier)
                .map_err(UserInfoError::ClaimsVerification)
            }
            ref content_type => Err(UserInfoError::Response(
                http_response.status_code,
                http_response.body,
                format!("unexpected response Content-Type: `{:?}`", content_type),
            )),
        }
    }

    pub fn require_signed_response(mut self, require_signed_response: bool) -> Self {
        self.require_signed_response = require_signed_response;
        self
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct UserInfoClaims<AC: AdditionalClaims, GC: GenderClaim>(UserInfoClaimsImpl<AC, GC>);
impl<AC, GC> UserInfoClaims<AC, GC>
where
    AC: AdditionalClaims,
    GC: GenderClaim,
{
    pub fn new(standard_claims: StandardClaims<GC>, additional_claims: AC) -> Self {
        Self(UserInfoClaimsImpl {
            issuer: None,
            audiences: None,
            standard_claims,
            additional_claims,
        })
    }

    pub fn from_json<RE>(
        user_info_json: &[u8],
        expected_subject: Option<&SubjectIdentifier>,
    ) -> Result<Self, UserInfoError<RE>>
    where
        RE: Fail,
    {
        let user_info = serde_json::from_slice::<UserInfoClaimsImpl<AC, GC>>(&user_info_json)
            .map_err(UserInfoError::Parse)?;

        // This is the only verification we need to do for JSON-based user info claims, so don't
        // bother with the complexity of a separate verifier object.
        if expected_subject
            .iter()
            .all(|expected_subject| user_info.standard_claims.sub == **expected_subject)
        {
            Ok(Self(user_info))
        } else {
            Err(UserInfoError::ClaimsVerification(
                ClaimsVerificationError::InvalidSubject(format!(
                    "expected `{}` (found `{}`)",
                    // This can only happen when expected_subject is not None.
                    expected_subject.unwrap().as_str(),
                    user_info.standard_claims.sub.as_str(),
                )),
            ))
        }
    }

    field_getters_setters![
        pub self [self.0] {
            set_issuer -> issuer[Option<IssuerUrl>],
            set_audiences -> audiences[Option<Vec<Audience>>],
        }
    ];

    pub fn subject(&self) -> &SubjectIdentifier {
        &self.0.standard_claims.sub
    }
    pub fn set_subject(&mut self, subject: SubjectIdentifier) {
        self.0.standard_claims.sub = subject
    }

    field_getters_setters![
        pub self [self.0.standard_claims] {
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
            set_zoneinfo -> zoneinfo[Option<EndUserTimezone>],
            set_locale -> locale[Option<LanguageTag>],
            set_phone_number -> phone_number[Option<EndUserPhoneNumber>],
            set_phone_number_verified -> phone_number_verified[Option<bool>],
            set_address -> address[Option<AddressClaim>],
            set_updated_at -> updated_at[Option<DateTime<Utc>>],
        }
    ];

    pub fn additional_claims(&self) -> &AC {
        &self.0.additional_claims
    }
    pub fn additional_claims_mut(&mut self) -> &mut AC {
        &mut self.0.additional_claims
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct UserInfoClaimsImpl<AC, GC>
where
    AC: AdditionalClaims,
    GC: GenderClaim,
{
    #[serde(rename = "iss", skip_serializing_if = "Option::is_none")]
    pub issuer: Option<IssuerUrl>,
    // We always serialize as an array, which is valid according to the spec.
    #[serde(
        default,
        rename = "aud",
        deserialize_with = "deserialize_string_or_vec_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub audiences: Option<Vec<Audience>>,

    #[serde(bound = "GC: GenderClaim", flatten)]
    pub standard_claims: StandardClaims<GC>,

    #[serde(bound = "AC: AdditionalClaims", flatten)]
    pub additional_claims: AC,
}
impl<AC, GC> AudiencesClaim for UserInfoClaimsImpl<AC, GC>
where
    AC: AdditionalClaims,
    GC: GenderClaim,
{
    fn audiences(&self) -> Option<&Vec<Audience>> {
        self.audiences.as_ref()
    }
}
impl<'a, AC, GC> AudiencesClaim for &'a UserInfoClaimsImpl<AC, GC>
where
    AC: AdditionalClaims,
    GC: GenderClaim,
{
    fn audiences(&self) -> Option<&Vec<Audience>> {
        self.audiences.as_ref()
    }
}

impl<AC, GC> IssuerClaim for UserInfoClaimsImpl<AC, GC>
where
    AC: AdditionalClaims,
    GC: GenderClaim,
{
    fn issuer(&self) -> Option<&IssuerUrl> {
        self.issuer.as_ref()
    }
}
impl<'a, AC, GC> IssuerClaim for &'a UserInfoClaimsImpl<AC, GC>
where
    AC: AdditionalClaims,
    GC: GenderClaim,
{
    fn issuer(&self) -> Option<&IssuerUrl> {
        self.issuer.as_ref()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UserInfoJsonWebToken<
    AC: AdditionalClaims,
    GC: GenderClaim,
    JE: JweContentEncryptionAlgorithm<JT>,
    JS: JwsSigningAlgorithm<JT>,
    JT: JsonWebKeyType,
>(
    #[serde(bound = "AC: AdditionalClaims")]
    JsonWebToken<JE, JS, JT, UserInfoClaimsImpl<AC, GC>, JsonWebTokenJsonPayloadSerde>,
);
impl<AC, GC, JE, JS, JT> UserInfoJsonWebToken<AC, GC, JE, JS, JT>
where
    AC: AdditionalClaims,
    GC: GenderClaim,
    JE: JweContentEncryptionAlgorithm<JT>,
    JS: JwsSigningAlgorithm<JT>,
    JT: JsonWebKeyType,
{
    pub fn new<JU, K, S>(
        claims: UserInfoClaims<AC, GC>,
        signing_key: &S,
        alg: JS,
    ) -> Result<Self, JsonWebTokenError>
    where
        JU: JsonWebKeyUse,
        K: JsonWebKey<JS, JT, JU>,
        S: PrivateSigningKey<JS, JT, JU, K>,
    {
        Ok(Self(JsonWebToken::new(claims.0, signing_key, &alg)?))
    }

    pub fn claims<JU, K>(
        self,
        verifier: &UserInfoVerifier<JE, JS, JT, JU, K>,
    ) -> Result<UserInfoClaims<AC, GC>, ClaimsVerificationError>
    where
        JU: JsonWebKeyUse,
        K: JsonWebKey<JS, JT, JU>,
    {
        Ok(UserInfoClaims(verifier.verified_claims(self.0)?))
    }
}

new_url_type![UserInfoUrl];

#[derive(Debug, Fail)]
pub enum UserInfoError<RE>
where
    RE: Fail,
{
    #[fail(display = "Failed to verify claims")]
    ClaimsVerification(#[cause] ClaimsVerificationError),
    #[fail(display = "Failed to parse server response")]
    Parse(#[cause] serde_json::Error),
    #[fail(display = "Request failed")]
    Request(#[cause] RE),
    #[fail(display = "Server returned invalid response: {}", _2)]
    Response(StatusCode, Vec<u8>, String),
    #[fail(display = "Other error: {}", _0)]
    Other(String),
}
