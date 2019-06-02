use std::ops::Deref;
use std::str;

use chrono::{DateTime, Utc};
use failure::Fail;
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

#[derive(Clone, Debug, PartialEq, Serialize)]
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
        subject: &SubjectIdentifier,
    ) -> Result<Self, UserInfoError<RE>>
    where
        RE: Fail,
    {
        let user_info = serde_json::from_slice::<UserInfoClaimsImpl<AC, GC>>(&user_info_json)
            .map_err(UserInfoError::Parse)?;

        // This is the only verification we need to do for JSON-based user info claims, so don't
        // bother with the complexity of a separate verifier object.
        if user_info.standard_claims.sub == *subject {
            Ok(Self(user_info))
        } else {
            Err(UserInfoError::ClaimsVerification(
                ClaimsVerificationError::InvalidSubject(format!(
                    "expected `{}` (found `{}`)",
                    **subject, *user_info.standard_claims.sub,
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

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
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

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
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

new_url_type![
    UserInfoUrl
    impl {
        pub fn get_user_info<AC, GC, HC, JE, JS, JT, JU, K, RE>(
            &self,
            access_token: &AccessToken,
            require_signed_response: bool,
            signed_response_verifier: &UserInfoVerifier<JE, JS, JT, JU, K>,
            http_client: HC,
        ) -> Result<UserInfoClaims<AC, GC>, UserInfoError<RE>>
        where
            AC: AdditionalClaims,
            GC: GenderClaim,
            HC: FnOnce(HttpRequest) -> Result<HttpResponse, RE>,
            JE: JweContentEncryptionAlgorithm<JT>,
            JS: JwsSigningAlgorithm<JT>,
            JT: JsonWebKeyType,
            JU: JsonWebKeyUse,
            K: JsonWebKey<JS, JT, JU>,
            RE: Fail,
        {
            let (auth_header, auth_value) = auth_bearer(access_token);
            let user_info_response =
                http_client(
                    HttpRequest {
                        url: self.0.clone(),
                        method: Method::GET,
                        headers: vec![
                            (ACCEPT, HeaderValue::from_static(MIME_TYPE_JSON)),
                            (auth_header, auth_value),
                        ].into_iter().collect(),
                        body: Vec::new(),
                    }
                )
                .map_err(UserInfoError::Request)?;

            if user_info_response.status_code != StatusCode::OK {
                return Err(
                    UserInfoError::Response(
                        user_info_response.status_code,
                        user_info_response.body.clone(),
                        "unexpected HTTP status code".to_string()
                    )
                );
            }

            match user_info_response
                .headers
                .get(CONTENT_TYPE)
                .map(ToOwned::to_owned)
                .unwrap_or_else(|| HeaderValue::from_static(MIME_TYPE_JSON))
            {
               ref content_type if content_type == HeaderValue::from_static(MIME_TYPE_JSON) => {
                    if require_signed_response {
                        return Err(
                            UserInfoError::ClaimsVerification(ClaimsVerificationError::NoSignature)
                        );
                    }
                    UserInfoClaims::from_json(
                        &user_info_response.body,
                        signed_response_verifier.subject(),
                    )
                }
                ref content_type if content_type == HeaderValue::from_static(MIME_TYPE_JWT) => {
                    let jwt_str =
                        String::from_utf8(user_info_response.body)
                            .map_err(|_|
                                UserInfoError::Other(
                                    "response body has invalid UTF-8 encoding".to_string()
                                )
                            )?;
                    serde_json::from_value::<UserInfoJsonWebToken<AC, GC, JE, JS, JT>>(
                        serde_json::Value::String(jwt_str)
                    )
                    .map_err(UserInfoError::Parse)?
                    .claims(signed_response_verifier)
                    .map_err(UserInfoError::ClaimsVerification)
                }
                ref content_type =>
                    Err(
                        UserInfoError::Response(
                            user_info_response.status_code,
                            user_info_response.body,
                            format!("unexpected response Content-Type: `{:?}`", content_type)
                        )
                    ),
            }
        }
    }
];

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
