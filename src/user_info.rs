use std::ops::Deref;
use std::str;

use chrono::{DateTime, Utc};
use curl;
use oauth2::AccessToken;
use serde_json;
use url::Url;

use super::claims::StandardClaimsImpl;
use super::http::{
    auth_bearer, HttpRequest, HttpRequestMethod, ACCEPT_JSON, HTTP_STATUS_OK, MIME_TYPE_JSON,
    MIME_TYPE_JWT,
};
use super::jwt::JsonWebTokenJsonPayloadDeserializer;
use super::types::helpers::{seconds_to_utc, utc_to_seconds};
use super::types::LocalizedClaim;
use super::verification::UserInfoVerifier;
use super::{
    AdditionalClaims, AddressClaim, Audience, AudiencesClaim, ClaimsVerificationError,
    EndUserBirthday, EndUserEmail, EndUserFamilyName, EndUserGivenName, EndUserMiddleName,
    EndUserName, EndUserNickname, EndUserPhoneNumber, EndUserPictureUrl, EndUserProfileUrl,
    EndUserTimezone, EndUserUsername, EndUserWebsiteUrl, GenderClaim, IssuerClaim, IssuerUrl,
    JsonWebKey, JsonWebKeyType, JsonWebKeyUse, JsonWebToken, JweContentEncryptionAlgorithm,
    JwsSigningAlgorithm, LanguageTag, StandardClaims, SubjectIdentifier,
};

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct UserInfoClaims<AC, GC>
where
    AC: AdditionalClaims,
    GC: GenderClaim,
{
    #[serde(skip_serializing_if = "Option::is_none")]
    iss: Option<IssuerUrl>,
    // FIXME: this needs to be a vector, but it may also come as a single string
    #[serde(skip_serializing_if = "Option::is_none")]
    aud: Option<Vec<Audience>>,

    #[serde(bound = "GC: GenderClaim")]
    #[serde(flatten)]
    standard_claims: StandardClaimsImpl<GC>,

    #[serde(bound = "AC: AdditionalClaims")]
    #[serde(flatten)]
    additional_claims: AC,
}
// FIXME: see what other structs should have friendlier trait interfaces like this one
impl<AC, GC> UserInfoClaims<AC, GC>
where
    AC: AdditionalClaims,
    GC: GenderClaim,
{
    pub fn issuer(&self) -> Option<&IssuerUrl> {
        self.iss.as_ref()
    }
    pub fn audiences(&self) -> Option<&Vec<Audience>> {
        self.aud.as_ref()
    }
    pub fn additional_claims(&self) -> &AC {
        &self.additional_claims
    }
}
impl<AC, GC> StandardClaims<GC> for UserInfoClaims<AC, GC>
where
    AC: AdditionalClaims,
    GC: GenderClaim,
{
    field_getters_setters![
        self [self.standard_claims] {
            set_sub -> sub[SubjectIdentifier],
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
            set_address -> address[Option<AddressClaim>],        }
    ];

    fn updated_at(&self) -> Option<Result<DateTime<Utc>, ()>> {
        self.standard_claims.updated_at.as_ref().map(seconds_to_utc)
    }

    fn set_updated_at(mut self, updated_at: Option<&DateTime<Utc>>) -> Self {
        self.standard_claims.updated_at = updated_at.map(utc_to_seconds);
        self
    }
}

impl<AC, GC> AudiencesClaim for UserInfoClaims<AC, GC>
where
    AC: AdditionalClaims,
    GC: GenderClaim,
{
    fn audiences(&self) -> Option<&Vec<Audience>> {
        UserInfoClaims::audiences(&self)
    }
}
impl<'a, AC, GC> AudiencesClaim for &'a UserInfoClaims<AC, GC>
where
    AC: AdditionalClaims,
    GC: GenderClaim,
{
    fn audiences(&self) -> Option<&Vec<Audience>> {
        UserInfoClaims::audiences(&self)
    }
}

impl<AC, GC> IssuerClaim for UserInfoClaims<AC, GC>
where
    AC: AdditionalClaims,
    GC: GenderClaim,
{
    fn issuer(&self) -> Option<&IssuerUrl> {
        UserInfoClaims::issuer(&self)
    }
}
impl<'a, AC, GC> IssuerClaim for &'a UserInfoClaims<AC, GC>
where
    AC: AdditionalClaims,
    GC: GenderClaim,
{
    fn issuer(&self) -> Option<&IssuerUrl> {
        UserInfoClaims::issuer(&self)
    }
}

new_url_type![
    UserInfoUrl
    impl {
        pub fn get_user_info<AC, GC, JE, JS, JT, JU, K>(
            &self,
            access_token: &AccessToken,
            verifier: &UserInfoVerifier<JE, JS, JT, JU, K>,
        ) -> Result<UserInfoClaims<AC, GC>, UserInfoError>
        where AC: AdditionalClaims,
                GC: GenderClaim,
                JE: JweContentEncryptionAlgorithm,
                JS: JwsSigningAlgorithm<JT>,
                JT: JsonWebKeyType,
                JU: JsonWebKeyUse,
                K: JsonWebKey<JS, JT, JU>{
            let (auth_header, auth_value) = auth_bearer(access_token);
            let user_info_response =
                HttpRequest {
                    url: &self.0,
                    method: HttpRequestMethod::Get,
                    headers: &vec![ACCEPT_JSON, (auth_header, auth_value.as_ref())],
                    post_body: &vec![],
                }
                .request()
                .map_err(UserInfoError::Request)?;

            // FIXME: improve error handling (i.e., is there a body response?)
            // possibly consolidate this error handling with discovery::get_provider_metadata().
            if user_info_response.status_code != HTTP_STATUS_OK {
                return Err(
                    UserInfoError::Response(
                        user_info_response.status_code,
                        "unexpected HTTP status code".to_string()
                    )
                );
            }

            match user_info_response.content_type.as_ref().map(String::as_str) {
                None | Some(MIME_TYPE_JSON) => {
                    verifier
                        .verified_claims(
                            UnverifiedUserInfoClaims::JsonClaims(
                                serde_json::from_slice(&user_info_response.body)
                                    .map_err(UserInfoError::Json)?
                            )
                        )
                        .map_err(UserInfoError::ClaimsVerification)
                }
                Some(MIME_TYPE_JWT) => {
                    let jwt_str =
                        String::from_utf8(user_info_response.body)
                            .map_err(|_|
                                UserInfoError::Other(
                                    "response body has invalid UTF-8 encoding".to_string()
                                )
                            )?;
                    verifier
                        .verified_claims(
                            UnverifiedUserInfoClaims::JwtClaims(
                                // TODO: Implement a simple deserializer so that we can go straight
                                // from a str to a JsonWebToken without first converting to/from
                                // JSON.
                                serde_json::from_value(serde_json::Value::String(jwt_str))
                                    .map_err(UserInfoError::Json)?
                            )
                        )
                        .map_err(UserInfoError::ClaimsVerification)
                }
                Some(content_type) =>
                    Err(
                        UserInfoError::Response(
                            user_info_response.status_code,
                            format!("unexpected response Content-Type: `{}`", content_type)
                        )
                    ),
            }
        }
    }
];

#[derive(Debug, Fail)]
pub enum UserInfoError {
    #[fail(display = "Failed to verify claims")]
    ClaimsVerification(#[cause] ClaimsVerificationError),
    #[fail(display = "Request failed")]
    Request(#[cause] curl::Error),
    #[fail(display = "Response error (status={}): {}", _0, _1)]
    Response(u32, String),
    #[fail(display = "Failed to parse response")]
    Json(#[cause] serde_json::Error),
    #[fail(display = "Other error: {}", _0)]
    Other(String),
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(crate) enum UnverifiedUserInfoClaims<AC, GC, JE, JS, JT>
where
    AC: AdditionalClaims,
    GC: GenderClaim,
    JE: JweContentEncryptionAlgorithm,
    JS: JwsSigningAlgorithm<JT>,
    JT: JsonWebKeyType,
{
    JsonClaims(#[serde(bound = "AC: AdditionalClaims")] UserInfoClaims<AC, GC>),
    JwtClaims(
        #[serde(bound = "AC: AdditionalClaims")]
        JsonWebToken<UserInfoClaims<AC, GC>, JE, JS, JT, JsonWebTokenJsonPayloadDeserializer>,
    ),
}
