use std::future::Future;
use std::ops::Deref;
use std::str;

use chrono::{DateTime, Utc};
use http::header::{HeaderValue, ACCEPT, CONTENT_TYPE};
use http::method::Method;
use http::status::StatusCode;
use oauth2::AccessToken;
use thiserror::Error;
use url::Url;

use crate::helpers::FilteredFlatten;
use crate::http_utils::{auth_bearer, content_type_has_essence, MIME_TYPE_JSON, MIME_TYPE_JWT};
use crate::jwt::{JsonWebTokenError, JsonWebTokenJsonPayloadSerde};
use crate::types::helpers::deserialize_string_or_vec_opt;
use crate::types::LocalizedClaim;
use crate::verification::UserInfoVerifier;
use crate::{
    AdditionalClaims, AddressClaim, Audience, AudiencesClaim, ClaimsVerificationError,
    EndUserBirthday, EndUserEmail, EndUserFamilyName, EndUserGivenName, EndUserMiddleName,
    EndUserName, EndUserNickname, EndUserPhoneNumber, EndUserPictureUrl, EndUserProfileUrl,
    EndUserTimezone, EndUserUsername, EndUserWebsiteUrl, GenderClaim, HttpRequest, HttpResponse,
    IssuerClaim, IssuerUrl, JsonWebKey, JsonWebKeyType, JsonWebKeyUse, JsonWebToken,
    JweContentEncryptionAlgorithm, JwsSigningAlgorithm, LanguageTag, PrivateSigningKey,
    StandardClaims, SubjectIdentifier,
};

///
/// User info request.
///
pub struct UserInfoRequest<'a, JE, JS, JT, JU, K>
where
    JE: JweContentEncryptionAlgorithm<JT>,
    JS: JwsSigningAlgorithm<JT>,
    JT: JsonWebKeyType,
    JU: JsonWebKeyUse,
    K: JsonWebKey<JS, JT, JU>,
{
    pub(super) url: &'a UserInfoUrl,
    pub(super) access_token: AccessToken,
    pub(super) require_signed_response: bool,
    pub(super) signed_response_verifier: UserInfoVerifier<'static, JE, JS, JT, JU, K>,
}
impl<'a, JE, JS, JT, JU, K> UserInfoRequest<'a, JE, JS, JT, JU, K>
where
    JE: JweContentEncryptionAlgorithm<JT>,
    JS: JwsSigningAlgorithm<JT>,
    JT: JsonWebKeyType,
    JU: JsonWebKeyUse,
    K: JsonWebKey<JS, JT, JU>,
{
    ///
    /// Submits this request to the associated user info endpoint using the specified synchronous
    /// HTTP client.
    ///
    pub fn request<AC, GC, HC, RE>(
        self,
        http_client: HC,
    ) -> Result<UserInfoClaims<AC, GC>, UserInfoError<RE>>
    where
        AC: AdditionalClaims,
        GC: GenderClaim,
        HC: FnOnce(HttpRequest) -> Result<HttpResponse, RE>,
        RE: std::error::Error + 'static,
    {
        http_client(self.prepare_request())
            .map_err(UserInfoError::Request)
            .and_then(|http_response| self.user_info_response(http_response))
    }

    ///
    /// Submits this request to the associated user info endpoint using the specified asynchronous
    /// HTTP client.
    ///
    pub async fn request_async<AC, C, F, GC, RE>(
        self,
        http_client: C,
    ) -> Result<UserInfoClaims<AC, GC>, UserInfoError<RE>>
    where
        AC: AdditionalClaims,
        C: FnOnce(HttpRequest) -> F,
        F: Future<Output = Result<HttpResponse, RE>>,
        GC: GenderClaim,
        RE: std::error::Error + 'static,
    {
        let http_request = self.prepare_request();
        let http_response = http_client(http_request)
            .await
            .map_err(UserInfoError::Request)?;

        self.user_info_response(http_response)
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
        RE: std::error::Error + 'static,
    {
        if http_response.status_code != StatusCode::OK {
            return Err(UserInfoError::Response(
                http_response.status_code,
                http_response.body,
                "unexpected HTTP status code".to_string(),
            ));
        }

        match http_response
            .headers
            .get(CONTENT_TYPE)
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| HeaderValue::from_static(MIME_TYPE_JSON))
        {
            ref content_type if content_type_has_essence(content_type, MIME_TYPE_JSON) => {
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
            ref content_type if content_type_has_essence(content_type, MIME_TYPE_JWT) => {
                let jwt_str = String::from_utf8(http_response.body).map_err(|_| {
                    UserInfoError::Other("response body has invalid UTF-8 encoding".to_string())
                })?;
                serde_path_to_error::deserialize::<_, UserInfoJsonWebToken<AC, GC, JE, JS, JT>>(
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

    ///
    /// Specifies whether to require the user info response to be a signed JSON Web Token (JWT).
    ///
    pub fn require_signed_response(mut self, require_signed_response: bool) -> Self {
        self.require_signed_response = require_signed_response;
        self
    }

    ///
    /// Specifies whether to require the issuer of the signed JWT response to match the expected
    /// issuer URL for this provider.
    ///
    /// This option has no effect on unsigned JSON responses.
    ///
    pub fn require_issuer_match(mut self, iss_required: bool) -> Self {
        self.signed_response_verifier = self
            .signed_response_verifier
            .require_issuer_match(iss_required);
        self
    }

    ///
    /// Specifies whether to require the audience of the signed JWT response to match the expected
    /// audience (client ID).
    ///
    /// This option has no effect on unsigned JSON responses.
    ///
    pub fn require_audience_match(mut self, aud_required: bool) -> Self {
        self.signed_response_verifier = self
            .signed_response_verifier
            .require_audience_match(aud_required);
        self
    }
}

///
/// User info claims.
///
#[derive(Clone, Debug, Serialize)]
pub struct UserInfoClaims<AC: AdditionalClaims, GC: GenderClaim>(UserInfoClaimsImpl<AC, GC>);
impl<AC, GC> UserInfoClaims<AC, GC>
where
    AC: AdditionalClaims,
    GC: GenderClaim,
{
    ///
    /// Initializes user info claims.
    ///
    pub fn new(standard_claims: StandardClaims<GC>, additional_claims: AC) -> Self {
        Self(UserInfoClaimsImpl {
            issuer: None,
            audiences: None,
            standard_claims,
            additional_claims: additional_claims.into(),
        })
    }

    ///
    /// Initializes user info claims from the provided raw JSON response.
    ///
    /// If an `expected_subject` is provided, this function verifies that the user info claims
    /// contain the expected subject and returns an error otherwise.
    ///
    pub fn from_json<RE>(
        user_info_json: &[u8],
        expected_subject: Option<&SubjectIdentifier>,
    ) -> Result<Self, UserInfoError<RE>>
    where
        RE: std::error::Error + 'static,
    {
        let user_info = serde_path_to_error::deserialize::<_, UserInfoClaimsImpl<AC, GC>>(
            &mut serde_json::Deserializer::from_slice(user_info_json),
        )
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
        pub self [self.0] ["claim"] {
            set_issuer -> issuer[Option<IssuerUrl>],
            set_audiences -> audiences[Option<Vec<Audience>>] ["aud"],
        }
    ];

    ///
    /// Returns the `sub` claim.
    ///
    pub fn subject(&self) -> &SubjectIdentifier {
        &self.0.standard_claims.sub
    }
    ///
    /// Sets the `sub` claim.
    ///
    pub fn set_subject(&mut self, subject: SubjectIdentifier) {
        self.0.standard_claims.sub = subject
    }

    field_getters_setters![
        pub self [self.0.standard_claims] ["claim"] {
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

    ///
    /// Returns the standard claims as a `StandardClaims` object.
    ///
    pub fn standard_claims(&self) -> &StandardClaims<GC> {
        &self.0.standard_claims
    }

    ///
    /// Returns additional user info claims.
    ///
    pub fn additional_claims(&self) -> &AC {
        self.0.additional_claims.as_ref()
    }
    ///
    /// Returns mutable additional user info claims.
    ///
    pub fn additional_claims_mut(&mut self) -> &mut AC {
        self.0.additional_claims.as_mut()
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
    pub additional_claims: FilteredFlatten<StandardClaims<GC>, AC>,
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

///
/// JSON Web Token (JWT) containing user info claims.
///
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
    ///
    /// Initializes a new signed JWT containing the specified claims, signed with the specified key
    /// and signing algorithm.
    ///
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

    ///
    /// Verifies and returns the user info claims.
    ///
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
    ///
    /// URL for a provider's user info endpoint.
    ///
    UserInfoUrl
];

///
/// Error retrieving user info.
///
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum UserInfoError<RE>
where
    RE: std::error::Error + 'static,
{
    ///
    /// Failed to verify user info claims.
    ///
    #[error("Failed to verify claims")]
    ClaimsVerification(#[source] ClaimsVerificationError),
    ///
    /// Failed to parse server response.
    ///
    #[error("Failed to parse server response")]
    Parse(#[source] serde_path_to_error::Error<serde_json::Error>),
    ///
    /// An error occurred while sending the request or receiving the response (e.g., network
    /// connectivity failed).
    ///
    #[error("Request failed")]
    Request(#[source] RE),
    ///
    /// Server returned an invalid response.
    ///
    #[error("Server returned invalid response: {2}")]
    Response(StatusCode, Vec<u8>, String),
    ///
    /// An unexpected error occurred.
    ///
    #[error("Other error: {0}")]
    Other(String),
}

#[cfg(test)]
mod tests {
    use crate::core::CoreGenderClaim;
    use crate::{AdditionalClaims, UserInfoClaims};

    use std::collections::HashMap;

    #[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
    struct TestClaims {
        pub tfa_method: String,
    }
    impl AdditionalClaims for TestClaims {}

    #[test]
    fn test_additional_claims() {
        let claims = UserInfoClaims::<TestClaims, CoreGenderClaim>::from_json::<
            crate::reqwest::HttpClientError,
        >(
            "{
                \"iss\": \"https://server.example.com\",
                \"sub\": \"24400320\",
                \"aud\": [\"s6BhdRkqt3\"],
                \"tfa_method\": \"u2f\"
            }"
            .as_bytes(),
            None,
        )
        .expect("failed to deserialize");
        assert_eq!(claims.additional_claims().tfa_method, "u2f");
        assert_eq!(
            serde_json::to_string(&claims).expect("failed to serialize"),
            "{\
             \"iss\":\"https://server.example.com\",\
             \"aud\":[\"s6BhdRkqt3\"],\
             \"sub\":\"24400320\",\
             \"tfa_method\":\"u2f\"\
             }",
        );

        UserInfoClaims::<TestClaims, CoreGenderClaim>::from_json::<crate::reqwest::HttpClientError>(
            "{
                \"iss\": \"https://server.example.com\",
                \"sub\": \"24400320\",
                \"aud\": [\"s6BhdRkqt3\"]
            }".as_bytes(),
            None,
        )
            .expect_err("missing claim should fail to deserialize");
    }

    #[derive(Debug, Deserialize, Serialize)]
    struct AllOtherClaims(HashMap<String, serde_json::Value>);
    impl AdditionalClaims for AllOtherClaims {}

    #[test]
    fn test_catch_all_additional_claims() {
        let claims = UserInfoClaims::<AllOtherClaims, CoreGenderClaim>::from_json::<
            crate::reqwest::HttpClientError,
        >(
            "{
                \"iss\": \"https://server.example.com\",
                \"sub\": \"24400320\",
                \"aud\": [\"s6BhdRkqt3\"],
                \"tfa_method\": \"u2f\",
                \"updated_at\": 1000
            }"
            .as_bytes(),
            None,
        )
        .expect("failed to deserialize");

        assert_eq!(claims.additional_claims().0.len(), 1);
        assert_eq!(claims.additional_claims().0["tfa_method"], "u2f");
    }
}
