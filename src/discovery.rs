
use std::fmt::Debug;
use std::marker::PhantomData;

use curl;
use oauth2::{
    AuthUrl,
    Scope,
    TokenUrl,
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json;
use url;

use super::{CONFIG_URL_SUFFIX, JsonWebKeySetUrl, UserInfoUrl};
use super::http::{
    ACCEPT_JSON,
    HttpRequest,
    HttpRequestMethod,
    HTTP_STATUS_OK,
    MIME_TYPE_JSON,
};
use super::macros::TraitStructExtract;
use super::types::{
    AuthDisplay,
    AuthenticationContextClass,
    ClientAuthMethod,
    ClaimName,
    ClaimType,
    GrantType,
    IssuerUrl,
    JsonWebKeyType,
    JweContentEncryptionAlgorithm,
    JweKeyManagementAlgorithm,
    JwsSigningAlgorithm,
    LanguageTag,
    OpPolicyUrl,
    OpTosUrl,
    RegistrationUrl,
    ResponseMode,
    ResponseType,
    ResponseTypes,
    ServiceDocUrl,
    SubjectIdentifierType,
};

pub fn get_provider_metadata<PM, AD, CA, CN, CT, G, JE, JK, JS, JT, RM, RT, S>(
    issuer_url: &IssuerUrl
) -> Result<PM, DiscoveryError>
where AD: AuthDisplay,
        CA: ClientAuthMethod,
        CN: ClaimName,
        CT: ClaimType,
        G: GrantType,
        JE: JweContentEncryptionAlgorithm,
        JK: JweKeyManagementAlgorithm,
        JS: JwsSigningAlgorithm<JT>,
        JT: JsonWebKeyType,
        RM: ResponseMode,
        RT: ResponseType,
        S: SubjectIdentifierType,
        PM: ProviderMetadata<AD, CA, CN, CT, G, JE, JK, JS, JT, RM, RT, S> {
    let discover_url =
        issuer_url
            .join(CONFIG_URL_SUFFIX)
            .map_err(DiscoveryError::UrlParse)?;
    let discover_response =
        HttpRequest {
            url: &discover_url,
            method: HttpRequestMethod::Get,
            headers: &vec![ACCEPT_JSON],
            post_body: &vec![],
        }
        .request()
        .map_err(DiscoveryError::Request)?;

    // FIXME: improve error handling (i.e., is there a body response?)
    if discover_response.status_code != HTTP_STATUS_OK {
        return Err(
            DiscoveryError::Response(
                discover_response.status_code,
                "unexpected HTTP status code".to_string()
            )
        );
    }

    discover_response
        .check_content_type(MIME_TYPE_JSON)
        .map_err(|err_msg| DiscoveryError::Response(discover_response.status_code, err_msg))?;

    let provider_metadata: PM =
        serde_json::from_slice(&discover_response.body)
            .map_err(DiscoveryError::Json)?;

    provider_metadata.validate(issuer_url)
}

// FIXME: switch to embedding a flattened extra_fields struct
trait_struct![
    trait ProviderMetadata[
        AD: AuthDisplay,
        CA: ClientAuthMethod,
        CN: ClaimName,
        CT: ClaimType,
        G: GrantType,
        JE: JweContentEncryptionAlgorithm,
        JK: JweKeyManagementAlgorithm,
        JS: JwsSigningAlgorithm<JT>,
        JT: JsonWebKeyType,
        RM: ResponseMode,
        RT: ResponseType,
        S: SubjectIdentifierType,
    ] : [Debug + DeserializeOwned + PartialEq + Serialize + Sized] {
        // consumes self so that, if validation fails, it doesn't get used
        fn validate(self, issuer_uri: &IssuerUrl) -> Result<Self, DiscoveryError> {
            if self.issuer() != issuer_uri {
                return Err(
                    DiscoveryError::Validation(
                        format!(
                            "unexpected issuer URI `{}` (expected `{}`); this may indicate an \
                                OpenID Provider impersonation attack",
                            **self.issuer(),
                            **issuer_uri
                        )
                    )
                )
            }
            Ok(self)
        }
    }
    #[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
    struct Discovery10ProviderMetadata[
        AD: AuthDisplay,
        CA: ClientAuthMethod,
        CN: ClaimName,
        CT: ClaimType,
        G: GrantType,
        JE: JweContentEncryptionAlgorithm,
        JK: JweKeyManagementAlgorithm,
        JS: JwsSigningAlgorithm<JT>,
        JT: JsonWebKeyType,
        RM: ResponseMode,
        RT: ResponseType,
        S: SubjectIdentifierType,
    ] {
        issuer(&IssuerUrl) <- IssuerUrl,
        authorization_endpoint(&AuthUrl) <- AuthUrl,
        token_endpoint(Option<&TokenUrl>) <- Option<TokenUrl>,
        userinfo_endpoint(Option<&UserInfoUrl>) <- Option<UserInfoUrl>,
        jwks_uri(Option<&JsonWebKeySetUrl>) <- Option<JsonWebKeySetUrl>,
        registration_endpoint(Option<&RegistrationUrl>) <- Option<RegistrationUrl>,
        scopes_supported(Option<&Vec<Scope>>) <- Option<Vec<Scope>>,
        #[serde(bound(deserialize = "RT: ResponseType"))]
        response_types_supported(&Vec<ResponseTypes<RT>>) <- Vec<ResponseTypes<RT>>,
        #[serde(bound(deserialize = "RM: ResponseMode"))]
        response_modes_supported(Option<&Vec<RM>>) <- Option<Vec<RM>>,
        #[serde(bound(deserialize = "G: GrantType"))]
        grant_types_supported(Option<&Vec<G>>) <- Option<Vec<G>>,
        acr_values_supported(Option<&Vec<AuthenticationContextClass>>)
            <- Option<Vec<AuthenticationContextClass>>,
        #[serde(bound(deserialize = "S: SubjectIdentifierType"))]
        subject_types_supported(&Vec<S>) <- Vec<S>,
        #[serde(bound(deserialize = "JS: JwsSigningAlgorithm<JT>"))]
        id_token_signing_alg_values_supported(&Vec<JS>) <- Vec<JS>,
        #[serde(bound(deserialize = "JK: JweKeyManagementAlgorithm"))]
        id_token_encryption_alg_values_supported(Option<&Vec<JK>>) <- Option<Vec<JK>>,
        #[serde(bound(deserialize = "JE: JweContentEncryptionAlgorithm"))]
        id_token_encryption_enc_values_supported(Option<&Vec<JE>>) <- Option<Vec<JE>>,
        #[serde(bound(deserialize = "JS: JwsSigningAlgorithm<JT>"))]
        userinfo_signing_alg_values_supported(Option<&Vec<JS>>) <- Option<Vec<JS>>,
        #[serde(bound(deserialize = "JK: JweKeyManagementAlgorithm"))]
        userinfo_encryption_alg_values_supported(Option<&Vec<JK>>) <- Option<Vec<JK>>,
        #[serde(bound(deserialize = "JE: JweContentEncryptionAlgorithm"))]
        userinfo_encryption_enc_values_supported(Option<&Vec<JE>>) <- Option<Vec<JE>>,
        #[serde(bound(deserialize = "JS: JwsSigningAlgorithm<JT>"))]
        request_object_signing_alg_values_supported(Option<&Vec<JS>>) <- Option<Vec<JS>>,
        #[serde(bound(deserialize = "JK: JweKeyManagementAlgorithm"))]
        request_object_encryption_alg_values_supported(Option<&Vec<JK>>) <- Option<Vec<JK>>,
        #[serde(bound(deserialize = "JE: JweContentEncryptionAlgorithm"))]
        request_object_encryption_enc_values_supported(Option<&Vec<JE>>) <- Option<Vec<JE>>,
        #[serde(bound(deserialize = "CA: ClientAuthMethod"))]
        token_endpoint_auth_methods_supported(Option<&Vec<CA>>) <- Option<Vec<CA>>,
        #[serde(bound(deserialize = "JS: JwsSigningAlgorithm<JT>"))]
        token_endpoint_auth_signing_alg_values_supported(Option<&Vec<JS>>) <- Option<Vec<JS>>,
        #[serde(bound(deserialize = "AD: AuthDisplay"))]
        display_values_supported(Option<&Vec<AD>>) <- Option<Vec<AD>>,
        #[serde(bound(deserialize = "CT: ClaimType"))]
        claim_types_supported(Option<&Vec<CT>>) <- Option<Vec<CT>>,
        #[serde(bound(deserialize = "CN: ClaimName"))]
        claims_supported(Option<&Vec<CN>>) <- Option<Vec<CN>>,
        service_documentation(Option<&ServiceDocUrl>) <- Option<ServiceDocUrl>,
        claims_locales_supported(Option<&Vec<LanguageTag>>) <- Option<Vec<LanguageTag>>,
        ui_locales_supported(Option<&Vec<LanguageTag>>) <- Option<Vec<LanguageTag>>,
        claims_parameter_supported(Option<bool>) <- Option<bool>,
        request_parameter_supported(Option<bool>) <- Option<bool>,
        request_uri_parameter_supported(Option<bool>) <- Option<bool>,
        require_request_uri_registration(Option<bool>) <- Option<bool>,
        op_policy_uri(Option<&OpPolicyUrl>) <- Option<OpPolicyUrl>,
        op_tos_uri(Option<&OpTosUrl>) <- Option<OpTosUrl>,
        // FIXME: remove trait method
        #[serde(skip)]
        _phantom_jt(PhantomData<JT>) <- PhantomData<JT>,
    }
    impl [
        AD: AuthDisplay,
        CA: ClientAuthMethod,
        CN: ClaimName,
        CT: ClaimType,
        G: GrantType,
        JE: JweContentEncryptionAlgorithm,
        JK: JweKeyManagementAlgorithm,
        JS: JwsSigningAlgorithm<JT>,
        JT: JsonWebKeyType,
        RM: ResponseMode,
        RT: ResponseType,
        S: SubjectIdentifierType,
    ] trait[AD, CA, CN, CT, G, JE, JK, JS, JT, RM, RT, S] for
    struct[AD, CA, CN, CT, G, JE, JK, JS, JT, RM, RT, S]
];

#[derive(Debug, Fail)]
pub enum DiscoveryError {
    #[fail(display = "URL parse error: {}", _0)]
    UrlParse(url::ParseError),
    #[fail(display = "Request error: {}", _0)]
    Request(curl::Error),
    #[fail(display = "Response error (status={}): {}", _0, _1)]
    Response(u32, String),
    #[fail(display = "JSON error: {}", _0)]
    Json(serde_json::Error),
    #[fail(display = "Validation error: {}", _0)]
    Validation(String),
    #[fail(display = "Other error: {}", _0)]
    Other(String),
}
