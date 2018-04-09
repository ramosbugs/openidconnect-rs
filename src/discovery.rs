extern crate curl;
extern crate url;
extern crate serde;
extern crate serde_json;

use std::fmt::Debug;

use oauth2::{
    AuthUrl,
    Scope,
    TokenUrl,
};
use serde::Serialize;
use serde::de::DeserializeOwned;

use super::macros::TraitStructExtract;
use super::types::{
    AuthDisplay,
    AuthenticationContextClass,
    ClientAuthMethod,
    ClaimName,
    ClaimType,
    GrantType,
    IssuerUrl,
    JweContentEncryptionAlgorithm,
    JweKeyManagementAlgorithm,
    JwkSetUrl,
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
    UserInfoUrl,
};

trait_struct![
    trait ProviderMetadata[
        AD: AuthDisplay,
        CA: ClientAuthMethod,
        CN: ClaimName,
        CT: ClaimType,
        G: GrantType,
        JE: JweContentEncryptionAlgorithm,
        JK: JweKeyManagementAlgorithm,
        JS: JwsSigningAlgorithm,
        RM: ResponseMode,
        RT: ResponseType,
        S: SubjectIdentifierType,
    ] : [Debug + DeserializeOwned + PartialEq + Serialize]
    struct Discovery10ProviderMetadata[
        AD: AuthDisplay,
        CA: ClientAuthMethod,
        CN: ClaimName,
        CT: ClaimType,
        G: GrantType,
        JE: JweContentEncryptionAlgorithm,
        JK: JweKeyManagementAlgorithm,
        JS: JwsSigningAlgorithm,
        RM: ResponseMode,
        RT: ResponseType,
        S: SubjectIdentifierType,
    ] {
        #[serde(rename = "issuer")]
        issuer(&IssuerUrl)
            <- _issuer(IssuerUrl),
        #[serde(rename = "authorization_endpoint")]
        authorization_endpoint(&AuthUrl)
            <- _authorization_endpoint(AuthUrl),
        #[serde(rename = "token_endpoint")]
        token_endpoint(Option<&TokenUrl>)
            <- _token_endpoint(Option<TokenUrl>),
        #[serde(rename = "userinfo_endpoint")]
        userinfo_endpoint(Option<&UserInfoUrl>)
            <- _userinfo_endpoint(Option<UserInfoUrl>),
        #[serde(rename = "jwks_uri")]
        jwks_uri(Option<&JwkSetUrl>)
            <- _jwks_uri(Option<JwkSetUrl>),
        #[serde(rename = "registration_endpoint")]
        registration_endpoint(Option<&RegistrationUrl>)
            <- _registration_endpoint(Option<RegistrationUrl>),
        #[serde(rename = "scopes_supported")]
        scopes_supported(Option<&Vec<Scope>>)
            <- _scopes_supported(Option<Vec<Scope>>),
        #[serde(rename = "response_types_supported")]
        #[serde(bound(deserialize = "RT: ResponseType"))]
        response_types_supported(&Vec<ResponseTypes<RT>>)
            <- _response_types_supported(Vec<ResponseTypes<RT>>),
        #[serde(rename = "response_modes_supported")]
        #[serde(bound(deserialize = "RM: ResponseMode"))]
        response_modes_supported(Option<&Vec<RM>>)
            <- _response_modes_supported(Option<Vec<RM>>),
        #[serde(rename = "grant_types_supported")]
        #[serde(bound(deserialize = "G: GrantType"))]
        grant_types_supported(Option<&Vec<G>>)
            <- _grant_types_supported(Option<Vec<G>>),
        #[serde(rename = "acr_values_supported")]
        acr_values_supported(Option<&Vec<AuthenticationContextClass>>)
            <- _acr_values_supported(Option<Vec<AuthenticationContextClass>>),
        #[serde(rename = "subject_types_supported")]
        #[serde(bound(deserialize = "S: SubjectIdentifierType"))]
        subject_types_supported(&Vec<S>)
            <- _subject_types_supported(Vec<S>),
        #[serde(rename = "id_token_signing_alg_values_supported")]
        #[serde(bound(deserialize = "JS: JwsSigningAlgorithm"))]
        id_token_signing_alg_values_supported(&Vec<JS>)
            <- _id_token_signing_alg_values_supported(Vec<JS>),
        #[serde(rename = "id_token_encryption_alg_values_supported")]
        #[serde(bound(deserialize = "JK: JweKeyManagementAlgorithm"))]
        id_token_encryption_alg_values_supported(Option<&Vec<JK>>)
            <- _id_token_encryption_alg_values_supported(Option<Vec<JK>>),
        #[serde(rename = "id_token_encryption_enc_values_supported")]
        #[serde(bound(deserialize = "JE: JweContentEncryptionAlgorithm"))]
        id_token_encryption_enc_values_supported(Option<&Vec<JE>>)
            <- _id_token_encryption_enc_values_supported(Option<Vec<JE>>),
        #[serde(rename = "userinfo_signing_alg_values_supported")]
        #[serde(bound(deserialize = "JS: JwsSigningAlgorithm"))]
        userinfo_signing_alg_values_supported(Option<&Vec<JS>>)
            <- _userinfo_signing_alg_values_supported(Option<Vec<JS>>),
        #[serde(rename = "userinfo_encryption_alg_values_supported")]
        #[serde(bound(deserialize = "JK: JweKeyManagementAlgorithm"))]
        userinfo_encryption_alg_values_supported(Option<&Vec<JK>>)
            <- _userinfo_encryption_alg_values_supported(Option<Vec<JK>>),
        #[serde(rename = "userinfo_encryption_enc_values_supported")]
        #[serde(bound(deserialize = "JE: JweContentEncryptionAlgorithm"))]
        userinfo_encryption_enc_values_supported(Option<&Vec<JE>>)
            <- _userinfo_encryption_enc_values_supported(Option<Vec<JE>>),
        #[serde(rename = "request_object_signing_alg_values_supported")]
        #[serde(bound(deserialize = "JS: JwsSigningAlgorithm"))]
        request_object_signing_alg_values_supported(Option<&Vec<JS>>)
            <- _request_object_signing_alg_values_supported(Option<Vec<JS>>),
        #[serde(rename = "request_object_encryption_alg_values_supported")]
        #[serde(bound(deserialize = "JK: JweKeyManagementAlgorithm"))]
        request_object_encryption_alg_values_supported(Option<&Vec<JK>>)
            <- _request_object_encryption_alg_values_supported(Option<Vec<JK>>),
        #[serde(rename = "request_object_encryption_enc_values_supported")]
        #[serde(bound(deserialize = "JE: JweContentEncryptionAlgorithm"))]
        request_object_encryption_enc_values_supported(Option<&Vec<JE>>)
            <- _request_object_encryption_enc_values_supported(Option<Vec<JE>>),
        #[serde(rename = "token_endpoint_auth_methods_supported")]
        #[serde(bound(deserialize = "CA: ClientAuthMethod"))]
        token_endpoint_auth_methods_supported(Option<&Vec<CA>>)
            <- _token_endpoint_auth_methods_supported(Option<Vec<CA>>),
        #[serde(rename = "token_endpoint_auth_signing_alg_values_supported")]
        #[serde(bound(deserialize = "JS: JwsSigningAlgorithm"))]
        token_endpoint_auth_signing_alg_values_supported(Option<&Vec<JS>>)
            <- _token_endpoint_auth_signing_alg_values_supported(Option<Vec<JS>>),
        #[serde(rename = "display_values_supported")]
        #[serde(bound(deserialize = "AD: AuthDisplay"))]
        display_values_supported(Option<&Vec<AD>>)
            <- _display_values_supported(Option<Vec<AD>>),
        #[serde(rename = "claim_types_supported")]
        #[serde(bound(deserialize = "CT: ClaimType"))]
        claim_types_supported(Option<&Vec<CT>>)
            <- _claim_types_supported(Option<Vec<CT>>),
        #[serde(rename = "claims_supported")]
        #[serde(bound(deserialize = "CN: ClaimName"))]
        claims_supported(Option<&Vec<CN>>)
            <- _claims_supported(Option<Vec<CN>>),
        #[serde(rename = "service_documentation")]
        service_documentation(Option<&ServiceDocUrl>)
            <- _service_documentation(Option<ServiceDocUrl>),
        #[serde(rename = "claims_locales_supported")]
        claims_locales_supported(Option<&Vec<LanguageTag>>)
            <- _claims_locales_supported(Option<Vec<LanguageTag>>),
        #[serde(rename = "ui_locales_supported")]
        ui_locales_supported(Option<&Vec<LanguageTag>>)
            <- _ui_locales_supported(Option<Vec<LanguageTag>>),
        #[serde(rename = "claims_parameter_supported")]
        claims_parameter_supported(Option<bool>)
            <- _claims_parameter_supported(Option<bool>),
        #[serde(rename = "request_parameter_supported")]
        request_parameter_supported(Option<bool>)
            <- _request_parameter_supported(Option<bool>),
        #[serde(rename = "request_uri_parameter_supported")]
        request_uri_parameter_supported(Option<bool>)
            <- _request_uri_parameter_supported(Option<bool>),
        #[serde(rename = "require_request_uri_registration")]
        require_request_uri_registration(Option<bool>)
            <- _require_request_uri_registration(Option<bool>),
        #[serde(rename = "op_policy_uri")]
        op_policy_uri(Option<&OpPolicyUrl>)
            <- _op_policy_uri(Option<OpPolicyUrl>),
        #[serde(rename = "op_tos_uri")]
        op_tos_uri(Option<&OpTosUrl>)
            <- _op_tos_uri(Option<OpTosUrl>),
    }
    impl [
        AD: AuthDisplay,
        CA: ClientAuthMethod,
        CN: ClaimName,
        CT: ClaimType,
        G: GrantType,
        JE: JweContentEncryptionAlgorithm,
        JK: JweKeyManagementAlgorithm,
        JS: JwsSigningAlgorithm,
        RM: ResponseMode,
        RT: ResponseType,
        S: SubjectIdentifierType,
    ] trait[AD, CA, CN, CT, G, JE, JK, JS, RM, RT, S] for
    struct[AD, CA, CN, CT, G, JE, JK, JS, RM, RT, S]
];

#[derive(Debug, Fail)]
pub enum DiscoveryError {
    #[fail(display = "URL parse error: {}", _0)]
    UrlParse(url::ParseError),
    #[fail(display = "Request error: {}", _0)]
    Request(curl::Error),
    #[fail(display = "Other error: {}", _0)]
    Other(String),
}
