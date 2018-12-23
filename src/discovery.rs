use std::fmt::Debug;
use std::marker::PhantomData;
use std::ops::Deref;

use curl;
use oauth2::{AuthUrl, Scope, TokenUrl};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json;
use url;
use url::Url;

use super::http::{HttpRequest, HttpRequestMethod, ACCEPT_JSON, HTTP_STATUS_OK, MIME_TYPE_JSON};
use super::macros::TraitStructExtract;
use super::types::{
    AuthDisplay, AuthenticationContextClass, ClaimName, ClaimType, ClientAuthMethod, GrantType,
    IssuerUrl, JsonWebKey, JsonWebKeySet, JsonWebKeyType, JsonWebKeyUse,
    JweContentEncryptionAlgorithm, JweKeyManagementAlgorithm, JwsSigningAlgorithm, LanguageTag,
    OpPolicyUrl, OpTosUrl, RegistrationUrl, ResponseMode, ResponseType, ResponseTypes,
    ServiceDocUrl, SubjectIdentifierType,
};
use super::{UserInfoUrl, CONFIG_URL_SUFFIX};

pub fn get_provider_metadata<PM, AD, CA, CN, CT, G, JE, JK, JS, JT, RM, RT, S>(
    issuer_url: &IssuerUrl,
) -> Result<PM, DiscoveryError>
where
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
    PM: ProviderMetadata<AD, CA, CN, CT, G, JE, JK, JS, JT, RM, RT, S>,
{
    let discover_url = issuer_url
        .join(CONFIG_URL_SUFFIX)
        .map_err(DiscoveryError::UrlParse)?;
    let discover_response = HttpRequest {
        url: &discover_url,
        method: HttpRequestMethod::Get,
        headers: &vec![ACCEPT_JSON],
        post_body: &vec![],
    }
    .request()
    .map_err(DiscoveryError::Request)?;

    // FIXME: improve error handling (i.e., is there a body response?)
    if discover_response.status_code != HTTP_STATUS_OK {
        return Err(DiscoveryError::Response(
            discover_response.status_code,
            "unexpected HTTP status code".to_string(),
        ));
    }

    discover_response
        .check_content_type(MIME_TYPE_JSON)
        .map_err(|err_msg| DiscoveryError::Response(discover_response.status_code, err_msg))?;

    let provider_metadata: PM =
        serde_json::from_slice(&discover_response.body).map_err(DiscoveryError::Json)?;

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
    ] : [Clone + Debug + DeserializeOwned + PartialEq + Serialize] {
        // consumes self so that, if validation fails, it doesn't get used
        fn validate(self, issuer_uri: &IssuerUrl) -> Result<Self, DiscoveryError> {
            if self.issuer() != issuer_uri {
                return Err(
                    DiscoveryError::Validation(
                        format!(
                            "unexpected issuer URI `{}` (expected `{}`); this may indicate an \
                                OpenID Provider impersonation attack",
                            self.issuer().url(),
                            issuer_uri.url()
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
        #[serde(skip_serializing_if="Option::is_none")]
        token_endpoint(Option<&TokenUrl>) <- Option<TokenUrl>,
        #[serde(skip_serializing_if="Option::is_none")]
        userinfo_endpoint(Option<&UserInfoUrl>) <- Option<UserInfoUrl>,
        #[serde(skip_serializing_if="Option::is_none")]
        jwks_uri(Option<&JsonWebKeySetUrl>) <- Option<JsonWebKeySetUrl>,
        #[serde(skip_serializing_if="Option::is_none")]
        registration_endpoint(Option<&RegistrationUrl>) <- Option<RegistrationUrl>,
        #[serde(skip_serializing_if="Option::is_none")]
        scopes_supported(Option<&Vec<Scope>>) <- Option<Vec<Scope>>,
        #[serde(bound(deserialize = "RT: ResponseType"))]
        response_types_supported(&Vec<ResponseTypes<RT>>) <- Vec<ResponseTypes<RT>>,
        #[serde(bound(deserialize = "RM: ResponseMode"), skip_serializing_if="Option::is_none")]
        response_modes_supported(Option<&Vec<RM>>) <- Option<Vec<RM>>,
        #[serde(bound(deserialize = "G: GrantType"), skip_serializing_if="Option::is_none")]
        grant_types_supported(Option<&Vec<G>>) <- Option<Vec<G>>,
        #[serde(skip_serializing_if="Option::is_none")]
        acr_values_supported(Option<&Vec<AuthenticationContextClass>>)
            <- Option<Vec<AuthenticationContextClass>>,
        #[serde(bound(deserialize = "S: SubjectIdentifierType"))]
        subject_types_supported(&Vec<S>) <- Vec<S>,
        #[serde(bound(deserialize = "JS: JwsSigningAlgorithm<JT>"))]
        id_token_signing_alg_values_supported(&Vec<JS>) <- Vec<JS>,
        #[serde(bound(deserialize = "JK: JweKeyManagementAlgorithm"), skip_serializing_if="Option::is_none")]
        id_token_encryption_alg_values_supported(Option<&Vec<JK>>) <- Option<Vec<JK>>,
        #[serde(bound(deserialize = "JE: JweContentEncryptionAlgorithm"), skip_serializing_if="Option::is_none")]
        id_token_encryption_enc_values_supported(Option<&Vec<JE>>) <- Option<Vec<JE>>,
        #[serde(bound(deserialize = "JS: JwsSigningAlgorithm<JT>"), skip_serializing_if="Option::is_none")]
        userinfo_signing_alg_values_supported(Option<&Vec<JS>>) <- Option<Vec<JS>>,
        #[serde(bound(deserialize = "JK: JweKeyManagementAlgorithm"), skip_serializing_if="Option::is_none")]
        userinfo_encryption_alg_values_supported(Option<&Vec<JK>>) <- Option<Vec<JK>>,
        #[serde(bound(deserialize = "JE: JweContentEncryptionAlgorithm"), skip_serializing_if="Option::is_none")]
        userinfo_encryption_enc_values_supported(Option<&Vec<JE>>) <- Option<Vec<JE>>,
        #[serde(bound(deserialize = "JS: JwsSigningAlgorithm<JT>"), skip_serializing_if="Option::is_none")]
        request_object_signing_alg_values_supported(Option<&Vec<JS>>) <- Option<Vec<JS>>,
        #[serde(bound(deserialize = "JK: JweKeyManagementAlgorithm"), skip_serializing_if="Option::is_none")]
        request_object_encryption_alg_values_supported(Option<&Vec<JK>>) <- Option<Vec<JK>>,
        #[serde(bound(deserialize = "JE: JweContentEncryptionAlgorithm"), skip_serializing_if="Option::is_none")]
        request_object_encryption_enc_values_supported(Option<&Vec<JE>>) <- Option<Vec<JE>>,
        #[serde(bound(deserialize = "CA: ClientAuthMethod"), skip_serializing_if="Option::is_none")]
        token_endpoint_auth_methods_supported(Option<&Vec<CA>>) <- Option<Vec<CA>>,
        #[serde(bound(deserialize = "JS: JwsSigningAlgorithm<JT>"), skip_serializing_if="Option::is_none")]
        token_endpoint_auth_signing_alg_values_supported(Option<&Vec<JS>>) <- Option<Vec<JS>>,
        #[serde(bound(deserialize = "AD: AuthDisplay"), skip_serializing_if="Option::is_none")]
        display_values_supported(Option<&Vec<AD>>) <- Option<Vec<AD>>,
        #[serde(bound(deserialize = "CT: ClaimType"), skip_serializing_if="Option::is_none")]
        claim_types_supported(Option<&Vec<CT>>) <- Option<Vec<CT>>,
        #[serde(bound(deserialize = "CN: ClaimName"), skip_serializing_if="Option::is_none")]
        claims_supported(Option<&Vec<CN>>) <- Option<Vec<CN>>,
        #[serde(skip_serializing_if="Option::is_none")]
        service_documentation(Option<&ServiceDocUrl>) <- Option<ServiceDocUrl>,
        #[serde(skip_serializing_if="Option::is_none")]
        claims_locales_supported(Option<&Vec<LanguageTag>>) <- Option<Vec<LanguageTag>>,
        #[serde(skip_serializing_if="Option::is_none")]
        ui_locales_supported(Option<&Vec<LanguageTag>>) <- Option<Vec<LanguageTag>>,
        #[serde(skip_serializing_if="Option::is_none")]
        claims_parameter_supported(Option<bool>) <- Option<bool>,
        #[serde(skip_serializing_if="Option::is_none")]
        request_parameter_supported(Option<bool>) <- Option<bool>,
        #[serde(skip_serializing_if="Option::is_none")]
        request_uri_parameter_supported(Option<bool>) <- Option<bool>,
        #[serde(skip_serializing_if="Option::is_none")]
        require_request_uri_registration(Option<bool>) <- Option<bool>,
        #[serde(skip_serializing_if="Option::is_none")]
        op_policy_uri(Option<&OpPolicyUrl>) <- Option<OpPolicyUrl>,
        #[serde(skip_serializing_if="Option::is_none")]
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

// FIXME: clean up Display/Debug/cause for this and other Fail impls
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

new_url_type![
    JsonWebKeySetUrl
    impl {
        // FIXME: don't depend on super::discovery in this module (factor this out into some kind
        // of HttpError?
        pub fn get_keys<JS, JT, JU, K>(
            &self
        ) -> Result<JsonWebKeySet<JS, JT, JU, K>, DiscoveryError>
        where JS: JwsSigningAlgorithm<JT>,
                JT: JsonWebKeyType,
                JU: JsonWebKeyUse,
                K: JsonWebKey<JS, JT, JU> {
            let key_response =
                HttpRequest {
                    url: &self.0,
                    method: HttpRequestMethod::Get,
                    headers: &vec![ACCEPT_JSON],
                    post_body: &vec![],
                }
                .request()
            .map_err(DiscoveryError::Request)?;

            // FIXME: improve error handling (i.e., is there a body response?)
            // possibly consolidate this error handling with discovery::get_provider_metadata().
            if key_response.status_code != HTTP_STATUS_OK {
                return Err(
                    DiscoveryError::Response(
                        key_response.status_code,
                        "unexpected HTTP status code".to_string()
                    )
                );
            }

            key_response
                .check_content_type(MIME_TYPE_JSON)
                .map_err(|err_msg| DiscoveryError::Response(key_response.status_code, err_msg))?;

            serde_json::from_slice(&key_response.body).map_err(DiscoveryError::Json)
        }
    }
];

#[cfg(test)]
mod tests {
    use oauth2::prelude::*;
    use oauth2::{AuthUrl, Scope, TokenUrl};
    use url::Url;

    use super::super::core::{
        CoreAuthDisplay, CoreClaimName, CoreClaimType, CoreClientAuthMethod, CoreGrantType,
        CoreJweContentEncryptionAlgorithm, CoreJweKeyManagementAlgorithm, CoreJwsSigningAlgorithm,
        CoreProviderMetadata, CoreResponseMode, CoreResponseType, CoreSubjectIdentifierType,
    };
    use super::super::{
        AuthenticationContextClass, IssuerUrl, LanguageTag, OpPolicyUrl, OpTosUrl, RegistrationUrl,
        ResponseTypes, ServiceDocUrl, UserInfoUrl,
    };
    use super::{JsonWebKeySetUrl, ProviderMetadata};

    #[test]
    fn test_discovery_deserialization() {
        // Fetched from: https://rp.certification.openid.net:8080/openidconnect-rs/
        //     rp-response_type-code/.well-known/openid-configuration
        let json_response = "{
        \"request_object_signing_alg_values_supported\" : [
           \"RS256\",
           \"RS384\",
           \"RS512\",
           \"ES256\",
           \"ES384\",
           \"ES512\",
           \"HS256\",
           \"HS384\",
           \"HS512\",
           \"PS256\",
           \"PS384\",
           \"PS512\",
           \"none\"
        ],
        \"subject_types_supported\" : [
           \"public\",
           \"pairwise\"
        ],
        \"end_session_endpoint\" : \"https://rp.certification.openid.net:8080/openidconnect-rs/rp-response_type-code/end_session\",
        \"token_endpoint_auth_signing_alg_values_supported\" : [
           \"RS256\",
           \"RS384\",
           \"RS512\",
           \"ES256\",
           \"ES384\",
           \"ES512\",
           \"HS256\",
           \"HS384\",
           \"HS512\",
           \"PS256\",
           \"PS384\",
           \"PS512\"
        ],
        \"scopes_supported\" : [
           \"email\",
           \"phone\",
           \"profile\",
           \"openid\",
           \"address\",
           \"offline_access\",
           \"openid\"
        ],
        \"userinfo_signing_alg_values_supported\" : [
           \"RS256\",
           \"RS384\",
           \"RS512\",
           \"ES256\",
           \"ES384\",
           \"ES512\",
           \"HS256\",
           \"HS384\",
           \"HS512\",
           \"PS256\",
           \"PS384\",
           \"PS512\",
           \"none\"
        ],
        \"id_token_encryption_enc_values_supported\" : [
           \"A128CBC-HS256\",
           \"A192CBC-HS384\",
           \"A256CBC-HS512\",
           \"A128GCM\",
           \"A192GCM\",
           \"A256GCM\"
        ],
        \"grant_types_supported\" : [
           \"authorization_code\",
           \"implicit\",
           \"urn:ietf:params:oauth:grant-type:jwt-bearer\",
           \"refresh_token\"
        ],
        \"response_modes_supported\" : [
           \"query\",
           \"fragment\",
           \"form_post\"
        ],
        \"require_request_uri_registration\" : true,
        \"registration_endpoint\" : \"https://rp.certification.openid.net:8080/openidconnect-rs/rp-response_type-code/registration\",
        \"response_types_supported\" : [
           \"code\"
        ],
        \"claims_parameter_supported\" : true,
        \"request_object_encryption_enc_values_supported\" : [
           \"A128CBC-HS256\",
           \"A192CBC-HS384\",
           \"A256CBC-HS512\",
           \"A128GCM\",
           \"A192GCM\",
           \"A256GCM\"
        ],
        \"userinfo_endpoint\" : \"https://rp.certification.openid.net:8080/openidconnect-rs/rp-response_type-code/userinfo\",
        \"id_token_signing_alg_values_supported\" : [
           \"RS256\",
           \"RS384\",
           \"RS512\",
           \"ES256\",
           \"ES384\",
           \"ES512\",
           \"HS256\",
           \"HS384\",
           \"HS512\",
           \"PS256\",
           \"PS384\",
           \"PS512\",
           \"none\"
        ],
        \"token_endpoint_auth_methods_supported\" : [
           \"client_secret_post\",
           \"client_secret_basic\",
           \"client_secret_jwt\",
           \"private_key_jwt\"
        ],
        \"claims_supported\" : [
           \"name\",
           \"given_name\",
           \"middle_name\",
           \"picture\",
           \"email_verified\",
           \"birthdate\",
           \"sub\",
           \"address\",
           \"zoneinfo\",
           \"email\",
           \"gender\",
           \"preferred_username\",
           \"family_name\",
           \"website\",
           \"profile\",
           \"phone_number_verified\",
           \"nickname\",
           \"updated_at\",
           \"phone_number\",
           \"locale\"
        ],
        \"issuer\" : \"https://rp.certification.openid.net:8080/openidconnect-rs/rp-response_type-code\",
        \"request_object_encryption_alg_values_supported\" : [
           \"RSA1_5\",
           \"RSA-OAEP\",
           \"RSA-OAEP-256\",
           \"A128KW\",
           \"A192KW\",
           \"A256KW\",
           \"ECDH-ES\",
           \"ECDH-ES+A128KW\",
           \"ECDH-ES+A192KW\",
           \"ECDH-ES+A256KW\"
        ],
        \"jwks_uri\" : \"https://rp.certification.openid.net:8080/static/jwks_3INbZl52IrrPCp2j.json\",
        \"claim_types_supported\" : [
           \"normal\",
           \"aggregated\",
           \"distributed\"
        ],
        \"request_uri_parameter_supported\" : true,
        \"request_parameter_supported\" : true,
        \"token_endpoint\" : \"https://rp.certification.openid.net:8080/openidconnect-rs/rp-response_type-code/token\",
        \"authorization_endpoint\" : \"https://rp.certification.openid.net:8080/openidconnect-rs/rp-response_type-code/authorization\",
        \"version\" : \"3.0\",
        \"id_token_encryption_alg_values_supported\" : [
           \"RSA1_5\",
           \"RSA-OAEP\",
           \"RSA-OAEP-256\",
           \"A128KW\",
           \"A192KW\",
           \"A256KW\",
           \"ECDH-ES\",
           \"ECDH-ES+A128KW\",
           \"ECDH-ES+A192KW\",
           \"ECDH-ES+A256KW\"
        ],
        \"userinfo_encryption_alg_values_supported\" : [
           \"RSA1_5\",
           \"RSA-OAEP\",
           \"RSA-OAEP-256\",
           \"A128KW\",
           \"A192KW\",
           \"A256KW\",
           \"ECDH-ES\",
           \"ECDH-ES+A128KW\",
           \"ECDH-ES+A192KW\",
           \"ECDH-ES+A256KW\"
        ],
        \"userinfo_encryption_enc_values_supported\" : [
           \"A128CBC-HS256\",
           \"A192CBC-HS384\",
           \"A256CBC-HS512\",
           \"A128GCM\",
           \"A192GCM\",
           \"A256GCM\"
        ],
        \"acr_values_supported\" : [
           \"PASSWORD\"
        ]
    }";

        let provider_metadata: CoreProviderMetadata = serde_json::from_str(json_response).unwrap();

        assert_eq!(
            IssuerUrl::new(
                "https://rp.certification.openid.net:8080/openidconnect-rs/rp-response_type-code"
                    .to_string()
            )
            .unwrap(),
            *provider_metadata.issuer()
        );
        assert_eq!(
            AuthUrl::new(
                Url::parse(
                    "https://rp.certification.openid.net:8080/openidconnect-rs/rp-response_type-code\
                 /authorization"
                )
                    .unwrap()
            ),
            *provider_metadata.authorization_endpoint()
        );
        assert_eq!(
            Some(&TokenUrl::new(
                Url::parse(
                    "https://rp.certification.openid.net:8080/openidconnect-rs\
                     /rp-response_type-code/token"
                )
                .unwrap()
            )),
            provider_metadata.token_endpoint()
        );
        assert_eq!(
            Some(
                &UserInfoUrl::new(
                    "https://rp.certification.openid.net:8080/openidconnect-rs\
                     /rp-response_type-code/userinfo"
                        .to_string()
                )
                .unwrap()
            ),
            provider_metadata.userinfo_endpoint()
        );
        assert_eq!(
            Some(
                &JsonWebKeySetUrl::new(
                    "https://rp.certification.openid.net:8080/static/jwks_3INbZl52IrrPCp2j.json"
                        .to_string()
                )
                .unwrap()
            ),
            provider_metadata.jwks_uri()
        );
        assert_eq!(
            Some(
                &RegistrationUrl::new(
                    "https://rp.certification.openid.net:8080/openidconnect-rs\
                     /rp-response_type-code/registration"
                        .to_string()
                )
                .unwrap()
            ),
            provider_metadata.registration_endpoint()
        );
        assert_eq!(
            Some(
                &vec![
                    "email",
                    "phone",
                    "profile",
                    "openid",
                    "address",
                    "offline_access",
                    "openid",
                ]
                .iter()
                .map(|s| s.to_string())
                .map(Scope::new)
                .collect::<Vec<_>>()
            ),
            provider_metadata.scopes_supported()
        );
        assert_eq!(
            vec![ResponseTypes::new(vec![CoreResponseType::Code])],
            *provider_metadata.response_types_supported()
        );
        assert_eq!(
            Some(&vec![
                CoreResponseMode::Query,
                CoreResponseMode::Fragment,
                CoreResponseMode::FormPost,
            ]),
            provider_metadata.response_modes_supported()
        );
        assert_eq!(
            Some(
                &vec![
                    CoreGrantType::AuthorizationCode,
                    CoreGrantType::Implicit,
                    CoreGrantType::Extension(
                        "urn:ietf:params:oauth:grant-type:jwt-bearer".to_string()
                    ),
                    CoreGrantType::RefreshToken,
                ]
                .into_iter()
                .collect::<Vec<_>>()
            ),
            provider_metadata.grant_types_supported()
        );
        assert_eq!(
            Some(&vec![AuthenticationContextClass::new(
                "PASSWORD".to_string(),
            )]),
            provider_metadata.acr_values_supported()
        );
        assert_eq!(
            vec![
                CoreSubjectIdentifierType::Public,
                CoreSubjectIdentifierType::Pairwise,
            ],
            *provider_metadata.subject_types_supported()
        );
        assert_eq!(
            vec![
                CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
                CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha384,
                CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha512,
                CoreJwsSigningAlgorithm::EcdsaP256Sha256,
                CoreJwsSigningAlgorithm::EcdsaP384Sha384,
                CoreJwsSigningAlgorithm::EcdsaP521Sha512,
                CoreJwsSigningAlgorithm::HmacSha256,
                CoreJwsSigningAlgorithm::HmacSha384,
                CoreJwsSigningAlgorithm::HmacSha512,
                CoreJwsSigningAlgorithm::RsaSsaPssSha256,
                CoreJwsSigningAlgorithm::RsaSsaPssSha384,
                CoreJwsSigningAlgorithm::RsaSsaPssSha512,
                CoreJwsSigningAlgorithm::None,
            ],
            *provider_metadata.id_token_signing_alg_values_supported()
        );
        assert_eq!(
            Some(&vec![
                CoreJweKeyManagementAlgorithm::RsaPkcs1V15,
                CoreJweKeyManagementAlgorithm::RsaOaep,
                CoreJweKeyManagementAlgorithm::RsaOaepSha256,
                CoreJweKeyManagementAlgorithm::AesKeyWrap128,
                CoreJweKeyManagementAlgorithm::AesKeyWrap192,
                CoreJweKeyManagementAlgorithm::AesKeyWrap256,
                CoreJweKeyManagementAlgorithm::EcdhEs,
                CoreJweKeyManagementAlgorithm::EcdhEsAesKeyWrap128,
                CoreJweKeyManagementAlgorithm::EcdhEsAesKeyWrap192,
                CoreJweKeyManagementAlgorithm::EcdhEsAesKeyWrap256,
            ]),
            provider_metadata.id_token_encryption_alg_values_supported()
        );
        assert_eq!(
            Some(&vec![
                CoreJweContentEncryptionAlgorithm::Aes128CbcHmacSha256,
                CoreJweContentEncryptionAlgorithm::Aes192CbcHmacSha384,
                CoreJweContentEncryptionAlgorithm::Aes256CbcHmacSha512,
                CoreJweContentEncryptionAlgorithm::Aes128Gcm,
                CoreJweContentEncryptionAlgorithm::Aes192Gcm,
                CoreJweContentEncryptionAlgorithm::Aes256Gcm,
            ]),
            provider_metadata.id_token_encryption_enc_values_supported()
        );
        assert_eq!(
            Some(&vec![
                CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
                CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha384,
                CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha512,
                CoreJwsSigningAlgorithm::EcdsaP256Sha256,
                CoreJwsSigningAlgorithm::EcdsaP384Sha384,
                CoreJwsSigningAlgorithm::EcdsaP521Sha512,
                CoreJwsSigningAlgorithm::HmacSha256,
                CoreJwsSigningAlgorithm::HmacSha384,
                CoreJwsSigningAlgorithm::HmacSha512,
                CoreJwsSigningAlgorithm::RsaSsaPssSha256,
                CoreJwsSigningAlgorithm::RsaSsaPssSha384,
                CoreJwsSigningAlgorithm::RsaSsaPssSha512,
                CoreJwsSigningAlgorithm::None,
            ]),
            provider_metadata.userinfo_signing_alg_values_supported()
        );
        assert_eq!(
            Some(&vec![
                CoreJweKeyManagementAlgorithm::RsaPkcs1V15,
                CoreJweKeyManagementAlgorithm::RsaOaep,
                CoreJweKeyManagementAlgorithm::RsaOaepSha256,
                CoreJweKeyManagementAlgorithm::AesKeyWrap128,
                CoreJweKeyManagementAlgorithm::AesKeyWrap192,
                CoreJweKeyManagementAlgorithm::AesKeyWrap256,
                CoreJweKeyManagementAlgorithm::EcdhEs,
                CoreJweKeyManagementAlgorithm::EcdhEsAesKeyWrap128,
                CoreJweKeyManagementAlgorithm::EcdhEsAesKeyWrap192,
                CoreJweKeyManagementAlgorithm::EcdhEsAesKeyWrap256,
            ]),
            provider_metadata.userinfo_encryption_alg_values_supported()
        );
        assert_eq!(
            Some(&vec![
                CoreJweContentEncryptionAlgorithm::Aes128CbcHmacSha256,
                CoreJweContentEncryptionAlgorithm::Aes192CbcHmacSha384,
                CoreJweContentEncryptionAlgorithm::Aes256CbcHmacSha512,
                CoreJweContentEncryptionAlgorithm::Aes128Gcm,
                CoreJweContentEncryptionAlgorithm::Aes192Gcm,
                CoreJweContentEncryptionAlgorithm::Aes256Gcm,
            ]),
            provider_metadata.userinfo_encryption_enc_values_supported()
        );
        assert_eq!(
            Some(&vec![
                CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
                CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha384,
                CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha512,
                CoreJwsSigningAlgorithm::EcdsaP256Sha256,
                CoreJwsSigningAlgorithm::EcdsaP384Sha384,
                CoreJwsSigningAlgorithm::EcdsaP521Sha512,
                CoreJwsSigningAlgorithm::HmacSha256,
                CoreJwsSigningAlgorithm::HmacSha384,
                CoreJwsSigningAlgorithm::HmacSha512,
                CoreJwsSigningAlgorithm::RsaSsaPssSha256,
                CoreJwsSigningAlgorithm::RsaSsaPssSha384,
                CoreJwsSigningAlgorithm::RsaSsaPssSha512,
                CoreJwsSigningAlgorithm::None,
            ]),
            provider_metadata.request_object_signing_alg_values_supported()
        );
        assert_eq!(
            Some(&vec![
                CoreJweKeyManagementAlgorithm::RsaPkcs1V15,
                CoreJweKeyManagementAlgorithm::RsaOaep,
                CoreJweKeyManagementAlgorithm::RsaOaepSha256,
                CoreJweKeyManagementAlgorithm::AesKeyWrap128,
                CoreJweKeyManagementAlgorithm::AesKeyWrap192,
                CoreJweKeyManagementAlgorithm::AesKeyWrap256,
                CoreJweKeyManagementAlgorithm::EcdhEs,
                CoreJweKeyManagementAlgorithm::EcdhEsAesKeyWrap128,
                CoreJweKeyManagementAlgorithm::EcdhEsAesKeyWrap192,
                CoreJweKeyManagementAlgorithm::EcdhEsAesKeyWrap256,
            ]),
            provider_metadata.request_object_encryption_alg_values_supported()
        );
        assert_eq!(
            Some(&vec![
                CoreJweContentEncryptionAlgorithm::Aes128CbcHmacSha256,
                CoreJweContentEncryptionAlgorithm::Aes192CbcHmacSha384,
                CoreJweContentEncryptionAlgorithm::Aes256CbcHmacSha512,
                CoreJweContentEncryptionAlgorithm::Aes128Gcm,
                CoreJweContentEncryptionAlgorithm::Aes192Gcm,
                CoreJweContentEncryptionAlgorithm::Aes256Gcm,
            ]),
            provider_metadata.request_object_encryption_enc_values_supported()
        );
        assert_eq!(
            Some(&vec![
                CoreClientAuthMethod::ClientSecretPost,
                CoreClientAuthMethod::ClientSecretBasic,
                CoreClientAuthMethod::ClientSecretJwt,
                CoreClientAuthMethod::PrivateKeyJwt,
            ]),
            provider_metadata.token_endpoint_auth_methods_supported()
        );
        assert_eq!(
            Some(&vec![
                CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
                CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha384,
                CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha512,
                CoreJwsSigningAlgorithm::EcdsaP256Sha256,
                CoreJwsSigningAlgorithm::EcdsaP384Sha384,
                CoreJwsSigningAlgorithm::EcdsaP521Sha512,
                CoreJwsSigningAlgorithm::HmacSha256,
                CoreJwsSigningAlgorithm::HmacSha384,
                CoreJwsSigningAlgorithm::HmacSha512,
                CoreJwsSigningAlgorithm::RsaSsaPssSha256,
                CoreJwsSigningAlgorithm::RsaSsaPssSha384,
                CoreJwsSigningAlgorithm::RsaSsaPssSha512,
            ]),
            provider_metadata.token_endpoint_auth_signing_alg_values_supported()
        );
        assert_eq!(None, provider_metadata.display_values_supported());
        assert_eq!(
            Some(&vec![
                CoreClaimType::Normal,
                CoreClaimType::Aggregated,
                CoreClaimType::Distributed,
            ]),
            provider_metadata.claim_types_supported()
        );
        assert_eq!(
            Some(&vec![
                CoreClaimName::new("name".to_string()),
                CoreClaimName::new("given_name".to_string()),
                CoreClaimName::new("middle_name".to_string()),
                CoreClaimName::new("picture".to_string()),
                CoreClaimName::new("email_verified".to_string()),
                CoreClaimName::new("birthdate".to_string()),
                CoreClaimName::new("sub".to_string()),
                CoreClaimName::new("address".to_string()),
                CoreClaimName::new("zoneinfo".to_string()),
                CoreClaimName::new("email".to_string()),
                CoreClaimName::new("gender".to_string()),
                CoreClaimName::new("preferred_username".to_string()),
                CoreClaimName::new("family_name".to_string()),
                CoreClaimName::new("website".to_string()),
                CoreClaimName::new("profile".to_string()),
                CoreClaimName::new("phone_number_verified".to_string()),
                CoreClaimName::new("nickname".to_string()),
                CoreClaimName::new("updated_at".to_string()),
                CoreClaimName::new("phone_number".to_string()),
                CoreClaimName::new("locale".to_string()),
            ]),
            provider_metadata.claims_supported()
        );
        assert_eq!(None, provider_metadata.service_documentation());
        assert_eq!(None, provider_metadata.claims_locales_supported());
        assert_eq!(None, provider_metadata.ui_locales_supported());
        assert_eq!(Some(true), provider_metadata.claims_parameter_supported());
        assert_eq!(Some(true), provider_metadata.request_parameter_supported());
        assert_eq!(
            Some(true),
            provider_metadata.request_uri_parameter_supported()
        );
        assert_eq!(
            Some(true),
            provider_metadata.require_request_uri_registration()
        );
        assert_eq!(None, provider_metadata.op_policy_uri());
        assert_eq!(None, provider_metadata.op_tos_uri());

        // Note: the following fields provided by the response above are not part of the OpenID
        // Connect Discovery 1.0 spec:
        // - end_session_endpoint
        // - version

        let serialized_json = serde_json::to_string(&provider_metadata).unwrap();

        let redeserialized_metadata: CoreProviderMetadata =
            serde_json::from_str(&serialized_json).unwrap();
        assert_eq!(provider_metadata, redeserialized_metadata);
    }

    // Tests the fields missing from the example response in test_discovery_deserialization().
    #[test]
    fn test_discovery_deserialization_other_fields() {
        let json_response = "{
        \"issuer\" : \"https://rp.certification.openid.net:8080/openidconnect-rs/rp-response_type-code\",
        \"authorization_endpoint\" : \"https://rp.certification.openid.net:8080/openidconnect-rs/rp-response_type-code/authorization\",
        \"response_types_supported\" : [
           \"code\",
           \"code token\",
           \"code id_token\",
           \"id_token token\",
           \"code id_token token\",
           \"token id_token\",
           \"token id_token code\",
           \"id_token\",
           \"token\"
        ],
        \"subject_types_supported\" : [
           \"public\",
           \"pairwise\"
        ],
        \"id_token_signing_alg_values_supported\" : [
           \"HS256\",
           \"HS384\",
           \"HS512\"
        ],
        \"display_values_supported\" : [
           \"page\",
           \"popup\",
           \"touch\",
           \"wap\"
        ],
        \"service_documentation\" : \"https://rp.certification.openid.net:8080/openidconnect-rs/rp-response_type-code/documentation\",
        \"claims_locales_supported\" : [
           \"de\",
           \"fr\",
           \"de-CH-1901\"
        ],
        \"ui_locales_supported\" : [
           \"ja\",
           \"sr-Latn\",
           \"yue-HK\"
        ],
        \"op_policy_uri\" : \"https://rp.certification.openid.net:8080/openidconnect-rs/rp-response_type-code/op_policy\",
        \"op_tos_uri\" : \"https://rp.certification.openid.net:8080/openidconnect-rs/rp-response_type-code/op_tos\"
    }";

        let provider_metadata: CoreProviderMetadata = serde_json::from_str(json_response).unwrap();

        assert_eq!(
            IssuerUrl::new(
                "https://rp.certification.openid.net:8080/openidconnect-rs/rp-response_type-code"
                    .to_string()
            )
            .unwrap(),
            *provider_metadata.issuer()
        );
        assert_eq!(
            AuthUrl::new(
                Url::parse(
                    "https://rp.certification.openid.net:8080/openidconnect-rs/rp-response_type-code\
                 /authorization"
                )
                    .unwrap()
            ),
            *provider_metadata.authorization_endpoint()
        );
        assert_eq!(None, provider_metadata.token_endpoint());
        assert_eq!(None, provider_metadata.userinfo_endpoint());
        assert_eq!(None, provider_metadata.jwks_uri());
        assert_eq!(None, provider_metadata.registration_endpoint());
        assert_eq!(None, provider_metadata.scopes_supported());
        assert_eq!(
            vec![
                ResponseTypes::new(vec![CoreResponseType::Code]),
                ResponseTypes::new(vec![CoreResponseType::Code, CoreResponseType::Token]),
                ResponseTypes::new(vec![CoreResponseType::Code, CoreResponseType::IdToken]),
                ResponseTypes::new(vec![CoreResponseType::IdToken, CoreResponseType::Token]),
                ResponseTypes::new(vec![
                    CoreResponseType::Code,
                    CoreResponseType::IdToken,
                    CoreResponseType::Token,
                ]),
                ResponseTypes::new(vec![CoreResponseType::Token, CoreResponseType::IdToken]),
                ResponseTypes::new(vec![
                    CoreResponseType::Token,
                    CoreResponseType::IdToken,
                    CoreResponseType::Code,
                ]),
                ResponseTypes::new(vec![CoreResponseType::IdToken]),
                ResponseTypes::new(vec![CoreResponseType::Token]),
            ],
            *provider_metadata.response_types_supported()
        );
        assert_eq!(None, provider_metadata.response_modes_supported());
        assert_eq!(None, provider_metadata.grant_types_supported());
        assert_eq!(None, provider_metadata.acr_values_supported());
        assert_eq!(
            vec![
                CoreSubjectIdentifierType::Public,
                CoreSubjectIdentifierType::Pairwise,
            ],
            *provider_metadata.subject_types_supported()
        );
        assert_eq!(
            vec![
                CoreJwsSigningAlgorithm::HmacSha256,
                CoreJwsSigningAlgorithm::HmacSha384,
                CoreJwsSigningAlgorithm::HmacSha512,
            ],
            *provider_metadata.id_token_signing_alg_values_supported()
        );
        assert_eq!(
            None,
            provider_metadata.id_token_encryption_alg_values_supported()
        );
        assert_eq!(
            None,
            provider_metadata.id_token_encryption_enc_values_supported()
        );
        assert_eq!(
            None,
            provider_metadata.userinfo_signing_alg_values_supported()
        );
        assert_eq!(
            None,
            provider_metadata.userinfo_encryption_alg_values_supported()
        );
        assert_eq!(
            None,
            provider_metadata.userinfo_encryption_enc_values_supported()
        );
        assert_eq!(
            None,
            provider_metadata.request_object_signing_alg_values_supported()
        );
        assert_eq!(
            None,
            provider_metadata.request_object_encryption_alg_values_supported()
        );
        assert_eq!(
            None,
            provider_metadata.request_object_encryption_enc_values_supported()
        );
        assert_eq!(
            None,
            provider_metadata.token_endpoint_auth_methods_supported()
        );
        assert_eq!(
            None,
            provider_metadata.token_endpoint_auth_signing_alg_values_supported()
        );
        assert_eq!(
            Some(&vec![
                CoreAuthDisplay::Page,
                CoreAuthDisplay::Popup,
                CoreAuthDisplay::Touch,
                CoreAuthDisplay::Wap,
            ]),
            provider_metadata.display_values_supported()
        );
        assert_eq!(None, provider_metadata.claim_types_supported());
        assert_eq!(None, provider_metadata.claims_supported());

        assert_eq!(
            Some(
                &ServiceDocUrl::new(
                    "https://rp.certification.openid.net:8080/openidconnect-rs/rp-response_type-code\
                 /documentation"
                        .to_string()
                )
                    .unwrap()
            ),
            provider_metadata.service_documentation()
        );
        assert_eq!(
            Some(&vec![
                LanguageTag::new("de".to_string()),
                LanguageTag::new("fr".to_string()),
                LanguageTag::new("de-CH-1901".to_string()),
            ]),
            provider_metadata.claims_locales_supported()
        );
        assert_eq!(
            Some(&vec![
                LanguageTag::new("ja".to_string()),
                LanguageTag::new("sr-Latn".to_string()),
                LanguageTag::new("yue-HK".to_string()),
            ]),
            provider_metadata.ui_locales_supported()
        );
        assert_eq!(None, provider_metadata.claims_parameter_supported());
        assert_eq!(None, provider_metadata.request_parameter_supported());
        assert_eq!(None, provider_metadata.request_uri_parameter_supported());
        assert_eq!(None, provider_metadata.require_request_uri_registration());
        assert_eq!(
            Some(
                &OpPolicyUrl::new(
                    "https://rp.certification.openid.net:8080/openidconnect-rs/rp-response_type-code\
                 /op_policy"
                        .to_string()
                )
                    .unwrap()
            ),
            provider_metadata.op_policy_uri()
        );
        assert_eq!(
            Some(
                &OpTosUrl::new(
                    "https://rp.certification.openid.net:8080/openidconnect-rs/rp-response_type-code\
                 /op_tos"
                        .to_string()
                )
                    .unwrap()
            ),
            provider_metadata.op_tos_uri()
        );

        let serialized_json = serde_json::to_string(&provider_metadata).unwrap();

        let redeserialized_metadata: CoreProviderMetadata =
            serde_json::from_str(&serialized_json).unwrap();
        assert_eq!(provider_metadata, redeserialized_metadata);
    }
}
