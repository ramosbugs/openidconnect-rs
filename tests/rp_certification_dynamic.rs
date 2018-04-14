
extern crate env_logger;
#[macro_use] extern crate log;
extern crate oauth2;
extern crate openidconnect;
#[macro_use] extern crate pretty_assertions;
extern crate serde_json;
extern crate url;

use std::sync::{Once, ONCE_INIT};

use oauth2::prelude::*;
use oauth2::RedirectUrl;
use url::Url;

use openidconnect::*;
use openidconnect::core::*;
use openidconnect::discovery::*;
use openidconnect::registration::*;

const CERTIFICATION_BASE_URL: &str = "https://rp.certification.openid.net:8080";
const CERTIFICATION_RP_NAME: &str = "openidconnect-rs";

static INIT_LOG: Once = ONCE_INIT;

macro_rules! log_info {
    ($($args:tt)+) => {
        info!("[{}] {}", TEST_ID, format!($($args)+));
    }
}
macro_rules! log_debug {
    ($($args:tt)+) => {
        debug!("[{}] {}", TEST_ID, format!($($args)+));
    }
}

fn init_log() {
    env_logger::init();
}

fn issuer_url(test_id: &str) -> IssuerUrl {
    IssuerUrl::new(
        Url::parse(
            &format!(
                "{}/{}/{}",
                CERTIFICATION_BASE_URL,
                CERTIFICATION_RP_NAME,
                test_id
            )
        ).expect("Failed to parse issuer URL")
    )
}

#[test]
fn rp_discovery_openid_configuration() {
    const TEST_ID: &str = "rp-discovery-openid-configuration";
    INIT_LOG.call_once(init_log);

    let _issuer_url = issuer_url(TEST_ID);
    let provider_metadata: CoreDiscovery10ProviderMetadata =
        get_provider_metadata(_issuer_url.clone())
            .expect(&format!("Failed to fetch provider metadata from {:?}", _issuer_url));

    macro_rules! log_field {
        ($field:ident) => {
            log_info!(concat!("  ", stringify!($field), " = {:?}"), provider_metadata.$field());
        }
    }

    log_info!("Successfully retrieved provider metadata from {:?}", _issuer_url);
    log_field!(issuer);
    log_field!(authorization_endpoint);
    log_field!(token_endpoint);
    log_field!(userinfo_endpoint);
    log_field!(jwks_uri);
    log_field!(registration_endpoint);
    log_field!(scopes_supported);
    log_field!(response_types_supported);
    log_field!(response_modes_supported);
    log_field!(grant_types_supported);
    log_field!(acr_values_supported);
    log_field!(subject_types_supported);
    log_field!(id_token_signing_alg_values_supported);
    log_field!(id_token_encryption_alg_values_supported);
    log_field!(id_token_encryption_enc_values_supported);
    log_field!(userinfo_signing_alg_values_supported);
    log_field!(userinfo_encryption_alg_values_supported);
    log_field!(userinfo_encryption_enc_values_supported);
    log_field!(request_object_signing_alg_values_supported);
    log_field!(request_object_encryption_alg_values_supported);
    log_field!(request_object_encryption_enc_values_supported);
    log_field!(token_endpoint_auth_methods_supported);
    log_field!(token_endpoint_auth_signing_alg_values_supported);
    log_field!(display_values_supported);
    log_field!(claim_types_supported);
    log_field!(claims_supported);
    log_field!(service_documentation);
    log_field!(claims_locales_supported);
    log_field!(ui_locales_supported);
    log_field!(claims_parameter_supported);
    log_field!(request_parameter_supported);
    log_field!(request_uri_parameter_supported);
    log_field!(require_request_uri_registration);
    log_field!(op_policy_uri);
    log_field!(op_tos_uri);

    log_debug!("Provider metadata: {:?}", provider_metadata);

    log_info!("SUCCESS");
}

#[test]
fn rp_registration_dynamic() {
    const TEST_ID: &str = "rp-registration-dynamic";
    INIT_LOG.call_once(init_log);

    let _issuer_url = issuer_url(TEST_ID);
    let provider_metadata: CoreDiscovery10ProviderMetadata =
        get_provider_metadata(_issuer_url.clone())
            .expect(&format!("Failed to fetch provider metadata from {:?}", _issuer_url));

    let registration_request =
        CoreRegistration10ClientRegistrationRequest::new(
            vec![RedirectUrl::new(Url::parse("https://example.com/redirect").unwrap())]
        )
        .set_application_type(Some(CoreApplicationType::Web))
        .set_client_name(Some(ClientName::new(CERTIFICATION_RP_NAME.to_string())), None)
        .set_contacts(Some(vec![ContactEmail::new("ramos@cs.stanford.edu".to_string())]));

    let registration_endpoint =
        provider_metadata
            .registration_endpoint()
            .expect("provider does not support dynamic registration");
    let registration_response =
        registration_request
            .register(&registration_endpoint)
            .expect(&format!("Failed to register client at {:?}", registration_endpoint));

    macro_rules! log_field {
        ($field:ident) => {
            log_info!(concat!("  ", stringify!($field), " = {:?}"), registration_response.$field());
        }
    }

    log_info!("Successfully registered client at {:?}", registration_endpoint);
    log_field!(client_id);
    log_field!(client_secret);
    log_field!(registration_access_token);
    log_field!(registration_client_uri);
    log_field!(client_id_issued_at);
    log_field!(client_secret_expires_at);
    log_field!(redirect_uris);
    log_field!(response_types);
    log_field!(grant_types);
    log_field!(application_type);
    log_field!(contacts);
    log_field!(client_name);
    log_field!(logo_uri);
    log_field!(client_uri);
    log_field!(policy_uri);
    log_field!(tos_uri);
    log_field!(jwks_uri);
    log_field!(jwks);
    log_field!(sector_identifier_uri);
    log_field!(subject_type);
    log_field!(id_token_signed_response_alg);
    log_field!(id_token_encrypted_response_alg);
    log_field!(id_token_encrypted_response_enc);
    log_field!(userinfo_signed_response_alg);
    log_field!(userinfo_encrypted_response_alg);
    log_field!(userinfo_encrypted_response_enc);
    log_field!(request_object_signing_alg);
    log_field!(request_object_encryption_alg);
    log_field!(request_object_encryption_enc);
    log_field!(token_endpoint_auth_method);
    log_field!(token_endpoint_auth_signing_alg);
    log_field!(default_max_age);
    log_field!(require_auth_time);
    log_field!(default_acr_values);
    log_field!(initiate_login_uri);
    log_field!(request_uris);

    log_debug!("Registration response: {:?}", registration_response);

    assert_eq!(
        format!(
            "https://rp.certification.openid.net:8080/{}/registration?client_id={}",
            CERTIFICATION_RP_NAME,
            registration_response.client_id().to_string()
        ),
        registration_response.registration_client_uri().unwrap().to_string()
    );

    log_info!("SUCCESS");
}
