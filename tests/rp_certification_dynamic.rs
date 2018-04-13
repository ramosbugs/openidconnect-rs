
extern crate env_logger;
#[macro_use] extern crate log;
extern crate oauth2;
extern crate openidconnect;
#[macro_use] extern crate pretty_assertions;
extern crate serde_json;
extern crate url;

use std::sync::{Once, ONCE_INIT};

use oauth2::prelude::*;
use url::Url;

use openidconnect::*;
use openidconnect::core::*;
use openidconnect::discovery::*;

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

fn issuer_url() -> IssuerUrl {
    IssuerUrl::new(
        Url::parse(
            &format!(
                "{}/{}/rp-discovery-openid-configuration",
                CERTIFICATION_BASE_URL,
                CERTIFICATION_RP_NAME
            )
        ).expect("Failed to parse issuer URL")
    )
}

#[test]
fn rp_discovery_openid_configuration() {
    const TEST_ID: &str = "rp-discovery-openid-configuration";
    INIT_LOG.call_once(init_log);

    let _issuer_url = issuer_url();
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

