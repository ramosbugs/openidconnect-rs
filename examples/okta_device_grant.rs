//!
//! This example showcases the process of using the device grant flow to obtain an ID token from the
//! [Okta](https://developer.okta.com/docs/guides/device-authorization-grant/main/#request-the-device-verification-code)
//! provider.
//!
//! Before running it, you'll need to generate your own
//! [Okta Server](https://developer.okta.com/signup/).
//!
//! In order to run the example call:
//!
//! ```sh
//! CLIENT_ID=xxx CLIENT_SECRET=yyy ISSUER_URL=zzz cargo run --example okta_device_grant
//! ```
//!
//! ...and follow the instructions.
//!

use openidconnect::core::{
    CoreAuthDisplay, CoreClaimName, CoreClaimType, CoreClient, CoreClientAuthMethod,
    CoreDeviceAuthorizationResponse, CoreGrantType, CoreJsonWebKey, CoreJsonWebKeyType,
    CoreJsonWebKeyUse, CoreJweContentEncryptionAlgorithm, CoreJweKeyManagementAlgorithm,
    CoreJwsSigningAlgorithm, CoreResponseMode, CoreResponseType, CoreSubjectIdentifierType,
};
use openidconnect::{
    AdditionalProviderMetadata, AuthType, ClientId, ClientSecret, DeviceAuthorizationUrl,
    IssuerUrl, ProviderMetadata, Scope,
};
use std::env;

use serde::{Deserialize, Serialize};

use openidconnect::reqwest::http_client;

use std::process::exit;

// Obtain the device_authorization_url from the OIDC metadata provider.
#[derive(Clone, Debug, Deserialize, Serialize)]
struct DeviceEndpointProviderMetadata {
    device_authorization_endpoint: DeviceAuthorizationUrl,
}
impl AdditionalProviderMetadata for DeviceEndpointProviderMetadata {}
type DeviceProviderMetadata = ProviderMetadata<
    DeviceEndpointProviderMetadata,
    CoreAuthDisplay,
    CoreClientAuthMethod,
    CoreClaimName,
    CoreClaimType,
    CoreGrantType,
    CoreJweContentEncryptionAlgorithm,
    CoreJweKeyManagementAlgorithm,
    CoreJwsSigningAlgorithm,
    CoreJsonWebKeyType,
    CoreJsonWebKeyUse,
    CoreJsonWebKey,
    CoreResponseMode,
    CoreResponseType,
    CoreSubjectIdentifierType,
>;

fn handle_error<T: std::error::Error>(fail: &T, msg: &'static str) {
    let mut err_msg = format!("ERROR: {}", msg);
    let mut cur_fail: Option<&dyn std::error::Error> = Some(fail);
    while let Some(cause) = cur_fail {
        err_msg += &format!("\n    caused by: {}", cause);
        cur_fail = cause.source();
    }
    println!("{}", err_msg);
    exit(1);
}

fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    let client_id =
        ClientId::new(env::var("CLIENT_ID").expect("Missing the CLIENT_ID environment variable."));
    let client_secret = ClientSecret::new(
        env::var("CLIENT_SECRET").expect("Missing the CLIENT_SECRET environment variable."),
    );
    let issuer_url = IssuerUrl::new(
        env::var("ISSUER_URL").expect("Missing the ISSUER_URL environment variable."),
    )
    .expect("Invalid issuer URL");

    // Fetch Okta's OpenID Connect discovery document.
    let provider_metadata = DeviceProviderMetadata::discover(&issuer_url, http_client)
        .unwrap_or_else(|err| {
            handle_error(&err, "Failed to discover OpenID Provider");
            unreachable!();
        });

    // Use the custom metadata to get the device_authorization_endpoint
    let device_authorization_endpoint = provider_metadata
        .additional_metadata()
        .device_authorization_endpoint
        .clone();

    // Set up the config for the Okta device authorization process.
    let client =
        CoreClient::from_provider_metadata(provider_metadata, client_id, Some(client_secret))
            .set_device_authorization_uri(device_authorization_endpoint)
            .set_auth_type(AuthType::RequestBody);

    let details: CoreDeviceAuthorizationResponse = client
        .exchange_device_code()?
        .add_scope(Scope::new("profile".to_string()))
        .request(http_client)
        .expect("Failed to get device code");
    println!("Fetching device code...");
    dbg!(&details);

    // Display the URL and user-code.
    println!(
        "Open this URL in your browser:\n{}\nand enter the code: {}",
        details.verification_uri_complete().unwrap().secret(),
        details.user_code().secret()
    );

    // Now poll for the token
    let token = client
        .exchange_device_access_token(&details)
        .request(http_client, std::thread::sleep, None)
        .expect("Failed to get token");

    // Finally, display the ID Token to verify we are using OIDC
    println!("ID Token response: {:?}", token.extra_fields().id_token());

    Ok(())
}
