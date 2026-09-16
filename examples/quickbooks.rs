//!
//! This example showcases the process of integrating with the
//! [Quickbooks OpenID Connect](https://developer.intuit.com/app/developer/qbo/docs/develop/authentication-and-authorization/openid-connect)
//! provider.
//!
//! Before running it, you'll need to generate your own Quickbooks OAuth2 Sandbox credentials.
//!
//! In order to run the example call:
//!
//! ```sh
//! QB_CLIENT_ID=xxx QB_CLIENT_SECRET=yyy cargo run --example quickbooks
//! ```
//!
//! ...and follow the instructions.
//!

use openidconnect::core::{
    CoreAuthDisplay, CoreClaimName, CoreClaimType, CoreClient, CoreClientAuthMethod, CoreGrantType,
    CoreIdToken, CoreIdTokenClaims, CoreIdTokenVerifier, CoreJsonWebKey,
    CoreJweContentEncryptionAlgorithm, CoreJweKeyManagementAlgorithm, CoreProviderMetadata,
    CoreResponseMode, CoreResponseType, CoreRevocableToken, CoreSubjectIdentifierType,
};
use openidconnect::{reqwest, NonceVerifier};
use openidconnect::{
    AdditionalProviderMetadata, AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret,
    CsrfToken, IssuerUrl, Nonce, OAuth2TokenResponse, ProviderMetadata, RedirectUrl, RevocationUrl,
    Scope,
};
use serde::{Deserialize, Serialize};
use serde_json::Value::Null;
use url::Url;

use std::env;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::process::exit;

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

// Teach openidconnect-rs about a OpenID Discovery response that we can use as the RFC 7009 OAuth
// 2.0 Token Revocation endpoint.
#[derive(Clone, Debug, Deserialize, Serialize)]
struct RevocationEndpointProviderMetadata {
    revocation_endpoint: String,
}
impl AdditionalProviderMetadata for RevocationEndpointProviderMetadata {}
type QuickbooksProviderMetadata = ProviderMetadata<
    RevocationEndpointProviderMetadata,
    CoreAuthDisplay,
    CoreClientAuthMethod,
    CoreClaimName,
    CoreClaimType,
    CoreGrantType,
    CoreJweContentEncryptionAlgorithm,
    CoreJweKeyManagementAlgorithm,
    CoreJsonWebKey,
    CoreResponseMode,
    CoreResponseType,
    CoreSubjectIdentifierType,
>;

fn main() {
    env_logger::init();

    let client_id = ClientId::new(
        env::var("QB_CLIENT_ID").expect("Missing the QB_CLIENT_ID environment variable."),
    );
    let client_secret = ClientSecret::new(
        env::var("QB_CLIENT_SECRET").expect("Missing the QB_CLIENT_SECRET environment variable."),
    );
    // let disc_url = Url::parse("https://developer.api.intuit.com/.well-known/openid-configuration")
    let disc_url =
        Url::parse("https://developer.api.intuit.com/.well-known/openid_sandbox_configuration")
            .unwrap_or_else(|err| {
                handle_error(&err, "Invalid discovery doc URL");
                unreachable!();
            });
    let issuer_url = IssuerUrl::new("https://oauth.platform.intuit.com/op/v1".to_string())
        .unwrap_or_else(|err| {
            handle_error(&err, "Invalid issuer URL");
            unreachable!();
        });

    let http_client = reqwest::blocking::ClientBuilder::new()
        // Following redirects opens the client up to SSRF vulnerabilities.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap_or_else(|err| {
            handle_error(&err, "Failed to build HTTP client");
            unreachable!();
        });

    // Fetch Quickbook's OpenID Connect discovery document.
    //
    // Note: If we don't care about token revocation we can simply use CoreProviderMetadata here
    // instead of QuickbooksProviderMetadata. If instead we wanted to optionally use the token
    // revocation endpoint if it seems to be supported we could do something like this:
    //   #[derive(Clone, Debug, Deserialize, Serialize)]
    //   struct AllOtherProviderMetadata(HashMap<String, serde_json::Value>);
    //   impl AdditionalClaims for AllOtherProviderMetadata {}
    // And then test for the presence of "revocation_endpoint" in the map returned by a call to
    // .additional_metadata().

    let provider_metadata =
        QuickbooksProviderMetadata::discover_with_doc_url(&disc_url, &issuer_url, &http_client)
            .unwrap_or_else(|err| {
                handle_error(&err, "Failed to discover OpenID Provider");
                unreachable!();
            });

    let revocation_endpoint = provider_metadata
        .additional_metadata()
        .revocation_endpoint
        .clone();
    println!(
        "Discovered Quickbooks revocation endpoint: {}",
        revocation_endpoint
    );

    // Set up the config for the Quickbooks OAuth2 process.
    let client =
        CoreClient::from_provider_metadata(provider_metadata, client_id, Some(client_secret))
            // This example will be running its own server at localhost:8080.
            // See below for the server implementation.
            .set_redirect_uri(
                RedirectUrl::new("http://localhost:9999/".to_string()).unwrap_or_else(|err| {
                    handle_error(&err, "Invalid redirect URL");
                    unreachable!();
                }),
            )
            // Quickbooks supports OAuth 2.0 Token Revocation (RFC-7009)
            .set_revocation_url(
                RevocationUrl::new(revocation_endpoint).unwrap_or_else(|err| {
                    handle_error(&err, "Invalid revocation endpoint URL");
                    unreachable!();
                }),
            );

    // Generate the authorization URL to which we'll redirect the user.
    let (authorize_url, csrf_state, nonce) = client
        .authorize_url(
            AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        // This example is requesting access to the "calendar" features and the user's profile.
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .add_scope(Scope::new("address".to_string()))
        .add_scope(Scope::new("phone".to_string()))
        // .add_scope(Scope::new("com.intuit.quickbooks.accounting".to_string()))
        .url();

    println!("Open this URL in your browser:\n{}\n", authorize_url);

    let (code, state) = {
        // A very naive implementation of the redirect server.
        let listener = TcpListener::bind("127.0.0.1:9999").unwrap();

        // Accept one connection
        let (mut stream, _) = listener.accept().unwrap();

        let mut reader = BufReader::new(&stream);

        let mut request_line = String::new();
        reader.read_line(&mut request_line).unwrap();

        let redirect_url = request_line.split_whitespace().nth(1).unwrap();
        let url = Url::parse(&("http://localhost".to_string() + redirect_url)).unwrap();

        let code = url
            .query_pairs()
            .find(|(key, _)| key == "code")
            .map(|(_, code)| AuthorizationCode::new(code.into_owned()))
            .unwrap();

        let state = url
            .query_pairs()
            .find(|(key, _)| key == "state")
            .map(|(_, state)| CsrfToken::new(state.into_owned()))
            .unwrap();

        let message = "Go back to your terminal :)";
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{}",
            message.len(),
            message
        );
        stream.write_all(response.as_bytes()).unwrap();

        (code, state)
    };

    println!(
        "Quickbooks returned the following code:\n{}\n",
        code.secret()
    );
    println!(
        "Quickbooks returned the following state:\n{} (expected `{}`)\n",
        state.secret(),
        csrf_state.secret()
    );

    // Exchange the code with a token.
    let token_response = client
        .exchange_code(code)
        .unwrap_or_else(|err| {
            handle_error(&err, "No user info endpoint");
            unreachable!();
        })
        .request(&http_client)
        .unwrap_or_else(|err| {
            handle_error(&err, "Failed to contact token endpoint");
            unreachable!();
        });

    println!(
        "Quickbooks returned access token:\n{}\n",
        token_response.access_token().secret()
    );
    println!("Quickbooks returned scopes: {:?}", token_response.scopes());

    let id_token_verifier: CoreIdTokenVerifier = client.id_token_verifier();
    // let mut id_token = token_response
    let id_token_claims: &CoreIdTokenClaims = token_response
        .extra_fields()
        .id_token()
        // id_token.set_non
        .expect("Server did not return an ID token")
        .claims(&id_token_verifier, NullNonceVerifier {}) // quickbooks doesn't use nonce
        .unwrap_or_else(|err| {
            handle_error(&err, "Failed to verify ID token");
            unreachable!();
        });
    println!("Quickbooks returned ID token: {:?}", id_token_claims);

    // Revoke the obtained token
    let token_to_revoke: CoreRevocableToken = match token_response.refresh_token() {
        Some(token) => token.into(),
        None => token_response.access_token().into(),
    };

    client
        .revoke_token(token_to_revoke)
        .unwrap_or_else(|err| {
            handle_error(&err, "Failed to revoke token");
            unreachable!();
        })
        .request(&http_client)
        .unwrap_or_else(|err| {
            handle_error(&err, "Failed to revoke token");
            unreachable!();
        });
}

struct NullNonceVerifier {}

impl NonceVerifier for NullNonceVerifier {
    fn verify(self, nonce: Option<&Nonce>) -> Result<(), String> {
        Ok(())
    }
}
