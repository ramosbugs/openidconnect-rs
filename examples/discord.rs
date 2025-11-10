//!
//! This example showcases the process of integrating with the
//! [Discord OpenID Connect](https://discord.com/.well-known/openid-configuration)
//! provider.
//!
//! Before running it, you'll need to [register your own developer application](https://discord.com/developers/applications) and get the client ID and secret.
//!
//! In order to run the example call:
//!
//! ```sh
//! CLIENT_ID=xxx CLIENT_SECRET=yyy cargo run --example discord
//! ```
//!
//! ...and follow the instructions.
//!

use openidconnect::core::{
    CoreClient, CoreIdTokenClaims, CoreIdTokenVerifier, CoreProviderMetadata, CoreResponseType,
};
use openidconnect::reqwest;
use openidconnect::{
    AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce,
    OAuth2TokenResponse, RedirectUrl, Scope,
};
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

fn main() {
    env_logger::init();

    let client_id =
        ClientId::new(env::var("CLIENT_ID").expect("Missing the CLIENT_ID environment variable."));
    let client_secret = ClientSecret::new(
        env::var("CLIENT_SECRET").expect("Missing the CLIENT_SECRET environment variable."),
    );
    // Do not use www.discord.com or you will get 301 Moved Permanently on OpenID Connect discovery
    let issuer_url = IssuerUrl::new("https://discord.com".to_string()).unwrap_or_else(|err| {
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

    // Fetch Discord's OpenID Connect discovery document.
    let provider_metadata = CoreProviderMetadata::discover(&issuer_url, &http_client)
        .unwrap_or_else(|err| {
            handle_error(&err, "Failed to discover OpenID Provider");
            unreachable!();
        });

    // Set up the config for the Discord OAuth2 process.
    let client =
        CoreClient::from_provider_metadata(provider_metadata, client_id, Some(client_secret))
            // This example will be running its own server at localhost:8080.
            // See below for the server implementation.
            .set_redirect_uri(
                RedirectUrl::new("http://localhost:8080".to_string()).unwrap_or_else(|err| {
                    handle_error(&err, "Invalid redirect URL");
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
        // This example is requesting access to the email address and identity.
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("identify".to_string()))
        .url();

    println!("Open this URL in your browser:\n{}\n", authorize_url);

    let (code, state) = {
        // A very naive implementation of the redirect server.
        let listener = TcpListener::bind("127.0.0.1:8080").unwrap();

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

    println!("Discord returned the following code:\n{}\n", code.secret());
    println!(
        "Discord returned the following state:\n{} (expected `{}`)\n",
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
        "Discord returned access token:\n{}\n",
        token_response.access_token().secret()
    );
    println!("Discord returned scopes: {:?}", token_response.scopes());

    let id_token_verifier: CoreIdTokenVerifier = client.id_token_verifier();
    let id_token_claims: &CoreIdTokenClaims = token_response
        .extra_fields()
        .id_token()
        .expect("Server did not return an ID token")
        .claims(&id_token_verifier, &nonce)
        .unwrap_or_else(|err| {
            handle_error(&err, "Failed to verify ID token");
            unreachable!();
        });
    println!("Discord returned ID token: {:?}", id_token_claims);
}
