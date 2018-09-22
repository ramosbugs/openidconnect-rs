//!
//! This example showcases the process of integrating with the
//! [Google OpenID Connect](https://developers.google.com/identity/protocols/OpenIDConnect)
//! provider.
//!
//! Before running it, you'll need to generate your own Google OAuth2 credentials.
//!
//! In order to run the example call:
//!
//! ```sh
//! GOOGLE_CLIENT_ID=xxx GOOGLE_CLIENT_SECRET=yyy cargo run --example google
//! ```
//!
//! ...and follow the instructions.
//!

extern crate base64;
extern crate env_logger;
extern crate failure;
extern crate oauth2;
extern crate openidconnect;
extern crate rand;
extern crate url;

use std::env;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::process::exit;

use failure::Fail;
use oauth2::prelude::*;
use oauth2::{AuthorizationCode, ClientId, ClientSecret, CsrfToken, RedirectUrl, Scope};
use url::Url;

use openidconnect::core::{CoreClient, CoreIdTokenClaims, CoreIdTokenVerifier};
use openidconnect::{AuthenticationFlow, IssuerUrl, Nonce};

fn handle_error<T: Fail>(fail: &T, msg: &'static str) {
    let mut err_msg = format!("ERROR: {}", msg);
    let mut cur_fail: Option<&Fail> = Some(fail);
    while let Some(cause) = cur_fail {
        err_msg += &format!("\n    caused by: {}", cause);
        cur_fail = cause.cause();
    }
    println!("{}", err_msg);
    exit(1);
}

fn main() {
    env_logger::init();

    let google_client_id = ClientId::new(
        env::var("GOOGLE_CLIENT_ID").expect("Missing the GOOGLE_CLIENT_ID environment variable."),
    );
    let google_client_secret = ClientSecret::new(
        env::var("GOOGLE_CLIENT_SECRET")
            .expect("Missing the GOOGLE_CLIENT_SECRET environment variable."),
    );
    let issuer_url =
        IssuerUrl::new("https://accounts.google.com".to_string()).expect("Invalid issuer URL");

    // Set up the config for the Google OAuth2 process.
    let client = CoreClient::discover(google_client_id, Some(google_client_secret), &issuer_url)
            .unwrap_or_else(|err| {
                handle_error(&err, "Failed to discover OpenID Provider");
                unreachable!();
            })
            // This example is requesting access to the "calendar" features and the user's profile.
            .add_scope(Scope::new("email".to_string()))
            .add_scope(Scope::new("profile".to_string()))
            // This example will be running its own server at localhost:8080.
            // See below for the server implementation.
            .set_redirect_uri(
                RedirectUrl::new(
                    Url::parse("http://localhost:8080")
                        .expect("Invalid redirect URL")
                )
            );

    // Generate the authorization URL to which we'll redirect the user.
    let (authorize_url, csrf_state, nonce) = client.authorize_url(
        &AuthenticationFlow::AuthorizationCode,
        CsrfToken::new_random,
        Nonce::new_random,
    );

    println!(
        "Open this URL in your browser:\n{}\n",
        authorize_url.to_string()
    );

    // A very naive implementation of the redirect server.
    let listener = TcpListener::bind("127.0.0.1:8080").unwrap();
    for stream in listener.incoming() {
        if let Ok(mut stream) = stream {
            let code;
            let state;
            {
                let mut reader = BufReader::new(&stream);

                let mut request_line = String::new();
                reader.read_line(&mut request_line).unwrap();

                let redirect_url = request_line.split_whitespace().nth(1).unwrap();
                let url = Url::parse(&("http://localhost".to_string() + redirect_url)).unwrap();

                let code_pair = url
                    .query_pairs()
                    .find(|pair| {
                        let &(ref key, _) = pair;
                        key == "code"
                    }).unwrap();

                let (_, value) = code_pair;
                code = AuthorizationCode::new(value.into_owned());

                let state_pair = url
                    .query_pairs()
                    .find(|pair| {
                        let &(ref key, _) = pair;
                        key == "state"
                    }).unwrap();

                let (_, value) = state_pair;
                state = CsrfToken::new(value.into_owned());
            }

            let message = "Go back to your terminal :)";
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{}",
                message.len(),
                message
            );
            stream.write_all(response.as_bytes()).unwrap();

            println!("Google returned the following code:\n{}\n", code.secret());
            println!(
                "Google returned the following state:\n{} (expected `{}`)\n",
                state.secret(),
                csrf_state.secret()
            );

            // Exchange the code with a token.
            let token_response = client.exchange_code(code).unwrap_or_else(|err| {
                handle_error(&err, "Failed to access token endpoint");
                unreachable!();
            });

            println!(
                "Google returned access token:\n{}\n",
                token_response.access_token().secret()
            );
            println!("Google returned scopes: {:?}", token_response.scopes());

            let id_token_verifier: CoreIdTokenVerifier =
                client.id_token_verifier().unwrap_or_else(|err| {
                    handle_error(&err, "Failed to create ID token verifier");
                    unreachable!();
                });
            let id_token_claims: &CoreIdTokenClaims = token_response
                .extra_fields()
                .id_token()
                .claims(&id_token_verifier, &nonce)
                .unwrap_or_else(|err| {
                    handle_error(&err, "Failed to verify ID token");
                    unreachable!();
                });
            println!("Google returned ID token: {:?}", id_token_claims);

            // The server will terminate itself after collecting the first code.
            break;
        }
    }
}
