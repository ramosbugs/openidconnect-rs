//!
//! This example showcases the process of integrating with the
//! [Twitch OpenID Connect](https://dev.twitch.tv/docs/authentication/getting-tokens-oidc/)
//! provider.
//!
//! Twitch's token response requires a custom implementation to extract the scopes, as it returns
//! them as a standard JSON array instead of a space-separated string as the spec expects.
//!
//! Before running it, you'll need to generate your own
//! [Twitch Application](https://dev.twitch.tv/docs/authentication/register-app/).
//!
//! In order to run the example call:
//!
//! ```sh
//! TWITCH_CLIENT_ID=xxx TWITCH_CLIENT_SECRET=yyy cargo run --example twitch --features="reqwest-blocking"
//! ```
//!
//! ...and follow the instructions.
//!

use oauth2::AuthType::RequestBody;
use oauth2::{
    AccessToken, EndpointNotSet, ExtraTokenFields, RefreshToken, StandardErrorResponse, TokenType,
};
use openidconnect::core::{
    CoreAuthDisplay, CoreAuthPrompt, CoreErrorResponseType, CoreGenderClaim, CoreIdTokenClaims,
    CoreIdTokenFields, CoreIdTokenVerifier, CoreJsonWebKey, CoreJweContentEncryptionAlgorithm,
    CoreProviderMetadata, CoreResponseType, CoreRevocableToken, CoreRevocationErrorResponse,
    CoreTokenIntrospectionResponse, CoreTokenType,
};
use openidconnect::TokenResponse;
use openidconnect::{reqwest, Client, EmptyAdditionalClaims, IdTokenFields};
use openidconnect::{
    AdditionalClaims, GenderClaim, IdToken, JweContentEncryptionAlgorithm, JwsSigningAlgorithm,
    UserInfoClaims,
};
use openidconnect::{
    AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce,
    OAuth2TokenResponse, RedirectUrl, Scope,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use url::Url;

use std::env;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::process::exit;
use std::time::Duration;

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

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TwitchCustomTokenResponse<EF, TT>
where
    EF: ExtraTokenFields,
    TT: TokenType,
{
    access_token: AccessToken,
    #[serde(bound = "TT: TokenType")]
    #[serde(deserialize_with = "oauth2::helpers::deserialize_untagged_enum_case_insensitive")]
    token_type: TT,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_in: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<RefreshToken>,
    // Twitch returns scopes as a JSON array instead of the standard space-separated string.
    #[serde(rename = "scope")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    scopes: Option<Vec<Scope>>,
    #[serde(bound = "EF: ExtraTokenFields")]
    #[serde(flatten)]
    extra_fields: EF,
}

impl<EF, TT> TwitchCustomTokenResponse<EF, TT>
where
    EF: ExtraTokenFields,
    TT: TokenType,
{
    /// Instantiate a new OAuth2 token response.
    pub fn new(access_token: AccessToken, token_type: TT, extra_fields: EF) -> Self {
        Self {
            access_token,
            token_type,
            expires_in: None,
            refresh_token: None,
            scopes: None,
            extra_fields,
        }
    }

    /// Set the `access_token` field.
    pub fn set_access_token(&mut self, access_token: AccessToken) {
        self.access_token = access_token;
    }

    /// Set the `token_type` field.
    pub fn set_token_type(&mut self, token_type: TT) {
        self.token_type = token_type;
    }

    /// Set the `expires_in` field.
    pub fn set_expires_in(&mut self, expires_in: Option<&Duration>) {
        self.expires_in = expires_in.map(Duration::as_secs);
    }

    /// Set the `refresh_token` field.
    pub fn set_refresh_token(&mut self, refresh_token: Option<RefreshToken>) {
        self.refresh_token = refresh_token;
    }

    /// Set the `scopes` field.
    pub fn set_scopes(&mut self, scopes: Option<Vec<Scope>>) {
        self.scopes = scopes;
    }

    /// Extra fields defined by the client application.
    pub fn extra_fields(&self) -> &EF {
        &self.extra_fields
    }

    /// Set the extra fields defined by the client application.
    pub fn set_extra_fields(&mut self, extra_fields: EF) {
        self.extra_fields = extra_fields;
    }
}

impl<EF, TT> OAuth2TokenResponse for TwitchCustomTokenResponse<EF, TT>
where
    EF: ExtraTokenFields,
    TT: TokenType,
{
    type TokenType = TT;
    /// REQUIRED. The access token issued by the authorization server.
    fn access_token(&self) -> &AccessToken {
        &self.access_token
    }
    /// REQUIRED. The type of the token issued as described in
    /// [Section 7.1](https://tools.ietf.org/html/rfc6749#section-7.1).
    /// Value is case insensitive and deserialized to the generic `TokenType` parameter.
    fn token_type(&self) -> &TT {
        &self.token_type
    }
    /// RECOMMENDED. The lifetime in seconds of the access token. For example, the value 3600
    /// denotes that the access token will expire in one hour from the time the response was
    /// generated. If omitted, the authorization server SHOULD provide the expiration time via
    /// other means or document the default value.
    fn expires_in(&self) -> Option<Duration> {
        self.expires_in.map(Duration::from_secs)
    }
    /// OPTIONAL. The refresh token, which can be used to obtain new access tokens using the same
    /// authorization grant as described in
    /// [Section 6](https://tools.ietf.org/html/rfc6749#section-6).
    fn refresh_token(&self) -> Option<&RefreshToken> {
        self.refresh_token.as_ref()
    }
    /// OPTIONAL, if identical to the scope requested by the client; otherwise, REQUIRED. The
    /// scope of the access token as described by
    /// [Section 3.3](https://tools.ietf.org/html/rfc6749#section-3.3). If included in the response,
    /// this space-delimited field is parsed into a `Vec` of individual scopes. If omitted from
    /// the response, this field is `None`.
    /// Twitch returns scopes as a JSON array instead of the specified space-delimited field.
    fn scopes(&self) -> Option<&Vec<Scope>> {
        self.scopes.as_ref()
    }
}

impl<AC, EF, GC, JE, JS, TT> TokenResponse<AC, GC, JE, JS>
    for TwitchCustomTokenResponse<IdTokenFields<AC, EF, GC, JE, JS>, TT>
where
    AC: AdditionalClaims,
    EF: ExtraTokenFields,
    GC: GenderClaim,
    JE: JweContentEncryptionAlgorithm<KeyType = JS::KeyType>,
    JS: JwsSigningAlgorithm,
    TT: TokenType,
{
    fn id_token(&self) -> Option<&IdToken<AC, GC, JE, JS>> {
        self.extra_fields().id_token()
    }
}

type TwitchTokenResponse = TwitchCustomTokenResponse<CoreIdTokenFields, CoreTokenType>;

pub type TwitchClient<
    HasAuthUrl = EndpointNotSet,
    HasDeviceAuthUrl = EndpointNotSet,
    HasIntrospectionUrl = EndpointNotSet,
    HasRevocationUrl = EndpointNotSet,
    HasTokenUrl = EndpointNotSet,
    HasUserInfoUrl = EndpointNotSet,
> = Client<
    EmptyAdditionalClaims,
    CoreAuthDisplay,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJsonWebKey,
    CoreAuthPrompt,
    StandardErrorResponse<CoreErrorResponseType>,
    TwitchTokenResponse,
    CoreTokenIntrospectionResponse,
    CoreRevocableToken,
    CoreRevocationErrorResponse,
    HasAuthUrl,
    HasDeviceAuthUrl,
    HasIntrospectionUrl,
    HasRevocationUrl,
    HasTokenUrl,
    HasUserInfoUrl,
>;

fn main() {
    env_logger::init();

    let twitch_client_id = ClientId::new(
        env::var("TWITCH_CLIENT_ID").expect("Missing the TWITCH_CLIENT_ID environment variable."),
    );
    let twitch_client_secret = ClientSecret::new(
        env::var("TWITCH_CLIENT_SECRET")
            .expect("Missing the TWITCH_CLIENT_SECRET environment variable."),
    );
    let issuer_url =
        IssuerUrl::new("https://id.twitch.tv/oauth2".to_string()).unwrap_or_else(|err| {
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

    // Fetch Twitch's OpenID Connect discovery document.
    let provider_metadata = CoreProviderMetadata::discover(&issuer_url, &http_client)
        .unwrap_or_else(|err| {
            handle_error(&err, "Failed to discover OpenID Provider");
            unreachable!();
        });

    // Set up the config for the Twitch OAuth2 process.
    let client = TwitchClient::from_provider_metadata(
        provider_metadata,
        twitch_client_id,
        Some(twitch_client_secret),
    )
    // This example will be running its own server at localhost:8080.
    // See below for the server implementation.
    .set_redirect_uri(
        RedirectUrl::new("http://localhost:8080".to_string()).unwrap_or_else(|err| {
            handle_error(&err, "Invalid redirect URL");
            unreachable!();
        }),
    )
    .set_auth_type(RequestBody);

    // Generate the authorization URL to which we'll redirect the user.
    let (authorize_url, csrf_state, nonce) = client
        .authorize_url(
            AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        // Add scope and claims parameters to request non-default claims
        // See: https://dev.twitch.tv/docs/authentication/getting-tokens-oidc/#requesting-claims
        .add_scope(Scope::new("user:read:email".to_string()))
        .add_extra_param(
            "claims",
            json!({
                "id_token": {
                    "email": null,
                    "email_verified": null,
                    "picture": null,
                    "preferred_username": null
                },
                "userinfo": {
                    "email": null,
                    "email_verified": null,
                    "picture": null,
                    "preferred_username": null,
                }
            })
            .to_string(),
        )
        .url();

    println!("Open this URL in your browser:\n{authorize_url}\n");

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

    println!("Twitch returned the following code:\n{}\n", code.secret());
    println!(
        "Twitch returned the following state:\n{} (expected `{}`)\n",
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
        "Twitch returned access token:\n{}\n",
        token_response.access_token().secret()
    );
    println!("Twitch returned scopes: {:?}\n", token_response.scopes());

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
    println!("Twitch returned ID token: {:?}\n", id_token_claims);

    let userinfo_claims: UserInfoClaims<EmptyAdditionalClaims, CoreGenderClaim> = client
        .user_info(token_response.access_token().to_owned(), None)
        .unwrap_or_else(|err| {
            handle_error(&err, "No user info endpoint");
            unreachable!();
        })
        .request(&http_client)
        .unwrap_or_else(|err| {
            handle_error(&err, "Failed requesting user info");
            unreachable!();
        });
    println!("Twitch returned UserInfo: {:?}", userinfo_claims);
}
