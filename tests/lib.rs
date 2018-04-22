
extern crate oauth2;
extern crate openidconnect;
#[macro_use] extern crate pretty_assertions;
extern crate serde_json;
extern crate url;

use oauth2::prelude::*;
use oauth2::{
    AccessToken,
    AuthType,
    AuthUrl,
    Client,
    ClientId,
    ClientSecret,
    CsrfToken,
    ErrorResponseType,
    RedirectUrl,
    RefreshToken,
    ResponseType,
    Scope,
    TokenResponse,
    TokenType,
    TokenUrl,
};
use oauth2::basic::{
    BasicClient,
    BasicErrorResponse,
    BasicErrorResponseType,
    BasicRequestTokenError,
    BasicTokenResponse,
    BasicTokenType,
};
use openidconnect::*;
use openidconnect::core::*;
use std::time::Duration;
use url::Url;

fn new_client() -> CoreClient {
    CoreClient::new(
        ClientId::new("aaa".to_string()),
        Some(ClientSecret::new("bbb".to_string())),
        AuthUrl::new(Url::parse("https://example/authorize").unwrap()),
        Some(TokenUrl::new(Url::parse("https://example/token").unwrap()))
    )
}

#[test]
fn test_authorize_url_minimal() {
    let client = new_client();

    let (authorize_url, _, _) =
        client
            .authorize_url(
                &AuthenticationFlow::AuthorizationCode::<CoreResponseType>,
                || CsrfToken::new("CSRF123".to_string()),
                || Nonce::new("NONCE456".to_string())
            );

    assert_eq!(
        "https://example/authorize?response_type=code&client_id=aaa&scope=openid&\
         state=CSRF123&nonce=NONCE456",
        authorize_url.to_string());
}

#[test]
fn test_authorize_url_full() {
    let client =
        new_client()
            .add_scope(Scope::new("email".to_string()))
            .set_redirect_uri(RedirectUrl::new(Url::parse("http://localhost:8888/").unwrap()))
            .set_display(Some(CoreAuthDisplay::Touch))
            .set_prompts(Some(vec![CoreAuthPrompt::Login, CoreAuthPrompt::Consent]))
            .set_max_age(Some(Duration::from_secs(1800)))
            .set_ui_locales(
                Some(
                    vec![
                        LanguageTag::new("fr-CA".to_string()),
                        LanguageTag::new("fr".to_string()),
                        LanguageTag::new("en".to_string())
                    ]
                )
            )
            .set_acr_values(
                Some(
                    vec![
                        AuthenticationContextClass::new("urn:mace:incommon:iap:silver".to_string())
                    ]
                )
            );

    let (authorize_url, _, _) =
        client
            .authorize_url(
                &AuthenticationFlow::AuthorizationCode::<CoreResponseType>,
                || CsrfToken::new("CSRF123".to_string()),
                || Nonce::new("NONCE456".to_string())
            );

    assert_eq!(
        "https://example/authorize?response_type=code&client_id=aaa&\
         redirect_uri=http%3A%2F%2Flocalhost%3A8888%2F&scope=openid+email&state=CSRF123&\
         nonce=NONCE456&acr_values=urn%3Amace%3Aincommon%3Aiap%3Asilver&display=touch&\
         max_age=1800&prompt=login+consent&ui_locales=fr-CA+fr+en",
        authorize_url.to_string());
}

#[test]
fn test_issuer_url_append() {
    assert_eq!(
        "http://example.com/.well-known/openid-configuration",
        IssuerUrl::new(Url::parse("http://example.com").unwrap())
            .join(".well-known/openid-configuration")
            .unwrap()
            .to_string()
    );
    assert_eq!(
        "http://example.com/.well-known/openid-configuration",
        IssuerUrl::new(Url::parse("http://example.com/").unwrap())
            .join(".well-known/openid-configuration")
            .unwrap()
            .to_string()
    );
    assert_eq!(
        "http://example.com/x/.well-known/openid-configuration",
        IssuerUrl::new(Url::parse("http://example.com/x").unwrap())
            .join(".well-known/openid-configuration")
            .unwrap()
            .to_string()
    );
    assert_eq!(
        "http://example.com/x/.well-known/openid-configuration",
        IssuerUrl::new(Url::parse("http://example.com/x/").unwrap())
            .join(".well-known/openid-configuration")
            .unwrap()
            .to_string()
    );
}

#[test]
fn test_url_serialize() {
    let issuer_url =
        IssuerUrl::new(Url::parse("http://example.com/.well-known/openid-configuration").unwrap());
    let serialized_url = serde_json::to_string(&issuer_url).unwrap();

    assert_eq!("\"http://example.com/.well-known/openid-configuration\"", serialized_url);

    let deserialized_url = serde_json::from_str(&serialized_url).unwrap();
    assert_eq!(issuer_url, deserialized_url);
}

#[test]
fn test_grant_type_serialize() {
    let serialized_implicit =
        serde_json::to_string(&CoreGrantTypeWrapper::new(CoreGrantType::Implicit)).unwrap();
    assert_eq!("\"implicit\"", serialized_implicit);
    assert_eq!(
        CoreGrantType::Implicit,
        *serde_json::from_str::<CoreGrantTypeWrapper>(&serialized_implicit).unwrap()
    );

    let ext =
        CoreGrantTypeWrapper::new(
            CoreGrantType::Extension("urn:ietf:params:oauth:grant-type:foobar".to_string())
        );
    let serialized_ext = serde_json::to_string(&ext).unwrap();
    assert_eq!("\"urn:ietf:params:oauth:grant-type:foobar\"", serialized_ext);
    assert_eq!(ext, serde_json::from_str::<CoreGrantTypeWrapper>(&serialized_ext).unwrap());
}
