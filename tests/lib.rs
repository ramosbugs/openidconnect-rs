
extern crate openidconnect;

use openidconnect::*;
use openidconnect::core::*;
use std::time::Duration;

#[test]
fn test_authorize_url_minimal() {
    let client =
        CoreOpenIdConnectClient::new(
            "aaa",
            Some("bbb"),
            "https://example/authorize",
            "https://example/token"
        )
        .unwrap();

    let auth_options =
        CoreOpenIdConnectAuthOptions::new();

    let authorize_url =
        client.authorize_url(&auth_options, &CsrfToken::new("CSRF123"), &Nonce::new("NONCE456"));

    assert_eq!(
        "https://example/authorize?response_type=code&client_id=aaa&scope=openid&\
         state=CSRF123&nonce=NONCE456",
        authorize_url.to_string());
}

#[test]
fn test_authorize_url_full() {
    let client =
        CoreOpenIdConnectClient::new(
            "aaa",
            Some("bbb"),
            "https://example/authorize",
            "https://example/token"
        )
        .unwrap()
        .add_scope("email")
        .set_redirect_url("http://localhost:8888");

    let auth_options =
        CoreOpenIdConnectAuthOptions::new()
            .set_display(CoreOpenIdConnectAuthDisplay::Touch)
            .add_prompt(CoreOpenIdConnectAuthPrompt::Login)
            .add_prompt(CoreOpenIdConnectAuthPrompt::Consent)
            .set_max_age(Duration::from_secs(1800))
            .add_ui_locale(LanguageTag::new("fr-CA"))
            .add_ui_locale(LanguageTag::new("fr"))
            .add_ui_locale(LanguageTag::new("en"))
            .add_acr_value(AuthenticationContextClass::new("urn:mace:incommon:iap:silver"));

    let authorize_url =
        client.authorize_url(&auth_options, &CsrfToken::new("CSRF123"), &Nonce::new("NONCE456"));

    assert_eq!(
        "https://example/authorize?response_type=code&client_id=aaa&\
         redirect_uri=http%3A%2F%2Flocalhost%3A8888&scope=openid+email&state=CSRF123&\
         nonce=NONCE456&display=touch&prompt=login+consent&max_age=1800&ui_locales=fr-CA+fr+en&\
         acr_values=urn%3Amace%3Aincommon%3Aiap%3Asilver",
        authorize_url.to_string());
}
