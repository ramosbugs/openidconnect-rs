
extern crate curl;
extern crate env_logger;
extern crate jsonwebtoken as jwt;
#[macro_use] extern crate log;
extern crate oauth2;
extern crate openidconnect;
#[macro_use] extern crate pretty_assertions;
extern crate url;

use std::borrow::Borrow;
use std::collections::HashMap;

use curl::easy::Easy;
use oauth2::prelude::*;
use oauth2::{AuthorizationCode, CsrfToken, Scope};
use url::Url;

use openidconnect::{AuthenticationFlow, IdToken, IdTokenDecodeError};
use openidconnect::core::{
    CoreClient,
    CoreClientRegistrationResponse,
    CoreIdToken,
    CoreJsonWebKeySet,
    CoreProviderMetadata,
    CoreResponseType
};
use openidconnect::discovery::ProviderMetadata;
use openidconnect::registration::{ClientMetadata, ClientRegistrationResponse};
use openidconnect::types::Nonce;

#[macro_use] mod rp_common;

use rp_common::{
    CERTIFICATION_BASE_URL,
    get_provider_metadata,
    init_log,
    issuer_url,
    register_client,
    RP_CONTACT_EMAIL,
    RP_NAME,
};

struct TestState {
    authorization_code: Option<AuthorizationCode>,
    client: CoreClient,
    id_token: Option<CoreIdToken>,
    nonce: Option<Nonce>,
    provider_metadata: CoreProviderMetadata,
    registration_response: CoreClientRegistrationResponse,
}
impl TestState {
    pub fn id_token(&self) -> &CoreIdToken {
        self.id_token.as_ref().expect("no id_token")
    }

    pub fn init(test_id: &'static str) -> Self {
        init_log(test_id);

        let _issuer_url = issuer_url(test_id);
        let provider_metadata = get_provider_metadata(test_id);
        let registration_response = register_client(&provider_metadata);

        let redirect_uri = registration_response.redirect_uris()[0].clone();
        let client: CoreClient =
            CoreClient::from_dynamic_registration(&provider_metadata, &registration_response)
                .set_redirect_uri(redirect_uri);

        TestState {
            authorization_code: None,
            client,
            id_token: None,
            nonce: None,
            provider_metadata,
            registration_response,
        }
    }

    pub fn authorize(mut self, scopes: &Vec<Scope>) -> Self {
        self.client =
            scopes
                .iter()
                .fold(self.client, |mut client, scope| {
                    client = client.add_scope(scope.clone());
                    client
                });
        let (url, state, nonce) =
            self.client.authorize_url(
                &AuthenticationFlow::AuthorizationCode::<CoreResponseType>,
                CsrfToken::new_random,
                Nonce::new_random,
            );
        log_debug!("Authorize URL: {:?}", url);

        let mut easy = Easy::new();
        easy.url(&url.to_string()[..]).unwrap();
        easy.perform().unwrap();

        let redirected_url = Url::parse(easy.redirect_url().unwrap().unwrap()).unwrap();

        log_debug!("Authorization Server redirected to: {:?}", redirected_url);

        let mut query_params = HashMap::new();
        redirected_url
            .query_pairs()
            .for_each(|(key, value)| { query_params.insert(key, value); });
        log_debug!("Authorization Server returned query params: {:?}", query_params);

        assert_eq!(self.provider_metadata.issuer().as_str(), query_params.get("iss").unwrap());
        assert_eq!(state.secret(), query_params.get("state").unwrap());

        log_info!("Successfully received authentication response from Authorization Server");

        let authorization_code =
            AuthorizationCode::new(query_params.get("code").unwrap().to_string());
        log_debug!(
            "Authorization Server returned authorization code: {}",
            authorization_code.secret()
        );

        self.authorization_code = Some(authorization_code);
        self.nonce = Some(nonce);

        self
    }

    pub fn exchange_code(mut self) -> Self {
        let token_response =
            self.client
                .exchange_code(self.authorization_code.take().expect("no authorization_code"))
                .unwrap();
        log_debug!("Authorization Server returned token response: {:?}", token_response);

        let id_token = (*token_response.extra_fields().id_token()).clone();
        self.id_token = Some(id_token);

        self
    }

    pub fn jwks(&self) -> CoreJsonWebKeySet {
        self.provider_metadata.jwks_uri().unwrap().get_keys().unwrap()
    }
}

#[test]
fn rp_response_type_code() {
    let test_state =
        TestState::init("rp-response_type-code")
            .authorize(&vec![]);
    assert!(test_state.authorization_code.expect("no authorization_code").secret() != "");
    log_info!("SUCCESS");
}

#[test]
fn rp_scope_userinfo_claims() {
    let user_info_scopes =
        vec!["profile", "email", "address", "phone"]
            .iter()
            .map(|scope| Scope::new(scope.to_string()))
            .collect::<Vec<_>>();
    let test_state =
        TestState::init("rp-scope-userinfo-claims")
            .authorize(&user_info_scopes);

    // FIXME: implement the rest of this test
}

#[test]
fn rp_nonce_invalid() {
    let test_state =
        TestState::init("rp-nonce-invalid")
            .authorize(&vec![])
            .exchange_code();

    let claims_result = test_state.id_token().claims_for_private_client(
        &test_state.jwks(),
        test_state.registration_response.client_secret().unwrap(),
        // FIXME: make sure this fails since nonce is private
        test_state.nonce.as_ref().expect("no nonce"),
    );

    match claims_result {
        Err(IdTokenDecodeError::InvalidNonce(_)) =>
            log_info!("ID token contains invalid nonce (expected result)"),
        other => panic!("Unexpected result verifying ID token claims: ${:?}", other)
    }

    log_info!("SUCCESS");
}

