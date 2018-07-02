
extern crate curl;
extern crate env_logger;
extern crate jsonwebtoken as jwt;
#[macro_use] extern crate log;
extern crate oauth2;
extern crate openidconnect;
#[macro_use] extern crate pretty_assertions;
extern crate url;

use std::collections::HashMap;

use curl::easy::Easy;
use oauth2::prelude::*;
use oauth2::{AccessToken, AuthorizationCode, CsrfToken, Scope};
use url::Url;

use openidconnect::{AuthenticationFlow, IdTokenDecodeError, StandardClaims, UserInfoResponse};
use openidconnect::core::{
    CoreClient,
    CoreClientRegistrationResponse,
    CoreIdToken,
    CoreIdTokenClaims,
    CoreJsonWebKeySet,
    CoreProviderMetadata,
    CoreResponseType,
    CoreUserInfoResponse,
};
use openidconnect::discovery::ProviderMetadata;
use openidconnect::registration::{ClientMetadata, ClientRegistrationResponse};
use openidconnect::types::Nonce;

#[macro_use] mod rp_common;

use rp_common::{
    get_provider_metadata,
    init_log,
    issuer_url,
    register_client,
};

struct TestState {
    access_token: Option<AccessToken>,
    authorization_code: Option<AuthorizationCode>,
    client: CoreClient,
    id_token: Option<CoreIdToken>,
    nonce: Option<Nonce>,
    provider_metadata: CoreProviderMetadata,
    registration_response: CoreClientRegistrationResponse,
}
impl TestState {
    pub fn access_token(&self) -> &AccessToken {
        self.access_token.as_ref().expect("no access_token")
    }
    pub fn id_token(&self) -> &CoreIdToken {
        self.id_token.as_ref().expect("no id_token")
    }
    pub fn id_token_claims(&self) -> &CoreIdTokenClaims {
        self.id_token()
            .claims_for_private_client(
                &self.jwks(),
                self.registration_response.client_secret().expect("no client_secret"),
                self.nonce.as_ref().expect("no nonce"),
            )
            .expect("failed to validate claims")
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
            access_token: None,
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

        self.access_token = Some(token_response.access_token().clone());

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
            .authorize(&user_info_scopes)
            .exchange_code();
    let id_token_claims = test_state.id_token_claims();

    let user_info_response: CoreUserInfoResponse =
        test_state
            .provider_metadata
            .userinfo_endpoint()
            .unwrap()
            .get_user_info(test_state.access_token())
            .unwrap();
    let user_info_claims =
        match user_info_response {
            UserInfoResponse::JsonResponse(user_info_claims) => user_info_claims,
            other => panic!("Unexpected user info response: {:?}", other),
        };

    log_debug!("UserInfo response: {:?}", user_info_claims);

    assert!(id_token_claims.sub() == user_info_claims.sub());
    assert!(!user_info_claims.email().expect("no email returned by UserInfo endpoint").is_empty());
    assert!(
        !user_info_claims
            .address()
            .expect("no address returned by UserInfo endpoint")
            .street_address()
            .expect("no street address returned by UserInfo endpoint")
            .is_empty()
    );
    assert!(
        !user_info_claims
            .phone_number()
            .expect("no phone_number returned by UserInfo endpoint")
            .is_empty()
    );

    log_info!("SUCCESS");
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
        test_state.nonce.as_ref().expect("no nonce"),
    );

    match claims_result {
        Err(IdTokenDecodeError::InvalidNonce(_)) =>
            log_info!("ID token contains invalid nonce (expected result)"),
        other => panic!("Unexpected result verifying ID token claims: {:?}", other),
    }

    log_info!("SUCCESS");
}

