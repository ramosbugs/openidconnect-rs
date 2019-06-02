// FIXME: uncomment
//#![warn(missing_docs)]

#![cfg_attr(feature = "nightly", feature(type_alias_enum_variants))]

//!
//! [OpenID Connect](http://openid.net/specs/openid-connect-core-1_0.html) support.
//!

extern crate base64;
extern crate chrono;
extern crate failure;
#[macro_use]
extern crate failure_derive;
extern crate http as http_;
extern crate itertools;
extern crate oauth2;
extern crate rand;
extern crate ring;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate untrusted;
extern crate url;

#[cfg(test)]
extern crate color_backtrace;

#[cfg(test)]
#[macro_use]
extern crate pretty_assertions;

use std::borrow::Cow;
use std::marker::PhantomData;
use std::str;
use std::time::Duration;

use failure::Fail;
use oauth2::helpers::variant_name;
use oauth2::ResponseType as OAuth2ResponseType;
pub use oauth2::{
    curl, reqwest, AccessToken, AuthType, AuthUrl, AuthorizationCode, ClientId, ClientSecret,
    CodeTokenRequest, CsrfToken, ErrorResponse, ErrorResponseType, ExtraTokenFields, HttpRequest,
    HttpResponse, PkceCodeChallenge, PkceCodeChallengeMethod, PkceCodeVerifier, RedirectUrl,
    RefreshToken, RefreshTokenRequest, RequestTokenError, Scope, StandardErrorResponse,
    StandardTokenResponse, TokenResponse as OAuth2TokenResponse, TokenType, TokenUrl,
};
use url::Url;

pub use claims::{
    AdditionalClaims, AddressClaim, EmptyAdditionalClaims, GenderClaim, StandardClaims,
};
pub use discovery::{
    get_provider_metadata, AdditionalProviderMetadata, DiscoveryError,
    EmptyAdditionalProviderMetadata, ProviderMetadata,
};
pub use id_token::IdTokenFields;
pub use id_token::{IdToken, IdTokenClaims};
pub use jwt::JsonWebTokenError;
use jwt::{JsonWebToken, JsonWebTokenAccess, JsonWebTokenAlgorithm, JsonWebTokenHeader};
use registration::{
    AdditionalClientMetadata, AdditionalClientRegistrationResponse, ClientRegistrationResponse,
};
// Flatten the module hierarchy involving types. They're only separated to improve code
// organization.
pub use types::{
    AccessTokenHash, AddressCountry, AddressLocality, AddressPostalCode, AddressRegion,
    ApplicationType, Audience, AuthDisplay, AuthPrompt, AuthenticationContextClass,
    AuthenticationMethodReference, AuthorizationCodeHash, Base64UrlEncodedBytes, ClaimName,
    ClaimType, ClientAuthMethod, ClientConfigUrl, ClientName, ClientUrl, ContactEmail,
    EndUserBirthday, EndUserEmail, EndUserFamilyName, EndUserGivenName, EndUserMiddleName,
    EndUserName, EndUserNickname, EndUserPhoneNumber, EndUserPictureUrl, EndUserProfileUrl,
    EndUserTimezone, EndUserUsername, EndUserWebsiteUrl, FormattedAddress, GrantType,
    InitiateLoginUrl, IssuerUrl, JsonWebKey, JsonWebKeyId, JsonWebKeySet, JsonWebKeySetFetchError,
    JsonWebKeySetUrl, JsonWebKeyType, JsonWebKeyUse, JweContentEncryptionAlgorithm,
    JweKeyManagementAlgorithm, JwsSigningAlgorithm, LanguageTag, LoginHint, LogoUrl, Nonce,
    OpPolicyUrl, OpTosUrl, PolicyUrl, PrivateSigningKey, RegistrationAccessToken, RegistrationUrl,
    RequestUrl, ResponseMode, ResponseType, ResponseTypes, SectorIdentifierUrl, ServiceDocUrl,
    SigningError, StreetAddress, SubjectIdentifier, SubjectIdentifierType, ToSUrl,
};
pub use user_info::{UserInfoClaims, UserInfoError, UserInfoJsonWebToken, UserInfoUrl};
use verification::{AudiencesClaim, IssuerClaim};
pub use verification::{
    ClaimsVerificationError, IdTokenVerifier, NonceVerifier, SignatureVerificationError,
    UserInfoVerifier,
};

// Defined first since other modules need the macros, and definition order is significant for
// macros. This module is private.
#[macro_use]
mod macros;

pub mod core;
pub mod registration;

// Private modules since we may move types between different modules; these are exported publicly
// via the pub use above.
mod claims;
mod discovery;
mod id_token;
mod types;
mod user_info;
mod verification;

// Private module for HTTP(S) utilities.
mod http;

// Private module for JWT utilities.
mod jwt;

const CONFIG_URL_SUFFIX: &str = ".well-known/openid-configuration";
const OPENID_SCOPE: &str = "openid";

///
/// Authentication flow, which determines how the Authorization Server returns the OpenID Connect
/// ID token and OAuth2 access token to the Relying Party.
///
#[derive(Clone, Debug, PartialEq)]
pub enum AuthenticationFlow<RT: ResponseType> {
    ///
    /// Authorization Code Flow.
    ///
    /// The authorization server will return an OAuth2 authorization code. Clients must subsequently
    /// call `Client::exchange_code()` with the authorization code in order to retrieve an
    /// OpenID Connect ID token and OAuth2 access token.
    ///
    AuthorizationCode,
    ///
    /// Implicit Flow.
    ///
    /// Boolean value indicates whether an OAuth2 access token should also be returned. If `true`,
    /// the Authorization Server will return both an OAuth2 access token and OpenID Connect ID
    /// token. If `false`, it will return only an OpenID Connect ID token.
    ///
    Implicit(bool),
    ///
    /// Hybrid Flow.
    ///
    /// A hybrid flow according to [OAuth 2.0 Multiple Response Type Encoding Practices](
    ///     http://openid.net/specs/oauth-v2-multiple-response-types-1_0.html). The enum value
    /// contains the desired `response_type`s. See
    /// [Section 3](http://openid.net/specs/openid-connect-core-1_0.html#Authentication) for
    /// details.
    ///
    Hybrid(Vec<RT>),
}

#[derive(Clone, Debug)]
pub struct Client<AC, AD, AM, CA, CN, CT, G, GC, JE, JK, JS, JT, P, RM, RT, S, TE, TR, TT>
where
    AC: AdditionalClaims,
    AD: AuthDisplay,
    AM: AdditionalProviderMetadata,
    CA: ClientAuthMethod,
    CN: ClaimName,
    CT: ClaimType,
    G: GrantType,
    GC: GenderClaim,
    JE: JweContentEncryptionAlgorithm<JT>,
    JK: JweKeyManagementAlgorithm,
    JS: JwsSigningAlgorithm<JT>,
    JT: JsonWebKeyType,
    P: AuthPrompt,
    RM: ResponseMode,
    RT: ResponseType,
    S: SubjectIdentifierType,
    TE: ErrorResponse,
    TR: TokenResponse<AC, GC, JE, JS, JT, TT>,
    TT: TokenType + 'static,
{
    oauth2_client: oauth2::Client<TE, TR, TT>,
    client_id: ClientId,
    client_secret: Option<ClientSecret>,
    #[allow(clippy::type_complexity)]
    provider_metadata: Option<ProviderMetadata<AM, AD, CA, CN, CT, G, JE, JK, JS, JT, RM, RT, S>>,
    _phantom: PhantomData<(AC, CA, CN, CT, G, GC, JE, JK, JS, JT, RM, RT, P, S)>,
}
impl<AC, AD, AP, CA, CN, CT, G, GC, JE, JK, JS, JT, P, RM, RT, S, TE, TR, TT>
    Client<AC, AD, AP, CA, CN, CT, G, GC, JE, JK, JS, JT, P, RM, RT, S, TE, TR, TT>
where
    AC: AdditionalClaims,
    AD: AuthDisplay,
    AP: AdditionalProviderMetadata,
    CA: ClientAuthMethod,
    CN: ClaimName,
    CT: ClaimType,
    G: GrantType,
    GC: GenderClaim,
    JE: JweContentEncryptionAlgorithm<JT>,
    JK: JweKeyManagementAlgorithm,
    JS: JwsSigningAlgorithm<JT>,
    JT: JsonWebKeyType,
    P: AuthPrompt,
    RM: ResponseMode,
    RT: ResponseType,
    S: SubjectIdentifierType,
    TE: ErrorResponse,
    TR: TokenResponse<AC, GC, JE, JS, JT, TT>,
    TT: TokenType,
{
    pub fn new(
        client_id: ClientId,
        client_secret: Option<ClientSecret>,
        auth_url: AuthUrl,
        token_url: Option<TokenUrl>,
    ) -> Self {
        let oauth2_client = oauth2::Client::new(
            client_id.clone(),
            client_secret.clone(),
            auth_url,
            token_url,
        );
        Client {
            oauth2_client,
            client_id,
            client_secret,
            provider_metadata: None,
            _phantom: PhantomData,
        }
    }

    pub fn discover<HC, RE>(
        client_id: ClientId,
        client_secret: Option<ClientSecret>,
        issuer_url: &IssuerUrl,
        http_client: HC,
    ) -> Result<Self, DiscoveryError<RE>>
    where
        HC: FnOnce(HttpRequest) -> Result<HttpResponse, RE>,
        RE: Fail,
    {
        #[allow(clippy::type_complexity)]
        let provider_metadata: ProviderMetadata<
            AP,
            AD,
            CA,
            CN,
            CT,
            G,
            JE,
            JK,
            JS,
            JT,
            RM,
            RT,
            S,
        > = discovery::get_provider_metadata(issuer_url, http_client)?;

        let oauth2_client = oauth2::Client::new(
            client_id.clone(),
            client_secret.clone(),
            provider_metadata.authorization_endpoint().clone(),
            provider_metadata.token_endpoint().cloned(),
        );
        Ok(Client {
            oauth2_client,
            client_id,
            client_secret,
            provider_metadata: Some(provider_metadata),
            _phantom: PhantomData,
        })
    }

    #[allow(clippy::type_complexity)]
    pub fn from_dynamic_registration<A, AR, AT, JU, K>(
        provider_metadata: &ProviderMetadata<AP, AD, CA, CN, CT, G, JE, JK, JS, JT, RM, RT, S>,
        registration_response: &ClientRegistrationResponse<
            A,
            AR,
            AT,
            CA,
            G,
            JE,
            JK,
            JS,
            JT,
            JU,
            K,
            RT,
            S,
        >,
    ) -> Self
    where
        A: AdditionalClientMetadata,
        AR: AdditionalClientRegistrationResponse,
        AT: ApplicationType,
        JU: JsonWebKeyUse,
        K: JsonWebKey<JS, JT, JU>,
    {
        let oauth2_client = oauth2::Client::new(
            registration_response.client_id().clone(),
            registration_response.client_secret().cloned(),
            provider_metadata.authorization_endpoint().clone(),
            provider_metadata.token_endpoint().cloned(),
        );
        Client {
            oauth2_client,
            client_id: registration_response.client_id().clone(),
            client_secret: registration_response.client_secret().cloned(),
            provider_metadata: Some(provider_metadata.clone()),
            _phantom: PhantomData,
        }
    }

    ///
    /// Configures the type of client authentication used for communicating with the authorization
    /// server.
    ///
    /// The default is to use HTTP Basic authentication, as recommended in
    /// [Section 2.3.1 of RFC 6749](https://tools.ietf.org/html/rfc6749#section-2.3.1).
    ///
    pub fn set_auth_type(mut self, auth_type: AuthType) -> Self {
        self.oauth2_client = self.oauth2_client.set_auth_type(auth_type);
        self
    }

    ///
    /// Sets the the redirect URL used by the authorization endpoint.
    ///
    pub fn set_redirect_uri(mut self, redirect_uri: RedirectUrl) -> Self {
        self.oauth2_client = self.oauth2_client.set_redirect_url(redirect_uri);
        self
    }

    pub fn id_token_verifier<HC, JU, K, RE>(
        &self,
        http_client: HC,
    ) -> Result<IdTokenVerifier<JS, JT, JU, K>, JsonWebKeySetFetchError<RE>>
    where
        HC: FnOnce(HttpRequest) -> Result<HttpResponse, RE>,
        JU: JsonWebKeyUse,
        K: JsonWebKey<JS, JT, JU>,
        RE: Fail,
    {
        let provider_metadata = self.provider_metadata.as_ref().ok_or_else(|| {
            JsonWebKeySetFetchError::Other("no provider metadata present".to_string())
        })?;
        let signature_keys = provider_metadata.jwks_uri().get_keys(http_client)?;
        if let Some(ref client_secret) = self.client_secret {
            Ok(IdTokenVerifier::new_private_client(
                self.client_id.clone(),
                client_secret.clone(),
                provider_metadata.issuer().clone(),
                signature_keys,
            ))
        } else {
            Ok(IdTokenVerifier::new_public_client(
                self.client_id.clone(),
                provider_metadata.issuer().clone(),
                signature_keys,
            ))
        }
    }

    // FIXME: document that we don't currently support passing authorization request parameters
    // as a JWT: https://openid.net/specs/openid-connect-core-1_0.html#JWTRequests
    pub fn authorize_url<NF, SF>(
        &self,
        authentication_flow: AuthenticationFlow<RT>,
        state_fn: SF,
        nonce_fn: NF,
    ) -> AuthorizationRequest<AD, P, RT>
    where
        NF: FnOnce() -> Nonce + 'static,
        SF: FnOnce() -> CsrfToken + 'static,
    {
        AuthorizationRequest {
            inner: self.oauth2_client.authorize_url(state_fn),
            acr_values: Vec::new(),
            authentication_flow,
            claims_locales: Vec::new(),
            display: None,
            id_token_hint: None,
            login_hint: None,
            max_age: None,
            nonce: nonce_fn(),
            prompts: Vec::new(),
            ui_locales: Vec::new(),
        }
        .add_scope(Scope::new(OPENID_SCOPE.to_string()))
    }

    ///
    /// Exchanges a code produced by a successful authorization process with an access token.
    ///
    /// Acquires ownership of the `code` because authorization codes may only be used once to
    /// retrieve an access token from the authorization server.
    ///
    /// See https://tools.ietf.org/html/rfc6749#section-4.1.3
    ///
    pub fn exchange_code(&self, code: AuthorizationCode) -> CodeTokenRequest<TE, TR, TT> {
        self.oauth2_client.exchange_code(code)
    }

    ///
    /// Exchanges a refresh token for an access token.
    ///
    /// See https://tools.ietf.org/html/rfc6749#section-6
    ///
    pub fn exchange_refresh_token<'a, 'b>(
        &'a self,
        refresh_token: &'b RefreshToken,
    ) -> RefreshTokenRequest<'b, TE, TR, TT>
    where
        'a: 'b,
    {
        self.oauth2_client.exchange_refresh_token(refresh_token)
    }

    ///
    /// Returns the associated provider metadata (if present).
    ///
    /// The provider metadata is only available if the Client was created using the `discover`
    /// or `from_dynamic_registration` methods. Otherwise, this function returns `None`.
    ///
    #[allow(clippy::type_complexity)]
    pub fn provider_metadata(
        &self,
    ) -> Option<&ProviderMetadata<AP, AD, CA, CN, CT, G, JE, JK, JS, JT, RM, RT, S>> {
        self.provider_metadata.as_ref()
    }
}

///
/// A request to the authorization endpoint
///
pub struct AuthorizationRequest<'a, AD, P, RT>
where
    AD: AuthDisplay,
    P: AuthPrompt,
    RT: ResponseType,
{
    inner: oauth2::AuthorizationRequest<'a>,
    acr_values: Vec<AuthenticationContextClass>,
    authentication_flow: AuthenticationFlow<RT>,
    claims_locales: Vec<LanguageTag>,
    display: Option<AD>,
    id_token_hint: Option<String>,
    login_hint: Option<LoginHint>,
    max_age: Option<Duration>,
    nonce: Nonce,
    prompts: Vec<P>,
    ui_locales: Vec<LanguageTag>,
}
impl<'a, AD, P, RT> AuthorizationRequest<'a, AD, P, RT>
where
    AD: AuthDisplay,
    P: AuthPrompt,
    RT: ResponseType,
{
    ///
    /// Appends a new scope to the authorization URL.
    ///
    pub fn add_scope(mut self, scope: Scope) -> Self {
        self.inner = self.inner.add_scope(scope);
        self
    }

    ///
    /// Appends an extra param to the authorization URL.
    ///
    /// This method allows extensions to be used without direct support from
    /// this crate. If `name` conflicts with a parameter managed by this crate, the
    /// behavior is undefined. In particular, do not set parameters defined by
    /// [RFC 6749](https://tools.ietf.org/html/rfc6749) or
    /// [RFC 7636](https://tools.ietf.org/html/rfc7636).
    ///
    /// # Security Warning
    ///
    /// Callers should follow the security recommendations for any OAuth2 extensions used with
    /// this function, which are beyond the scope of
    /// [RFC 6749](https://tools.ietf.org/html/rfc6749).
    ///
    pub fn add_extra_param<N, V>(mut self, name: N, value: V) -> Self
    where
        N: Into<Cow<'a, str>>,
        V: Into<Cow<'a, str>>,
    {
        self.inner = self.inner.add_extra_param(name, value);
        self
    }

    ///
    /// Enables the use of [Proof Key for Code Exchange](https://tools.ietf.org/html/rfc7636)
    /// (PKCE).
    ///
    /// PKCE is *highly recommended* for all public clients (i.e., those for which there
    /// is no client secret or for which the client secret is distributed with the client,
    /// such as in a native, mobile app, or browser app).
    ///
    pub fn set_pkce_challenge(mut self, pkce_code_challenge: PkceCodeChallenge) -> Self {
        self.inner = self.inner.set_pkce_challenge(pkce_code_challenge);
        self
    }

    pub fn add_auth_context_value(mut self, acr_value: AuthenticationContextClass) -> Self {
        self.acr_values.push(acr_value);
        self
    }

    pub fn add_claims_locale(mut self, claims_locale: LanguageTag) -> Self {
        self.claims_locales.push(claims_locale);
        self
    }

    // TODO: support 'claims' parameter
    // https://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter

    pub fn set_display(mut self, display: AD) -> Self {
        self.display = Some(display);
        self
    }

    pub fn set_id_token_hint<AC, GC, JE, JS, JT>(
        mut self,
        id_token_hint: &'a IdToken<AC, GC, JE, JS, JT>,
    ) -> Self
    where
        AC: AdditionalClaims,
        GC: GenderClaim,
        JE: JweContentEncryptionAlgorithm<JT>,
        JS: JwsSigningAlgorithm<JT>,
        JT: JsonWebKeyType,
    {
        self.id_token_hint = Some(id_token_hint.to_string());
        self
    }

    pub fn set_login_hint(mut self, login_hint: LoginHint) -> Self {
        self.login_hint = Some(login_hint);
        self
    }

    pub fn set_max_age(mut self, max_age: Duration) -> Self {
        self.max_age = Some(max_age);
        self
    }

    pub fn add_prompt(mut self, prompt: P) -> Self {
        self.prompts.push(prompt);
        self
    }

    pub fn add_ui_locale(mut self, ui_locale: LanguageTag) -> Self {
        self.ui_locales.push(ui_locale);
        self
    }

    ///
    /// Returns the full authorization URL and CSRF state for this authorization
    /// request.
    ///
    pub fn url(self) -> (Url, CsrfToken, Nonce) {
        let response_type = match self.authentication_flow {
            AuthenticationFlow::AuthorizationCode => core::CoreResponseType::Code.to_oauth2(),
            AuthenticationFlow::Implicit(include_token) => {
                if include_token {
                    OAuth2ResponseType::new(
                        vec![
                            core::CoreResponseType::IdToken,
                            core::CoreResponseType::Token,
                        ]
                        .iter()
                        .map(variant_name)
                        .collect::<Vec<_>>()
                        .join(" "),
                    )
                } else {
                    core::CoreResponseType::IdToken.to_oauth2()
                }
            }
            AuthenticationFlow::Hybrid(ref response_types) => OAuth2ResponseType::new(
                response_types
                    .iter()
                    .map(variant_name)
                    .collect::<Vec<_>>()
                    .join(" "),
            ),
        };
        let (mut inner, nonce) = (
            self.inner
                .set_response_type(&response_type)
                .add_extra_param("nonce", self.nonce.secret().clone()),
            self.nonce,
        );
        if !self.acr_values.is_empty() {
            inner = inner.add_extra_param("acr_values", join_vec(&self.acr_values));
        }
        if !self.claims_locales.is_empty() {
            inner = inner.add_extra_param("claims_locales", join_vec(&self.claims_locales));
        }
        if let Some(ref display) = self.display {
            inner = inner.add_extra_param("display", display.as_ref());
        }
        if let Some(ref id_token_hint) = self.id_token_hint {
            inner = inner.add_extra_param("id_token_hint", id_token_hint);
        }
        if let Some(ref login_hint) = self.login_hint {
            inner = inner.add_extra_param("login_hint", login_hint.secret());
        }
        if let Some(max_age) = self.max_age {
            inner = inner.add_extra_param("max_age", max_age.as_secs().to_string());
        }
        if !self.prompts.is_empty() {
            inner = inner.add_extra_param("prompt", join_vec(&self.prompts));
        }
        if !self.ui_locales.is_empty() {
            inner = inner.add_extra_param("ui_locales", join_vec(&self.ui_locales));
        }

        let (url, state) = inner.url();
        (url, state, nonce)
    }
}

pub trait TokenResponse<AC, GC, JE, JS, JT, TT>: OAuth2TokenResponse<TT>
where
    AC: AdditionalClaims,
    GC: GenderClaim,
    JE: JweContentEncryptionAlgorithm<JT>,
    JS: JwsSigningAlgorithm<JT>,
    JT: JsonWebKeyType,
    TT: TokenType,
{
    fn id_token(&self) -> &IdToken<AC, GC, JE, JS, JT>;
}

impl<AC, EF, GC, JE, JS, JT, TT> TokenResponse<AC, GC, JE, JS, JT, TT>
    for StandardTokenResponse<IdTokenFields<AC, EF, GC, JE, JS, JT>, TT>
where
    AC: AdditionalClaims,
    EF: ExtraTokenFields,
    GC: GenderClaim,
    JE: JweContentEncryptionAlgorithm<JT>,
    JS: JwsSigningAlgorithm<JT>,
    JT: JsonWebKeyType,
    TT: TokenType,
{
    fn id_token(&self) -> &IdToken<AC, GC, JE, JS, JT> {
        self.extra_fields().id_token()
    }
}

fn join_vec<T>(entries: &[T]) -> String
where
    T: AsRef<str>,
{
    entries
        .iter()
        .map(AsRef::as_ref)
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use oauth2::{AuthUrl, ClientId, ClientSecret, CsrfToken, RedirectUrl, Scope, TokenUrl};
    use url::Url;

    #[cfg(feature = "nightly")]
    use super::core::CoreAuthenticationFlow;
    use super::core::{CoreAuthDisplay, CoreAuthPrompt, CoreClient, CoreIdToken, CoreResponseType};
    use super::{AuthenticationContextClass, AuthenticationFlow, LanguageTag, LoginHint, Nonce};

    fn new_client() -> CoreClient {
        color_backtrace::install();
        CoreClient::new(
            ClientId::new("aaa".to_string()),
            Some(ClientSecret::new("bbb".to_string())),
            AuthUrl::new(Url::parse("https://example/authorize").unwrap()),
            Some(TokenUrl::new(Url::parse("https://example/token").unwrap())),
        )
    }

    #[test]
    fn test_authorize_url_minimal() {
        let client = new_client();

        let (authorize_url, _, _) = client
            .authorize_url(
                AuthenticationFlow::AuthorizationCode::<CoreResponseType>,
                || CsrfToken::new("CSRF123".to_string()),
                || Nonce::new("NONCE456".to_string()),
            )
            .url();

        assert_eq!(
            "https://example/authorize?response_type=code&client_id=aaa&\
             state=CSRF123&scope=openid&nonce=NONCE456",
            authorize_url.to_string()
        );
    }

    #[test]
    fn test_authorize_url_full() {
        let client = new_client().set_redirect_uri(RedirectUrl::new(
            Url::parse("http://localhost:8888/").unwrap(),
        ));

        #[cfg(feature = "nightly")]
        let flow = CoreAuthenticationFlow::AuthorizationCode;
        #[cfg(not(feature = "nightly"))]
        let flow = AuthenticationFlow::AuthorizationCode::<CoreResponseType>;

        fn new_csrf() -> CsrfToken {
            CsrfToken::new("CSRF123".to_string())
        }
        fn new_nonce() -> Nonce {
            Nonce::new("NONCE456".to_string())
        }

        let (authorize_url, _, _) = client
            .authorize_url(flow.clone(), new_csrf, new_nonce)
            .add_scope(Scope::new("email".to_string()))
            .set_display(CoreAuthDisplay::Touch)
            .add_prompt(CoreAuthPrompt::Login)
            .add_prompt(CoreAuthPrompt::Consent)
            .set_max_age(Duration::from_secs(1800))
            .add_ui_locale(LanguageTag::new("fr-CA".to_string()))
            .add_ui_locale(LanguageTag::new("fr".to_string()))
            .add_ui_locale(LanguageTag::new("en".to_string()))
            .add_auth_context_value(AuthenticationContextClass::new(
                "urn:mace:incommon:iap:silver".to_string(),
            ))
            .url();
        assert_eq!(
            "https://example/authorize?response_type=code&client_id=aaa&\
             state=CSRF123&redirect_uri=http%3A%2F%2Flocalhost%3A8888%2F&scope=openid+email&\
             nonce=NONCE456&acr_values=urn%3Amace%3Aincommon%3Aiap%3Asilver&display=touch&\
             max_age=1800&prompt=login+consent&ui_locales=fr-CA+fr+en",
            authorize_url.to_string()
        );

        let serialized_jwt =
            "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwiYXVkIjpbIm15X2NsaWVudCJdL\
             CJleHAiOjE1NDQ5MzIxNDksImlhdCI6MTU0NDkyODU0OSwiYXV0aF90aW1lIjoxNTQ0OTI4NTQ4LCJub25jZSI\
             6InRoZV9ub25jZSIsImFjciI6InRoZV9hY3IiLCJzdWIiOiJzdWJqZWN0In0.gb5HuuyDMu-LvYvG-jJNIJPEZ\
             823qNwvgNjdAtW0HJpgwJWhJq0hOHUuZz6lvf8ud5xbg5GOo0Q37v3Ke08TvGu6E1USWjecZzp1aYVm9BiMvw5\
             EBRUrwAaOCG2XFjuOKUVfglSMJnRnoNqVVIWpCAr1ETjZzRIbkU3n5GQRguC5CwN5n45I3dtjoKuNGc2Ni-IMl\
             J2nRiCJOl2FtStdgs-doc-A9DHtO01x-5HCwytXvcE28Snur1JnqpUgmWrQ8gZMGuijKirgNnze2Dd5BsZRHZ2\
             CLGIwBsCnauBrJy_NNlQg4hUcSlGsuTa0dmZY7mCf4BN2WCpyOh0wgtkAgQ";
        let id_token = serde_json::from_value::<CoreIdToken>(serde_json::Value::String(
            serialized_jwt.to_string(),
        ))
        .unwrap();

        let (authorize_url, _, _) = client
            .authorize_url(flow, new_csrf, new_nonce)
            .add_scope(Scope::new("email".to_string()))
            .set_display(CoreAuthDisplay::Touch)
            .set_id_token_hint(&id_token)
            .set_login_hint(LoginHint::new("foo@bar.com".to_string()))
            .add_prompt(CoreAuthPrompt::Login)
            .add_prompt(CoreAuthPrompt::Consent)
            .set_max_age(Duration::from_secs(1800))
            .add_ui_locale(LanguageTag::new("fr-CA".to_string()))
            .add_ui_locale(LanguageTag::new("fr".to_string()))
            .add_ui_locale(LanguageTag::new("en".to_string()))
            .add_auth_context_value(AuthenticationContextClass::new(
                "urn:mace:incommon:iap:silver".to_string(),
            ))
            .add_extra_param("foo", "bar")
            .url();
        assert_eq!(
            format!(
                "https://example/authorize?response_type=code&client_id=aaa&state=CSRF123&\
                 redirect_uri=http%3A%2F%2Flocalhost%3A8888%2F&scope=openid+email&foo=bar&\
                 nonce=NONCE456&acr_values=urn%3Amace%3Aincommon%3Aiap%3Asilver&display=touch&\
                 id_token_hint={}&login_hint=foo%40bar.com&\
                 max_age=1800&prompt=login+consent&ui_locales=fr-CA+fr+en",
                serialized_jwt
            ),
            authorize_url.to_string()
        );
    }
}
