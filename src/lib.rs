// FIXME: uncomment
//#![warn(missing_docs)]

#![cfg_attr(feature = "nightly", feature(type_alias_enum_variants))]

//!
//! [OpenID Connect](http://openid.net/specs/openid-connect-core-1_0.html) support.
//!

extern crate base64;
extern crate chrono;
extern crate curl;
extern crate failure;
#[macro_use]
extern crate failure_derive;
extern crate itertools;
#[macro_use]
extern crate log;
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

use std::marker::PhantomData;
use std::str;
use std::time::Duration;

use oauth2::helpers::variant_name;
use oauth2::prelude::*;
use oauth2::ResponseType as OAuth2ResponseType;
pub use oauth2::{
    AccessToken, AuthType, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
    ErrorResponseType, ExtraTokenFields, RedirectUrl, RequestTokenError, Scope,
    StandardTokenResponse, TokenResponse as OAuth2TokenResponse, TokenType, TokenUrl,
};
use url::Url;

pub use claims::{
    AdditionalClaims, AddressClaim, EmptyAdditionalClaims, GenderClaim, StandardClaims,
};
pub use discovery::{
    get_provider_metadata, AdditionalProviderMetadata, DiscoveryError,
    EmptyAdditionalProviderMetadata, JsonWebKeySetUrl, ProviderMetadata,
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
    InitiateLoginUrl, IssuerUrl, JsonWebKey, JsonWebKeyId, JsonWebKeySet, JsonWebKeyType,
    JsonWebKeyUse, JweContentEncryptionAlgorithm, JweKeyManagementAlgorithm, JwsSigningAlgorithm,
    LanguageTag, LoginHint, LogoUrl, Nonce, OpPolicyUrl, OpTosUrl, PolicyUrl, PrivateSigningKey,
    RegistrationAccessToken, RegistrationUrl, RequestUrl, ResponseMode, ResponseType,
    ResponseTypes, SectorIdentifierUrl, ServiceDocUrl, SigningError, StreetAddress,
    SubjectIdentifier, SubjectIdentifierType, ToSUrl,
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
mod discovery;
pub mod prelude {
    pub use super::{OAuth2TokenResponse, OpenIdConnect};
    pub use oauth2::prelude::*;
}
pub mod registration;

// Private modules since we may move types between different modules; these are exported publicly
// via the pub use above.
mod claims;
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

// Convenience trait to allow clients to mock out OIDC
pub trait OpenIdConnect<AC, AD, AP, CA, CN, CT, G, GC, JE, JK, JS, JT, P, RM, RT, S, TE, TR, TT>:
    Sized
where
    AC: AdditionalClaims,
    AD: AuthDisplay,
    AP: AdditionalProviderMetadata,
    CA: ClientAuthMethod,
    CN: ClaimName,
    CT: ClaimType,
    G: GrantType,
    GC: GenderClaim,
    JE: JweContentEncryptionAlgorithm,
    JK: JweKeyManagementAlgorithm,
    JS: JwsSigningAlgorithm<JT>,
    JT: JsonWebKeyType,
    P: AuthPrompt,
    RM: ResponseMode,
    RT: ResponseType,
    S: SubjectIdentifierType,
    TE: ErrorResponseType + 'static,
    TR: TokenResponse<AC, GC, JE, JS, JT, TT>,
    TT: TokenType + 'static,
{
    fn new(
        client_id: ClientId,
        client_secret: Option<ClientSecret>,
        auth_url: AuthUrl,
        token_url: Option<TokenUrl>,
    ) -> Self;
    fn discover(
        client_id: ClientId,
        client_secret: Option<ClientSecret>,
        issuer_url: &IssuerUrl,
    ) -> Result<Self, DiscoveryError>;
    #[allow(clippy::type_complexity)]
    fn from_dynamic_registration<A, AR, AT, JU, K>(
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
        K: JsonWebKey<JS, JT, JU>;
    fn add_scope(self, scope: Scope) -> Self;
    fn set_auth_type(self, auth_type: AuthType) -> Self;
    fn set_redirect_uri(self, redirect_uri: RedirectUrl) -> Self;
    fn auth_context_values(&self) -> Option<&Vec<AuthenticationContextClass>>;
    fn set_auth_context_values(self, acr_values: Option<Vec<AuthenticationContextClass>>) -> Self;
    fn claims_locales(&self) -> Option<&Vec<LanguageTag>>;
    fn set_claims_locales(self, claims_locales: Option<Vec<LanguageTag>>) -> Self;
    fn display(&self) -> Option<&AD>;
    fn set_display(self, display: Option<AD>) -> Self;
    fn max_age(&self) -> Option<&Duration>;
    fn set_max_age(self, max_age: Option<Duration>) -> Self;
    fn prompts(&self) -> Option<&Vec<P>>;
    fn set_prompts(self, prompts: Option<Vec<P>>) -> Self;
    fn ui_locales(&self) -> Option<&Vec<LanguageTag>>;
    fn set_ui_locales(self, ui_locales: Option<Vec<LanguageTag>>) -> Self;
    fn id_token_verifier<JU, K>(&self) -> Result<IdTokenVerifier<JS, JT, JU, K>, DiscoveryError>
    where
        JU: JsonWebKeyUse,
        K: JsonWebKey<JS, JT, JU>;
    fn authorize_url<NF, SF>(
        &self,
        authentication_flow: &AuthenticationFlow<RT>,
        state_fn: SF,
        nonce_fn: NF,
    ) -> (Url, CsrfToken, Nonce)
    where
        NF: FnOnce() -> Nonce + 'static,
        SF: FnOnce() -> CsrfToken + 'static;
    fn authorize_url_with_hint<NF, SF>(
        &self,
        authentication_flow: &AuthenticationFlow<RT>,
        state_fn: SF,
        nonce_fn: NF,
        id_token_hint: Option<&IdToken<AC, GC, JE, JS, JT>>,
        login_hint: Option<&LoginHint>,
    ) -> (Url, CsrfToken, Nonce)
    where
        NF: FnOnce() -> Nonce + 'static,
        SF: FnOnce() -> CsrfToken + 'static;
    fn exchange_code(&self, code: AuthorizationCode) -> Result<TR, RequestTokenError<TE>>;
    #[allow(clippy::type_complexity)]
    fn provider_metadata(
        &self,
    ) -> Option<&ProviderMetadata<AP, AD, CA, CN, CT, G, JE, JK, JS, JT, RM, RT, S>>;
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
    JE: JweContentEncryptionAlgorithm,
    JK: JweKeyManagementAlgorithm,
    JS: JwsSigningAlgorithm<JT>,
    JT: JsonWebKeyType,
    P: AuthPrompt,
    RM: ResponseMode,
    RT: ResponseType,
    S: SubjectIdentifierType,
    TE: ErrorResponseType + 'static,
    TR: TokenResponse<AC, GC, JE, JS, JT, TT>,
    TT: TokenType + 'static,
{
    oauth2_client: oauth2::Client<TE, TR, TT>,
    acr_values: Option<Vec<AuthenticationContextClass>>,
    claims_locales: Option<Vec<LanguageTag>>,
    client_id: ClientId,
    client_secret: Option<ClientSecret>,
    display: Option<AD>,
    max_age: Option<Duration>,
    prompts: Option<Vec<P>>,
    #[allow(clippy::type_complexity)]
    provider_metadata: Option<ProviderMetadata<AM, AD, CA, CN, CT, G, JE, JK, JS, JT, RM, RT, S>>,
    ui_locales: Option<Vec<LanguageTag>>,
    _phantom_ac: PhantomData<AC>,
    _phantom_ca: PhantomData<CA>,
    _phantom_cn: PhantomData<CN>,
    _phantom_ct: PhantomData<CT>,
    _phantom_g: PhantomData<G>,
    _phantom_gc: PhantomData<GC>,
    _phantom_je: PhantomData<JE>,
    _phantom_jk: PhantomData<JK>,
    _phantom_js: PhantomData<JS>,
    _phantom_jt: PhantomData<JT>,
    _phantom_rm: PhantomData<RM>,
    _phantom_rt: PhantomData<RT>,
    _phantom_s: PhantomData<S>,
    // FIXME: Other parameters MAY be sent. See Sections 3.2.2, 3.3.2, 5.2, 5.5, 6, and 7.2.1 for
    // additional Authorization Request parameters and parameter values defined by this
    // specification.
}
impl<AC, AD, AP, CA, CN, CT, G, GC, JE, JK, JS, JT, P, RM, RT, S, TE, TR, TT>
    OpenIdConnect<AC, AD, AP, CA, CN, CT, G, GC, JE, JK, JS, JT, P, RM, RT, S, TE, TR, TT>
    for Client<AC, AD, AP, CA, CN, CT, G, GC, JE, JK, JS, JT, P, RM, RT, S, TE, TR, TT>
where
    AC: AdditionalClaims,
    AD: AuthDisplay,
    AP: AdditionalProviderMetadata,
    CA: ClientAuthMethod,
    CN: ClaimName,
    CT: ClaimType,
    G: GrantType,
    GC: GenderClaim,
    JE: JweContentEncryptionAlgorithm,
    JK: JweKeyManagementAlgorithm,
    JS: JwsSigningAlgorithm<JT>,
    JT: JsonWebKeyType,
    P: AuthPrompt,
    RM: ResponseMode,
    RT: ResponseType,
    S: SubjectIdentifierType,
    TE: ErrorResponseType,
    TR: TokenResponse<AC, GC, JE, JS, JT, TT>,
    TT: TokenType,
{
    fn new(
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
        )
        .add_scope(Scope::new(OPENID_SCOPE.to_string()));
        Client {
            oauth2_client,
            acr_values: None,
            claims_locales: None,
            client_id,
            client_secret,
            display: None,
            max_age: None,
            prompts: None,
            provider_metadata: None,
            ui_locales: None,
            _phantom_ac: PhantomData,
            _phantom_ca: PhantomData,
            _phantom_cn: PhantomData,
            _phantom_ct: PhantomData,
            _phantom_g: PhantomData,
            _phantom_gc: PhantomData,
            _phantom_je: PhantomData,
            _phantom_jk: PhantomData,
            _phantom_js: PhantomData,
            _phantom_jt: PhantomData,
            _phantom_rm: PhantomData,
            _phantom_rt: PhantomData,
            _phantom_s: PhantomData,
        }
    }

    fn discover(
        client_id: ClientId,
        client_secret: Option<ClientSecret>,
        issuer_url: &IssuerUrl,
    ) -> Result<Self, DiscoveryError> {
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
        > = discovery::get_provider_metadata(issuer_url)?;

        let oauth2_client = oauth2::Client::new(
            client_id.clone(),
            client_secret.clone(),
            provider_metadata.authorization_endpoint().clone(),
            provider_metadata.token_endpoint().cloned(),
        )
        .add_scope(Scope::new(OPENID_SCOPE.to_string()));
        Ok(Client {
            oauth2_client,
            acr_values: None,
            claims_locales: None,
            client_id,
            client_secret,
            display: None,
            max_age: None,
            prompts: None,
            provider_metadata: Some(provider_metadata),
            ui_locales: None,
            _phantom_ac: PhantomData,
            _phantom_ca: PhantomData,
            _phantom_cn: PhantomData,
            _phantom_ct: PhantomData,
            _phantom_g: PhantomData,
            _phantom_gc: PhantomData,
            _phantom_je: PhantomData,
            _phantom_jk: PhantomData,
            _phantom_js: PhantomData,
            _phantom_jt: PhantomData,
            _phantom_rm: PhantomData,
            _phantom_rt: PhantomData,
            _phantom_s: PhantomData,
        })
    }

    #[allow(clippy::type_complexity)]
    fn from_dynamic_registration<A, AR, AT, JU, K>(
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
        )
        .add_scope(Scope::new(OPENID_SCOPE.to_string()));
        Client {
            oauth2_client,
            acr_values: None,
            claims_locales: None,
            client_id: registration_response.client_id().clone(),
            client_secret: registration_response.client_secret().cloned(),
            display: None,
            max_age: None,
            prompts: None,
            provider_metadata: Some(provider_metadata.clone()),
            ui_locales: None,
            _phantom_ac: PhantomData,
            _phantom_ca: PhantomData,
            _phantom_cn: PhantomData,
            _phantom_ct: PhantomData,
            _phantom_g: PhantomData,
            _phantom_gc: PhantomData,
            _phantom_je: PhantomData,
            _phantom_jk: PhantomData,
            _phantom_js: PhantomData,
            _phantom_jt: PhantomData,
            _phantom_rm: PhantomData,
            _phantom_rt: PhantomData,
            _phantom_s: PhantomData,
        }
    }

    ///
    /// Appends a new scope to the authorization URL.
    ///
    fn add_scope(mut self, scope: Scope) -> Self {
        self.oauth2_client = self.oauth2_client.add_scope(scope);
        self
    }

    ///
    /// Configures the type of client authentication used for communicating with the authorization
    /// server.
    ///
    /// The default is to use HTTP Basic authentication, as recommended in
    /// [Section 2.3.1 of RFC 6749](https://tools.ietf.org/html/rfc6749#section-2.3.1).
    ///
    fn set_auth_type(mut self, auth_type: AuthType) -> Self {
        self.oauth2_client = self.oauth2_client.set_auth_type(auth_type);
        self
    }

    ///
    /// Sets the the redirect URL used by the authorization endpoint.
    ///
    fn set_redirect_uri(mut self, redirect_uri: RedirectUrl) -> Self {
        self.oauth2_client = self.oauth2_client.set_redirect_url(redirect_uri);
        self
    }

    fn auth_context_values(&self) -> Option<&Vec<AuthenticationContextClass>> {
        self.acr_values.as_ref()
    }
    fn set_auth_context_values(
        mut self,
        acr_values: Option<Vec<AuthenticationContextClass>>,
    ) -> Self {
        self.acr_values = acr_values;
        self
    }

    fn claims_locales(&self) -> Option<&Vec<LanguageTag>> {
        self.claims_locales.as_ref()
    }
    fn set_claims_locales(mut self, claims_locales: Option<Vec<LanguageTag>>) -> Self {
        self.claims_locales = claims_locales;
        self
    }

    fn display(&self) -> Option<&AD> {
        self.display.as_ref()
    }
    fn set_display(mut self, display: Option<AD>) -> Self {
        self.display = display;
        self
    }

    fn max_age(&self) -> Option<&Duration> {
        self.max_age.as_ref()
    }
    fn set_max_age(mut self, max_age: Option<Duration>) -> Self {
        self.max_age = max_age;
        self
    }

    fn prompts(&self) -> Option<&Vec<P>> {
        self.prompts.as_ref()
    }
    fn set_prompts(mut self, prompts: Option<Vec<P>>) -> Self {
        self.prompts = prompts;
        self
    }

    fn ui_locales(&self) -> Option<&Vec<LanguageTag>> {
        self.ui_locales.as_ref()
    }
    fn set_ui_locales(mut self, ui_locales: Option<Vec<LanguageTag>>) -> Self {
        self.ui_locales = ui_locales;
        self
    }

    fn id_token_verifier<JU, K>(&self) -> Result<IdTokenVerifier<JS, JT, JU, K>, DiscoveryError>
    where
        JU: JsonWebKeyUse,
        K: JsonWebKey<JS, JT, JU>,
    {
        let provider_metadata = self
            .provider_metadata
            .as_ref()
            .ok_or_else(|| DiscoveryError::Other("no provider metadata present".to_string()))?;
        let signature_keys = provider_metadata.jwks_uri().get_keys()?;
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

    fn authorize_url<NF, SF>(
        &self,
        authentication_flow: &AuthenticationFlow<RT>,
        state_fn: SF,
        nonce_fn: NF,
    ) -> (Url, CsrfToken, Nonce)
    where
        NF: FnOnce() -> Nonce + 'static,
        SF: FnOnce() -> CsrfToken + 'static,
    {
        self.authorize_url_with_hint(authentication_flow, state_fn, nonce_fn, None, None)
    }

    fn authorize_url_with_hint<NF, SF>(
        &self,
        authentication_flow: &AuthenticationFlow<RT>,
        state_fn: SF,
        nonce_fn: NF,
        id_token_hint: Option<&IdToken<AC, GC, JE, JS, JT>>,
        login_hint: Option<&LoginHint>,
    ) -> (Url, CsrfToken, Nonce)
    where
        NF: FnOnce() -> Nonce + 'static,
        SF: FnOnce() -> CsrfToken + 'static,
    {
        // Create string versions of any options that need to be converted. This must be done
        // before creating extra_params so that the lifetimes extend beyond extra_params's lifetime.
        let acr_values_opt = join_optional_vec(self.auth_context_values());
        let claims_locales_opt = join_optional_vec(self.claims_locales());
        let max_age_opt = self.max_age().map(|max_age| max_age.as_secs().to_string());
        let prompts_opt = join_optional_vec(self.prompts());
        let ui_locales_opt = join_optional_vec(self.ui_locales());
        let id_token_hint_str = id_token_hint.map(ToString::to_string);

        let nonce = nonce_fn();

        fn param_or_none<'a, T>(param: Option<&'a T>, name: &'a str) -> Option<(&'a str, &'a str)>
        where
            T: AsRef<str> + 'a,
        {
            if let Some(p) = param {
                Some((name, p.as_ref()))
            } else {
                None
            }
        }

        let (url, state) = {
            let extra_params: Vec<(&str, &str)> = vec![
                Some(("nonce", nonce.secret().as_str())),
                param_or_none(acr_values_opt.as_ref(), "acr_values"),
                param_or_none(claims_locales_opt.as_ref(), "claims_locales"),
                param_or_none(self.display(), "display"),
                param_or_none(id_token_hint_str.as_ref(), "id_token_hint"),
                param_or_none(login_hint.map(SecretNewType::secret), "login_hint"),
                param_or_none(max_age_opt.as_ref(), "max_age"),
                param_or_none(prompts_opt.as_ref(), "prompt"),
                param_or_none(ui_locales_opt.as_ref(), "ui_locales"),
            ]
            .into_iter()
            .filter(Option::is_some)
            .map(Option::unwrap)
            .collect();

            let response_type = match *authentication_flow {
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

            self.oauth2_client
                .authorize_url_extension(&response_type, state_fn, &extra_params)
        };
        (url, state, nonce)
    }

    fn exchange_code(&self, code: AuthorizationCode) -> Result<TR, RequestTokenError<TE>> {
        self.oauth2_client.exchange_code(code)
    }

    ///
    /// Returns the associated provider metadata (if present).
    ///
    /// The provider metadata is only available if the Client was created using the `discover`
    /// or `from_dynamic_registration` methods. Otherwise, this function returns `None`.
    ///
    #[allow(clippy::type_complexity)]
    fn provider_metadata(
        &self,
    ) -> Option<&ProviderMetadata<AP, AD, CA, CN, CT, G, JE, JK, JS, JT, RM, RT, S>> {
        self.provider_metadata.as_ref()
    }
}

pub trait TokenResponse<AC, GC, JE, JS, JT, TT>: OAuth2TokenResponse<TT>
where
    AC: AdditionalClaims,
    GC: GenderClaim,
    JE: JweContentEncryptionAlgorithm,
    JS: JwsSigningAlgorithm<JT>,
    JT: JsonWebKeyType,
    TT: TokenType,
{
    fn id_token(&self) -> &IdToken<AC, GC, JE, JS, JT>;
}

impl<AC, GC, JE, JS, JT, TT> TokenResponse<AC, GC, JE, JS, JT, TT>
    for StandardTokenResponse<IdTokenFields<AC, GC, JE, JS, JT>, TT>
where
    AC: AdditionalClaims,
    GC: GenderClaim,
    JE: JweContentEncryptionAlgorithm,
    JS: JwsSigningAlgorithm<JT>,
    JT: JsonWebKeyType,
    TT: TokenType,
{
    fn id_token(&self) -> &IdToken<AC, GC, JE, JS, JT> {
        self.extra_fields().id_token()
    }
}

fn join_optional_vec<T>(vec_opt: Option<&Vec<T>>) -> Option<String>
where
    T: AsRef<str>,
{
    match vec_opt {
        Some(entries) => Some(
            entries
                .iter()
                .map(AsRef::as_ref)
                .collect::<Vec<_>>()
                .join(" "),
        ),
        None => None,
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use oauth2::{AuthUrl, ClientId, ClientSecret, CsrfToken, RedirectUrl, Scope, TokenUrl};
    use url::Url;

    #[cfg(feature = "nightly")]
    use super::core::CoreAuthenticationFlow;
    use super::core::{CoreAuthDisplay, CoreAuthPrompt, CoreClient, CoreIdToken, CoreResponseType};
    use super::prelude::*;
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

        let (authorize_url, _, _) = client.authorize_url(
            &AuthenticationFlow::AuthorizationCode::<CoreResponseType>,
            || CsrfToken::new("CSRF123".to_string()),
            || Nonce::new("NONCE456".to_string()),
        );

        assert_eq!(
            "https://example/authorize?response_type=code&client_id=aaa&scope=openid&\
             state=CSRF123&nonce=NONCE456",
            authorize_url.to_string()
        );
    }

    #[test]
    fn test_authorize_url_full() {
        let client = new_client()
            .add_scope(Scope::new("email".to_string()))
            .set_redirect_uri(RedirectUrl::new(
                Url::parse("http://localhost:8888/").unwrap(),
            ))
            .set_display(Some(CoreAuthDisplay::Touch))
            .set_prompts(Some(vec![CoreAuthPrompt::Login, CoreAuthPrompt::Consent]))
            .set_max_age(Some(Duration::from_secs(1800)))
            .set_ui_locales(Some(vec![
                LanguageTag::new("fr-CA".to_string()),
                LanguageTag::new("fr".to_string()),
                LanguageTag::new("en".to_string()),
            ]))
            .set_auth_context_values(Some(vec![AuthenticationContextClass::new(
                "urn:mace:incommon:iap:silver".to_string(),
            )]));

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

        let (authorize_url, _, _) = client.authorize_url(&flow, new_csrf, new_nonce);
        assert_eq!(
            "https://example/authorize?response_type=code&client_id=aaa&\
             redirect_uri=http%3A%2F%2Flocalhost%3A8888%2F&scope=openid+email&state=CSRF123&\
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

        let (authorize_url, _, _) = client.authorize_url_with_hint(
            &flow,
            new_csrf,
            new_nonce,
            Some(&id_token),
            Some(&LoginHint::new("foo@bar.com".to_string())),
        );
        assert_eq!(
            format!(
                "https://example/authorize?response_type=code&client_id=aaa&\
                 redirect_uri=http%3A%2F%2Flocalhost%3A8888%2F&scope=openid+email&state=CSRF123&\
                 nonce=NONCE456&acr_values=urn%3Amace%3Aincommon%3Aiap%3Asilver&display=touch&\
                 id_token_hint={}&login_hint=foo%40bar.com&\
                 max_age=1800&prompt=login+consent&ui_locales=fr-CA+fr+en",
                serialized_jwt
            ),
            authorize_url.to_string()
        );
    }
}
