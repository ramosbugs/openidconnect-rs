// FIXME: uncomment
//#![warn(missing_docs)]

// FIXME: remove
//#![feature(trace_macros)]

//!
//! [OpenID Connect](http://openid.net/specs/openid-connect-core-1_0.html) support.
//!

// FIXME: specify the backward compatibility contract (e.g., no guarantee that non-JSON
// serializations will continue to deserialize; fields may be reordered, so assuming a particular
// order is undefined behavior).

extern crate base64;
extern crate chrono;
extern crate curl;
extern crate failure;
#[macro_use]
extern crate failure_derive;
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
extern crate itertools;

use std::marker::PhantomData;
use std::str;
use std::time::Duration;

use oauth2::helpers::variant_name;
use oauth2::prelude::*;
pub use oauth2::{
    AuthType, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, ErrorResponseType,
    ExtraTokenFields, RedirectUrl, RequestTokenError, Scope, TokenResponse, TokenType, TokenUrl,
};
use oauth2::ResponseType as OAuth2ResponseType;
use url::Url;

pub use claims::{
    AdditionalClaims, AddressClaim, EmptyAdditionalClaims, GenderClaim, StandardClaims,
};
pub use discovery::{DiscoveryError, ProviderMetadata};
pub use id_token::IdTokenFields;
pub use id_token::{IdToken, IdTokenClaims};
use jwt::{JsonWebToken, JsonWebTokenAccess, JsonWebTokenAlgorithm, JsonWebTokenHeader};
use registration::ClientRegistrationResponse;
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
    LanguageTag, LoginHint, LogoUrl, Nonce, OpPolicyUrl, OpTosUrl, PolicyUrl,
    RegistrationAccessToken, RegistrationUrl, RequestUrl, ResponseMode, ResponseType,
    ResponseTypes, SectorIdentifierUrl, ServiceDocUrl, StreetAddress, SubjectIdentifier,
    SubjectIdentifierType, ToSUrl,
};
pub use user_info::{UserInfoClaims, UserInfoError, UserInfoUrl};
use verification::{AudiencesClaim, IssuerClaim};
pub use verification::{
    ClaimsVerificationError, IdTokenVerifier, SignatureVerificationError, UserInfoVerifier,
};

// Defined first since other modules need the macros, and definition order is significant for
// macros. This module is private.
#[macro_use]
mod macros;

pub mod core;
pub mod discovery;
pub mod prelude {
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

pub struct Client<AC, AD, CA, CN, CT, G, GC, JE, JK, JS, JT, P, PM, RM, RT, S, TE, TT>
where
    AC: AdditionalClaims,
    AD: AuthDisplay,
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
    PM: ProviderMetadata<AD, CA, CN, CT, G, JE, JK, JS, JT, RM, RT, S>,
    RM: ResponseMode,
    RT: ResponseType,
    S: SubjectIdentifierType,
    TE: ErrorResponseType,
    TT: TokenType,
{
    oauth2_client: oauth2::Client<IdTokenFields<AC, GC, JE, JS, JT>, TT, TE>,
    acr_values: Option<Vec<AuthenticationContextClass>>,
    claims_locales: Option<Vec<LanguageTag>>,
    client_id: ClientId,
    client_secret: Option<ClientSecret>,
    display: Option<AD>,
    max_age: Option<Duration>,
    prompts: Option<Vec<P>>,
    provider_metadata: Option<PM>,
    ui_locales: Option<Vec<LanguageTag>>,
    _phantom_ca: PhantomData<CA>,
    _phantom_cn: PhantomData<CN>,
    _phantom_ct: PhantomData<CT>,
    _phantom_g: PhantomData<G>,
    _phantom_jk: PhantomData<JK>,
    _phantom_jt: PhantomData<JT>,
    _phantom_rm: PhantomData<RM>,
    _phantom_rt: PhantomData<RT>,
    _phantom_s: PhantomData<S>,
    // FIXME: Other parameters MAY be sent. See Sections 3.2.2, 3.3.2, 5.2, 5.5, 6, and 7.2.1 for
    // additional Authorization Request parameters and parameter values defined by this
    // specification.
}
impl<AC, AD, CA, CN, CT, G, GC, JE, JK, JS, JT, P, PM, RM, RT, S, TE, TT>
    Client<AC, AD, CA, CN, CT, G, GC, JE, JK, JS, JT, P, PM, RM, RT, S, TE, TT>
where
    AC: AdditionalClaims,
    AD: AuthDisplay,
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
    PM: ProviderMetadata<AD, CA, CN, CT, G, JE, JK, JS, JT, RM, RT, S>,
    RM: ResponseMode,
    RT: ResponseType,
    S: SubjectIdentifierType,
    TE: ErrorResponseType,
    TT: TokenType,
{
    pub fn new(
        client_id: ClientId,
        client_secret: Option<ClientSecret>,
        auth_url: AuthUrl,
        token_url: Option<TokenUrl>,
    ) -> Client<AC, AD, CA, CN, CT, G, GC, JE, JK, JS, JT, P, PM, RM, RT, S, TE, TT> {
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
            _phantom_ca: PhantomData,
            _phantom_cn: PhantomData,
            _phantom_ct: PhantomData,
            _phantom_g: PhantomData,
            _phantom_jk: PhantomData,
            _phantom_jt: PhantomData,
            _phantom_rm: PhantomData,
            _phantom_rt: PhantomData,
            _phantom_s: PhantomData,
        }
    }

    pub fn discover(
        client_id: ClientId,
        client_secret: Option<ClientSecret>,
        issuer_url: &IssuerUrl,
    ) -> Result<Self, DiscoveryError> {
        let provider_metadata: PM = discovery::get_provider_metadata(issuer_url)?;

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
            _phantom_ca: PhantomData,
            _phantom_cn: PhantomData,
            _phantom_ct: PhantomData,
            _phantom_g: PhantomData,
            _phantom_jk: PhantomData,
            _phantom_jt: PhantomData,
            _phantom_rm: PhantomData,
            _phantom_rt: PhantomData,
            _phantom_s: PhantomData,
        })
    }
    pub fn from_dynamic_registration<AT, CR, JU, K>(
        provider_metadata: &PM,
        registration_response: &CR,
    ) -> Self
    where
        AT: ApplicationType,
        CR: ClientRegistrationResponse<AT, CA, G, JE, JK, JS, JT, JU, K, RT, S>,
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
            _phantom_ca: PhantomData,
            _phantom_cn: PhantomData,
            _phantom_ct: PhantomData,
            _phantom_g: PhantomData,
            _phantom_jk: PhantomData,
            _phantom_jt: PhantomData,
            _phantom_rm: PhantomData,
            _phantom_rt: PhantomData,
            _phantom_s: PhantomData,
        }
    }

    ///
    /// Appends a new scope to the authorization URL.
    ///
    pub fn add_scope(mut self, scope: Scope) -> Self {
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

    pub fn auth_context_values(&self) -> Option<&Vec<AuthenticationContextClass>> {
        self.acr_values.as_ref()
    }
    pub fn set_auth_context_values(
        mut self,
        acr_values: Option<Vec<AuthenticationContextClass>>,
    ) -> Self {
        self.acr_values = acr_values;
        self
    }

    pub fn claims_locales(&self) -> Option<&Vec<LanguageTag>> {
        self.claims_locales.as_ref()
    }
    pub fn set_claims_locales(mut self, claims_locales: Option<Vec<LanguageTag>>) -> Self {
        self.claims_locales = claims_locales;
        self
    }

    pub fn display(&self) -> Option<&AD> {
        self.display.as_ref()
    }
    pub fn set_display(mut self, display: Option<AD>) -> Self {
        self.display = display;
        self
    }

    pub fn max_age(&self) -> Option<&Duration> {
        self.max_age.as_ref()
    }
    pub fn set_max_age(mut self, max_age: Option<Duration>) -> Self {
        self.max_age = max_age;
        self
    }

    pub fn prompts(&self) -> Option<&Vec<P>> {
        self.prompts.as_ref()
    }
    pub fn set_prompts(mut self, prompts: Option<Vec<P>>) -> Self {
        self.prompts = prompts;
        self
    }

    pub fn ui_locales(&self) -> Option<&Vec<LanguageTag>> {
        self.ui_locales.as_ref()
    }
    pub fn set_ui_locales(mut self, ui_locales: Option<Vec<LanguageTag>>) -> Self {
        self.ui_locales = ui_locales;
        self
    }

    pub fn id_token_verifier<JU, K>(&self) -> Result<IdTokenVerifier<JS, JT, JU, K>, DiscoveryError>
    where
        JU: JsonWebKeyUse,
        K: JsonWebKey<JS, JT, JU>,
    {
        let provider_metadata = self
            .provider_metadata
            .as_ref()
            .ok_or_else(|| DiscoveryError::Other("no provider metadata present".to_string()))?;
        let jwks_uri = provider_metadata.jwks_uri().ok_or_else(|| {
            DiscoveryError::Other("provider metadata contains no `jwks_uri`".to_string())
        })?;
        let signature_keys = jwks_uri.get_keys()?;
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

    pub fn authorize_url<NF, SF>(
        &self,
        authentication_flow: &AuthenticationFlow<RT>,
        state_fn: SF,
        nonce_fn: NF,
    ) -> (Url, CsrfToken, Nonce)
    where
        NF: Fn() -> Nonce,
        SF: Fn() -> CsrfToken,
    {
        self.authorize_url_with_hint(authentication_flow, state_fn, nonce_fn, None, None)
    }

    pub fn authorize_url_with_hint<NF, SF>(
        &self,
        authentication_flow: &AuthenticationFlow<RT>,
        state_fn: SF,
        nonce_fn: NF,
        id_token_hint: Option<&IdToken<AC, GC, JE, JS, JT>>,
        login_hint: Option<&LoginHint>,
    ) -> (Url, CsrfToken, Nonce)
    where
        NF: Fn() -> Nonce,
        SF: Fn() -> CsrfToken,
    {
        // Create string versions of any options that need to be converted. This must be done
        // before creating extra_params so that the lifetimes extend beyond extra_params's lifetime.
        let acr_values_opt = join_optional_vec(self.auth_context_values());
        let claims_locales_opt = join_optional_vec(self.claims_locales());
        let max_age_opt = self.max_age().map(|max_age| max_age.as_secs().to_string());
        let prompts_opt = join_optional_vec(self.prompts());
        let ui_locales_opt = join_optional_vec(self.ui_locales());

        let nonce = nonce_fn();

        let (url, state) = {
            let mut extra_params: Vec<(&str, &str)> = vec![("nonce", nonce.secret())];

            if let Some(ref acr_values) = acr_values_opt {
                extra_params.push(("acr_values", acr_values));
            }

            if let Some(ref claims_locales) = claims_locales_opt {
                extra_params.push(("claims_locales", claims_locales));
            }

            if let Some(display) = self.display() {
                extra_params.push(("display", display.to_str()));
            }

            // FIXME: uncomment
            /*
                        if let Some(id_token_hint) = id_token_hint {
                            extra_params.push(("id_token_hint", id_token_hint));
                        }
            */

            if let Some(login_hint) = login_hint {
                extra_params.push(("login_hint", login_hint.secret()));
            }

            if let Some(ref max_age) = max_age_opt {
                extra_params.push(("max_age", max_age));
            }

            if let Some(ref prompts) = prompts_opt {
                extra_params.push(("prompt", prompts));
            }

            if let Some(ref ui_locales) = ui_locales_opt {
                extra_params.push(("ui_locales", ui_locales));
            }

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

    pub fn exchange_code(
        &self,
        code: AuthorizationCode,
    ) -> Result<TokenResponse<IdTokenFields<AC, GC, JE, JS, JT>, TT>, RequestTokenError<TE>> {
        self.oauth2_client.exchange_code(code)
    }

    ///
    /// Returns the associated provider metadata (if present).
    ///
    /// The provider metadata is only available if the Client was created using the `discover`
    /// or `from_dynamic_registration` methods. Otherwise, this function returns `None`.
    ///
    pub fn provider_metadata(&self) -> Option<&PM> {
        self.provider_metadata.as_ref()
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
                .map(|entries| entries.as_ref())
                .collect::<Vec<_>>()
                .join(" "),
        ),
        None => None,
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use oauth2::prelude::*;
    use oauth2::{AuthUrl, ClientId, ClientSecret, CsrfToken, RedirectUrl, Scope, TokenUrl};
    use url::Url;

    use super::core::{CoreAuthDisplay, CoreAuthPrompt, CoreClient, CoreResponseType};
    use super::{AuthenticationContextClass, AuthenticationFlow, LanguageTag, Nonce};

    fn new_client() -> CoreClient {
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

        let (authorize_url, _, _) = client.authorize_url(
            &AuthenticationFlow::AuthorizationCode::<CoreResponseType>,
            || CsrfToken::new("CSRF123".to_string()),
            || Nonce::new("NONCE456".to_string()),
        );

        assert_eq!(
            "https://example/authorize?response_type=code&client_id=aaa&\
             redirect_uri=http%3A%2F%2Flocalhost%3A8888%2F&scope=openid+email&state=CSRF123&\
             nonce=NONCE456&acr_values=urn%3Amace%3Aincommon%3Aiap%3Asilver&display=touch&\
             max_age=1800&prompt=login+consent&ui_locales=fr-CA+fr+en",
            authorize_url.to_string()
        );
    }
}
