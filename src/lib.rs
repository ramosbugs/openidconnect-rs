// FIXME: uncomment
//#![warn(missing_docs)]
//!
//! [OpenID Connect](http://openid.net/specs/openid-connect-core-1_0.html) support.
//!

extern crate curl;
extern crate failure;
#[macro_use] extern crate failure_derive;
#[macro_use] extern crate oauth2;
extern crate serde;
#[macro_use] extern crate serde_derive;
extern crate serde_json;
extern crate url;

use std::convert::From;
use std::fmt::{Debug, Display, Error as FormatterError, Formatter};
use std::marker::PhantomData;
use std::time::Duration;

use curl::easy::Easy;
use oauth2::prelude::*;
use oauth2::{
    AccessToken,
    AuthType,
    AuthUrl,
    ClientId,
    ClientSecret,
    CsrfToken,
    ErrorResponseType,
    RedirectUrl,
    RefreshToken,
    Scope,
    TokenType,
    TokenUrl,
};
use oauth2::basic::{
    BasicClient,
    BasicErrorResponse,
    BasicErrorResponseType,
    BasicRequestTokenError,
    BasicToken,
    BasicTokenType,
};
use oauth2::helpers::{deserialize_url, serialize_url};
use serde::Serialize;
use serde::de::DeserializeOwned;
use url::Url;

use http::{HttpRequest, HttpRequestMethod, HttpResponse};
use macros::TraitStructExtract;

// Defined first since other modules need the macros, and definition order is significant for
// macros.
#[macro_use] pub mod macros;

pub mod core;
pub mod discovery;
pub mod types;

use discovery::DiscoveryError;

// Flatten the module hierarchy involving types. They're only separated to improve code
// organization.
pub use types::*;

mod http;


const ACCEPT_JSON: (&str, &str) = ("Accept", CONTENT_TYPE_JSON);
const CONFIG_URL_SUFFIX: &str = ".well-known/openid-configuration";
const CONTENT_TYPE_JSON: &str = "application/json";
const OPENID_SCOPE: &str = "openid";


pub struct Client<
    TT: TokenType,
    T: oauth2::Token<TT>,
    TE: ErrorResponseType,
    ID: IdToken
>(
    oauth2::Client<TT, T, TE>,
    PhantomData<ID>,
);

impl<TT, T, TE, ID> Client<TT, T, TE, ID>
where TT: TokenType, T: oauth2::Token<TT>, TE: ErrorResponseType, ID: IdToken {
    pub fn new(
        client_id: ClientId,
        client_secret: Option<ClientSecret>,
        auth_url: AuthUrl,
        token_url: TokenUrl
    ) -> Client<TT, T, TE, ID> {
        let client =
            oauth2::Client::new(client_id, client_secret, auth_url, token_url)
                .add_scope(Scope::new(OPENID_SCOPE.to_string()));
        Client(client, PhantomData)
    }

    pub fn discover(
        client_id: ClientId,
        client_secret: Option<ClientSecret>,
        issuer_url: IssuerUrl
    ) -> Result<()/*Client<TT, T, TE, ID>*/, DiscoveryError> {
        let discover_url =
            issuer_url
                .join(CONFIG_URL_SUFFIX)
                .map_err(DiscoveryError::UrlParse)?;
        let discover_response =
            HttpRequest {
                url: discover_url,
                method: HttpRequestMethod::Get,
                headers: vec![ACCEPT_JSON],
                post_body: vec![],
            }
            .request()
            .map_err(DiscoveryError::Request)?;

        discover_response
            .check_content_type(CONTENT_TYPE_JSON)
            .map_err(DiscoveryError::Other)?;

        Ok(())
    }

    ///
    /// Appends a new scope to the authorization URL.
    ///
    pub fn add_scope(mut self, scope: Scope) -> Self {
        self.0 = self.0.add_scope(scope);
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
        self.0 = self.0.set_auth_type(auth_type);
        self
    }

    ///
    /// Sets the the redirect URL used by the authorization endpoint.
    ///
    pub fn set_redirect_url(mut self, redirect_url: RedirectUrl) -> Self {
        self.0 = self.0.set_redirect_url(redirect_url);
        self
    }

    pub fn authorize_url<D, P>(
        &self,
        auth_options: &AuthOptions<D, P>,
        state: &CsrfToken,
        nonce: &Nonce
    ) -> Url
    where D: AuthDisplay, P: AuthPrompt {
        self.authorize_url_with_hint(auth_options, state, nonce, None, None)
    }

    pub fn authorize_url_with_hint<D, P>(
        &self,
        auth_options: &AuthOptions<D, P>,
        state: &CsrfToken,
        nonce: &Nonce,
        id_token_hint_opt: Option<&ID>,
        login_hint_opt: Option<&LoginHint>,
    ) -> Url
    where D: AuthDisplay, P: AuthPrompt {
        // Create string versions of any options that need to be converted. This must be done
        // before creating extra_params so that the lifetimes extend beyond extra_params's lifetime.
        let id_token_hint_raw_opt = id_token_hint_opt.map(|id_token_hint| id_token_hint.raw());
        let max_age_opt = auth_options.max_age().map(|max_age| max_age.as_secs().to_string());
        let prompts_opt = join_optional_vec(auth_options.prompts());
        let ui_locales_opt = join_optional_vec(auth_options.ui_locales());
        let acr_values_opt = join_optional_vec(auth_options.acr_values());

        let mut extra_params: Vec<(&str, &str)> = vec![
            ("state", state.secret()),
            ("nonce", nonce.secret()),
        ];

        if let Some(display) = auth_options.display() {
            extra_params.push(("display", display.to_str()));
        }

        if let Some(ref prompts) = prompts_opt {
            extra_params.push(("prompt", prompts));
        }

        if let Some(ref max_age) = max_age_opt {
            extra_params.push(("max_age", max_age));
        }

        if let Some(ref ui_locales) = ui_locales_opt {
            extra_params.push(("ui_locales", ui_locales));
        }

        if let Some(id_token_hint_raw) = id_token_hint_raw_opt {
            extra_params.push(("id_token_hint", id_token_hint_raw));
        }

        if let Some(login_hint) = login_hint_opt {
            extra_params.push(("login_hint", login_hint.secret()));
        }

        if let Some(ref acr_values) = acr_values_opt {
            extra_params.push(("acr_values", acr_values));
        }

        self.0.authorize_url_extension(&core::CoreResponseType::Code.to_oauth2(), &extra_params)
    }
}

///
/// Authentication Request options.
///
/// The fields in this struct are a subset of the parameters defined in
/// [Section 3.1.2.1](http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest) that are
/// commonly shared across multiple authentication requests. Parameters that should be unique
/// to each request (i.e., for security reasons) are passed directly to `authorize_url` or
/// `authorize_url_with_hint`.
///
// FIXME: convert to a trait?
// FIXME: what's the rationale for this being separate from the Client interface? why do scopes
// go in the client but these things go here? putting everything in the client seems unclean, but
// then we should have a clear way to delineate the interfaces.
pub struct AuthOptions<D, P>
where D: AuthDisplay, P: AuthPrompt {
    _display: Option<D>,
    _prompts: Option<Vec<P>>,
    _max_age: Option<Duration>,
    _ui_locales: Option<Vec<LanguageTag>>,
    _acr_values: Option<Vec<AuthenticationContextClass>>,
}

impl<D, P> AuthOptions<D, P>
where D: AuthDisplay, P: AuthPrompt {
    pub fn new() -> Self {
        AuthOptions::<D, P> {
            _display: None,
            _prompts: None,
            _max_age: None,
            _ui_locales: None,
            _acr_values: None,
        }
    }

    ///
    /// How the Authorization Server displays the authentication and/or consent user interface pages
    /// to the End-User.
    ///
    pub fn display(&self) -> Option<&D> { self._display.as_ref() }

    ///
    /// Have the Authorization Server use the default authentication and/or consent display. This
    /// is equivalent to `CoreAuthDisplay::Page`.
    ///
    pub fn clear_display(mut self) -> Self {
        self._display = None;
        self
    }

    ///
    /// Set the Authorization Server authentication and/or user consent display.
    ///
    pub fn set_display(mut self, display: D) -> Self {
        self._display = Some(display);
        self
    }

    ///
    /// Whether the Authorization Server prompts the End-User for reauthentication and/or consent.
    ///
    pub fn prompts(&self) -> Option<&Vec<P>> { self._prompts.as_ref() }

    ///
    /// Have the Authorization Server choose whether to prompt the End-User for reauthentication
    /// and/or consent. This is *not* equivalent to `CoreAuthPrompt::None`, which
    /// forces the Authorization Server not to show any prompts.
    ///
    pub fn clear_prompts(mut self) -> Self {
        self._prompts = None;
        self
    }

    ///
    /// Specify a prompt that the Authorization Server should present to the End-User.
    ///
    /// NOTE: The Authorization Server will return an error if `CoreAuthPrompt::None`
    /// is combined with any other prompts.
    ///
    pub fn add_prompt(mut self, prompt: P) -> Self {
        if let Some(mut prompts) = self._prompts {
            prompts.push(prompt);
            self._prompts = Some(prompts);
        } else {
            self._prompts = Some(vec![prompt]);
        }
        self
    }

    ///
    /// Maximum Authentication Age.
    ///
    /// Specifies the allowable elapsed time in seconds since the last time the End-User was
    /// actively authenticated by the OP. If the elapsed time is greater than this value, the OP
    /// MUST attempt to actively re-authenticate the End-User.
    ///
    pub fn max_age(&self) -> Option<&Duration> { self._max_age.as_ref() }

    ///
    /// Allow the Authorization Server to choose its own maximum authentication age.
    ///
    pub fn clear_max_age(mut self) -> Self {
        self._max_age = None;
        self
    }

    ///
    /// Specify the maximum authentication age. See `max_age` for further information.
    ///
    pub fn set_max_age(mut self, max_age: Duration) -> Self {
        self._max_age = Some(max_age);
        self
    }

    ///
    /// End-User's preferred languages and scripts for the user interface, in order of preference.
    ///
    /// An error SHOULD NOT result if some or all of the requested locales are not supported by the
    /// OpenID Provider.
    ///
    pub fn ui_locales(&self) -> Option<&Vec<LanguageTag>> { self._ui_locales.as_ref() }

    ///
    /// Allow the Authorization Server to choose the languages and scripts for the user interface.
    ///
    pub fn clear_ui_locales(mut self) -> Self {
        self._ui_locales = None;
        self
    }

    ///
    /// Add a preferred language and/or script that the Authorization Server should use for the
    /// user interface.
    ///
    pub fn add_ui_locale(mut self, ui_locale: LanguageTag) -> Self {
        if let Some(mut ui_locales) = self._ui_locales {
            ui_locales.push(ui_locale);
            self._ui_locales = Some(ui_locales);
        } else {
            self._ui_locales = Some(vec![ui_locale]);
        }
        self
    }

    ///
    /// Requested Authentication Context Class Reference values.
    ///
    /// Specifies the `acr` values that the Authorization Server is being requested to use for
    /// processing this Authentication Request, with the values appearing in order of preference.
    /// The Authentication Context Class satisfied by the authentication performed is returned as
    /// the `acr` Claim Value, as specified in
    /// [Section 2](http://openid.net/specs/openid-connect-core-1_0.html#IDToken). The `acr` Claim
    /// is requested as a Voluntary Claim by this parameter.
    ///
    // FIXME: update this doc to refer to the ID Token methods we use to access the ACR claim value
    pub fn acr_values(&self) -> Option<&Vec<AuthenticationContextClass>> {
        self._acr_values.as_ref()
    }

    ///
    /// Do not request any Authentication Context Class Reference claims from the Authorization
    /// Server.
    ///
    pub fn clear_acr_values(mut self) -> Self {
        self._acr_values = None;
        self
    }

    ///
    /// Add a preferred Authentication Context Class Reference value to request as a claim from
    /// the Authorization Server.
    ///
    pub fn add_acr_value(mut self, acr_value: AuthenticationContextClass) -> Self {
        if let Some(mut acr_values) = self._acr_values {
            acr_values.push(acr_value);
            self._acr_values = Some(acr_values);
        } else {
            self._acr_values = Some(vec![acr_value]);
        }
        self
    }

    // FIXME: Other parameters MAY be sent. See Sections 3.2.2, 3.3.2, 5.2, 5.5, 6, and 7.2.1 for
    // additional Authorization Request parameters and parameter values defined by this
    // specification.
}

pub trait IdToken : Debug + DeserializeOwned + PartialEq + Serialize {
    fn raw(&self) -> &str;
}

///
/// OpenID Connect authorization token.
///
/// The fields in this struct are defined in
/// [Section 3.1.3.3](http://openid.net/specs/openid-connect-core-1_0.html#TokenResponse).
/// The fields are private and should be accessed via the getters.
///
#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub struct Token {
    #[serde(flatten)]
    _basic_token: BasicToken<BasicTokenType>,
    // FIXME: this should probably be something else
    _id_token: String
}

impl oauth2::Token<BasicTokenType> for Token {
    fn access_token(&self) -> &AccessToken { self._basic_token.access_token() }
    fn token_type(&self) -> &BasicTokenType { self._basic_token.token_type() }
    fn expires_in(&self) -> Option<Duration> { self._basic_token.expires_in() }
    fn refresh_token(&self) -> Option<&RefreshToken> { self._basic_token.refresh_token() }
    fn scopes(&self) -> Option<&Vec<Scope>> { self._basic_token.scopes() }

    fn from_json(data: &str) -> Result<Self, serde_json::error::Error> {
        serde_json::from_str(data)
    }
}

fn join_optional_vec<T>(vec_opt: Option<&Vec<T>>) -> Option<String> where T: AsRef<str> {
    match vec_opt {
        Some(entries) => Some(
            entries
                .iter()
                .map(|entries| entries.as_ref())
                .collect::<Vec<_>>()
                .join(" ")
        ),
        None => None,
    }
}
