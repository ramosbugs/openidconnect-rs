// FIXME: uncomment
//#![warn(missing_docs)]
//!
//! [OpenID Connect](http://openid.net/specs/openid-connect-core-1_0.html) support.
//!

extern crate oauth2;
extern crate serde;
#[macro_use] extern crate serde_derive;
extern crate serde_json;
extern crate url;

use oauth2::*;
use oauth2::basic::{
    BasicClient,
    BasicErrorResponse,
    BasicErrorResponseType,
    BasicRequestTokenError,
    BasicToken,
    BasicTokenType,
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::convert::From;
use std::fmt::{Debug, Display, Formatter};
use std::fmt::Error as FormatterError;
use std::marker::PhantomData;
use std::ops::Deref;
use std::time::Duration;
use url::Url;

///
/// How the Authorization Server displays the authentication and consent user interface pages to
/// the End-User.
///
pub trait OpenIdConnectAuthDisplay : Display + PartialEq {
    fn to_str(&self) -> &str;
}

///
/// Whether the Authorization Server should prompt the End-User for reauthentication and consent.
///
pub trait OpenIdConnectAuthPrompt : Display + PartialEq {
    fn to_str(&self) -> &str;
}

pub struct LanguageTag(String);
impl LanguageTag {
    pub fn new(s: &str) -> Self {
        LanguageTag(s.to_string())
    }
}
impl Deref for LanguageTag {
    type Target = String;
    fn deref(&self) -> &String {
        &self.0
    }
}
impl ToString for LanguageTag {
    fn to_string(&self) -> String { (*self).clone() }
}

pub struct AuthenticationContextClass(String);
impl AuthenticationContextClass {
    pub fn new(s: &str) -> Self {
        AuthenticationContextClass(s.to_string())
    }
}
impl Deref for AuthenticationContextClass {
    type Target = String;
    fn deref(&self) -> &String {
        &self.0
    }
}
impl ToString for AuthenticationContextClass {
    fn to_string(&self) -> String { (*self).clone() }
}

pub struct CsrfToken(String);
impl CsrfToken {
    pub fn new(s: &str) -> Self {
        CsrfToken(s.to_string())
    }
}
impl Deref for CsrfToken {
    type Target = String;
    fn deref(&self) -> &String {
        &self.0
    }
}

pub struct Nonce(String);
impl Nonce {
    pub fn new(s: &str) -> Self {
        Nonce(s.to_string())
    }
}

pub struct LoginHint(String);

pub struct OpenIdConnectClient<
    TT: TokenType,
    T: Token<TT>,
    TE: ErrorResponseType,
    ID: OpenIdConnectIdToken
>(
    Client<TT, T, TE>,
    PhantomData<ID>,
);

impl<TT, T, TE, ID> OpenIdConnectClient<TT, T, TE, ID>
where TT: TokenType, T: Token<TT>, TE: ErrorResponseType, ID: OpenIdConnectIdToken {
    pub fn new<I, S, A, U>(
        client_id: I, client_secret: Option<S>, auth_url: A, token_url: U
    ) -> Result<OpenIdConnectClient<TT, T, TE, ID>, url::ParseError>
    where I: Into<String>, S: Into<String>, A: AsRef<str>, U: AsRef<str> {
        let client =
            Client::new(client_id, client_secret, auth_url, token_url)?
                .add_scope("openid");
        Ok(OpenIdConnectClient(client, PhantomData))
    }

    ///
    /// Appends a new scope to the authorization URL.
    ///
    // FIXME: change to a Scope newtype in oauth2
    pub fn add_scope(mut self, scope: &str) -> Self {
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
    // FIXME: change to a RedirectUrl newtype in auth2, which should convert to a valid URL type
    // while instantiating the RedirectUrl
    pub fn set_redirect_url(mut self, redirect_url: &str) -> Self {
        self.0 = self.0.set_redirect_url(redirect_url);
        self
    }

    pub fn authorize_url<D, P>(
        &self,
        auth_options: &OpenIdConnectAuthOptions<D, P>,
        state: &CsrfToken,
        nonce: &Nonce
    ) -> Url
    where D: OpenIdConnectAuthDisplay, P: OpenIdConnectAuthPrompt {
        self.authorize_url_with_hint(auth_options, state, nonce, None, None)
    }

    pub fn authorize_url_with_hint<D, P>(
        &self,
        auth_options: &OpenIdConnectAuthOptions<D, P>,
        state: &CsrfToken,
        nonce: &Nonce,
        id_token_hint_opt: Option<&ID>,
        login_hint_opt: Option<&LoginHint>,
    ) -> Url
    where D: OpenIdConnectAuthDisplay, P: OpenIdConnectAuthPrompt {
        // Create string versions of any options that need to be converted. This must be done
        // before creating extra_params so that the lifetimes extend beyond extra_params's lifetime.
        let id_token_hint_raw_opt = id_token_hint_opt.map(|id_token_hint| id_token_hint.raw());
        let max_age_opt = auth_options.max_age().map(|max_age| max_age.as_secs().to_string());
        let prompts_opt = join_optional_vec(auth_options.prompts());
        let ui_locales_opt = join_optional_vec(auth_options.ui_locales());
        let acr_values_opt = join_optional_vec(auth_options.acr_values());

        let mut extra_params: Vec<(&str, &str)> = vec![
            ("state", &state.0),
            ("nonce", &nonce.0),
        ];

        if let &Some(ref display) = auth_options.display() {
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

        if let Some(ref id_token_hint_raw) = id_token_hint_raw_opt {
            extra_params.push(("id_token_hint", id_token_hint_raw));
        }

        if let Some(ref login_hint) = login_hint_opt {
            extra_params.push(("login_hint", &login_hint.0));
        }

        if let Some(ref acr_values) = acr_values_opt {
            extra_params.push(("acr_values", acr_values));
        }

        self.0.authorize_url_extension("code", extra_params)
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
pub struct OpenIdConnectAuthOptions<D, P>
where D: OpenIdConnectAuthDisplay, P: OpenIdConnectAuthPrompt {
    _display: Option<D>,
    _prompts: Option<Vec<P>>,
    _max_age: Option<Duration>,
    _ui_locales: Option<Vec<LanguageTag>>,
    _acr_values: Option<Vec<AuthenticationContextClass>>,
}

impl<D, P> OpenIdConnectAuthOptions<D, P>
where D: OpenIdConnectAuthDisplay, P: OpenIdConnectAuthPrompt {
    pub fn new() -> Self {
        OpenIdConnectAuthOptions::<D, P> {
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
    pub fn display(&self) -> &Option<D> { &self._display }

    ///
    /// Have the Authorization Server use the default authentication and/or consent display. This
    /// is equivalent to `CoreOpenIdConnectAuthDisplay::Page`.
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
    pub fn prompts(&self) -> &Option<Vec<P>> { &self._prompts }

    ///
    /// Have the Authorization Server choose whether to prompt the End-User for reauthentication
    /// and/or consent. This is *not* equivalent to `CoreOpenIdConnectAuthPrompt::None`, which
    /// forces the Authorization Server not to show any prompts.
    ///
    pub fn clear_prompts(mut self) -> Self {
        self._prompts = None;
        self
    }

    ///
    /// Specify a prompt that the Authorization Server should present to the End-User.
    ///
    /// NOTE: The Authorization Server will return an error if `CoreOpenIdConnectAuthPrompt::None`
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
    pub fn max_age(&self) -> &Option<Duration> { &self._max_age }

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
    pub fn ui_locales(&self) -> &Option<Vec<LanguageTag>> { &self._ui_locales }

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
    pub fn acr_values(&self) -> &Option<Vec<AuthenticationContextClass>> { &self._acr_values }

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

pub trait OpenIdConnectIdToken : Debug + DeserializeOwned + PartialEq + Serialize {
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
pub struct OpenIdConnectToken {
    #[serde(flatten)]
    _basic_token: BasicToken<BasicTokenType>,
    // FIXME: this should probably be something else
    _id_token: String
}

impl Token<BasicTokenType> for OpenIdConnectToken {
    fn access_token(&self) -> &str { &self._basic_token.access_token() }
    fn token_type(&self) -> &BasicTokenType { &self._basic_token.token_type() }
    fn expires_in(&self) -> Option<Duration> { self._basic_token.expires_in() }
    fn refresh_token(&self) -> &Option<String> { &self._basic_token.refresh_token() }
    fn scopes(&self) -> &Option<Vec<String>> { &self._basic_token.scopes() }

    fn from_json(data: &str) -> Result<Self, serde_json::error::Error> {
        serde_json::from_str(data)
    }
}

pub mod core {
    use oauth2::*;
    use oauth2::basic::{
        BasicClient,
        BasicErrorResponse,
        BasicErrorResponseType,
        BasicRequestTokenError,
        BasicToken,
        BasicTokenType,
    };
    use super::*;

    pub type CoreOpenIdConnectClient =
        OpenIdConnectClient<
            // FIXME: mixing these OAuth2 and OIDC types is a little messy. See if it makes sense
            // to use type aliases to make this cleaner.
            BasicTokenType,
            OpenIdConnectToken,
            BasicErrorResponseType,
            CoreOpenIdConnectIdToken
        >;

    #[derive(Debug, Deserialize, PartialEq, Serialize)]
    pub struct CoreOpenIdConnectIdToken {}
    impl OpenIdConnectIdToken for CoreOpenIdConnectIdToken {
        fn raw(&self) -> &str {
            "blah"
        }
    }

    ///
    /// How the Authorization Server displays the authentication and consent user interface pages
    /// to the End-User.
    ///
    /// These values are defined in
    /// [Section 3.1.2.1](http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest).
    ///
    #[derive(PartialEq)]
    pub enum CoreOpenIdConnectAuthDisplay {
        ///
        /// The Authorization Server SHOULD display the authentication and consent UI consistent
        /// with a full User Agent page view. If the display parameter is not specified, this is
        /// the default display mode.
        ///
        Page,
        ///
        /// The Authorization Server SHOULD display the authentication and consent UI consistent
        /// with a popup User Agent window. The popup User Agent window should be of an appropriate
        /// size for a login-focused dialog and should not obscure the entire window that it is
        /// popping up over.
        ///
        Popup,
        ///
        /// The Authorization Server SHOULD display the authentication and consent UI consistent
        /// with a device that leverages a touch interface.
        ///
        Touch,
        ///
        /// The Authorization Server SHOULD display the authentication and consent UI consistent
        /// with a "feature phone" type display.
        ///
        Wap,
    }

    impl OpenIdConnectAuthDisplay for CoreOpenIdConnectAuthDisplay {
        fn to_str(&self) -> &str {
            match self {
                &CoreOpenIdConnectAuthDisplay::Page => "page",
                &CoreOpenIdConnectAuthDisplay::Popup => "popup",
                &CoreOpenIdConnectAuthDisplay::Touch => "touch",
                &CoreOpenIdConnectAuthDisplay::Wap => "wap",
            }
        }
    }

    impl Display for CoreOpenIdConnectAuthDisplay {
        fn fmt(&self, f: &mut Formatter) -> Result<(), FormatterError> {
            write!(f, "{}", self.to_str())
        }
    }

    ///
    /// Whether the Authorization Server should prompt the End-User for reauthentication and
    /// consent.
    ///
    /// These values are defined in
    /// [Section 3.1.2.1](http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest).
    ///
    #[derive(PartialEq)]
    pub enum CoreOpenIdConnectAuthPrompt {
        ///
        /// The Authorization Server MUST NOT display any authentication or consent user interface
        /// pages. An error is returned if an End-User is not already authenticated or the Client
        /// does not have pre-configured consent for the requested Claims or does not fulfill other
        /// conditions for processing the request. The error code will typically be
        /// `login_required,` `interaction_required`, or another code defined in
        /// [Section 3.1.2.6](http://openid.net/specs/openid-connect-core-1_0.html#AuthError).
        /// This can be used as a method to check for existing authentication and/or consent.
        ///
        None,
        ///
        /// The Authorization Server SHOULD prompt the End-User for reauthentication. If it cannot
        /// reauthenticate the End-User, it MUST return an error, typically `login_required`.
        ///
        Login,
        ///
        /// The Authorization Server SHOULD prompt the End-User for consent before returning
        /// information to the Client. If it cannot obtain consent, it MUST return an error,
        /// typically `consent_required`.
        ///
        Consent,
        ///
        /// The Authorization Server SHOULD prompt the End-User to select a user account. This
        /// enables an End-User who has multiple accounts at the Authorization Server to select
        /// amongst the multiple accounts that they might have current sessions for. If it cannot
        /// obtain an account selection choice made by the End-User, it MUST return an error,
        /// typically `account_selection_required`.
        ///
        SelectAccount,
    }

    impl OpenIdConnectAuthPrompt for CoreOpenIdConnectAuthPrompt {
        fn to_str(&self) -> &str {
            match self {
                &CoreOpenIdConnectAuthPrompt::None => "none",
                &CoreOpenIdConnectAuthPrompt::Login => "login",
                &CoreOpenIdConnectAuthPrompt::Consent => "consent",
                &CoreOpenIdConnectAuthPrompt::SelectAccount => "select_account",
            }
        }
    }

    impl Display for CoreOpenIdConnectAuthPrompt {
        fn fmt(&self, f: &mut Formatter) -> Result<(), FormatterError> {
            write!(f, "{}", self.to_str())
        }
    }

    pub type CoreOpenIdConnectAuthOptions =
        OpenIdConnectAuthOptions<CoreOpenIdConnectAuthDisplay, CoreOpenIdConnectAuthPrompt>;
}

fn join_optional_vec<X>(vec_opt: &Option<Vec<X>>) -> Option<String>
where X: ToString {
    match vec_opt {
        &Some(ref entries) => Some(
            entries
                .iter()
                .map(|entries| entries.to_string())
                .collect::<Vec<_>>()
                .join(" ")
        ),
        &None => None,
    }
}
