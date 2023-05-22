use oauth2::{ClientId, CsrfToken};
use serde_with::skip_serializing_none;
use url::Url;

use crate::{
    core::{
        CoreAuthDisplay, CoreClaimName, CoreClaimType, CoreClientAuthMethod, CoreGrantType,
        CoreJsonWebKey, CoreJsonWebKeyType, CoreJsonWebKeyUse, CoreJweContentEncryptionAlgorithm,
        CoreJweKeyManagementAlgorithm, CoreJwsSigningAlgorithm, CoreResponseMode, CoreResponseType,
        CoreSubjectIdentifierType,
    },
    types::{LogoutHint, PostLogoutRedirectUrl},
    AdditionalClaims, AdditionalProviderMetadata, EmptyAdditionalProviderMetadata, EndSessionUrl,
    GenderClaim, IdToken, JsonWebKeyType, JweContentEncryptionAlgorithm, JwsSigningAlgorithm,
    LanguageTag, ProviderMetadata,
};

///
/// Additional metadata for providers implementing [OpenID Connect RP-Initiated
/// Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html).
///
#[non_exhaustive]
#[skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct LogoutProviderMetadata<A>
where
    A: AdditionalProviderMetadata,
{
    ///
    /// The end session endpoint as described in [OpenID Connect RP-Initiated
    /// Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html).
    ///
    pub end_session_endpoint: Option<EndSessionUrl>,
    #[serde(bound = "A: AdditionalProviderMetadata", flatten)]
    ///
    /// A field for an additional struct implementing AdditionalProviderMetadata.
    ///
    pub additional_metadata: A,
}
impl<A> AdditionalProviderMetadata for LogoutProviderMetadata<A> where A: AdditionalProviderMetadata {}

///
/// Provider metadata returned by [OpenID Connect Discovery](
/// https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata)
/// that returns [`openidconnect::ProviderMetadata::additional_metadata`] for providers
/// implementing [OpenID Connect RP-Initiated Logout 1.0](
/// https://openid.net/specs/openid-connect-rpinitiated-1_0.html).
///
pub type ProviderMetadataWithLogout = ProviderMetadata<
    LogoutProviderMetadata<EmptyAdditionalProviderMetadata>,
    CoreAuthDisplay,
    CoreClientAuthMethod,
    CoreClaimName,
    CoreClaimType,
    CoreGrantType,
    CoreJweContentEncryptionAlgorithm,
    CoreJweKeyManagementAlgorithm,
    CoreJwsSigningAlgorithm,
    CoreJsonWebKeyType,
    CoreJsonWebKeyUse,
    CoreJsonWebKey,
    CoreResponseMode,
    CoreResponseType,
    CoreSubjectIdentifierType,
>;

///
/// A request to the end session endpoint.
///
pub struct LogoutRequest {
    end_session_endpoint: EndSessionUrl,
    parameters: LogoutRequestParameters,
}

#[derive(Default)]
struct LogoutRequestParameters {
    id_token_hint: Option<String>,
    logout_hint: Option<LogoutHint>,
    client_id: Option<ClientId>,
    post_logout_redirect_uri: Option<PostLogoutRedirectUrl>,
    state: Option<CsrfToken>,
    ui_locales: Vec<LanguageTag>,
}

impl From<EndSessionUrl> for LogoutRequest {
    fn from(value: EndSessionUrl) -> Self {
        LogoutRequest {
            end_session_endpoint: value,
            parameters: Default::default(),
        }
    }
}

impl LogoutRequest {
    ///
    /// Provides an ID token previously issued by this OpenID Connect Provider as a hint about
    /// the user's identity.
    ///
    pub fn set_id_token_hint<AC, GC, JE, JS, JT>(
        mut self,
        id_token_hint: &IdToken<AC, GC, JE, JS, JT>,
    ) -> Self
    where
        AC: AdditionalClaims,
        GC: GenderClaim,
        JE: JweContentEncryptionAlgorithm<JT>,
        JS: JwsSigningAlgorithm<JT>,
        JT: JsonWebKeyType,
    {
        self.parameters.id_token_hint = Some(id_token_hint.to_string());
        self
    }

    ///
    /// Provides the OpenID Connect Provider with a hint about the user's identity.
    ///
    /// The nature of this hint is specific to each provider.
    ///
    pub fn set_logout_hint(mut self, logout_hint: LogoutHint) -> Self {
        self.parameters.logout_hint = Some(logout_hint);
        self
    }

    ///
    /// Provides the OpenID Connect Provider with the client identifier.
    ///
    /// When both this and `id_token_hint` are set, the provider must verify that
    /// this client id matches the one used when the ID token was issued.
    ///
    pub fn set_client_id(mut self, client_id: ClientId) -> Self {
        self.parameters.client_id = Some(client_id);
        self
    }

    ///
    /// Provides the OpenID Connect Provider with a URI to redirect to after
    /// the logout has been performed.
    ///
    pub fn set_post_logout_redirect_uri(mut self, redirect_uri: PostLogoutRedirectUrl) -> Self {
        self.parameters.post_logout_redirect_uri = Some(redirect_uri);
        self
    }

    ///
    /// Specify an opaque value that the OpenID Connect Provider should pass back
    /// to your application using the state parameter when redirecting to post_logout_redirect_uri.
    ///
    pub fn set_state(mut self, state: CsrfToken) -> Self {
        self.parameters.state = Some(state);
        self
    }

    ///
    /// Requests the preferred languages for the user interface presented by the OpenID Connect
    /// Provider.
    ///
    /// Languages should be added in order of preference.
    ///
    pub fn add_ui_locale(mut self, ui_locale: LanguageTag) -> Self {
        self.parameters.ui_locales.push(ui_locale);
        self
    }

    ///
    /// Returns the full logout URL. In order to logout, a GET request should be made to this URL
    /// by the client's browser.
    ///
    pub fn http_get_url(self) -> Url {
        let mut url = self.end_session_endpoint.url().to_owned();
        {
            let mut query = url.query_pairs_mut();

            macro_rules! add_pair {
                ($name:ident, $acc:expr) => {
                    if let Some($name) = self.parameters.$name {
                        query.append_pair(stringify!($name), $acc);
                    }
                };
            }

            add_pair!(id_token_hint, id_token_hint.as_str());
            add_pair!(logout_hint, logout_hint.secret());
            add_pair!(client_id, client_id.as_str());
            add_pair!(post_logout_redirect_uri, post_logout_redirect_uri.as_str());
            add_pair!(state, state.secret());
        }
        url
    }
}
