use crate::{
    AccessToken, AdditionalClaims, AdditionalProviderMetadata, AuthDisplay, AuthPrompt, AuthType,
    AuthUrl, AuthenticationFlow, AuthorizationCode, AuthorizationRequest, ClaimName, ClaimType,
    ClientAuthMethod, ClientCredentialsTokenRequest, ClientId, ClientSecret, CodeTokenRequest,
    ConfigurationError, CsrfToken, DeviceAccessTokenRequest, DeviceAuthorizationRequest,
    DeviceAuthorizationResponse, DeviceAuthorizationUrl, ErrorResponse,
    ExtraDeviceAuthorizationFields, GenderClaim, GrantType, IdTokenVerifier, IntrospectionRequest,
    IntrospectionUrl, IssuerUrl, JsonWebKey, JsonWebKeySet, JsonWebKeyType, JsonWebKeyUse,
    JweContentEncryptionAlgorithm, JweKeyManagementAlgorithm, JwsSigningAlgorithm, Nonce,
    PasswordTokenRequest, ProviderMetadata, RedirectUrl, RefreshToken, RefreshTokenRequest,
    ResourceOwnerPassword, ResourceOwnerUsername, ResponseMode, ResponseType, RevocableToken,
    RevocationRequest, RevocationUrl, Scope, SubjectIdentifier, SubjectIdentifierType,
    TokenIntrospectionResponse, TokenResponse, TokenType, TokenUrl, UserInfoRequest,
    UserInfoResponseType, UserInfoUrl, UserInfoVerifier,
};

use std::marker::PhantomData;

const OPENID_SCOPE: &str = "openid";

/// OpenID Connect client.
///
/// # Error Types
///
/// To enable compile time verification that only the correct and complete set of errors for the `Client` function being
/// invoked are exposed to the caller, the `Client` type is specialized on multiple implementations of the
/// [`ErrorResponse`] trait. The exact [`ErrorResponse`] implementation returned varies by the RFC that the invoked
/// `Client` function implements:
///
///   - Generic type `TE` (aka Token Error) for errors defined by [RFC 6749 OAuth 2.0 Authorization Framework](https://tools.ietf.org/html/rfc6749).
///   - Generic type `TRE` (aka Token Revocation Error) for errors defined by [RFC 7009 OAuth 2.0 Token Revocation](https://tools.ietf.org/html/rfc7009).
///
/// For example when revoking a token, error code `unsupported_token_type` (from RFC 7009) may be returned:
/// ```rust
/// # use http::status::StatusCode;
/// # use http::header::{HeaderValue, CONTENT_TYPE};
/// # use openidconnect::core::CoreClient;
/// # use openidconnect::{
/// #     AccessToken,
/// #     AuthUrl,
/// #     ClientId,
/// #     ClientSecret,
/// #     HttpResponse,
/// #     IssuerUrl,
/// #     JsonWebKeySet,
/// #     RequestTokenError,
/// #     RevocationErrorResponseType,
/// #     RevocationUrl,
/// #     TokenUrl,
/// # };
/// # use thiserror::Error;
/// #
/// # let client = CoreClient::new(
/// #     ClientId::new("aaa".to_string()),
/// #     Some(ClientSecret::new("bbb".to_string())),
/// #     IssuerUrl::new("https://example".to_string()).unwrap(),
/// #     AuthUrl::new("https://example/authorize".to_string()).unwrap(),
/// #     Some(TokenUrl::new("https://example/token".to_string()).unwrap()),
/// #     None,
/// #     JsonWebKeySet::default(),
/// # )
/// # .set_revocation_uri(RevocationUrl::new("https://revocation/url".to_string()).unwrap());
/// #
/// # #[derive(Debug, Error)]
/// # enum FakeError {
/// #     #[error("error")]
/// #     Err,
/// # }
/// #
/// # let http_client = |_| -> Result<HttpResponse, FakeError> {
/// #     Ok(HttpResponse {
/// #         status_code: StatusCode::BAD_REQUEST,
/// #         headers: vec![(
/// #             CONTENT_TYPE,
/// #             HeaderValue::from_str("application/json").unwrap(),
/// #         )]
/// #         .into_iter()
/// #         .collect(),
/// #         body: "{\"error\": \"unsupported_token_type\", \"error_description\": \"stuff happened\", \
/// #                \"error_uri\": \"https://errors\"}"
/// #             .to_string()
/// #             .into_bytes(),
/// #     })
/// # };
/// #
/// let res = client
///     .revoke_token(AccessToken::new("some token".to_string()).into())
///     .unwrap()
///     .request(http_client);
///
/// assert!(matches!(res, Err(
///     RequestTokenError::ServerResponse(err)) if matches!(err.error(),
///         RevocationErrorResponseType::UnsupportedTokenType)));
/// ```
#[derive(Clone, Debug)]
pub struct Client<AC, AD, GC, JE, JS, JT, JU, K, P, TE, TR, TT, TIR, RT, TRE>
where
    AC: AdditionalClaims,
    AD: AuthDisplay,
    GC: GenderClaim,
    JE: JweContentEncryptionAlgorithm<JT>,
    JS: JwsSigningAlgorithm<JT>,
    JT: JsonWebKeyType,
    JU: JsonWebKeyUse,
    K: JsonWebKey<JS, JT, JU>,
    P: AuthPrompt,
    TE: ErrorResponse,
    TR: TokenResponse<AC, GC, JE, JS, JT, TT>,
    TT: TokenType + 'static,
    TIR: TokenIntrospectionResponse<TT>,
    RT: RevocableToken,
    TRE: ErrorResponse,
{
    oauth2_client: oauth2::Client<TE, TR, TT, TIR, RT, TRE>,
    client_id: ClientId,
    client_secret: Option<ClientSecret>,
    issuer: IssuerUrl,
    userinfo_endpoint: Option<UserInfoUrl>,
    jwks: JsonWebKeySet<JS, JT, JU, K>,
    id_token_signing_algs: Option<Vec<JS>>,
    use_openid_scope: bool,
    _phantom: PhantomData<(AC, AD, GC, JE, P)>,
}
impl<AC, AD, GC, JE, JS, JT, JU, K, P, TE, TR, TT, TIR, RT, TRE>
    Client<AC, AD, GC, JE, JS, JT, JU, K, P, TE, TR, TT, TIR, RT, TRE>
where
    AC: AdditionalClaims,
    AD: AuthDisplay,
    GC: GenderClaim,
    JE: JweContentEncryptionAlgorithm<JT>,
    JS: JwsSigningAlgorithm<JT>,
    JT: JsonWebKeyType,
    JU: JsonWebKeyUse,
    K: JsonWebKey<JS, JT, JU>,
    P: AuthPrompt,
    TE: ErrorResponse + 'static,
    TR: TokenResponse<AC, GC, JE, JS, JT, TT>,
    TT: TokenType + 'static,
    TIR: TokenIntrospectionResponse<TT>,
    RT: RevocableToken,
    TRE: ErrorResponse + 'static,
{
    /// Initializes an OpenID Connect client.
    pub fn new(
        client_id: ClientId,
        client_secret: Option<ClientSecret>,
        issuer: IssuerUrl,
        auth_url: AuthUrl,
        token_url: Option<TokenUrl>,
        userinfo_endpoint: Option<UserInfoUrl>,
        jwks: JsonWebKeySet<JS, JT, JU, K>,
    ) -> Self {
        Client {
            oauth2_client: oauth2::Client::new(
                client_id.clone(),
                client_secret.clone(),
                auth_url,
                token_url,
            ),
            client_id,
            client_secret,
            issuer,
            userinfo_endpoint,
            jwks,
            id_token_signing_algs: None,
            use_openid_scope: true,
            _phantom: PhantomData,
        }
    }

    /// Initializes an OpenID Connect client from OpenID Connect Discovery provider metadata.
    ///
    /// Use [`ProviderMetadata::discover`] or
    /// [`ProviderMetadata::discover_async`] to fetch the provider metadata.
    pub fn from_provider_metadata<A, CA, CN, CT, G, JK, RM, RS, S>(
        provider_metadata: ProviderMetadata<A, AD, CA, CN, CT, G, JE, JK, JS, JT, JU, K, RM, RS, S>,
        client_id: ClientId,
        client_secret: Option<ClientSecret>,
    ) -> Self
    where
        A: AdditionalProviderMetadata,
        CA: ClientAuthMethod,
        CN: ClaimName,
        CT: ClaimType,
        G: GrantType,
        JK: JweKeyManagementAlgorithm,
        RM: ResponseMode,
        RS: ResponseType,
        S: SubjectIdentifierType,
    {
        Client {
            oauth2_client: oauth2::Client::new(
                client_id.clone(),
                client_secret.clone(),
                provider_metadata.authorization_endpoint().clone(),
                provider_metadata.token_endpoint().cloned(),
            ),
            client_id,
            client_secret,
            issuer: provider_metadata.issuer().clone(),
            userinfo_endpoint: provider_metadata.userinfo_endpoint().cloned(),
            jwks: provider_metadata.jwks().to_owned(),
            id_token_signing_algs: Some(
                provider_metadata
                    .id_token_signing_alg_values_supported()
                    .to_owned(),
            ),
            use_openid_scope: true,
            _phantom: PhantomData,
        }
    }

    /// Configures the type of client authentication used for communicating with the authorization
    /// server.
    ///
    /// The default is to use HTTP Basic authentication, as recommended in
    /// [Section 2.3.1 of RFC 6749](https://tools.ietf.org/html/rfc6749#section-2.3.1). Note that
    /// if a client secret is omitted (i.e., `client_secret` is set to `None` when calling
    /// [`Client::new`]), [`AuthType::RequestBody`] is used regardless of the `auth_type` passed to
    /// this function.
    pub fn set_auth_type(mut self, auth_type: AuthType) -> Self {
        self.oauth2_client = self.oauth2_client.set_auth_type(auth_type);
        self
    }

    /// Sets the redirect URL used by the authorization endpoint.
    pub fn set_redirect_uri(mut self, redirect_url: RedirectUrl) -> Self {
        self.oauth2_client = self.oauth2_client.set_redirect_uri(redirect_url);
        self
    }

    /// Sets the introspection URL for contacting the ([RFC 7662](https://tools.ietf.org/html/rfc7662))
    /// introspection endpoint.
    pub fn set_introspection_uri(mut self, introspection_url: IntrospectionUrl) -> Self {
        self.oauth2_client = self.oauth2_client.set_introspection_uri(introspection_url);
        self
    }

    /// Sets the revocation URL for contacting the revocation endpoint ([RFC 7009](https://tools.ietf.org/html/rfc7009)).
    ///
    /// See: [`revoke_token()`](Self::revoke_token())
    pub fn set_revocation_uri(mut self, revocation_url: RevocationUrl) -> Self {
        self.oauth2_client = self.oauth2_client.set_revocation_uri(revocation_url);
        self
    }

    /// Sets the device authorization URL for contacting the device authorization endpoint ([RFC 8628](https://tools.ietf.org/html/rfc8628)).
    pub fn set_device_authorization_uri(
        mut self,
        device_authorization_url: DeviceAuthorizationUrl,
    ) -> Self {
        self.oauth2_client = self
            .oauth2_client
            .set_device_authorization_url(device_authorization_url);
        self
    }

    /// Enables the `openid` scope to be requested automatically.
    ///
    /// This scope is requested by default, so this function is only useful after previous calls to
    /// [`disable_openid_scope`][Client::disable_openid_scope].
    pub fn enable_openid_scope(mut self) -> Self {
        self.use_openid_scope = true;
        self
    }

    /// Disables the `openid` scope from being requested automatically.
    pub fn disable_openid_scope(mut self) -> Self {
        self.use_openid_scope = false;
        self
    }

    /// Returns an ID token verifier for use with the [`IdToken::claims`] method.
    pub fn id_token_verifier(&self) -> IdTokenVerifier<JS, JT, JU, K> {
        let verifier = if let Some(ref client_secret) = self.client_secret {
            IdTokenVerifier::new_confidential_client(
                self.client_id.clone(),
                client_secret.clone(),
                self.issuer.clone(),
                self.jwks.clone(),
            )
        } else {
            IdTokenVerifier::new_public_client(
                self.client_id.clone(),
                self.issuer.clone(),
                self.jwks.clone(),
            )
        };

        if let Some(id_token_signing_algs) = self.id_token_signing_algs.clone() {
            verifier.set_allowed_algs(id_token_signing_algs)
        } else {
            verifier
        }
    }

    /// Generates an authorization URL for a new authorization request.
    ///
    /// NOTE: [Passing authorization request parameters as a JSON Web Token
    /// ](https://openid.net/specs/openid-connect-core-1_0.html#JWTRequests)
    /// instead of URL query parameters is not currently supported. The
    /// [`claims` parameter](https://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter)
    /// is also not directly supported, although the [`AuthorizationRequest::add_extra_param`]
    /// method can be used to add custom parameters, including `claims`.
    ///
    /// # Arguments
    ///
    /// * `authentication_flow` - The authentication flow to use (code, implicit, or hybrid).
    /// * `state_fn` - A function that returns an opaque value used by the client to maintain state
    ///   between the request and callback. The authorization server includes this value when
    ///   redirecting the user-agent back to the client.
    /// * `nonce_fn` - Similar to `state_fn`, but used to generate an opaque nonce to be used
    ///   when verifying the ID token returned by the OpenID Connect Provider.
    ///
    /// # Security Warning
    ///
    /// Callers should use a fresh, unpredictable `state` for each authorization request and verify
    /// that this value matches the `state` parameter passed by the authorization server to the
    /// redirect URI. Doing so mitigates
    /// [Cross-Site Request Forgery](https://tools.ietf.org/html/rfc6749#section-10.12)
    ///  attacks.
    ///
    /// Similarly, callers should use a fresh, unpredictable `nonce` to help protect against ID
    /// token reuse and forgery.
    pub fn authorize_url<NF, RS, SF>(
        &self,
        authentication_flow: AuthenticationFlow<RS>,
        state_fn: SF,
        nonce_fn: NF,
    ) -> AuthorizationRequest<AD, P, RS>
    where
        NF: FnOnce() -> Nonce + 'static,
        RS: ResponseType,
        SF: FnOnce() -> CsrfToken + 'static,
    {
        let request = AuthorizationRequest {
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
        };
        if self.use_openid_scope {
            request.add_scope(Scope::new(OPENID_SCOPE.to_string()))
        } else {
            request
        }
    }

    /// Creates a request builder for exchanging an authorization code for an access token.
    ///
    /// Acquires ownership of the `code` because authorization codes may only be used once to
    /// retrieve an access token from the authorization server.
    ///
    /// See <https://tools.ietf.org/html/rfc6749#section-4.1.3>
    pub fn exchange_code(&self, code: AuthorizationCode) -> CodeTokenRequest<TE, TR, TT> {
        self.oauth2_client.exchange_code(code)
    }

    /// Creates a request builder for device authorization.
    ///
    /// See <https://tools.ietf.org/html/rfc8628#section-3.4>
    pub fn exchange_device_code(
        &self,
    ) -> Result<DeviceAuthorizationRequest<TE>, ConfigurationError> {
        let request = self.oauth2_client.exchange_device_code();
        if self.use_openid_scope {
            Ok(request?.add_scope(Scope::new(OPENID_SCOPE.to_string())))
        } else {
            request
        }
    }

    /// Creates a request builder for exchanging a device code for an access token.
    ///
    /// See <https://tools.ietf.org/html/rfc8628#section-3.4>
    pub fn exchange_device_access_token<'a, 'b, 'c, EF>(
        &'a self,
        auth_response: &'b DeviceAuthorizationResponse<EF>,
    ) -> DeviceAccessTokenRequest<'b, 'c, TR, TT, EF>
    where
        'a: 'b,
        EF: ExtraDeviceAuthorizationFields,
    {
        self.oauth2_client
            .exchange_device_access_token(auth_response)
    }

    /// Creates a request builder for exchanging a refresh token for an access token.
    ///
    /// See <https://tools.ietf.org/html/rfc6749#section-6>
    pub fn exchange_refresh_token<'a, 'b>(
        &'a self,
        refresh_token: &'b RefreshToken,
    ) -> RefreshTokenRequest<'b, TE, TR, TT>
    where
        'a: 'b,
    {
        self.oauth2_client.exchange_refresh_token(refresh_token)
    }

    /// Creates a request builder for exchanging credentials for an access token.
    ///
    /// See <https://tools.ietf.org/html/rfc6749#section-6>
    pub fn exchange_password<'a, 'b>(
        &'a self,
        username: &'b ResourceOwnerUsername,
        password: &'b ResourceOwnerPassword,
    ) -> PasswordTokenRequest<'b, TE, TR, TT>
    where
        'a: 'b,
    {
        self.oauth2_client.exchange_password(username, password)
    }

    /// Creates a request builder for exchanging client credentials for an access token.
    ///
    /// See <https://tools.ietf.org/html/rfc6749#section-4.4>
    pub fn exchange_client_credentials<'a, 'b>(
        &'a self,
    ) -> ClientCredentialsTokenRequest<'b, TE, TR, TT>
    where
        'a: 'b,
    {
        self.oauth2_client.exchange_client_credentials()
    }

    /// Creates a request builder for info about the user associated with the given access token.
    ///
    /// This function requires that this [`Client`] be configured with a user info endpoint,
    /// which is an optional feature for OpenID Connect Providers to implement. If this `Client`
    /// does not know the provider's user info endpoint, it returns the [`ConfigurationError`]
    /// error.
    ///
    /// To help protect against token substitution attacks, this function optionally allows clients
    /// to provide the subject identifier whose user info they expect to receive. If provided and
    /// the subject returned by the OpenID Connect Provider does not match, the
    /// [`UserInfoRequest::request`] or [`UserInfoRequest::request_async`] functions will return
    /// [`UserInfoError::ClaimsVerification`]. If set to `None`, any subject is accepted.
    pub fn user_info(
        &self,
        access_token: AccessToken,
        expected_subject: Option<SubjectIdentifier>,
    ) -> Result<UserInfoRequest<JE, JS, JT, JU, K>, ConfigurationError> {
        Ok(UserInfoRequest {
            url: self
                .userinfo_endpoint
                .as_ref()
                .ok_or(ConfigurationError::MissingUrl("userinfo"))?,
            access_token,
            require_signed_response: false,
            response_type: UserInfoResponseType::Json,
            signed_response_verifier: UserInfoVerifier::new(
                self.client_id.clone(),
                self.issuer.clone(),
                self.jwks.clone(),
                expected_subject,
            ),
        })
    }

    /// Creates a request builder for obtaining metadata about a previously received token.
    ///
    /// See <https://tools.ietf.org/html/rfc7662>
    pub fn introspect<'a>(
        &'a self,
        token: &'a AccessToken,
    ) -> Result<IntrospectionRequest<'a, TE, TIR, TT>, ConfigurationError> {
        self.oauth2_client.introspect(token)
    }

    /// Creates a request builder for revoking a previously received token.
    ///
    /// Requires that [`set_revocation_uri()`](Self::set_revocation_uri()) have already been called to set the
    /// revocation endpoint URL.
    ///
    /// Attempting to submit the generated request without calling [`set_revocation_uri()`](Self::set_revocation_uri())
    /// first will result in an error.
    ///
    /// See <https://tools.ietf.org/html/rfc7009>
    pub fn revoke_token(
        &self,
        token: RT,
    ) -> Result<RevocationRequest<RT, TRE>, ConfigurationError> {
        self.oauth2_client.revoke_token(token)
    }
}
