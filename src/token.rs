use crate::{
    AdditionalClaims, ExtraTokenFields, GenderClaim, IdToken, IdTokenFields, JsonWebKeyType,
    JweContentEncryptionAlgorithm, JwsSigningAlgorithm, OAuth2TokenResponse, StandardTokenResponse,
    TokenType,
};

/// Extends the base OAuth2 token response with an ID token.
pub trait TokenResponse<AC, GC, JE, JS, JT, TT>: OAuth2TokenResponse<TT>
where
    AC: AdditionalClaims,
    GC: GenderClaim,
    JE: JweContentEncryptionAlgorithm<JT>,
    JS: JwsSigningAlgorithm<JT>,
    JT: JsonWebKeyType,
    TT: TokenType,
{
    /// Returns the ID token provided by the token response.
    ///
    /// OpenID Connect authorization servers should always return this field, but it is optional
    /// to allow for interoperability with authorization servers that only support OAuth2.
    fn id_token(&self) -> Option<&IdToken<AC, GC, JE, JS, JT>>;
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
    fn id_token(&self) -> Option<&IdToken<AC, GC, JE, JS, JT>> {
        self.extra_fields().id_token()
    }
}
