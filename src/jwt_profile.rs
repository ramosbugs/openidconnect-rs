use std::{marker::PhantomData, time::Duration};

use crate::{
    core::CoreJwsSigningAlgorithm,
    jwt::{JsonWebToken, JsonWebTokenJsonPayloadSerde},
    types::helpers::{serde_utc_seconds, serde_utc_seconds_opt},
    AdditionalClaims, Audience, AuthDisplay, AuthPrompt, GenderClaim, IdTokenClaims, IssuerUrl,
    JsonWebKey, JsonWebKeyType, JsonWebKeyUse, JsonWebTokenError, JweContentEncryptionAlgorithm,
    JwsSigningAlgorithm, Nonce, PrivateSigningKey, TokenResponse,
};
use chrono::{DateTime, Days, Utc};
use oauth2::{
    AuthorizationCode, CodeTokenRequest, ErrorResponse, RevocableToken, TokenIntrospectionResponse,
    TokenType, ClientCredentialsTokenRequest,
};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fmt::Debug;
///
/// Additional claims beyond the set of Standard Claims defined by OpenID Connect Core.
///
pub trait AdditionalClientAuthTokenClaims: Debug + DeserializeOwned + Serialize + 'static {}

///
/// No additional claims.
///
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
// In order to support serde flatten, this must be an empty struct rather than an empty
// tuple struct.
pub struct EmptyAdditionalClientAuthTokenClaims {}
impl AdditionalClientAuthTokenClaims for EmptyAdditionalClientAuthTokenClaims {}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ClientAuthTokenClaims<AC> {
    #[serde(rename = "iss")]
    issuer: String,

    #[serde(rename = "sub")]
    subject: String,

    #[serde(rename = "aud")]
    audience: Audience,

    #[serde(rename = "exp", with = "serde_utc_seconds")]
    expiration: DateTime<Utc>,

    #[serde(
        rename = "nbf",
        default,
        with = "serde_utc_seconds_opt",
        skip_serializing_if = "Option::is_none"
    )]
    not_before: Option<DateTime<Utc>>,

    #[serde(
        rename = "iat",
        default,
        with = "serde_utc_seconds_opt",
        skip_serializing_if = "Option::is_none"
    )]
    iat: Option<DateTime<Utc>>,

    #[serde(rename = "jti", default, skip_serializing_if = "Option::is_none")]
    jti: Option<String>,

    #[serde(bound = "AC: AdditionalClientAuthTokenClaims")]
    #[serde(flatten)]
    additional_claims: AC,
}

#[must_use]
#[derive(Clone, Deserialize, Serialize)]
pub struct ClientAuthTokenId(String);
impl ClientAuthTokenId {
    ///
    /// Generate a new random, base64-encoded 128-bit CSRF token.
    ///
    pub fn new_random() -> Self {
        ClientAuthTokenId("haha".to_string())
    }
}

impl<AC, AD, GC, JE, JS, JT, JU, K, P, TE, TR, TT, TIR, RT, TRE>
    crate::Client<AC, AD, GC, JE, JS, JT, JU, K, P, TE, TR, TT, TIR, RT, TRE>
where
    // AC: AdditionalClientAuthTokenClaims,
    AC: AdditionalClaims,
    // AC: AdditionalClaims,
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
    pub fn client_auth_token_builder<S, RF, ATC>(
        &self,
        signing_key: S,
        signing_algo: JS,
        token_id: RF,
        duration: Duration,
        additional_claims: ATC,
    ) -> ClientAuthTokenBuilder<ATC, JE, JS, JT, JU, K, RF, S>
    where
        RF: FnOnce() -> ClientAuthTokenId + 'static,
        ATC: AdditionalClientAuthTokenClaims,
        S: PrivateSigningKey<JS, JT, JU, K>,
    {
        ClientAuthTokenBuilder::new(
            self.client_id.to_string(),
            Audience::new(self.oauth2_client.token_url().unwrap().to_string()),
            signing_key,
            signing_algo,
            token_id,
            duration,
            additional_claims,
        )
    }

    pub fn exchange_client_credential_with_auth_token<ATC>(
        &self,
        token: ClientAuthToken<ATC, JE, JS, JT>
) -> Result<ClientCredentialsTokenRequest<TE, TR, TT>, JsonWebTokenError>

    where
        ATC: AdditionalClientAuthTokenClaims,
    {

        let ccrt = self.exchange_client_credentials().add_extra_param(
            "client_assertion_type",
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        )
        .add_extra_param("client_assertion", token.to_string());

        Ok(ccrt)
    }
}

pub struct ClientAuthTokenBuilder<
    AC: AdditionalClientAuthTokenClaims,
    JE: JweContentEncryptionAlgorithm<JT>,
    JS: JwsSigningAlgorithm<JT>,
    JT: JsonWebKeyType,
    JU: JsonWebKeyUse,
    K: JsonWebKey<JS, JT, JU>,
    RF: FnOnce() -> ClientAuthTokenId + 'static,
    SK: PrivateSigningKey<JS, JT, JU, K>,
> {
    additional_claims: AC,
    issuer: String,
    subject: String,
    audience: Audience,
    expiration_time: DateTime<Utc>,
    key_id_method: JwsKeyIdMethod,
    signing_key: SK,
    signing_algo: JS,
    _phantom_jt: PhantomData<(AC, JE, JS, RF, JT, JU, K, JS)>,
}

impl<'a, AC, JE, JS, JT, JU, K, RF, SK> ClientAuthTokenBuilder<AC, JE, JS, JT, JU, K, RF, SK>
where
    AC: AdditionalClientAuthTokenClaims,
    JE: JweContentEncryptionAlgorithm<JT>,
    JS: JwsSigningAlgorithm<JT>,
    JT: JsonWebKeyType,
    JU: JsonWebKeyUse,
    K: JsonWebKey<JS, JT, JU>,
    RF: FnOnce() -> ClientAuthTokenId + 'static,
    SK: PrivateSigningKey<JS, JT, JU, K>,
{
    pub fn new(
        issuer: String,
        audience: Audience,
        signing_key: SK,
        signing_algo: JS,
        random: RF,
        duration: Duration,
        additional_claims: AC,
    ) -> Self {
        Self {
            issuer: issuer.clone(),
            subject: issuer,
            audience: audience,
            additional_claims,
            signing_key: signing_key,
            signing_algo,
            expiration_time: chrono::offset::Utc::now()
                .checked_add_days(Days::new(1))
                .unwrap(),
            key_id_method: JwsKeyIdMethod::KeyId("default".to_string()),
            _phantom_jt: PhantomData,
        }
    }
    pub fn set_issuer(mut self, issuer: String) -> Self {
        self.issuer = issuer;
        self
    }

    pub fn set_audience(mut self, audience: Audience) -> Self {
        self.audience = audience;
        self
    }

    pub fn set_key_id_method(mut self, key_id_method: JwsKeyIdMethod) -> Self {
        self.key_id_method = key_id_method;
        self
    }

    pub fn build(self) -> Result<ClientAuthToken<AC, JE, JS, JT>, JsonWebTokenError> {
        let claims = ClientAuthTokenClaims {
            issuer: self.issuer,
            subject: self.subject,
            audience: self.audience,
            expiration: self.expiration_time,
            not_before: None,
            iat: None,
            jti: None,
            additional_claims: self.additional_claims,
        };

        let t = ClientAuthToken::new(claims, &self.signing_key, self.signing_algo).unwrap();
        Ok(t)
    }
}

#[non_exhaustive]
pub enum JwsKeyIdMethod {
    X5t(String),
    X509Sha256([u8; 32]),
    KeyId(String),
    X509Url(String),
    X509Sha1(Vec<u8>),
}

/// OpenID Connect ID token.
///
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ClientAuthToken<
    AC: AdditionalClientAuthTokenClaims,
    JE: JweContentEncryptionAlgorithm<JT>,
    JS: JwsSigningAlgorithm<JT>,
    JT: JsonWebKeyType,
>(
    #[serde(bound = "AC: AdditionalClientAuthTokenClaims")]
    JsonWebToken<JE, JS, JT, ClientAuthTokenClaims<AC>, JsonWebTokenJsonPayloadSerde>,
);

impl<AC, JE, JS, JT> ClientAuthToken<AC, JE, JS, JT>
where
    AC: AdditionalClientAuthTokenClaims,
    JE: JweContentEncryptionAlgorithm<JT>,
    JS: JwsSigningAlgorithm<JT>,
    JT: JsonWebKeyType,
{
    pub fn new<JU, K, S>(
        claims: ClientAuthTokenClaims<AC>,
        signing_key: &S,
        alg: JS,
        // access_token: Option<&AccessToken>,
        // code: Option<&AuthorizationCode>,
    ) -> Result<Self, JsonWebTokenError>
    where
        JU: JsonWebKeyUse,
        K: JsonWebKey<JS, JT, JU>,
        S: PrivateSigningKey<JS, JT, JU, K>,
    {
        JsonWebToken::new(ClientAuthTokenClaims { ..claims }, signing_key, &alg).map(Self)
    }
}

impl<AC, JE, JS, JT> ToString for ClientAuthToken<AC, JE, JS, JT>
where
    AC: AdditionalClientAuthTokenClaims,
    JE: JweContentEncryptionAlgorithm<JT>,
    JS: JwsSigningAlgorithm<JT>,
    JT: JsonWebKeyType,
{
    fn to_string(&self) -> String {
        serde_json::to_value(&self)
            // This should never arise, since we're just asking serde_json to serialize the
            // signing input concatenated with the signature, both of which are precomputed.
            .expect("ID token serialization failed")
            .as_str()
            // This should also never arise, since our IdToken serializer always calls serialize_str
            .expect("ID token serializer did not produce a str")
            .to_owned()
    }
}

#[cfg(test)]
mod tests {

    use std::time::Duration;

    use oauth2::{reqwest::http_client, AuthUrl};

    use crate::{
        core::{
            CoreAuthDisplay, CoreClaimName, CoreClaimType, CoreClientAuthMethod, CoreGrantType,
            CoreJsonWebKey, CoreJsonWebKeyType, CoreJsonWebKeyUse,
            CoreJweContentEncryptionAlgorithm, CoreJweKeyManagementAlgorithm, CoreResponseMode,
            CoreRsaPrivateSigningKey, CoreSubjectIdentifierType,
        },
        jwt::tests::TEST_RSA_PRIV_KEY,
        AdditionalProviderMetadata, ClaimName, Client, EmptyAdditionalProviderMetadata,
        JsonWebKeySetUrl, ProviderMetadata, ResponseType, ResponseTypes, JsonWebKeyId,
    };

    use crate::core::{
        CoreAuthenticationFlow, CoreClient, CoreProviderMetadata, CoreResponseType,
        CoreUserInfoClaims,
    };
    use crate::{
        AccessTokenHash, AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
        IssuerUrl, Nonce, PkceCodeChallenge, RedirectUrl, Scope,
    };

    use super::*;
    use anyhow::anyhow;

    #[derive(Debug, Deserialize, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize)]
    pub struct CoreClaimName2(String);
    impl ClaimName for CoreClaimName2 {}

    use crate::{OAuth2TokenResponse, TokenResponse};

    type MicrosoftProviderMetadata = ProviderMetadata<
        EmptyAdditionalProviderMetadata,
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

    #[test]
    fn azure_ad_style() -> Result<(), anyhow::Error> {
        let private_key = CoreRsaPrivateSigningKey::from_pem(TEST_RSA_PRIV_KEY, Some(JsonWebKeyId::new(
            "flyveQx6E1p5crtxOzA64kwjYmo".to_string(),
        ))).unwrap();
        const tenant_id: &str = "3d02d73d-a23a-4989-93ef-ac3c459edabb";

        let client_id = ClientId::new("9aca7c0e-8e4a-4b36-8c69-1c2323092699".to_string());
        let issuer = IssuerUrl::new(
            format!(
                "https://login.microsoftonline.com/{}/oauth2/v2.0",
                tenant_id
            )
            .to_string(),
        )
        .unwrap();
        let authorization_endpoint = AuthUrl::new(format!(
            "https://login.microsoft.com/{}/oauth2/v2.0/authorize",
            tenant_id
        ))
        .unwrap();

        let provider_metadata = MicrosoftProviderMetadata::discover(
            &IssuerUrl::new(format!(
                "https://login.microsoftonline.com/{}/v2.0",
                tenant_id
            ))
            .unwrap(),
            http_client,
        )
        .unwrap();

        let client = CoreClient::from_provider_metadata(
            provider_metadata,
            client_id,
            None,
        );


        let client_auth_token_builder = client
            .client_auth_token_builder(
                private_key,
                CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
                ClientAuthTokenId::new_random,
                Duration::from_secs(30),
                EmptyAdditionalClientAuthTokenClaims {},
            )
            // .set_audience(Audience::new("a".to_string()))
            .set_key_id_method(JwsKeyIdMethod::X509Sha1(vec![]));

        let token = client_auth_token_builder.build().unwrap();

        let token_response = client
            .exchange_client_credential_with_auth_token(token)
            .unwrap()
            .add_scope(Scope::new(
                                "https://0fsxp-admin.sharepoint.com/.default".to_string(),
                            ))
            .request(http_client)
            .unwrap();

        eprintln!("token_response = {:?}", token_response);

        Ok(())
    }
}
