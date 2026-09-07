use super::{discovery_request, discovery_response, AdditionalProviderMetadata, CONFIG_URL_SUFFIX};
use crate::{
    AsyncHttpClient, ClientId, ClientSecret, DiscoveryError, IdTokenVerifier, IssuerUrl,
    JsonWebKey, JsonWebKeySet, JsonWebKeySetUrl, SyncHttpClient,
};

use serde::{Deserialize, Serialize};
use serde_with::{serde_as, VecSkipError};
use std::future::Future;

#[cfg(test)]
mod tests;

/// Discovery metadata for issuers that publish signed workload tokens without a browser login flow.
///
/// This type requires `issuer`, `jwks_uri`, and `id_token_signing_alg_values_supported`. It does not
/// require authorization or token endpoints, response types, or subject types. Use
/// [`ProviderMetadata`](crate::ProviderMetadata) for full OpenID Connect login flows.
///
/// Discovery validates the issuer and fetches its keys using the supplied HTTP client. Configure
/// that client not to follow redirects, and only discover issuers trusted by the application;
/// do not discover arbitrary URLs taken from unverified token claims.
///
/// The returned verifier uses the existing ID token validation rules. Workload tokens must still
/// contain the required ID token claims, including `iss`, `sub`, `aud`, `exp`, and `iat`.
///
/// ```no_run
/// use openidconnect::core::{CoreIdToken, CoreWorkloadProviderMetadata};
/// use openidconnect::{ClientId, IssuerUrl, Nonce};
/// # #[cfg(feature = "reqwest")]
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let http_client = reqwest::Client::builder()
///     .redirect(reqwest::redirect::Policy::none())
///     .build()?;
/// let metadata = CoreWorkloadProviderMetadata::discover_async(
///     IssuerUrl::new("https://issuer.example".to_string())?,
///     &http_client,
/// ).await?;
/// let verifier = metadata.id_token_verifier(ClientId::new("my-service".to_string()), None);
/// let token: CoreIdToken = "received-token".parse()?;
/// // Only skip nonce validation for tokens obtained outside a browser authorization flow.
/// let claims = token.claims(&verifier, |_: Option<&Nonce>| Ok(()))?;
/// # Ok(())
/// # }
/// ```
#[serde_as]
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct WorkloadProviderMetadata<A, K>
where
    A: AdditionalProviderMetadata,
    K: JsonWebKey,
{
    issuer: IssuerUrl,
    jwks_uri: JsonWebKeySetUrl,
    #[serde(bound(deserialize = "K: JsonWebKey"))]
    #[serde_as(as = "VecSkipError<_>")]
    id_token_signing_alg_values_supported: Vec<K::SigningAlgorithm>,
    #[serde(default = "JsonWebKeySet::default", skip)]
    jwks: JsonWebKeySet<K>,
    #[serde(bound(deserialize = "A: AdditionalProviderMetadata"), flatten)]
    additional_metadata: A,
}

impl<A, K> WorkloadProviderMetadata<A, K>
where
    A: AdditionalProviderMetadata,
    K: JsonWebKey,
{
    /// Instantiates workload provider metadata. Keys must be fetched or supplied with `set_jwks`
    /// before verifying tokens.
    pub fn new(
        issuer: IssuerUrl,
        jwks_uri: JsonWebKeySetUrl,
        id_token_signing_alg_values_supported: Vec<K::SigningAlgorithm>,
        additional_metadata: A,
    ) -> Self {
        Self {
            issuer,
            jwks_uri,
            id_token_signing_alg_values_supported,
            jwks: JsonWebKeySet::default(),
            additional_metadata,
        }
    }

    field_getters_setters![
        pub self [self] ["workload provider metadata value"] {
            set_issuer -> issuer[IssuerUrl],
            set_jwks_uri -> jwks_uri[JsonWebKeySetUrl],
            set_id_token_signing_alg_values_supported -> id_token_signing_alg_values_supported[Vec<K::SigningAlgorithm>],
            set_jwks -> jwks[JsonWebKeySet<K>],
        }
    ];

    /// Fetches workload discovery metadata and its JSON Web Key Set from a trusted issuer.
    pub fn discover<C>(
        issuer_url: &IssuerUrl,
        http_client: &C,
    ) -> Result<Self, DiscoveryError<<C as SyncHttpClient>::Error>>
    where
        C: SyncHttpClient,
    {
        let discovery_url = issuer_url
            .join(CONFIG_URL_SUFFIX)
            .map_err(DiscoveryError::UrlParse)?;
        let response = http_client
            .call(discovery_request(discovery_url.clone()).map_err(|err| {
                DiscoveryError::Other(format!("failed to prepare request: {err}"))
            })?)
            .map_err(DiscoveryError::Request)?;
        let metadata: Self =
            discovery_response(issuer_url, &discovery_url, response, Self::issuer)?;
        JsonWebKeySet::fetch(metadata.jwks_uri(), http_client).map(|jwks| metadata.set_jwks(jwks))
    }

    /// Asynchronously fetches workload discovery metadata and its JSON Web Key Set.
    pub fn discover_async<'c, C>(
        issuer_url: IssuerUrl,
        http_client: &'c C,
    ) -> impl Future<Output = Result<Self, DiscoveryError<<C as AsyncHttpClient<'c>>::Error>>> + 'c
    where
        Self: 'c,
        C: AsyncHttpClient<'c>,
    {
        Box::pin(async move {
            let discovery_url = issuer_url
                .join(CONFIG_URL_SUFFIX)
                .map_err(DiscoveryError::UrlParse)?;
            let response = http_client
                .call(discovery_request(discovery_url.clone()).map_err(|err| {
                    DiscoveryError::Other(format!("failed to prepare request: {err}"))
                })?)
                .await
                .map_err(DiscoveryError::Request)?;
            let metadata: Self =
                discovery_response(&issuer_url, &discovery_url, response, Self::issuer)?;
            JsonWebKeySet::fetch_async(metadata.jwks_uri(), http_client)
                .await
                .map(|jwks| metadata.set_jwks(jwks))
        })
    }

    /// Builds an ID token verifier using this issuer, its keys, and advertised signing algorithms.
    ///
    /// Supply the expected audience as `client_id`. A client secret is only needed for tokens
    /// signed with a shared-secret algorithm. An empty or entirely unsupported algorithm list
    /// permits no signing algorithms. Nonce and other claim checks use the existing
    /// [`IdTokenVerifier`] defaults and can be configured on the returned verifier.
    pub fn id_token_verifier<'a>(
        &self,
        client_id: ClientId,
        client_secret: Option<ClientSecret>,
    ) -> IdTokenVerifier<'a, K> {
        let verifier = match client_secret {
            Some(secret) => IdTokenVerifier::new_confidential_client(
                client_id,
                secret,
                self.issuer.clone(),
                self.jwks.clone(),
            ),
            None => IdTokenVerifier::new_public_client(
                client_id,
                self.issuer.clone(),
                self.jwks.clone(),
            ),
        };
        verifier.set_allowed_algs(self.id_token_signing_alg_values_supported.clone())
    }

    /// Returns additional provider metadata fields.
    pub fn additional_metadata(&self) -> &A {
        &self.additional_metadata
    }

    /// Returns mutable additional provider metadata fields.
    pub fn additional_metadata_mut(&mut self) -> &mut A {
        &mut self.additional_metadata
    }
}
