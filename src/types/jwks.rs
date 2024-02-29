use crate::http_utils::{check_content_type, MIME_TYPE_JSON, MIME_TYPE_JWKS};
use crate::types::jwk::{
    JsonWebKey, JsonWebKeyId, JsonWebKeyType, JsonWebKeyUse, JwsSigningAlgorithm,
};
use crate::{DiscoveryError, HttpRequest, HttpResponse};

use http::header::ACCEPT;
use http::{HeaderValue, Method, StatusCode};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, VecSkipError};

use std::future::Future;
use std::marker::PhantomData;

new_url_type![
    /// JSON Web Key Set URL.
    JsonWebKeySetUrl
];

/// JSON Web Key Set.
#[serde_as]
#[derive(Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct JsonWebKeySet<JS, JT, JU, K>
where
    JS: JwsSigningAlgorithm<JT>,
    JT: JsonWebKeyType,
    JU: JsonWebKeyUse,
    K: JsonWebKey<JS, JT, JU>,
{
    // FIXME: write a test that ensures duplicate object member names cause an error
    // (see https://tools.ietf.org/html/rfc7517#section-5)
    #[serde(bound = "K: JsonWebKey<JS, JT, JU>")]
    // Ignores invalid keys rather than failing. That way, clients can function using the keys that
    // they do understand, which is fine if they only ever get JWTs signed with those keys.
    #[serde_as(as = "VecSkipError<_>")]
    keys: Vec<K>,
    #[serde(skip)]
    _phantom: PhantomData<(JS, JT, JU)>,
}

/// Checks whether a JWK key can be used with a given signing algorithm.
pub(crate) fn check_key_compatibility<JS, JT, JU, K>(
    key: &K,
    signing_algorithm: &JS,
) -> Result<(), &'static str>
where
    JS: JwsSigningAlgorithm<JT>,
    JT: JsonWebKeyType,
    JU: JsonWebKeyUse,
    K: JsonWebKey<JS, JT, JU>,
{
    // if this key isn't suitable for signing
    if let Some(use_) = key.key_use() {
        if !use_.allows_signature() {
            return Err("key usage not permitted for digital signatures");
        }
    }

    // if this key doesn't have the right key type
    if signing_algorithm.key_type().as_ref() != Some(key.key_type()) {
        return Err("key type does not match signature algorithm");
    }

    #[cfg(feature = "jwk-alg")]
    match key.signing_alg() {
        // if no specific algorithm is mandated, any will do
        crate::JsonWebKeyAlgorithm::Unspecified => Ok(()),
        crate::JsonWebKeyAlgorithm::Unsupported => Err("key algorithm is not a signing algorithm"),
        crate::JsonWebKeyAlgorithm::Algorithm(key_alg) if key_alg == signing_algorithm => Ok(()),
        crate::JsonWebKeyAlgorithm::Algorithm(_) => Err("incompatible key algorithm"),
    }

    #[cfg(not(feature = "jwk-alg"))]
    Ok(())
}

impl<JS, JT, JU, K> JsonWebKeySet<JS, JT, JU, K>
where
    JS: JwsSigningAlgorithm<JT>,
    JT: JsonWebKeyType,
    JU: JsonWebKeyUse,
    K: JsonWebKey<JS, JT, JU>,
{
    /// Create a new JSON Web Key Set.
    pub fn new(keys: Vec<K>) -> Self {
        Self {
            keys,
            _phantom: PhantomData,
        }
    }

    /// Return a list of suitable keys, given a key id an signature algorithm
    pub(crate) fn filter_keys(&self, key_id: &Option<JsonWebKeyId>, signature_alg: &JS) -> Vec<&K> {
        self.keys()
        .iter()
        .filter(|key|
            // Either the JWT doesn't include a 'kid' (in which case any 'kid'
            // is acceptable), or the 'kid' matches the key's ID.
            if key_id.is_some() && key_id.as_ref() != key.key_id() {
                false
            } else {
                check_key_compatibility(*key, signature_alg).is_ok()
            }
        )
        .collect()
    }

    /// Fetch a remote JSON Web Key Set from the specified `url` using the given `http_client`
    /// (e.g., [`crate::reqwest::http_client`] or [`crate::curl::http_client`]).
    pub fn fetch<HC, RE>(
        url: &JsonWebKeySetUrl,
        http_client: HC,
    ) -> Result<Self, DiscoveryError<RE>>
    where
        HC: FnOnce(HttpRequest) -> Result<HttpResponse, RE>,
        RE: std::error::Error + 'static,
    {
        http_client(Self::fetch_request(url))
            .map_err(DiscoveryError::Request)
            .and_then(Self::fetch_response)
    }

    /// Fetch a remote JSON Web Key Set from the specified `url` using the given async `http_client`
    /// (e.g., [`crate::reqwest::async_http_client`]).
    pub async fn fetch_async<F, HC, RE>(
        url: &JsonWebKeySetUrl,
        http_client: HC,
    ) -> Result<Self, DiscoveryError<RE>>
    where
        F: Future<Output = Result<HttpResponse, RE>>,
        HC: FnOnce(HttpRequest) -> F,
        RE: std::error::Error + 'static,
    {
        http_client(Self::fetch_request(url))
            .await
            .map_err(DiscoveryError::Request)
            .and_then(Self::fetch_response)
    }

    fn fetch_request(url: &JsonWebKeySetUrl) -> HttpRequest {
        HttpRequest {
            url: url.url().clone(),
            method: Method::GET,
            headers: vec![(ACCEPT, HeaderValue::from_static(MIME_TYPE_JSON))]
                .into_iter()
                .collect(),
            body: Vec::new(),
        }
    }

    fn fetch_response<RE>(http_response: HttpResponse) -> Result<Self, DiscoveryError<RE>>
    where
        RE: std::error::Error + 'static,
    {
        if http_response.status_code != StatusCode::OK {
            return Err(DiscoveryError::Response(
                http_response.status_code,
                http_response.body,
                format!("HTTP status code {}", http_response.status_code),
            ));
        }

        check_content_type(&http_response.headers, MIME_TYPE_JSON)
            .or_else(|err| {
                check_content_type(&http_response.headers, MIME_TYPE_JWKS).map_err(|_| err)
            })
            .map_err(|err_msg| {
                DiscoveryError::Response(
                    http_response.status_code,
                    http_response.body.clone(),
                    err_msg,
                )
            })?;

        serde_path_to_error::deserialize(&mut serde_json::Deserializer::from_slice(
            &http_response.body,
        ))
        .map_err(DiscoveryError::Parse)
    }

    /// Return the keys in this JSON Web Key Set.
    pub fn keys(&self) -> &Vec<K> {
        &self.keys
    }
}
impl<JS, JT, JU, K> Clone for JsonWebKeySet<JS, JT, JU, K>
where
    JS: JwsSigningAlgorithm<JT>,
    JT: JsonWebKeyType,
    JU: JsonWebKeyUse,
    K: JsonWebKey<JS, JT, JU>,
{
    fn clone(&self) -> Self {
        Self::new(self.keys.clone())
    }
}
impl<JS, JT, JU, K> Default for JsonWebKeySet<JS, JT, JU, K>
where
    JS: JwsSigningAlgorithm<JT>,
    JT: JsonWebKeyType,
    JU: JsonWebKeyUse,
    K: JsonWebKey<JS, JT, JU>,
{
    fn default() -> Self {
        Self::new(Vec::new())
    }
}
