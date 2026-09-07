use crate::core::{
    CoreHmacKey, CoreIdToken, CoreIdTokenClaims, CoreJsonWebKey, CoreJsonWebKeySet,
    CoreJwsSigningAlgorithm, CoreProviderMetadata, CoreRsaPrivateSigningKey,
    CoreWorkloadProviderMetadata,
};
use crate::http_utils::{MIME_TYPE_JSON, MIME_TYPE_JWKS};
use crate::jwt::tests::{TEST_RSA_PRIV_KEY, TEST_RSA_PUB_KEY};
use crate::{
    Audience, ClaimsVerificationError, ClientId, ClientSecret, DiscoveryError,
    EmptyAdditionalProviderMetadata, HttpRequest, HttpResponse, IssuerUrl, JsonWebKeySetUrl, Nonce,
    StandardClaims, SubjectIdentifier,
};
use chrono::{TimeZone, Utc};
use http::header::{ACCEPT, CONTENT_TYPE};
use serde_json::json;
use std::cell::Cell;
use std::future::Future;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};

const ISSUER: &str = "https://issuer.example/workload";
const JWKS_URL: &str = "https://keys.example/jwks";
const NOW: i64 = 1_700_000_000;

fn metadata_json() -> serde_json::Value {
    json!({
        "issuer": ISSUER,
        "jwks_uri": JWKS_URL,
        "id_token_signing_alg_values_supported": ["RS256"]
    })
}

fn metadata_with_keys() -> CoreWorkloadProviderMetadata {
    serde_json::from_value::<CoreWorkloadProviderMetadata>(metadata_json())
        .unwrap()
        .set_jwks(CoreJsonWebKeySet::new(vec![serde_json::from_str::<
            CoreJsonWebKey,
        >(TEST_RSA_PUB_KEY)
        .unwrap()]))
}

fn response(request: HttpRequest, document: &str) -> HttpResponse {
    assert_eq!(request.method(), http::Method::GET);
    assert!(request.body().is_empty());
    let (content_type, body) = if request.uri() == JWKS_URL {
        let accepts_jwks = request.headers()[ACCEPT]
            .to_str()
            .unwrap()
            .split(',')
            .any(|value| value.trim() == MIME_TYPE_JWKS);
        if !accepts_jwks {
            return http::Response::builder()
                .status(406)
                .body(Vec::new())
                .unwrap();
        }
        (MIME_TYPE_JWKS, format!("{{\"keys\":[{TEST_RSA_PUB_KEY}]}}"))
    } else {
        assert_eq!(
            request.uri(),
            "https://issuer.example/workload/.well-known/openid-configuration"
        );
        assert_eq!(request.headers()[ACCEPT], MIME_TYPE_JSON);
        (MIME_TYPE_JSON, document.to_string())
    };
    http::Response::builder()
        .status(200)
        .header(CONTENT_TYPE, content_type)
        .body(body.into_bytes())
        .unwrap()
}

fn poll_ready<T>(future: impl Future<Output = T>) -> T {
    struct NoopWake;
    impl Wake for NoopWake {
        fn wake(self: Arc<Self>) {}
    }
    let waker = Waker::from(Arc::new(NoopWake));
    match Box::pin(future)
        .as_mut()
        .poll(&mut Context::from_waker(&waker))
    {
        Poll::Ready(result) => result,
        Poll::Pending => panic!("mock HTTP responses should be immediately ready"),
    }
}

#[test]
fn test_workload_discovery_sync_and_async() {
    let document = metadata_json().to_string();
    let calls = Cell::new(0);
    let client = |request| {
        calls.set(calls.get() + 1);
        Ok::<_, std::io::Error>(response(request, &document))
    };
    let issuer = IssuerUrl::new(ISSUER.to_string()).unwrap();
    let metadata = CoreWorkloadProviderMetadata::discover(&issuer, &client).unwrap();
    assert_eq!(calls.get(), 2);
    assert_eq!(metadata.issuer(), &issuer);
    assert_eq!(metadata.jwks_uri().as_str(), JWKS_URL);
    assert_eq!(metadata.jwks(), metadata_with_keys().jwks());

    let async_client = |request| std::future::ready(client(request));
    let async_metadata = poll_ready(CoreWorkloadProviderMetadata::discover_async(
        issuer,
        &async_client,
    ))
    .unwrap();
    assert_eq!(calls.get(), 4);
    assert_eq!(metadata, async_metadata);
    assert_eq!(serde_json::to_value(&metadata).unwrap(), metadata_json());
}

#[test]
fn test_workload_metadata_required_fields_and_duplicates() {
    for field in [
        "issuer",
        "jwks_uri",
        "id_token_signing_alg_values_supported",
    ] {
        let mut document = metadata_json();
        document.as_object_mut().unwrap().remove(field);
        assert!(serde_json::from_value::<CoreWorkloadProviderMetadata>(document).is_err());
        let mut document = metadata_json();
        document[field] = serde_json::Value::Null;
        assert!(serde_json::from_value::<CoreWorkloadProviderMetadata>(document).is_err());
        let mut document = metadata_json().to_string();
        document.pop();
        document.push_str(&format!(",\"{field}\":{}}}", metadata_json()[field]));
        assert!(serde_json::from_str::<CoreWorkloadProviderMetadata>(&document).is_err());
    }
    for field in ["issuer", "jwks_uri"] {
        let mut document = metadata_json();
        document[field] = json!("not a URL");
        assert!(serde_json::from_value::<CoreWorkloadProviderMetadata>(document).is_err());
    }
}

#[test]
fn test_workload_metadata_extensions_and_unknown_algorithms() {
    #[derive(Clone, Debug, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
    struct ExtraMetadata {
        claims_supported: Vec<String>,
    }
    impl crate::AdditionalProviderMetadata for ExtraMetadata {}
    let mut document = metadata_json();
    document["id_token_signing_alg_values_supported"] = json!(["future-alg", "RS256"]);
    document["claims_supported"] = json!(["sub"]);
    document["jwks"] =
        json!({"keys": [serde_json::from_str::<serde_json::Value>(TEST_RSA_PUB_KEY).unwrap()]});
    let mut metadata: crate::WorkloadProviderMetadata<ExtraMetadata, CoreJsonWebKey> =
        serde_json::from_value(document).unwrap();
    assert_eq!(
        metadata.id_token_signing_alg_values_supported(),
        &vec![CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256]
    );
    assert!(
        metadata.jwks().keys().is_empty(),
        "embedded keys must not be trusted"
    );
    assert_eq!(metadata.additional_metadata().claims_supported, vec!["sub"]);
    metadata
        .additional_metadata_mut()
        .claims_supported
        .push("aud".to_string());
    assert_eq!(
        serde_json::to_value(metadata).unwrap()["claims_supported"],
        json!(["sub", "aud"])
    );
}

#[test]
fn test_workload_discovery_rejects_issuer_mismatch_before_fetching_keys() {
    let mut document = metadata_json();
    document["issuer"] = json!("https://untrusted.example");
    let document = document.to_string();
    let calls = Cell::new(0);
    let client = |request: HttpRequest| {
        calls.set(calls.get() + 1);
        assert_ne!(request.uri(), JWKS_URL);
        Ok::<_, std::io::Error>(response(request, &document))
    };
    let issuer = IssuerUrl::new(ISSUER.to_string()).unwrap();
    assert!(matches!(
        CoreWorkloadProviderMetadata::discover(&issuer, &client),
        Err(DiscoveryError::Validation(_))
    ));
    let async_client = |request| std::future::ready(client(request));
    assert!(matches!(
        poll_ready(CoreWorkloadProviderMetadata::discover_async(
            issuer,
            &async_client
        )),
        Err(DiscoveryError::Validation(_))
    ));
    assert_eq!(calls.get(), 2);
}

#[test]
fn test_workload_discovery_propagates_http_and_parse_errors() {
    let issuer = IssuerUrl::new(ISSUER.to_string()).unwrap();
    for fail_jwks in [false, true] {
        for (status, content_type, body) in [
            (500, MIME_TYPE_JSON, "{}"),
            (200, "text/html", "{}"),
            (200, MIME_TYPE_JSON, "not JSON"),
        ] {
            let calls = Cell::new(0);
            let client = |request: HttpRequest| {
                calls.set(calls.get() + 1);
                Ok::<_, std::io::Error>(if (request.uri() == JWKS_URL) == fail_jwks {
                    http::Response::builder()
                        .status(status)
                        .header(CONTENT_TYPE, content_type)
                        .body(body.as_bytes().to_vec())
                        .unwrap()
                } else {
                    response(request, &metadata_json().to_string())
                })
            };
            let result = CoreWorkloadProviderMetadata::discover(&issuer, &client);
            if body == "not JSON" {
                assert!(matches!(result, Err(DiscoveryError::Parse(_))));
            } else {
                assert!(matches!(result, Err(DiscoveryError::Response(_, _, _))));
            }
            assert_eq!(calls.get(), if fail_jwks { 2 } else { 1 });
        }
    }
    let client = |_| {
        Err::<HttpResponse, _>(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "blocked by client",
        ))
    };
    assert!(matches!(
        CoreWorkloadProviderMetadata::discover(&issuer, &client),
        Err(DiscoveryError::Request(_))
    ));
    let async_client = |request| std::future::ready(client(request));
    assert!(matches!(
        poll_ready(CoreWorkloadProviderMetadata::discover_async(
            issuer,
            &async_client
        )),
        Err(DiscoveryError::Request(_))
    ));
}

#[test]
fn test_full_provider_discovery_remains_strict() {
    let error = serde_json::from_value::<CoreProviderMetadata>(metadata_json()).unwrap_err();
    assert!(error.to_string().contains("authorization_endpoint"));
    let mut document = metadata_json();
    document["authorization_endpoint"] = json!("https://issuer.example/authorize");
    document["token_endpoint"] = json!("https://issuer.example/token");
    document["response_types_supported"] = json!(["code"]);
    document["subject_types_supported"] = json!(["public"]);
    let client = |request| Ok::<_, std::io::Error>(response(request, &document.to_string()));
    let issuer = IssuerUrl::new(ISSUER.to_string()).unwrap();
    let metadata = CoreProviderMetadata::discover(&issuer, &client).unwrap();
    assert_eq!(
        metadata.authorization_endpoint().as_str(),
        "https://issuer.example/authorize"
    );
    let async_client = |request| std::future::ready(client(request));
    assert_eq!(
        metadata,
        poll_ready(CoreProviderMetadata::discover_async(issuer, &async_client)).unwrap()
    );
}

fn token_claims(issuer: &str, audience: &str, expiry: i64) -> CoreIdTokenClaims {
    CoreIdTokenClaims::new(
        IssuerUrl::new(issuer.to_string()).unwrap(),
        vec![Audience::new(audience.to_string())],
        Utc.timestamp_opt(expiry, 0).unwrap(),
        Utc.timestamp_opt(NOW - 60, 0).unwrap(),
        StandardClaims::new(SubjectIdentifier::new("workload".to_string())),
        Default::default(),
    )
}

#[test]
fn test_workload_verifier_preserves_claim_and_signature_checks() {
    let metadata = metadata_with_keys();
    let verifier = metadata
        .id_token_verifier(ClientId::new("service".to_string()), None)
        .set_time_fn(|| Utc.timestamp_opt(NOW, 0).unwrap());
    let key = CoreRsaPrivateSigningKey::from_pem(TEST_RSA_PRIV_KEY, None).unwrap();
    let token = CoreIdToken::new(
        token_claims(ISSUER, "service", NOW + 60),
        &key,
        CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
        None,
        None,
    )
    .unwrap();
    assert_eq!(
        token
            .claims(&verifier, |_: Option<&Nonce>| Ok(()))
            .unwrap()
            .subject()
            .as_str(),
        "workload"
    );
    assert!(matches!(
        token.claims(&verifier, &Nonce::new("required-nonce".to_string())),
        Err(ClaimsVerificationError::InvalidNonce(_))
    ));
    for (issuer, audience, expiry) in [
        ("https://wrong.example", "service", NOW + 60),
        (ISSUER, "other-service", NOW + 60),
        (ISSUER, "service", NOW - 1),
    ] {
        let token = CoreIdToken::new(
            token_claims(issuer, audience, expiry),
            &key,
            CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
            None,
            None,
        )
        .unwrap();
        let error = token
            .claims(&verifier, |_: Option<&Nonce>| Ok(()))
            .unwrap_err();
        match (issuer == ISSUER, audience == "service") {
            (false, _) => assert!(matches!(error, ClaimsVerificationError::InvalidIssuer(_))),
            (_, false) => assert!(matches!(error, ClaimsVerificationError::InvalidAudience(_))),
            _ => assert!(matches!(error, ClaimsVerificationError::Expired(_))),
        }
    }
    let mut altered = token.to_string();
    let signature_start = altered.rfind('.').unwrap() + 1;
    let replacement = if altered.as_bytes()[signature_start] == b'A' {
        "B"
    } else {
        "A"
    };
    altered.replace_range(signature_start..signature_start + 1, replacement);
    let altered: CoreIdToken = altered.parse().unwrap();
    assert!(matches!(
        altered.claims(&verifier, |_: Option<&Nonce>| Ok(())),
        Err(ClaimsVerificationError::SignatureVerification(_))
    ));
    for algorithms in [vec![], vec![CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha512]] {
        let verifier = metadata
            .clone()
            .set_id_token_signing_alg_values_supported(algorithms)
            .id_token_verifier(ClientId::new("service".to_string()), None)
            .set_time_fn(|| Utc.timestamp_opt(NOW, 0).unwrap());
        assert!(matches!(
            token.claims(&verifier, |_: Option<&Nonce>| Ok(())),
            Err(ClaimsVerificationError::SignatureVerification(_))
        ));
    }
}

#[test]
fn test_workload_verifier_preserves_client_secret() {
    let metadata = CoreWorkloadProviderMetadata::new(
        IssuerUrl::new(ISSUER.to_string()).unwrap(),
        JsonWebKeySetUrl::new(JWKS_URL.to_string()).unwrap(),
        vec![CoreJwsSigningAlgorithm::HmacSha256],
        EmptyAdditionalProviderMetadata {},
    );
    let token = CoreIdToken::new(
        token_claims(ISSUER, "service", NOW + 60),
        &CoreHmacKey::new(b"test-client-secret"),
        CoreJwsSigningAlgorithm::HmacSha256,
        None,
        None,
    )
    .unwrap();
    for secret in [None, Some("wrong-secret"), Some("test-client-secret")] {
        let verifier = metadata
            .id_token_verifier(
                ClientId::new("service".to_string()),
                secret.map(|value| ClientSecret::new(value.to_string())),
            )
            .set_time_fn(|| Utc.timestamp_opt(NOW, 0).unwrap());
        assert_eq!(
            token.claims(&verifier, |_: Option<&Nonce>| Ok(())).is_ok(),
            secret == Some("test-client-secret")
        );
    }
}

#[test]
fn test_workload_verifier_supports_borrowed_audience_policy() {
    let metadata = metadata_with_keys();
    let extra_audience = String::from("trusted-service");
    let mut claims = token_claims(ISSUER, "service", NOW + 60);
    claims = claims.set_audiences(vec![
        Audience::new("service".to_string()),
        Audience::new(extra_audience.clone()),
    ]);
    let key = CoreRsaPrivateSigningKey::from_pem(TEST_RSA_PRIV_KEY, None).unwrap();
    let token = CoreIdToken::new(
        claims,
        &key,
        CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
        None,
        None,
    )
    .unwrap();
    let verifier = metadata
        .id_token_verifier(ClientId::new("service".to_string()), None)
        .set_time_fn(|| Utc.timestamp_opt(NOW, 0).unwrap());
    assert!(matches!(
        token.claims(&verifier, |_: Option<&Nonce>| Ok(())),
        Err(ClaimsVerificationError::InvalidAudience(_))
    ));
    let verifier = verifier.set_other_audience_verifier_fn(|aud| aud.as_str() == extra_audience);
    assert!(token.claims(&verifier, |_: Option<&Nonce>| Ok(())).is_ok());
}

#[test]
fn test_workload_unsupported_algorithms_do_not_enable_defaults() {
    let mut document = metadata_json();
    document["id_token_signing_alg_values_supported"] = json!(["future-alg"]);
    let metadata: CoreWorkloadProviderMetadata = serde_json::from_value(document).unwrap();
    assert!(metadata.id_token_signing_alg_values_supported().is_empty());
    let metadata = metadata.set_jwks(metadata_with_keys().jwks().clone());
    let verifier = metadata
        .id_token_verifier(ClientId::new("service".to_string()), None)
        .set_time_fn(|| Utc.timestamp_opt(NOW, 0).unwrap());
    let key = CoreRsaPrivateSigningKey::from_pem(TEST_RSA_PRIV_KEY, None).unwrap();
    let token = CoreIdToken::new(
        token_claims(ISSUER, "service", NOW + 60),
        &key,
        CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
        None,
        None,
    )
    .unwrap();
    assert!(matches!(
        token.claims(&verifier, |_: Option<&Nonce>| Ok(())),
        Err(ClaimsVerificationError::SignatureVerification(_))
    ));
}
