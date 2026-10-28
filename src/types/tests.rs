use crate::IssuerUrl;

#[test]
fn test_issuer_url_append() {
    assert_eq!(
        "http://example.com/.well-known/openid-configuration",
        IssuerUrl::new("http://example.com".to_string())
            .unwrap()
            .join(".well-known/openid-configuration")
            .unwrap()
            .to_string()
    );
    assert_eq!(
        "http://example.com/.well-known/openid-configuration",
        IssuerUrl::new("http://example.com/".to_string())
            .unwrap()
            .join(".well-known/openid-configuration")
            .unwrap()
            .to_string()
    );
    assert_eq!(
        "http://example.com/x/.well-known/openid-configuration",
        IssuerUrl::new("http://example.com/x".to_string())
            .unwrap()
            .join(".well-known/openid-configuration")
            .unwrap()
            .to_string()
    );
    assert_eq!(
        "http://example.com/x/.well-known/openid-configuration",
        IssuerUrl::new("http://example.com/x/".to_string())
            .unwrap()
            .join(".well-known/openid-configuration")
            .unwrap()
            .to_string()
    );
}

#[test]
fn test_url_serialize() {
    let issuer_url =
        IssuerUrl::new("http://example.com/.well-known/openid-configuration".to_string()).unwrap();
    let serialized_url = serde_json::to_string(&issuer_url).unwrap();

    assert_eq!(
        "\"http://example.com/.well-known/openid-configuration\"",
        serialized_url
    );

    let deserialized_url = serde_json::from_str(&serialized_url).unwrap();
    assert_eq!(issuer_url, deserialized_url);

    assert_eq!(
        serde_json::to_string(&IssuerUrl::new("http://example.com".to_string()).unwrap()).unwrap(),
        "\"http://example.com\"",
    );
}

#[cfg(feature = "accept-string-booleans")]
#[test]
fn test_string_bool_parse() {
    use crate::helpers::Boolean;

    fn test_case(input: &str, expect: bool) {
        let value: Boolean = serde_json::from_str(input).unwrap();
        assert_eq!(value.0, expect);
    }
    test_case("true", true);
    test_case("false", false);
    test_case("\"true\"", true);
    test_case("\"false\"", false);
    assert!(serde_json::from_str::<Boolean>("\"maybe\"").is_err());
}

fn jwks_response(request: crate::HttpRequest, content_type: &str) -> crate::HttpResponse {
    use http::header::{ACCEPT, CONTENT_TYPE};

    assert_eq!(request.method(), http::Method::GET);
    assert_eq!(request.uri(), "https://issuer.example/jwks");
    assert!(request.body().is_empty());
    let accepts_response = request.headers().get_all(ACCEPT).iter().any(|value| {
        value
            .to_str()
            .unwrap()
            .split(',')
            .any(|media_type| media_type.trim() == content_type)
    });
    if !accepts_response {
        return http::Response::builder()
            .status(http::StatusCode::NOT_ACCEPTABLE)
            .body(Vec::new())
            .unwrap();
    }
    http::Response::builder()
        .status(http::StatusCode::OK)
        .header(CONTENT_TYPE, content_type)
        .body(br#"{"keys":[]}"#.to_vec())
        .unwrap()
}

#[test]
fn test_jwks_fetch_media_types() {
    use crate::core::CoreJsonWebKeySet;
    use crate::http_utils::{MIME_TYPE_JSON, MIME_TYPE_JWKS};
    use crate::JsonWebKeySetUrl;

    let url = JsonWebKeySetUrl::new("https://issuer.example/jwks".to_string()).unwrap();
    for content_type in [MIME_TYPE_JSON, MIME_TYPE_JWKS] {
        let client = |request| Ok::<_, std::io::Error>(jwks_response(request, content_type));
        let jwks = CoreJsonWebKeySet::fetch(&url, &client).unwrap();
        assert!(jwks.keys().is_empty());
    }
}

#[test]
fn test_jwks_fetch_async_media_types() {
    use crate::core::CoreJsonWebKeySet;
    use crate::http_utils::{MIME_TYPE_JSON, MIME_TYPE_JWKS};
    use crate::JsonWebKeySetUrl;
    use std::future::Future;
    use std::sync::Arc;
    use std::task::{Context, Poll, Wake, Waker};

    struct NoopWake;
    impl Wake for NoopWake {
        fn wake(self: Arc<Self>) {}
    }

    let waker = Waker::from(Arc::new(NoopWake));
    let mut context = Context::from_waker(&waker);
    let url = JsonWebKeySetUrl::new("https://issuer.example/jwks".to_string()).unwrap();
    for content_type in [MIME_TYPE_JSON, MIME_TYPE_JWKS] {
        let client = |request| {
            std::future::ready(Ok::<_, std::io::Error>(jwks_response(
                request,
                content_type,
            )))
        };
        let mut future = Box::pin(CoreJsonWebKeySet::fetch_async(&url, &client));
        match future.as_mut().poll(&mut context) {
            Poll::Ready(result) => assert!(result.unwrap().keys().is_empty()),
            Poll::Pending => panic!("mock HTTP response should be immediately ready"),
        }
    }
}
