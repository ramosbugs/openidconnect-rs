use http::header::{HeaderMap, HeaderName, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use oauth2::AccessToken;

pub const MIME_TYPE_JSON: &str = "application/json";
pub const MIME_TYPE_JWT: &str = "application/jwt";

pub const BEARER: &str = "Bearer";

pub fn header_starts_with_ignoring_case(header: &HeaderValue, expected_start: &str) -> bool {
    header
        .to_str()
        .ok()
        .filter(|ct| ct.to_lowercase().starts_with(&expected_start.to_lowercase()))
        .is_some()
}

pub fn check_content_type(headers: &HeaderMap, expected_content_type: &str) -> Result<(), String> {
    headers
        .get(CONTENT_TYPE)
        .map_or(Ok(()), |content_type|
            // Section 3.1.1.1 of RFC 7231 indicates that media types are case insensitive and
            // may be followed by optional whitespace and/or a parameter (e.g., charset).
            // See https://tools.ietf.org/html/rfc7231#section-3.1.1.1.
            if !header_starts_with_ignoring_case(&content_type, expected_content_type) {
                Err(
                    format!(
                        "Unexpected response Content-Type: {:?}, should be `{}`",
                        content_type,
                        expected_content_type
                    )
                )
            } else {
                Ok(())
            }
        )
}

pub fn auth_bearer(access_token: &AccessToken) -> (HeaderName, HeaderValue) {
    (
        AUTHORIZATION,
        HeaderValue::from_str(&format!("{} {}", BEARER, access_token.secret()))
            .expect("invalid access token"),
    )
}
