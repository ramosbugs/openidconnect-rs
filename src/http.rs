use std::io::Read;

use curl;
use curl::easy::Easy;
use oauth2::prelude::*;
use oauth2::AccessToken;
use url::Url;

pub const MIME_TYPE_JSON: &str = "application/json";
pub const MIME_TYPE_JWT: &str = "application/jwt";

// Request headers
pub const ACCEPT_JSON: (&str, &str) = ("Accept", MIME_TYPE_JSON);
pub const AUTHORIZATION: &str = "Authorization";
pub const BEARER: &str = "Bearer";
pub const CONTENT_TYPE_JSON: (&str, &str) = ("Content-Type", MIME_TYPE_JSON);

// Response status codes
pub const HTTP_STATUS_OK: u32 = 200;
pub const HTTP_STATUS_CREATED: u32 = 201;
pub const HTTP_STATUS_BAD_REQUEST: u32 = 400;

#[derive(Debug)]
pub struct HttpResponse {
    pub status_code: u32,
    pub content_type: Option<String>,
    pub body: Vec<u8>,
}
impl HttpResponse {
    pub fn check_content_type(&self, expected_content_type: &str) -> Result<(), String> {
        if let Some(ref content_type) = self.content_type {
            // Section 3.1.1.1 of RFC 7231 indicates that media types may be followed by
            // optional whitespace and/or a parameter (e.g., charset).
            // See https://tools.ietf.org/html/rfc7231#section-3.1.1.1.
            if !content_type.starts_with(expected_content_type) {
                Err(format!(
                    "Unexpected response Content-Type: `{}`, should be `{}`",
                    content_type, expected_content_type
                ))
            } else {
                Ok(())
            }
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum HttpRequestMethod {
    Get,
    Post,
}
impl Default for HttpRequestMethod {
    fn default() -> HttpRequestMethod {
        HttpRequestMethod::Get
    }
}

pub fn auth_bearer(access_token: &AccessToken) -> (&str, String) {
    (
        AUTHORIZATION,
        format!("{} {}", BEARER, access_token.secret()),
    )
}

#[derive(Debug)]
pub struct HttpRequest<'a> {
    pub url: &'a Url,
    pub method: HttpRequestMethod,
    pub headers: &'a Vec<(&'a str, &'a str)>,
    pub post_body: &'a Vec<u8>,
}
impl<'a> HttpRequest<'a> {
    pub fn request(self) -> Result<HttpResponse, curl::Error> {
        let mut easy = Easy::new();
        easy.url(&self.url.to_string()[..])?;
        match self.method {
            HttpRequestMethod::Get => {
                // FIXME: make this a flag that gets passed in
                trace!("GET {:?}", self.url);
            }
            HttpRequestMethod::Post => {
                // FIXME: remove
                trace!("POST {:?}", self.url);
                easy.post(true)?;
                easy.post_field_size(self.post_body.len() as u64)?;
                // FIXME: remove
                trace!(
                    "Body: {}",
                    String::from_utf8(self.post_body.to_vec()).unwrap()
                );
            }
        }

        if !self.headers.is_empty() {
            // FIXME: remove
            trace!("Headers: {:?}", self.headers);
            let mut headers = curl::easy::List::new();
            self.headers
                .iter()
                .map(|&(name, value)| headers.append(&format!("{}: {}", name, value)))
                .skip_while(|res| res.is_ok())
                .next()
                .unwrap_or(Ok(()))?;
            easy.http_headers(headers)?;
        }

        let mut response_body = Vec::new();
        let mut post_body_slice = &self.post_body[..];
        {
            let mut transfer = easy.transfer();
            transfer.read_function(|buf| Ok(post_body_slice.read(buf).unwrap_or(0)))?;

            transfer.write_function(|new_data| {
                response_body.extend_from_slice(new_data);
                Ok(new_data.len())
            })?;

            transfer.perform()?;
        }

        let response = HttpResponse {
            status_code: easy.response_code()?,
            // Section 3.1.1.1 of RFC 7231 indicates that media types are case insensitive.
            content_type: easy.content_type()?.map(|s| s.to_lowercase().to_string()),
            body: response_body,
        };
        // FIXME: remove
        trace!(
            "Response: status_code={}, content_type=`{:?}`, body=`{}`",
            response.status_code,
            response.content_type,
            String::from_utf8(response.body.to_vec()).unwrap()
        );
        Ok(response)
    }
}
