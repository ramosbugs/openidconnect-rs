
extern crate curl;

use std::io::Read;

use curl::easy::Easy;
use url::Url;

pub const ACCEPT_JSON: (&str, &str) = ("Accept", CONTENT_TYPE_JSON);
pub const CONTENT_TYPE_JSON: &str = "application/json";
pub const HTTP_STATUS_OK: u32 = 200;

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
                    content_type,
                    expected_content_type
                ))
            } else {
                Ok(())
            }
        } else {
            Ok(())
        }
    }
}

pub enum HttpRequestMethod {
    Get,
    Post,
}
impl Default for HttpRequestMethod {
    fn default() -> HttpRequestMethod { HttpRequestMethod::Get }
}

pub struct HttpRequest<'a> {
    pub url: Url,
    pub method: HttpRequestMethod,
    pub headers: Vec<(&'a str, &'a str)>,
    pub post_body: Vec<u8>,
}
impl<'a> HttpRequest<'a> {
    pub fn request(self) -> Result<HttpResponse, curl::Error> {
        let mut easy = Easy::new();
        easy.url(&self.url.to_string()[..])?;
        match self.method {
            HttpRequestMethod::Get => {},
            HttpRequestMethod::Post => {
                easy.post(true)?;
                easy.post_field_size(self.post_body.len() as u64)?
            },
        }

        if !self.headers.is_empty() {
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
            transfer.read_function(|buf| {
                Ok(post_body_slice.read(buf).unwrap_or(0))
            })?;

            transfer.write_function(|new_data| {
                response_body.extend_from_slice(new_data);
                Ok(new_data.len())
            })?;

            transfer.perform()?;
        }

        let response =
            HttpResponse {
                status_code: easy.response_code()?,
                // Section 3.1.1.1 of RFC 7231 indicates that media types are case insensitive.
                content_type: easy.content_type()?.map(|s| s.to_lowercase().to_string()),
                body: response_body,
            };
        Ok(response)
    }
}
