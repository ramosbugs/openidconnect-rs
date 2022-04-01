//! This module implements components needed for [back-channel logout]
//!
//! [back-channel logout]: <https://openid.net/specs/openid-connect-backchannel-1_0.html>

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{de::Error, ser::SerializeMap, Deserialize, Serialize};

use crate::{
    helpers::{FilteredFlatten, FlattenFilter},
    jwt::{JsonWebToken, JsonWebTokenJsonPayloadSerde},
    types::helpers::{deserialize_string_or_vec, serde_utc_seconds},
    types::SessionIdentifier,
    AdditionalClaims, Audience, IssuerUrl, JsonWebKeyId, JsonWebKeyType,
    JweContentEncryptionAlgorithm, JwsSigningAlgorithm, SubjectIdentifier,
};

/// Back-Channel Logout Token
///
/// Parses a JWT as a Logout Token as definied in [section 2.4]
///
/// [section 2.4]: <https://openid.net/specs/openid-connect-backchannel-1_0.html#LogoutToken>
#[derive(Debug, Clone, PartialEq)]
pub struct LogoutToken<AC, JE, JS, JT>(
    JsonWebToken<JE, JS, JT, LogoutTokenClaims<AC>, JsonWebTokenJsonPayloadSerde>,
)
where
    AC: AdditionalClaims,
    JE: JweContentEncryptionAlgorithm<JT>,
    JS: JwsSigningAlgorithm<JT>,
    JT: JsonWebKeyType;

impl<AC, JE, JS, JT> LogoutToken<AC, JE, JS, JT>
where
    AC: AdditionalClaims,
    JE: JweContentEncryptionAlgorithm<JT>,
    JS: JwsSigningAlgorithm<JT>,
    JT: JsonWebKeyType,
{
    // TODO: implement signature verification & friends
}

/// The Logout Token Claims as defined in [section 2.4] of the [OpenID Connect Back-Channel Logout spec][1]
///
/// [1]: <https://openid.net/specs/openid-connect-backchannel-1_0.html>
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct LogoutTokenClaims<AC: AdditionalClaims> {
    /// The issuer of this token
    iss: IssuerUrl,
    /// The audience this token is intended for
    aud: Vec<Audience>,
    /// Time at which this token was issued
    #[serde(with = "serde_utc_seconds")]
    iat: DateTime<Utc>,
    /// The unique identifier for this token. This can be used to detect
    /// replay attacks.
    jti: JsonWebKeyId,
    #[serde(flatten)]
    identifier: LogoutIdentifier,
    events: HashMap<String, serde_json::Value>,
    additional_claims: FilteredFlatten<Self, AC>,
}

impl<AC> FlattenFilter for LogoutTokenClaims<AC>
where
    AC: AdditionalClaims,
{
    fn should_include(field_name: &str) -> bool {
        !matches!(
            field_name,
            "iss" | "aud" | "iat" | "jti" | "sub" | "sid" | "events"
        )
    }
}

impl<AC> LogoutTokenClaims<AC>
where
    AC: AdditionalClaims,
{
    /// The `iss` claim
    pub fn issuer(&self) -> &IssuerUrl {
        &self.iss
    }

    /// The `aud` claim
    pub fn audiences(&self) -> impl Iterator<Item = &Audience> {
        self.aud.iter()
    }

    /// The `iat` claim
    pub fn issue_time(&self) -> DateTime<Utc> {
        self.iat
    }

    /// The `jti` claim. It's the unique identifier for this token and can be
    /// used to detect replay attacks.
    pub fn jti(&self) -> &JsonWebKeyId {
        &self.jti
    }

    /// As per spec, a [`LogoutToken`] MUST either have the `sub`  or `sid`
    /// claim and MAY contain both. You can match the [`Identifier`] to detect
    /// which claims are present.
    pub fn identifier(&self) -> &LogoutIdentifier {
        &self.identifier
    }

    /// A [`LogoutToken`] is compatible with the [SET standard from RFC 8417][1]
    ///
    /// [1]: <https://www.rfc-editor.org/info/rfc8417>
    pub fn events(&self) -> &HashMap<String, serde_json::Value> {
        &self.events
    }
}
impl<'de, AC> Deserialize<'de> for LogoutTokenClaims<AC>
where
    AC: AdditionalClaims,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value: serde_json::Value = serde_json::Value::deserialize(deserializer)?;
        if let serde_json::Value::Object(ref map) = value {
            if map.contains_key("nonce") {
                return Err(<D::Error as Error>::custom("nonce claim is prohibited"));
            }
        }

        #[derive(Deserialize)]
        struct Repr<AC: AdditionalClaims> {
            /// The issuer of this token
            iss: IssuerUrl,
            /// The audience this token is intended for
            #[serde(deserialize_with = "deserialize_string_or_vec")]
            aud: Vec<Audience>,
            /// Time at which this token was issued
            #[serde(with = "serde_utc_seconds")]
            iat: DateTime<Utc>,
            /// The unique identifier for this token. This can be used to detect
            /// replay attacks.
            jti: JsonWebKeyId,
            #[serde(flatten)]
            identifier: LogoutIdentifier,
            events: HashMap<String, serde_json::Value>,
            #[serde(bound = "AC: AdditionalClaims")]
            #[serde(flatten)]
            additional_claims: FilteredFlatten<LogoutTokenClaims<AC>, AC>,
        }

        let token: Repr<AC> = serde_json::from_value(value).map_err(<D::Error as Error>::custom)?;

        token
            .events
            // according to the spec, this event must be included in the mapping
            .get("http://schemas.openid.net/event/backchannel-logout")
            .ok_or_else(|| {
                <D::Error as Error>::custom("token is missing correct JSON Object in events claim")
            })?
            // and it must be a JSON object and MAY BE empty but is allowed to
            // contain fields
            .as_object()
            .ok_or_else(|| <D::Error as Error>::custom("not a JSON Object"))?;
        Ok(LogoutTokenClaims {
            iss: token.iss,
            aud: token.aud,
            iat: token.iat,
            jti: token.jti,
            identifier: token.identifier,
            events: token.events,
            additional_claims: token.additional_claims,
        })
    }
}

/// A [`LogoutToken`] MUST contain either a `sub` or a `sid` claim and MAY
/// contain both. This enum represents these three possibilities.
#[derive(Debug, Hash, Clone, PartialEq, Eq)]
pub enum LogoutIdentifier {
    /// Both, the `sid` and `sub` claims are present
    Both {
        /// The `sub` claim as in [`Identifier::Subject`]
        subject: SubjectIdentifier,
        /// The `sid` claim as in [`Identifier::Subject`]
        session: SessionIdentifier,
    },
    /// Only the `sid` claim is present
    Session(SessionIdentifier),
    /// Only the `sub` claim is present
    Subject(SubjectIdentifier),
}

impl LogoutIdentifier {
    /// Directly return the [`SubjectIdentifier`] if the variant is either
    /// [`Identifier::Subject`] or [`Identifier::Both`]
    pub fn subject(&self) -> Option<&SubjectIdentifier> {
        match self {
            Self::Subject(s) => Some(s),
            Self::Both {
                subject,
                session: _,
            } => Some(subject),
            Self::Session(_) => None,
        }
    }

    /// Directly return the [`SessionIdentifier`] if the variant is either
    /// [`Identifier::Session`] or [`Identifier::Both`]
    pub fn session(&self) -> Option<&SessionIdentifier> {
        match self {
            Self::Subject(_) => None,
            Self::Both {
                subject: _,
                session,
            } => Some(session),
            Self::Session(s) => Some(s),
        }
    }
}

// serde does not have #[serde(flatten)] on enums with struct variants, so
impl<'de> Deserialize<'de> for LogoutIdentifier {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Both claims are set
        #[derive(Deserialize)]
        struct Both {
            sub: SubjectIdentifier,
            sid: SessionIdentifier,
        }

        // Only one claim is set
        #[derive(Deserialize)]
        enum SidOrSub {
            #[serde(rename = "sid")]
            Session(SessionIdentifier),
            #[serde(rename = "sub")]
            Subject(SubjectIdentifier),
        }

        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Either {
            Both(Both),
            Single(SidOrSub),
        }

        Ok(match Either::deserialize(deserializer)? {
            Either::Both(both) => LogoutIdentifier::Both {
                subject: both.sub,
                session: both.sid,
            },
            Either::Single(s) => match s {
                SidOrSub::Subject(s) => LogoutIdentifier::Subject(s),
                SidOrSub::Session(s) => LogoutIdentifier::Session(s),
            },
        })
    }
}

impl Serialize for LogoutIdentifier {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let len = self.session().is_some() as usize + self.subject().is_some() as usize;

        let mut map = serializer.serialize_map(Some(len))?;

        if let Some(s) = self.session() {
            map.serialize_entry("sid", s)?;
        }

        if let Some(s) = self.subject() {
            map.serialize_entry("sub", s)?;
        }

        map.end()
    }
}
#[cfg(test)]
mod tests {
    use crate::EmptyAdditionalClaims;

    use super::{LogoutIdentifier, LogoutTokenClaims};

    #[test]
    fn deserialize_only_sid() {
        let t: LogoutTokenClaims<EmptyAdditionalClaims> = serde_json::from_str(
            r#"
            {
                "iss": "https://server.example.com",
                "aud": "s6BhdRkqt3",
                "iat": 1471566154,
                "jti": "bWJq",
                "sid": "08a5019c-17e1-4977-8f42-65a12843ea02",
                "events": {
                    "http://schemas.openid.net/event/backchannel-logout": {}
                }
            }
        "#,
        )
        .unwrap();
        assert!(matches!(t.identifier(), LogoutIdentifier::Session(_)));
    }

    #[test]
    fn deserialize_only_sub() {
        let t: LogoutTokenClaims<EmptyAdditionalClaims> = serde_json::from_str(
            r#"
            {
                "iss": "https://server.example.com",
                "sub": "248289761001",
                "aud": "s6BhdRkqt3",
                "iat": 1471566154,
                "jti": "bWJq",
                "events": {
                    "http://schemas.openid.net/event/backchannel-logout": {}
                }
            }
        "#,
        )
        .unwrap();
        assert!(matches!(t.identifier(), LogoutIdentifier::Subject(_)));
    }

    #[test]
    #[should_panic]
    fn deserialize_missing_identifier() {
        let _: LogoutTokenClaims<EmptyAdditionalClaims> = serde_json::from_str(
            r#"
            {
                "iss": "https://server.example.com",
                "aud": "s6BhdRkqt3",
                "iat": 1471566154,
                "jti": "bWJq",
                "events": {
                    "http://schemas.openid.net/event/backchannel-logout": {}
                }
            }
        "#,
        )
        .unwrap();
    }

    #[test]
    fn deserialize_valid() {
        let t: LogoutTokenClaims<EmptyAdditionalClaims> = serde_json::from_str(
            r#"
            {
                "iss": "https://server.example.com",
                "sub": "248289761001",
                "aud": "s6BhdRkqt3",
                "iat": 1471566154,
                "jti": "bWJq",
                "sid": "08a5019c-17e1-4977-8f42-65a12843ea02",
                "events": {
                    "http://schemas.openid.net/event/backchannel-logout": {}
                }
            }
        "#,
        )
        .unwrap();
        assert!(matches!(
            t.identifier(),
            LogoutIdentifier::Both {
                subject: _,
                session: _
            }
        ))
    }

    #[test]
    #[should_panic]
    fn deserialize_events_empty() {
        let _: LogoutTokenClaims<EmptyAdditionalClaims> = serde_json::from_str(
            r#"
            {
                "iss": "https://server.example.com",
                "sub": "248289761001",
                "aud": "s6BhdRkqt3",
                "iat": 1471566154,
                "jti": "bWJq",
                "sid": "08a5019c-17e1-4977-8f42-65a12843ea02",
                "events": {
                }
            }
        "#,
        )
        .unwrap();
    }

    #[test]
    #[should_panic]
    fn deserialize_events_empty_array() {
        let _: LogoutTokenClaims<EmptyAdditionalClaims> = serde_json::from_str(
            r#"
            {
                "iss": "https://server.example.com",
                "sub": "248289761001",
                "aud": "s6BhdRkqt3",
                "iat": 1471566154,
                "jti": "bWJq",
                "sid": "08a5019c-17e1-4977-8f42-65a12843ea02",
                "events": []
            }
        "#,
        )
        .unwrap();
    }

    #[test]
    #[should_panic]
    fn deserialize_events_missing() {
        let _: LogoutTokenClaims<EmptyAdditionalClaims> = serde_json::from_str(
            r#"
            {
                "iss": "https://server.example.com",
                "sub": "248289761001",
                "aud": "s6BhdRkqt3",
                "iat": 1471566154,
                "jti": "bWJq",
                "sid": "08a5019c-17e1-4977-8f42-65a12843ea02"
            }
        "#,
        )
        .unwrap();
    }

    #[test]
    #[should_panic]
    fn deserialize_events_array() {
        let _: LogoutTokenClaims<EmptyAdditionalClaims> = serde_json::from_str(
            r#"
            {
                "iss": "https://server.example.com",
                "sub": "248289761001",
                "aud": "s6BhdRkqt3",
                "iat": 1471566154,
                "jti": "bWJq",
                "sid": "08a5019c-17e1-4977-8f42-65a12843ea02",
                "events": [
                    {"http://schemas.openid.net/event/backchannel-logout": {}}
                ],
                "nonce": "snsuigdbnfcjkn"
            }
        "#,
        )
        .unwrap();
    }
    #[test]
    #[should_panic]
    fn deserialize_nonce() {
        let _: LogoutTokenClaims<EmptyAdditionalClaims> = serde_json::from_str(
            r#"
            {
                "iss": "https://server.example.com",
                "sub": "248289761001",
                "aud": "s6BhdRkqt3",
                "iat": 1471566154,
                "jti": "bWJq",
                "sid": "08a5019c-17e1-4977-8f42-65a12843ea02",
                "events": {
                    "http://schemas.openid.net/event/backchannel-logout": {}
                },
                "nonce": "snsuigdbnfcjkn"
            }
        "#,
        )
        .unwrap();
    }

    #[test]
    fn deserialize_extra_field() {
        let _: LogoutTokenClaims<EmptyAdditionalClaims> = serde_json::from_str(
            r#"
            {
                "iss": "https://server.example.com",
                "sub": "248289761001",
                "aud": "s6BhdRkqt3",
                "iat": 1471566154,
                "jti": "bWJq",
                "sid": "08a5019c-17e1-4977-8f42-65a12843ea02",
                "events": {
                    "http://schemas.openid.net/event/backchannel-logout": {
                        "foo": "bar"
                    }
                }
            }
        "#,
        )
        .unwrap();
    }

    #[test]
    fn deserialize_multiple_events() {
        let _: LogoutTokenClaims<EmptyAdditionalClaims> = serde_json::from_str(
            r#"
            {
                "iss": "https://server.example.com",
                "sub": "248289761001",
                "aud": "s6BhdRkqt3",
                "iat": 1471566154,
                "jti": "bWJq",
                "sid": "08a5019c-17e1-4977-8f42-65a12843ea02",
                "events": {
                    "http://schemas.openid.net/event/backchannel-logout": {},
                    "http://schemas.example.org/event/foo": {}
                }
            }
        "#,
        )
        .unwrap();
    }

    #[test]
    fn deserialize_multiple_events_extra_fields() {
        let _: LogoutTokenClaims<EmptyAdditionalClaims> = serde_json::from_str(
            r#"
            {
                "iss": "https://server.example.com",
                "sub": "248289761001",
                "aud": "s6BhdRkqt3",
                "iat": 1471566154,
                "jti": "bWJq",
                "sid": "08a5019c-17e1-4977-8f42-65a12843ea02",
                "events": {
                    "http://schemas.openid.net/event/backchannel-logout": {
                        "foo": "bar"
                    },
                    "http://schemas.example.org/events/something": {
                        "faz": true
                    }
                }
            }
        "#,
        )
        .unwrap();
    }
}
