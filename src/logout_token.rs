//! This module implements components needed for [back-channel logout]
//!
//! [back-channel logout]: <https://openid.net/specs/openid-connect-backchannel-1_0.html>

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{de::Error, Deserialize};

use crate::{
    types::helpers::{deserialize_string_or_vec, serde_utc_seconds},
    types::SessionIdentifier,
    Audience, IssuerUrl, SubjectIdentifier,
};

/// The Logout Token as defined in [section 2.4] of the [OpenID Connect Back-Channel Logout spec][1]
///
/// [section 2.4]: <https://openid.net/specs/openid-connect-backchannel-1_0.html#LogoutToken>
/// [1]: <https://openid.net/specs/openid-connect-backchannel-1_0.html>
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogoutToken {
    /// The issuer of this token
    iss: IssuerUrl,
    /// The audience this token is intended for
    aud: Vec<Audience>,
    /// Time at which this token was issued
    iat: DateTime<Utc>,
    /// The unique identifier for this token. This can be used to detect
    /// replay attacks.
    jti: String,
    identifier: Identifier,
    events: HashMap<String, serde_json::Value>,
}

impl LogoutToken {
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
    pub fn jti(&self) -> &str {
        &self.jti
    }

    /// As per spec, a [`LogoutToken`] MUST either have the `sub`  or `sid`
    /// claim and MAY contain both. You can match the [`Identifier`] to detect
    /// which claims are present.
    pub fn identifier(&self) -> &Identifier {
        &self.identifier
    }

    /// A [`LogoutToken`] is compatible with the [SET standard from RFC 8417][1]
    ///
    /// [1]: <https://www.rfc-editor.org/info/rfc8417>
    pub fn events(&self) -> &HashMap<String, serde_json::Value> {
        &self.events
    }
}
impl<'de> Deserialize<'de> for LogoutToken {
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
        struct Repr {
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
            jti: String,
            #[serde(flatten)]
            identifier: Identifier,
            events: HashMap<String, serde_json::Value>,
        }

        let token: Repr = serde_json::from_value(value).map_err(<D::Error as Error>::custom)?;

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
        Ok(LogoutToken {
            iss: token.iss,
            aud: token.aud,
            iat: token.iat,
            jti: token.jti,
            identifier: token.identifier,
            events: token.events,
        })
    }
}

/// A [`LogoutToken`] MUST contain either a `sub` or a `sid` claim and MAY
/// contain both. This enum represents these three possibilities.
#[derive(Debug, Hash, Clone, PartialEq, Eq)]
pub enum Identifier {
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

impl Identifier {
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
impl<'de> Deserialize<'de> for Identifier {
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
            Either::Both(both) => Identifier::Both {
                subject: both.sub,
                session: both.sid,
            },
            Either::Single(s) => match s {
                SidOrSub::Subject(s) => Identifier::Subject(s),
                SidOrSub::Session(s) => Identifier::Session(s),
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::Identifier;

    use super::LogoutToken;

    #[test]
    fn deserialize_only_sid() {
        let t: LogoutToken = serde_json::from_str(
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
        assert!(matches!(t.identifier(), Identifier::Session(_)));
    }

    #[test]
    fn deserialize_only_sub() {
        let t: LogoutToken = serde_json::from_str(
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
        assert!(matches!(t.identifier(), Identifier::Subject(_)));
    }

    #[test]
    #[should_panic]
    fn deserialize_missing_identifier() {
        let _: LogoutToken = serde_json::from_str(
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
        let t: LogoutToken = serde_json::from_str(
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
        println!("{:#?}", t.identifier());
        assert!(matches!(
            t.identifier(),
            Identifier::Both {
                subject: _,
                session: _
            }
        ))
    }

    #[test]
    #[should_panic]
    fn deserialize_events_empty() {
        let _: LogoutToken = serde_json::from_str(
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
        let _: LogoutToken = serde_json::from_str(
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
        let _: LogoutToken = serde_json::from_str(
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
        let _: LogoutToken = serde_json::from_str(
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
        let _: LogoutToken = serde_json::from_str(
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
        let _: LogoutToken = serde_json::from_str(
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
        let _: LogoutToken = serde_json::from_str(
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
        let _: LogoutToken = serde_json::from_str(
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
