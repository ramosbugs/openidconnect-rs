use crate::core::{CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm};
use crate::helpers::{deserialize_string_or_vec, Timestamp};
use crate::jwt::JsonWebTokenAccess;
use crate::jwt::{JsonWebTokenError, JsonWebTokenJsonPayloadSerde};
use crate::{
    Audience, AudiencesClaim, ClaimsVerificationError, IssuerClaim, IssuerUrl, JsonWebKey,
    JsonWebToken, JsonWebTokenAlgorithm, JsonWebTokenIdentifier, JweContentEncryptionAlgorithm,
    JwsSigningAlgorithm, LogoutTokenVerifier, PrivateSigningKey, SessionIdentifier,
    SignatureVerificationError, SubjectIdentifier,
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use serde_with::{serde_as, skip_serializing_none};

use std::fmt::{Debug, Display};
use std::str::FromStr;

#[cfg(test)]
mod tests;

/// OpenID Connect logout token used for back-channel logout requests.
#[cfg_attr(
    any(test, feature = "timing-resistant-secret-traits"),
    derive(PartialEq)
)]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LogoutToken<
    JE: JweContentEncryptionAlgorithm<KeyType = JS::KeyType> = CoreJweContentEncryptionAlgorithm,
    JS: JwsSigningAlgorithm = CoreJwsSigningAlgorithm,
>(
    #[serde(bound(deserialize = ""))]
    JsonWebToken<JE, JS, LogoutTokenClaims, JsonWebTokenJsonPayloadSerde>,
);

impl<JE, JS> FromStr for LogoutToken<JE, JS>
where
    JE: JweContentEncryptionAlgorithm<KeyType = JS::KeyType>,
    JS: JwsSigningAlgorithm,
{
    type Err = serde_json::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_value(Value::String(s.to_string()))
    }
}

impl<JE, JS> LogoutToken<JE, JS>
where
    JE: JweContentEncryptionAlgorithm<KeyType = JS::KeyType>,
    JS: JwsSigningAlgorithm,
{
    /// Initializes a logout token with the specified claims, signed using the given signing key and
    /// algorithm.
    pub fn new<S>(
        claims: LogoutTokenClaims,
        signing_key: &S,
        alg: JS,
    ) -> Result<Self, JsonWebTokenError>
    where
        S: PrivateSigningKey,
        <S as PrivateSigningKey>::VerificationKey: JsonWebKey<SigningAlgorithm = JS>,
    {
        JsonWebToken::new(claims, signing_key, &alg).map(Self)
    }

    /// Verifies and returns a reference to the logout token claims.
    pub fn claims<'a, K>(
        &'a self,
        verifier: &LogoutTokenVerifier<K>,
    ) -> Result<&'a LogoutTokenClaims, ClaimsVerificationError>
    where
        K: JsonWebKey<SigningAlgorithm = JS>,
    {
        verifier.verified_claims(&self.0)
    }

    /// Verifies and returns the logout token claims.
    pub fn into_claims<K>(
        self,
        verifier: &LogoutTokenVerifier<K>,
    ) -> Result<LogoutTokenClaims, ClaimsVerificationError>
    where
        K: JsonWebKey<SigningAlgorithm = JS>,
    {
        verifier.verified_claims_owned(self.0)
    }

    /// Returns the [`JwsSigningAlgorithm`] used to sign this logout token.
    ///
    /// This function returns an error if the token is unsigned or utilizes JSON Web Encryption
    /// (JWE).
    pub fn signing_alg(&self) -> Result<&JS, SignatureVerificationError> {
        match self.0.unverified_header().alg {
            JsonWebTokenAlgorithm::Signature(ref signing_alg) => Ok(signing_alg),
            JsonWebTokenAlgorithm::Encryption(ref other) => {
                Err(SignatureVerificationError::UnsupportedAlg(
                    serde_plain::to_string(other).unwrap_or_else(|_| format!("{other:?}")),
                ))
            }
            JsonWebTokenAlgorithm::None => Err(SignatureVerificationError::NoSignature),
        }
    }

    /// Returns the [`JsonWebKey`] usable for verifying this logout token's JSON Web Signature.
    ///
    /// This function returns an error if the token has no signature or a corresponding key cannot
    /// be found.
    pub fn signing_key<'s, K>(
        &self,
        verifier: &'s LogoutTokenVerifier<'s, K>,
    ) -> Result<&'s K, SignatureVerificationError>
    where
        K: JsonWebKey<SigningAlgorithm = JS>,
    {
        verifier
            .jwt_verifier
            .signing_key(self.0.unverified_header().kid.as_ref(), self.signing_alg()?)
    }
}
impl<JE, JS> Display for LogoutToken<JE, JS>
where
    JE: JweContentEncryptionAlgorithm<KeyType = JS::KeyType>,
    JS: JwsSigningAlgorithm,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = serde_json::to_value(self)
            // This should never arise, since we're just asking serde_json to serialize the
            // signing input concatenated with the signature, both of which are precomputed.
            .expect("logout token serialization failed");
        let str = value
            .as_str()
            // This should also never arise, since our LogoutToken serializer always calls serialize_str
            .expect("logout token serializer did not produce a str");
        write!(f, "{str}")
    }
}

/// The target of the logout token - either a specific session (with optional subject identifier),
/// or all sessions for a subject
#[cfg_attr(
    any(test, feature = "timing-resistant-secret-traits"),
    derive(PartialEq)
)]
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum LogoutTokenTarget {
    /// The logout request includes a session identifier, optionally with subject identifier
    Session {
        /// The ID of the session to end
        sid: SessionIdentifier,
        /// Optional ID of the subject that owns the session
        sub: Option<SubjectIdentifier>,
    },
    /// The logout request includes only a subject identifier
    Subject {
        /// The ID of the subject to be logged out
        sub: SubjectIdentifier,
    },
}

impl LogoutTokenTarget {
    /// Create logout token target from a session ID string
    pub fn from_sid(sid: String) -> Self {
        Self::Session {
            sid: SessionIdentifier::new(sid),
            sub: None,
        }
    }

    /// Create logout token target from a subject string
    pub fn from_sub(sub: String) -> Self {
        Self::Subject {
            sub: SubjectIdentifier::new(sub),
        }
    }

    /// Create logout token target from a session ID and subject string
    pub fn from_sid_and_sub(sid: String, sub: String) -> Self {
        Self::Session {
            sid: SessionIdentifier::new(sid),
            sub: Some(SubjectIdentifier::new(sub)),
        }
    }
}

/// OpenID Connect logout token claims.
#[cfg_attr(
    any(test, feature = "timing-resistant-secret-traits"),
    derive(PartialEq)
)]
#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LogoutTokenClaims {
    #[serde(rename = "iss")]
    issuer: IssuerUrl,
    // We always serialize as an array, which is valid according to the spec. This sets the
    // 'default' attribute to be compatible with non-spec compliant OIDC providers that omit this
    // field.
    #[serde(
        default,
        rename = "aud",
        deserialize_with = "deserialize_string_or_vec"
    )]
    audiences: Vec<Audience>,
    #[serde_as(as = "Timestamp")]
    #[serde(rename = "exp")]
    expiration: DateTime<Utc>,
    #[serde_as(as = "Timestamp")]
    #[serde(rename = "iat")]
    issue_time: DateTime<Utc>,
    #[serde(rename = "jti")]
    token_identifier: JsonWebTokenIdentifier,
    events: Value,
    #[serde(flatten)]
    target: LogoutTokenTarget,
    #[serde(
        rename = "nonce",
        default,
        skip_serializing,
        deserialize_with = "deserialize_nonce"
    )]
    /// Internal field to flag the presence of a nonce in JSON
    pub(crate) has_nonce: bool,
}

/// Set `has_nonce` when deserializing if a nonce field exists
fn deserialize_nonce<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: serde::Deserializer<'de>,
{
    serde::de::IgnoredAny::deserialize(deserializer)?;
    Ok(true)
}

impl LogoutTokenClaims {
    /// Fixed value used in the events claim
    pub const BACKCHANNEL_LOGOUT_EVENT: &str = "http://schemas.openid.net/event/backchannel-logout";

    /// Initializes new logout token claims.
    pub fn new(
        issuer: IssuerUrl,
        audiences: Vec<Audience>,
        expiration: DateTime<Utc>,
        issue_time: DateTime<Utc>,
        token_identifier: JsonWebTokenIdentifier,
        target: LogoutTokenTarget,
    ) -> Self {
        // The events claim must include this to be valid.
        let events = json!({Self::BACKCHANNEL_LOGOUT_EVENT: {}});

        Self {
            issuer,
            audiences,
            expiration,
            issue_time,
            token_identifier,
            target,
            events,
            has_nonce: false,
        }
    }

    field_getters_setters![
        pub self [self] ["claim"] {
            set_issuer -> issuer[IssuerUrl] ["iss"],
            set_audiences -> audiences[Vec<Audience>] ["aud"],
            set_expiration -> expiration[DateTime<Utc>] ["exp"],
            set_issue_time -> issue_time[DateTime<Utc>] ["iat"],
            set_token_identifier -> token_identifier[JsonWebTokenIdentifier] ["jti"],
        }
    ];

    /// Returns the `sub` claim.
    pub fn subject(&self) -> Option<&SubjectIdentifier> {
        match self.target {
            LogoutTokenTarget::Session { ref sub, .. } => sub.as_ref(),
            LogoutTokenTarget::Subject { ref sub } => Some(sub),
        }
    }

    /// Returns the `sid` claim.
    pub fn session_id(&self) -> Option<&SessionIdentifier> {
        if let LogoutTokenTarget::Session { ref sid, .. } = self.target {
            Some(sid)
        } else {
            None
        }
    }

    /// Gets the logout target (`sub` claim, `sid` claim, or both)
    pub fn target(&self) -> &LogoutTokenTarget {
        &self.target
    }

    /// Sets the logout target (`sub` claim, `sid` claim, or both)
    pub fn set_target(mut self, target: LogoutTokenTarget) -> Self {
        self.target = target;
        self
    }

    /// Gets the events claim
    pub fn events(&self) -> &Value {
        &self.events
    }
}

impl AudiencesClaim for LogoutTokenClaims {
    fn audiences(&self) -> Option<&Vec<Audience>> {
        Some(LogoutTokenClaims::audiences(self))
    }
}
impl AudiencesClaim for &LogoutTokenClaims {
    fn audiences(&self) -> Option<&Vec<Audience>> {
        Some(LogoutTokenClaims::audiences(self))
    }
}
impl IssuerClaim for LogoutTokenClaims {
    fn issuer(&self) -> Option<&IssuerUrl> {
        Some(LogoutTokenClaims::issuer(self))
    }
}
impl IssuerClaim for &LogoutTokenClaims {
    fn issuer(&self) -> Option<&IssuerUrl> {
        Some(LogoutTokenClaims::issuer(self))
    }
}
