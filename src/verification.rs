use std::collections::HashSet;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::ops::Deref;

use chrono::{DateTime, Utc};
use oauth2::helpers::variant_name;
use oauth2::prelude::*;
use oauth2::{ClientId, ClientSecret};
use serde::de::DeserializeOwned;
use serde::Serialize;

use super::jwt::JsonWebToken;
use super::user_info::UnverifiedUserInfoClaims;
use super::{
    AdditionalClaims, Audience, AuthenticationContextClass, GenderClaim, IdTokenClaims, IssuerUrl,
    JsonWebKey, JsonWebKeySet, JsonWebKeyType, JsonWebKeyUse, JsonWebTokenAccess,
    JsonWebTokenAlgorithm, JsonWebTokenHeader, JweContentEncryptionAlgorithm, JwsSigningAlgorithm,
    Nonce, StandardClaims, SubjectIdentifier, UserInfoClaims,
};

/*

Things to control in our validator:

All JWT validations (ID token and user info):
 - whether to disable the integrity check altogether
 - whether or not to consider a symmetric key (i.e., the client secret)
 - expected issuer ('iss')
 - the client_id that should be one of the 'aud'iences
 - whether to allow 'aud' to include other audiences. if so, which?
 - which 'alg' values to allow (RS256-only by default, unless others are specified during registration)

ID token validation only:
 - whether to validate the azp claim (which SHOULD be provided if there are multiple audiences), and
   which to expect. there's some confusion:
     https://bitbucket.org/openid/connect/issues/973/
     https://stackoverflow.com/questions/41231018/openid-connect-standard-authorized-party-azp-contradiction/41240814
 - maximum expiration time (default to current timestamp in UTC); this should be a closure

 - custom nonce validation function?
 - custom acr validation function
 - custom auth_time validation function

Possible factory methods to have:
 - public client
 - private client (w/ client secret)

*/

pub trait AudiencesClaim {
    fn audiences(&self) -> Option<&Vec<Audience>>;
}

pub trait IssuerClaim {
    fn issuer(&self) -> Option<&IssuerUrl>;
}

#[derive(Clone, Debug, Fail, PartialEq)]
pub enum ClaimsVerificationError {
    #[fail(display = "Expired: {}", _0)]
    Expired(String),
    #[fail(display = "Invalid audiences: {}", _0)]
    InvalidAudience(String),
    #[fail(
        display = "Invalid authorization context class reference: {}",
        _0
    )]
    InvalidAuthContext(String),
    #[fail(display = "Invalid authentication time: {}", _0)]
    InvalidAuthTime(String),
    #[fail(display = "Invalid issuer: {}", _0)]
    InvalidIssuer(String),
    #[fail(display = "Invalid nonce: {}", _0)]
    InvalidNonce(String),
    #[fail(display = "Invalid subject: {}", _0)]
    InvalidSubject(String),
    #[fail(display = "Claims must be signed")]
    NoSignature,
    #[fail(display = "{}", _0)]
    Other(String),
    #[fail(display = "Signature verification failed")]
    SignatureVerification(#[cause] SignatureVerificationError),
    #[fail(display = "Unsupported: {}", _0)]
    Unsupported(String),
}

#[derive(Clone, Debug, Fail, PartialEq)]
pub enum SignatureVerificationError {
    #[fail(display = "Ambiguous key identification: {}", _0)]
    AmbiguousKeyId(String),
    #[fail(display = "Crypto error: {}", _0)]
    CryptoError(String),
    #[fail(display = "Disallowed signature algorithm: {}", _0)]
    DisallowedAlg(String),
    #[fail(display = "Invalid cryptographic key: {}", _0)]
    InvalidKey(String),
    /// The signing key needed for verifying the
    /// [JSON Web Token](https://tools.ietf.org/html/rfc7519)'s signature/MAC could not be found.
    /// This error can occur if the key ID (`kid`) specified in the JWT's
    /// [JOSE header](https://tools.ietf.org/html/rfc7519#section-5) does not match the ID of any
    /// key in the OpenID Connect provider's JSON Web Key Set (JWKS), typically retrieved from
    /// the provider's [JWKS document](
    /// http://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata). To support
    /// [rotation of asyimmetric signing keys](
    /// http://openid.net/specs/openid-connect-core-1_0.html#RotateSigKeys), client applications
    /// should consider refreshing the JWKS document (via
    /// [`JsonWebKeySetUrl::get_keys`][`::discovery::JsonWebKeySetUrl::get_keys`]).
    ///
    /// This error can also occur if the identified
    /// [JSON Web Key](https://tools.ietf.org/html/rfc7517) is of the wrong type (e.g., an RSA key
    /// when the JOSE header specifies an ECDSA algorithm) or does not support signing.
    #[fail(display = "No matching key found")]
    NoMatchingKey,
    #[fail(display = "Unsupported signature algorithm: {}", _0)]
    UnsupportedAlg(String),
    #[fail(display = "Other error: {}", _0)]
    Other(String),
}

// This struct is intentionally private.
struct JwtClaimsVerifier<JS, JT, JU, K>
where
    JS: JwsSigningAlgorithm<JT>,
    JT: JsonWebKeyType,
    JU: JsonWebKeyUse,
    K: JsonWebKey<JS, JT, JU>,
{
    allowed_algs: Option<HashSet<JS>>,
    aud_required: bool,
    client_id: ClientId,
    client_secret: Option<ClientSecret>,
    iss_required: bool,
    issuer: IssuerUrl,
    is_signature_check_enabled: bool,
    signature_keys: JsonWebKeySet<JS, JT, JU, K>,
}
impl<JS, JT, JU, K> JwtClaimsVerifier<JS, JT, JU, K>
where
    JS: JwsSigningAlgorithm<JT>,
    JT: JsonWebKeyType,
    JU: JsonWebKeyUse,
    K: JsonWebKey<JS, JT, JU>,
{
    pub fn new(
        client_id: ClientId,
        issuer: IssuerUrl,
        signature_keys: JsonWebKeySet<JS, JT, JU, K>,
    ) -> Self {
        JwtClaimsVerifier {
            allowed_algs: Some([JS::rsa_sha_256()].iter().cloned().collect()),
            aud_required: true,
            client_id,
            client_secret: None,
            iss_required: true,
            issuer,
            is_signature_check_enabled: true,
            signature_keys,
        }
    }

    pub fn require_audience_match(mut self, aud_required: bool) -> Self {
        self.aud_required = aud_required;
        self
    }

    pub fn require_issuer_match(mut self, iss_required: bool) -> Self {
        self.iss_required = iss_required;
        self
    }

    pub fn require_signature_check(mut self, sig_required: bool) -> Self {
        self.is_signature_check_enabled = sig_required;
        self
    }

    pub fn set_allowed_algs<I>(mut self, algs: I) -> Self
    where
        I: IntoIterator<Item = JS>,
    {
        self.allowed_algs = Some(algs.into_iter().collect());
        self
    }
    pub fn allow_any_alg(mut self) -> Self {
        self.allowed_algs = None;
        self
    }

    pub fn set_client_secret(mut self, client_secret: ClientSecret) -> Self {
        self.client_secret = Some(client_secret);
        self
    }

    fn validate_jose_header<JE>(
        jose_header: &JsonWebTokenHeader<JE, JS, JT>,
    ) -> Result<(), ClaimsVerificationError>
    where
        JE: JweContentEncryptionAlgorithm,
    {
        // The 'typ' header field must either be omitted or have the canonicalized value JWT.
        if let Some(ref jwt_type) = jose_header.typ {
            if jwt_type.to_uppercase() != "JWT" {
                return Err(ClaimsVerificationError::Unsupported(format!(
                    "unexpected or unsupported JWT type `{}`",
                    **jwt_type
                )));
            }
        }
        // The 'cty' header field must be omitted, since it's only used for JWTs that contain
        // content types other than JSON-encoded claims. This may include nested JWTs, such as if
        // JWE encryption is used. This is currently unsupported.
        if let Some(ref content_type) = jose_header.cty {
            if content_type.to_uppercase() == "JWT" {
                return Err(ClaimsVerificationError::Unsupported(
                    "nested JWT's are not currently supported".to_string(),
                ));
            } else {
                return Err(ClaimsVerificationError::Unsupported(format!(
                    "unexpected or unsupported JWT content type `{}`",
                    **content_type
                )));
            }
        }

        // If 'crit' fields are specified, we must reject any we do not understand. Since this
        // implementation doesn't understand any of them, unconditionally reject the JWT. Note that
        // the spec prohibits this field from containing any of the standard headers or being empty.
        if let Some(_) = jose_header.crit {
            // FIXME: add a test case using this test vector:
            // https://tools.ietf.org/html/rfc7515#appendix-E
            return Err(ClaimsVerificationError::Unsupported(
                "critical JWT header fields are unsupported".to_string(),
            ));
        }
        Ok(())
    }

    pub fn verified_claims<A, C, JE, T>(&self, jwt: A) -> Result<T, ClaimsVerificationError>
    where
        A: JsonWebTokenAccess<C, JE, JS, JT, ReturnType = T>,
        C: AudiencesClaim + Debug + DeserializeOwned + IssuerClaim + Serialize,
        JE: JweContentEncryptionAlgorithm,
        T: AudiencesClaim + IssuerClaim,
    {
        {
            let jose_header = jwt.unverified_header();
            Self::validate_jose_header(jose_header)?;

            // The code below roughly follows the validation steps described in
            // https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation

            // 1. If the ID Token is encrypted, decrypt it using the keys and algorithms that the Client
            //    specified during Registration that the OP was to use to encrypt the ID Token. If
            //    encryption was negotiated with the OP at Registration time and the ID Token is not
            //    encrypted, the RP SHOULD reject it.

            if let JsonWebTokenAlgorithm::Encryption(ref encryption_alg) = jose_header.alg {
                return Err(ClaimsVerificationError::Unsupported(format!(
                    "JWE encryption is not currently supported (found algorithm `{}`)",
                    variant_name(encryption_alg),
                )));
            }
        }

        // TODO: Add encryption (JWE) support
        {
            // 2. The Issuer Identifier for the OpenID Provider (which is typically obtained during
            //    Discovery) MUST exactly match the value of the iss (issuer) Claim.
            let unverified_claims = jwt.unverified_claims_ref();
            if self.iss_required {
                if let Some(issuer) = unverified_claims.issuer() {
                    if *issuer != self.issuer {
                        return Err(ClaimsVerificationError::InvalidIssuer(format!(
                            "expected `{}` (found `{}`)",
                            *self.issuer, **issuer
                        )));
                    }
                } else {
                    return Err(ClaimsVerificationError::InvalidIssuer(
                        "missing issuer claim".to_string(),
                    ));
                }
            }

            // 3. The Client MUST validate that the aud (audience) Claim contains its client_id value
            //    registered at the Issuer identified by the iss (issuer) Claim as an audience. The aud
            //    (audience) Claim MAY contain an array with more than one element. The ID Token MUST be
            //    rejected if the ID Token does not list the Client as a valid audience, or if it
            //    contains additional audiences not trusted by the Client.
            if self.aud_required {
                if let Some(audiences) = unverified_claims.audiences() {
                    if audiences
                        .iter()
                        .find(|aud| (**aud).deref() == self.client_id.deref())
                        .is_none()
                    {
                        return Err(ClaimsVerificationError::InvalidAudience(format!(
                            "must contain `{}` (found audiences: {})",
                            *self.client_id,
                            audiences
                                .iter()
                                .map(|aud| format!("`{}`", Deref::deref(aud)))
                                .collect::<Vec<_>>()
                                .join(", ")
                        )));
                    }
                } else {
                    return Err(ClaimsVerificationError::InvalidAudience(
                        "missing audiences claim".to_string(),
                    ));
                }
            }
        }
        // Steps 4--5 (azp claim validation) are specific to the ID token.

        // 6. If the ID Token is received via direct communication between the Client and the Token
        //    Endpoint (which it is in this flow), the TLS server validation MAY be used to validate
        //    the issuer in place of checking the token signature. The Client MUST validate the
        //    signature of all other ID Tokens according to JWS [JWS] using the algorithm specified
        //    in the JWT alg Header Parameter. The Client MUST use the keys provided by the Issuer.
        if !self.is_signature_check_enabled {
            return Ok(jwt.unverified_claims());
        }

        // Borrow the header again. We had to drop the reference above to allow for the
        // early exit calling jwt.unverified_claims(), which takes ownership of the JWT.
        let signature_alg = match jwt.unverified_header().alg {
            // Encryption is handled above.
            JsonWebTokenAlgorithm::Encryption(_) => panic!("unreachable"),
            JsonWebTokenAlgorithm::Signature(ref signature_alg, _) => signature_alg,
            // Section 2 of OpenID Connect Core 1.0 specifies that "ID Tokens MUST NOT use
            // none as the alg value unless the Response Type used returns no ID Token from
            // the Authorization Endpoint (such as when using the Authorization Code Flow)
            // and the Client explicitly requested the use of none at Registration time."
            //
            // While there's technically a use case where this is ok, we choose not to
            // support it for now to protect against accidental misuse. If demand arises,
            // we can figure out a API that mitigates the risk.
            JsonWebTokenAlgorithm::None => return Err(ClaimsVerificationError::NoSignature),
        }.clone();

        // 7. The alg value SHOULD be the default of RS256 or the algorithm sent by the Client
        //    in the id_token_signed_response_alg parameter during Registration.
        if let Some(ref allowed_algs) = self.allowed_algs {
            if !allowed_algs.contains(&signature_alg) {
                return Err(ClaimsVerificationError::SignatureVerification(
                    SignatureVerificationError::DisallowedAlg(format!(
                        "algorithm `{}` is not one of: {}",
                        variant_name(&signature_alg),
                        allowed_algs
                            .iter()
                            .map(variant_name)
                            .collect::<Vec<_>>()
                            .join(", "),
                    )),
                ));
            }
        }

        // NB: We must *not* trust the 'kid' (key ID) or 'alg' (algorithm) fields present in the
        // JOSE header, as an attacker could manipulate these while forging the JWT. The code
        // below must be secure regardless of how these fields are manipulated.

        if signature_alg.is_symmetric() {
            // 8. If the JWT alg Header Parameter uses a MAC based algorithm such as HS256,
            //    HS384, or HS512, the octets of the UTF-8 representation of the client_secret
            //    corresponding to the client_id contained in the aud (audience) Claim are used
            //    as the key to validate the signature. For MAC based algorithms, the behavior
            //    is unspecified if the aud is multi-valued or if an azp value is present that
            //    is different than the aud value.
            if let Some(ref client_secret) = self.client_secret {
                let key = K::new_symmetric(client_secret.secret().clone().into_bytes());
                return jwt
                    .claims(&signature_alg.clone(), &key)
                    .map_err(ClaimsVerificationError::SignatureVerification);
            } else {
                // The client secret isn't confidential for public clients, so anyone can forge a
                // JWT with a valid signature.
                return Err(ClaimsVerificationError::SignatureVerification(
                    SignatureVerificationError::DisallowedAlg(
                        "symmetric signatures are disallowed for public clients".to_string(),
                    ),
                ));
            }
        }

        // Section 10.1 of OpenID Connect Core 1.0 states that the JWT must include a key ID
        // if the JWK set contains more than one public key.

        // See if any key has a matching key ID (if supplied) and compatible type.
        let key_type = signature_alg
            .key_type()
            .map_err(ClaimsVerificationError::Unsupported)?;
        let public_keys = {
            let jose_header = jwt.unverified_header();
            self.signature_keys
                .keys()
                .iter()
                .filter(|key|
                    // The key must be of the type expected for this signature algorithm.
                    *key.key_type() == key_type &&
                        // Either the key hasn't specified it's allowed usage (in which case
                        // any usage is acceptable), or the key supports signing.
                        (key.key_use().is_none() ||
                            key.key_use().iter().any(
                                |key_use| key_use.allows_signature()
                            )) &&
                        // Either the JWT doesn't include a 'kid' (in which case any 'kid'
                        // is acceptable), or the 'kid' matches the key's ID.
                        (jose_header.kid.is_none() ||
                            jose_header.kid.as_ref() == key.key_id())).collect::<Vec<&K>>()
        };
        if public_keys.is_empty() {
            return Err(ClaimsVerificationError::SignatureVerification(
                SignatureVerificationError::NoMatchingKey,
            ));
        } else if public_keys.len() != 1 {
            return Err(ClaimsVerificationError::SignatureVerification(
                SignatureVerificationError::AmbiguousKeyId(format!(
                    "JWK set must only contain one eligible public key \
                     ({} eligible keys: {})",
                    public_keys.len(),
                    public_keys
                        .iter()
                        .map(|key| format!(
                            "{} ({})",
                            key.key_id()
                                .map(|kid| format!("`{}`", **kid))
                                .unwrap_or_else(|| "null ID".to_string()),
                            variant_name(key.key_type())
                        )).collect::<Vec<_>>()
                        .join(", ")
                )),
            ));
        }

        jwt.claims(
            &signature_alg.clone(),
            *public_keys.first().expect("unreachable"),
        ).map_err(ClaimsVerificationError::SignatureVerification)

        // Steps 9--13 are specific to the ID token.
    }
}

pub struct IdTokenVerifier<JS, JT, JU, K>
where
    JS: JwsSigningAlgorithm<JT>,
    JT: JsonWebKeyType,
    JU: JsonWebKeyUse,
    K: JsonWebKey<JS, JT, JU>,
{
    acr_verifier_fn: Box<Fn(Option<&AuthenticationContextClass>) -> Result<(), String>>,
    auth_time_verifier_fn: Box<Fn(Option<&DateTime<Utc>>) -> Result<(), String>>,
    iat_verifier_fn: Box<Fn(&DateTime<Utc>) -> Result<(), String>>,
    jwt_verifier: JwtClaimsVerifier<JS, JT, JU, K>,
    time_fn: Box<Fn() -> DateTime<Utc>>,
}
impl<JS, JT, JU, K> IdTokenVerifier<JS, JT, JU, K>
where
    JS: JwsSigningAlgorithm<JT>,
    JT: JsonWebKeyType,
    JU: JsonWebKeyUse,
    K: JsonWebKey<JS, JT, JU>,
{
    fn new(jwt_verifier: JwtClaimsVerifier<JS, JT, JU, K>) -> Self {
        IdTokenVerifier {
            // By default, accept authorization context reference (acr claim).
            acr_verifier_fn: Box::new(|_| Ok(())),
            auth_time_verifier_fn: Box::new(|_| Ok(())),
            // By default, accept any issued time (iat claim).
            iat_verifier_fn: Box::new(|_| Ok(())),
            jwt_verifier,
            // By default, use the current system time.
            time_fn: Box::new(Utc::now),
        }
    }

    pub fn new_public_client(
        client_id: ClientId,
        issuer: IssuerUrl,
        signature_keys: JsonWebKeySet<JS, JT, JU, K>,
    ) -> Self {
        Self::new(JwtClaimsVerifier::new(client_id, issuer, signature_keys))
    }

    pub fn new_private_client(
        client_id: ClientId,
        client_secret: ClientSecret,
        issuer: IssuerUrl,
        signature_keys: JsonWebKeySet<JS, JT, JU, K>,
    ) -> Self {
        Self::new(
            JwtClaimsVerifier::new(client_id, issuer, signature_keys)
                .set_client_secret(client_secret),
        )
    }

    pub fn set_allowed_algs<I>(mut self, algs: I) -> Self
    where
        I: IntoIterator<Item = JS>,
    {
        self.jwt_verifier = self.jwt_verifier.set_allowed_algs(algs);
        self
    }
    pub fn allow_any_alg(mut self) -> Self {
        self.jwt_verifier = self.jwt_verifier.allow_any_alg();
        self
    }

    pub fn set_auth_context_verifier_fn(
        mut self,
        acr_verifier_fn: Box<Fn(Option<&AuthenticationContextClass>) -> Result<(), String>>,
    ) -> Self {
        self.acr_verifier_fn = acr_verifier_fn;
        self
    }

    pub fn set_auth_time_verifier_fn(
        mut self,
        auth_time_verifier_fn: Box<Fn(Option<&DateTime<Utc>>) -> Result<(), String>>,
    ) -> Self {
        self.auth_time_verifier_fn = auth_time_verifier_fn;
        self
    }

    pub fn enable_signature_check(mut self) -> Self {
        self.jwt_verifier = self.jwt_verifier.require_signature_check(true);
        self
    }
    pub fn insecure_disable_signature_check(mut self) -> Self {
        self.jwt_verifier = self.jwt_verifier.require_signature_check(false);
        self
    }

    pub fn set_time_fn(mut self, time_fn: Box<Fn() -> DateTime<Utc>>) -> Self {
        self.time_fn = time_fn;
        self
    }

    pub fn set_issue_time_verifier_fn(
        mut self,
        iat_verifier_fn: Box<Fn(&DateTime<Utc>) -> Result<(), String>>,
    ) -> Self {
        self.iat_verifier_fn = iat_verifier_fn;
        self
    }

    // TODO: Add a version that accepts a nonce validation function. Some client applications may
    // use crypto or some other mechanism to validate nonces instead of storing every nonce.
    pub(super) fn verified_claims<'b, AC, GC, JE>(
        &self,
        jwt: &'b JsonWebToken<IdTokenClaims<AC, GC>, JE, JS, JT>,
        nonce: Option<&Nonce>,
    ) -> Result<&'b IdTokenClaims<AC, GC>, ClaimsVerificationError>
    where
        AC: AdditionalClaims,
        GC: GenderClaim,
        JE: JweContentEncryptionAlgorithm,
    {
        // The code below roughly follows the validation steps described in
        // https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation

        // Steps 1--3 are handled by the generic JwtClaimsVerifier.
        let partially_verified_claims = self.jwt_verifier.verified_claims(jwt)?;

        // 4. If the ID Token contains multiple audiences, the Client SHOULD verify that an azp
        //    Claim is present.

        // FIXME(docs): add a reference in the module documentation describing this intentional
        // deviation from the spec.

        // There is significant confusion and contradiction in the OpenID Connect Core spec around
        // the azp claim. See https://bitbucket.org/openid/connect/issues/973/ for a detailed
        // discussion. Given the lack of clarity around how this claim should be used, we defer
        // any verification of it here until a use case becomes apparent. If such a use case does
        // arise, we most likely want to allow clients to pass in a function for validating the
        // azp claim rather than introducing logic that affects all clients of this library.

        // This naive implementation of the spec would almost certainly not be useful in practice:
        /*
        let azp_required = partially_verified_claims.audiences().len() > 1;

        // 5. If an azp (authorized party) Claim is present, the Client SHOULD verify that its
        //    client_id is the Claim Value.
        if let Some(authorized_party) = partially_verified_claims.authorized_party() {
            if *authorized_party != self.client_id {
                return Err(ClaimsVerificationError::InvalidAudience(format!(
                    "authorized party must match client ID `{}` (found `{}`",
                    *self.client_id, **authorized_party
                )));
            }
        } else if azp_required {
            return Err(ClaimsVerificationError::InvalidAudience(format!(
                "missing authorized party claim but multiple audiences found"
            )));
        }
        */

        // Steps 6--8 are handled by the generic JwtClaimsVerifier.

        // 9. The current time MUST be before the time represented by the exp Claim.
        let cur_time = (*self.time_fn)();
        if let Ok(expiration) = partially_verified_claims.expiration() {
            if cur_time > expiration {
                return Err(ClaimsVerificationError::Expired(format!(
                    "ID token expired at {} (current time is {})",
                    expiration, cur_time
                )));
            }
        } else {
            return Err(ClaimsVerificationError::Other(
                "expiration out of bounds".to_string(),
            ));
        }

        // 10. The iat Claim can be used to reject tokens that were issued too far away from the
        //     current time, limiting the amount of time that nonces need to be stored to prevent
        //     attacks. The acceptable range is Client specific.
        if let Ok(ref issue_time) = partially_verified_claims.issue_time() {
            (*self.iat_verifier_fn)(issue_time).map_err(ClaimsVerificationError::Expired)?;
        } else {
            return Err(ClaimsVerificationError::Other(
                "issue time out of bounds".to_string(),
            ));
        }

        // 11. If a nonce value was sent in the Authentication Request, a nonce Claim MUST be
        //     present and its value checked to verify that it is the same value as the one that was
        //     sent in the Authentication Request. The Client SHOULD check the nonce value for
        //     replay attacks. The precise method for detecting replay attacks is Client specific.
        if let Some(expected_nonce) = nonce {
            if let Some(claims_nonce) = partially_verified_claims.nonce() {
                if claims_nonce != expected_nonce {
                    return Err(ClaimsVerificationError::InvalidNonce(
                        "nonce mismatch".to_string(),
                    ));
                }
            } else {
                return Err(ClaimsVerificationError::InvalidNonce(
                    "missing nonce claim".to_string(),
                ));
            }
        }

        // 12. If the acr Claim was requested, the Client SHOULD check that the asserted Claim Value
        //     is appropriate. The meaning and processing of acr Claim Values is out of scope for
        //     this specification.
        (*self.acr_verifier_fn)(partially_verified_claims.auth_context_ref())
            .map_err(ClaimsVerificationError::InvalidAuthContext)?;

        // 13. If the auth_time Claim was requested, either through a specific request for this
        //     Claim or by using the max_age parameter, the Client SHOULD check the auth_time Claim
        //     value and request re-authentication if it determines too much time has elapsed since
        //     the last End-User authentication.
        match partially_verified_claims.auth_time() {
            Some(ref auth_time_result) => auth_time_result
                .map(|auth_time| (*self.auth_time_verifier_fn)(Some(&auth_time)))
                .map_err(|_| ClaimsVerificationError::Other("auth time out of bounds".to_string()))?
                .map_err(ClaimsVerificationError::InvalidAuthTime)?,
            None => (*self.auth_time_verifier_fn)(None)
                .map_err(ClaimsVerificationError::InvalidAuthTime)?,
        };

        Ok(partially_verified_claims)
    }
}

pub struct UserInfoVerifier<JE, JS, JT, JU, K>
where
    JE: JweContentEncryptionAlgorithm,
    JS: JwsSigningAlgorithm<JT>,
    JT: JsonWebKeyType,
    JU: JsonWebKeyUse,
    K: JsonWebKey<JS, JT, JU>,
{
    jwt_required: bool,
    jwt_verifier: JwtClaimsVerifier<JS, JT, JU, K>,
    sub: SubjectIdentifier,
    _phantom: PhantomData<JE>,
}
impl<JE, JS, JT, JU, K> UserInfoVerifier<JE, JS, JT, JU, K>
where
    JE: JweContentEncryptionAlgorithm,
    JS: JwsSigningAlgorithm<JT>,
    JT: JsonWebKeyType,
    JU: JsonWebKeyUse,
    K: JsonWebKey<JS, JT, JU>,
{
    pub fn new(
        client_id: ClientId,
        issuer: IssuerUrl,
        signature_keys: JsonWebKeySet<JS, JT, JU, K>,
        sub: SubjectIdentifier,
    ) -> Self {
        UserInfoVerifier {
            jwt_required: false,
            jwt_verifier: JwtClaimsVerifier::new(client_id, issuer, signature_keys),
            sub,
            _phantom: PhantomData,
        }
    }

    pub fn require_signed_response(mut self, jwt_required: bool) -> Self {
        self.jwt_required = jwt_required;
        self
    }

    pub fn require_issuer_match(mut self, iss_required: bool) -> Self {
        self.jwt_verifier = self.jwt_verifier.require_issuer_match(iss_required);
        self
    }

    pub fn require_audience_match(mut self, aud_required: bool) -> Self {
        self.jwt_verifier = self.jwt_verifier.require_audience_match(aud_required);
        self
    }

    pub(super) fn verified_claims<AC, GC>(
        &self,
        unverified_user_info: UnverifiedUserInfoClaims<AC, GC, JE, JS, JT>,
    ) -> Result<UserInfoClaims<AC, GC>, ClaimsVerificationError>
    where
        AC: AdditionalClaims,
        GC: GenderClaim,
    {
        let user_info = match unverified_user_info {
            UnverifiedUserInfoClaims::JsonClaims(user_info) => {
                if self.jwt_required {
                    return Err(ClaimsVerificationError::NoSignature);
                }
                user_info
            }
            UnverifiedUserInfoClaims::JwtClaims(user_info_jwt) => {
                trace!("here: {:?}", user_info_jwt);
                self.jwt_verifier.verified_claims(user_info_jwt)?
            }
        };

        if *user_info.sub() != self.sub {
            return Err(ClaimsVerificationError::InvalidSubject(format!(
                "expected `{}` (found `{}`)",
                *self.sub,
                **user_info.sub()
            )));
        }

        Ok(user_info)
    }
}
