
use std::collections::HashSet;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::ops::Deref;

use oauth2::{
    ClientId,
    ClientSecret,
};
use oauth2::helpers::variant_name;
use oauth2::prelude::*;
use serde::Serialize;
use serde::de::DeserializeOwned;

use super::{
    AdditionalClaims,
    Audience,
    GenderClaim,
    IdTokenClaims,
    IssuerUrl,
    JsonWebKey,
    JsonWebKeySet,
    JsonWebKeyType,
    JsonWebKeyUse,
    JsonWebTokenAccess,
    JsonWebTokenAlgorithm,
    JsonWebTokenHeader,
    JweContentEncryptionAlgorithm,
    JwsSigningAlgorithm,
    Nonce,
    StandardClaims,
    SubjectIdentifier,
    UserInfoClaims,
};
use super::jwt::JsonWebToken;
use super::user_info::UnverifiedUserInfoClaims;

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
 - earliest acceptable 'iat' (issue time); this should be a closure
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
    #[fail(display = "Invalid audiences: {}", _0)]
    InvalidAudience(String),
    // FIXME: do we need this one?
    #[fail(display = "Invalid token header: {}", _0)]
    InvalidHeader(String),
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
    #[fail(display = "No matching key found")]
    NoMatchingKey,
    #[fail(display = "Unsupported signature algorithm: {}", _0)]
    UnsupportedAlg(String),
    #[fail(display = "Other error: {}", _0)]
    Other(String),
}

// This struct is intentionally private.
struct JwtClaimsVerifier<'a, JS, JT, JU, K>
    where JS: 'a + JwsSigningAlgorithm<JT>,
          JT: 'a + JsonWebKeyType,
          JU: 'a + JsonWebKeyUse,
          K: 'a + JsonWebKey<JS, JT, JU> {
    allowed_algs: Option<HashSet<JS>>,
    aud_required: bool,
    client_id: &'a ClientId,
    client_secret: Option<&'a ClientSecret>,
    iss_required: bool,
    issuer: &'a IssuerUrl,
    is_signature_check_enabled: bool,
    signature_keys: &'a JsonWebKeySet<JS, JT, JU, K>,
}
impl<'a, JS, JT, JU, K> JwtClaimsVerifier<'a, JS, JT, JU, K>
    where JS: 'a + JwsSigningAlgorithm<JT>,
          JT: 'a + JsonWebKeyType,
          JU: 'a + JsonWebKeyUse,
          K: 'a + JsonWebKey<JS, JT, JU> {
    pub fn new(
        client_id: &'a ClientId,
        issuer: &'a IssuerUrl,
        signature_keys: &'a JsonWebKeySet<JS, JT, JU, K>
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
        where I: IntoIterator<Item = JS> {
        self.allowed_algs = Some(algs.into_iter().collect());
        self
    }
    pub fn allow_any_alg(mut self) -> Self {
        self.allowed_algs = None;
        self
    }

    pub fn set_client_secret(mut self, client_secret: &'a ClientSecret) -> Self {
        self.client_secret = Some(client_secret);
        self
    }

    fn validate_jose_header<JE>(
        jose_header: &JsonWebTokenHeader<JE, JS, JT>
    ) -> Result<(), ClaimsVerificationError>
        where JE: JweContentEncryptionAlgorithm {
        // The 'typ' header field must either be omitted or have the canonicalized value JWT.
        if let Some(ref jwt_type) = jose_header.typ {
            if jwt_type.to_uppercase() != "JWT" {
                return Err(
                    ClaimsVerificationError::Unsupported(
                        format!("unexpected or unsupported JWT type `{}`", **jwt_type)
                    )
                )
            }
        }
        // The 'cty' header field must be omitted, since it's only used for JWTs that contain
        // content types other than JSON-encoded claims. This may include nested JWTs, such as if
        // JWE encryption is used. This is currently unsupported.
        if let Some(ref content_type) = jose_header.cty {
            if content_type.to_uppercase() == "JWT" {
                return Err(
                    ClaimsVerificationError::Unsupported(
                        "nested JWT's are not currently supported".to_string()
                    )
                )
            } else {
                return Err(
                    ClaimsVerificationError::Unsupported(
                        format!("unexpected or unsupported JWT content type `{}`", **content_type)
                    )
                )
            }
        }

        // If 'crit' fields are specified, we must reject any we do not understand. Since this
        // implementation doesn't understand any of them, unconditionally reject the JWT. Note that
        // the spec prohibits this field from containing any of the standard headers or being empty.
        if let Some(_) = jose_header.crit {
            return Err(
                ClaimsVerificationError::Unsupported(
                    "critical JWT header fields are unsupported".to_string()
                )
            )
        }
        Ok(())
    }

    pub fn verified_claims<A, C, JE, T>(
        &self,
        jwt: A
    ) -> Result<T, ClaimsVerificationError>
        where A: JsonWebTokenAccess<C, JE, JS, JT, ReturnType = T>,
              C: AudiencesClaim + Debug + DeserializeOwned + IssuerClaim + Serialize,
              JE: JweContentEncryptionAlgorithm,
              T: AudiencesClaim + IssuerClaim {
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
                return Err(
                    ClaimsVerificationError::Unsupported(
                        format!(
                            "JWE encryption is not currently supported (found algorithm `{}`)",
                            variant_name(encryption_alg),
                        )
                    )
                );
            }
        }

        // TODO: Add encryption (JWE) support
        {
            // 2. The Issuer Identifier for the OpenID Provider (which is typically obtained during
            //    Discovery) MUST exactly match the value of the iss (issuer) Claim.
            let unverified_claims = jwt.unverified_claims_ref();
            if self.iss_required {
                if let Some(issuer) = unverified_claims.issuer() {
                    if issuer != self.issuer {
                        return Err(
                            ClaimsVerificationError::InvalidIssuer(
                                format!("expected `{}` (found `{}`)", **self.issuer, **issuer)
                            )
                        );
                    }
                } else {
                    return Err(
                        ClaimsVerificationError::InvalidIssuer("missing issuer claim".to_string())
                    );
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
                        .find(|aud| (**aud).deref() == self.client_id.deref()).is_none() {
                        return Err(
                            ClaimsVerificationError::InvalidAudience(
                                format!(
                                    "must contain `{}` (found audiences: {})",
                                    **self.client_id,
                                    audiences
                                        .iter()
                                        .map(|aud| format!("`{}`", Deref::deref(aud)))
                                        .collect::<Vec<_>>()
                                        .join(", ")
                                )
                            )
                        );
                    }
                } else {
                    return Err(
                        ClaimsVerificationError::InvalidAudience(
                            "missing audiences claim".to_string()
                        )
                    );
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
        let signature_alg =
            match jwt.unverified_header().alg {
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
                JsonWebTokenAlgorithm::None => {
                    return Err(ClaimsVerificationError::NoSignature)
                }
            }.clone();

        // 7. The alg value SHOULD be the default of RS256 or the algorithm sent by the Client
        //    in the id_token_signed_response_alg parameter during Registration.
        if let Some(ref allowed_algs) = self.allowed_algs {
            if !allowed_algs.contains(&signature_alg) {
                return Err(
                    ClaimsVerificationError::SignatureVerification(
                        SignatureVerificationError::DisallowedAlg(
                            format!(
                                "algorithm `{}` is not one of: {}",
                                variant_name(&signature_alg),
                                allowed_algs
                                    .iter()
                                    .map(variant_name)
                                    .collect::<Vec<_>>()
                                    .join(", "),
                            )
                        )
                    )
                );
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
            if let Some(client_secret) = self.client_secret {
                let key = K::new_symmetric(client_secret.secret().clone().into_bytes());
                return jwt.claims(&signature_alg.clone(), &key)
                    .map_err(ClaimsVerificationError::SignatureVerification);
            } else {
                // The client secret isn't confidential for public clients, so anyone can forge a
                // JWT with a valid signature.
                return Err(
                    ClaimsVerificationError::SignatureVerification(
                        SignatureVerificationError::DisallowedAlg(
                            "symmetric signatures are disallowed for public clients".to_string()
                        )
                    )
                )
            }
        }

        // Section 10.1 of OpenID Connect Core 1.0 states that the JWT must include a key ID
        // if the JWK set contains more than one public key.

        // See if any key has a matching key ID (if supplied) and compatible type.
        let key_type = signature_alg.key_type().map_err(ClaimsVerificationError::Unsupported)?;
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
                            jose_header.kid.as_ref() == key.key_id())
                )
                .collect::<Vec<&K>>()
        };
        if public_keys.is_empty() {
            // FIXME: if there's a KID but no matching key, try re-fetching the
            // JWKS to support KeyRotation
            return Err(
                ClaimsVerificationError::SignatureVerification(
                    SignatureVerificationError::NoMatchingKey
                )
            )
        } else if public_keys.len() != 1 {
            return Err(
                ClaimsVerificationError::SignatureVerification(
                    SignatureVerificationError::AmbiguousKeyId(
                        format!(
                            "JWK set must only contain one eligible public key \
                            ({} eligible keys: {})",
                            public_keys.len(),
                            public_keys
                                .iter()
                                .map(|key|
                                    format!(
                                        "{} ({})",
                                        key.key_id()
                                            .map(|kid| format!("`{}`", **kid))
                                            .unwrap_or_else(|| "null ID".to_string()),
                                        variant_name(key.key_type())
                                    )
                                )
                                .collect::<Vec<_>>()
                                .join(", ")
                        )
                    )
                )
            )
        }

        jwt.claims(&signature_alg.clone(), *public_keys.first().expect("unreachable"))
            .map_err(ClaimsVerificationError::SignatureVerification)

        // Steps 9--13 are specific to the ID token.
    }
}

pub struct IdTokenVerifier<'a, JS, JT, JU, K>
    where JS: 'a + JwsSigningAlgorithm<JT>,
          JT: 'a + JsonWebKeyType,
          JU: 'a + JsonWebKeyUse,
          K: 'a + JsonWebKey<JS, JT, JU> {
    jwt_verifier: JwtClaimsVerifier<'a, JS, JT, JU, K>
}
impl<'a, JS, JT, JU, K> IdTokenVerifier<'a, JS, JT, JU, K>
    where JS: 'a + JwsSigningAlgorithm<JT>,
          JT: 'a + JsonWebKeyType,
          JU: 'a + JsonWebKeyUse,
          K: 'a + JsonWebKey<JS, JT, JU> {
    pub fn new_public_client(
        client_id: &'a ClientId,
        issuer: &'a IssuerUrl,
        signature_keys: &'a JsonWebKeySet<JS, JT, JU, K>
    ) -> Self {
        IdTokenVerifier {
            jwt_verifier: JwtClaimsVerifier::new(client_id, issuer, signature_keys),
        }
    }

    pub fn new_private_client(
        client_id: &'a ClientId,
        client_secret: &'a ClientSecret,
        issuer: &'a IssuerUrl,
        signature_keys: &'a JsonWebKeySet<JS, JT, JU, K>,
    ) -> Self {
        IdTokenVerifier {
            jwt_verifier: JwtClaimsVerifier::new(client_id, issuer, signature_keys)
                .set_client_secret(client_secret),
        }
    }

    pub fn set_allowed_algs<I>(mut self, algs: I) -> Self
        where I: IntoIterator<Item = JS> {
        self.jwt_verifier = self.jwt_verifier.set_allowed_algs(algs);
        self
    }
    pub fn allow_any_alg(mut self) -> Self {
        self.jwt_verifier = self.jwt_verifier.allow_any_alg();
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

    pub(super) fn verified_claims<'b, AC, GC, JE>(
        &self,
        jwt: &'b JsonWebToken<IdTokenClaims<AC, GC>, JE, JS, JT>,
        nonce: Option<&Nonce>,
    ) -> Result<&'b IdTokenClaims<AC, GC>, ClaimsVerificationError>
        where AC: AdditionalClaims,
              GC: GenderClaim,
              JE: JweContentEncryptionAlgorithm {
        // The code below roughly follows the validation steps described in
        // https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation

        // Steps 1--3 are handled by the generic JwtClaimsVerifier.
        let partially_verified_claims = self.jwt_verifier.verified_claims(jwt)?;

        // 4. If the ID Token contains multiple audiences, the Client SHOULD verify that an azp
        //    Claim is present.

        // 5. If an azp (authorized party) Claim is present, the Client SHOULD verify that its
        //    client_id is the Claim Value.

        // Steps 6--8 are handled by the generic JwtClaimsVerifier.

        // 9. The current time MUST be before the time represented by the exp Claim.

        // 10. The iat Claim can be used to reject tokens that were issued too far away from the
        //     current time, limiting the amount of time that nonces need to be stored to prevent
        //     attacks. The acceptable range is Client specific.

        // 11. If a nonce value was sent in the Authentication Request, a nonce Claim MUST be
        //     present and its value checked to verify that it is the same value as the one that was
        //     sent in the Authentication Request. The Client SHOULD check the nonce value for
        //     replay attacks. The precise method for detecting replay attacks is Client specific.
        if let Some(expected_nonce) = nonce {
            if let Some(claims_nonce) = partially_verified_claims.nonce() {
                if claims_nonce != expected_nonce {
                    return Err(
                        ClaimsVerificationError::InvalidNonce("nonce mismatch".to_string())
                    )
                }
            } else {
                return Err(
                    ClaimsVerificationError::InvalidNonce("missing nonce claim".to_string())
                )
            }
        }

        // 12. If the acr Claim was requested, the Client SHOULD check that the asserted Claim Value
        //     is appropriate. The meaning and processing of acr Claim Values is out of scope for
        //     this specification.

        // 13. If the auth_time Claim was requested, either through a specific request for this
        //     Claim or by using the max_age parameter, the Client SHOULD check the auth_time Claim
        //     value and request re-authentication if it determines too much time has elapsed since
        //     the last End-User authentication.

        // FIXME: implement validation above
        Ok(partially_verified_claims)
    }
}

pub struct UserInfoVerifier<'a, JE, JS, JT, JU, K>
    where JE: 'a + JweContentEncryptionAlgorithm,
          JS: 'a + JwsSigningAlgorithm<JT>,
          JT: 'a + JsonWebKeyType,
          JU: 'a + JsonWebKeyUse,
          K: 'a + JsonWebKey<JS, JT, JU> {
    jwt_required: bool,
    jwt_verifier: JwtClaimsVerifier<'a, JS, JT, JU, K>,
    sub: &'a SubjectIdentifier,
    _phantom: PhantomData<JE>,
}
impl<'a, JE, JS, JT, JU, K> UserInfoVerifier<'a, JE, JS, JT, JU, K>
    where JE: 'a + JweContentEncryptionAlgorithm,
          JS: 'a + JwsSigningAlgorithm<JT>,
          JT: 'a + JsonWebKeyType,
          JU: 'a + JsonWebKeyUse,
          K: 'a + JsonWebKey<JS, JT, JU> {
    pub fn new(
        client_id: &'a ClientId,
        issuer: &'a IssuerUrl,
        signature_keys: &'a JsonWebKeySet<JS, JT, JU, K>,
        sub: &'a SubjectIdentifier,
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
        where AC: AdditionalClaims, GC: GenderClaim {
        let user_info =
            match unverified_user_info {
                UnverifiedUserInfoClaims::JsonClaims(user_info) => {
                    if self.jwt_required {
                        return Err(ClaimsVerificationError::NoSignature);
                    }
                    user_info
                },
                UnverifiedUserInfoClaims::JwtClaims(user_info_jwt) => {
                    trace!("here: {:?}", user_info_jwt);
                    self.jwt_verifier.verified_claims(user_info_jwt)?
                }
            };

        if user_info.sub() != self.sub {
            return Err(
                ClaimsVerificationError::InvalidSubject(
                    format!("expected `{}` (found `{}`)", **self.sub, **user_info.sub())
                )
            );
        }

        Ok(user_info)
    }
}
