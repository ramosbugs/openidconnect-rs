use std::collections::HashMap;
use std::marker::PhantomData;

use chrono::{DateTime, Utc};
use oauth2::ClientId;

use super::claims::StandardClaimsImpl;
use super::jwt::JsonWebTokenJsonPayloadDeserializer;
use super::types::helpers::{deserialize_string_or_vec, seconds_to_utc};
use super::types::Seconds;
use super::{
    AccessTokenHash, AdditionalClaims, AddressClaim, Audience, AudiencesClaim,
    AuthenticationContextClass, AuthenticationMethodReference, AuthorizationCodeHash,
    ClaimsVerificationError, EndUserBirthday, EndUserEmail, EndUserFamilyName, EndUserGivenName,
    EndUserMiddleName, EndUserName, EndUserNickname, EndUserPhoneNumber, EndUserPictureUrl,
    EndUserProfileUrl, EndUserTimezone, EndUserUsername, EndUserWebsiteUrl, ExtraTokenFields,
    GenderClaim, IdTokenVerifier, IssuerClaim, IssuerUrl, JsonWebKey, JsonWebKeyType,
    JsonWebKeyUse, JsonWebToken, JweContentEncryptionAlgorithm, JwsSigningAlgorithm, LanguageTag,
    Nonce, NonceVerifier, StandardClaims, SubjectIdentifier,
};

// This wrapper layer exists instead of directly verifying the JWT and returning the claims so that
// we can pass it around and easily access a serialized JWT representation of it (e.g., for passing
// to the authorization endpoint as an id_token_hint).
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct IdToken<
    AC: AdditionalClaims,
    GC: GenderClaim,
    JE: JweContentEncryptionAlgorithm,
    JS: JwsSigningAlgorithm<JT>,
    JT: JsonWebKeyType,
>(
    #[serde(bound = "AC: AdditionalClaims")]
    JsonWebToken<IdTokenClaims<AC, GC>, JE, JS, JT, JsonWebTokenJsonPayloadDeserializer>,
);
impl<AC, GC, JE, JS, JT> IdToken<AC, GC, JE, JS, JT>
where
    AC: AdditionalClaims,
    GC: GenderClaim,
    JE: JweContentEncryptionAlgorithm,
    JS: JwsSigningAlgorithm<JT>,
    JT: JsonWebKeyType,
{
    pub fn claims<'a, 'b, JU, K, N>(
        &'a self,
        verifier: &'b IdTokenVerifier<JS, JT, JU, K>,
        nonce_verifier: N,
    ) -> Result<&'a IdTokenClaims<AC, GC>, ClaimsVerificationError>
    where
        JU: JsonWebKeyUse,
        K: JsonWebKey<JS, JT, JU>,
        N: NonceVerifier<'a>,
    {
        verifier.verified_claims(&self.0, nonce_verifier)
    }
}

// FIXME: document at the module level that we do not support aggregated or distributed claims,
// which are OPTIONAL in the spec:
// http://openid.net/specs/openid-connect-core-1_0.html#AggregatedDistributedClaims
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct IdTokenClaims<AC, GC>
where
    AC: AdditionalClaims,
    GC: GenderClaim,
{
    iss: IssuerUrl,
    // We always serialize as an array, which is valid according to the spec.
    #[serde(deserialize_with = "deserialize_string_or_vec")]
    aud: Vec<Audience>,
    exp: Seconds,
    iat: Seconds,
    #[serde(skip_serializing_if = "Option::is_none")]
    auth_time: Option<Seconds>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<Nonce>,
    #[serde(skip_serializing_if = "Option::is_none")]
    acr: Option<AuthenticationContextClass>,
    #[serde(skip_serializing_if = "Option::is_none")]
    amr: Option<Vec<AuthenticationMethodReference>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    azp: Option<ClientId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    at_hash: Option<AccessTokenHash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    c_hash: Option<AuthorizationCodeHash>,

    #[serde(bound = "GC: GenderClaim")]
    #[serde(flatten)]
    standard_claims: StandardClaimsImpl<GC>,

    #[serde(bound = "AC: AdditionalClaims")]
    #[serde(flatten)]
    additional_claims: AC,
}
// FIXME: see what other structs should have friendlier trait interfaces like this one
impl<AC, GC> IdTokenClaims<AC, GC>
where
    AC: AdditionalClaims,
    GC: GenderClaim,
{
    pub fn issuer(&self) -> &IssuerUrl {
        &self.iss
    }
    pub fn audiences(&self) -> &Vec<Audience> {
        &self.aud
    }
    pub fn expiration(&self) -> Result<DateTime<Utc>, ()> {
        seconds_to_utc(&self.exp)
    }
    pub fn issue_time(&self) -> Result<DateTime<Utc>, ()> {
        seconds_to_utc(&self.iat)
    }
    pub fn auth_time(&self) -> Option<Result<DateTime<Utc>, ()>> {
        self.auth_time.as_ref().map(seconds_to_utc)
    }
    pub fn nonce(&self) -> Option<&Nonce> {
        self.nonce.as_ref()
    }
    pub fn auth_context_ref(&self) -> Option<&AuthenticationContextClass> {
        self.acr.as_ref()
    }
    pub fn auth_methods_refs(&self) -> Option<&Vec<AuthenticationMethodReference>> {
        self.amr.as_ref()
    }
    pub fn authorized_party(&self) -> Option<&ClientId> {
        self.azp.as_ref()
    }
    pub fn access_token_hash(&self) -> Option<&AccessTokenHash> {
        self.at_hash.as_ref()
    }
    pub fn code_hash(&self) -> Option<&AuthorizationCodeHash> {
        self.c_hash.as_ref()
    }

    pub fn additional_claims(&self) -> &AC {
        &self.additional_claims
    }
}
impl<AC, GC> StandardClaims<GC> for IdTokenClaims<AC, GC>
where
    AC: AdditionalClaims,
    GC: GenderClaim,
{
    field_getters![
        self [self.standard_claims] {
            sub[&SubjectIdentifier],
            name[Option<&HashMap<Option<LanguageTag>, EndUserName>>],
            given_name[Option<&HashMap<Option<LanguageTag>, EndUserGivenName>>],
            family_name[Option<&HashMap<Option<LanguageTag>, EndUserFamilyName>>],
            middle_name[Option<&HashMap<Option<LanguageTag>, EndUserMiddleName>>],
            nickname[Option<&HashMap<Option<LanguageTag>, EndUserNickname>>],
            preferred_username[Option<&EndUserUsername>],
            profile[Option<&HashMap<Option<LanguageTag>, EndUserProfileUrl>>],
            picture[Option<&HashMap<Option<LanguageTag>, EndUserPictureUrl>>],
            website[Option<&HashMap<Option<LanguageTag>, EndUserWebsiteUrl>>],
            email[Option<&EndUserEmail>],
            email_verified[Option<bool>],
            gender[Option<&GC>],
            birthday[Option<&EndUserBirthday>],
            zoneinfo[Option<&EndUserTimezone>],
            locale[Option<&LanguageTag>],
            phone_number[Option<&EndUserPhoneNumber>],
            phone_number_verified[Option<bool>],
            address[Option<&AddressClaim>],
            updated_at[Option<Result<DateTime<Utc>, ()>> {
                self.standard_claims.updated_at.as_ref().map(seconds_to_utc)
            }],
        }
    ];
}
impl<AC, GC> AudiencesClaim for IdTokenClaims<AC, GC>
where
    AC: AdditionalClaims,
    GC: GenderClaim,
{
    fn audiences(&self) -> Option<&Vec<Audience>> {
        Some(IdTokenClaims::audiences(self))
    }
}
impl<'a, AC, GC> AudiencesClaim for &'a IdTokenClaims<AC, GC>
where
    AC: AdditionalClaims,
    GC: GenderClaim,
{
    fn audiences(&self) -> Option<&Vec<Audience>> {
        Some(IdTokenClaims::audiences(self))
    }
}
impl<AC, GC> IssuerClaim for IdTokenClaims<AC, GC>
where
    AC: AdditionalClaims,
    GC: GenderClaim,
{
    fn issuer(&self) -> Option<&IssuerUrl> {
        Some(IdTokenClaims::issuer(self))
    }
}
impl<'a, AC, GC> IssuerClaim for &'a IdTokenClaims<AC, GC>
where
    AC: AdditionalClaims,
    GC: GenderClaim,
{
    fn issuer(&self) -> Option<&IssuerUrl> {
        Some(IdTokenClaims::issuer(self))
    }
}

///
/// OpenID Connect authorization token.
///
/// The fields in this struct are defined in
/// [Section 3.1.3.3](http://openid.net/specs/openid-connect-core-1_0.html#TokenResponse).
///
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct IdTokenFields<AC, GC, JE, JS, JT>
where
    AC: AdditionalClaims,
    GC: GenderClaim,
    JE: JweContentEncryptionAlgorithm,
    JS: JwsSigningAlgorithm<JT>,
    JT: JsonWebKeyType,
{
    #[serde(bound = "AC: AdditionalClaims")]
    id_token: IdToken<AC, GC, JE, JS, JT>,
    #[serde(skip)]
    _phantom_jt: PhantomData<JT>,
}
impl<AC, GC, JE, JS, JT> IdTokenFields<AC, GC, JE, JS, JT>
where
    AC: AdditionalClaims,
    GC: GenderClaim,
    JE: JweContentEncryptionAlgorithm,
    JS: JwsSigningAlgorithm<JT>,
    JT: JsonWebKeyType,
{
    pub fn id_token(&self) -> &IdToken<AC, GC, JE, JS, JT> {
        &self.id_token
    }
    // FIXME: add extra_fields here to enable further extensibility by clients
}
impl<AC, GC, JE, JS, JT> ExtraTokenFields for IdTokenFields<AC, GC, JE, JS, JT>
where
    AC: AdditionalClaims,
    GC: GenderClaim,
    JE: JweContentEncryptionAlgorithm,
    JS: JwsSigningAlgorithm<JT>,
    JT: JsonWebKeyType,
{
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};
    use itertools::sorted;
    use oauth2::basic::BasicTokenType;
    use oauth2::prelude::{NewType, SecretNewType};
    use oauth2::{AccessToken, ClientId, TokenResponse};
    use serde_json;
    use url::Url;

    use super::super::claims::{AdditionalClaims, EmptyAdditionalClaims, StandardClaims};
    use super::super::core::{CoreGenderClaim, CoreIdToken, CoreIdTokenClaims, CoreTokenResponse};
    use super::super::jwt::JsonWebTokenAccess;
    use super::super::{
        AccessTokenHash, AddressCountry, AddressLocality, AddressPostalCode, AddressRegion,
        Audience, AuthenticationContextClass, AuthenticationMethodReference, AuthorizationCodeHash,
        EndUserBirthday, EndUserEmail, EndUserFamilyName, EndUserGivenName, EndUserMiddleName,
        EndUserName, EndUserNickname, EndUserPhoneNumber, EndUserPictureUrl, EndUserProfileUrl,
        EndUserTimezone, EndUserUsername, EndUserWebsiteUrl, FormattedAddress, IssuerUrl,
        LanguageTag, Nonce, StreetAddress, SubjectIdentifier,
    };
    use super::{AudiencesClaim, IdTokenClaims, IssuerClaim};

    #[test]
    fn test_id_token() {
        let id_token_str = "\"eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL3NlcnZlci5leGFtcGxlLmNvbSI\
            sImF1ZCI6WyJzNkJoZFJrcXQzIl0sImV4cCI6MTMxMTI4MTk3MCwiaWF0IjoxMzExMjgwOTcwLCJzdWIiOiIyND\
            QwMDMyMCIsInRmYV9tZXRob2QiOiJ1MmYifQ.aW52YWxpZF9zaWduYXR1cmU\"";

        let id_token =
            serde_json::from_str::<CoreIdToken>(id_token_str).expect("failed to deserialize");

        let claims = id_token.0.unverified_claims_ref();

        assert_eq!(
            *claims.issuer().url(),
            Url::parse("https://server.example.com").unwrap()
        );
        assert_eq!(
            *claims.audiences(),
            vec![Audience::new("s6BhdRkqt3".to_string())]
        );
        assert_eq!(claims.expiration().unwrap(), Utc.timestamp(1311281970, 0));
        assert_eq!(claims.issue_time().unwrap(), Utc.timestamp(1311280970, 0));
        assert_eq!(
            *claims.sub(),
            SubjectIdentifier::new("24400320".to_string())
        );

        assert_eq!(
            serde_json::to_string(&id_token).expect("failed to serialize"),
            id_token_str
        );
    }

    #[test]
    fn test_oauth2_response() {
        let response_str = "{\
            \"access_token\":\"foobar\",\
            \"token_type\":\"bearer\",\
            \"id_token\":\"eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL3NlcnZlci5leGFtcGxlLmNvbSIsImF\
            1ZCI6WyJzNkJoZFJrcXQzIl0sImV4cCI6MTMxMTI4MTk3MCwiaWF0IjoxMzExMjgwOTcwLCJzdWIiOiIyNDQwMD\
            MyMCIsInRmYV9tZXRob2QiOiJ1MmYifQ.aW52YWxpZF9zaWduYXR1cmU\"\
        }";
        let response =
            serde_json::from_str::<CoreTokenResponse>(response_str).expect("failed to deserialize");

        assert_eq!(
            *response.access_token(),
            AccessToken::new("foobar".to_string())
        );
        assert_eq!(*response.token_type(), BasicTokenType::Bearer);

        let id_token = response.extra_fields().id_token();
        let claims = id_token.0.unverified_claims_ref();

        assert_eq!(
            *claims.issuer().url(),
            Url::parse("https://server.example.com").unwrap()
        );
        assert_eq!(
            *claims.audiences(),
            vec![Audience::new("s6BhdRkqt3".to_string())]
        );
        assert_eq!(claims.expiration().unwrap(), Utc.timestamp(1311281970, 0));
        assert_eq!(claims.issue_time().unwrap(), Utc.timestamp(1311280970, 0));
        assert_eq!(
            *claims.sub(),
            SubjectIdentifier::new("24400320".to_string())
        );

        assert_eq!(
            serde_json::to_string(&response).expect("failed to serialize"),
            response_str
        );
    }

    #[test]
    fn test_minimal_claims_serde() {
        let claims_json = "{
            \"iss\": \"https://server.example.com\",
            \"sub\": \"24400320\",
            \"aud\": \"s6BhdRkqt3\",
            \"exp\": 1311281970,
            \"iat\": 1311280970
        }";

        let claims: CoreIdTokenClaims =
            serde_json::from_str(claims_json).expect("failed to deserialize");
        assert_eq!(
            *claims.issuer().url(),
            Url::parse("https://server.example.com").unwrap()
        );
        assert_eq!(
            *claims.audiences(),
            vec![Audience::new("s6BhdRkqt3".to_string())]
        );
        assert_eq!(claims.expiration().unwrap(), Utc.timestamp(1311281970, 0));
        assert_eq!(claims.issue_time().unwrap(), Utc.timestamp(1311280970, 0));
        assert_eq!(claims.auth_time(), None);
        assert_eq!(claims.nonce(), None);
        assert_eq!(claims.auth_context_ref(), None);
        assert_eq!(claims.auth_methods_refs(), None);
        assert_eq!(claims.authorized_party(), None);
        assert_eq!(claims.access_token_hash(), None);
        assert_eq!(claims.code_hash(), None);
        assert_eq!(*claims.additional_claims(), EmptyAdditionalClaims {});
        assert_eq!(
            *claims.sub(),
            SubjectIdentifier::new("24400320".to_string())
        );
        assert_eq!(claims.name(), None);
        assert_eq!(claims.given_name(), None);
        assert_eq!(claims.family_name(), None);
        assert_eq!(claims.middle_name(), None);
        assert_eq!(claims.nickname(), None);
        assert_eq!(claims.preferred_username(), None);
        assert_eq!(claims.profile(), None);
        assert_eq!(claims.picture(), None);
        assert_eq!(claims.website(), None);
        assert_eq!(claims.email(), None);
        assert_eq!(claims.email_verified(), None);
        assert_eq!(claims.gender(), None);
        assert_eq!(claims.birthday(), None);
        assert_eq!(claims.zoneinfo(), None);
        assert_eq!(claims.locale(), None);
        assert_eq!(claims.phone_number(), None);
        assert_eq!(claims.phone_number_verified(), None);
        assert_eq!(claims.address(), None);
        assert_eq!(claims.updated_at(), None);

        let serialized_claims = serde_json::to_string(&claims).expect("failed to serialize");
        assert_eq!(
            serialized_claims,
            "{\
             \"iss\":\"https://server.example.com\",\
             \"aud\":[\"s6BhdRkqt3\"],\
             \"exp\":1311281970,\
             \"iat\":1311280970,\
             \"sub\":\"24400320\"\
             }"
        );

        let claims_round_trip: CoreIdTokenClaims =
            serde_json::from_str(&serialized_claims).expect("failed to deserialize");
        assert_eq!(claims, claims_round_trip);
    }

    #[test]
    fn test_complete_claims_serde() {
        let claims_json = "{
            \"iss\": \"https://server.example.com\",
            \"aud\": \"s6BhdRkqt3\",
            \"exp\": 1311281970,
            \"iat\": 1311280970,
            \"auth_time\": 1311282970.5,
            \"nonce\": \"Zm9vYmFy\",
            \"acr\": \"urn:mace:incommon:iap:silver\",
            \"amr\": [\"password\", \"totp\"],
            \"azp\": \"dGhpc19jbGllbnQ\",
            \"at_hash\": \"_JPLB-GtkomFJxAOWKHPHQ\",
            \"c_hash\": \"VpTQii5T_8rgwxA-Wtb2Bw\",
            \"sub\": \"24400320\",
            \"name\": \"Homer Simpson\",
            \"name#es\": \"Jomer Simpson\",
            \"given_name\": \"Homer\",
            \"given_name#es\": \"Jomer\",
            \"family_name\": \"Simpson\",
            \"family_name#es\": \"Simpson\",
            \"middle_name\": \"Jay\",
            \"middle_name#es\": \"Jay\",
            \"nickname\": \"Homer\",
            \"nickname#es\": \"Jomer\",
            \"preferred_username\": \"homersimpson\",
            \"profile\": \"https://example.com/profile?id=12345\",
            \"profile#es\": \"https://example.com/profile?id=12345&lang=es\",
            \"picture\": \"https://example.com/avatar?id=12345\",
            \"picture#es\": \"https://example.com/avatar?id=12345&lang=es\",
            \"website\": \"https://homersimpson.me\",
            \"website#es\": \"https://homersimpson.me/?lang=es\",
            \"email\": \"homer@homersimpson.me\",
            \"email_verified\": true,
            \"gender\": \"male\",
            \"birthday\": \"1956-05-12\",
            \"zoneinfo\": \"America/Los_Angeles\",
            \"locale\": \"en-US\",
            \"phone_number\": \"+1 (555) 555-5555\",
            \"phone_number_verified\": false,
            \"address\": {
                \"formatted\": \"1234 Hollywood Blvd., Los Angeles, CA 90210\",
                \"street_address\": \"1234 Hollywood Blvd.\",
                \"locality\": \"Los Angeles\",
                \"region\": \"CA\",
                \"postal_code\": \"90210\",
                \"country\": \"US\"
            },
            \"updated_at\": 1311283970,
            \"some_other_field\": \"some_other_value\"
        }";

        let claims: CoreIdTokenClaims =
            serde_json::from_str(claims_json).expect("failed to deserialize");
        assert_eq!(
            *claims.issuer().url(),
            Url::parse("https://server.example.com").unwrap(),
        );
        assert_eq!(
            *claims.audiences(),
            vec![Audience::new("s6BhdRkqt3".to_string())]
        );
        assert_eq!(claims.expiration().unwrap(), Utc.timestamp(1311281970, 0));
        assert_eq!(claims.issue_time().unwrap(), Utc.timestamp(1311280970, 0));
        assert_eq!(
            claims.auth_time(),
            Some(Ok(Utc.timestamp(1311282970, 500000000))),
        );
        assert_eq!(*claims.nonce().unwrap(), Nonce::new("Zm9vYmFy".to_string()));
        assert_eq!(
            *claims.auth_context_ref().unwrap(),
            AuthenticationContextClass::new("urn:mace:incommon:iap:silver".to_string()),
        );
        assert_eq!(
            *claims.auth_methods_refs().unwrap(),
            vec![
                AuthenticationMethodReference::new("password".to_string()),
                AuthenticationMethodReference::new("totp".to_string()),
            ]
        );
        assert_eq!(
            *claims.authorized_party().unwrap(),
            ClientId::new("dGhpc19jbGllbnQ".to_string()),
        );
        assert_eq!(
            *claims.access_token_hash().unwrap(),
            AccessTokenHash::new("_JPLB-GtkomFJxAOWKHPHQ".to_string()),
        );
        assert_eq!(
            *claims.code_hash().unwrap(),
            AuthorizationCodeHash::new("VpTQii5T_8rgwxA-Wtb2Bw".to_string()),
        );
        assert_eq!(*claims.additional_claims(), EmptyAdditionalClaims {});
        assert_eq!(
            *claims.sub(),
            SubjectIdentifier::new("24400320".to_string()),
        );
        assert_eq!(
            sorted(claims.name().unwrap().clone()),
            vec![
                (None, EndUserName::new("Homer Simpson".to_string())),
                (
                    Some(LanguageTag::new("es".to_string())),
                    EndUserName::new("Jomer Simpson".to_string()),
                ),
            ]
        );
        assert_eq!(
            sorted(claims.given_name().unwrap().clone()),
            vec![
                (None, EndUserGivenName::new("Homer".to_string())),
                (
                    Some(LanguageTag::new("es".to_string())),
                    EndUserGivenName::new("Jomer".to_string()),
                ),
            ]
        );
        assert_eq!(
            sorted(claims.family_name().unwrap().clone()),
            vec![
                (None, EndUserFamilyName::new("Simpson".to_string())),
                (
                    Some(LanguageTag::new("es".to_string())),
                    EndUserFamilyName::new("Simpson".to_string()),
                ),
            ]
        );
        assert_eq!(
            sorted(claims.middle_name().unwrap().clone()),
            vec![
                (None, EndUserMiddleName::new("Jay".to_string())),
                (
                    Some(LanguageTag::new("es".to_string())),
                    EndUserMiddleName::new("Jay".to_string()),
                ),
            ]
        );
        assert_eq!(
            sorted(claims.nickname().unwrap().clone()),
            vec![
                (None, EndUserNickname::new("Homer".to_string())),
                (
                    Some(LanguageTag::new("es".to_string())),
                    EndUserNickname::new("Jomer".to_string()),
                ),
            ]
        );
        assert_eq!(
            claims.preferred_username(),
            Some(&EndUserUsername::new("homersimpson".to_string()))
        );
        assert_eq!(
            sorted(claims.profile().unwrap().clone()),
            vec![
                (
                    None,
                    EndUserProfileUrl::new("https://example.com/profile?id=12345".to_string())
                        .unwrap(),
                ),
                (
                    Some(LanguageTag::new("es".to_string())),
                    EndUserProfileUrl::new(
                        "https://example.com/profile?id=12345&lang=es".to_string()
                    )
                    .unwrap(),
                ),
            ]
        );
        assert_eq!(
            sorted(claims.picture().unwrap().clone()),
            vec![
                (
                    None,
                    EndUserPictureUrl::new("https://example.com/avatar?id=12345".to_string())
                        .unwrap(),
                ),
                (
                    Some(LanguageTag::new("es".to_string())),
                    EndUserPictureUrl::new(
                        "https://example.com/avatar?id=12345&lang=es".to_string()
                    )
                    .unwrap(),
                ),
            ]
        );
        assert_eq!(
            sorted(claims.website().unwrap().clone()),
            vec![
                (
                    None,
                    EndUserWebsiteUrl::new("https://homersimpson.me".to_string()).unwrap(),
                ),
                (
                    Some(LanguageTag::new("es".to_string())),
                    EndUserWebsiteUrl::new("https://homersimpson.me/?lang=es".to_string()).unwrap(),
                ),
            ]
        );
        assert_eq!(
            claims.email(),
            Some(&EndUserEmail::new("homer@homersimpson.me".to_string()))
        );
        assert_eq!(claims.email_verified(), Some(true));
        assert_eq!(claims.gender(), Some(&CoreGenderClaim::Male));
        assert_eq!(
            claims.birthday(),
            Some(&EndUserBirthday::new("1956-05-12".to_string()))
        );
        assert_eq!(
            claims.zoneinfo(),
            Some(&EndUserTimezone::new("America/Los_Angeles".to_string())),
        );
        assert_eq!(
            claims.locale(),
            Some(&LanguageTag::new("en-US".to_string()))
        );
        assert_eq!(
            claims.phone_number(),
            Some(&EndUserPhoneNumber::new("+1 (555) 555-5555".to_string()))
        );
        assert_eq!(claims.phone_number_verified(), Some(false));
        assert_eq!(
            claims.address().unwrap().formatted(),
            Some(&FormattedAddress::new(
                "1234 Hollywood Blvd., Los Angeles, CA 90210".to_string()
            ))
        );
        assert_eq!(
            claims.address().unwrap().street_address(),
            Some(&StreetAddress::new("1234 Hollywood Blvd.".to_string()))
        );
        assert_eq!(
            claims.address().unwrap().locality(),
            Some(&AddressLocality::new("Los Angeles".to_string()))
        );
        assert_eq!(
            claims.address().unwrap().region(),
            Some(&AddressRegion::new("CA".to_string()))
        );
        assert_eq!(
            claims.address().unwrap().postal_code(),
            Some(&AddressPostalCode::new("90210".to_string()))
        );
        assert_eq!(
            claims.address().unwrap().country(),
            Some(&AddressCountry::new("US".to_string()))
        );
        assert_eq!(claims.updated_at(), Some(Ok(Utc.timestamp(1311283970, 0))),);

        let serialized_claims = serde_json::to_string(&claims).expect("failed to serialize");
        let claims_round_trip: CoreIdTokenClaims =
            serde_json::from_str(&serialized_claims).expect("failed to deserialize");
        assert_eq!(claims, claims_round_trip);
    }

    #[test]
    fn test_audience() {
        let single_aud_str_claims = serde_json::from_str::<CoreIdTokenClaims>(
            "{
                    \"iss\": \"https://server.example.com\",
                    \"sub\": \"24400320\",
                    \"aud\": \"s6BhdRkqt3\",
                    \"exp\": 1311281970,
                    \"iat\": 1311280970
                }",
        )
        .expect("failed to deserialize");
        assert_eq!(
            *single_aud_str_claims.audiences(),
            vec![Audience::new("s6BhdRkqt3".to_string())],
        );

        // We always serialize aud as an array, which is valid according to the spec.
        assert_eq!(
            serde_json::to_string(&single_aud_str_claims).expect("failed to serialize"),
            "{\
             \"iss\":\"https://server.example.com\",\
             \"aud\":[\"s6BhdRkqt3\"],\
             \"exp\":1311281970,\
             \"iat\":1311280970,\
             \"sub\":\"24400320\"\
             }",
        );

        let single_aud_vec_claims = serde_json::from_str::<CoreIdTokenClaims>(
            "{
                    \"iss\": \"https://server.example.com\",
                    \"sub\": \"24400320\",
                    \"aud\": [\"s6BhdRkqt3\"],
                    \"exp\": 1311281970,
                    \"iat\": 1311280970
                }",
        )
        .expect("failed to deserialize");
        assert_eq!(
            *single_aud_vec_claims.audiences(),
            vec![Audience::new("s6BhdRkqt3".to_string())],
        );
        assert_eq!(
            serde_json::to_string(&single_aud_vec_claims).expect("failed to serialize"),
            "{\
             \"iss\":\"https://server.example.com\",\
             \"aud\":[\"s6BhdRkqt3\"],\
             \"exp\":1311281970,\
             \"iat\":1311280970,\
             \"sub\":\"24400320\"\
             }",
        );

        let multi_aud_claims = serde_json::from_str::<CoreIdTokenClaims>(
            "{\
                    \"iss\": \"https://server.example.com\",
                    \"sub\": \"24400320\",
                    \"aud\": [\"s6BhdRkqt3\", \"aud2\"],
                    \"exp\": 1311281970,
                    \"iat\": 1311280970
                }",
        )
        .expect("failed to deserialize");
        assert_eq!(
            *multi_aud_claims.audiences(),
            vec![
                Audience::new("s6BhdRkqt3".to_string()),
                Audience::new("aud2".to_string())
            ],
        );
        assert_eq!(
            serde_json::to_string(&multi_aud_claims).expect("failed to serialize"),
            "{\
             \"iss\":\"https://server.example.com\",\
             \"aud\":[\"s6BhdRkqt3\",\"aud2\"],\
             \"exp\":1311281970,\
             \"iat\":1311280970,\
             \"sub\":\"24400320\"\
             }",
        );
    }

    #[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
    struct TestClaims {
        pub tfa_method: String,
    }
    impl AdditionalClaims for TestClaims {}

    #[test]
    fn test_additional_claims() {
        let claims = serde_json::from_str::<IdTokenClaims<TestClaims, CoreGenderClaim>>(
            "{
                \"iss\": \"https://server.example.com\",
                \"sub\": \"24400320\",
                \"aud\": [\"s6BhdRkqt3\"],
                \"exp\": 1311281970,
                \"iat\": 1311280970,
                \"tfa_method\": \"u2f\"
            }",
        )
        .expect("failed to deserialize");
        assert_eq!(claims.additional_claims().tfa_method, "u2f");
        assert_eq!(
            serde_json::to_string(&claims).expect("failed to serialize"),
            "{\
             \"iss\":\"https://server.example.com\",\
             \"aud\":[\"s6BhdRkqt3\"],\
             \"exp\":1311281970,\
             \"iat\":1311280970,\
             \"sub\":\"24400320\",\
             \"tfa_method\":\"u2f\"\
             }",
        );

        serde_json::from_str::<IdTokenClaims<TestClaims, CoreGenderClaim>>(
            "{
                \"iss\": \"https://server.example.com\",
                \"sub\": \"24400320\",
                \"aud\": [\"s6BhdRkqt3\"],
                \"exp\": 1311281970,
                \"iat\": 1311280970
            }",
        )
        .expect_err("missing claim should fail to deserialize");
    }

    #[test]
    fn test_audiences_claim() {
        let claims = serde_json::from_str::<CoreIdTokenClaims>(
            "{
                    \"iss\": \"https://server.example.com\",
                    \"sub\": \"24400320\",
                    \"aud\": \"s6BhdRkqt3\",
                    \"exp\": 1311281970,
                    \"iat\": 1311280970
                }",
        )
        .expect("failed to deserialize");

        fn verify_audiences<A: AudiencesClaim>(audiences_claim: &A) {
            assert_eq!(
                (*audiences_claim).audiences(),
                Some(&vec![Audience::new("s6BhdRkqt3".to_string())]),
            )
        }
        verify_audiences(&claims);
        verify_audiences(&&claims);
    }

    #[test]
    fn test_issuer_claim() {
        let claims = serde_json::from_str::<CoreIdTokenClaims>(
            "{
                    \"iss\": \"https://server.example.com\",
                    \"sub\": \"24400320\",
                    \"aud\": \"s6BhdRkqt3\",
                    \"exp\": 1311281970,
                    \"iat\": 1311280970
                }",
        )
        .expect("failed to deserialize");

        fn verify_issuer<I: IssuerClaim>(issuer_claim: &I) {
            assert_eq!(
                (*issuer_claim).issuer(),
                Some(&IssuerUrl::new("https://server.example.com".to_string()).unwrap()),
            )
        }
        verify_issuer(&claims);
        verify_issuer(&&claims);
    }
}
