use crate::{
    Audience, IssuerUrl, JsonWebTokenAccess, JsonWebTokenIdentifier, LogoutToken,
    LogoutTokenClaims, LogoutTokenTarget, SessionIdentifier, SubjectIdentifier,
};

use chrono::{TimeZone, Utc};
use pretty_assertions::assert_eq;
use serde_json::json;
use url::Url;

#[test]
fn test_logout_token() {
    static LOGOUT_TOKEN: &str = concat!(
        "eyJhbGciOiJIUzI1NiJ9.",
        "eyJpc3MiOiJodHRwczovL3NlcnZlci5leGFtcGxlLmNvbSIsImF1ZCI6WyJzNkJoZ",
        "FJrcXQzIl0sImV4cCI6MTMxMTI4MTk3MCwiaWF0IjoxMzExMjgwOTcwLCJqdGkiOi",
        "JleGFtcGxlLWp0aSIsImV2ZW50cyI6eyJodHRwOi8vc2NoZW1hcy5vcGVuaWQubmV",
        "0L2V2ZW50L2JhY2tjaGFubmVsLWxvZ291dCI6e319LCJzdWIiOiIyNDQwMDMyMCJ9",
        ".L0EDXVnrPFOhBZkAAZCUEu7XuAtSmYhvuQDKGYD1NNI"
    );

    // `serde::Deserialize` implementation is tested within the `FromStr` implementation
    let logout_token: LogoutToken = LOGOUT_TOKEN.parse().expect("failed to parse logout_token");

    let claims = logout_token.0.unverified_payload_ref();

    assert_eq!(
        *claims.issuer().url(),
        Url::parse("https://server.example.com").unwrap()
    );
    assert_eq!(
        *claims.audiences(),
        vec![Audience::new("s6BhdRkqt3".to_string())]
    );
    assert_eq!(
        claims.expiration(),
        Utc.timestamp_opt(1311281970, 0)
            .single()
            .expect("valid timestamp")
    );
    assert_eq!(
        claims.issue_time(),
        Utc.timestamp_opt(1311280970, 0)
            .single()
            .expect("valid timestamp")
    );
    assert!(claims.subject().is_some());
    assert_eq!(
        *claims.subject().unwrap(),
        SubjectIdentifier::new("24400320".to_string())
    );
    assert!(claims.session_id().is_none());
    assert_eq!(
        *claims.token_identifier(),
        JsonWebTokenIdentifier::new("example-jti".to_string())
    );
    assert_eq!(
        *claims.events(),
        json!({"http://schemas.openid.net/event/backchannel-logout": {}})
    );

    // test `ToString` implementation
    assert_eq!(&logout_token.to_string(), LOGOUT_TOKEN);

    // test `serde::Serialize` implementation too
    let de = serde_json::to_string(&logout_token).expect("failed to serialize logout token");
    assert_eq!(de, format!("\"{}\"", LOGOUT_TOKEN));
}

#[test]
fn test_claims_serde() {
    let new_claims = LogoutTokenClaims::new(
        IssuerUrl::new("https://server.example.com".to_string()).unwrap(),
        vec![Audience::new("s6BhdRkqt3".to_string())],
        Utc.timestamp_opt(1311281970, 0)
            .single()
            .expect("valid timestamp"),
        Utc.timestamp_opt(1311280970, 0)
            .single()
            .expect("valid timestamp"),
        JsonWebTokenIdentifier::new("example-jti".to_string()),
        LogoutTokenTarget::from_sub("24400320".to_string()),
    );
    let expected_serialized_claims = "\
                                          {\
                                          \"iss\":\"https://server.example.com\",\
                                          \"aud\":[\"s6BhdRkqt3\"],\
                                          \"exp\":1311281970,\
                                          \"iat\":1311280970,\
                                          \"jti\":\"example-jti\",\
                                          \"events\":{\"http://schemas.openid.net/event/backchannel-logout\":{}},\
                                          \"sub\":\"24400320\"\
                                          }";

    let new_serialized_claims = serde_json::to_string(&new_claims).expect("failed to serialize");
    assert_eq!(new_serialized_claims, expected_serialized_claims);

    let claims: LogoutTokenClaims = serde_json::from_str(
        "{
            \"iss\": \"https://server.example.com\",
            \"sub\": \"24400320\",
            \"aud\": \"s6BhdRkqt3\",
            \"exp\": 1311281970,
            \"iat\": 1311280970,
            \"jti\": \"example-jti\",
            \"events\": {
                \"http://schemas.openid.net/event/backchannel-logout\": {}
            }
        }",
    )
    .expect("failed to deserialize");
    assert_eq!(claims, new_claims);
    assert_eq!(claims.issuer().url(), new_claims.issuer().url());
    assert_eq!(claims.audiences(), new_claims.audiences());
    assert_eq!(claims.expiration(), new_claims.expiration());
    assert_eq!(claims.issue_time(), new_claims.issue_time());
    assert_eq!(claims.token_identifier(), new_claims.token_identifier());
    assert_eq!(claims.subject(), new_claims.subject());
    assert_eq!(claims.session_id(), new_claims.session_id());
    assert_eq!(*claims.events(), *new_claims.events());

    let serialized_claims = serde_json::to_string(&claims).expect("failed to serialize");
    assert_eq!(serialized_claims, expected_serialized_claims);

    let claims_round_trip: LogoutTokenClaims =
        serde_json::from_str(&serialized_claims).expect("failed to deserialize");
    assert_eq!(claims, claims_round_trip);

    let claims_sid = claims.set_target(LogoutTokenTarget::from_sid("session-id".to_string()));
    assert_eq!(
        claims_sid.session_id(),
        Some(SessionIdentifier::new("session-id".to_string())).as_ref()
    );
    assert_eq!(claims_sid.subject(), None);

    let serialized_claims_sid = serde_json::to_string(&claims_sid).expect("failed to serialize");
    assert_eq!(
        serialized_claims_sid,
        "{\
            \"iss\":\"https://server.example.com\",\
            \"aud\":[\"s6BhdRkqt3\"],\
            \"exp\":1311281970,\
            \"iat\":1311280970,\
            \"jti\":\"example-jti\",\
            \"events\":{\"http://schemas.openid.net/event/backchannel-logout\":{}},\
            \"sid\":\"session-id\"\
        }"
    );

    let claims_sid_round_trip: LogoutTokenClaims =
        serde_json::from_str(&serialized_claims_sid).expect("failed to deserialize");

    assert_eq!(claims_sid_round_trip.subject(), claims_sid.subject());
    assert_eq!(claims_sid_round_trip.session_id(), claims_sid.session_id());

    let claims_sid_sub = claims_sid.set_target(LogoutTokenTarget::from_sid_and_sub(
        "session-id".to_string(),
        "some-subject".to_string(),
    ));
    assert_eq!(
        claims_sid_sub.session_id(),
        Some(SessionIdentifier::new("session-id".to_string())).as_ref()
    );
    assert_eq!(
        claims_sid_sub.subject(),
        Some(SubjectIdentifier::new("some-subject".to_string())).as_ref()
    );

    let serialized_claims_sid_sub =
        serde_json::to_string(&claims_sid_sub).expect("failed to serialize");
    assert_eq!(
        serialized_claims_sid_sub,
        "{\
            \"iss\":\"https://server.example.com\",\
            \"aud\":[\"s6BhdRkqt3\"],\
            \"exp\":1311281970,\
            \"iat\":1311280970,\
            \"jti\":\"example-jti\",\
            \"events\":{\"http://schemas.openid.net/event/backchannel-logout\":{}},\
            \"sid\":\"session-id\",\
            \"sub\":\"some-subject\"\
        }"
    );

    let claims_sid_sub_round_trip: LogoutTokenClaims =
        serde_json::from_str(&serialized_claims_sid_sub).expect("failed to deserialize");

    assert_eq!(
        claims_sid_sub_round_trip.subject(),
        claims_sid_sub.subject()
    );
    assert_eq!(
        claims_sid_sub_round_trip.session_id(),
        claims_sid_sub.session_id()
    );
}

#[test]
fn test_unknown_claims_serde() {
    let expected_serialized_claims = "{\
        \"iss\":\"https://server.example.com\",\
        \"aud\":[\"s6BhdRkqt3\"],\
        \"exp\":1311281970,\
        \"iat\":1311280970,\
        \"jti\":\"example-jti\",\
        \"events\":{\
            \"http://schemas.openid.net/event/backchannel-logout\":{}\
        },\
        \"sub\":\"24400320\"\
    }";

    let claims: LogoutTokenClaims = serde_json::from_str(
        "{
            \"iss\": \"https://server.example.com\",
            \"sub\": \"24400320\",
            \"aud\": \"s6BhdRkqt3\",
            \"exp\": 1311281970,
            \"iat\": 1311280970,
            \"jti\": \"example-jti\",
            \"events\": {
                \"http://schemas.openid.net/event/backchannel-logout\": {}
            },
            \"some_other_field\":\"some_other_value\"\
        }",
    )
    .expect("failed to deserialize");

    let serialized_claims = serde_json::to_string(&claims).expect("failed to serialize");
    assert_eq!(serialized_claims, expected_serialized_claims);

    let claims_round_trip: LogoutTokenClaims =
        serde_json::from_str(&serialized_claims).expect("failed to deserialize");
    assert_eq!(claims, claims_round_trip);
}
