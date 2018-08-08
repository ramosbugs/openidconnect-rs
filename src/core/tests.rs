use serde_json;

use super::CoreGrantType;

#[test]
fn test_grant_type_serialize() {
    let serialized_implicit = serde_json::to_string(&CoreGrantType::Implicit).unwrap();
    assert_eq!("\"implicit\"", serialized_implicit);
    assert_eq!(
        CoreGrantType::Implicit,
        serde_json::from_str::<CoreGrantType>(&serialized_implicit).unwrap()
    );

    let ext = CoreGrantType::Extension("urn:ietf:params:oauth:grant-type:foobar".to_string());
    let serialized_ext = serde_json::to_string(&ext).unwrap();
    assert_eq!(
        "\"urn:ietf:params:oauth:grant-type:foobar\"",
        serialized_ext
    );
    assert_eq!(
        ext,
        serde_json::from_str::<CoreGrantType>(&serialized_ext).unwrap()
    );
}
