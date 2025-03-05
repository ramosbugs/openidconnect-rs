//!
//! An example using openidconnect to verify a Google Sign-In ID token 
//! on a backend server ([Authenticate with a backend server]
//! (https://developers.google.com/identity/sign-in/web/backend-auth)).
//! To be used with [Android or iOS native app SDKs and apps or 
//! platforms directly calling Google's OAuth2 or OpenID services]
//! (https://developers.googleblog.com/2021/08/gsi-jsweb-deprecation.html).
//!
//! Before running it, you'll need to generate your own [Google OAuth2 
//! credentials for Mobile & Desktop Apps]
//! (https://developers.google.com/identity/protocols/oauth2/native-app).
//!
//! Run with:
//!
//! ```not_rust
//! pushd examples && GOOGLE_CLIENT_ID="xxx" GOOGLE_ID_TOKEN="yyy" cargo test -p google-idtoken --all-features -- --show-output && popd
//! ```

#[cfg(test)]
mod test {
    use openidconnect::{core::{CoreClient, CoreIdToken}, reqwest, AuthUrl, ClientId, ClientSecret, IdToken, IssuerUrl, JsonWebKeySet, JsonWebKeySetUrl, Nonce};
    use std::{env, str::FromStr};

    #[cfg(feature = "sync")]
    #[test]
    fn verify_id_token() {
        let google_client_id = ClientSecret::new(
            env::var("GOOGLE_CLIENT_ID")
                .expect("Missing the GOOGLE_CLIENT_ID environment variable."),
        )
        .secret()
        .to_owned();

        let google_id_token = ClientSecret::new(
            env::var("GOOGLE_ID_TOKEN").expect("Missing the GOOGLE_ID_TOKEN environment variable."),
        )
        .secret()
        .to_owned();

        let client = CoreClient::new(
            ClientId::new(google_client_id),
            IssuerUrl::new("https://accounts.google.com".to_string()).unwrap(),
            JsonWebKeySet::fetch(
                &JsonWebKeySetUrl::new("https://www.googleapis.com/oauth2/v3/certs".to_string())
                    .unwrap(),
                &reqwest::blocking::Client::new(),
            )
            .unwrap(),
        )
            .set_auth_uri(AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string()).unwrap());

        let id_token: CoreIdToken = IdToken::from_str(&google_id_token).unwrap();

        let claims = id_token.claims(&client.id_token_verifier().allow_any_alg(), |_: Option<&Nonce>| Ok(()));

        match claims {
            Ok(claims) => println!(
                "name: {}",
                claims.name().unwrap().get(None).unwrap().as_str()
            ),
            Err(err) => println!("{:#?}", err),
        };
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn verify_id_token_async() {
        let google_client_id = ClientSecret::new(
            env::var("GOOGLE_CLIENT_ID")
                .expect("Missing the GOOGLE_CLIENT_ID environment variable."),
        )
        .secret()
        .to_owned();

        let google_id_token = ClientSecret::new(
            env::var("GOOGLE_ID_TOKEN").expect("Missing the GOOGLE_ID_TOKEN environment variable."),
        )
        .secret()
        .to_owned();

        let client = CoreClient::new(
            ClientId::new(google_client_id),
            IssuerUrl::new("https://accounts.google.com".to_string()).unwrap(),
            JsonWebKeySet::fetch_async(
                &JsonWebKeySetUrl::new("https://www.googleapis.com/oauth2/v3/certs".to_string())
                    .unwrap(),
                &crate::test::reqwest::Client::new(),
            )
            .await
            .unwrap(),
        )
            .set_auth_uri(AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string()).unwrap());

        let id_token: CoreIdToken = IdToken::from_str(&google_id_token).unwrap();

        let claims = id_token.claims(&client.id_token_verifier(), |_: Option<&Nonce>| Ok(()));

        match claims {
            Ok(claims) => println!(
                "name: {}",
                claims.name().unwrap().get(None).unwrap().as_str()
            ),
            Err(err) => println!("{:#?}", err),
        };
    }
}
