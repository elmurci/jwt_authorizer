#[cfg(test)]
mod integration_tests {
    use jwt_authorizer::{auth::Auth, utils};

    #[tokio::test]
    async fn test_read_keys_from_auth0_ok()  {
        let keys = utils::get_jwks("https://boto.eu.auth0.com/.well-known/jwks.json".to_string()).await.unwrap();
        assert_eq!(keys.len(), 2);
    }

    #[tokio::test]
    async fn test_read_keys_from_auth0_bad_url()  {
        let keys = utils::get_jwks("https://xxx.eu.aaa.com/.well-known/jwks.json".to_string()).await;
        assert_eq!(keys.is_err(), true);
    }

    #[tokio::test]
    async fn test_auth_new()  {
        let audience = "https://5q06q4o1qe.execute-api.eu-west-2.amazonaws.com/dev".to_string();
        let issuer = "https://boto.eu.auth0.com/".to_string();
        let keys = utils::get_jwks("https://boto.eu.auth0.com/.well-known/jwks.json".to_string()).await;
        let auth = Auth::new(
            audience.clone(), issuer.clone(), keys.unwrap()
        );
        assert_eq!(auth.issuer, issuer);
        assert_eq!(auth.audience, audience);
        assert_eq!(auth.keys.len(), 2);
    }
}