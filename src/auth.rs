use anyhow::bail;
use jsonwebtoken::{Algorithm, DecodingKey, TokenData, Validation, decode, decode_header};
use fehler::throws;
use log::debug;
use std::collections::HashSet;

use crate::{structs::{Claims, JWK}, utils};

pub struct Auth {
    pub audience: String,
    pub issuer: String,
    pub keys: Vec<JWK>
}

impl Auth {
    pub fn new(audience: String, issuer: String, keys: Vec<JWK>) -> Self {
        debug!(target: "auth_events.new", "New... (audience: {:?})", audience);
        Self { audience, issuer, keys }
    }

    #[throws(anyhow::Error)]
    pub fn validate_token(&mut self,token: &str) -> TokenData<Claims> {
        debug!(target: "auth.validate_token", "Validating token");
        let mut audience = HashSet::new();
        let header = decode_header(&token)?;
        let kid = header.kid.unwrap_or("Could not find kid in token".to_string());
        let header = utils::find_jwk(kid, self.keys.clone())?;
        // 1. Retrieve the JWKS and filter for potential signature verification keys.
        // 2. Extract the JWT from the request's authorization header.
        // 3. Decode the JWT and grab the kid property from the header.
        // 4. Find the signature verification key in the filtered JWKS with a matching kid property.
        // 5. Using the x5c property build a certificate which will be used to verify the JWT signature.
        audience.insert(self.audience.to_string());
        let validation = Validation {
            aud: Some(audience),
            iss: Some(self.issuer.clone()),
            algorithms: vec![Algorithm::RS256],
            ..Validation::default()
        };
        let decoding_key = &DecodingKey::from_rsa_components(&header.n, &header.e);
        match decode::<Claims>(&token, decoding_key, &validation) {
            Ok(token_data) => {
                debug!(target: "auth.validate_token.result", "Token is valid");
                // TODO: Ensure the JWT contains the expected audience, issuer, expiration, etc.
                return token_data;
            },
            Err(err) => bail!(format!("{}", err))
        };
    }
}

#[cfg(test)]
mod tests {

    use super::*;
 
    #[tokio::test]
    async fn test_valid_token_with_multiple_audiences() {
        // TODO: method to get a token on the go
        let token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImZtaDlYei10NHloZHV4a2FFeVpITCJ9.eyJodHRwczovL2JvdG8uaW8vY2xhaW1zL2J1aWQiOiIzZThjMGYxNi1hNWI4LTQ0ZTctYTlkMi1kYTk1ZWI2M2Y0ZjUiLCJpc3MiOiJodHRwczovL2JvdG9kZXYuZXUuYXV0aDAuY29tLyIsInN1YiI6Imdvb2dsZS1vYXV0aDJ8MTEzODM1NjM4NjIxNzIyNzgxMTY0IiwiYXVkIjpbImh0dHBzOi8vZDJzZnMweWJ0bmU0ZDYuY2xvdWRmcm9udC5uZXQiLCJodHRwczovL2JvdG9kZXYuZXUuYXV0aDAuY29tL3VzZXJpbmZvIl0sImlhdCI6MTY0MjQ4ODA1NywiZXhwIjoxNjQyNTc0NDU3LCJhenAiOiJkRlN3ZEhKM3lRUXFRT1FVMHQ1aHl0MmM0SjZ4S3ltdyIsInNjb3BlIjoib3BlbmlkIHByb2ZpbGUgZW1haWwifQ.hzEolPMDewyfGseDiEaGZwp3no0zddqsqFvV41cSLKyQah2FlDWYppqyF9YAt7KUgi6m6rS99AtPZfhd2dLsUehO83nnoLkR94R695To0jXrW54KhCtG8auIXMqKTtF-n-rs_SNtjFMrNrP8mzeQZColQFonDKtOXl_6ui-7Sd34BFBmt9BezQtt94EXP4Xcc89ckBxNbfzl1WClzFIAr96sBYFbMUGTWhgADJSbk-iTwtEhcmUo84CVQ5qNPPz0f4G4Lju1ItwBke_6N_VdGOS4DcQ7KnKre1NVuCPE_e2df76lAZ_mgSB81Plfm7D6kpkd7FBVLFFft9-Wn-zF2g";
        let audience = "https://d2sfs0ybtne4d6.cloudfront.net".to_string();
        let issuer = "https://botodev.eu.auth0.com/".to_string();
        let keys = utils::get_jwks("https://botodev.eu.auth0.com/.well-known/jwks.json".to_string()).await;
        let mut auth = Auth::new(
            audience.clone(), issuer.clone(), keys.unwrap()
        );
        let result = auth.validate_token(token);
        assert_eq!(result.is_err(), false)
    }

    // #[tokio::test]
    // async fn test_valid_token_with_single_audience() {
    //     // TODO: method to get a token on the go
    //     let token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImZtaDlYei10NHloZHV4a2FFeVpITCJ9.eyJodHRwczovL2JvdG8uaW8vY2xhaW1zL2J1aWQiOiIzZThjMGYxNi1hNWI4LTQ0ZTctYTlkMi1kYTk1ZWI2M2Y0ZjUiLCJpc3MiOiJodHRwczovL2JvdG9kZXYuZXUuYXV0aDAuY29tLyIsInN1YiI6Imdvb2dsZS1vYXV0aDJ8MTEzODM1NjM4NjIxNzIyNzgxMTY0IiwiYXVkIjoiaHR0cHM6Ly9kMnNmczB5YnRuZTRkNi5jbG91ZGZyb250Lm5ldCIsImlhdCI6MTY0MjQ4ODA1NywiZXhwIjoxNjQyNTc0NDU3LCJhenAiOiJkRlN3ZEhKM3lRUXFRT1FVMHQ1aHl0MmM0SjZ4S3ltdyIsInNjb3BlIjoib3BlbmlkIHByb2ZpbGUgZW1haWwifQ.g4pHip2gHaOCr-R-KFp2hI3SDEZsGKZMy5w7-UylFKypyIYhgiYQpvs0GQEwAID4TMOoegxzTXLv9EGeSzc1OO1S2u2Zq9k9VRYVIpyjEV6zq1fOdo3LTsshOq-PED5Bgm7xTpqxkYa1CE9nij5g3EmWDX6wE2ZLfZIU4f3duj0G0YAh4QiYLlENMfX6Xf7VYO3TPsvRXN9B4OynsKm2wqA4ntfhKN5AgmesP7CAdcE8KS4XrINMWMnOHZjyPfHxjYFT_A6XJf4PhfKOWKTNpV9tDu0Q-MJlv9-yDpMS3KWLBW5egJ84_-L3-_joeZkBR1EZHIrr20660gf8NycdUQ";
    //     let audience = "https://d2sfs0ybtne4d6.cloudfront.net".to_string();
    //     let issuer = "https://botodev.eu.auth0.com/".to_string();
    //     let keys = utils::get_jwks("https://botodev.eu.auth0.com/.well-known/jwks.json".to_string()).await;
    //     let mut auth = Auth::new(
    //         audience.clone(), issuer.clone(), keys.unwrap()
    //     );
    //     let result = auth.validate_token(token);
    //     assert_eq!(result.is_err(), false)
    // }

    #[tokio::test]
    async fn test_valid_token_without_user_id() {
        // TODO: method to get a token on the go
        let token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImZtaDlYei10NHloZHV4a2FFeVpITCJ9.eyJpc3MiOiJodHRwczovL2JvdG9kZXYuZXUuYXV0aDAuY29tLyIsInN1YiI6ImxmdHdHaEJ6akFFT0swS0NuR3QzM0wyVlVacXVhWDNjQGNsaWVudHMiLCJhdWQiOiJodHRwczovL2Qyc2ZzMHlidG5lNGQ2LmNsb3VkZnJvbnQubmV0IiwiaWF0IjoxNjQyNDg5MjYzLCJleHAiOjE2NDI1NzU2NjMsImF6cCI6ImxmdHdHaEJ6akFFT0swS0NuR3QzM0wyVlVacXVhWDNjIiwiZ3R5IjoiY2xpZW50LWNyZWRlbnRpYWxzIn0.QSBmLjC3HKY8B6cu7P9kLu-rJqtD7VTC5sc65X_gPftgcSClQKjauD5azKbtUn1-LtDLAWKfDX9DyQNpvilC6uwmZihFK_-DmLsAgNxan1FFWOkOfODK4aMKzL7rjkrdGgeyXjt9tt3ydfN-_s_JTvNiX3Tfr8QeGiiN70IWDF_E2QcoIrNG2rMKPsdnLeApYgykcWcCp-O2OKxIYNOEx_NMjld4pGpE9sTi-FpvcSo9ZKSxnNVWwNnJeLYM-cqzk78_Novzc_OJGaZ0sHvlQsS34KsHeBV55qqq88Ecmj6KDdvtEoUJ1pdRHVgZQNaCkFSQxCSCtscmMY_7_TB0cA";
        let audience = "https://d2sfs0ybtne4d6.cloudfront.net".to_string();
        let issuer = "https://botodev.eu.auth0.com/".to_string();
        let keys = utils::get_jwks("https://botodev.eu.auth0.com/.well-known/jwks.json".to_string()).await;
        let mut auth = Auth::new(
            audience.clone(), issuer.clone(), keys.unwrap()
        );
        let result = auth.validate_token(token);
        assert_eq!(result.is_err(), true)
    }

    #[tokio::test]
    async fn test_invalid_token() {
        // TODO: method to get a token on the go
        let token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImZtaDlYei10NHloZHV4a2FFeVpITCJ9.eyJodHRwczovL2JvdG8uaW8vY2xhaW1zL2J1aWQiOiIzZThjMGYxNi1hNWI4LTQ0ZTctYTlkMi1kYTk1ZWI2M2Y0ZjUiLCJpc3MiOiJodHRwczovL2JvdG9kZXYuZXUuYXV0aDAuY29tLyIsInN1YiI6Imdvb2dsZS1vYXV0aDJ8MTEzODM1NjM4NjIxNzIyNzgxMTY0IiwiYXVkIjpbImh0dHBzOi8vZDJzZnMweWJ0bmU0ZDYuY2xvdWRmcm9udC5uZXQiLCJodHRwczovL2JvdG9kZXYuZXUuYXV0aDAuY29tL3VzZXJpbmZvIl0sImlhdCI6MTY0MjQ4ODA1NywiZXhwIjoxNjQyNTc0NDU3LCJhenAiOiJkRlN3ZEhKM3lRUXFRT1FVMHQ1aHl0MmM0SjZ4S3ltdyIsInNjb3BlIjoib3BlbmlkIHByb2ZpbGUgZW1haWwifQ.hzEolPMDewyfGseDiEaGZwp3no0zddqsqFvV41cSLKyQah2FlDWYppqyF9YAt7KUgi6m6rS99AtPZfhd2dLsUehO83nnoLkR94R695To0jXrW54KhCtG8auIXMqKTtF-n-rs_SNtjFMrNrP8mzeQZColQFonDKtOXl_6ui-7Sd34BFBmt9BezQtt94EXP4Xcc89ckBxNbfzl1WClzFIAr96sBYFbMUGTWhgADJSbk-iTwtEhcmUo84CVQ5qNPPz0f4G4Lju1ItwBke_6N_VdGOS4DcQ7KnKre1NVuCPE_e2df76lAZ_mgSB81Plfm7D6kpkd7FBVLFFft9-Wn-zF2g";
        let audience = "https://bad_audience.cloudfront.net".to_string();
        let issuer = "https://botodev.eu.auth0.com/".to_string();
        let keys = utils::get_jwks("https://botodev.eu.auth0.com/.well-known/jwks.json".to_string()).await;
        let mut auth = Auth::new(
            audience.clone(), issuer.clone(), keys.unwrap()
        );
        let result = auth.validate_token(token);
        assert_eq!(result.is_err(), true)
    }
}