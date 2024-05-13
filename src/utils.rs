use std::collections::HashMap;

use anyhow::bail;
use fehler::throws;

use crate::structs::JWK;

#[throws(anyhow::Error)]
pub async fn get_jwks(url: String) -> Vec<JWK> {
    let response = reqwest::get(url)
    .await?
    .json::<HashMap<String, Vec<JWK>>>()
    .await?;
    if let Some(keys) = response.get("keys") {
        keys.clone()
    } else {
        bail!("No keys found in request to jwks endpoint")
    }
}

#[throws(anyhow::Error)]
pub fn find_jwk(kid: String, keys: Vec<JWK>) -> JWK {
    let mut iter = keys.iter();
    let header = iter.find(|&x| x.kid == Some(kid.clone()));
    if let Some(found) = header {
        found.clone()
    } else {
        bail!("No key corresponding to kid {} found in the jkws", kid)
    }
}

    