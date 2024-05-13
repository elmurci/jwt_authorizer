use serde::{Serialize, Deserialize};
use strum_macros::EnumString;
use strum_macros::Display;

#[derive(Debug, Serialize, Deserialize)]
pub enum Effect {
    Allow,
    Deny,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum StringOrArray {
    Str(String),
    StrArray(Vec<String>),   
}

#[derive(Serialize, Deserialize, EnumString, Display)]
pub enum HttpMethod {
    #[serde(rename = "GET")]
    GET,
    #[serde(rename = "POST")]
    POST,
    #[serde(rename = "PUT")]
    PUT,
    #[serde(rename = "DELETE")]
    DELETE,
    #[serde(rename = "PATCH")]
    PATCH,
    #[serde(rename = "HEAD")]
    HEAD,
    #[serde(rename = "OPTIONS")]
    OPTIONS,
    #[serde(rename = "*")]
    ALL,
}

#[derive(Clone, Deserialize, Debug)]
pub enum KeyType { 
    RSA
}

#[derive(Clone, Deserialize, Debug)]
pub enum KeyAlgorithm {
    RS256
}