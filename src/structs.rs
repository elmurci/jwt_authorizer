use std::{error::Error, fmt};
use serde::{Serialize, Deserialize};
use serde_json::Value;
use crate::enums::{Effect, HttpMethod, KeyAlgorithm, KeyType, StringOrArray};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,
    pub iss: String,
    pub aud: StringOrArray,
    pub iat: usize,
    pub exp: usize,
    pub azp: String,
    pub gty: Option<String>,
    #[serde(rename = "https://boto.io/claims/user_id")]
    pub user_id: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct JWK {
    pub kty: KeyType,
    pub alg: Option<KeyAlgorithm>,
    pub kid: Option<String>,
    // Shared modulus
    pub n: String,
    // Public key exponent
    pub e: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LambdaResponse {
    pub status_code: u16,
    pub body: String,
}

#[derive(Debug, Clone)]
pub struct LambdaError {
    pub is_authenticated: bool,
    pub req_id: String,
    pub msg: String,
}

// Error doesn't require you to implement any methods, but
// your type must also implement Debug and Display.
impl<'a> Error for LambdaError {}

impl<'a> fmt::Display for LambdaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Delegate to the Display impl for `&str`:
        self.msg.fmt(f)
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct APIGatewayCustomAuthorizerResponse {
    pub principal_id: String,
    pub policy_document: APIGatewayCustomAuthorizerPolicy,
    pub context: Value,
}

#[derive(Debug, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct APIGatewayCustomAuthorizerPolicy {
    pub Version: String,
    pub Statement: Vec<IAMPolicyStatement>,
}

#[derive(Debug, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct IAMPolicyStatement {
    pub Action: Vec<String>,
    pub Effect: Effect,
    pub Resource: Vec<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct APIGatewayCustomAuthorizerRequest {
    #[serde(rename = "type")]
    pub _type: String,
    pub authorization_token: String,
    pub method_arn: String,
}

pub struct APIGatewayPolicyBuilder {
    pub region: String,
    pub aws_account_id: String,
    pub rest_api_id: String,
    pub stage: String,
    pub policy: APIGatewayCustomAuthorizerPolicy,
}

impl APIGatewayPolicyBuilder {
    pub fn new(
        region: &str,
        account_id: &str,
        api_id: &str,
        stage: &str,
    ) -> APIGatewayPolicyBuilder {
        Self {
            region: region.to_string(),
            aws_account_id: account_id.to_string(),
            rest_api_id: api_id.to_string(),
            stage: stage.to_string(),
            policy: APIGatewayCustomAuthorizerPolicy {
                Version: "2012-10-17".to_string(),
                Statement: vec![],
            },
        }
    }

    pub fn add_method<T: Into<String>>(
        mut self,
        effect: Effect,
        method: HttpMethod,
        resource: T,
    ) -> Self {
        let m = match method {
            HttpMethod::ALL => "*".to_string(),
            _ => method.to_string()
        };
        let resource_arn = format!(
            "arn:aws:execute-api:{}:{}:{}/{}/{}/{}",
            &self.region,
            &self.aws_account_id,
            &self.rest_api_id,
            &self.stage,
            m,
            resource.into().trim_start_matches("/")
        );

        let stmt = IAMPolicyStatement {
            Effect: effect,
            Action: vec!["execute-api:Invoke".to_string()],
            Resource: vec![resource_arn],
        };

        self.policy.Statement.push(stmt);
        self
    }

    pub fn allow_all_methods(self) -> Self {
        self.add_method(Effect::Allow, HttpMethod::ALL, "*")
    }
    
    // pub fn deny_all_methods(self) -> Self {
    //     self.add_method(Effect::Deny, HttpMethod::ALL, "*")
    // }

    // pub fn allow_method(self, method: HttpMethod, resource: String) -> Self {
    //     self.add_method(Effect::Allow, method, resource)
    // }

    pub fn deny_method(self, method: HttpMethod, resource: String) -> Self {
        self.add_method(Effect::Deny, method, resource)
    }

    // Creates and executes a new child thread.
    pub fn build(self) -> APIGatewayCustomAuthorizerPolicy {
        self.policy
    }
}