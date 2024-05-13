use std::env;

use log::debug;
use lambda_runtime::{handler_fn, Context, Error};
use anyhow::Result;
use serde_json::json;
use structs::{APIGatewayCustomAuthorizerRequest, APIGatewayCustomAuthorizerResponse, APIGatewayPolicyBuilder};
use auth::Auth;

mod structs;
mod enums;
mod utils;
mod auth;

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<(), Error> {
    env_logger::init();
    let func = handler_fn(execute);
    lambda_runtime::run(func).await?;
    Ok(())
}

async fn execute(event: APIGatewayCustomAuthorizerRequest, _context: Context) -> Result<APIGatewayCustomAuthorizerResponse, Error> {
    debug!(target: "main.arn", "Method ARN: {}", event.method_arn);
    let token = str::replace(&event.authorization_token.to_string(), "Bearer ", "");
    debug!(target: "main.token", "Token: {:?}", &token);
    // this could be accomplished in a number of ways:
    // 1. Validate and Decode JWT and produce the principal user identifier associated with the token
    // 2. Lookup in DynamoBD (user blocked?), TODO: check token.sub in our DB
  
    // if the token is valid, a policy must be generated which will allow or deny access to the client
    //     - if access is denied, the client will recieve a 403 Access Denied response
    //     - if access is allowed, API Gateway will proceed with the backend integration configured on the method that was called

    // the policy is cached for 5 minutes by default (TTL is configurable in the authorizer)
    // and will apply to subsequent calls to any method/resource in the API
    // made with the same token
    let tmp: Vec<&str> = event.method_arn.split(":").collect();
    let api_gateway_arn_tmp: Vec<&str> = tmp[5].split("/").collect();
    let aws_account_id = tmp[4];
    let region = tmp[3];
    let rest_api_id = api_gateway_arn_tmp[0];
    let stage = api_gateway_arn_tmp[1];

    debug!(target: "main.arn","aws_account_id: {}, region: {}, rest_api_id: {}, stage: {}", aws_account_id, region, rest_api_id, stage);

    // TODO! -- add additional key-value pairs associated with the authenticated principal
    // these are made available by APIGW like so: $context.authorizer.<key>
    // additional context is cached
    let audience = env::var("JWTAUTH_TOKEN_AUDIENCE").expect("Please specify an audience as env var");
    let issuer = env::var("JWTAUTH_TOKEN_ISSUER").expect("Please specify an issuer as env var");
    // TODO: cache this
    let keys_repo = env::var("JWTAUTH_KEYS_REPO").expect("Please specify a keys repo (jwk) as env var");
    let keys = utils::get_jwks(keys_repo).await?;
    let mut auth = Auth::new(
        audience, issuer, keys
    );
    match auth.validate_token(&token.to_string()) {
        Ok(token_data) => {
            debug!(target: "main.ok", "Token is valid, claims: {:?}", &token_data);
            let token_claims = token_data.claims;
            let principal_id = token_claims.sub;
            // allows access to all resources in the API
            let policy = APIGatewayPolicyBuilder::new(region, aws_account_id, rest_api_id, stage)
            .allow_all_methods()
            .build();
            // TODO: reduce access to just the required resource (botos, users...) instead of *
            debug!(target: "main.policy", "Policy is: {:?}", &policy);
            let user_id = token_claims.user_id;
            let gateway_response = APIGatewayCustomAuthorizerResponse {
                principal_id: user_id.clone(),
                policy_document: policy,
                context: json!({
                    "sub": principal_id,
                    "user_id": user_id
                })
            };
            debug!(target: "main.response", "Gateway Response: {:?}", &gateway_response);
            return Ok(gateway_response)
            // if we want to deny access, for example, the user is blocked
            // Access Denied, 401
            // let policy = APIGatewayPolicyBuilder::new(region, aws_account_id, rest_api_id, stage)
            // .deny_all_methods()
            // .build();
            // return APIGatewayCustomAuthorizerResponse {
            //     principal_id: principal_id.to_string(),
            //     policy_document: policy,
            //     context: json!({
            //     "stringKey": "stringval",
            //     "numberKey": 123,
            //     "booleanKey": true
            //   })
            // }
        },
        Err(error) => {
            // Forbidden, 403
            let error_string = format!("Error validating token: {}", error.root_cause());
            debug!(target: "main.error", "Token is invalid, {}", error_string);
            // allows access to all resources in the API
            let policy = APIGatewayPolicyBuilder::new(region, aws_account_id, rest_api_id, stage)
            .deny_method(enums::HttpMethod::GET, "boto".to_string())
            .build();
            debug!(target: "main.policy", "Policy is: {:?}", &policy);
            let gateway_response = APIGatewayCustomAuthorizerResponse {
                principal_id: "user".to_string(),
                policy_document: policy,
                context: json!({
                    "messageDescription": error_string,
                    "messageType": "Access Denied".to_string()
                })
            };
            debug!(target: "main.response", "Gateway Response: {:?}", &gateway_response);
            return Ok(gateway_response)
        }
    };
}
