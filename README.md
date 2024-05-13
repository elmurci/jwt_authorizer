# Boto Authorization Service

Rust service that validates JWT tokens from Auth0.

The service:

1. Retrieves the JWKS and filter for potential signature verification keys. 
2. Extracts the JWT from the request's authorization header.
3. Decodes the JWT and grab the kid property from the header.
4. Finds the signature verification key in the filtered JWKS with a matching kid property.
5. Using the x5c property build a certificate which will be used to verify the JWT signature.
6. Ensures the JWT contains the expected audience, issuer, expiration, etc.
7. Returns the verification result and pass Audience, Issuer and Sub to the lambda.

## Env Variables

| Name  | Description  |
|---|---|
| BOTO_KEYS_REPO  | Repo where the keys to validate the token reside (Example: https://boto.eu.auth0.com/.well-known/jwks.json)  | 
| BOTO_TOKEN_AUDIENCE  | Token audience  | 
| BOTO_TOKEN_ISSUER  | Token issuer  | 

## Custom Claim

This service extracts the value of the custom claim `https://boto.io/claims/user_id` (Boto ID) to the downstream services.

## Run

```
cargo run
```

## Build

```
cargo build
```

## Test

### DynamoDB Local

```
cd tests && docker-compose up
```

### Run Unit tests

```
cargo test -- --nocapture
```

### Run Integration tests only

```
cargo test --test '*' -- --nocapture
```

## TODO

- Retrieve from the Redis cache the JWKS.