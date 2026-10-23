# AWS Lambda Web Functions POC

This proof of concept runs an all-TypeScript, server-rendered Express application directly as an AWS Lambda Web Function. Amazon CloudFront is the public entry point and uses Origin Access Control to sign requests to an IAM-authenticated Lambda Web Function endpoint. Amazon Cognito Managed Login provides OIDC authorization-code authentication with PKCE; identity and tokens remain in an encrypted, `HttpOnly` session cookie.

The CDK application is split into two stacks to avoid a CloudFormation dependency cycle: `AuthStack` creates Cognito, then `WebAppStack` creates the Web Function and CloudFront distribution and registers the final CloudFront callback URLs through a scoped custom resource.

## Prerequisites

- Node.js 24 and npm
- AWS credentials with permission to bootstrap/deploy CDK resources
- An IAM managed policy named `developer-policy` in the target account; CDK applies it as the permissions boundary to all roles it creates
- AWS CDK CLI 2.1146.1 or newer (the project includes a compatible CLI)
- An AWS region that supports Lambda Web Functions; the commands below use `eu-west-1`
- The current AWS CLI if you want to inspect Web Function endpoints directly

The examples below use the `moonbeam` AWS profile. Set it once so both AWS CLI and CDK commands use the same account:

```sh
export AWS_PROFILE=moonbeam
```

## Local development

Install dependencies:

```sh
npm install
```

### Deploy the auth stack

The auth-only deployment creates the Cognito user pool, Managed Login domain, default branding style, and local OAuth client without creating CloudFront or Lambda resources:

```sh
npx cdk deploy AuthStack \
  --region eu-west-1 \
  --require-approval never \
  -c authOnly=true
```

Self-sign-up is disabled, so users must be created with the AWS CLI. Get the user-pool ID from the stack outputs:

```sh
aws cloudformation describe-stacks \
  --stack-name AuthStack \
  --region eu-west-1 \
  --query 'Stacks[0].Outputs'
```

Create a user administratively. The temporary password must meet the password policy; the second command makes it permanent. Replace the username, email, and passwords with your own values:

```sh
POOL_ID="$(aws cloudformation describe-stacks \
  --stack-name AuthStack \
  --region eu-west-1 \
  --query "Stacks[0].Outputs[?OutputKey=='CognitoUserPoolId'].OutputValue" \
  --output text)"

aws cognito-idp admin-create-user \
  --user-pool-id "$POOL_ID" \
  --username user@example.com \
  --user-attributes Name=email,Value=user@example.com Name=email_verified,Value=true \
  --temporary-password 'TempPassword123!'

aws cognito-idp admin-set-user-password \
  --user-pool-id "$POOL_ID" \
  --username user@example.com \
  --password 'PermanentPassword123!' \
  --permanent
```

### Configure and run locally

Build the application:

```sh
npm run build
```

Load the Cognito values from CloudFormation:

```sh
export COGNITO_CLIENT_ID="$(aws cloudformation describe-stacks \
  --stack-name AuthStack --region eu-west-1 \
  --query "Stacks[0].Outputs[?OutputKey=='CognitoClientId'].OutputValue" \
  --output text)"

export COGNITO_ISSUER="$(aws cloudformation describe-stacks \
  --stack-name AuthStack --region eu-west-1 \
  --query "Stacks[0].Outputs[?OutputKey=='CognitoIssuer'].OutputValue" \
  --output text)"

export COGNITO_AUTH_DOMAIN="$(aws cloudformation describe-stacks \
  --stack-name AuthStack --region eu-west-1 \
  --query "Stacks[0].Outputs[?OutputKey=='CognitoAuthDomain'].OutputValue" \
  --output text)"
```

`COGNITO_ISSUER` is the user-pool issuer used for JWT validation and OIDC discovery. `COGNITO_AUTH_DOMAIN` is the Managed Login domain used by Cognito’s authorization and logout endpoints. Verify the issuer before starting the app:

```sh
curl --fail --silent --show-error \
  "$COGNITO_ISSUER/.well-known/openid-configuration" >/dev/null \
  && echo 'Cognito discovery OK'
```

Start the local server:

```sh
export NODE_ENV=development
export SESSION_SECRET="$(openssl rand -base64 32)"
npm start
```

The local server listens on `127.0.0.1:3000`. Open `http://localhost:3000`, choose **Sign in with Cognito**, and sign in with the administrative user. The auth-only client allows `http://localhost:3000/oauth2/callback` and `http://localhost:3000`.

Local cookies are non-secure because the local server uses HTTP. If Safari retains stale authentication state, use a private window or clear cookies for `localhost:3000`.

The auth stack defines an API resource server with the custom scopes `api/read` and `api/write`. The login request asks Cognito for both scopes, so the token response includes an access token whose `scope` claim contains them. The ID token and access token are separate tokens: the access token is not derived from the ID token. In this POC, both are stored inside the encrypted session cookie for server-side use; browser JavaScript does not receive either token.

## Deploy

Bootstrap the account and region once if needed:

```sh
npx cdk bootstrap aws://ACCOUNT_ID/eu-west-1 \
  --custom-permissions-boundary developer-policy
```

The `--custom-permissions-boundary` option applies `developer-policy` to the CDK bootstrap roles. The stack also applies the same boundary to application-created roles. The deploying principal must be allowed to pass/use the boundary when creating IAM roles, and the policy must already exist in the account before deployment. Re-run the bootstrap command for an existing environment if its bootstrap roles need to be updated.

Deploy with a strong secret supplied through CDK context. Do not put the secret in `cdk.json`, source control, or shell history used for shared environments:

```sh
npx cdk deploy --all \
  --region eu-west-1 \
  --require-approval never \
  -c sessionSecret="$(openssl rand -base64 32)"
```

To avoid collisions in the Cognito hosted UI domain prefix, optionally provide one:

```sh
npx cdk deploy --all \
  --region eu-west-1 \
  --require-approval never \
  -c cognitoDomainPrefix=my-lambda-web-poc-unique \
  -c sessionSecret="$(openssl rand -base64 32)"
```

The outputs include the CloudFront URL, Cognito issuer, Managed Login URL, OAuth callback URL, client ID, and raw Lambda Web Function endpoint. Self-sign-up remains disabled; create users with `admin-create-user` before visiting the CloudFront URL and choosing **Sign in with Cognito**.

The Web Function endpoint is configured with `IamAuth`, so a direct unsigned request should fail:

```sh
curl -i https://RAW_LAMBDA_WEB_FUNCTION_ENDPOINT/
```

The same request through the CloudFront URL should succeed because CloudFront signs the origin request with OAC.

## Cleanup

```sh
npx cdk destroy --all --force --region eu-west-1
```

## POC boundaries

This repository intentionally excludes custom domains and certificates, WAF, CI/CD, a database, multi-region routing, and an automated test suite. Dynamic authenticated pages use CloudFront's managed disabled-cache policy; the app does not expose access or ID tokens to browser JavaScript.
