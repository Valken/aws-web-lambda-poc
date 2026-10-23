import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as cdk from 'aws-cdk-lib';
import { aws_cloudfront as cloudfront, custom_resources as customResources, aws_iam as iam, aws_lambda as lambda, aws_s3 as s3, aws_s3_deployment as s3deploy } from 'aws-cdk-lib';
import { Construct } from 'constructs';
import { AuthStack } from './auth-stack.js';

export class WebAppStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: cdk.StackProps & { auth: AuthStack }) {
    super(scope, id, props);

    const developerPolicy = iam.ManagedPolicy.fromManagedPolicyName(this, 'DeveloperPolicyBoundary', 'developer-policy');
    iam.PermissionsBoundary.of(this).apply(developerPolicy);

    const sessionSecret = this.node.tryGetContext('sessionSecret');
    if (typeof sessionSecret !== 'string' || sessionSecret.length < 32) {
      throw new Error('Provide a session secret with at least 32 characters using: cdk deploy -c sessionSecret=<secret>');
    }

    const originAccessControl = new cloudfront.CfnOriginAccessControl(this, 'WebFunctionOac', {
      originAccessControlConfig: {
        name: `${this.stackName}-web-function`,
        description: 'CloudFront signing for the Lambda Web Function origin',
        originAccessControlOriginType: 'lambda',
        signingBehavior: 'always-amz-auth',
        signingProtocol: 'sigv4',
      },
    });
    const codeBucket = new s3.Bucket(this, 'WebFunctionCodeBucket', {
      versioned: true,
      enforceSSL: true,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      encryption: s3.BucketEncryption.S3_MANAGED,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      autoDeleteObjects: true,
    });
    codeBucket.addToResourcePolicy(new iam.PolicyStatement({
      principals: [new iam.ServicePrincipal('lambda.amazonaws.com')],
      actions: ['s3:GetObject', 's3:GetObjectVersion'],
      resources: [codeBucket.arnForObjects('*')],
      conditions: { StringEquals: { 'aws:SourceAccount': this.account } },
    }));
    const code = s3deploy.Source.asset(path.join(path.dirname(fileURLToPath(import.meta.url)), '../web'));
    const upload = new s3deploy.BucketDeployment(this, 'UploadWebFunctionCode', {
      sources: [code],
      destinationBucket: codeBucket,
      extract: false,
      prune: false,
      memoryLimit: 1024,
    });
    const codeKey = cdk.Fn.select(0, upload.objectKeys);
    const executionRole = new iam.Role(this, 'WebFunctionExecutionRole', {
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
      managedPolicies: [iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AWSLambdaBasicExecutionRole')],
    });
    const webFunction = new lambda.CfnWebFunction(this, 'WebFunction', {
      functionName: `${this.stackName.toLowerCase()}-web`,
      tags: [{ key: 'Project', value: this.stackName }],
    });
    const environmentVariables: Record<string, string> = {
      AWS_LAMBDA_NODEJS_ENTRYPOINT: 'server.js',
      NODE_ENV: 'production',
      COGNITO_CLIENT_ID: props.auth.clientId,
      COGNITO_ISSUER: props.auth.issuer,
      COGNITO_AUTH_DOMAIN: props.auth.authDomain,
      SESSION_SECRET: sessionSecret,
    };
    const revision = new lambda.CfnWebFunctionRevision(this, 'WebFunctionRevision', {
      functionName: webFunction.functionName,
      buildConfig: {
        codeConfig: { s3Object: { bucket: upload.deployedBucket.bucketName, key: codeKey } },
        runtimeConfig: { runtime: 'nodejs24.x' },
      },
      serviceConfig: { executionRoleArn: executionRole.roleArn, environmentVariables },
    });
    revision.addDependency(webFunction);
    revision.node.addDependency(executionRole, upload);
    const endpoint = new lambda.CfnWebFunctionEndpoint(this, 'WebFunctionEndpoint', {
      functionName: webFunction.functionName,
      endpointName: 'dev',
      endpointType: 'HomeRegion',
      authType: 'IamAuth',
      revisionWeights: [{ revisionId: revision.attrRevisionId, weight: 100 }],
    });
    endpoint.addDependency(revision);
    const viewerHostHeaderFunction = new cloudfront.Function(this, 'ViewerHostHeaderFunction', {
      code: cloudfront.FunctionCode.fromInline(
        'function handler(event) { var request = event.request; request.headers["x-forwarded-host"] = { value: request.headers.host.value }; return request; }',
      ),
    });
    const distribution = new cloudfront.CfnDistribution(this, 'Distribution', {
      distributionConfig: {
        enabled: true,
        comment: 'Lambda Web Function POC',
        httpVersion: 'http2and3',
        priceClass: 'PriceClass_100',
        origins: [{
          id: 'LambdaWebFunctionOrigin',
          domainName: endpoint.attrDomainName,
          originAccessControlId: originAccessControl.attrId,
          customOriginConfig: { originProtocolPolicy: 'https-only', httpsPort: 443, httpPort: 80, originSslProtocols: ['TLSv1.2'] },
        }],
        defaultCacheBehavior: {
          targetOriginId: 'LambdaWebFunctionOrigin',
          viewerProtocolPolicy: 'redirect-to-https',
          cachePolicyId: '4135ea2d-6df8-44a3-9df3-4b5a84be39ad',
          originRequestPolicyId: 'b689b0a8-53d0-40ab-baf2-68738e2966ac',
          allowedMethods: ['GET', 'HEAD', 'OPTIONS', 'PUT', 'POST', 'PATCH', 'DELETE'],
          cachedMethods: ['GET', 'HEAD'],
          compress: true,
          functionAssociations: [{
            eventType: 'viewer-request',
            functionArn: viewerHostHeaderFunction.functionArn,
          }],
        },
        restrictions: { geoRestriction: { restrictionType: 'none' } },
        viewerCertificate: { cloudFrontDefaultCertificate: true },
      },
    });
    distribution.addDependency(endpoint);
    originAccessControl.addDependency(endpoint);

    const cloudFrontUrl = `https://${distribution.attrDomainName}`;
    new customResources.AwsCustomResource(this, 'RegisterCloudFrontCallbacks', {
      onCreate: {
        service: 'CognitoIdentityServiceProvider',
        action: 'updateUserPoolClient',
        parameters: {
          UserPoolId: props.auth.userPoolId,
          ClientId: props.auth.clientId,
          AllowedOAuthFlows: ['code'],
          AllowedOAuthFlowsUserPoolClient: true,
          AllowedOAuthScopes: ['openid', 'email', 'profile', 'api/read', 'api/write'],
          CallbackURLs: [`${cloudFrontUrl}/oauth2/callback`],
          LogoutURLs: [cloudFrontUrl],
          SupportedIdentityProviders: ['COGNITO'],
        },
        physicalResourceId: customResources.PhysicalResourceId.of(`${props.auth.clientId}-cloudfront-callbacks`),
      },
      onUpdate: {
        service: 'CognitoIdentityServiceProvider',
        action: 'updateUserPoolClient',
        parameters: {
          UserPoolId: props.auth.userPoolId,
          ClientId: props.auth.clientId,
          AllowedOAuthFlows: ['code'],
          AllowedOAuthFlowsUserPoolClient: true,
          AllowedOAuthScopes: ['openid', 'email', 'profile', 'api/read', 'api/write'],
          CallbackURLs: [`${cloudFrontUrl}/oauth2/callback`],
          LogoutURLs: [cloudFrontUrl],
          SupportedIdentityProviders: ['COGNITO'],
        },
        physicalResourceId: customResources.PhysicalResourceId.of(`${props.auth.clientId}-cloudfront-callbacks`),
      },
      policy: customResources.AwsCustomResourcePolicy.fromStatements([
        new iam.PolicyStatement({
          actions: ['cognito-idp:UpdateUserPoolClient'],
          resources: [`arn:${this.partition}:cognito-idp:${this.region}:${this.account}:userpool/${props.auth.userPoolId}`],
        }),
      ]),
    });

    const policy = new lambda.CfnResourcePolicy(this, 'CloudFrontInvokePolicy', {
      resourceArn: webFunction.attrFunctionArn,
      policyDocument: {
        Version: '2012-10-17',
        Statement: [{
          Sid: 'AllowCloudFrontOacAccess',
          Effect: 'Allow',
          Principal: { Service: 'cloudfront.amazonaws.com' },
          Action: 'lambda:InvokeWebFunctionEndpoint',
          Resource: `${webFunction.attrFunctionArn}/endpoint/${endpoint.endpointName}`,
          Condition: { StringEquals: { 'AWS:SourceArn': `arn:${this.partition}:cloudfront::${this.account}:distribution/${distribution.ref}` } },
        }],
      },
    });
    policy.addDependency(distribution);
    policy.addDependency(endpoint);

    new cdk.CfnOutput(this, 'CloudFrontUrl', { value: cloudFrontUrl });
    new cdk.CfnOutput(this, 'CognitoIssuer', { value: props.auth.issuer });
    new cdk.CfnOutput(this, 'CognitoClientId', { value: props.auth.clientId });
    new cdk.CfnOutput(this, 'CognitoCallbackUrl', { value: `${cloudFrontUrl}/oauth2/callback` });
    new cdk.CfnOutput(this, 'CognitoHostedUiUrl', { value: props.auth.authDomain });
    new cdk.CfnOutput(this, 'LambdaWebFunctionEndpoint', { value: endpoint.attrDomainName });
  }
}
