import * as cdk from 'aws-cdk-lib';
import { aws_cognito as cognito } from 'aws-cdk-lib';
import { Construct } from 'constructs';

export class AuthStack extends cdk.Stack {
  readonly clientId: string;
  readonly clientArn: string;
  readonly userPoolId: string;
  readonly issuer: string;
  readonly authDomain: string;

  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    const domainPrefix = this.node.tryGetContext('cognitoDomainPrefix') ?? `${this.stackName.toLowerCase()}-${this.account}`;
    const userPool = new cognito.UserPool(this, 'UserPool', {
      selfSignUpEnabled: false,
      signInAliases: { email: true },
      standardAttributes: { email: { required: true, mutable: true } },
      featurePlan: cognito.FeaturePlan.ESSENTIALS,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });
    const domain = userPool.addDomain('HostedUiDomain', { cognitoDomain: { domainPrefix } });
    const cfnDomain = domain.node.defaultChild as cognito.CfnUserPoolDomain;
    cfnDomain.managedLoginVersion = 2;
    const apiReadScope = new cognito.ResourceServerScope({
      scopeName: 'read',
      scopeDescription: 'Read API data',
    });
    const apiWriteScope = new cognito.ResourceServerScope({
      scopeName: 'write',
      scopeDescription: 'Write API data',
    });
    const apiServer = userPool.addResourceServer('ApiResourceServer', {
      identifier: 'api',
      userPoolResourceServerName: 'POC API',
      scopes: [apiReadScope, apiWriteScope],
    });
    const client = new cognito.UserPoolClient(this, 'UserPoolClient', {
      userPool,
      generateSecret: false,
      oAuth: {
        flows: { authorizationCodeGrant: true },
        scopes: [
          cognito.OAuthScope.OPENID,
          cognito.OAuthScope.EMAIL,
          cognito.OAuthScope.PROFILE,
          cognito.OAuthScope.resourceServer(apiServer, apiReadScope),
          cognito.OAuthScope.resourceServer(apiServer, apiWriteScope),
        ],
        callbackUrls: ['http://localhost:3000/oauth2/callback'],
        logoutUrls: ['http://localhost:3000'],
      },
    });
    const branding = new cognito.CfnManagedLoginBranding(this, 'ManagedLoginBranding', {
      clientId: client.userPoolClientId,
      userPoolId: userPool.userPoolId,
      useCognitoProvidedValues: true,
    });
    branding.node.addDependency(cfnDomain);

    this.clientId = client.userPoolClientId;
    this.clientArn = `arn:${this.partition}:cognito-idp:${this.region}:${this.account}:userpoolclient/${this.clientId}`;
    this.userPoolId = userPool.userPoolId;
    this.authDomain = `https://${domainPrefix}.auth.${this.region}.amazoncognito.com`;
    this.issuer = `https://cognito-idp.${this.region}.amazonaws.com/${this.userPoolId}`;
    new cdk.CfnOutput(this, 'CognitoIssuer', { value: this.issuer });
    new cdk.CfnOutput(this, 'CognitoAuthDomain', { value: this.authDomain });
    new cdk.CfnOutput(this, 'CognitoClientId', { value: this.clientId });
    new cdk.CfnOutput(this, 'CognitoUserPoolId', { value: this.userPoolId });
  }
}
