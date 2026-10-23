import * as cdk from 'aws-cdk-lib';
import { AuthStack } from './auth-stack.js';
import { WebAppStack } from './web-app-stack.js';

const app = new cdk.App();
const auth = new AuthStack(app, 'AuthStack', {
  description: 'Cognito foundation for the Lambda Web Function POC',
});
const authOnly = app.node.tryGetContext('authOnly') === true || app.node.tryGetContext('authOnly') === 'true';
if (!authOnly) {
  new WebAppStack(app, 'WebAppStack', {
    description: 'CloudFront and Lambda Web Function for the TypeScript web POC',
    auth,
  });
}
