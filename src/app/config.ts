export interface AppConfig {
  clientId: string;
  clientSecret?: string;
  issuer: string;
  authDomain: string;
  sessionSecret: string;
  port: number;
  host: string;
}

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`Missing required environment variable: ${name}`);
  return value;
}

export function loadConfig(): AppConfig {
  const endpoint = process.env.AWS_LAMBDA_HTTP_ENDPOINT ?? '127.0.0.1:3000';
  const [host, portText] = endpoint.split(':');
  const port = Number(portText);
  if (!host || !Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`AWS_LAMBDA_HTTP_ENDPOINT must be host:port, received "${endpoint}"`);
  }

  return {
    clientId: required('COGNITO_CLIENT_ID'),
    clientSecret: process.env.COGNITO_CLIENT_SECRET,
    issuer: required('COGNITO_ISSUER').replace(/\/$/, ''),
    authDomain: required('COGNITO_AUTH_DOMAIN').replace(/\/$/, ''),
    sessionSecret: required('SESSION_SECRET'),
    host,
    port,
  };
}
