export function getEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`La variable ${name} no esta definida en process.env`);
  }
  return value;
}

export const PORT = process.env.PORT || 3000;

export const MONGODB_URI = getEnv('MONGODB_URI');
export const FATSECRET_CONSUMER_KEY = getEnv('FATSECRET_CONSUMER_KEY');
export const FATSECRET_CONSUMER_SECRET = getEnv('FATSECRET_CONSUMER_SECRET');
export const NUTRITIONIX_APP_ID = getEnv('NUTRITIONIX_APP_ID');
export const NUTRITIONIX_APP_KEY = getEnv('NUTRITIONIX_APP_KEY');

export const SALT_ROUNDS = 10;
export const JWT_SECRET: string = getEnv('JWT_SECRET');

export const serviceAccount = {
  type: 'service_account',
  project_id: getEnv('FIREBASE_PROJECT_ID'),
  private_key_id: getEnv('FIREBASE_PRIVATE_KEY_ID'),
  private_key: getEnv('FIREBASE_PRIVATE_KEY').replace(/\\n/g, '\n'),
  client_email: getEnv('FIREBASE_CLIENT_EMAIL'),
  client_id: getEnv('FIREBASE_CLIENT_ID'),
  auth_uri: 'https://accounts.google.com/o/oauth2/auth',
  token_uri: 'https://oauth2.googleapis.com/token',
  auth_provider_x509_cert_url: 'https://www.googleapis.com/oauth2/v1/certs',
  client_x509_cert_url: `https://www.googleapis.com/robot/v1/metadata/x509/${getEnv('FIREBASE_CLIENT_EMAIL')}`,
};
