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
