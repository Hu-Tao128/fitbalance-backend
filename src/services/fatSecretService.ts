import axios from 'axios';
import { FATSECRET_CONSUMER_KEY, FATSECRET_CONSUMER_SECRET } from '../config/env';

let fatSecretAccessToken: string | null = null;
let fatSecretTokenExpiry = 0;

export async function getFatSecretToken(): Promise<string> {
  const clientId = FATSECRET_CONSUMER_KEY;
  const clientSecret = FATSECRET_CONSUMER_SECRET;

  const credentials = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');

  const response = await axios.post(
    'https://oauth.fatsecret.com/connect/token',
    new URLSearchParams({
      grant_type: 'client_credentials',
      scope: 'basic',
    }),
    {
      headers: {
        Authorization: `Basic ${credentials}`,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
    }
  );

  const token = response.data.access_token;

  if (!token) {
    throw new Error('No se pudo obtener el token de FatSecret');
  }

  return token;
}

export async function searchFatSecretFoods(query: string): Promise<any> {
  const token = await getFatSecretToken();

  const response = await axios.post(
    'https://platform.fatsecret.com/rest/foods/search/v1',
    new URLSearchParams({ expression: query }),
    {
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
    }
  );

  return response.data;
}
