import axios from 'axios';
import { NUTRITIONIX_APP_ID, NUTRITIONIX_APP_KEY } from '../config/env';

export interface NutritionixFoodResult {
  food_name: string;
  serving_weight_grams?: number;
  nf_calories?: number;
  nf_protein?: number;
  nf_total_carbohydrate?: number;
  nf_total_fat?: number;
  nf_dietary_fiber?: number;
  nf_sugars?: number;
  brand_name?: string;
  category?: string;
}

export async function searchNutritionixForList(query: string): Promise<NutritionixFoodResult[]> {
  const response = await axios.get('https://trackapi.nutritionix.com/v2/search/instant', {
    params: { query },
    headers: {
      'x-app-id': NUTRITIONIX_APP_ID,
      'x-app-key': NUTRITIONIX_APP_KEY,
    },
  });

  const common = response.data.common || [];
  const branded = response.data.branded || [];

  return [...common, ...branded] as NutritionixFoodResult[];
}

export async function searchFoods(query: string): Promise<NutritionixFoodResult[]> {
  return searchNutritionixForList(query);
}
