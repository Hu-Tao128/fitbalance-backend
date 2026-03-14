import { Request, Response } from 'express';

export type { Request, Response };

export interface ILoginRequest {
  username: string;
  password: string;
}

export interface ILoginResponse {
  message: string;
  patient: any;
}

export interface IChangePasswordRequest {
  patient_id: string;
  currentPassword: string;
  newPassword: string;
}

export interface ISendResetCodeRequest {
  email: string;
}

export interface IUpdatePatientRequest {
  name?: string;
  email?: string;
  phone?: string;
  age?: number;
  gender?: 'male' | 'female' | 'other';
  height_cm?: number;
  weight_kg?: number;
  objective?: string;
  allergies?: string[];
  dietary_restrictions?: string[];
  notes?: string;
  nutritionist_id?: string;
}

export interface IAddMealRequest {
  patient_id: string;
  meal: {
    day?: string;
    type: 'breakfast' | 'lunch' | 'dinner' | 'snack';
    time: string;
    foods: Array<{
      food_id: string;
      grams: number;
    }>;
  };
  weight?: number;
}

export interface IDailyLogByDateQuery {
  patient_id: string;
  date: string;
}

export interface IAddFoodRequest {
  patient_id: string;
  type: 'breakfast' | 'lunch' | 'dinner' | 'snack';
  time: string;
  food_data: {
    food_name: string;
    serving_weight_grams?: number;
    category?: string;
    nf_calories?: number;
    nf_protein?: number;
    nf_total_carbohydrate?: number;
    nf_total_fat?: number;
    nf_dietary_fiber?: number;
    nf_sugars?: number;
  };
}

export interface ICreatePatientMealRequest {
  patient_id: string;
  name: string;
  ingredients: Array<{
    food_id: string;
    amount_g: number;
  }>;
  nutrients: {
    energy_kcal: number;
    protein_g: number;
    carbohydrates_g: number;
    fat_g: number;
    fiber_g: number;
    sugar_g: number;
  };
  instructions?: string;
}

export interface IAddCustomMealRequest {
  patient_id: string;
  meal_id: string;
  type: 'breakfast' | 'lunch' | 'dinner' | 'snack';
  time: string;
}

export interface IApiResponse<T = any> {
  message?: string;
  error?: string;
  details?: string;
  [key: string]: T | string | undefined;
}

export interface ITodayMealLogResponse {
  date: Date;
  totals: {
    calories: number;
    protein: number;
    fat: number;
    carbs: number;
  };
  meals: any[];
  notes?: string;
}

export interface IWeeklyPlanResponse {
  _id?: any;
  patient_id: any;
  week_start?: Date;
  dailyCalories: number;
  protein: number;
  fat: number;
  carbs: number;
  meals: any[];
}

export interface IDailyNutritionQuery {
  patient_id: string;
  date: string;
}

export interface IDailyNutritionResponse {
  date: Date;
  consumed: {
    calories: number;
    protein: number;
    fat: number;
    carbs: number;
  };
  meals: any[];
}

export interface PopulatedFood {
  _id: any;
  name: string;
  portion_size_g?: number;
  nutrients?: {
    calories?: number;
    protein?: number;
    fat?: number;
    carbs?: number;
  };
}

export interface PopulatedIngredient {
  food_id: PopulatedFood;
  amount_g: number;
}

export interface PopulatedPatientMeal {
  _id: any;
  patient_id: any;
  name: string;
  ingredients: PopulatedIngredient[];
  nutrients: {
    energy_kcal: number;
    protein_g: number;
    carbohydrates_g: number;
    fat_g: number;
    fiber_g: number;
    sugar_g: number;
  };
  instructions?: string;
}
