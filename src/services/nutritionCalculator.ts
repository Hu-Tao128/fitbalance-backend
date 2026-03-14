import { Types } from 'mongoose';
import { Food, IDailyMealLog } from '../models';

export interface DailyTotals {
  totalCalories: number;
  totalProtein: number;
  totalFat: number;
  totalCarbs: number;
  caloriesConsumed: number;
}

export async function calculateDailyTotals(dailyLog: IDailyMealLog): Promise<DailyTotals> {
  let totalCalories = 0;
  let totalProtein = 0;
  let totalFat = 0;
  let totalCarbs = 0;

  const foodIds = dailyLog.meals.flatMap((meal) =>
    meal.foods.map((food) => new Types.ObjectId(food.food_id))
  );

  const foods = await Food.find({ _id: { $in: foodIds } }).lean();

  for (const meal of dailyLog.meals) {
    for (const foodItem of meal.foods) {
      const food = foods.find((f) => f._id.equals(foodItem.food_id));
      if (food) {
        const ratio = foodItem.grams / (food.portion_size_g || 1);

        if (foodItem.nutrients?.calories) {
          totalCalories += foodItem.nutrients.calories;
        } else if (food.nutrients?.energy_kcal) {
          totalCalories += food.nutrients.energy_kcal * ratio;
        }

        if (foodItem.nutrients?.protein) {
          totalProtein += foodItem.nutrients.protein;
        } else if (food.nutrients?.protein_g) {
          totalProtein += food.nutrients.protein_g * ratio;
        }

        if (foodItem.nutrients?.fat) {
          totalFat += foodItem.nutrients.fat;
        } else if (food.nutrients?.fat_g) {
          totalFat += food.nutrients.fat_g * ratio;
        }

        if (foodItem.nutrients?.carbs) {
          totalCarbs += foodItem.nutrients.carbs;
        } else if (food.nutrients?.carbohydrates_g) {
          totalCarbs += food.nutrients.carbohydrates_g * ratio;
        }
      }
    }
  }

  const totals: DailyTotals = {
    totalCalories: Math.round(totalCalories || 0),
    totalProtein: Math.round(totalProtein || 0),
    totalFat: Math.round(totalFat || 0),
    totalCarbs: Math.round(totalCarbs || 0),
    caloriesConsumed: Math.round(totalCalories || 0),
  };

  dailyLog.totalCalories = totals.totalCalories;
  dailyLog.totalProtein = totals.totalProtein;
  dailyLog.totalFat = totals.totalFat;
  dailyLog.totalCarbs = totals.totalCarbs;
  dailyLog.caloriesConsumed = totals.caloriesConsumed;

  return totals;
}
