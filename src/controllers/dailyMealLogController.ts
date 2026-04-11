import { Request, Response } from 'express';
import { Types } from 'mongoose';
import { DailyMealLog, Food, PatientMeal, WeeklyPlan } from '../models';
import { calculateDailyTotals } from '../services/nutritionCalculator';
import {
  todayStartInTijuana,
  todayEndInTijuana,
  nowInTijuana,
  parseISODateInTijuana,
  formatDateToISO,
} from '../services/dateService';

export async function getDailyNutrition(req: Request, res: Response): Promise<void> {
  const { patient_id, date } = req.query;

  if (!patient_id || !date) {
    res.status(400).json({ error: 'Missing patient_id or date' });
    return;
  }

  try {
    const pid = new Types.ObjectId(patient_id as string);
    const inputDate = new Date(date as string);

    const startOfDay = new Date(inputDate);
    startOfDay.setHours(0, 0, 0, 0);
    const endOfDay = new Date(startOfDay);
    endOfDay.setHours(23, 59, 59, 999);

    let log = await DailyMealLog.findOne({
      patient_id: pid,
      date: { $gte: startOfDay, $lte: endOfDay },
    });

    if (!log) {
      log = new DailyMealLog({
        patient_id: pid,
        date: startOfDay,
        meals: [],
        totalCalories: 0,
        totalProtein: 0,
        totalFat: 0,
        totalCarbs: 0,
        caloriesConsumed: 0,
      });
      await log.save();
    }

    res.json({
      date: log.date,
      consumed: {
        calories: log.totalCalories || 0,
        protein: log.totalProtein || 0,
        fat: log.totalFat || 0,
        carbs: log.totalCarbs || 0,
      },
      meals: log.meals,
    });
  } catch (error: any) {
    console.error('Error en /daily-nutrition:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
}

export async function getTodayMealLog(req: Request, res: Response): Promise<void> {
  const { patient_id } = req.params;

  if (!Types.ObjectId.isValid(patient_id)) {
    res.status(400).json({ error: 'ID de paciente no valido' });
    return;
  }

  try {
    const pid = new Types.ObjectId(patient_id);
    const start = todayStartInTijuana();
    const end = todayEndInTijuana();

    let log = await DailyMealLog.findOne({
      patient_id: pid,
      date: { $gte: start, $lte: end },
    });

    if (!log) {
      log = new DailyMealLog({
        patient_id: pid,
        date: start,
        meals: [],
        totalCalories: 0,
        totalProtein: 0,
        totalFat: 0,
        totalCarbs: 0,
        caloriesConsumed: 0,
      });
      await log.save();
    }

    if (log.totalCalories === undefined) {
      await calculateDailyTotals(log);
      await log.save();
    }

    res.json({
      date: log.date,
      totals: {
        calories: log.totalCalories || 0,
        protein: log.totalProtein || 0,
        fat: log.totalFat || 0,
        carbs: log.totalCarbs || 0,
      },
      meals: log.meals,
      notes: log.notes,
    });
  } catch (error: any) {
    console.error('Error en /daily-meal-logs/today:', error);
    res
      .status(500)
      .json({ error: 'Error al obtener/crear registro diario', details: error.message });
  }
}

export async function getAllMealLogs(req: Request, res: Response): Promise<void> {
  const { patient_id } = req.params;

  if (!Types.ObjectId.isValid(patient_id)) {
    res.status(400).json({ error: 'ID de paciente no valido' });
    return;
  }

  try {
    const pid = new Types.ObjectId(patient_id);
    const logs = await DailyMealLog.find({ patient_id: pid }).sort({ date: -1 }).lean();

    if (!logs || logs.length === 0) {
      res.json([]);
      return;
    }

    const logsWithTotals = await Promise.all(
      logs.map(async (log) => {
        if (
          log.totalCalories !== undefined &&
          log.totalProtein !== undefined &&
          log.totalFat !== undefined &&
          log.totalCarbs !== undefined
        )
          return log;
        const logDoc = new DailyMealLog(log);
        await calculateDailyTotals(logDoc);
        return logDoc.toObject();
      })
    );

    const formattedLogs = logsWithTotals.map((log) => ({
      date: formatDateToISO(log.date),
      totals: {
        calories: log.totalCalories || 0,
        protein: log.totalProtein || 0,
        fat: log.totalFat || 0,
        carbs: log.totalCarbs || 0,
      },
      meals: log.meals,
      notes: log.notes,
    }));

    res.json(formattedLogs);
  } catch (error: any) {
    console.error('Error en /daily-meal-logs/all:', error);
    res.status(500).json({ error: 'Error al obtener los registros de comidas' });
  }
}

export async function getMealLogByDate(req: Request, res: Response): Promise<void> {
  const { patient_id, date } = req.query;

  if (!patient_id || !date) {
    res.status(400).json({ error: 'patient_id and date are required query parameters.' });
    return;
  }

  if (!Types.ObjectId.isValid(patient_id as string)) {
    res.status(400).json({ error: 'Invalid patient ID.' });
    return;
  }

  try {
    const { startOfDay, endOfDay } = parseISODateInTijuana(date as string);

    const log = await DailyMealLog.findOne({
      patient_id: new Types.ObjectId(patient_id as string),
      date: { $gte: startOfDay, $lte: endOfDay },
    }).populate('meals.foods.food_id', 'name');

    if (!log) {
      res.json({
        _id: null,
        date: startOfDay,
        meals: [],
        totals: { calories: 0, protein: 0, fat: 0, carbs: 0 },
      });
      return;
    }

    res.json({
      _id: log._id,
      date: log.date,
      meals: log.meals,
      totals: {
        calories: log.totalCalories || 0,
        protein: log.totalProtein || 0,
        fat: log.totalFat || 0,
        carbs: log.totalCarbs || 0,
      },
    });
  } catch (error) {
    console.error('Error in /daily-meal-logs/by-date:', error);
    res.status(500).json({ error: 'Server error fetching daily log.' });
  }
}

export async function addMeal(req: Request, res: Response): Promise<void> {
  const { patient_id, meal, weight } = req.body;

  if (!patient_id || !meal) {
    res.status(400).json({ error: 'patient_id y meal son obligatorios.' });
    return;
  }

  try {
    const start = todayStartInTijuana();
    const end = todayEndInTijuana();

    let log = await DailyMealLog.findOne({
      patient_id: new Types.ObjectId(patient_id),
      date: { $gte: start, $lte: end },
    });

    if (!log) {
      log = new DailyMealLog({
        patient_id: new Types.ObjectId(patient_id),
        date: start,
        meals: [],
        totalCalories: 0,
        totalProtein: 0,
        totalFat: 0,
        totalCarbs: 0,
        caloriesConsumed: 0,
      });
    }

    const originalTotal = meal.foods.reduce((s: number, f: any) => s + f.grams, 0) || 1;
    const ratio = weight != null ? weight / originalTotal : 1;

    const foods = meal.foods.map((f: any) => ({
      food_id: new Types.ObjectId(f.food_id),
      grams: Math.round(f.grams * ratio),
    }));

    log.meals.push({
      day: nowInTijuana().weekdayLong!.toLowerCase(),
      type: meal.type,
      time: meal.time,
      foods,
      consumed: true,
      notes: weight != null ? `Porcion pesada: ${Math.round(weight)}g` : `Porcion recomendada`,
    });

    await calculateDailyTotals(log);
    await log.save();

    res.json({ message: 'Comida anadida al log diario', dailyLog: log });
  } catch (err) {
    console.error('Error en add-meal:', err);
    res.status(500).json({ error: 'Error al anadir la comida.' });
  }
}

export async function addWeeklyMeal(req: Request, res: Response): Promise<void> {
  const { patient_id, meal } = req.body;

  if (!patient_id || !meal) {
    res.status(400).json({ error: 'Faltan datos obligatorios (patient_id, meal)' });
    return;
  }

  try {
    const today = todayStartInTijuana();
    today.setHours(0, 0, 0, 0);

    let dailyLog = await DailyMealLog.findOne({ patient_id, date: today });

    if (!dailyLog) {
      dailyLog = new DailyMealLog({
        patient_id,
        date: today,
        meals: [],
        totalCalories: 0,
        totalProtein: 0,
        totalFat: 0,
        totalCarbs: 0,
        caloriesConsumed: 0,
      });
    }

    const alreadyExists = dailyLog.meals.some((m) => m.type === meal.type && m.time === meal.time);

    if (alreadyExists) {
      res.status(400).json({ error: 'Esta comida ya fue anadida.' });
      return;
    }

    dailyLog.meals.push({
      day: meal.day,
      type: meal.type,
      time: meal.time,
      foods: meal.foods.map((f: any) => ({
        food_id: f.food_id,
        grams: f.grams,
      })),
      consumed: true,
      notes: `Comida anadida desde el WeeklyPlan`,
    });

    await calculateDailyTotals(dailyLog);
    await dailyLog.save();

    res.status(200).json({ message: 'Comida del plan anadida al log diario', dailyLog });
  } catch (err) {
    console.error('Error en /DailyMealLogs/add-weekly-meal:', err);
    res.status(500).json({ error: 'Error al anadir la comida al log diario' });
  }
}

export async function addCustomMeal(req: Request, res: Response): Promise<void> {
  const { patient_id, meal_id, type, time } = req.body;

  if (!patient_id || !meal_id || !type || !time) {
    res.status(400).json({ error: 'Faltan campos obligatorios' });
    return;
  }

  try {
    const patientMeal = await PatientMeal.findById(meal_id)
      .populate('ingredients.food_id', 'name nutrients portion_size_g')
      .lean();

    if (!patientMeal) {
      res.status(404).json({ message: 'Comida personalizada no encontrada.' });
      return;
    }

    if (String(patientMeal.patient_id) !== patient_id) {
      res.status(403).json({ message: 'No puedes usar una comida que no te pertenece.' });
      return;
    }

    const todayStart = todayStartInTijuana();
    const todayEnd = todayEndInTijuana();

    let dailyLog = await DailyMealLog.findOne({
      patient_id: new Types.ObjectId(patient_id),
      date: { $gte: todayStart, $lte: todayEnd },
    });

    if (!dailyLog) {
      dailyLog = new DailyMealLog({
        patient_id: new Types.ObjectId(patient_id),
        date: todayStart,
        meals: [],
        totalCalories: 0,
        totalProtein: 0,
        totalFat: 0,
        totalCarbs: 0,
        caloriesConsumed: 0,
      });
    }

    dailyLog.meals.push({
      day: nowInTijuana().weekdayLong!.toLowerCase(),
      type,
      time,
      foods: patientMeal.ingredients.map((ing: any) => ({
        food_id: ing.food_id._id,
        grams: Math.round(ing.amount_g),
      })),
      consumed: true,
      notes: `Comida personalizada: ${patientMeal.name}`,
    });

    await calculateDailyTotals(dailyLog);
    await dailyLog.save();

    res.status(200).json({ message: 'Comida anadida al log diario', dailyLog });
  } catch (err) {
    console.error('Error en /DailyMealLogs/add-custom-meal:', err);
    res.status(500).json({ error: 'Error al anadir la comida al log diario' });
  }
}

export async function deleteMeal(req: Request, res: Response): Promise<void> {
  const { logId, mealId } = req.params;

  if (!Types.ObjectId.isValid(logId) || !Types.ObjectId.isValid(mealId)) {
    res.status(400).json({ error: 'Invalid Log ID or Meal ID.' });
    return;
  }

  try {
    const updatedLog = await DailyMealLog.findByIdAndUpdate(
      logId,
      { $pull: { meals: { _id: mealId } } },
      { new: true }
    );

    if (!updatedLog) {
      res.status(404).json({ error: 'Daily log not found.' });
      return;
    }

    await calculateDailyTotals(updatedLog);
    const finalLog = await updatedLog.save();

    res.json({ message: 'Meal deleted successfully.', dailyLog: finalLog });
  } catch (error) {
    console.error('Error deleting meal:', error);
    res.status(500).json({ error: 'Server error deleting meal.' });
  }
}

export async function addFoodFromScanner(req: Request, res: Response): Promise<void> {
  const { patient_id, type, time, food_data } = req.body;

  if (!patient_id || !type || !time || !food_data || !food_data.food_name) {
    res.status(400).json({ error: 'Faltan campos obligatorios.' });
    return;
  }

  try {
    const foodToSave = {
      name: food_data.food_name,
      portion_size_g: food_data.serving_weight_grams || 100,
      category: food_data.category || 'general',
      nutrients: {
        energy_kj: 0,
        energy_kcal: food_data.nf_calories || 0,
        fat_g: food_data.nf_total_fat || 0,
        saturated_fat_g: 0,
        monounsaturated_fat_g: 0,
        polyunsaturated_fat_g: 0,
        carbohydrates_g: food_data.nf_total_carbohydrate || 0,
        sugar_g: food_data.nf_sugars || 0,
        fiber_g: food_data.nf_dietary_fiber || 0,
        protein_g: food_data.nf_protein || 0,
        salt_g: 0,
        cholesterol_mg: 0,
        potassium_mg: 0,
      },
    };

    const savedFood = await Food.findOneAndUpdate(
      { name: foodToSave.name, portion_size_g: foodToSave.portion_size_g },
      { $set: foodToSave },
      { new: true, upsert: true, runValidators: true }
    );

    const today = todayStartInTijuana();
    today.setHours(0, 0, 0, 0);

    let dailyLog = await DailyMealLog.findOne({
      patient_id: new Types.ObjectId(patient_id),
      date: today,
    });

    if (!dailyLog) {
      dailyLog = new DailyMealLog({
        patient_id: new Types.ObjectId(patient_id),
        date: today,
        meals: [],
        totalCalories: 0,
        totalProtein: 0,
        totalFat: 0,
        totalCarbs: 0,
        caloriesConsumed: 0,
      });
    }

    const weekday = nowInTijuana().weekdayLong!.toLowerCase();

    dailyLog.meals.push({
      day: weekday,
      type,
      time,
      foods: [
        {
          food_id: savedFood._id,
          grams: Math.max(1, Math.round(savedFood.portion_size_g)),
        },
      ],
      consumed: true,
      notes: savedFood.name,
    });

    await calculateDailyTotals(dailyLog);
    await dailyLog.save();

    res.status(200).json({ message: 'Alimento añadido al log diario', dailyLog });
  } catch (err: any) {
    console.error('Error en /dailymeallogs/add-food:', err);
    res.status(500).json({
      error: 'Error interno al añadir el alimento.',
      details: err.message,
    });
  }
}
