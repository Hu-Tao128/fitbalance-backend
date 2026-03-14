import { Request, Response } from 'express';
import { Types } from 'mongoose';
import { WeeklyPlan, Food } from '../models';
import { nowInTijuana } from '../services/dateService';

export async function getLatestWeeklyPlan(req: Request, res: Response): Promise<void> {
  const { patient_id } = req.params;

  if (!Types.ObjectId.isValid(patient_id)) {
    res.status(400).json({ error: 'Invalid patient ID' });
    return;
  }

  try {
    const latestPlan = await WeeklyPlan.findOne({
      patient_id: new Types.ObjectId(patient_id),
    })
      .sort({ week_start: -1 })
      .lean();

    if (!latestPlan) {
      res.status(200).json({
        message: 'No weekly plan found.',
        dailyCalories: 2000,
        protein: 150,
        fat: 70,
        carbs: 250,
      });
      return;
    }

    res.json(latestPlan);
  } catch (error) {
    console.error('Error in /weeklyplan/latest:', error);
    res.status(500).json({ error: 'Error getting the latest weekly plan' });
  }
}

export async function getDailyPlan(req: Request, res: Response): Promise<void> {
  let { patient_id } = req.params;
  patient_id = patient_id.replace(/\.$/, '');

  try {
    const plan = await WeeklyPlan.findOne({ patient_id: new Types.ObjectId(patient_id) })
      .sort({ week_start: -1 })
      .lean();

    if (!plan) {
      res.status(404).json({ message: 'Plan no encontrado' });
      return;
    }

    const todayInTijuana = nowInTijuana();
    const todayWeekDay = todayInTijuana.weekdayLong!.toLowerCase();

    const todayMeals = plan.meals.filter((meal) => meal.day === todayWeekDay);

    const enrichedMeals = await Promise.all(
      todayMeals.map(async (meal) => {
        const enrichedFoods = await Promise.all(
          meal.foods.map(async (item) => {
            const food = await Food.findById(item.food_id).lean();
            return {
              ...item,
              name: food?.name || 'Desconocido',
            };
          })
        );

        return {
          ...meal,
          foods: enrichedFoods,
        };
      })
    );

    res.json({ ...plan, meals: enrichedMeals });
  } catch (err) {
    console.error('Error al obtener el plan diario:', err);
    res.status(500).json({ message: 'Error interno del servidor' });
  }
}
