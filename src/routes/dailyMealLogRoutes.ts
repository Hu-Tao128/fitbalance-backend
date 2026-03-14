import { Router } from 'express';
import { dailyMealLogController } from '../controllers';

const router = Router();

router.get('/daily-nutrition', dailyMealLogController.getDailyNutrition);
router.get('/daily-meal-logs/today/:patient_id', dailyMealLogController.getTodayMealLog);
router.get('/daily-meal-logs/all/:patient_id', dailyMealLogController.getAllMealLogs);
router.get('/daily-meal-logs/by-date', dailyMealLogController.getMealLogByDate);
router.post('/daily-meal-logs/add-meal', dailyMealLogController.addMeal);
router.post('/daily-meal-logs/add-weekly-meal', dailyMealLogController.addWeeklyMeal);
router.post('/DailyMealLogs/add-weekly-meal', dailyMealLogController.addWeeklyMeal);
router.post('/DailyMealLogs/add-custom-meal', dailyMealLogController.addCustomMeal);
router.delete('/daily-meal-logs/:logId/meals/:mealId', dailyMealLogController.deleteMeal);

export default router;
