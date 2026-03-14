import { Router } from 'express';
import { weeklyPlanController } from '../controllers';

const router = Router();

router.get('/weeklyplan/latest/:patient_id', weeklyPlanController.getLatestWeeklyPlan);
router.get('/weeklyplan/daily/:patient_id', weeklyPlanController.getDailyPlan);

export default router;
