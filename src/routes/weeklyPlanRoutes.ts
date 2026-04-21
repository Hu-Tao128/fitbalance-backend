import { Router } from 'express';
import { weeklyPlanController } from '../controllers';
import { authenticateToken } from '../middleware/authMiddleware';

const router = Router();

router.use(authenticateToken);

router.get('/weeklyplan/latest/:patient_id', weeklyPlanController.getLatestWeeklyPlan);
router.get('/weeklyplan/daily/:patient_id', weeklyPlanController.getDailyPlan);

export default router;
