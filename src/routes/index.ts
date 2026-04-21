import { Router } from 'express';
import authRoutes from './authRoutes';
import patientRoutes from './patientRoutes';
import foodRoutes from './foodRoutes';
import weeklyPlanRoutes from './weeklyPlanRoutes';
import dailyMealLogRoutes from './dailyMealLogRoutes';
import patientMealRoutes from './patientMealRoutes';
import appointmentRoutes from './appointmentRoutes';
import nutritionistRoutes from './nutritionistRoutes';
import notificationRoutes from './notificationRoutes';

const router = Router();

router.use(authRoutes);
router.use(patientRoutes);
router.use(foodRoutes);
router.use(weeklyPlanRoutes);
router.use(dailyMealLogRoutes);
router.use(patientMealRoutes);
router.use(appointmentRoutes);
router.use(nutritionistRoutes);
router.use(notificationRoutes);

export default router;
