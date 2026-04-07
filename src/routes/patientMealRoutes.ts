import { Router } from 'express';
import { patientMealController } from '../controllers';
import { authenticateToken } from '../middleware/authMiddleware';

const router = Router();

router.use(authenticateToken);

router.post('/PatientMeals', patientMealController.createPatientMeal);
router.get('/PatientMeals/:patient_id', patientMealController.getPatientMeals);
router.put('/PatientMeals/:meal_id', patientMealController.updatePatientMeal);
router.delete('/PatientMeals/:meal_id', patientMealController.deletePatientMeal);

export default router;
