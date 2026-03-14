import { Router } from 'express';
import { patientMealController } from '../controllers';

const router = Router();

router.post('/PatientMeals', patientMealController.createPatientMeal);
router.get('/PatientMeals/:patient_id', patientMealController.getPatientMeals);
router.put('/PatientMeals/:meal_id', patientMealController.updatePatientMeal);
router.delete('/PatientMeals/:meal_id', patientMealController.deletePatientMeal);

export default router;
