import { Router } from 'express';
import { patientController } from '../controllers';

const router = Router();

router.get('/user/:username', patientController.getUserByUsername);
router.put('/patient/:id', patientController.updatePatient);

export default router;
