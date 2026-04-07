import { Router } from 'express';
import { appointmentController } from '../controllers';
import { authenticateToken } from '../middleware/authMiddleware';

const router = Router();

router.use(authenticateToken);

router.get('/appointments/:patient_id', appointmentController.getPatientAppointments);

export default router;
