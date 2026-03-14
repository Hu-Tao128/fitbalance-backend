import { Router } from 'express';
import { appointmentController } from '../controllers';

const router = Router();

router.get('/appointments/:patient_id', appointmentController.getPatientAppointments);

export default router;
