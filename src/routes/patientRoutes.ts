import { Router } from 'express';
import { patientController } from '../controllers';
import { authenticateToken } from '../middleware/authMiddleware';

const router = Router();

// Apply authentication middleware to all routes in this router
router.use(authenticateToken);

router.get('/user/:username', patientController.getUserByUsername);
router.put('/patient/:id', patientController.updatePatient);
router.post('/fcm-token', patientController.saveFcmToken);
router.put('/notification-preferences', patientController.updateNotificationPreferences);

export default router;
