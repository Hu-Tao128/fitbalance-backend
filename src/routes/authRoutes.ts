import { Router } from 'express';
import { authController } from '../controllers';

const router = Router();

router.post('/login', authController.login);
router.post('/send-reset-code', authController.sendResetCode);
router.put('/patients/change-password', authController.changePassword);

export default router;
