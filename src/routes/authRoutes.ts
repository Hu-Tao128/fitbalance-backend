import { Router } from 'express';
import { authController } from '../controllers';
import { authenticateToken } from '../middleware/authMiddleware';

const router = Router();

router.post('/login', authController.login);
router.post('/send-reset-code', authController.sendResetCode);
router.put('/patients/change-password', authenticateToken, authController.changePassword);

export default router;
