import { Router } from 'express';
import { authController } from '../controllers';
import { authenticateToken } from '../middleware/authMiddleware';

const router = Router();

router.post('/login', authController.login);
router.post('/send-reset-code', authController.sendResetCode);
router.post('/verify-reset-code', authController.verifyResetCode);
router.post('/reset-password', authController.resetPassword);
router.put('/patients/change-password', authenticateToken, authController.changePassword);

export default router;
