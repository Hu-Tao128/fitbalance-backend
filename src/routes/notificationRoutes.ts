import { Router } from 'express';
import { sendNotification } from '../controllers/notificationController';
import { authenticateToken } from '../middleware/authMiddleware';

const router = Router();

router.use(authenticateToken);

router.post('/notifications/send', sendNotification);

export default router;