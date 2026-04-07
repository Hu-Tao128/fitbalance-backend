import { Router } from 'express';
import { nutritionistController } from '../controllers';
import { authenticateToken } from '../middleware/authMiddleware';

const router = Router();

router.use(authenticateToken);

router.get('/nutritionist/:id', nutritionistController.getNutritionist);

export default router;
