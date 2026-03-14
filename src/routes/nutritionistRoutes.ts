import { Router } from 'express';
import { nutritionistController } from '../controllers';

const router = Router();

router.get('/nutritionist/:id', nutritionistController.getNutritionist);

export default router;
