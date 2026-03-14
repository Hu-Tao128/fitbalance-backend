import { Router } from 'express';
import { foodController } from '../controllers';

const router = Router();

router.post('/search-food', foodController.searchFood);
router.get('/api/food', foodController.getAllFoods);

export default router;
