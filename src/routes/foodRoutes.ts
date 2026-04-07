import { Router } from 'express';
import { foodController } from '../controllers';
import { authenticateToken } from '../middleware/authMiddleware';

const router = Router();

// Apply authentication middleware to all routes in this router
router.use(authenticateToken);

router.post('/search-food', foodController.searchFood);
router.get('/api/food', foodController.getAllFoods);

export default router;
