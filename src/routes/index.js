import { Router } from 'express';
import authRoutes from './auth.routes.js';
import workerRoutes from './workers.routes.js';
import customerRoutes from './customers.routes.js';

const router = Router();

router.use('/api', authRoutes);
router.use('/api', workerRoutes);
router.use('/api', customerRoutes);

export default router;
