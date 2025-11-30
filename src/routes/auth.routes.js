import { Router } from 'express';
import { workerLogin, customerLogin, customerSignup, refreshTokens } from '../controllers/auth.controller.js';
import { loginLimiter } from '../middleware/rate-limiter.js';

const router = Router();

router.post('/auth/worker/login', loginLimiter, workerLogin);
router.post('/auth/login', loginLimiter, customerLogin);
router.post('/auth/signup', customerSignup);
router.post('/auth/refresh', refreshTokens);

export default router;
