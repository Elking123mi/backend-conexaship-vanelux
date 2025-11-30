import { Router } from 'express';
import { authenticate } from '../middleware/authenticate.js';
import { authorize } from '../middleware/authorize.js';
import { getProfile, clockIn, clockOut, getTimesheet } from '../controllers/workers.controller.js';

const router = Router();

router.use(authenticate, authorize('worker', 'manager', 'admin'));

router.get('/workers/me', getProfile);
router.post('/workers/me/clock-in', clockIn);
router.post('/workers/me/clock-out', clockOut);
router.get('/workers/me/timesheet', getTimesheet);

export default router;
