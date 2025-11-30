import { Router } from 'express';
import { getSampleCustomers } from '../controllers/customers.controller.js';

const router = Router();

router.get('/customers/sample', getSampleCustomers);

export default router;
