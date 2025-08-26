import express from 'express';
import { verifyToken, isAdmin } from '../middlewares/authentication.js';
import {
  getPaymentSlips,
  approvePaymentSlip,
  rejectPaymentSlip,
} from '../controllers/paymentController.js';

const router = express.Router();

router.use(verifyToken);
router.use(isAdmin);

router.get('/', getPaymentSlips);
router.post('/:id/approve', approvePaymentSlip);
router.post('/:id/reject', rejectPaymentSlip);

export default router;