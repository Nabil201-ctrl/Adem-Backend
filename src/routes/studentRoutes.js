import express from 'express';
import { verifyToken, isStudent } from '../middlewares/authentication.js';
import {
  getStudentDashboard,
  uploadPaymentSlip,
  getStudentDocuments,
  verifyOTP,
} from '../controllers/studentController.js';
import upload from '../config/multer.js';

const router = express.Router();

router.use(verifyToken);
router.use(isStudent);

router.get('/dashboard', getStudentDashboard);
router.post('/payment-slips', upload.single('paymentSlip'), uploadPaymentSlip);
router.get('/documents', getStudentDocuments);
router.post('/verify-otp', verifyOTP);

export default router;