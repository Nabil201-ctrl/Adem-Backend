import express from 'express';
import { verifyToken, isAdmin } from '../middlewares/authentication.js';
import {
  getAdminDashboard,
  getPendingRequests,
  approveStudentRequest,
  declineStudentRequest,
  setRegistrationDeadline,
} from '../controllers/adminController.js';

const router = express.Router();

router.use(verifyToken);
router.use(isAdmin);

router.get('/dashboard', getAdminDashboard);
router.get('/pending-requests', getPendingRequests);
router.post('/approve-request', approveStudentRequest);
router.post('/decline-request', declineStudentRequest);
router.post('/registration-deadline', setRegistrationDeadline);

export default router;