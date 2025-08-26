import express from 'express';
import { verifyToken, isAdmin } from '../middlewares/authentication.js';
import {
  getMaintenanceRequests,
  createMaintenanceRequest,
  resolveMaintenanceRequest,
  deleteMaintenanceRequest,
} from '../controllers/maintenanceController.js';

const router = express.Router();

router.use(verifyToken);
router.use(isAdmin);

router.get('/', getMaintenanceRequests);
router.post('/', createMaintenanceRequest);
router.patch('/:id/resolve', resolveMaintenanceRequest);
router.delete('/:id', deleteMaintenanceRequest);

export default router;