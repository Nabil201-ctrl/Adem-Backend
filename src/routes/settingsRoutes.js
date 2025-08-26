import express from 'express';
import { verifyToken } from '../middlewares/authentication.js';
import {
  getSettings,
  updateProfile,
  updateNotifications,
  updateSecurity,
  updateSystemPreferences,
} from '../controllers/settingsController.js';
import upload from '../config/multer.js';

const router = express.Router();

router.use(verifyToken);

router.get('/', getSettings);
router.put('/profile', upload.single('avatar'), updateProfile);
router.put('/notifications', updateNotifications);
router.put('/security', updateSecurity);
router.put('/system', updateSystemPreferences);

export default router;