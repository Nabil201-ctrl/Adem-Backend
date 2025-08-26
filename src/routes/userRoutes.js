import express from 'express';
import { verifyToken } from '../middlewares/authentication.js';
import {
  getUserProfile,
  updateUserProfile,
} from '../controllers/userController.js';

const router = express.Router();

router.use(verifyToken);

router.get('/profile', getUserProfile);
router.put('/profile', updateUserProfile);

export default router;