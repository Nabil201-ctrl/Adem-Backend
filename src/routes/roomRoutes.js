import express from 'express';
import { verifyToken, isAdmin } from '../middlewares/authentication.js';
import {
  getRooms,
  getRoomStats,
  createRoom,
  updateRoom,
  deleteRoom,
  assignRoomToStudent,
} from '../controllers/roomController.js';
import { validateRoomCreation, handleValidationErrors } from '../middlewares/validation.js';

const router = express.Router();

router.use(verifyToken);
router.use(isAdmin);

router.get('/', getRooms);
router.get('/stats', getRoomStats);
router.post('/', validateRoomCreation, handleValidationErrors, createRoom);
router.put('/:id', validateRoomCreation, handleValidationErrors, updateRoom);
router.delete('/:id', deleteRoom);
router.post('/assign', assignRoomToStudent);

export default router;