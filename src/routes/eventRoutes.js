import express from 'express';
import { verifyToken } from '../middlewares/authentication.js';
import { isAdmin } from '../middlewares/authentication.js';
import {
  getEvents,
  getEventStats,
  createEvent,
  updateEvent,
  deleteEvent,
} from '../controllers/eventController.js';

const router = express.Router();

router.use(verifyToken);

router.get('/', getEvents);
router.get('/stats', isAdmin, getEventStats);
router.post('/', isAdmin, createEvent);
router.put('/:id', isAdmin, updateEvent);
router.delete('/:id', isAdmin, deleteEvent);

export default router;