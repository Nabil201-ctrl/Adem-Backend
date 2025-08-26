import express from 'express';
import { verifyToken, isAdmin } from '../middlewares/authentication.js';
import {
  createWelcomeDocument,
  getWelcomeDocuments,
  updateWelcomeDocument,
  deleteWelcomeDocument,
} from '../controllers/documentController.js';
import { validatePdfUrl, validateId } from '../middlewares/validation.js';

const router = express.Router();

router.use(verifyToken);
router.use(isAdmin);

router.post('/', validatePdfUrl, createWelcomeDocument);
router.get('/', getWelcomeDocuments);
router.put('/:id', validateId, validatePdfUrl, updateWelcomeDocument);
router.delete('/:id', validateId, deleteWelcomeDocument);

export default router;