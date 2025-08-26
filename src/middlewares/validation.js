import { body, param, query } from 'express-validator';

export const validatePdfUrl = [
  body('pdfUrl')
    .notEmpty()
    .withMessage('URL is required')
    .isURL()
    .withMessage('Invalid URL format')
    .trim(),
];

export const validateId = [
  param('id').isMongoId().withMessage('Invalid document ID'),
];

export const validateEvent = [
  body('title').trim().notEmpty().withMessage('Title is required'),
  body('date').isISO8601().withMessage('Invalid date format'),
  body('time').matches(/^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/).withMessage('Invalid time format'),
  body('description').optional().trim(),
  body('status').optional().isIn(['Scheduled', 'Pending', 'Cancelled']).withMessage('Invalid status'),
];

export const validateMaintenance = [
  body('roomId').isMongoId().withMessage('Invalid room ID'),
  body('issue').trim().notEmpty().withMessage('Issue is required'),
  body('type').isIn(['warning', 'danger']).withMessage('Type must be warning or danger'),
];

export const validateRoomAssignment = [
  body('studentId').isMongoId().withMessage('Invalid student ID'),
  body('roomId').isMongoId().withMessage('Invalid room ID'),
];

export const validateRegistrationDeadline = [
  body('deadline')
    .isISO8601()
    .withMessage('Invalid deadline format')
    .custom((value) => {
      const deadline = new Date(value);
      const now = new Date();
      if (deadline <= now) {
        throw new Error('Deadline must be in the future');
      }
      return true;
    }),
];