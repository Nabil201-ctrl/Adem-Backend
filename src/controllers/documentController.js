import WelcomeDocument from '../models/WelcomeDocument.js';
import StudentDocument from '../models/StudentDocument.js';
import { handleValidationErrors } from '../middlewares/validation.js';
import { sendEmail } from '../services/emailService.js';

export const createWelcomeDocument = async (request, response) => {
  try {
    const { pdfUrl } = request.body;
    const adminId = request.user.id;

    const welcomeDoc = new WelcomeDocument({
      pdfUrl,
      uploadedBy: adminId,
    });

    await welcomeDoc.save();

    response.status(201).json({
      message: 'Welcome document created successfully',
      document: welcomeDoc,
    });
  } catch (error) {
    console.error('Create welcome document error:', error);
    response.status(500).json({
      error: {
        message: 'Failed to create welcome document',
        code: 'SERVER_ERROR',
      },
    });
  }
};

export const getWelcomeDocuments = async (request, response) => {
  try {
    const documents = await WelcomeDocument.find().sort({ createdAt: -1 });
    response.json({ documents });
  } catch (error) {
    console.error('Get welcome documents error:', error);
    response.status(500).json({
      error: {
        message: 'Failed to get welcome documents',
        code: 'SERVER_ERROR',
      },
    });
  }
};

export const updateWelcomeDocument = async (request, response) => {
  try {
    const { id } = request.params;
    const { pdfUrl } = request.body;

    const document = await WelcomeDocument.findByIdAndUpdate(
      id,
      { pdfUrl },
      { new: true }
    );

    if (!document) {
      return response.status(404).json({
        error: {
          message: 'Document not found',
          code: 'NOT_FOUND',
        },
      });
    }

    response.json({
      message: 'Document updated successfully',
      document,
    });
  } catch (error) {
    console.error('Update welcome document error:', error);
    response.status(500).json({
      error: {
        message: 'Failed to update welcome document',
        code: 'SERVER_ERROR',
      },
    });
  }
};

export const deleteWelcomeDocument = async (request, response) => {
  try {
    const { id } = request.params;
    const document = await WelcomeDocument.findByIdAndDelete(id);

    if (!document) {
      return response.status(404).json({
        error: {
          message: 'Document not found',
          code: 'NOT_FOUND',
        },
      });
    }

    response.json({ message: 'Document deleted successfully' });
  } catch (error) {
    console.error('Delete welcome document error:', error);
    response.status(500).json({
      error: {
        message: 'Failed to delete welcome document',
        code: 'SERVER_ERROR',
      },
    });
  }
};