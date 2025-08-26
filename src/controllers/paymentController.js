import PaymentSlip from '../models/PaymentSlip.js';
import User from '../models/User.js';
import { sendEmail } from '../services/emailService.js';
import cloudinary from '../config/cloudinary.js';

export const getPaymentSlips = async (request, response) => {
  try {
    const paymentSlips = await PaymentSlip.find()
      .populate('student', 'name matricNumber email');

    response.json({ paymentSlips });
  } catch (error) {
    console.error('Get payment slips error:', error);
    response.status(500).json({
      error: {
        message: 'Failed to get payment slips',
        code: 'SERVER_ERROR',
      },
    });
  }
};

export const approvePaymentSlip = async (request, response) => {
  try {
    const { id } = request.params;
    const paymentSlip = await PaymentSlip.findById(id).populate('student');

    if (!paymentSlip) {
      return response.status(404).json({
        error: {
          message: 'Payment slip not found',
          code: 'NOT_FOUND',
        },
      });
    }

    paymentSlip.status = 'Approved';
    await paymentSlip.save();

    await sendEmail(
      paymentSlip.student.email,
      'Payment Approved',
      'Your payment has been approved',
      '<p>Your payment slip has been approved.</p>'
    );

    response.json({ message: 'Payment slip approved' });
  } catch (error) {
    console.error('Approve payment slip error:', error);
    response.status(500).json({
      error: {
        message: 'Failed to approve payment slip',
        code: 'SERVER_ERROR',
      },
    });
  }
};

export const rejectPaymentSlip = async (request, response) => {
  try {
    const { id } = request.params;
    const paymentSlip = await PaymentSlip.findById(id).populate('student');

    if (!paymentSlip) {
      return response.status(404).json({
        error: {
          message: 'Payment slip not found',
          code: 'NOT_FOUND',
        },
      });
    }

    // Delete file from Cloudinary
    await cloudinary.uploader.destroy(paymentSlip.publicId, {
      resource_type: paymentSlip.fileType === 'image' ? 'image' : 'raw',
    });

    await paymentSlip.deleteOne();

    await sendEmail(
      paymentSlip.student.email,
      'Payment Rejected',
      'Your payment has been rejected',
      '<p>Your payment slip has been rejected. Please upload a new one.</p>'
    );

    response.json({ message: 'Payment slip rejected' });
  } catch (error) {
    console.error('Reject payment slip error:', error);
    response.status(500).json({
      error: {
        message: 'Failed to reject payment slip',
        code: 'SERVER_ERROR',
      },
    });
  }
};