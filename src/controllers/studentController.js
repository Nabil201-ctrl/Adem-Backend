import User from '../models/User.js';
import Room from '../models/Room.js';
import PaymentSlip from '../models/PaymentSlip.js';
import { uploadDocuments } from '../middlewares/upload.js';
import { handleValidationErrors } from '../middlewares/validation.js';
import { sendEmail } from '../services/emailService.js';
import { generateOTP } from '../services/authService.js';
import cloudinary from '../config/cloudinary.js';

export const getStudentDashboard = async (request, response) => {
  try {
    const student = await User.findById(request.user.id)
      .select('name email matricNumber room dateOfBirth faculty level department')
      .populate('room', 'roomNumber type');

    if (!student) {
      return response.status(404).json({
        error: {
          message: 'Student not found',
          code: 'NOT_FOUND',
        },
      });
    }

    // Check for approved payment slip
    const paymentSlip = await PaymentSlip.findOne({
      student: request.user.id,
      status: 'Approved',
    });

    if (!paymentSlip) {
      return response.status(403).json({
        error: {
          message: 'Payment required',
          code: 'PAYMENT_REQUIRED',
          redirect: '/payment-upload',
        },
      });
    }

    response.json({
      student: {
        name: student.name,
        email: student.email,
        matricNumber: student.matricNumber,
        room: student.room,
        faculty: student.faculty,
        level: student.level,
        department: student.department,
      },
    });
  } catch (error) {
    console.error('Student dashboard error:', error);
    response.status(500).json({
      error: {
        message: 'Failed to load student dashboard',
        code: 'SERVER_ERROR',
      },
    });
  }
};

export const uploadPaymentSlip = async (request, response) => {
  try {
    if (!request.file) {
      return response.status(400).json({
        error: {
          message: 'No file uploaded',
          code: 'NO_FILE',
        },
      });
    }

    const { amount } = request.body;
    const studentId = request.user.id;

    const paymentSlip = new PaymentSlip({
      student: studentId,
      fileUrl: request.file.path,
      publicId: request.file.filename,
      fileType: request.file.mimetype.startsWith('image') ? 'image' : 'raw',
      amount: parseFloat(amount),
      status: 'Pending',
    });

    await paymentSlip.save();

    // Notify admins
    const admins = await User.find({ userType: 'admin' });
    for (const admin of admins) {
      await sendEmail(
        admin.email,
        'New Payment Slip Uploaded',
        `Student ${request.user.name} has uploaded a payment slip.`,
        `<p>Please review the payment slip in the admin dashboard.</p>`
      );
    }

    response.status(201).json({
      message: 'Payment slip uploaded successfully',
      paymentSlip,
    });
  } catch (error) {
    console.error('Payment slip upload error:', error);
    if (request.file) {
      await cloudinary.uploader.destroy(request.file.filename);
    }
    response.status(500).json({
      error: {
        message: 'Failed to upload payment slip',
        code: 'SERVER_ERROR',
      },
    });
  }
};

export const getStudentDocuments = async (request, response) => {
  try {
    const documents = await StudentDocument.find({ student: request.user.id });
    response.json({ documents });
  } catch (error) {
    console.error('Get student documents error:', error);
    response.status(500).json({
      error: {
        message: 'Failed to get student documents',
        code: 'SERVER_ERROR',
      },
    });
  }
};

export const verifyOTP = async (request, response) => {
  try {
    const { email, otp } = request.body;
    const student = await User.findOne({ email, userType: 'student' });

    if (!student) {
      return response.status(404).json({
        error: {
          message: 'Student not found',
          code: 'NOT_FOUND',
        },
      });
    }

    if (student.status !== 'Approved' || !student.otp || student.otp !== otp || student.otpExpires < Date.now()) {
      return response.status(400).json({
        error: {
          message: 'Invalid or expired OTP',
          code: 'INVALID_OTP',
        },
      });
    }

    student.isVerified = true;
    student.otp = undefined;
    student.otpExpires = undefined;
    await student.save();

    const token = generateToken(student);

    response.json({
      message: 'Account activated successfully',
      token,
      user: {
        id: student._id,
        name: student.name,
        email: student.email,
        userType: student.userType,
      },
    });
  } catch (error) {
    console.error('OTP verification error:', error);
    response.status(500).json({
      error: {
        message: 'Failed to verify OTP',
        code: 'SERVER_ERROR',
      },
    });
  }
};