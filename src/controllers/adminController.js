import User from '../models/User.js';
import Room from '../models/Room.js';
import PaymentSlip from '../models/PaymentSlip.js';
import RegistrationDeadline from '../models/RegistrationDeadline.js';
import { sendEmail } from '../services/emailService.js';
import { generateOTP } from '../services/authService.js';
import cloudinary from '../config/cloudinary.js';

export const getAdminDashboard = async (request, response) => {
  try {
    const totalStudents = await User.countDocuments({ userType: 'student' });
    const occupiedRooms = await Room.countDocuments({ status: 'Occupied' });
    const pendingRequests = await User.countDocuments({ userType: 'student', status: 'Pending' });

    const monthlyRevenue = await PaymentSlip.aggregate([
      {
        $match: {
          status: 'Approved',
          createdAt: {
            $gte: new Date(new Date().getFullYear(), new Date().getMonth(), 1),
            $lt: new Date(new Date().getFullYear(), new Date().getMonth() + 1, 1),
          },
        },
      },
      { $group: { _id: null, total: { $sum: '$amount' } } },
    ]);

    response.json({
      totalStudents,
      occupiedRooms,
      pendingRequests,
      monthlyRevenue: monthlyRevenue[0]?.total || 0,
    });
  } catch (error) {
    console.error('Admin dashboard error:', error);
    response.status(500).json({
      error: {
        message: 'Failed to load admin dashboard',
        code: 'SERVER_ERROR',
      },
    });
  }
};

export const getPendingRequests = async (request, response) => {
  try {
    const requests = await User.find({ userType: 'student', status: 'Pending' })
      .select('name email matricNumber phone gender dateOfBirth faculty level department createdAt status');

    response.json({ requests });
  } catch (error) {
    console.error('Pending requests error:', error);
    response.status(500).json({
      error: {
        message: 'Failed to get pending requests',
        code: 'SERVER_ERROR',
      },
    });
  }
};

export const approveStudentRequest = async (request, response) => {
  try {
    const { studentId } = request.body;
    const student = await User.findById(studentId);

    if (!student || student.userType !== 'student' || student.status !== 'Pending') {
      return response.status(404).json({
        error: {
          message: 'Student not found or not pending',
          code: 'NOT_FOUND',
        },
      });
    }

    const otp = generateOTP();
    const otpExpires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 1 day

    student.otp = otp;
    student.otpExpires = otpExpires;
    student.status = 'Approved';
    await student.save();

    await sendEmail(
      student.email,
      'Your OTP for Account Activation',
      `Your OTP is: ${otp}`,
      `<p>Use this OTP to activate your account: <strong>${otp}</strong></p>`
    );

    response.json({ message: 'Student approved and OTP sent' });
  } catch (error) {
    console.error('Approve student error:', error);
    response.status(500).json({
      error: {
        message: 'Failed to approve student',
        code: 'SERVER_ERROR',
      },
    });
  }
};

export const declineStudentRequest = async (request, response) => {
  try {
    const { studentId } = request.body;
    const student = await User.findById(studentId);

    if (!student || student.userType !== 'student' || student.status !== 'Pending') {
      return response.status(404).json({
        error: {
          message: 'Student not found or not pending',
          code: 'NOT_FOUND',
        },
      });
    }

    student.status = 'Declined';
    await student.save();

    await sendEmail(
      student.email,
      'Registration Declined',
      'Your registration has been declined',
      '<p>We regret to inform you that your registration has been declined.</p>'
    );

    response.json({ message: 'Student registration declined' });
  } catch (error) {
    console.error('Decline student error:', error);
    response.status(500).json({
      error: {
        message: 'Failed to decline student',
        code: 'SERVER_ERROR',
      },
    });
  }
};

export const setRegistrationDeadline = async (request, response) => {
  try {
    const { deadline } = request.body;

    // Delete existing deadline
    await RegistrationDeadline.deleteMany({});

    const newDeadline = new RegistrationDeadline({
      deadline: new Date(deadline),
    });

    await newDeadline.save();

    response.json({ message: 'Registration deadline set', deadline: newDeadline });
  } catch (error) {
    console.error('Set deadline error:', error);
    response.status(500).json({
      error: {
        message: 'Failed to set registration deadline',
        code: 'SERVER_ERROR',
      },
    });
  }
};