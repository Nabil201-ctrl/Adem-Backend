import User from '../models/User.js';
import {
  hashPassword,
  comparePasswords,
  generateToken,
  generateOTP,
  generateResetToken,
} from '../services/authService.js';
import {
  sendWelcomeEmail,
  sendPasswordResetEmail,
} from '../services/emailService.js';
import { handleValidationErrors } from '../middlewares/validation.js';

export const register = async (request, response) => {
  try {
    const { name, email, password, userType } = request.body;

    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return response.status(400).json({
        error: {
          message: 'Email already exists',
          code: 'EMAIL_EXISTS',
        },
      });
    }

    // Hash password
    const hashedPassword = await hashPassword(password);

    // Create user
    const user = new User({
      name,
      email,
      password: hashedPassword,
      userType,
    });

    await user.save();

    // Send welcome email
    await sendWelcomeEmail(user);

    // Generate token
    const token = generateToken(user);

    response.status(201).json({
      message: 'User registered successfully',
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        userType: user.userType,
      },
    });
  } catch (error) {
    console.error('Registration error:', error);
    response.status(500).json({
      error: {
        message: 'Failed to register user',
        code: 'SERVER_ERROR',
      },
    });
  }
};

export const login = async (request, response) => {
  try {
    const { email, password } = request.body;

    // Check if user exists
    const user = await User.findOne({ email });
    if (!user) {
      return response.status(400).json({
        error: {
          message: 'Invalid credentials',
          code: 'INVALID_CREDENTIALS',
        },
      });
    }

    // Check password
    const isMatch = await comparePasswords(password, user.password);
    if (!isMatch) {
      return response.status(400).json({
        error: {
          message: 'Invalid credentials',
          code: 'INVALID_CREDENTIALS',
        },
      });
    }

    // Generate token
    const token = generateToken(user);

    response.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        userType: user.userType,
      },
    });
  } catch (error) {
    console.error('Login error:', error);
    response.status(500).json({
      error: {
        message: 'Failed to login',
        code: 'SERVER_ERROR',
      },
    });
  }
};

export const forgotPassword = async (request, response) => {
  try {
    const { email } = request.body;

    const user = await User.findOne({ email });
    if (!user) {
      return response.status(404).json({
        error: {
          message: 'Email not found',
          code: 'EMAIL_NOT_FOUND',
        },
      });
    }

    // Generate reset token
    const resetToken = generateResetToken();
    user.resetPasswordToken = resetToken;
    user.resetPasswordExpires = Date.now() + 3600000; // 1 hour

    await user.save();

    // Send reset email
    await sendPasswordResetEmail(user, resetToken);

    response.json({
      message: 'Password reset email sent',
    });
  } catch (error) {
    console.error('Forgot password error:', error);
    response.status(500).json({
      error: {
        message: 'Failed to process forgot password request',
        code: 'SERVER_ERROR',
      },
    });
  }
};

export const resetPassword = async (request, response) => {
  try {
    const { token, newPassword } = request.body;

    const user = await User.findOne({
      resetPasswordToken: token,
      resetPasswordExpires: { $gt: Date.now() },
    });

    if (!user) {
      return response.status(400).json({
        error: {
          message: 'Invalid or expired token',
          code: 'INVALID_TOKEN',
        },
      });
    }

    // Hash new password
    user.password = await hashPassword(newPassword);
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;

    await user.save();

    response.json({
      message: 'Password reset successful',
    });
  } catch (error) {
    console.error('Reset password error:', error);
    response.status(500).json({
      error: {
        message: 'Failed to reset password',
        code: 'SERVER_ERROR',
      },
    });
  }
};