import User from '../models/User.js';
import Settings from '../models/Settings.js';
import { hashPassword, comparePasswords } from '../services/authService.js';
import { sendEmail } from '../services/emailService.js';
import cloudinary from '../config/cloudinary.js';

export const getSettings = async (request, response) => {
  try {
    const user = await User.findById(request.user.id).select('name email avatar userType security');
    const settings = await Settings.findOne({ user: request.user.id });

    if (!user) {
      return response.status(404).json({
        error: {
          message: 'User not found',
          code: 'NOT_FOUND',
        },
      });
    }

    response.json({
      name: user.name,
      email: user.email,
      avatar: user.avatar || '',
      userType: user.userType,
      settings: settings || {
        notifications: { email: true, newStudent: false, maintenance: true },
        preferences: { language: 'en', timezone: 'Africa/Lagos', theme: 'dark' },
      },
      security: user.security || { twoFactorAuth: false },
    });
  } catch (error) {
    console.error('Get settings error:', error);
    response.status(500).json({
      error: {
        message: 'Failed to get settings',
        code: 'SERVER_ERROR',
      },
    });
  }
};

export const updateProfile = async (request, response) => {
  try {
    const { name, email } = request.body;
    const user = await User.findById(request.user.id);

    if (!user) {
      return response.status(404).json({
        error: {
          message: 'User not found',
          code: 'NOT_FOUND',
        },
      });
    }

    if (email !== user.email) {
      const emailExists = await User.findOne({ email, _id: { $ne: user._id } });
      if (emailExists) {
        return response.status(400).json({
          error: {
            message: 'Email already in use',
            code: 'EMAIL_TAKEN',
          },
        });
      }
    }

    let avatarUrl = user.avatar;
    if (request.file) {
      const uploadResult = await cloudinary.uploader.upload(request.file.path, {
        folder: 'adem_baba/avatars',
        resource_type: 'image',
      });
      avatarUrl = uploadResult.secure_url;

      if (user.avatar && user.avatar.includes('cloudinary')) {
        const publicId = user.avatar.split('/').pop().split('.')[0];
        await cloudinary.uploader.destroy(`adem_baba/avatars/${publicId}`);
      }
    }

    user.name = name;
    user.email = email;
    user.avatar = avatarUrl;
    await user.save();

    await sendEmail(
      user.email,
      'Profile Updated',
      'Your profile has been updated successfully',
      '<p>Your profile information has been updated.</p>'
    );

    response.json({
      message: 'Profile updated successfully',
      data: { name, email, avatar: avatarUrl },
    });
  } catch (error) {
    console.error('Update profile error:', error);
    response.status(500).json({
      error: {
        message: 'Failed to update profile',
        code: 'SERVER_ERROR',
      },
    });
  }
};

export const updateNotifications = async (request, response) => {
  try {
    const { email, newStudent, maintenance } = request.body;
    let settings = await Settings.findOne({ user: request.user.id });

    if (!settings) {
      settings = new Settings({ user: request.user.id });
    }

    settings.notifications = { email, newStudent, maintenance };
    await settings.save();

    response.json({
      message: 'Notification preferences updated',
      data: settings.notifications,
    });
  } catch (error) {
    console.error('Update notifications error:', error);
    response.status(500).json({
      error: {
        message: 'Failed to update notifications',
        code: 'SERVER_ERROR',
      },
    });
  }
};

export const updateSecurity = async (request, response) => {
  try {
    const { currentPassword, newPassword, twoFactorAuth } = request.body;
    const user = await User.findById(request.user.id);

    if (!user) {
      return response.status(404).json({
        error: {
          message: 'User not found',
          code: 'NOT_FOUND',
        },
      });
    }

    const isMatch = await comparePasswords(currentPassword, user.password);
    if (!isMatch) {
      return response.status(400).json({
        error: {
          message: 'Current password is incorrect',
          code: 'INVALID_PASSWORD',
        },
      });
    }

    if (newPassword) {
      user.password = await hashPassword(newPassword);
    }

    user.security.twoFactorAuth = twoFactorAuth;
    await user.save();

    response.json({ message: 'Security settings updated' });
  } catch (error) {
    console.error('Update security error:', error);
    response.status(500).json({
      error: {
        message: 'Failed to update security settings',
        code: 'SERVER_ERROR',
      },
    });
  }
};

export const updateSystemPreferences = async (request, response) => {
  try {
    const { language, timezone, theme } = request.body;
    let settings = await Settings.findOne({ user: request.user.id });

    if (!settings) {
      settings = new Settings({ user: request.user.id });
    }

    settings.preferences = { language, timezone, theme };
    await settings.save();

    response.json({
      message: 'System preferences updated',
      data: settings.preferences,
    });
  } catch (error) {
    console.error('Update system preferences error:', error);
    response.status(500).json({
      error: {
        message: 'Failed to update system preferences',
        code: 'SERVER_ERROR',
      },
    });
  }
};