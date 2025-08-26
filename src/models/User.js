import mongoose from 'mongoose';

const UserSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
  },
  password: {
    type: String,
    required: true,
  },
  userType: {
    type: String,
    enum: ['admin', 'student'],
    required: true,
  },
  matricNumber: {
    type: String,
    unique: true,
    sparse: true,
    match: [/^\d{2}\/[A-Z0-9]{6}\/\d{3}$/, 'Invalid matric number format'],
    required: function() {
      return this.userType === 'student';
    },
  },
  phone: {
    type: String,
    match: /^\+?[\d\s()-]{10,}$/,
    required: function() {
      return this.userType === 'student';
    },
  },
  gender: {
    type: String,
    enum: ['Male'],
    required: function() {
      return this.userType === 'student';
    },
  },
  dateOfBirth: {
    type: Date,
    required: function() {
      return this.userType === 'student';
    },
  },
  faculty: {
    type: String,
    trim: true,
    required: function() {
      return this.userType === 'student';
    },
  },
  level: {
    type: String,
    required: function() {
      return this.userType === 'student';
    },
    match: [/^(100|200|300|400|500|600|700)level$/, 'Invalid level format'],
  },
  department: {
    type: String,
    trim: true,
    required: function() {
      return this.userType === 'student';
    },
  },
  room: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Room',
  },
  status: {
    type: String,
    enum: ['Pending', 'Approved', 'Declined'],
    default: 'Pending',
  },
  otp: {
    type: String,
  },
  otpExpires: {
    type: Date,
  },
  interviewDate: {
    type: Date,
  },
  isVerified: {
    type: Boolean,
    default: false,
  },
  resetPasswordToken: {
    type: String,
  },
  resetPasswordExpires: {
    type: Date,
  },
  avatar: {
    url: {
      type: String,
      default: '',
    },
    publicId: {
      type: String,
      default: '',
    },
  },
  notifications: {
    email: {
      type: Boolean,
      default: true,
    },
    newStudent: {
      type: Boolean,
      default: true,
    },
    maintenance: {
      type: Boolean,
      default: false,
    },
  },
  documents: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'StudentDocument',
  }],
  security: {
    twoFactorAuth: {
      type: Boolean,
      default: false,
    },
    twoFactorSecret: {
      type: String,
    },
  },
  preferences: {
    language: {
      type: String,
      enum: ['en', 'fr', 'es'],
      default: 'en',
    },
    timezone: {
      type: String,
      enum: ['GMT+0', 'GMT+1', 'GMT+2'],
      default: 'GMT+1',
    },
  },
}, { timestamps: true });

const User = mongoose.model('User', UserSchema);

export default User;