import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import crypto from 'crypto';

dotenv.config();

const SALT_ROUNDS = 10;
const JWT_SECRET = process.env.JWT_SECRET;

export const hashPassword = async (password) => {
  return await bcrypt.hash(password, SALT_ROUNDS);
};

export const comparePasswords = async (plainPassword, hashedPassword) => {
  return await bcrypt.compare(plainPassword, hashedPassword);
};

export const generateToken = (user) => {
  return jwt.sign(
    {
      id: user._id,
      email: user.email,
      userType: user.userType,
      name: user.name,
    },
    JWT_SECRET,
    { expiresIn: '1h' }
  );
};

export const generateOTP = () => {
  return crypto.randomBytes(3).toString('hex').toUpperCase();
};

export const generateResetToken = () => {
  return crypto.randomBytes(32).toString('hex');
};