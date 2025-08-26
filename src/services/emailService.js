import nodemailer from 'nodemailer';
import dotenv from 'dotenv';

dotenv.config();

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_PASS,
  },
});

export const sendEmail = async (recipient, subject, text, html) => {
  const mailOptions = {
    from: process.env.GMAIL_USER,
    to: recipient,
    subject,
    text,
    html,
  };

  try {
    const info = await transporter.sendMail(mailOptions);
    console.log('Email sent successfully:', info.response);
    return info;
  } catch (error) {
    console.error('Error sending email:', error);
    throw new Error(`Failed to send email: ${error.message}`);
  }
};

export const sendWelcomeEmail = async (user) => {
  const subject = 'Welcome to Adem Baba Hostel';
  const text = `Hello ${user.name}, welcome to Adem Baba Hostel. Your account has been created successfully.`;
  const html = `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto;">
      <h2 style="color: #232f3e;">Welcome to Adem Baba Hostel</h2>
      <p>Hello ${user.name},</p>
      <p>Your account has been created successfully.</p>
      <p>Thank you for choosing Adem Baba Hostel.</p>
    </div>
  `;

  return sendEmail(user.email, subject, text, html);
};

export const sendPasswordResetEmail = async (user, resetToken) => {
  const resetUrl = `${process.env.FRONTEND_URL}/reset-password?token=${resetToken}`;
  const subject = 'Password Reset Request';
  const text = `Hello ${user.name}, you requested to reset your password. Use this link: ${resetUrl}`;
  const html = `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto;">
      <h2 style="color: #232f3e;">Password Reset Request</h2>
      <p>Hello ${user.name},</p>
      <p>You requested to reset your password. Click the button below to proceed:</p>
      <a href="${resetUrl}" style="background-color: #0073bb; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Reset Password</a>
      <p>This link will expire in 1 hour.</p>
    </div>
  `;

  return sendEmail(user.email, subject, text, html);
};