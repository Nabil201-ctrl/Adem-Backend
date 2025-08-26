import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';

dotenv.config();

export const verifyToken = (request, response, next) => {
  const authHeader = request.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return response.status(401).json({
      error: {
        message: 'Access denied. Token missing.',
        code: 'NO_TOKEN',
      },
    });
  }

  try {
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    request.user = verified;
    next();
  } catch (error) {
    return response.status(403).json({
      error: {
        message: 'Invalid token',
        code: 'INVALID_TOKEN',
      },
    });
  }
};

export const isAdmin = (request, response, next) => {
  if (!request.user) {
    return response.status(401).json({
      error: {
        message: 'Authentication required. No user found.',
        code: 'NO_USER',
      },
    });
  }

  if (request.user.userType !== 'admin') {
    return response.status(403).json({
      error: {
        message: 'Access denied. Admins only.',
        code: 'ADMIN_ONLY',
      },
    });
  }

  next();
};

export const isStudent = (request, response, next) => {
  if (request.user.userType !== 'student') {
    return response.status(403).json({
      error: {
        message: 'Access denied. Students only.',
        code: 'STUDENT_ONLY',
      },
    });
  }

  next();
};