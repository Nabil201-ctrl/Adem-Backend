import multer from 'multer';
import { CloudinaryStorage } from 'multer-storage-cloudinary';
import cloudinary from './cloudinary.js';

const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'payment-slips',
    allowed_formats: ['jpeg', 'jpg', 'png', 'pdf'],
    resource_type: 'auto',
  },
});

const fileFilter = (request, file, callback) => {
  const filetypes = /jpeg|jpg|png|pdf/;
  const extname = filetypes.test(file.originalname.toLowerCase());
  const mimetype = filetypes.test(file.mimetype);

  if (extname && mimetype) {
    return callback(null, true);
  } else {
    callback(new Error('Invalid file type. Only JPEG, PNG, and PDF allowed.'), false);
  }
};

const upload = multer({
  storage,
  fileFilter,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
});

export default upload;