import multer from 'multer';
import { CloudinaryStorage } from 'multer-storage-cloudinary';
import cloudinary from '../config/cloudinary.js';

const documentStorage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: (request, file) => {
    let folder;
    if (file.fieldname === 'jambOrCgpa') {
      folder = request.body.jambOrCgpaType === 'JAMB_RESULT' ? 'jamb_result' : 'cgpa';
    } else if (file.fieldname === 'admissionLetter') {
      folder = 'admission_letter';
    } else if (file.fieldname === 'nin') {
      folder = 'nin';
    }
    return {
      folder: `adem_baba/documents/${folder}`,
      allowed_formats: ['jpeg', 'jpg', 'png'],
      resource_type: 'image',
    };
  },
});

const documentFileFilter = (request, file, callback) => {
  const filetypes = /jpeg|jpg|png/;
  const extname = filetypes.test(file.originalname.toLowerCase());
  const mimetype = filetypes.test(file.mimetype);

  if (extname && mimetype) {
    return callback(null, true);
  } else {
    callback(new Error('Invalid file type. Only JPEG and PNG allowed.'), false);
  }
};

export const uploadDocuments = multer({
  storage: documentStorage,
  fileFilter: documentFileFilter,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
}).fields([
  { name: 'jambOrCgpa', maxCount: 1 },
  { name: 'admissionLetter', maxCount: 1 },
  { name: 'nin', maxCount: 1 },
]);

export const handleUploadErrors = (error, request, response, next) => {
  if (error instanceof multer.MulterError) {
    return response.status(400).json({
      error: {
        message: error.message,
        code: 'UPLOAD_ERROR',
      },
    });
  } else if (error) {
    return response.status(400).json({
      error: {
        message: error.message,
        code: 'FILE_ERROR',
      },
    });
  }
  next();
};