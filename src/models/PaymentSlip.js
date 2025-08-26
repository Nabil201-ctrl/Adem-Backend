import mongoose from 'mongoose';

const PaymentSlipSchema = new mongoose.Schema({
  student: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  },
  fileUrl: {
    type: String,
    required: true,
  },
  publicId: {
    type: String,
    required: true,
  },
  fileType: {
    type: String,
    enum: ['image', 'raw'],
    required: true,
  },
  status: {
    type: String,
    enum: ['Pending', 'Approved', 'Rejected'],
    default: 'Pending',
  },
  amount: {
    type: Number,
    required: true,
    min: 0,
  },
}, { timestamps: true });

const PaymentSlip = mongoose.model('PaymentSlip', PaymentSlipSchema);

export default PaymentSlip;