import mongoose from 'mongoose';

const RegistrationDeadlineSchema = new mongoose.Schema({
  deadline: {
    type: Date,
    required: true,
  },
  extended: {
    type: Boolean,
    default: false,
  },
  extendedDeadline: {
    type: Date,
  },
}, { timestamps: true });

const RegistrationDeadline = mongoose.model('RegistrationDeadline', RegistrationDeadlineSchema);

export default RegistrationDeadline;