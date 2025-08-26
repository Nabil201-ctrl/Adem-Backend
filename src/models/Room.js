import mongoose from 'mongoose';

const RoomSchema = new mongoose.Schema({
  roomNumber: {
    type: String,
    required: true,
    unique: true,
    index: true,
  },
  type: {
    type: String,
    enum: ['Standard', 'Premium'],
    required: true,
  },
  capacity: {
    type: Number,
    required: true,
    min: 1,
  },
  occupants: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
  }],
  status: {
    type: String,
    enum: ['Occupied', 'Available', 'Maintenance'],
    default: 'Available',
  },
}, { timestamps: true });

const Room = mongoose.model('Room', RoomSchema);

export default Room;