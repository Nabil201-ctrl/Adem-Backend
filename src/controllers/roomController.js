import Room from '../models/Room.js';
import User from '../models/User.js';
import Maintenance from '../models/Maintenance.js';

export const getRooms = async (request, response) => {
  try {
    const rooms = await Room.find().populate('occupants', 'name email matricNumber');
    response.json({ rooms });
  } catch (error) {
    console.error('Get rooms error:', error);
    response.status(500).json({
      error: {
        message: 'Failed to get rooms',
        code: 'SERVER_ERROR',
      },
    });
  }
};

export const getRoomStats = async (request, response) => {
  try {
    const totalRooms = await Room.countDocuments();
    const occupiedRooms = await Room.countDocuments({ status: 'Occupied' });
    const availableRooms = await Room.countDocuments({ status: 'Available' });
    const maintenanceRooms = await Room.countDocuments({ status: 'Maintenance' });

    response.json({
      totalRooms,
      occupiedRooms,
      availableRooms,
      maintenanceRooms,
    });
  } catch (error) {
    console.error('Get room stats error:', error);
    response.status(500).json({
      error: {
        message: 'Failed to get room statistics',
        code: 'SERVER_ERROR',
      },
    });
  }
};

export const createRoom = async (request, response) => {
  try {
    const { roomNumber, type, capacity } = request.body;

    const existingRoom = await Room.findOne({ roomNumber });
    if (existingRoom) {
      return response.status(400).json({
        error: {
          message: 'Room number already exists',
          code: 'ROOM_EXISTS',
        },
      });
    }

    const room = new Room({
      roomNumber,
      type,
      capacity,
    });

    await room.save();

    response.status(201).json({
      message: 'Room created successfully',
      room,
    });
  } catch (error) {
    console.error('Create room error:', error);
    response.status(500).json({
      error: {
        message: 'Failed to create room',
        code: 'SERVER_ERROR',
      },
    });
  }
};

export const updateRoom = async (request, response) => {
  try {
    const { id } = request.params;
    const { roomNumber, type, capacity } = request.body;

    const room = await Room.findById(id);
    if (!room) {
      return response.status(404).json({
        error: {
          message: 'Room not found',
          code: 'NOT_FOUND',
        },
      });
    }

    const existingRoom = await Room.findOne({ roomNumber, _id: { $ne: id } });
    if (existingRoom) {
      return response.status(400).json({
        error: {
          message: 'Room number already exists',
          code: 'ROOM_EXISTS',
        },
      });
    }

    room.roomNumber = roomNumber;
    room.type = type;
    room.capacity = capacity;
    await room.save();

    response.json({
      message: 'Room updated successfully',
      room,
    });
  } catch (error) {
    console.error('Update room error:', error);
    response.status(500).json({
      error: {
        message: 'Failed to update room',
        code: 'SERVER_ERROR',
      },
    });
  }
};

export const deleteRoom = async (request, response) => {
  try {
    const { id } = request.params;
    const room = await Room.findById(id);

    if (!room) {
      return response.status(404).json({
        error: {
          message: 'Room not found',
          code: 'NOT_FOUND',
        },
      });
    }

    if (room.occupants.length > 0) {
      return response.status(400).json({
        error: {
          message: 'Cannot delete room with occupants',
          code: 'ROOM_OCCUPIED',
        },
      });
    }

    const maintenanceRequests = await Maintenance.find({ room: id, status: 'Open' });
    if (maintenanceRequests.length > 0) {
      return response.status(400).json({
        error: {
          message: 'Cannot delete room with open maintenance requests',
          code: 'MAINTENANCE_ACTIVE',
        },
      });
    }

    await User.updateMany({ room: id }, { $unset: { room: '' } });
    await Room.findByIdAndDelete(id);

    response.json({ message: 'Room deleted successfully' });
  } catch (error) {
    console.error('Delete room error:', error);
    response.status(500).json({
      error: {
        message: 'Failed to delete room',
        code: 'SERVER_ERROR',
      },
    });
  }
};

export const assignRoomToStudent = async (request, response) => {
  try {
    const { studentId, roomId } = request.body;

    const student = await User.findOne({ _id: studentId, userType: 'student', status: 'Approved' });
    if (!student) {
      return response.status(404).json({
        error: {
          message: 'Approved student not found',
          code: 'NOT_FOUND',
        },
      });
    }

    const room = await Room.findById(roomId);
    if (!room || room.status === 'Maintenance' || room.occupants.length >= room.capacity) {
      return response.status(400).json({
        error: {
          message: 'Invalid or unavailable room',
          code: 'INVALID_ROOM',
        },
      });
    }

    // Remove student from previous room
    if (student.room) {
      const previousRoom = await Room.findById(student.room);
      if (previousRoom) {
        previousRoom.occupants = previousRoom.occupants.filter(occupant => occupant.toString() !== studentId);
        previousRoom.status = previousRoom.occupants.length >= previousRoom.capacity ? 'Occupied' : 'Available';
        await previousRoom.save();
      }
    }

    // Assign to new room
    student.room = roomId;
    await student.save();

    room.occupants.push(studentId);
    room.status = room.occupants.length >= room.capacity ? 'Occupied' : 'Available';
    await room.save();

    response.json({ message: 'Room assigned successfully' });
  } catch (error) {
    console.error('Assign room error:', error);
    response.status(500).json({
      error: {
        message: 'Failed to assign room',
        code: 'SERVER_ERROR',
      },
    });
  }
};