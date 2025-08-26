import Maintenance from '../models/Maintenance.js';
import Room from '../models/Room.js';
import User from '../models/User.js';
import { sendEmail } from '../services/emailService.js';

export const getMaintenanceRequests = async (request, response) => {
  try {
    const requests = await Maintenance.find({ status: 'Open' })
      .populate('room', 'roomNumber')
      .sort({ createdAt: -1 });

    const formattedRequests = requests.map(request => ({
      id: request._id,
      text: `Room ${request.room.roomNumber}: ${request.issue}`,
      type: request.type,
      icon: request.icon,
      time: request.createdAt.toLocaleString(),
    }));

    response.json({ requests: formattedRequests });
  } catch (error) {
    console.error('Get maintenance requests error:', error);
    response.status(500).json({
      error: {
        message: 'Failed to get maintenance requests',
        code: 'SERVER_ERROR',
      },
    });
  }
};

export const createMaintenanceRequest = async (request, response) => {
  try {
    const { roomId, issue, type } = request.body;

    const room = await Room.findById(roomId);
    if (!room) {
      return response.status(404).json({
        error: {
          message: 'Room not found',
          code: 'NOT_FOUND',
        },
      });
    }

    const maintenance = new Maintenance({
      room: roomId,
      issue,
      type,
      icon: type === 'warning' ? 'wrench' : 'exclamation-circle',
    });

    await maintenance.save();

    room.status = 'Maintenance';
    await room.save();

    // Notify admins
    const admins = await User.find({ userType: 'admin' });
    for (const admin of admins) {
      await sendEmail(
        admin.email,
        'New Maintenance Request',
        `Maintenance request for Room ${room.roomNumber}: ${issue}`,
        `<p>Please review the maintenance request in the admin dashboard.</p>`
      );
    }

    response.status(201).json({
      message: 'Maintenance request created successfully',
      maintenance,
    });
  } catch (error) {
    console.error('Create maintenance request error:', error);
    response.status(500).json({
      error: {
        message: 'Failed to create maintenance request',
        code: 'SERVER_ERROR',
      },
    });
  }
};

export const resolveMaintenanceRequest = async (request, response) => {
  try {
    const { id } = request.params;
    const maintenance = await Maintenance.findById(id).populate('room');

    if (!maintenance) {
      return response.status(404).json({
        error: {
          message: 'Maintenance request not found',
          code: 'NOT_FOUND',
        },
      });
    }

    maintenance.status = 'Resolved';
    await maintenance.save();

    // Check if room has no other open maintenance requests
    const openRequests = await Maintenance.countDocuments({
      room: maintenance.room._id,
      status: 'Open',
    });

    if (openRequests === 0) {
      const room = await Room.findById(maintenance.room._id);
      room.status = room.occupants.length >= room.capacity ? 'Occupied' : 'Available';
      await room.save();
    }

    response.json({ message: 'Maintenance request resolved' });
  } catch (error) {
    console.error('Resolve maintenance request error:', error);
    response.status(500).json({
      error: {
        message: 'Failed to resolve maintenance request',
        code: 'SERVER_ERROR',
      },
    });
  }
};

export const deleteMaintenanceRequest = async (request, response) => {
  try {
    const { id } = request.params;
    const maintenance = await Maintenance.findById(id);

    if (!maintenance) {
      return response.status(404).json({
        error: {
          message: 'Maintenance request not found',
          code: 'NOT_FOUND',
        },
      });
    }

    const room = await Room.findById(maintenance.room);
    await Maintenance.findByIdAndDelete(id);

    if (room) {
      const remainingMaintenance = await Maintenance.countDocuments({
        room: room._id,
        status: 'Open',
      });

      if (remainingMaintenance === 0) {
        room.status = room.occupants.length >= room.capacity ? 'Occupied' : 'Available';
        await room.save();
      }
    }

    response.json({ message: 'Maintenance request deleted successfully' });
  } catch (error) {
    console.error('Delete maintenance request error:', error);
    response.status(500).json({
      error: {
        message: 'Failed to delete maintenance request',
        code: 'SERVER_ERROR',
      },
    });
  }
};