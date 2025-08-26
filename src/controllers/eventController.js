import Event from '../models/Event.js';

export const getEvents = async (request, response) => {
  try {
    const { keyword, start, end, status } = request.query;
    let filter = {};

    if (keyword) {
      filter.title = { $regex: keyword, $options: 'i' };
    }

    if (start && end) {
      filter.date = { $gte: new Date(start), $lte: new Date(end) };
    } else if (start) {
      filter.date = { $gte: new Date(start) };
    } else if (end) {
      filter.date = { $lte: new Date(end) };
    }

    if (status) {
      filter.status = status;
    } else if (request.user.userType === 'student') {
      filter.status = 'Scheduled';
    }

    const events = await Event.find(filter).sort({ date: 1, time: 1 });
    response.json({ events });
  } catch (error) {
    console.error('Get events error:', error);
    response.status(500).json({
      error: {
        message: 'Failed to get events',
        code: 'SERVER_ERROR',
      },
    });
  }
};

export const getEventStats = async (request, response) => {
  try {
    const today = new Date();
    today.setHours(0, 0, 0, 0);

    const weekStart = new Date(today);
    weekStart.setDate(today.getDate() - today.getDay());

    const todaysEvents = await Event.countDocuments({
      date: { $gte: today, $lt: new Date(today.getTime() + 86400000) },
    });

    const weeklyEvents = await Event.countDocuments({
      date: { $gte: weekStart, $lt: new Date(weekStart.getTime() + 7 * 86400000) },
    });

    const cancelledEvents = await Event.countDocuments({ status: 'Cancelled' });

    response.json({
      todaysEvents,
      weeklyEvents,
      cancelledEvents,
    });
  } catch (error) {
    console.error('Get event stats error:', error);
    response.status(500).json({
      error: {
        message: 'Failed to get event statistics',
        code: 'SERVER_ERROR',
      },
    });
  }
};

export const createEvent = async (request, response) => {
  try {
    const { title, date, time, description } = request.body;

    const event = new Event({
      title,
      date,
      time,
      description,
      status: 'Pending',
    });

    await event.save();

    response.status(201).json({
      message: 'Event created successfully',
      event,
    });
  } catch (error) {
    console.error('Create event error:', error);
    response.status(500).json({
      error: {
        message: 'Failed to create event',
        code: 'SERVER_ERROR',
      },
    });
  }
};

export const updateEvent = async (request, response) => {
  try {
    const { id } = request.params;
    const { title, date, time, description, status } = request.body;

    const event = await Event.findByIdAndUpdate(
      id,
      { title, date, time, description, status },
      { new: true }
    );

    if (!event) {
      return response.status(404).json({
        error: {
          message: 'Event not found',
          code: 'NOT_FOUND',
        },
      });
    }

    response.json({
      message: 'Event updated successfully',
      event,
    });
  } catch (error) {
    console.error('Update event error:', error);
    response.status(500).json({
      error: {
        message: 'Failed to update event',
        code: 'SERVER_ERROR',
      },
    });
  }
};

export const deleteEvent = async (request, response) => {
  try {
    const { id } = request.params;
    const event = await Event.findByIdAndDelete(id);

    if (!event) {
      return response.status(404).json({
        error: {
          message: 'Event not found',
          code: 'NOT_FOUND',
        },
      });
    }

    response.json({ message: 'Event deleted successfully' });
  } catch (error) {
    console.error('Delete event error:', error);
    response.status(500).json({
      error: {
        message: 'Failed to delete event',
        code: 'SERVER_ERROR',
      },
    });
  }
};