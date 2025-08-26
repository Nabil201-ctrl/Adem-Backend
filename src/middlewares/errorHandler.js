export const errorHandler = (error, request, response, next) => {
  console.error('Unhandled error:', error);

  const statusCode = error.statusCode || 500;
  const message = error.message || 'Internal Server Error';
  const code = error.code || 'SERVER_ERROR';
  const details = process.env.NODE_ENV === 'development' ? error.stack : undefined;

  response.status(statusCode).json({
    error: {
      message,
      code,
      details,
    },
  });
};