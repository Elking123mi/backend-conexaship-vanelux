export function errorHandler (err, req, res, next) {
  // eslint-disable-line no-unused-vars
  const status = err.status || 500;
  const message = err.message || 'Error interno';
  if (process.env.NODE_ENV !== 'production') {
    // Quick log; for production use Winston transports
    // eslint-disable-next-line no-console
    console.error(err);
  }
  return res.status(status).json({ success: false, message });
}

export default errorHandler;
