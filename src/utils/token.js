import jwt from 'jsonwebtoken';

const defaultAccessTtl = process.env.JWT_EXPIRES_IN || '24h';
const defaultRefreshTtl = process.env.JWT_REFRESH_EXPIRES_IN || '30d';

export function signAccessToken (payload, options = {}) {
  return jwt.sign(payload, process.env.JWT_SECRET, {
    expiresIn: options.expiresIn || defaultAccessTtl
  });
}

export function signRefreshToken (payload, options = {}) {
  return jwt.sign(payload, process.env.JWT_REFRESH_SECRET, {
    expiresIn: options.expiresIn || defaultRefreshTtl
  });
}

export function verifyAccessToken (token) {
  return jwt.verify(token, process.env.JWT_SECRET);
}

export function verifyRefreshToken (token) {
  return jwt.verify(token, process.env.JWT_REFRESH_SECRET);
}
