const jwt = require('jsonwebtoken');
const { JWT_ACCESS_SECRET, ACCESS_TOKEN_TTL } = require('../config/env');

// Sign short-lived access token
function signAccessToken(payload = {}) {
  const opts = { expiresIn: `${ACCESS_TOKEN_TTL}s` };
  return jwt.sign(payload, JWT_ACCESS_SECRET, opts);
}

function verifyAccessToken(token) {
  try {
    return jwt.verify(token, JWT_ACCESS_SECRET);
  } catch (err) {
    return null;
  }
}

module.exports = { signAccessToken, verifyAccessToken };
