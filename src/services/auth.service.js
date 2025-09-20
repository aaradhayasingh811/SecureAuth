const db = require('../config/db');
const { hashPassword, verifyPassword, generateRandomToken, sha256Hex } = require('../utils/crypto');
const { signAccessToken } = require('../utils/jwt');
const { REFRESH_TOKEN_TTL_DAYS } = require('../config/env');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');

async function storeRefreshToken({ userId, rawToken, deviceId, ip, ua }) {
  const tokenHash = sha256Hex(rawToken);
  const expiresAt = new Date(Date.now() + REFRESH_TOKEN_TTL_DAYS * 24 * 60 * 60 * 1000);
  const text = `
    INSERT INTO refresh_tokens (id, user_id, token_hash, device_id, ip, ua, issued_at, expires_at)
    VALUES ($1,$2,$3,$4,$5,$6,now(),$7)
    RETURNING id, user_id, device_id, ip, ua, issued_at, expires_at, revoked_at
  `;
  const values = [uuidv4(), userId, tokenHash, deviceId || null, ip || null, ua || null, expiresAt];
  const { rows } = await db.query(text, values);
  return rows[0];
}

module.exports = {
  register: async ({ email, password }) => {
    // check existing
    const existing = await db.query('SELECT id FROM users WHERE email=$1', [email.toLowerCase()]);
    if (existing.rows.length) throw new Error('Email already registered');

    let passwordHash = null;
    let salt = null;
    if (password) {
      const saltBuf = crypto.randomBytes(16);
      salt = saltBuf;
      passwordHash = await hashPassword(password, saltBuf);
    }

    const insert = `
      INSERT INTO users (id, email, password_hash, salt)
      VALUES ($1, $2, $3, $4)
      RETURNING id, email, email_verified, created_at
    `;
    const values = [uuidv4(), email.toLowerCase(), passwordHash, salt];
    const { rows } = await db.query(insert, values);
    return rows[0];
  },

  loginWithPassword: async ({ email, password, ip, ua, deviceId }) => {
    const { rows } = await db.query('SELECT id, password_hash, salt, mfa_enabled FROM users WHERE email=$1', [email.toLowerCase()]);
    if (!rows.length) throw new Error('Invalid email or password');
    const user = rows[0];
    if (!user.password_hash) throw new Error('Password login not configured');

    const ok = await verifyPassword(password, user.salt, user.password_hash);
    if (!ok) throw new Error('Invalid email or password');

    if (user.mfa_enabled) {
      return { mfaRequired: true, userId: user.id };
    }

    const accessToken = signAccessToken({ sub: user.id });
    const refreshTokenRaw = generateRandomToken();
    await storeRefreshToken({ userId: user.id, rawToken: refreshTokenRaw, deviceId, ip, ua });

    return { accessToken, refreshToken: refreshTokenRaw, userId: user.id };
  },

  rotateRefresh: async ({ cookie, ip, ua }) => {
    if (!cookie) throw new Error('Missing refresh cookie');

    const raw = cookie;
    const tokenHash = sha256Hex(raw);
    const findQ = 'SELECT * FROM refresh_tokens WHERE token_hash=$1';
    const { rows } = await db.query(findQ, [tokenHash]);
    if (!rows.length) {
      // token not found => possible reuse or tampering
      throw new Error('Invalid refresh token');
    }
    const record = rows[0];

    if (record.revoked_at) {
      // reuse detected -> revoke all user's tokens
      await db.query('UPDATE refresh_tokens SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL', [record.user_id]);
      throw new Error('Refresh token reuse detected. All sessions revoked.');
    }

    if (new Date(record.expires_at) < new Date()) {
      throw new Error('Refresh token expired');
    }

    // revoke old and create new
    await db.query('UPDATE refresh_tokens SET revoked_at=now(), last_used_at=now() WHERE id=$1', [record.id]);
    const newRaw = generateRandomToken();
    await storeRefreshToken({ userId: record.user_id, rawToken: newRaw, deviceId: record.device_id, ip, ua });
    const accessToken = signAccessToken({ sub: record.user_id });

    return { accessToken, refreshToken: newRaw, userId: record.user_id };
  },

  revokeRefresh: async ({ cookie }) => {
    if (!cookie) return;
    const tokenHash = sha256Hex(cookie);
    await db.query('UPDATE refresh_tokens SET revoked_at=now() WHERE token_hash=$1', [tokenHash]);
  },

  listSessions: async (userId) => {
    const q = `
      SELECT id, device_id, ip, ua, issued_at, last_used_at, expires_at, revoked_at
      FROM refresh_tokens WHERE user_id=$1 ORDER BY issued_at DESC
    `;
    const { rows } = await db.query(q, [userId]);
    return rows;
  },

  revokeSession: async ({ userId, tokenId }) => {
    const { rows } = await db.query('SELECT user_id FROM refresh_tokens WHERE id=$1', [tokenId]);
    if (!rows.length) throw new Error('Session not found');
    if (rows[0].user_id !== userId) throw new Error('Session not found');
    await db.query('UPDATE refresh_tokens SET revoked_at=now() WHERE id=$1', [tokenId]);
  }
};
