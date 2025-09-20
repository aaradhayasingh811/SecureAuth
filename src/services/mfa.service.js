const db = require('../config/db');
const { authenticator } = require('otplib');
const crypto = require('crypto');
const { encryptSecret, decryptSecret, sha256Hex } = require('../utils/crypto');
const { signAccessToken } = require('../utils/jwt');
const { REFRESH_TOKEN_TTL_DAYS } = require('../config/env');
const { v4: uuidv4 } = require('uuid');

async function storeRefreshToken({ userId, rawToken, deviceId, ip, ua }) {
  const tokenHash = sha256Hex(rawToken);
  const expiresAt = new Date(Date.now() + REFRESH_TOKEN_TTL_DAYS * 24 * 60 * 60 * 1000);
  const text = `
    INSERT INTO refresh_tokens (id, user_id, token_hash, device_id, ip, ua, issued_at, expires_at)
    VALUES ($1,$2,$3,$4,$5,$6,now(),$7)
    RETURNING id
  `;
  const values = [uuidv4(), userId, tokenHash, deviceId || null, ip || null, ua || null, expiresAt];
  await db.query(text, values);
}

module.exports = {
  generateSetup: async (userId) => {
    const secret = authenticator.generateSecret();
    const otpAuth = authenticator.keyuri(`${userId}`, 'SecureAuth', secret);
    const encrypted = await encryptSecret(Buffer.from(secret, 'utf8'));
    await db.query(`
      INSERT INTO mfa_totp (user_id, secret_encrypted, created_at)
      VALUES ($1,$2,now())
      ON CONFLICT (user_id) DO UPDATE SET secret_encrypted = EXCLUDED.secret_encrypted, created_at = now()
    `, [userId, encrypted]);
    return { otpAuthUrl: otpAuth };
  },

  verifyDuringLogin: async ({ userId, code, backupCode, ip, ua, deviceId }) => {
    if (backupCode) {
      const { rows } = await db.query('SELECT id, code_hash, used FROM backup_codes WHERE user_id=$1 AND used=false', [userId]);
      for (const row of rows) {
        const hash = row.code_hash;
        if (sha256Hex(backupCode) === hash) {
          await db.query('UPDATE backup_codes SET used=true WHERE id=$1', [row.id]);
          const accessToken = signAccessToken({ sub: userId });
          const refreshTokenRaw = crypto.randomBytes(48).toString('base64url');
          await storeRefreshToken({ userId, rawToken: refreshTokenRaw, deviceId, ip, ua });
          return { success: true, accessToken, refreshToken: refreshTokenRaw, userId };
        }
      }
      return { success: false, message: 'Invalid backup code' };
    }

    // TOTP flow
    const { rows } = await db.query('SELECT secret_encrypted FROM mfa_totp WHERE user_id=$1', [userId]);
    if (!rows.length) return { success: false, message: 'MFA not configured' };
    const encrypted = rows[0].secret_encrypted;
    const secret = (await decryptSecret(encrypted)).toString('utf8');
    const ok = authenticator.check(code, secret);
    if (!ok) return { success: false, message: 'Invalid code' };

    // success -> issue tokens
    const accessToken = signAccessToken({ sub: userId });
    const refreshTokenRaw = crypto.randomBytes(48).toString('base64url');
    await storeRefreshToken({ userId, rawToken: refreshTokenRaw, deviceId, ip, ua });
    return { success: true, accessToken, refreshToken: refreshTokenRaw, userId };
  }
};
