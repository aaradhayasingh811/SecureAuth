const db = require('../config/db');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');
const { sha256Hex } = require('../utils/crypto');

module.exports = {
  generateBackupCodes: async (userId) => {
    // generate 10 codes, store sha256(code) and return plaintext list (show once)
    const codes = [];
    for (let i = 0; i < 10; i++) {
      // simple readable code: 8 char hex
      const plain = crypto.randomBytes(4).toString('hex');
      const hash = sha256Hex(plain);
      await db.query(`
        INSERT INTO backup_codes (id, user_id, code_hash, used, created_at)
        VALUES ($1,$2,$3,false,now())
      `, [uuidv4(), userId, hash]);
      codes.push(plain);
    }
    return codes;
  },

  consumeBackupCode: async ({ userId, code }) => {
    const hash = sha256Hex(code);
    const { rows } = await db.query('SELECT id FROM backup_codes WHERE user_id=$1 AND code_hash=$2 AND used=false LIMIT 1', [userId, hash]);
    if (!rows.length) return false;
    const id = rows[0].id;
    await db.query('UPDATE backup_codes SET used=true WHERE id=$1', [id]);
    return true;
  }
};
