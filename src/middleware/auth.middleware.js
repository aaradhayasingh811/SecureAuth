const { verifyAccessToken } = require('../utils/jwt');
const db = require('../config/db');

module.exports.requireAuth = async (req, res, next) => {
  try {
    const auth = req.get('Authorization') || '';
    if (!auth.startsWith('Bearer ')) return res.status(401).json({ ok: false, error: { message: 'Missing token' }});
    const token = auth.slice('Bearer '.length);
    const payload = verifyAccessToken(token);
    if (!payload || !payload.sub) return res.status(401).json({ ok: false, error: { message: 'Invalid token' }});
    const { rows } = await db.query('SELECT id, email FROM users WHERE id=$1', [payload.sub]);
    if (!rows.length) return res.status(401).json({ ok: false, error: { message: 'User not found' }});
    req.user = { id: rows[0].id, email: rows[0].email };
    next();
  } catch (err) {
    return res.status(401).json({ ok: false, error: { message: 'Unauthorized' }});
  }
};
