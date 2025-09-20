const authService = require('../services/auth.service');
const mfaService = require('../services/mfa.service');
const backupService = require('../services/backup.service');
const webhook = require('../services/webhook.service');
const { REFRESH_COOKIE_NAME, REFRESH_COOKIE_PATH } = require('../config/env');
const { jsonResponse } = require('../utils/response');
const webauthnService = require('../services/webhook.service');
const db = require('../config/db');
const crypto = require('crypto');
module.exports = {
  me : async (req, res, next) => {
    try {
      const userId = req.user.id;
      const { rows } = await db.query('SELECT id, email, email_verified, mfa_enabled, created_at FROM users WHERE id=$1', [userId]);
      const user = rows[0];
      if (!user) return res.status(404).json({ ok: false, error: { message: 'User not found' }});
      return res.json(jsonResponse(true, { user }));
    } catch (error) {
      next(error);
      
    }

  },
  register: async (req, res, next) => {
    try {
      const { email, password } = req.body;
      console.log(req.body)
      if (!email) return res.status(400).json({ ok: false, error: { message: 'Missing email' }});
      const user = await authService.register({ email, password });
      await webhook.log('register', user.id, req);
      return res.status(201).json(jsonResponse(true, { userId: user.id }));
    } catch (err) {
      next(err);
    }
  },

loginPassword: async (req, res, next) => {
  try {
    const { email, password, deviceId } = req.body;
    const ip = req.ip;
    const ua = req.get('User-Agent') || '';
    const result = await authService.loginWithPassword({ email, password, ip, ua, deviceId });

    if (result.mfaRequired) {
      await webhook.log('login_password_mfa_required', result.userId, req);
      return res.status(200).json(jsonResponse(true, { mfaRequired: true, userId: result.userId }));
    }

    // set refresh token cookie (httpOnly)
    res.cookie(REFRESH_COOKIE_NAME, result.refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      path: REFRESH_COOKIE_PATH
    });

    // generate CSRF token
    const csrfToken = crypto.randomBytes(32).toString("hex");

    // set csrf cookie (readable by frontend)
    res.cookie("XSRF-TOKEN", csrfToken, {
      httpOnly: false, // frontend must read it
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      path: "/"
    });

    // optionally return it in response too
    await webhook.log('login_success', result.userId, req, { method: 'password' });
    return res.json(jsonResponse(true, { accessToken: result.accessToken, csrfToken }));
  } catch (err) {
    await webhook.log('login_fail', null, req, { reason: err.message });
    next(err);
  }
}
,

  mfaSetup: async (req, res, next) => {
    try {
      const userId = req.user.id;
      const { otpAuthUrl } = await mfaService.generateSetup(userId);
      // return QR data (frontend will render QR)
      res.json(jsonResponse(true, { otpAuthUrl , userId}));
    } catch (err) { next(err); }
  },

  mfaVerify: async (req, res, next) => {
    try {
      const { userId, code, backupCode, deviceId } = req.body;
      console.log(req.body)
      const ip = req.ip; const ua = req.get('User-Agent') || '';
      console.log(ip, ua)
      const result = await mfaService.verifyDuringLogin({ userId, code, backupCode, ip, ua, deviceId });
      if (!result.success) return res.status(400).json({ ok: false, error: { message: result.message }});
      // set refresh cookie and return access token
      res.cookie(REFRESH_COOKIE_NAME, result.refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        path: REFRESH_COOKIE_PATH
      });
      await webhook.log('login_success', result.userId, req, { method: 'mfa' });
      res.json(jsonResponse(true, { accessToken: result.accessToken }));
    } catch (err) { next(err); }
  },

  refreshToken: async (req, res, next) => {
    try {
      const cookie = req.cookies[REFRESH_COOKIE_NAME];
      const ip = req.ip; const ua = req.get('User-Agent') || '';
      const { accessToken, refreshToken: newRefresh, userId } = await authService.rotateRefresh({ cookie, ip, ua });
      // set new cookie
      res.cookie(REFRESH_COOKIE_NAME, newRefresh, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        path: REFRESH_COOKIE_PATH
      });
      await webhook.log('refresh', userId, req);
      res.json(jsonResponse(true, { accessToken }));
    } catch (err) {
      next(err);
    }
  },

  logout: async (req, res, next) => {
    try {
      const cookie = req.cookies[REFRESH_COOKIE_NAME];
      await authService.revokeRefresh({ cookie });
      res.clearCookie(REFRESH_COOKIE_NAME, { path: REFRESH_COOKIE_PATH });
      res.json(jsonResponse(true));
    } catch (err) { next(err); }
  },

  listSessions: async (req, res, next) => {
    try {
      const userId = req.user.id;
      const sessions = await authService.listSessions(userId);
      res.json(jsonResponse(true, { sessions }));
    } catch (err) { next(err); }
  },

  revokeSession: async (req, res, next) => {
    try {
      const userId = req.user.id;
      const { tokenId } = req.body;
      await authService.revokeSession({ userId, tokenId });
      res.json(jsonResponse(true));
    } catch (err) { next(err); }
  },

  generateBackupCodes: async (req, res, next) => {
    try {
      const userId = req.user.id;
      const codes = await backupService.generateBackupCodes(userId);
      // return plain codes only once
      res.json(jsonResponse(true, { codes , userId
      }));
    } catch (err) { next(err); }
  },

  consumeBackupCode: async (req, res, next) => {
    try {
      const { userId, code } = req.body;
      const ok = await backupService.consumeBackupCode({ userId, code });
      res.json(jsonResponse(ok, {}));
    } catch (err) { next(err); }
  },

  

  
  webAuthnRegisterOptions: async (req, res, next) => {
    try {
      const userId = req.user.id;
      const user = { id: userId, email: req.user.email };
      const options = await webauthnService.generateRegistrationOptions(user);
      res.json(jsonResponse(true, options));
    } catch (err) { next(err); }
  },

  webAuthnRegister: async (req, res, next) => {
    try {
      const userId = req.user.id;
      const user = { id: userId, email: req.user.email };
      const result = await webauthnService.verifyRegistrationResponse(user, req.body);
      res.json(jsonResponse(result.verified, {}));
    } catch (err) { next(err); }
  },

  webAuthnLoginOptions: async (req, res, next) => {
    try {
      const { email } = req.body;
      const { rows } = await db.query('SELECT * FROM users WHERE email=$1', [email]);
      if (rows.length === 0) return res.status(404).json(jsonResponse(false, { message: 'User not found' }));

      const user = rows[0];
      const options = await webauthnService.generateLoginOptions(user);
      res.json(jsonResponse(true, { options, userId: user.id }));
    } catch (err) { next(err); }
  },

  webAuthnLogin: async (req, res, next) => {
    try {
      const { userId } = req.body;
      const { rows } = await db.query('SELECT * FROM users WHERE id=$1', [userId]);
      if (rows.length === 0) return res.status(404).json(jsonResponse(false, { message: 'User not found' }));
      const user = rows[0];
      // console.log(req.body)
      // console.log(user)

      const result = await webauthnService.verifyLoginResponse(user, req.body);
      console.log(result ,"result")

      if (result.verified) {
        const ip = req.ip;

        const ua = req.get('User-Agent') || '';
        const deviceId = req.body.deviceId;
        const tokens = await authService.issueTokens(user.id, ip, ua, deviceId);

        res.cookie(REFRESH_COOKIE_NAME, tokens.refreshToken, {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'lax',
          path: REFRESH_COOKIE_PATH,
        });

        res.json(jsonResponse(true, { accessToken: tokens.accessToken }));
      } else {
        res.status(400).json(jsonResponse(false, { message: 'Invalid WebAuthn login' }));
      }
    } catch (err) { next(err); }
  }
};
