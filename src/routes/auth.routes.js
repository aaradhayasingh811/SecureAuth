const express = require('express');
const router = express.Router();

const authController = require('../controllers/auth.controller');
const { rateLimiter } = require('../middleware/rateLimit');
const { requireAuth } = require('../middleware/auth.middleware');

// Public
router.post('/register', rateLimiter, authController.register);
router.post('/login/password', rateLimiter, authController.loginPassword);
router.post('/mfa/verify', rateLimiter, authController.mfaVerify);
router.post('/refresh', authController.refreshToken);
router.post('/logout', authController.logout);
router.get('/me', requireAuth, authController.me);

// Protected
router.post('/mfa/setup', requireAuth, authController.mfaSetup);
router.get('/sessions', requireAuth, authController.listSessions);
router.post('/sessions/revoke', requireAuth, authController.revokeSession);
router.post('/backup/generate', requireAuth, authController.generateBackupCodes);
router.post('/backup/consume', rateLimiter, authController.consumeBackupCode);

// WebAuthn placeholders (optional)
router.post('/webauthn/register-options', requireAuth , authController.webAuthnRegisterOptions);
router.post('/webauthn/register', requireAuth, authController.webAuthnRegister);
router.post('/webauthn/login-options', authController.webAuthnLoginOptions);
router.post('/webauthn/login', authController.webAuthnLogin);

module.exports = router;
