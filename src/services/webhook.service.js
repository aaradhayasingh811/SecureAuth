const db = require('../config/db');
const { v4: uuidv4 } = require('uuid');
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');

// RP config
const rpName = 'My Secure App';
const rpID = process.env.RP_ID || 'localhost';
const origin = process.env.ORIGIN || 'http://localhost:5173';

const pendingChallenges = new Map();

function deleteChallenge(userId) {
  pendingChallenges.delete(String(userId));
}
function storeChallenge(userId, challenge, userVerification) {
  pendingChallenges.set(String(userId), { challenge, userVerification });
  console.log(pendingChallenges,"pendingChallenges")
}

function getChallenge(userId) {
  const stored = pendingChallenges.get(String(userId));
  return stored ? stored.challenge : null;
}


module.exports = {
  log: async (eventType, userId = null, req = null, meta = null) => {
    try {
      const ip = req ? req.ip : null;
      const ua = req ? req.get('User-Agent') : null;
      const id = uuidv4();
      await db.query(
        `INSERT INTO auth_events (id, user_id, event_type, ip, ua, meta, created_at)
         VALUES ($1,$2,$3,$4,$5,$6,now())`,
        [id, userId, eventType, ip, ua, meta ? JSON.stringify(meta) : null]
      );
    } catch (err) {
      console.error('Failed to log auth event', err);
    }
  },

  // REGISTER OPTIONS
  generateRegistrationOptions: async (user) => {
    const options = await generateRegistrationOptions({
      rpName,
      rpID,
      userID: Buffer.from(String(user.id)), // always string -> Buffer
      userName: user.email,
      attestationType: 'none',
      authenticatorSelection: {
        userVerification: 'preferred',
        residentKey: 'preferred',
      },
      excludeCredentials: [], // can be filled with existing credentials
    });
    console.log(options.challenge)
    storeChallenge(user.id, options.challenge, options.authenticatorSelection?.userVerification);


    return options;
  },

  // REGISTER VERIFY
  verifyRegistrationResponse: async (user, response) => {
    const expectedChallenge = getChallenge(user.id);
    if (!expectedChallenge) throw new Error('No challenge for user');

    console.log(expectedChallenge ,"challenge")
    console.log(response ,"response")

    const verification = await verifyRegistrationResponse({
      response,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      user : user
    });

    console.log(verification ,"verification")

    if (!verification.verified) throw new Error('Registration failed');

    const { credentialPublicKey, credentialID, counter } =
      verification.registrationInfo;

    // Store credential in DB
    const credentialIdBase64url = Buffer.from(credentialID).toString('base64url');
    await db.query(
      `INSERT INTO webauthn_credentials
      (id, user_id, credential_id, public_key, sign_count, transports, device_name, attestation)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
      [
        uuidv4(),
        user.id,
        credentialIdBase64url,
        Buffer.from(credentialPublicKey),
        counter,
        response.response.transports || [],
        response.response.clientExtensionResults?.authenticatorDisplayName || 'Unknown Device',
        JSON.stringify(response),
      ]
    );

    deleteChallenge(user.id);

    return { verified: true };
  },

  
  // LOGIN OPTIONS
  generateLoginOptions: async (user) => {
    const { rows } = await db.query(
      `SELECT credential_id FROM webauthn_credentials WHERE user_id=$1`,
      [user.id]
    );

    const allowCredentials = rows.map((r) => ({
      id: r.credential_id,
      type: 'public-key',
    }));

    const options = generateAuthenticationOptions({
      rpID,
      allowCredentials,
      userVerification: 'preferred',
    });

    storeChallenge(user.id, options.challenge);

    return options;
  },

  // LOGIN VERIFY
  verifyLoginResponse: async (user, response) => {
    const expectedChallenge = getChallenge(user.id);
    if (!expectedChallenge) throw new Error('No challenge for login');

    // fetch user credentials
    const { rows } = await db.query(
      `SELECT * FROM webauthn_credentials WHERE user_id=$1`,
      [user.id]
    );

    const credential = rows.find((c) => c.credential_id === response.id);
    if (!credential) throw new Error('Unknown credential');

    const verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      authenticator: {
        credentialPublicKey: credential.public_key,
        credentialID: Buffer.from(credential.credential_id, 'base64url'),
        counter: credential.sign_count,
      },
    });

    if (!verification.verified) throw new Error('Login failed');

    await db.query(
      `UPDATE webauthn_credentials SET sign_count=$1 WHERE id=$2`,
      [verification.authenticationInfo.newCounter, credential.id]
    );

    deleteChallenge(user.id);

    return { verified: true };
  },
};

