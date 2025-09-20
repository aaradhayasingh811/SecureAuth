// src/config/env.js
const PORT = parseInt(process.env.PORT || '3000', 10);
const APP_ORIGIN = process.env.APP_ORIGIN || 'http://localhost:5173';
const NODE_ENV = process.env.NODE_ENV || 'development';

const PEPPER = process.env.PEPPER || 'dev-pepper-please-change';
const JWT_ACCESS_SECRET = process.env.JWT_ACCESS_SECRET || 'dev_jwt_access_secret_change';
const ACCESS_TOKEN_TTL = parseInt(process.env.ACCESS_TOKEN_TTL_SECONDS || '900', 10); // seconds
const REFRESH_TOKEN_TTL_DAYS = parseInt(process.env.REFRESH_TOKEN_TTL_DAYS || '14', 10);

const REFRESH_COOKIE_NAME = process.env.REFRESH_COOKIE_NAME || 'refresh_token';
const REFRESH_COOKIE_PATH = process.env.REFRESH_COOKIE_PATH || '/';

const DATABASE_URL = process.env.DATABASE_URL; 

module.exports = {
  PORT,
  APP_ORIGIN,
  NODE_ENV,
  PEPPER,
  JWT_ACCESS_SECRET,
  ACCESS_TOKEN_TTL,
  REFRESH_TOKEN_TTL_DAYS,
  REFRESH_COOKIE_NAME,
  REFRESH_COOKIE_PATH,
  DATABASE_URL
};
