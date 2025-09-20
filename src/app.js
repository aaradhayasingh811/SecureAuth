require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const cookieParser = require('cookie-parser');

const { APP_ORIGIN, NODE_ENV } = require('./config/env');
const routes = require('./routes');

const app = express();

// app.use(helmet());
app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'wasm-unsafe-eval'", "'inline-speculation-rules'"],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: [],
    },
  })
);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.use(cors({
  origin: APP_ORIGIN,
  credentials: true
}));

app.use('/api', routes);

app.get('/health', (req, res) => res.json({ ok: true, env: NODE_ENV }));

app.use((err, req, res, next) => {
  console.error(err);
  const status = err.status || 500;
  res.status(status).json({
    ok: false,
    error: { message: err.message || 'Internal Server Error' }
  });
});

module.exports = app;
