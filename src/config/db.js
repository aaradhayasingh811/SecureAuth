const { Pool } = require('pg');
const { DATABASE_URL } = require('./env');

if (!DATABASE_URL) {
  console.error('DATABASE_URL is not set. Set it in your environment or .env file.');
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
});

pool.on('error', (err) => {
  console.error('Unexpected error on idle Postgres client', err);
  process.exit(-1);
});

module.exports = {
  query: (text, params) => pool.query(text, params),
  pool
};
