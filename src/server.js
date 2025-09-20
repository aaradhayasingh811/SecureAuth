const app = require('./app');
const { PORT } = require('./config/env');

app.listen(PORT, () => {
  console.log(`Server listening on http://localhost:${PORT} (env=${process.env.NODE_ENV})`);
});
