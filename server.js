import app from './app.js';
import databaseConnection from './db/db.js';

// Handling uncaught Exception
process.on('uncaughtException', (err) => {
  console.log(`Error: ${err.message}`);
  process.exit(1);
});

// config
import dotenv from 'dotenv';
dotenv.config({
  path: './config/.env',
});

databaseConnection();

const server = app.listen(process.env.PORT, () => {
  console.log(`Server is running fine on PORT ${process.env.PORT}`);
});

// Handling unhandled Rejection
process.on('unhandledRejection', (err) => {
  console.log(`Error: Server shutting down on ${err.message}`);
  console.log('Unhandled rejection of server');

  server.close(() => {
    process.exit(1);
  });
});
