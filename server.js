const { connection } = require("mongoose");
const app = require("./app");
const databaseConnection = require("./db/db");

// Handling uncaught Exception
process.on("uncaughtException", (err) => {
  console.log(`Error: ${err.message}`);
  process.exit(1);
});

// config
if (process.env.NODE_ENV !== "PRODUCTION ") { 
    require("dotenv").config({ 
        path: "./config/.env",
      });
      
}

databaseConnection()

const server = app.listen(process.env.PORT, () => {
  console.log(`Server is running fine on PORT ${process.env.PORT}`);
});

// Handling unhandled Rejection
process.on("unhandledRejection", (err) => {
  console.log(`Error: Server shutting down on ${err.message}`);
  console.log("Unhandled rejection of server");

  server.close(() => {
    process.exit(1);
  });
});
