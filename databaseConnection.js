// Load environment variables from the .env file (MongoDB credentials, session secret, etc.)
require('dotenv').config();

// Extract MongoDB connection details and session secrets from environment variables
const mongodb_host = process.env.MONGODB_HOST;          // The MongoDB host (e.g., MongoDB Atlas cluster URL)
const mongodb_user = process.env.MONGODB_USER;          // The MongoDB username
const mongodb_password = process.env.MONGODB_PASSWORD;  // The MongoDB password
const mongodb_database_users = process.env.MONGODB_DATABASE_USERS; // The name of the database for users
const mongodb_database_sessions = process.env.MONGODB_DATABASE_SESSIONS; // The name of the database for sessions
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;  // The session secret for encrypting session data

// Import the MongoClient class from the MongoDB driver
const { MongoClient } = require('mongodb');

// Construct the MongoDB URI using the connection details from the .env file
const atlasURI = `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/?retryWrites=true&w=majority`;

// Create a new MongoClient instance
const client = new MongoClient(atlasURI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

let database; // Will hold the connected database instance

// Connect to MongoDB and set the `database` reference to the users database
async function connectToDatabase() {
  try {
    await client.connect();
    database = client.db(mongodb_database_users); // Set the default database for users
    console.log("✅ Successfully connected to MongoDB.");
  } catch (err) {
    console.error("❌ Failed to connect to MongoDB:", err);
    throw err;
  }
}

// Immediately connect on module load
connectToDatabase();

module.exports = { database };
