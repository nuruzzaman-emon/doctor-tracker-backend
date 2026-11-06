import { MongoClient } from "mongodb";
import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import dotenv from "dotenv";
dotenv.config();

import bcrypt from "bcryptjs";
const port = process.env.PORT || 5000;
const app = express();

const uri = process.env.MONGODB_URI;

// Middleware
app.use(express.json());
app.use(cookieParser());
app.use(
  cors({
    origin: "http://localhost:3000", // or your exact frontend URL
    credentials: true,
  }),
);
const client = new MongoClient(uri);
async function run() {
  try {
    await client.connect();
    const database = client.db("doctor-tracker");
    const usersCollection = await database.collection("users");

    // server.js or users.route.js
    app.post("/users", async (req, res) => {
      try {
        const userData = req.body;
        // Save user to database logic here...

        res.status(200).json({ message: "user created succesfully" });
      } catch (error) {
        res.status(500).json({ success: false, message: error.message });
      }
    });

    app.get("/users", async (req, res) => {
      res.send("all users");
    });
  } catch (error) {
    console.error(error);
    await client.close();
  }
}

app.get("/", async (req, res) => {
  res.send("succesfully created");
});

run().then(
  app.listen(port, () => {
    console.log(`app running on ${port}`);
  }),
);
