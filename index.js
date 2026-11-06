import { MongoClient, ObjectId } from "mongodb";
import express from "express";
import cors from "cors";
import jwt from "jsonwebtoken";
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
    origin: [
      "https://doctor-tracker-web-platform.vercel.app",
      "http://localhost:3000",
    ],
    credentials: true,
  }),
);
const client = new MongoClient(uri);
async function run() {
  try {
    await client.connect();
    const database = client.db("doctor-tracker");
    const usersCollection = database.collection("users");
    const doctorsCollection = database.collection("doctors");
    const patientsCollection = database.collection("patients");
    await Promise.all([
      usersCollection.createIndex({ email: 1 }),
      doctorsCollection.createIndex({ name: 1 }),
      doctorsCollection.createIndex({ createdAt: -1 }),
      patientsCollection.createIndex({ doctorId: 1, createdAt: -1 }),
      patientsCollection.createIndex({ createdAt: -1, name: 1 }),
    ]);

    const requireAdmin = async (req, res, next) => {
      const token = req.cookies?.token;
      if (!token)
        return res.status(401).json({ message: "Authentication required" });
      try {
        const payload = jwt.verify(token, process.env.JWT_SECRET);
        const user = await usersCollection.findOne({ email: payload.email });
        if (!user)
          return res.status(401).json({ message: "Authentication required" });
        if (user.role !== "admin")
          return res.status(403).json({ message: "Admin access required" });
        req.user = user;
        return next();
      } catch (error) {
        if (
          error.name === "JsonWebTokenError" ||
          error.name === "TokenExpiredError"
        ) {
          return res
            .status(401)
            .json({ message: "Invalid or expired session" });
        }
        console.error("Admin authorization failed:", error);
        return res.status(500).json({ message: "Could not verify access" });
      }
    };

    const makeSearchFilter = (search, fields) => {
      const value = String(search || "").trim();
      if (!value) return {};
      const escaped = value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      const pattern = new RegExp(escaped, "i");
      return { $or: fields.map((field) => ({ [field]: pattern })) };
    };

    // for register
    app.post("/register", async (req, res) => {
      try {
        const { password, ...userData } = req.body ?? {};
        if (typeof password !== "string" || password.length < 8) {
          return res.status(400).json({
            success: false,
            message: "Password must be at least 8 characters long",
          });
        }

        const hash_password = await bcrypt.hash(password, 12);
        const user = { ...userData, role: "user", hash_password };
        const result = await usersCollection.insertOne(user);
        res.status(201).json({
          success: true,
          message: "User created successfully",
          userId: result.insertedId,
        });
      } catch (error) {
        console.error("Failed to create user:", error);
        res
          .status(500)
          .json({ success: false, message: "Failed to create user" });
      }
    });

    // for login
    app.post("/login", async (req, res) => {
      const { email, password } = req.body;

      try {
        // ✅ Fix: Pass an object query to findOne
        const user = await usersCollection.findOne({ email });
        if (!user) {
          return res.status(400).json({ message: "Invalid credentials" });
        }

        const isMatch = await bcrypt.compare(password, user.hash_password);
        if (!isMatch) {
          return res.status(400).json({ message: "Invalid credentials" });
        }

        // Create JWT payload
        const payload = { userId: user._id || user.id, email: user.email };

        // Sign token (expires in 1 day)
        const token = jwt.sign(payload, process.env.JWT_SECRET, {
          expiresIn: "1d",
        });

        // Send token back in an HttpOnly cookie
        res.cookie("token", token, {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          sameSite: "strict",
          maxAge: 24 * 60 * 60 * 1000, // 1 day
        });

        // Send success response
        return res.status(200).json({ message: "Logged in successfully" });
      } catch (error) {
        console.error("Login server error:", error);
        // ✅ Fix: Always send a response in the catch block so it never hits a 500 without JSON
        return res
          .status(500)
          .json({ message: "Internal server error", error: error.message });
      }
    });

    app.post("/logout", (req, res) => {
      res.clearCookie("token", {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "strict",
        path: "/",
      });
      return res.status(200).json({ message: "Logged out successfully" });
    });

    app.get("/me", async (req, res) => {
      const token = req.cookies?.token;
      if (!token) {
        return res.status(401).json({ message: "Authentication required" });
      }

      try {
        const payload = jwt.verify(token, process.env.JWT_SECRET);
        if (typeof payload !== "object" || !payload.email) {
          return res
            .status(401)
            .json({ message: "Invalid or expired session" });
        }

        const user = await usersCollection.findOne(
          { email: payload.email },
          { projection: { hash_password: 0 } },
        );
        if (!user) {
          return res
            .status(401)
            .json({ message: "Invalid or expired session" });
        }

        return res.status(200).json(user);
      } catch (error) {
        if (
          error.name === "JsonWebTokenError" ||
          error.name === "TokenExpiredError"
        ) {
          return res
            .status(401)
            .json({ message: "Invalid or expired session" });
        }
        console.error("Get current user failed:", error);
        return res
          .status(500)
          .json({ message: "Could not get the current user" });
      }
    });

    app.get("/doctors", requireAdmin, async (req, res) => {
      try {
        const page = Math.max(1, Number.parseInt(req.query.page, 10) || 1);
        const limit = Math.min(
          100,
          Math.max(1, Number.parseInt(req.query.limit, 10) || 20),
        );
        const filter = makeSearchFilter(req.query.search, [
          "name",
          "specialization",
          "hospital",
          "email",
          "phone",
        ]);
        if (req.query.specialization) {
          const specialization = String(req.query.specialization)
            .trim()
            .replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
          if (specialization)
            filter.specialization = new RegExp(specialization, "i");
        }
        const dateRange = {};
        if (req.query.from) {
          const from = new Date(`${req.query.from}T00:00:00.000Z`);
          if (Number.isNaN(from.getTime()))
            return res.status(400).json({ message: "Invalid start date" });
          dateRange.$gte = from;
        }
        if (req.query.to) {
          const to = new Date(`${req.query.to}T23:59:59.999Z`);
          if (Number.isNaN(to.getTime()))
            return res.status(400).json({ message: "Invalid end date" });
          dateRange.$lte = to;
        }
        if (
          dateRange.$gte &&
          dateRange.$lte &&
          dateRange.$gte > dateRange.$lte
        ) {
          return res
            .status(400)
            .json({ message: "Start date must be before end date" });
        }
        if (Object.keys(dateRange).length) filter.createdAt = dateRange;
        const [doctors, total] = await Promise.all([
          doctorsCollection
            .aggregate([
              { $match: filter },
              { $sort: { name: 1 } },
              { $skip: (page - 1) * limit },
              { $limit: limit },
              {
                $lookup: {
                  from: "patients",
                  let: { doctorId: "$_id" },
                  pipeline: [
                    { $match: { $expr: { $eq: ["$doctorId", "$$doctorId"] } } },
                    { $count: "patientCount" },
                  ],
                  as: "patientStats",
                },
              },
              {
                $addFields: {
                  patientCount: {
                    $ifNull: [
                      { $arrayElemAt: ["$patientStats.patientCount", 0] },
                      0,
                    ],
                  },
                },
              },
              { $project: { patientStats: 0 } },
            ])
            .toArray(),
          doctorsCollection.countDocuments(filter),
        ]);
        return res.json({
          doctors,
          total,
          page,
          pages: Math.ceil(total / limit),
        });
      } catch (error) {
        console.error("Failed to load doctors:", error);
        return res.status(500).json({ message: "Could not load doctors" });
      }
    });

    app.post("/doctors", requireAdmin, async (req, res) => {
      try {
        const { name, specialization, hospital, phone, email } = req.body ?? {};
        const doctor = {
          name: String(name || "").trim(),
          specialization: String(specialization || "").trim(),
          hospital: String(hospital || "").trim(),
          phone: String(phone || "").trim(),
          email: String(email || "")
            .trim()
            .toLowerCase(),
        };
        if (Object.values(doctor).some((value) => !value)) {
          return res
            .status(400)
            .json({
              message:
                "Name, specialization, hospital, phone, and email are required",
            });
        }
        const existing = await doctorsCollection.findOne({
          email: doctor.email,
        });
        if (existing)
          return res
            .status(409)
            .json({ message: "A doctor with this email already exists" });
        doctor.createdAt = new Date();
        const result = await doctorsCollection.insertOne(doctor);
        return res
          .status(201)
          .json({ doctor: { ...doctor, _id: result.insertedId } });
      } catch (error) {
        console.error("Failed to create doctor:", error);
        return res.status(500).json({ message: "Could not create doctor" });
      }
    });

    app.get("/doctors/:doctorId/patients", requireAdmin, async (req, res) => {
      if (!ObjectId.isValid(req.params.doctorId)) {
        return res.status(400).json({ message: "Invalid doctor ID" });
      }
      try {
        const doctorId = new ObjectId(req.params.doctorId);
        const doctor = await doctorsCollection.findOne({ _id: doctorId });
        if (!doctor)
          return res.status(404).json({ message: "Doctor not found" });
        const patients = await patientsCollection
          .find({ doctorId })
          .sort({ createdAt: -1, name: 1 })
          .toArray();
        return res.json({ doctor, patients, total: patients.length });
      } catch (error) {
        console.error("Failed to load doctor's patients:", error);
        return res
          .status(500)
          .json({ message: "Could not load this doctor's patients" });
      }
    });

    app.post("/doctors/:doctorId/patients", requireAdmin, async (req, res) => {
      if (!ObjectId.isValid(req.params.doctorId)) {
        return res.status(400).json({ message: "Invalid doctor ID" });
      }
      try {
        const doctorId = new ObjectId(req.params.doctorId);
        const doctor = await doctorsCollection.findOne({ _id: doctorId });
        if (!doctor)
          return res.status(404).json({ message: "Doctor not found" });
        const patient = {
          name: String(req.body?.name || "").trim(),
          condition: String(req.body?.condition || "").trim(),
          phone: String(req.body?.phone || "").trim(),
          email: String(req.body?.email || "")
            .trim()
            .toLowerCase(),
          doctorId,
          createdAt: new Date(),
        };
        if (!patient.name || !patient.condition) {
          return res
            .status(400)
            .json({ message: "Patient name and condition are required" });
        }
        const result = await patientsCollection.insertOne(patient);
        return res
          .status(201)
          .json({ patient: { ...patient, _id: result.insertedId } });
      } catch (error) {
        console.error("Failed to add patient:", error);
        return res.status(500).json({ message: "Could not add patient" });
      }
    });

    app.delete(
      "/doctors/:doctorId/patients/:patientId",
      requireAdmin,
      async (req, res) => {
        if (
          !ObjectId.isValid(req.params.doctorId) ||
          !ObjectId.isValid(req.params.patientId)
        ) {
          return res
            .status(400)
            .json({ message: "Invalid doctor or patient ID" });
        }
        try {
          const result = await patientsCollection.deleteOne({
            _id: new ObjectId(req.params.patientId),
            doctorId: new ObjectId(req.params.doctorId),
          });
          if (!result.deletedCount)
            return res
              .status(404)
              .json({ message: "Patient not found for this doctor" });
          return res.json({
            message: "Patient removed from the doctor's list",
          });
        } catch (error) {
          console.error("Failed to delete patient:", error);
          return res.status(500).json({ message: "Could not delete patient" });
        }
      },
    );
    app.get("/patients", requireAdmin, async (req, res) => {
      try {
        const page = Math.max(1, Number.parseInt(req.query.page, 10) || 1);
        const limit = Math.min(
          100,
          Math.max(1, Number.parseInt(req.query.limit, 10) || 20),
        );
        const filter = makeSearchFilter(req.query.search, [
          "name",
          "condition",
          "phone",
          "email",
        ]);
        if (req.query.condition) {
          const condition = String(req.query.condition)
            .trim()
            .replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
          if (condition) filter.condition = new RegExp(condition, "i");
        }
        if (req.query.doctorId) {
          if (!ObjectId.isValid(req.query.doctorId))
            return res.status(400).json({ message: "Invalid doctor ID" });
          filter.doctorId = new ObjectId(req.query.doctorId);
        }
        const dateRange = {};
        if (req.query.from) {
          const from = new Date(`${req.query.from}T00:00:00.000Z`);
          if (Number.isNaN(from.getTime()))
            return res.status(400).json({ message: "Invalid start date" });
          dateRange.$gte = from;
        }
        if (req.query.to) {
          const to = new Date(`${req.query.to}T23:59:59.999Z`);
          if (Number.isNaN(to.getTime()))
            return res.status(400).json({ message: "Invalid end date" });
          dateRange.$lte = to;
        }
        if (
          dateRange.$gte &&
          dateRange.$lte &&
          dateRange.$gte > dateRange.$lte
        ) {
          return res
            .status(400)
            .json({ message: "Start date must be before end date" });
        }
        if (Object.keys(dateRange).length) filter.createdAt = dateRange;
        const [patients, total] = await Promise.all([
          patientsCollection
            .aggregate([
              { $match: filter },
              { $sort: { createdAt: -1, name: 1 } },
              { $skip: (page - 1) * limit },
              { $limit: limit },
              {
                $lookup: {
                  from: "doctors",
                  localField: "doctorId",
                  foreignField: "_id",
                  as: "doctor",
                },
              },
              {
                $unwind: { path: "$doctor", preserveNullAndEmptyArrays: true },
              },
              { $addFields: { doctorName: "$doctor.name" } },
              { $project: { doctor: 0 } },
            ])
            .toArray(),
          patientsCollection.countDocuments(filter),
        ]);
        return res.json({
          patients,
          total,
          page,
          pages: Math.ceil(total / limit),
        });
      } catch (error) {
        console.error("Failed to load patients:", error);
        return res.status(500).json({ message: "Could not load patients" });
      }
    });

    app.patch("/patients/:patientId", requireAdmin, async (req, res) => {
      if (!ObjectId.isValid(req.params.patientId)) {
        return res.status(400).json({ message: "Invalid patient ID" });
      }
      const updates = {
        name: String(req.body?.name || "").trim(),
        condition: String(req.body?.condition || "").trim(),
        phone: String(req.body?.phone || "").trim(),
        email: String(req.body?.email || "")
          .trim()
          .toLowerCase(),
      };
      if (!updates.name || !updates.condition) {
        return res
          .status(400)
          .json({ message: "Patient name and condition are required" });
      }
      try {
        const _id = new ObjectId(req.params.patientId);
        const result = await patientsCollection.updateOne(
          { _id },
          { $set: updates },
        );
        if (!result.matchedCount)
          return res.status(404).json({ message: "Patient not found" });
        const patient = await patientsCollection.findOne({ _id });
        return res.json({ patient });
      } catch (error) {
        console.error("Failed to update patient:", error);
        return res.status(500).json({ message: "Could not update patient" });
      }
    });

    app.delete("/patients/:patientId", requireAdmin, async (req, res) => {
      if (!ObjectId.isValid(req.params.patientId)) {
        return res.status(400).json({ message: "Invalid patient ID" });
      }
      try {
        const result = await patientsCollection.deleteOne({
          _id: new ObjectId(req.params.patientId),
        });
        if (!result.deletedCount)
          return res.status(404).json({ message: "Patient not found" });
        return res.json({ message: "Patient deleted successfully" });
      } catch (error) {
        console.error("Failed to delete patient:", error);
        return res.status(500).json({ message: "Could not delete patient" });
      }
    });
    app.get("/dashboard/stats", requireAdmin, async (req, res) => {
      try {
        const now = new Date();
        const start = new Date(now.getFullYear(), now.getMonth() - 5, 1);
        const [totalDoctors, totalPatients, patientsPerDoctor, monthlyCounts] =
          await Promise.all([
            doctorsCollection.countDocuments(),
            patientsCollection.countDocuments(),
            doctorsCollection
              .aggregate([
                {
                  $lookup: {
                    from: "patients",
                    let: { doctorId: "$_id" },
                    pipeline: [
                      {
                        $match: { $expr: { $eq: ["$doctorId", "$$doctorId"] } },
                      },
                      { $count: "patientCount" },
                    ],
                    as: "patientStats",
                  },
                },
                {
                  $project: {
                    doctorName: "$name",
                    patientCount: {
                      $ifNull: [
                        { $arrayElemAt: ["$patientStats.patientCount", 0] },
                        0,
                      ],
                    },
                  },
                },
                { $sort: { patientCount: -1, doctorName: 1 } },
              ])
              .toArray(),
            patientsCollection
              .aggregate([
                { $match: { createdAt: { $gte: start, $lte: now } } },
                {
                  $group: {
                    _id: {
                      $dateToString: { format: "%Y-%m", date: "$createdAt" },
                    },
                    count: { $sum: 1 },
                  },
                },
                { $sort: { _id: 1 } },
              ])
              .toArray(),
          ]);
        const countsByMonth = new Map(
          monthlyCounts.map(({ _id, count }) => [_id, count]),
        );
        const patientActivity = Array.from({ length: 6 }, (_, index) => {
          const date = new Date(
            start.getFullYear(),
            start.getMonth() + index,
            1,
          );
          const monthKey = `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, "0")}`;
          return {
            month: date.toLocaleString("en", {
              month: "short",
              year: "numeric",
            }),
            count: countsByMonth.get(monthKey) || 0,
          };
        });
        return res.json({
          totalDoctors,
          totalPatients,
          patientsPerDoctor,
          patientActivity,
        });
      } catch (error) {
        console.error("Failed to load dashboard stats:", error);
        return res
          .status(500)
          .json({ message: "Could not load dashboard analytics" });
      }
    });
    app.get("/users", async (req, res) => {
      res.send("all users");
    });
  } catch (error) {
    console.error(error);
    await client.close();
    throw error;
  }
}

app.get("/", async (req, res) => {
  res.send("succesfully created");
});

run()
  .then(() => {
    app.listen(port, () => console.log(`app running on ${port}`));
  })
  .catch((error) => {
    console.error("Backend failed to start:", error);
    process.exit(1);
  });
