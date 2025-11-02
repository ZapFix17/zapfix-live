import express from "express";
import mongoose from "mongoose";
import multer from "multer";
import { v2 as cloudinary } from "cloudinary";
import dotenv from "dotenv";
import cors from "cors";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

// Cloudinary config
cloudinary.config({
  cloud_name: process.env.CLOUD_NAME,
  api_key: process.env.CLOUD_API_KEY,
  api_secret: process.env.CLOUD_API_SECRET
});

// Multer setup (store file in memory)
const storage = multer.memoryStorage();
const upload = multer({ storage });

// MongoDB
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log("MongoDB connected"))
  .catch(err => console.log("MongoDB error:", err));

// Video schema
const videoSchema = new mongoose.Schema({
  title: String,
  description: String,
  thumbnail: String,
  video: String,
  comments: [{ name: String, text: String }]
});
const Video = mongoose.model("Video", videoSchema);

// Upload route
app.post("/upload", upload.fields([{ name: "video" }, { name: "thumbnail" }]), async (req, res) => {
  try {
    const { title, description } = req.body;

    if (!req.files || !req.files.video || !req.files.thumbnail) {
      return res.status(400).json({ success: false, message: "Files missing" });
    }

    // Upload thumbnail
    const thumbnailResult = await cloudinary.uploader.upload_stream({ folder: "zapfix" }, (error, result) => {
      if (error) throw error;
      return result;
    });
    const videoResult = await cloudinary.uploader.upload_stream({ resource_type: "video", folder: "zapfix" }, (error, result) => {
      if (error) throw error;
      return result;
    });

    // Save video in MongoDB
    const newVideo = await Video.create({
      title,
      description,
      thumbnail: thumbnailResult.secure_url,
      video: videoResult.secure_url
    });

    res.json({ success: true, video: newVideo.video, thumbnail: newVideo.thumbnail });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Upload failed" });
  }
});

// Fetch videos
app.get("/videos", async (req, res) => {
  try {
    const videos = await Video.find({});
    res.json({ success: true, videos });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false });
  }
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
