import express from 'express';
import mongoose from 'mongoose';
import multer from 'multer';
import { v2 as cloudinary } from 'cloudinary';
import bcryptjs from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import dotenv from 'dotenv';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
const PORT = process.env.PORT || 10000;

// Listen on all interfaces (Render requirement)
app.listen(PORT, '0.0.0.0', () => {
  console.log(`ZAPFIX LIVE on port ${PORT}`);
});

// Middleware
app.use(express.json({ limit: '100mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(join(__dirname, 'public')));
app.use(cors({ origin: '*' }));

const uploadLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10 });

// Cloudinary Config
cloudinary.config({
  cloud_name: process.env.CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// Multer (File Upload)
const storage = multer.memoryStorage();
const upload = multer({
  storage,
  limits: { fileSize: 100 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = [
      'image/jpeg', 'image/png', 'image/gif',
      'video/mp4', 'video/webm', 'video/ogg',
      'application/zip', 'application/x-rar-compressed', 'application/x-7z-compressed'
    ];
    cb(null, allowed.includes(file.mimetype));
  }
});

// MongoDB
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB error:', err));

// Tool/Video Schema
const toolSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: { type: String, required: true },
  icon: { type: String, required: true },
  thumbnail: { type: String, required: true },
  file: { type: String, required: true },
  likes: { type: Number, default: 0 },
  comments: [{
    name: { type: String, required: true },
    text: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
  }],
  createdAt: { type: Date, default: Date.now }
});

const Tool = mongoose.model("Tool", toolSchema);

// JWT Verify
const verifyJWT = (req, res, next) => {
  const token = req.header('Authorization')?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// === PUBLIC ROUTES ===

// Get all tools/videos
app.get('/api/tools', async (req, res) => {
  try {
    const tools = await Tool.find({}).sort({ createdAt: -1 });
    res.json({ success: true, tools });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch tools' });
  }
});

// Get videos (for feed.html)
app.get('/videos', async (req, res) => {
  try {
    const videos = await Tool.find({}).sort({ createdAt: -1 });
    res.json({ success: true, videos });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch videos' });
  }
});

// === ADMIN ROUTES ===

// Admin Login
app.post('/api/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

    if (email !== process.env.ADMIN_EMAIL) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    if (!process.env.ADMIN_HASH) {
      return res.status(500).json({ error: 'Server misconfigured' });
    }

    const isMatch = await bcryptjs.compare(password, process.env.ADMIN_HASH);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '24h' });
    res.json({ success: true, token });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Admin: Upload Tool/Video
app.post('/api/admin/upload', verifyJWT, uploadLimiter, upload.fields([
  { name: 'icon' },
  { name: 'thumbnail' },
  { name: 'file' }
]), async (req, res) => {
  try {
    const { name, description } = req.body;
    if (!name || !description || !req.files?.icon || !req.files?.thumbnail || !req.files?.file) {
      return res.status(400).json({ error: 'All fields and files required' });
    }

    const uploadFile = (buffer, type = 'raw') => {
      return new Promise((resolve, reject) => {
        cloudinary.uploader.upload_stream(
          { folder: 'zapfix_tools', resource_type: type },
          (error, result) => {
            if (error) reject(error);
            else resolve(result.secure_url);
          }
        ).end(buffer);
      });
    };

    const [iconUrl, thumbnailUrl, fileUrl] = await Promise.all([
      uploadFile(req.files.icon[0].buffer, 'image'),
      uploadFile(req.files.thumbnail[0].buffer, 'image'),
      uploadFile(req.files.file[0].buffer, 'raw')
    ]);

    const tool = await Tool.create({
      name,
      description,
      icon: iconUrl,
      thumbnail: thumbnailUrl,
      file: fileUrl
    });

    res.json({ success: true, message: 'Uploaded', tool });
  } catch (err) {
    console.error('Upload error:', err);
    res.status(500).json({ error: 'Upload failed' });
  }
});

// VIDEO UPLOAD ROUTE (for upload.html)
app.post('/upload', verifyJWT, upload.fields([
  { name: 'thumbnail', maxCount: 1 },
  { name: 'video', maxCount: 1 }
]), async (req, res) => {
  try {
    const { title, description } = req.body;
    const thumbnail = req.files?.thumbnail?.[0];
    const video = req.files?.video?.[0];

    if (!title || !description || !thumbnail || !video) {
      return res.status(400).json({ error: 'Title, description, thumbnail, and video required' });
    }

    const uploadFile = (buffer, type) => {
      return new Promise((resolve, reject) => {
        cloudinary.uploader.upload_stream(
          { folder: 'zapfix_videos', resource_type: type },
          (error, result) => error ? reject(error) : resolve(result.secure_url)
        ).end(buffer);
      });
    };

    const [thumbUrl, videoUrl] = await Promise.all([
      uploadFile(thumbnail.buffer, 'image'),
      uploadFile(video.buffer, 'video')
    ]);

    const newVideo = await Tool.create({
      name: title,
      description,
      icon: thumbUrl,
      thumbnail: thumbUrl,
      file: videoUrl
    });

    res.json({ success: true, message: 'Video uploaded', video: newVideo });
  } catch (err) {
    console.error('Video upload error:', err);
    res.status(500).json({ error: 'Upload failed' });
  }
});

// Admin: Get all tools
app.get('/api/admin/tools', verifyJWT, async (req, res) => {
  try {
    const tools = await Tool.find({}).sort({ createdAt: -1 });
    res.json(tools);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch tools' });
  }
});

// Admin: Update tool
app.put('/api/admin/tool/:id', verifyJWT, upload.fields([
  { name: 'icon' },
  { name: 'thumbnail' },
  { name: 'file' }
]), async (req, res) => {
  try {
    const updates = { name: req.body.name, description: req.body.description };
    if (req.files?.icon) updates.icon = await uploadFile(req.files.icon[0].buffer, 'image');
    if (req.files?.thumbnail) updates.thumbnail = await uploadFile(req.files.thumbnail[0].buffer, 'image');
    if (req.files?.file) updates.file = await uploadFile(req.files.file[0].buffer, 'raw');

    const tool = await Tool.findByIdAndUpdate(req.params.id, updates, { new: true });
    if (!tool) return res.status(404).json({ error: 'Tool not found' });
    res.json({ success: true, tool });
  } catch (err) {
    res.status(500).json({ error: 'Update failed' });
  }
});

// Admin: Delete tool
app.delete('/api/admin/tool/:id', verifyJWT, async (req, res) => {
  try {
    const tool = await Tool.findByIdAndDelete(req.params.id);
    if (!tool) return res.status(404).json({ error: 'Tool not found' });
    res.json({ success: true, message: 'Deleted' });
  } catch (err) {
    res.status(500).json({ error: 'Delete failed' });
  }
});

// Admin: Delete comment
app.delete('/api/admin/tool/:toolId/comment/:commentId', verifyJWT, async (req, res) => {
  try {
    const tool = await Tool.findByIdAndUpdate(
      req.params.toolId,
      { $pull: { comments: { _id: req.params.commentId } } },
      { new: true }
    );
    if (!tool) return res.status(404).json({ error: 'Tool not found' });
    res.json({ success: true, comments: tool.comments });
  } catch (err) {
    res.status(500).json({ error: 'Delete failed' });
  }
});

// Serve index.html
app.get('/', (req, res) => {
  res.sendFile(join(__dirname, 'public', 'index.html'));
});