import express from 'express';
import mongoose from 'mongoose';
import multer from 'multer';
import { v2 as cloudinary } from 'cloudinary';
import bcryptjs from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
const PORT = process.env.PORT || 10000;

// Middleware
app.use(express.json({ limit: '100mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(join(__dirname, 'public')));

app.use(cors({ origin: '*' }));

const uploadLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10 });

// Cloudinary
cloudinary.config({
  cloud_name: process.env.CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// Multer
const storage = multer.memoryStorage();
const upload = multer({
  storage,
  limits: { fileSize: 100 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = ['image/', 'video/', 'application/'].some(t => file.mimetype.startsWith(t));
    cb(null, allowed);
  }
});

// MongoDB
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('MongoDB Connected'))
  .catch(err => console.error(err));

// Tool Schema
const toolSchema = new mongoose.Schema({
  name: String,
  description: String,
  icon: String,
  thumbnail: String,
  file: String,
  likes: { type: Number, default: 0 },
  comments: [{ name: String, text: String, createdAt: { type: Date, default: Date.now } }],
  createdAt: { type: Date, default: Date.now }
});
const Tool = mongoose.model('Tool', toolSchema);

// JWT
const verifyJWT = (req, res, next) => {
  const token = req.header('Authorization')?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try { jwt.verify(token, process.env.JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Invalid token' }); }
};

// ========================
// TOOLS API
// ========================
app.get('/api/tools', async (req, res) => {
  const tools = await Tool.find().sort({ createdAt: -1 });
  res.json(tools);
});

app.get('/api/tools/:id', async (req, res) => {
  const tool = await Tool.findById(req.params.id);
  if (!tool) return res.status(404).json({ error: 'Not found' });
  res.json(tool);
});

app.post('/api/tools/:id/like', async (req, res) => {
  const tool = await Tool.findByIdAndUpdate(req.params.id, { $inc: { likes: 1 } }, { new: true });
  res.json({ likes: tool.likes });
});

app.post('/api/tools/:id/comments', async (req, res) => {
  const { name, text } = req.body;
  const tool = await Tool.findByIdAndUpdate(req.params.id, {
    $push: { comments: { name: name || 'Anonymous', text } }
  }, { new: true });
  res.json(tool.comments);
});

// ========================
// ADMIN API
// ========================
app.post('/api/admin/login', async (req, res) => {
  const { email, password } = req.body;
  if (email !== process.env.ADMIN_EMAIL) return res.status(401).json({ error: 'Invalid' });
  const match = await bcryptjs.compare(password, process.env.ADMIN_HASH);
  if (!match) return res.status(401).json({ error: 'Invalid' });
  const token = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '24h' });
  res.json({ token });
});

app.post('/api/admin/upload', verifyJWT, uploadLimiter, upload.fields([
  { name: 'icon' }, { name: 'thumbnail' }, { name: 'file' }
]), async (req, res) => {
  const { name, description } = req.body;
  if (!name || !description || !req.files?.icon || !req.files?.thumbnail || !req.files?.file) {
    return res.status(400).json({ error: 'All fields required' });
  }

  const uploadFile = (buffer, type = 'raw') => {
    return new Promise((resolve, reject) => {
      cloudinary.uploader.upload_stream(
        { folder: 'zapfix_tools', resource_type: type },
        (err, result) => err ? reject(err) : resolve(result.secure_url)
      ).end(buffer);
    });
  };

  const [icon, thumb, file] = await Promise.all([
    uploadFile(req.files.icon[0].buffer, 'image'),
    uploadFile(req.files.thumbnail[0].buffer, 'image'),
    uploadFile(req.files.file[0].buffer, 'raw')
  ]);

  await Tool.create({ name, description, icon, thumbnail: thumb, file });
  res.json({ message: 'Uploaded' });
});

app.get('/api/admin/tools', verifyJWT, async (req, res) => {
  const tools = await Tool.find().sort({ createdAt: -1 });
  res.json(tools);
});

// Serve main page
app.get('/', (req, res) => {
  res.sendFile(join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`ZAPFIX LIVE: https://your-app.onrender.com`);
});