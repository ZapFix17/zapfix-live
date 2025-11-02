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

const app = express();
const PORT = process.env.PORT || 10000;

// FIX: Bind to 0.0.0.0 for Render
app.listen(PORT, '0.0.0.0', () => {
  console.log(`ZAPFIX LIVE on port ${PORT}`);
});

// Middleware
app.use(express.json({ limit: '100mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(join(dirname(fileURLToPath(import.meta.url)), 'public')));
app.use(cors({ origin: '*' }));

// Rate limiting
const uploadLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Too many uploads, try again later' }
});

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
  .catch(err => {
    console.error('MongoDB ERROR:', err);
    process.exit(1);
  });

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

// JWT Verify
const verifyJWT = (req, res, next) => {
  const token = req.header('Authorization')?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// ========================
// ADMIN ROUTES
// ========================

// LOGIN
app.post('/api/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Missing fields' });

    if (email !== process.env.ADMIN_EMAIL) {
      return res.status(401).json({ error: 'Invalid email' });
    }

    if (!process.env.ADMIN_HASH) {
      return res.status(500).json({ error: 'Server misconfigured' });
    }

    const match = await bcryptjs.compare(password, process.env.ADMIN_HASH);
    if (!match) return res.status(401).json({ error: 'Invalid password' });

    const token = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '24h' });
    res.json({ token });
  } catch (err) {
    console.error('LOGIN ERROR:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// UPLOAD TOOL — THIS WAS MISSING!
app.post('/api/admin/upload', verifyJWT, uploadLimiter, upload.fields([
  { name: 'icon' },
  { name: 'thumbnail' },
  { name: 'file' }
]), async (req, res) => {
  try {
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
    res.json({ message: 'Uploaded successfully' });
  } catch (err) {
    console.error('UPLOAD ERROR:', err);
    res.status(500).json({ error: 'Upload failed' });
  }
});

// Serve HTML
app.get('*', (req, res) => {
  res.sendFile(join(dirname(fileURLToPath(import.meta.url)), 'public', 'index.html'));
});
