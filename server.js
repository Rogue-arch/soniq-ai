require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();

// HARDCODED VALUES - NO ENV DEPENDENCY
const PORT = 3000;
const MONGODB_URI = 'mongodb+srv://vihaansingh1787:6L6jqMLG3CTkN3x@cluster0.n4mvsb7.mongodb.net/';
const SESSION_SECRET = 'soniqai-secret-key-2024';
const ADMIN_PASSWORD = 'admin123'; // HARDCODED
const NODE_ENV = 'development';
const UPLOAD_DIR = 'uploads';
const MAX_FILE_SIZE = 52428800;
const SESSION_MAX_AGE = 86400000;
const BCRYPT_ROUNDS = 12;
const MAX_ACTIVE_SESSIONS = 2;
const CODE_EXPIRY_HOURS = 24;

// Initialize UUID - simplified version
let { v4: uuidv4 } = require('uuid');

// MongoDB Connection
mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use('/uploads', express.static(UPLOAD_DIR));

// Session configuration
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: MONGODB_URI
  }),
  cookie: {
    secure: false, // ALWAYS FALSE FOR DEVELOPMENT
    httpOnly: true,
    maxAge: SESSION_MAX_AGE
  }
}));

// View engine
app.set('view engine', 'ejs');
app.set('views', './views');

// Ensure uploads directory exists
if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR);
}

// MongoDB Schemas
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  name: { type: String, default: '' },
  plan: { type: String, enum: ['normal', 'abundance'], default: 'normal' },
  activeSessions: [{ 
    sessionId: String, 
    createdAt: { type: Date, default: Date.now } 
  }],
  createdAt: { type: Date, default: Date.now }
});

const songSchema = new mongoose.Schema({
  title: { type: String, required: true },
  artist: { type: String, required: true },
  album: String,
  duration: String,
  genre: String,
  plan: { type: String, enum: ['normal', 'abundance', 'both'], default: 'both' },
  filename: { type: String, required: true },
  description: String,
  uploadedAt: { type: Date, default: Date.now }
});

const oneTimeCodeSchema = new mongoose.Schema({
  code: { type: String, required: true, unique: true },
  plan: { type: String, enum: ['normal', 'abundance'], required: true },
  used: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now },
  expiresAt: { type: Date, default: () => new Date(Date.now() + (CODE_EXPIRY_HOURS * 60 * 60 * 1000)), expires: 0 }
});

const User = mongoose.model('User', userSchema);
const Song = mongoose.model('Song', songSchema);
const OneTimeCode = mongoose.model('OneTimeCode', oneTimeCodeSchema);

// Authentication Middleware
const requireAuth = (req, res, next) => {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  next();
};

const requireAdmin = (req, res, next) => {
  console.log('Admin check - Session admin:', req.session.admin);
  if (!req.session.admin) {
    console.log('Admin access denied, redirecting to admin-login');
    return res.redirect('/admin-login');
  }
  console.log('Admin access granted');
  next();
};

// API Auth Check Middleware
const apiRequireAuth = (req, res, next) => {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  next();
};

const apiRequireAdmin = (req, res, next) => {
  if (!req.session.admin) {
    return res.status(401).json({ error: 'Admin authentication required' });
  }
  next();
};

// Multer configuration for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, UPLOAD_DIR);
  },
  filename: (req, file, cb) => {
    const uniqueName = Date.now() + '-' + Math.round(Math.random() * 1E9) + path.extname(file.originalname);
    cb(null, uniqueName);
  }
});

const upload = multer({ 
  storage: storage,
  fileFilter: (req, file, cb) => {
    console.log('File info:', {
      originalname: file.originalname,
      mimetype: file.mimetype,
      size: file.size
    });
    
    const allowedExtensions = /\.(mp3|wav|flac|m4a|aac)$/i;
    const allowedMimeTypes = [
      'audio/mpeg',
      'audio/mp3',
      'audio/wav',
      'audio/wave',
      'audio/x-wav',
      'audio/flac',
      'audio/x-flac',
      'audio/mp4',
      'audio/m4a',
      'audio/aac',
      'audio/x-aac'
    ];
    
    const hasValidExtension = allowedExtensions.test(file.originalname);
    const hasValidMimeType = allowedMimeTypes.includes(file.mimetype);
    
    if (hasValidExtension || hasValidMimeType) {
      return cb(null, true);
    } else {
      console.log('Rejected file:', file.originalname, 'with mimetype:', file.mimetype);
      cb(new Error('Only audio files are allowed (MP3, WAV, FLAC, M4A, AAC)'));
    }
  },
  limits: { fileSize: MAX_FILE_SIZE }
});

// Helper function to generate one-time codes
function generateOneTimeCode() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let result = '';
  for (let i = 0; i < 12; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

// Helper function to manage user sessions
async function manageUserSessions(userId, currentSessionId) {
  const user = await User.findById(userId);
  if (!user) return;

  user.activeSessions = user.activeSessions.filter(session => 
    Date.now() - session.createdAt.getTime() < SESSION_MAX_AGE
  );

  if (user.activeSessions.length >= MAX_ACTIVE_SESSIONS) {
    user.activeSessions = user.activeSessions
      .sort((a, b) => b.createdAt - a.createdAt)
      .slice(0, MAX_ACTIVE_SESSIONS - 1);
  }

  user.activeSessions.push({
    sessionId: currentSessionId,
    createdAt: new Date()
  });

  await user.save();
}

// Routes
app.get('/', (req, res) => {
  res.render('index', { user: req.session.user });
});

app.get('/contact', (req, res) => {
  res.render('contact', { user: req.session.user });
});

app.get('/signup', (req, res) => {
  if (req.session.user) {
    return res.redirect('/dashboard');
  }
  res.render('signup', { error: null });
});

app.get('/login', (req, res) => {
  if (req.session.user) {
    return res.redirect('/dashboard');
  }
  res.render('login', { error: null });
});

app.get('/admin-login', (req, res) => {
  console.log('GET /admin-login - Session admin:', req.session.admin);
  if (req.session.admin) {
    console.log('Admin already logged in, redirecting to dashboard');
    return res.redirect('/admin-dashboard');
  }
  console.log('Rendering admin login page');
  res.render('admin-login', { error: null });
});

// Authentication check API endpoint
app.get('/api/auth/check', (req, res) => {
  if (req.session.user) {
    res.json({
      isAuthenticated: true,
      user: req.session.user
    });
  } else {
    res.json({
      isAuthenticated: false,
      user: null
    });
  }
});

// Logout API endpoint
app.post('/api/auth/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

// Sign up route
app.post('/signup', async (req, res) => {
  try {
    const { email, password, oneTimeCode, name } = req.body;

    const code = await OneTimeCode.findOne({ code: oneTimeCode, used: false });
    if (!code) {
      return res.render('signup', { error: 'Invalid or expired one-time code' });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.render('signup', { error: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, BCRYPT_ROUNDS);

    const user = new User({
      email,
      password: hashedPassword,
      name: name || '',
      plan: code.plan
    });

    await user.save();

    code.used = true;
    await code.save();

    res.redirect('/login');
  } catch (error) {
    console.error(error);
    res.render('signup', { error: 'Server error' });
  }
});

// Login route
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return res.render('login', { error: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.render('login', { error: 'Invalid credentials' });
    }

    const sessionId = uuidv4();
    req.session.sessionId = sessionId;
    await manageUserSessions(user._id, sessionId);

    req.session.user = {
      id: user._id,
      email: user.email,
      name: user.name,
      plan: user.plan
    };

    res.redirect('/dashboard');
  } catch (error) {
    console.error(error);
    res.render('login', { error: 'Server error' });
  }
});

// SUPER SIMPLE ADMIN LOGIN - NO COMPLEXITY
app.post('/admin-login', (req, res) => {
  console.log('=== ADMIN LOGIN START ===');
  console.log('Body:', req.body);
  
  const password = req.body.password;
  console.log('Password received:', password);
  console.log('Expected:', 'admin123');
  
  // DIRECT STRING COMPARISON
  if (password === 'admin123') {
    console.log('PASSWORD MATCH!');
    req.session.admin = true;
    console.log('Session admin set to:', req.session.admin);
    console.log('Redirecting to /admin-dashboard');
    return res.redirect('/admin-dashboard');
  } else {
    console.log('PASSWORD MISMATCH');
    return res.render('admin-login', { error: 'Invalid admin password' });
  }
});

// Dashboard route (protected)
app.get('/dashboard', requireAuth, async (req, res) => {
  try {
    let query = {};
    if (req.session.user.plan === 'abundance') {
      query = { $or: [{ plan: 'abundance' }, { plan: 'both' }] };
    } else {
      query = { $or: [{ plan: 'normal' }, { plan: 'both' }] };
    }

    const songs = await Song.find(query).sort({ uploadedAt: -1 });
    res.render('dashboard', { 
      user: req.session.user, 
      songs: songs 
    });
  } catch (error) {
    console.error(error);
    res.status(500).send('Server error');
  }
});

// Admin dashboard route (protected)
app.get('/admin-dashboard', requireAdmin, async (req, res) => {
  try {
    console.log('Admin dashboard access granted');
    const songs = await Song.find().sort({ uploadedAt: -1 });
    const codes = await OneTimeCode.find({ used: false }).sort({ createdAt: -1 });
    const usedCodes = await OneTimeCode.find({ used: true }).sort({ createdAt: -1 }).limit(10);
    
    console.log('Rendering admin dashboard with data');
    res.render('admin-dashboard', { songs, codes, usedCodes });
  } catch (error) {
    console.error('Admin dashboard error:', error);
    res.status(500).send('Server error');
  }
});

// Generate one-time code route
app.post('/admin/generate-code', apiRequireAdmin, async (req, res) => {
  try {
    const { plan } = req.body;
    const code = generateOneTimeCode();

    const oneTimeCode = new OneTimeCode({
      code,
      plan
    });

    await oneTimeCode.save();
    res.json({ success: true, code });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Add song route
app.post('/admin/add-song', apiRequireAdmin, (req, res) => {
  upload.single('audioFile')(req, res, async (err) => {
    if (err) {
      console.error('Multer error:', err.message);
      return res.status(400).json({ error: err.message });
    }
    
    try {
      if (!req.file) {
        return res.status(400).json({ error: 'No audio file uploaded' });
      }

      const { title, artist, album, duration, genre, plan, description } = req.body;

      if (!title || !artist) {
        return res.status(400).json({ error: 'Title and artist are required' });
      }

      console.log('Uploaded file:', {
        filename: req.file.filename,
        originalname: req.file.originalname,
        size: req.file.size,
        mimetype: req.file.mimetype
      });

      const song = new Song({
        title: title.trim(),
        artist: artist.trim(),
        album: album ? album.trim() : undefined,
        duration: duration ? duration.trim() : undefined,
        genre: genre ? genre.trim() : undefined,
        plan: plan || 'both',
        description: description ? description.trim() : undefined,
        filename: req.file.filename
      });

      await song.save();
      console.log('Song saved to database:', song.title);
      res.json({ success: true, message: 'Song uploaded successfully' });
    } catch (error) {
      console.error('Database error:', error);
      
      if (req.file) {
        const filePath = path.join(__dirname, UPLOAD_DIR, req.file.filename);
        if (fs.existsSync(filePath)) {
          fs.unlinkSync(filePath);
        }
      }
      
      res.status(500).json({ error: 'Failed to save song: ' + error.message });
    }
  });
});

// Delete song route
app.delete('/admin/delete-song/:id', apiRequireAdmin, async (req, res) => {
  try {
    const song = await Song.findById(req.params.id);
    if (!song) {
      return res.status(404).json({ error: 'Song not found' });
    }

    const filePath = path.join(__dirname, UPLOAD_DIR, song.filename);
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }

    await Song.findByIdAndDelete(req.params.id);
    res.json({ success: true });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get song details route
app.get('/api/song/:id', apiRequireAuth, async (req, res) => {
  try {
    const song = await Song.findById(req.params.id);
    if (!song) {
      return res.status(404).json({ error: 'Song not found' });
    }

    let hasAccess = false;
    if (song.plan === 'both') {
      hasAccess = true;
    } else if (req.session.user.plan === 'abundance' && (song.plan === 'abundance' || song.plan === 'both')) {
      hasAccess = true;
    } else if (req.session.user.plan === 'normal' && (song.plan === 'normal' || song.plan === 'both')) {
      hasAccess = true;
    }

    if (!hasAccess) {
      return res.status(403).json({ error: 'Access denied' });
    }

    res.json(song);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Stream audio route
app.get('/stream/:id', apiRequireAuth, async (req, res) => {
  try {
    const song = await Song.findById(req.params.id);
    if (!song) {
      return res.status(404).send('Song not found');
    }

    const filePath = path.join(__dirname, UPLOAD_DIR, song.filename);
    if (!fs.existsSync(filePath)) {
      return res.status(404).send('File not found');
    }

    const stat = fs.statSync(filePath);
    const fileSize = stat.size;
    const range = req.headers.range;

    if (range) {
      const parts = range.replace(/bytes=/, "").split("-");
      const start = parseInt(parts[0], 10);
      const end = parts[1] ? parseInt(parts[1], 10) : fileSize - 1;
      const chunksize = (end - start) + 1;
      const file = fs.createReadStream(filePath, { start, end });
      const head = {
        'Content-Range': `bytes ${start}-${end}/${fileSize}`,
        'Accept-Ranges': 'bytes',
        'Content-Length': chunksize,
        'Content-Type': 'audio/mpeg',
      };
      res.writeHead(206, head);
      file.pipe(res);
    } else {
      const head = {
        'Content-Length': fileSize,
        'Content-Type': 'audio/mpeg',
      };
      res.writeHead(200, head);
      fs.createReadStream(filePath).pipe(res);
    }
  } catch (error) {
    console.error(error);
    res.status(500).send('Server error');
  }
});

// Demo song endpoint
app.get('/api/demo-song', async (req, res) => {
  try {
    const songs = await Song.find({ plan: { $in: ['both', 'normal'] } }).limit(10);
    
    if (songs.length === 0) {
      return res.status(404).json({ error: 'No demo songs available' });
    }
    
    const randomIndex = Math.floor(Math.random() * songs.length);
    const demoSong = songs[randomIndex];
    
    res.json({
      _id: demoSong._id,
      title: demoSong.title,
      artist: demoSong.artist,
      genre: demoSong.genre,
      duration: demoSong.duration || '3:45',
      plan: demoSong.plan,
      album: demoSong.album
    });
  } catch (error) {
    console.error('Demo song error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Demo stream endpoint
app.get('/demo-stream/:id', async (req, res) => {
  try {
    const song = await Song.findById(req.params.id);
    if (!song) {
      return res.status(404).send('Demo song not found');
    }

    if (song.plan !== 'both' && song.plan !== 'normal') {
      return res.status(403).send('Demo access denied');
    }

    const filePath = path.join(__dirname, UPLOAD_DIR, song.filename);
    if (!fs.existsSync(filePath)) {
      return res.status(404).send('Demo file not found');
    }

    const stat = fs.statSync(filePath);
    const fileSize = stat.size;
    const range = req.headers.range;
    const maxBytes = Math.min(fileSize, fileSize * 0.3);

    if (range) {
      const parts = range.replace(/bytes=/, "").split("-");
      const start = parseInt(parts[0], 10);
      const end = Math.min(parts[1] ? parseInt(parts[1], 10) : maxBytes - 1, maxBytes - 1);
      const chunksize = (end - start) + 1;
      const file = fs.createReadStream(filePath, { start, end });
      const head = {
        'Content-Range': `bytes ${start}-${end}/${maxBytes}`,
        'Accept-Ranges': 'bytes',
        'Content-Length': chunksize,
        'Content-Type': 'audio/mpeg',
      };
      res.writeHead(206, head);
      file.pipe(res);
    } else {
      const head = {
        'Content-Length': maxBytes,
        'Content-Type': 'audio/mpeg',
      };
      res.writeHead(200, head);
      const readStream = fs.createReadStream(filePath, { start: 0, end: maxBytes - 1 });
      readStream.pipe(res);
    }
  } catch (error) {
    console.error('Demo stream error:', error);
    res.status(500).send('Server error');
  }
});

// Logout route
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

// Admin logout route
app.get('/admin/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

// Start server
app.listen(PORT, () => {
  console.log(`SoniqAI server running on port ${PORT}`);
  console.log(`Environment: ${NODE_ENV}`);
  console.log(`MongoDB URI: ${MONGODB_URI}`);
  console.log(`Upload Directory: ${UPLOAD_DIR}`);
  console.log(`Admin Password: ${ADMIN_PASSWORD}`);
});

