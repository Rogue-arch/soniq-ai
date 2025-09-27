require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { GridFSBucket } = require('mongodb');
// Dynamic import for uuid - will be loaded async
let uuidv4;

// Initialize UUID
(async () => {
  const uuid = await import('uuid');
  uuidv4 = uuid.v4;
})();

const app = express();

// Environment Variables with defaults
const {
  PORT = 3000,
  MONGODB_URI = 'mongodb://localhost:27017/soniqai',
  SESSION_SECRET = 'soniqai-secret-key-2024',
  ADMIN_PASSWORD = 'admin123',
  NODE_ENV = 'development',
  UPLOAD_DIR = 'uploads',
  MAX_FILE_SIZE = 52428800, // 50MB in bytes
  SESSION_MAX_AGE = 86400000, // 24 hours in milliseconds
  BCRYPT_ROUNDS = 12,
  MAX_ACTIVE_SESSIONS = 2,
  CODE_EXPIRY_HOURS = 24
} = process.env;

// MongoDB Connection
mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

// GridFS setup
let gfs;
let gridfsBucket;

mongoose.connection.once('open', () => {
  console.log('MongoDB connected');
  gridfsBucket = new GridFSBucket(mongoose.connection.db, {
    bucketName: 'audio'
  });
  
  // Legacy GridFS for compatibility
  gfs = new mongoose.mongo.GridFSBucket(mongoose.connection.db, {
    bucketName: 'audio'
  });
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
    secure: NODE_ENV === 'production',
    httpOnly: true,
    maxAge: parseInt(SESSION_MAX_AGE)
  }
}));

// View engine
app.set('view engine', 'ejs');
app.set('views', './views');

// Ensure uploads directory exists (keeping for backward compatibility)
if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR);
}

// MongoDB Schemas - Updated to include GridFS ID
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
  gridfsId: { type: mongoose.Schema.Types.ObjectId, required: true }, // GridFS file ID
  originalName: String, // Store original filename
  mimeType: String, // Store MIME type
  fileSize: Number, // Store file size
  description: String,
  uploadedAt: { type: Date, default: Date.now }
});

const oneTimeCodeSchema = new mongoose.Schema({
  code: { type: String, required: true, unique: true },
  plan: { type: String, enum: ['normal', 'abundance'], required: true },
  used: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now },
  expiresAt: { type: Date, default: () => new Date(Date.now() + (parseInt(CODE_EXPIRY_HOURS) * 60 * 60 * 1000)), expires: 0 }
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
  if (!req.session.admin) {
    return res.redirect('/admin-login');
  }
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

// Updated Multer configuration to store in memory first, then GridFS
const storage = multer.memoryStorage(); // Store in memory temporarily

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
  limits: { fileSize: parseInt(MAX_FILE_SIZE) }
});

// Helper function to upload file to GridFS
const uploadToGridFS = (buffer, filename, originalName, mimeType) => {
  return new Promise((resolve, reject) => {
    const uploadStream = gridfsBucket.openUploadStream(filename, {
      metadata: {
        originalName: originalName,
        uploadedAt: new Date()
      }
    });

    uploadStream.on('error', reject);
    uploadStream.on('finish', () => {
      // The uploadStream object contains the file ID after finish
      resolve(uploadStream.id);
    });

    // Write buffer to GridFS
    uploadStream.end(buffer);
  });
};

// Helper function to generate one-time codes
function generateOneTimeCode() {
  // Generate a proper 12-character alphanumeric code
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

  // Remove expired sessions (older than SESSION_MAX_AGE)
  user.activeSessions = user.activeSessions.filter(session => 
    Date.now() - session.createdAt.getTime() < parseInt(SESSION_MAX_AGE)
  );

  // If more than MAX_ACTIVE_SESSIONS, remove oldest ones
  if (user.activeSessions.length >= parseInt(MAX_ACTIVE_SESSIONS)) {
    user.activeSessions = user.activeSessions
      .sort((a, b) => b.createdAt - a.createdAt)
      .slice(0, parseInt(MAX_ACTIVE_SESSIONS) - 1);
  }

  // Add current session
  user.activeSessions.push({
    sessionId: currentSessionId,
    createdAt: new Date()
  });

  await user.save();
}

// Routes (keeping all existing routes the same)
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
  if (req.session.admin) {
    return res.redirect('/admin-dashboard');
  }
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

    // Check if one-time code exists and is valid
    const code = await OneTimeCode.findOne({ code: oneTimeCode, used: false });
    if (!code) {
      return res.render('signup', { error: 'Invalid or expired one-time code' });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.render('signup', { error: 'User already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, parseInt(BCRYPT_ROUNDS));

    // Create user
    const user = new User({
      email,
      password: hashedPassword,
      name: name || '',
      plan: code.plan
    });

    await user.save();

    // Mark code as used
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

    // Manage sessions
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

// Admin login route
app.post('/admin-login', async (req, res) => {
  try {
    const { password } = req.body;

    if (password !== ADMIN_PASSWORD) {
      return res.render('admin-login', { error: 'Invalid admin password' });
    }

    req.session.admin = true;
    res.redirect('/admin-dashboard');
  } catch (error) {
    console.error(error);
    res.render('admin-login', { error: 'Server error' });
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
    const songs = await Song.find().sort({ uploadedAt: -1 });
    const codes = await OneTimeCode.find({ used: false }).sort({ createdAt: -1 });
    const usedCodes = await OneTimeCode.find({ used: true }).sort({ createdAt: -1 }).limit(10);
    res.render('admin-dashboard', { songs, codes, usedCodes });
  } catch (error) {
    console.error(error);
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

// Updated Add song route - now uses GridFS (single upload)
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

      // Generate unique filename
      const uniqueFilename = Date.now() + '-' + Math.round(Math.random() * 1E9) + path.extname(req.file.originalname);

      console.log('Uploading to GridFS:', {
        filename: uniqueFilename,
        originalname: req.file.originalname,
        size: req.file.size,
        mimetype: req.file.mimetype
      });

      // Upload file to GridFS
      const gridfsId = await uploadToGridFS(
        req.file.buffer, 
        uniqueFilename, 
        req.file.originalname, 
        req.file.mimetype
      );

      const song = new Song({
        title: title.trim(),
        artist: artist.trim(),
        album: album ? album.trim() : undefined,
        duration: duration ? duration.trim() : undefined,
        genre: genre ? genre.trim() : undefined,
        plan: plan || 'both',
        description: description ? description.trim() : undefined,
        filename: uniqueFilename,
        gridfsId: gridfsId,
        originalName: req.file.originalname,
        mimeType: req.file.mimetype,
        fileSize: req.file.size
      });

      await song.save();
      console.log('Song saved to database:', song.title);
      res.json({ success: true, message: 'Song uploaded successfully' });
    } catch (error) {
      console.error('Database error:', error);
      res.status(500).json({ error: 'Failed to save song: ' + error.message });
    }
  });
});

// New Mass upload route - uses GridFS
app.post('/admin/mass-upload', apiRequireAdmin, (req, res) => {
  const uploadMultiple = multer({ 
    storage: multer.memoryStorage(),
    fileFilter: (req, file, cb) => {
      const allowedExtensions = /\.(mp3|wav|flac|m4a|aac)$/i;
      const allowedMimeTypes = [
        'audio/mpeg', 'audio/mp3', 'audio/wav', 'audio/wave',
        'audio/x-wav', 'audio/flac', 'audio/x-flac', 'audio/mp4',
        'audio/m4a', 'audio/aac', 'audio/x-aac'
      ];
      
      const hasValidExtension = allowedExtensions.test(file.originalname);
      const hasValidMimeType = allowedMimeTypes.includes(file.mimetype);
      
      if (hasValidExtension || hasValidMimeType) {
        return cb(null, true);
      } else {
        cb(new Error('Only audio files are allowed (MP3, WAV, FLAC, M4A, AAC)'));
      }
    },
    limits: { fileSize: parseInt(MAX_FILE_SIZE) }
  }).array('audioFiles', 50); // Max 50 files

  uploadMultiple(req, res, async (err) => {
    if (err) {
      console.error('Mass upload multer error:', err.message);
      return res.status(400).json({ error: err.message });
    }
    
    try {
      if (!req.files || req.files.length === 0) {
        return res.status(400).json({ error: 'No audio files uploaded' });
      }

      const { artist, plan } = req.body;

      if (!artist) {
        return res.status(400).json({ error: 'Artist is required for mass upload' });
      }

      const results = [];
      const errors = [];

      // Process each file
      for (let i = 0; i < req.files.length; i++) {
        const file = req.files[i];
        
        try {
          // Extract title from filename (remove extension)
          const title = path.parse(file.originalname).name;
          
          // Generate unique filename
          const uniqueFilename = Date.now() + '-' + Math.round(Math.random() * 1E9) + path.extname(file.originalname);

          console.log(`Uploading file ${i + 1}/${req.files.length} to GridFS:`, {
            filename: uniqueFilename,
            originalname: file.originalname,
            title: title,
            size: file.size,
            mimetype: file.mimetype
          });

          // Upload file to GridFS
          const gridfsId = await uploadToGridFS(
            file.buffer, 
            uniqueFilename, 
            file.originalname, 
            file.mimetype
          );

          // Create description
          const description = `${title} by ${artist.trim()}`;

          const song = new Song({
            title: title.trim(),
            artist: artist.trim(),
            plan: plan || 'both',
            description: description,
            filename: uniqueFilename,
            gridfsId: gridfsId,
            originalName: file.originalname,
            mimeType: file.mimetype,
            fileSize: file.size
          });

          await song.save();
          results.push({
            filename: file.originalname,
            title: title,
            status: 'success'
          });
          
          console.log(`Song saved: ${title} by ${artist}`);
        } catch (fileError) {
          console.error(`Error processing ${file.originalname}:`, fileError);
          errors.push({
            filename: file.originalname,
            error: fileError.message
          });
        }
      }

      const successCount = results.length;
      const errorCount = errors.length;
      
      res.json({
        success: true,
        message: `Mass upload completed: ${successCount} successful, ${errorCount} errors`,
        results: {
          successful: results,
          errors: errors,
          summary: {
            total: req.files.length,
            successful: successCount,
            failed: errorCount
          }
        }
      });
    } catch (error) {
      console.error('Mass upload error:', error);
      res.status(500).json({ error: 'Failed to complete mass upload: ' + error.message });
    }
  });
});

// Updated Delete song route - now deletes from GridFS
app.delete('/admin/delete-song/:id', apiRequireAdmin, async (req, res) => {
  try {
    const song = await Song.findById(req.params.id);
    if (!song) {
      return res.status(404).json({ error: 'Song not found' });
    }

    // Delete file from GridFS
    try {
      await gridfsBucket.delete(song.gridfsId);
    } catch (gridfsError) {
      console.error('Error deleting from GridFS:', gridfsError);
      // Continue with song deletion even if GridFS deletion fails
    }

    await Song.findByIdAndDelete(req.params.id);
    res.json({ success: true });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get song details route (unchanged)
app.get('/api/song/:id', apiRequireAuth, async (req, res) => {
  try {
    const song = await Song.findById(req.params.id);
    if (!song) {
      return res.status(404).json({ error: 'Song not found' });
    }

    // Check if user has access to this song based on plan
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

// Updated Stream audio route - now streams from GridFS
app.get('/stream/:id', apiRequireAuth, async (req, res) => {
  try {
    const song = await Song.findById(req.params.id);
    if (!song) {
      return res.status(404).send('Song not found');
    }

    // Check access permissions
    let hasAccess = false;
    if (song.plan === 'both') {
      hasAccess = true;
    } else if (req.session.user.plan === 'abundance' && (song.plan === 'abundance' || song.plan === 'both')) {
      hasAccess = true;
    } else if (req.session.user.plan === 'normal' && (song.plan === 'normal' || song.plan === 'both')) {
      hasAccess = true;
    }

    if (!hasAccess) {
      return res.status(403).send('Access denied');
    }

    const range = req.headers.range;
    
    try {
      // Get file info from GridFS
      const files = await gridfsBucket.find({ _id: song.gridfsId }).toArray();
      if (!files || files.length === 0) {
        return res.status(404).send('File not found in GridFS');
      }
      
      const file = files[0];
      const fileSize = file.length;

      if (range) {
        const parts = range.replace(/bytes=/, "").split("-");
        const start = parseInt(parts[0], 10);
        const end = parts[1] ? parseInt(parts[1], 10) : fileSize - 1;
        const chunksize = (end - start) + 1;
        
        const downloadStream = gridfsBucket.openDownloadStream(song.gridfsId, {
          start: start,
          end: end + 1
        });
        
        const head = {
          'Content-Range': `bytes ${start}-${end}/${fileSize}`,
          'Accept-Ranges': 'bytes',
          'Content-Length': chunksize,
          'Content-Type': song.mimeType || 'audio/mpeg',
        };
        res.writeHead(206, head);
        downloadStream.pipe(res);
      } else {
        const downloadStream = gridfsBucket.openDownloadStream(song.gridfsId);
        
        const head = {
          'Content-Length': fileSize,
          'Content-Type': song.mimeType || 'audio/mpeg',
        };
        res.writeHead(200, head);
        downloadStream.pipe(res);
      }
    } catch (streamError) {
      console.error('GridFS streaming error:', streamError);
      res.status(500).send('Error streaming file');
    }
  } catch (error) {
    console.error(error);
    res.status(500).send('Server error');
  }
});

// Demo song endpoint (unchanged)
app.get('/api/demo-song', async (req, res) => {
  try {
    // Get a random song from the database for demo purposes
    const songs = await Song.find({ plan: { $in: ['both', 'normal'] } }).limit(10);
    
    if (songs.length === 0) {
      return res.status(404).json({ error: 'No demo songs available' });
    }
    
    // Select a random song from available songs
    const randomIndex = Math.floor(Math.random() * songs.length);
    const demoSong = songs[randomIndex];
    
    // Return basic song info (no sensitive data)
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

// Updated Demo stream endpoint - now streams from GridFS with limits
app.get('/demo-stream/:id', async (req, res) => {
  try {
    const song = await Song.findById(req.params.id);
    if (!song) {
      return res.status(404).send('Demo song not found');
    }

    // Only allow streaming of 'both' or 'normal' plan songs for demo
    if (song.plan !== 'both' && song.plan !== 'normal') {
      return res.status(403).send('Demo access denied');
    }

    try {
      // Get file info from GridFS
      const files = await gridfsBucket.find({ _id: song.gridfsId }).toArray();
      if (!files || files.length === 0) {
        return res.status(404).send('Demo file not found in GridFS');
      }
      
      const file = files[0];
      const fileSize = file.length;
      const range = req.headers.range;

      // Limit demo streaming to first 30% of file
      const maxBytes = Math.min(fileSize, Math.floor(fileSize * 0.3));

      if (range) {
        const parts = range.replace(/bytes=/, "").split("-");
        const start = parseInt(parts[0], 10);
        const end = Math.min(parts[1] ? parseInt(parts[1], 10) : maxBytes - 1, maxBytes - 1);
        const chunksize = (end - start) + 1;
        
        const downloadStream = gridfsBucket.openDownloadStream(song.gridfsId, {
          start: start,
          end: end + 1
        });
        
        const head = {
          'Content-Range': `bytes ${start}-${end}/${maxBytes}`,
          'Accept-Ranges': 'bytes',
          'Content-Length': chunksize,
          'Content-Type': song.mimeType || 'audio/mpeg',
        };
        res.writeHead(206, head);
        downloadStream.pipe(res);
      } else {
        const downloadStream = gridfsBucket.openDownloadStream(song.gridfsId, {
          start: 0,
          end: maxBytes
        });
        
        const head = {
          'Content-Length': maxBytes,
          'Content-Type': song.mimeType || 'audio/mpeg',
        };
        res.writeHead(200, head);
        downloadStream.pipe(res);
      }
    } catch (streamError) {
      console.error('Demo GridFS streaming error:', streamError);
      res.status(500).send('Error streaming demo file');
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

// Initialize UUID and start server
(async () => {
  const uuid = await import('uuid');
  uuidv4 = uuid.v4;
  
  app.listen(PORT, () => {
    console.log(`SoniqAI server running on port ${PORT}`);
    console.log(`Environment: ${NODE_ENV}`);
    console.log(`MongoDB URI: ${MONGODB_URI}`);
    console.log(`Upload Directory: ${UPLOAD_DIR} (GridFS enabled)`);
  });
})();

const ADMIN_PASSWORD = 'SONIQAIBETTERTHANSPOTIFY';
