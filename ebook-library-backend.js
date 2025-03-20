// server.js - Main backend file
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/ebook-library', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('MongoDB connected'))
.catch(err => console.error('MongoDB connection error:', err));

// Define schemas
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

const bookSchema = new mongoose.Schema({
  title: { type: String, required: true },
  author: { type: String, default: 'Unknown' },
  fileName: { type: String, required: true },
  originalFileName: { type: String, required: true },
  fileSize: { type: Number, required: true },
  fileType: { type: String, required: true },
  coverImage: { type: String, default: '/api/placeholder/150/180' },
  category: { type: String, default: 'uncategorized' },
  isFavorite: { type: Boolean, default: false },
  uploadDate: { type: Date, default: Date.now },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }
});

// Create models
const User = mongoose.model('User', userSchema);
const Book = mongoose.model('Book', bookSchema);

// Set up file storage with multer
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const userFolder = path.join(__dirname, 'uploads', req.user.id);
    
    if (!fs.existsSync(userFolder)) {
      fs.mkdirSync(userFolder, { recursive: true });
    }
    
    cb(null, userFolder);
  },
  filename: (req, file, cb) => {
    const uniqueFilename = `${uuidv4()}${path.extname(file.originalname)}`;
    cb(null, uniqueFilename);
  }
});

const fileFilter = (req, file, cb) => {
  const allowedTypes = ['.epub', '.pdf', '.mobi', '.azw', '.txt', '.doc', '.docx'];
  const ext = path.extname(file.originalname).toLowerCase();
  
  if (allowedTypes.includes(ext)) {
    cb(null, true);
  } else {
    cb(new Error('Invalid file type. Only e-book formats are allowed.'), false);
  }
};

const upload = multer({ 
  storage: storage,
  fileFilter: fileFilter,
  limits: { fileSize: 50 * 1024 * 1024 } // 50MB limit
});

// Middleware for authentication
const authMiddleware = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    
    if (!token) {
      return res.status(401).json({ message: 'Authentication required' });
    }
    
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.id);
    
    if (!user) {
      return res.status(401).json({ message: 'User not found' });
    }
    
    req.user = { id: user._id, name: user.name, email: user.email };
    next();
  } catch (error) {
    res.status(401).json({ message: 'Invalid token' });
  }
};

// API Routes

// User registration
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    
    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }
    
    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    
    // Create new user
    const newUser = new User({
      name,
      email,
      password: hashedPassword
    });
    
    await newUser.save();
    
    // Generate JWT token
    const token = jwt.sign({ id: newUser._id }, JWT_SECRET, { expiresIn: '30d' });
    
    res.status(201).json({
      token,
      user: {
        id: newUser._id,
        name: newUser.name,
        email: newUser.email
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// User login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Check if user exists
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }
    
    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }
    
    // Generate JWT token
    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '30d' });
    
    res.json({
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Upload e-book
app.post('/api/books/upload', authMiddleware, upload.single('ebook'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: 'No file uploaded' });
    }
    
    const { title, author, category } = req.body;
    
    // Create new book record
    const newBook = new Book({
      title: title || req.file.originalname.split('.').slice(0, -1).join('.'),
      author: author || 'Unknown',
      fileName: req.file.filename,
      originalFileName: req.file.originalname,
      fileSize: req.file.size,
      fileType: path.extname(req.file.originalname).toLowerCase().substring(1),
      category: category || 'uncategorized',
      userId: req.user.id
    });
    
    await newBook.save();
    
    res.status(201).json({
      message: 'Book uploaded successfully',
      book: newBook
    });
  } catch (error) {
    console.error('Upload error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get all books for user
app.get('/api/books', authMiddleware, async (req, res) => {
  try {
    const { category, search } = req.query;
    
    // Build query
    let query = { userId: req.user.id };
    
    if (category && category !== 'all') {
      if (category === 'favorites') {
        query.isFavorite = true;
      } else {
        query.category = category;
      }
    }
    
    if (search) {
      query.$or = [
        { title: { $regex: search, $options: 'i' } },
        { author: { $regex: search, $options: 'i' } }
      ];
    }
    
    const books = await Book.find(query).sort({ uploadDate: -1 });
    
    res.json(books);
  } catch (error) {
    console.error('Get books error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get book by ID
app.get('/api/books/:id', authMiddleware, async (req, res) => {
  try {
    const book = await Book.findOne({ _id: req.params.id, userId: req.user.id });
    
    if (!book) {
      return res.status(404).json({ message: 'Book not found' });
    }
    
    res.json(book);
  } catch (error) {
    console.error('Get book error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Download book
app.get('/api/books/:id/download', authMiddleware, async (req, res) => {
  try {
    const book = await Book.findOne({ _id: req.params.id, userId: req.user.id });
    
    if (!book) {
      return res.status(404).json({ message: 'Book not found' });
    }
    
    const filePath = path.join(__dirname, 'uploads', req.user.id, book.fileName);
    
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ message: 'File not found' });
    }
    
    res.download(filePath, book.originalFileName);
  } catch (error) {
    console.error('Download error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Update book
app.put('/api/books/:id', authMiddleware, async (req, res) => {
  try {
    const { title, author, category, isFavorite } = req.body;
    
    const book = await Book.findOne({ _id: req.params.id, userId: req.user.id });
    
    if (!book) {
      return res.status(404).json({ message: 'Book not found' });
    }
    
    // Update fields
    if (title) book.title = title;
    if (author) book.author = author;
    if (category) book.category = category;
    if (isFavorite !== undefined) book.isFavorite = isFavorite;
    
    await book.save();
    
    res.json({
      message: 'Book updated successfully',
      book
    });
  } catch (error) {
    console.error('Update book error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Delete book
app.delete('/api/books/:id', authMiddleware, async (req, res) => {
  try {
    const book = await Book.findOne({ _id: req.params.id, userId: req.user.id });
    
    if (!book) {
      return res.status(404).json({ message: 'Book not found' });
    }
    
    // Delete file from storage
    const filePath = path.join(__dirname, 'uploads', req.user.id, book.fileName);
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }
    
    // Delete book from database
    await Book.deleteOne({ _id: req.params.id });
    
    res.json({ message: 'Book deleted successfully' });
  } catch (error) {
    console.error('Delete book error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
