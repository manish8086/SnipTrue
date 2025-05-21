require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const { OAuth2Client } = require('google-auth-library');
const fetch = require('node-fetch');
const rateLimit = require('express-rate-limit');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const AnalysisService = require('./services/analysis');

const app = express();
const PORT = process.env.PORT || 9999;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/sniptrue';
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';
const HUGGINGFACE_API_KEY = process.env.HUGGINGFACE_API_KEY;
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// Rate limiting
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 attempts
    message: 'Too many login attempts, please try again later'
});

// Email transporter
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// Middleware
app.use(cors({
    origin: '*',  // Allow all origins for testing
    credentials: true
}));
app.use(express.json());

// MongoDB Connection
mongoose.connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log('Connected to MongoDB'))
.catch(err => {
    console.error('MongoDB connection error:', err);
    process.exit(1);
});

// User Schema
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    isVerified: { type: Boolean, default: false },
    verificationToken: String,
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access denied. No token provided.' });
    }

    try {
        const verified = jwt.verify(token, process.env.JWT_SECRET);
        req.user = verified;
        next();
    } catch (err) {
        res.status(400).json({ error: 'Invalid token' });
    }
};

// Routes
app.post('/api/auth/signup', [
    body('username').isLength({ min: 3 }).trim().escape(),
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 8 })
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ error: 'Invalid input' });
        }

        const { username, email, password } = req.body;

        // Check if user exists
        const existingUser = await User.findOne({ $or: [{ username }, { email }] });
        if (existingUser) {
            return res.status(400).json({ error: 'Username or email already exists' });
        }

        // Hash password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Create verification token
        const verificationToken = jwt.sign(
            { username },
            process.env.JWT_SECRET,
            { expiresIn: '1d' }
        );

        // Create user
        const user = new User({
            username,
            email,
            password: hashedPassword,
            verificationToken
        });

        await user.save();

        // For testing purposes, auto-verify the user
        await User.updateOne({ username }, { isVerified: true });

        res.status(201).json({ message: 'User created successfully' });
    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        // Find user
        const user = await User.findOne({ $or: [{ username }, { email: username }] });
        if (!user) {
            return res.status(400).json({ error: 'User not found' });
        }

        // Check password
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(400).json({ error: 'Invalid password' });
        }

        // Check if user is verified
        if (!user.isVerified) {
            return res.status(400).json({ error: 'Please verify your email first' });
        }

        // Create token
        const token = jwt.sign(
            { id: user._id, username: user.username },
            process.env.JWT_SECRET,
            { expiresIn: '1d' }
        );

        res.json({ token, username: user.username });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

app.get('/api/auth/google', (req, res) => {
    const authUrl = `https://accounts.google.com/o/oauth2/v2/auth?client_id=${process.env.GOOGLE_CLIENT_ID}&redirect_uri=${process.env.GOOGLE_REDIRECT_URI}&response_type=code&scope=email profile`;
    res.redirect(authUrl);
});

app.get('/api/auth/google/callback', async (req, res) => {
    try {
        const { code } = req.query;
        
        // Exchange code for tokens
        const { tokens } = await googleClient.getToken(code);
        googleClient.setCredentials(tokens);

        // Get user info
        const { data } = await googleClient.getTokeninfo();

        // Find or create user
        let user = await User.findOne({ email: data.email });
        if (!user) {
            // Generate a username from email
            const username = data.email.split('@')[0] + Math.floor(Math.random() * 1000);
            user = new User({
                username,
                email: data.email,
                googleId: data.sub
            });
            await user.save();
        }

        // Generate token
        const token = jwt.sign(
            { userId: user._id, username: user.username },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        // Send token back to popup
        res.send(`
            <script>
                window.opener.postMessage({
                    token: '${token}',
                    username: '${user.username}'
                }, '${process.env.FRONTEND_URL}');
                window.close();
            </script>
        `);
    } catch (error) {
        console.error('Google auth error:', error);
        res.send(`
            <script>
                window.opener.postMessage({
                    error: 'Google authentication failed'
                }, '${process.env.FRONTEND_URL}');
                window.close();
            </script>
        `);
    }
});

// Initialize services
const analysisService = new AnalysisService(process.env.HUGGINGFACE_API_KEY);

// Analysis endpoint
app.post('/api/analyze', authenticateToken, async (req, res) => {
    try {
        const { content, metadata } = req.body;

        if (!content) {
            return res.status(400).json({ error: 'No content provided' });
        }

        console.log('Received analysis request:', {
            contentLength: content.length,
            metadata
        });

        const analysis = await analysisService.analyzeText(content);
        console.log('Analysis completed:', analysis);

        res.json(analysis);
    } catch (error) {
        console.error('Analysis error:', error);
        res.status(500).json({ error: error.message || 'Analysis failed' });
    }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', message: 'Server is running' });
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
}); 