require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const fetch = require('node-fetch');

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());

// In-memory user storage (replace with a database in production)
const users = new Map();

// Ollama API endpoint (default local installation)
const OLLAMA_API = 'http://localhost:11434/api';

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

// Auth routes
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (users.has(email)) {
      return res.status(400).json({ error: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    users.set(email, { email, password: hashedPassword });

    const token = jwt.sign({ email }, process.env.JWT_SECRET);
    res.json({ token, user: { email } });
  } catch (error) {
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = users.get(email);

    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ email }, process.env.JWT_SECRET);
    res.json({ token, user: { email } });
  } catch (error) {
    res.status(500).json({ error: 'Login failed' });
  }
});

app.get('/api/auth/verify', authenticateToken, (req, res) => {
  res.json({ user: { email: req.user.email } });
});

// Helper function to call Ollama API
async function analyzeWithOllama(text) {
  try {
    const response = await fetch(`${OLLAMA_API}/generate`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        model: 'llama2', // or any other model you have pulled
        prompt: `Analyze the following text for credibility, bias, and accuracy. Provide numerical scores between 0 and 1 for each category, and list any warnings or concerns. Format your response as JSON.

Text to analyze:
${text}

Please provide:
1. Credibility score (0-1)
2. Bias score (0-1, where 1 means unbiased)
3. Accuracy score (0-1)
4. A brief summary
5. List of warnings`,
        stream: false
      })
    });

    const data = await response.json();
    
    try {
      // Try to parse the response as JSON
      const analysisResult = JSON.parse(data.response);
      return analysisResult;
    } catch (e) {
      // If parsing fails, create a structured response from the text
      const scores = {
        credibility: 0.5,
        bias: 0.5,
        accuracy: 0.5,
        summary: data.response,
        warnings: ["Could not parse detailed analysis"]
      };
      return scores;
    }
  } catch (error) {
    console.error('Ollama API error:', error);
    throw error;
  }
}

// Analysis endpoint
app.post('/api/analyze', authenticateToken, async (req, res) => {
  try {
    const { text, metadata } = req.body;

    // Analyze text using Ollama
    const analysis = await analyzeWithOllama(text);

    res.json(analysis);
  } catch (error) {
    console.error('Analysis error:', error);
    res.status(500).json({ error: 'Analysis failed' });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
}); 