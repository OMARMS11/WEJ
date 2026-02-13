/**
 * WEJÀ Dummy Target Application
 * Interactive web server for testing the WAF with MongoDB integration.
 */

const express = require('express');
const mongoose = require('mongoose');
const methodOverride = require('method-override');
const path = require('path');

const app = express();
const PORT = 4000;

// MongoDB Connection
mongoose.connect('mongodb://localhost:27017/weja-target')
    .then(() => console.log('📦 Connected to MongoDB'))
    .catch(err => console.log('⚠️ MongoDB connection failed:', err.message));

// Models
const CommentSchema = new mongoose.Schema({
    content: String,
    author: { type: String, default: 'Anonymous' },
    createdAt: { type: Date, default: Date.now }
});
const Comment = mongoose.model('Comment', CommentSchema);

const SearchLogSchema = new mongoose.Schema({
    query: String,
    createdAt: { type: Date, default: Date.now }
});
const SearchLog = mongoose.model('SearchLog', SearchLogSchema);

// Middleware
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(methodOverride('_method'));
app.use(express.static(path.join(__dirname, 'public')));

// Helper to check MongoDB status
const getDbStatus = () => mongoose.connection.readyState === 1 ? 'connected' : 'disconnected';

// ============ HTML ROUTES ============

// Home - Dashboard
app.get('/', async (req, res) => {
    const commentCount = await Comment.countDocuments().catch(() => 0);
    const searchCount = await SearchLog.countDocuments().catch(() => 0);

    res.render('index', {
        title: 'Target Dashboard',
        dbStatus: getDbStatus(),
        stats: { comments: commentCount, searches: searchCount }
    });
});

// Search Page
app.get('/search', async (req, res) => {
    const query = req.query.q || '';
    let results = [];
    let recentSearches = [];

    if (query) {
        // Log search to MongoDB
        await SearchLog.create({ query }).catch(() => { });

        // Simulated results
        results = [
            { id: 1, title: `Result for "${query}"`, description: 'Sample search result item' },
            { id: 2, title: `Another match for "${query}"`, description: 'More sample content' }
        ];
    }

    recentSearches = await SearchLog.find().sort({ createdAt: -1 }).limit(5).catch(() => []);

    res.render('search', {
        title: 'Search',
        query,
        results,
        recentSearches,
        dbStatus: getDbStatus()
    });
});

// Login Page
app.get('/login', (req, res) => {
    res.render('login', {
        title: 'Login',
        message: null,
        dbStatus: getDbStatus()
    });
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;

    // Simulated login (always "succeeds" for testing)
    res.render('login', {
        title: 'Login',
        message: { type: 'success', text: `Login attempt with username: ${username}` },
        dbStatus: getDbStatus()
    });
});

// Comments Page
app.get('/comment', async (req, res) => {
    const comments = await Comment.find().sort({ createdAt: -1 }).limit(20).catch(() => []);

    res.render('comment', {
        title: 'Comments',
        comments,
        message: null,
        dbStatus: getDbStatus()
    });
});

app.post('/comment', async (req, res) => {
    const { content, author } = req.body;

    try {
        await Comment.create({ content, author: author || 'Anonymous' });
    } catch (err) {
        console.log('Failed to save comment:', err.message);
    }

    const comments = await Comment.find().sort({ createdAt: -1 }).limit(20).catch(() => []);

    res.render('comment', {
        title: 'Comments',
        comments,
        message: { type: 'success', text: 'Comment posted!' },
        dbStatus: getDbStatus()
    });
});

// File Viewer Page
app.get('/file', (req, res) => {
    const filename = req.query.name || '';
    let content = null;

    if (filename) {
        // Simulated file content (for testing path traversal detection)
        content = `Contents of: ${filename}\n\n[This is simulated file content for WAF testing]`;
    }

    res.render('file', {
        title: 'File Viewer',
        filename,
        content,
        dbStatus: getDbStatus()
    });
});

// User Profile Page
app.get('/users/:id', (req, res) => {
    const userId = req.params.id;
    res.render('user', {
        title: 'User Profile',
        user: {
            id: userId,
            name: 'Test User',
            email: 'user@example.com',
            joined: 'December 2024'
        },
        dbStatus: getDbStatus()
    });
});

// ============ JSON API ROUTES ============

// API: Home
app.get('/api', (req, res) => {
    res.json({
        message: '🎯 Welcome to the Dummy Target API!',
        endpoints: {
            home: 'GET /',
            search: 'GET /search?q=<query>',
            login: 'POST /login',
            users: 'GET /users/:id',
            comment: 'POST /comment',
            file: 'GET /file?name=<filename>'
        }
    });
});

// API: Search
app.get('/api/search', (req, res) => {
    const query = req.query.q || '';
    res.json({
        message: `Search results for: ${query}`,
        results: [
            { id: 1, title: 'Result 1' },
            { id: 2, title: 'Result 2' }
        ]
    });
});

// API: Login
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    res.json({
        message: 'Login processed',
        username: username,
        success: true
    });
});

// API: User Profile
app.get('/api/users/:id', (req, res) => {
    res.json({
        id: req.params.id,
        name: 'Test User',
        email: 'user@example.com'
    });
});

// API: Comment
app.post('/api/comment', (req, res) => {
    const { content } = req.body;
    res.json({
        message: 'Comment posted',
        content: content,
        timestamp: new Date().toISOString()
    });
});

// API: File
app.get('/api/file', (req, res) => {
    const filename = req.query.name || 'default.txt';
    res.json({
        filename: filename,
        content: 'File content would be here'
    });
});

app.listen(PORT, () => {
    console.log(`🎯 Dummy Target running on http://localhost:${PORT}`);
});
