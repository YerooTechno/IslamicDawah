const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bodyParser = require('body-parser');

const app = express();
const PORT = process.env.PORT || 5000;
const SECRET_KEY = process.env.SECRET_KEY || 'islamic-dawah-platform-secret-2024';

// Security Middleware
app.use(helmet());
app.use(cors({
    origin: ['http://localhost:3000', 'http://yourdomain.com'],
    credentials: true
}));
app.use(bodyParser.json());

// Rate Limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // limit each IP to 100 requests per windowMs
});
app.use('/api/', limiter);

// Database Setup
const db = new sqlite3.Database('./database/islamic-db.sqlite', (err) => {
    if (err) {
        console.error('Database connection error:', err);
    } else {
        console.log('✅ Connected to SQLite database');
        initializeDatabase();
    }
});

// Initialize Database Tables
function initializeDatabase() {
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            phone TEXT,
            country TEXT,
            user_type TEXT DEFAULT 'member',
            language TEXT DEFAULT 'en',
            status TEXT DEFAULT 'active',
            registration_date DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_login DATETIME
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS questions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            question TEXT NOT NULL,
            category TEXT,
            language TEXT DEFAULT 'en',
            status TEXT DEFAULT 'pending',
            answer TEXT,
            answered_by INTEGER,
            answered_date DATETIME,
            created_date DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (answered_by) REFERENCES users (id)
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS content (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            type TEXT NOT NULL,
            category TEXT,
            language TEXT DEFAULT 'en',
            author_id INTEGER,
            views INTEGER DEFAULT 0,
            likes INTEGER DEFAULT 0,
            status TEXT DEFAULT 'published',
            created_date DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (author_id) REFERENCES users (id)
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS user_activity (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            details TEXT,
            ip_address TEXT,
            created_date DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    `);

    // Create default admin user
    const adminPassword = bcrypt.hashSync('Admin@1234', 10);
    db.run(`
        INSERT OR IGNORE INTO users (name, email, password, user_type) 
        VALUES ('System Admin', 'admin@islamicdawah.com', ?, 'admin')
    `, [adminPassword]);
}

// Middleware to verify JWT token
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid token' });
        }
        req.user = user;
        next();
    });
}

// Middleware to check admin role
function isAdmin(req, res, next) {
    if (req.user.user_type !== 'admin') {
        return res.status(403).json({ error: 'Admin access required' });
    }
    next();
}

// ========== API ROUTES ==========

// User Registration
app.post('/api/register', async (req, res) => {
    try {
        const { name, email, password, phone, country } = req.body;

        // Validate input
        if (!name || !email || !password) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        // Check if user exists
        db.get('SELECT id FROM users WHERE email = ?', [email], async (err, row) => {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }

            if (row) {
                return res.status(400).json({ error: 'Email already registered' });
            }

            // Hash password
            const hashedPassword = await bcrypt.hash(password, 10);

            // Insert new user
            db.run(
                `INSERT INTO users (name, email, password, phone, country, user_type) 
                 VALUES (?, ?, ?, ?, ?, 'member')`,
                [name, email, hashedPassword, phone, country],
                function(err) {
                    if (err) {
                        return res.status(500).json({ error: 'Registration failed' });
                    }

                    // Log activity
                    db.run(
                        'INSERT INTO user_activity (user_id, action, details) VALUES (?, ?, ?)',
                        [this.lastID, 'registration', `User registered with email ${email}`]
                    );

                    res.json({ 
                        success: true, 
                        message: 'Registration successful',
                        userId: this.lastID 
                    });
                }
            );
        });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// User Login
app.post('/api/login', (req, res) => {
    const { email, password } = req.body;

    db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }

        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Check password
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Update last login
        db.run('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', [user.id]);

        // Create JWT token
        const token = jwt.sign(
            { 
                id: user.id, 
                email: user.email, 
                user_type: user.user_type,
                name: user.name 
            },
            SECRET_KEY,
            { expiresIn: '24h' }
        );

        res.json({
            success: true,
            token,
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                user_type: user.user_type,
                language: user.language
            }
        });
    });
});

// Submit Question
app.post('/api/questions', authenticateToken, (req, res) => {
    const { question, category, language } = req.body;
    const userId = req.user.id;

    if (!question) {
        return res.status(400).json({ error: 'Question is required' });
    }

    db.run(
        `INSERT INTO questions (user_id, question, category, language, status) 
         VALUES (?, ?, ?, ?, 'pending')`,
        [userId, question, category, language || 'en'],
        function(err) {
            if (err) {
                return res.status(500).json({ error: 'Failed to submit question' });
            }

            // Log activity
            db.run(
                'INSERT INTO user_activity (user_id, action, details) VALUES (?, ?, ?)',
                [userId, 'question_submitted', `Question ID: ${this.lastID}`]
            );

            res.json({ 
                success: true, 
                message: 'Question submitted successfully',
                questionId: this.lastID 
            });
        }
    );
});

// Get Questions (Admin)
app.get('/api/admin/questions', authenticateToken, isAdmin, (req, res) => {
    const { status, page = 1, limit = 20 } = req.query;
    const offset = (page - 1) * limit;

    let query = `
        SELECT q.*, u.name as user_name, u.email as user_email 
        FROM questions q
        LEFT JOIN users u ON q.user_id = u.id
    `;
    let params = [];

    if (status) {
        query += ' WHERE q.status = ?';
        params.push(status);
    }

    query += ' ORDER BY q.created_date DESC LIMIT ? OFFSET ?';
    params.push(limit, offset);

    db.all(query, params, (err, questions) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }

        // Get total count
        db.get('SELECT COUNT(*) as total FROM questions WHERE status = ?', [status], (err, count) => {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }

            res.json({
                success: true,
                questions,
                pagination: {
                    page: parseInt(page),
                    limit: parseInt(limit),
                    total: count.total
                }
            });
        });
    });
});

// Answer Question (Admin)
app.post('/api/admin/questions/:id/answer', authenticateToken, isAdmin, (req, res) => {
    const questionId = req.params.id;
    const { answer } = req.body;
    const adminId = req.user.id;

    if (!answer) {
        return res.status(400).json({ error: 'Answer is required' });
    }

    db.run(
        `UPDATE questions 
         SET answer = ?, answered_by = ?, answered_date = CURRENT_TIMESTAMP, status = 'answered'
         WHERE id = ?`,
        [answer, adminId, questionId],
        function(err) {
            if (err) {
                return res.status(500).json({ error: 'Failed to answer question' });
            }

            // Log activity
            db.run(
                'INSERT INTO user_activity (user_id, action, details) VALUES (?, ?, ?)',
                [adminId, 'question_answered', `Answered question ID: ${questionId}`]
            );

            res.json({ 
                success: true, 
                message: 'Answer submitted successfully' 
            });
        }
    );
});

// Get Users (Admin)
app.get('/api/admin/users', authenticateToken, isAdmin, (req, res) => {
    const { page = 1, limit = 20 } = req.query;
    const offset = (page - 1) * limit;

    db.all(
        `SELECT id, name, email, phone, country, user_type, status, registration_date, last_login 
         FROM users 
         ORDER BY registration_date DESC 
         LIMIT ? OFFSET ?`,
        [limit, offset],
        (err, users) => {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }

            db.get('SELECT COUNT(*) as total FROM users', (err, count) => {
                if (err) {
                    return res.status(500).json({ error: 'Database error' });
                }

                res.json({
                    success: true,
                    users,
                    pagination: {
                        page: parseInt(page),
                        limit: parseInt(limit),
                        total: count.total
                    }
                });
            });
        }
    );
});

// Get Statistics (Admin Dashboard)
app.get('/api/admin/statistics', authenticateToken, isAdmin, (req, res) => {
    const queries = [
        'SELECT COUNT(*) as total_users FROM users',
        'SELECT COUNT(*) as pending_questions FROM questions WHERE status = "pending"',
        'SELECT COUNT(*) as answered_questions FROM questions WHERE status = "answered"',
        'SELECT COUNT(*) as total_questions FROM questions',
        'SELECT COUNT(*) as active_today FROM users WHERE last_login LIKE ?',
        `SELECT strftime('%Y-%m', registration_date) as month, COUNT(*) as count 
         FROM users 
         GROUP BY strftime('%Y-%m', registration_date) 
         ORDER BY month DESC LIMIT 6`
    ];

    const today = new Date().toISOString().split('T')[0] + '%';

    db.serialize(() => {
        const stats = {};

        db.get(queries[0], (err, row) => {
            if (!err) stats.total_users = row.total_users;
        });

        db.get(queries[1], (err, row) => {
            if (!err) stats.pending_questions = row.pending_questions;
        });

        db.get(queries[2], (err, row) => {
            if (!err) stats.answered_questions = row.answered_questions;
        });

        db.get(queries[3], (err, row) => {
            if (!err) stats.total_questions = row.total_questions;
        });

        db.get(queries[4], [today], (err, row) => {
            if (!err) stats.active_today = row.active_today;
        });

        db.all(queries[5], (err, rows) => {
            if (!err) stats.user_growth = rows;

            res.json({
                success: true,
                statistics: stats
            });
        });
    });
});

// Update User Status (Admin)
app.put('/api/admin/users/:id/status', authenticateToken, isAdmin, (req, res) => {
    const userId = req.params.id;
    const { status } = req.body;

    if (!['active', 'suspended', 'banned'].includes(status)) {
        return res.status(400).json({ error: 'Invalid status' });
    }

    db.run(
        'UPDATE users SET status = ? WHERE id = ?',
        [status, userId],
        function(err) {
            if (err) {
                return res.status(500).json({ error: 'Failed to update user' });
            }

            // Log activity
            db.run(
                'INSERT INTO user_activity (user_id, action, details) VALUES (?, ?, ?)',
                [req.user.id, 'user_status_changed', `User ${userId} status changed to ${status}`]
            );

            res.json({ 
                success: true, 
                message: 'User status updated successfully' 
            });
        }
    );
});

// Server static files from public folder
app.use(express.static('../public'));

// Start server
app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`📁 Database: islamic-db.sqlite`);
    console.log(`🔑 Admin login: admin@islamicdawah.com / Admin@1234`);
    console.log(`🌐 Access: http://localhost:${PORT}`);
});
