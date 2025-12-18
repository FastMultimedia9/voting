// server.js
const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { body, validationResult } = require('express-validator');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors({
    origin: process.env.FRONTEND_URL || 'http://localhost:3000',
    credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Database connection pool
const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'voting_system',
    port: process.env.DB_PORT || 3306,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    enableKeepAlive: true,
    keepAliveInitialDelay: 0
});

// Test database connection
pool.getConnection((err, connection) => {
    if (err) {
        console.error('Database connection failed:', err.message);
        return;
    }
    console.log('Connected to MySQL database');
    connection.release();
});

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'voting-system-secret-key-2024';

// Utility functions
const generateVerificationToken = () => {
    return crypto.randomBytes(32).toString('hex');
};




const generateResetToken = () => {
    return crypto.randomBytes(32).toString('hex');
};

// Authentication middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ 
            success: false, 
            error: 'Access token required' 
        });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ 
                success: false, 
                error: 'Invalid or expired token' 
            });
        }
        req.user = user;
        next();
    });
};

// Role-based authorization middleware
const authorizeRoles = (...roles) => {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({ 
                success: false, 
                error: 'Authentication required' 
            });
        }
        
        if (!roles.includes(req.user.role)) {
            return res.status(403).json({ 
                success: false, 
                error: 'Insufficient permissions' 
            });
        }
        next();
    };
};


// ============================================
// AUTHENTICATION API ROUTES
// ============================================

// Login endpoint
app.post('/api/auth/login', [
    body('username').trim().notEmpty().withMessage('Username is required'),
    body('password').notEmpty().withMessage('Password is required'),
    body('userType').isIn(['voter', 'candidate', 'admin']).withMessage('Invalid user type')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ 
            success: false, 
            errors: errors.array() 
        });
    }

    const { username, password, userType } = req.body;

    try {
        // Find user by username
        const [users] = await pool.promise().query(
            `SELECT * FROM users WHERE username = ?`,
            [username]
        );

        if (users.length === 0) {
            return res.status(404).json({ 
                success: false, 
                error: 'Account not found' 
            });
        }

        const user = users[0];

        // Verify user type matches
        if (userType !== user.role) {
            return res.status(403).json({ 
                success: false, 
                error: `Invalid login type. Please select ${user.role} role.` 
            });
        }

        // Check if account is active
        if (!user.is_active) {
            return res.status(403).json({ 
                success: false, 
                error: 'Account is deactivated. Please contact support.' 
            });
        }

        // Check account status
        if (user.status !== 'active') {
            let statusMsg = user.status === 'pending' ? 'pending approval' : user.status;
            return res.status(403).json({ 
                success: false, 
                error: `Account is ${statusMsg}. Please contact administrator.` 
            });
        }

        // Verify email if required (for non-admin users)
        if (user.role !== 'admin' && !user.is_verified) {
            return res.status(403).json({ 
                success: false, 
                error: 'Account not verified. Please check your email or contact administrator.' 
            });
        }

        // Compare password with bcrypt hash from database
        const isValidPassword = await bcrypt.compare(password, user.password_hash);

        if (!isValidPassword) {
            // Log failed login attempt
            await pool.promise().query(
                `INSERT INTO security_logs (
                    user_id,
                    event_type,
                    severity,
                    ip_address,
                    user_agent,
                    details
                ) VALUES (?, ?, ?, ?, ?, ?)`,
                [
                    user.user_id,
                    'failed_login',
                    'warning',
                    req.ip,
                    req.headers['user-agent'],
                    `Failed login attempt for username: ${username}`
                ]
            );

            return res.status(401).json({ 
                success: false, 
                error: 'Invalid username or password' 
            });
        }

        // Update last login
        await pool.promise().query(
            `UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE user_id = ?`,
            [user.user_id]
        );

        // Create JWT token
        const tokenPayload = {
            userId: user.user_id,
            username: user.username,
            role: user.role,
            email: user.email,
            fullName: user.full_name
        };

        const token = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: '24h' });

        // Remove sensitive data from user object
        const { password_hash, reset_token, reset_token_expiry, verification_token, ...safeUser } = user;

        res.json({
            success: true,
            message: 'Login successful',
            token,
            user: safeUser
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Login failed. Please try again.' 
        });
    }
});



// ============================================
// PASSWORD RESET API ROUTES
// ============================================

// Simple password reset (for testing/emergency use)
app.post('/api/auth/simple-reset', [
    body('identifier').trim().notEmpty().withMessage('Username or email is required'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
    body('confirmPassword').custom((value, { req }) => {
        if (value !== req.body.password) {
            throw new Error('Passwords do not match');
        }
        return true;
    })
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ 
            success: false, 
            errors: errors.array() 
        });
    }

    const { identifier, password } = req.body;

    try {
        // Find user by username or email
        const [users] = await pool.promise().query(
            `SELECT * FROM users WHERE username = ? OR email = ?`,
            [identifier, identifier]
        );

        if (users.length === 0) {
            return res.status(404).json({ 
                success: false, 
                error: 'Account not found. Please check your username or email.' 
            });
        }

        const user = users[0];

        // Check if account is active
        if (!user.is_active) {
            return res.status(403).json({ 
                success: false, 
                error: 'Account is deactivated. Please contact support.' 
            });
        }

        // Hash the new password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Update password
        await pool.promise().query(
            `UPDATE users 
             SET password_hash = ?, 
                 reset_token = NULL,
                 reset_token_expiry = NULL,
                 updated_at = CURRENT_TIMESTAMP
             WHERE user_id = ?`,
            [hashedPassword, user.user_id]
        );

        // Log the password reset (security log)
        await pool.promise().query(
            `INSERT INTO security_logs (
                user_id,
                event_type,
                severity,
                ip_address,
                user_agent,
                details
            ) VALUES (?, ?, ?, ?, ?, ?)`,
            [
                user.user_id,
                'password_reset',
                'info',
                req.ip,
                req.headers['user-agent'],
                'Password reset via simple reset form'
            ]
        );

        // Log admin action if admin performed the reset
        if (req.headers['authorization']) {
            try {
                const token = req.headers['authorization'].split(' ')[1];
                const decoded = jwt.verify(token, JWT_SECRET);
                
                if (decoded.role === 'admin') {
                    await pool.promise().query(
                        `INSERT INTO admin_actions (
                            admin_id,
                            action_type,
                            action_details,
                            affected_entity_type,
                            affected_entity_id,
                            ip_address,
                            user_agent
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)`,
                        [
                            decoded.userId,
                            'reset_user_password',
                            `Reset password for user: ${user.username}`,
                            'users',
                            user.user_id,
                            req.ip,
                            req.headers['user-agent']
                        ]
                    );
                }
            } catch (err) {
                // Not an admin or invalid token - that's fine
            }
        }

        res.json({
            success: true,
            message: 'Password reset successful'
        });

    } catch (error) {
        console.error('Password reset error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to reset password. Please try again.' 
        });
    }
});

// Request password reset (send reset email)
app.post('/api/auth/request-reset', [
    body('email').isEmail().withMessage('Valid email is required')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ 
            success: false, 
            errors: errors.array() 
        });
    }

    const { email } = req.body;

    try {
        // Find user by email
        const [users] = await pool.promise().query(
            'SELECT * FROM users WHERE email = ?',
            [email]
        );

        // Don't reveal if user exists or not (security best practice)
        if (users.length === 0) {
            return res.json({
                success: true,
                message: 'If an account exists with this email, you will receive a reset link.'
            });
        }

        const user = users[0];

        // Generate reset token
        const resetToken = generateResetToken();
        const resetTokenExpiry = new Date(Date.now() + 3600000); // 1 hour

        // Save reset token to database
        await pool.promise().query(
            `UPDATE users 
             SET reset_token = ?,
                 reset_token_expiry = ?
             WHERE user_id = ?`,
            [resetToken, resetTokenExpiry, user.user_id]
        );

        // TODO: Send reset email with token
        // const resetLink = `${process.env.FRONTEND_URL}/reset-password/${resetToken}`;
        
        res.json({
            success: true,
            message: 'If an account exists with this email, you will receive a reset link.'
        });

    } catch (error) {
        console.error('Request reset error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to process reset request. Please try again.' 
        });
    }
});

// Reset password with token
app.post('/api/auth/reset-password/:token', [
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
    body('confirmPassword').custom((value, { req }) => {
        if (value !== req.body.password) {
            throw new Error('Passwords do not match');
        }
        return true;
    })
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ 
            success: false, 
            errors: errors.array() 
        });
    }

    const { token } = req.params;
    const { password } = req.body;

    try {
        // Find user by reset token
        const [users] = await pool.promise().query(
            `SELECT * FROM users 
             WHERE reset_token = ? 
               AND reset_token_expiry > NOW()`,
            [token]
        );

        if (users.length === 0) {
            return res.status(400).json({ 
                success: false, 
                error: 'Invalid or expired reset token.' 
            });
        }

        const user = users[0];

        // Hash new password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Update password and clear reset token
        await pool.promise().query(
            `UPDATE users 
             SET password_hash = ?,
                 reset_token = NULL,
                 reset_token_expiry = NULL,
                 updated_at = CURRENT_TIMESTAMP
             WHERE user_id = ?`,
            [hashedPassword, user.user_id]
        );

        // Log security event
        await pool.promise().query(
            `INSERT INTO security_logs (
                user_id,
                event_type,
                severity,
                ip_address,
                user_agent,
                details
            ) VALUES (?, ?, ?, ?, ?, ?)`,
            [
                user.user_id,
                'password_reset',
                'info',
                req.ip,
                req.headers['user-agent'],
                'Password reset via token link'
            ]
        );

        res.json({
            success: true,
            message: 'Password has been reset successfully. You can now login with your new password.'
        });

    } catch (error) {
        console.error('Reset password error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to reset password. Please try again.' 
        });
    }
});



// Logout endpoint (optional - usually handled client-side)
app.post('/api/auth/logout', authenticateToken, (req, res) => {
    // In a real app, you might want to:
    // 1. Add token to blacklist
    // 2. Clear session data
    // 3. Log the logout
    
    res.json({
        success: true,
        message: 'Logout successful'
    });
});

// User registration endpoint (optional)
app.post('/api/auth/register', [
    body('username').trim().notEmpty().withMessage('Username is required'),
    body('email').isEmail().withMessage('Valid email is required'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
    body('fullName').trim().notEmpty().withMessage('Full name is required'),
    body('role').optional().isIn(['voter', 'candidate']).withMessage('Invalid role')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ 
            success: false, 
            errors: errors.array() 
        });
    }

    const { username, email, password, fullName, role = 'voter' } = req.body;

    try {
        // Check if username or email already exists
        const [existing] = await pool.promise().query(
            'SELECT user_id FROM users WHERE username = ? OR email = ?',
            [username, email]
        );

        if (existing.length > 0) {
            return res.status(409).json({ 
                success: false, 
                error: 'Username or email already exists' 
            });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Generate verification token
        const verificationToken = generateVerificationToken();

        // Create user
        const [result] = await pool.promise().query(
            `INSERT INTO users (
                username,
                email,
                password_hash,
                full_name,
                role,
                verification_token,
                status
            ) VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [
                username,
                email,
                hashedPassword,
                fullName,
                role,
                verificationToken,
                'pending'
            ]
        );

        // TODO: Send verification email

        res.status(201).json({
            success: true,
            message: 'Registration successful. Please check your email to verify your account.',
            userId: result.insertId
        });

    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Registration failed. Please try again.' 
        });
    }
});


// ============================================
// ADMIN DASHBOARD API ROUTES
// ============================================

// 1. Get Admin Dashboard Statistics
app.get('/api/admin/dashboard/stats', authenticateToken, authorizeRoles('admin'), async (req, res) => {
    try {
        // Get total elections
        const [electionCount] = await pool.promise().query(
            "SELECT COUNT(*) as total FROM elections"
        );

        // Get active elections
        const [activeElections] = await pool.promise().query(
            "SELECT COUNT(*) as active FROM elections WHERE status = 'active'"
        );

        // Get total voters
        const [voterCount] = await pool.promise().query(
            "SELECT COUNT(*) as total FROM users WHERE role = 'voter'"
        );

        // Get verified voters
        const [verifiedVoters] = await pool.promise().query(
            "SELECT COUNT(*) as verified FROM users WHERE role = 'voter' AND is_verified = 1"
        );

        // Get pending voters
        const [pendingVoters] = await pool.promise().query(
            "SELECT COUNT(*) as pending FROM users WHERE role = 'voter' AND status = 'pending'"
        );

        // Get suspended voters
        const [suspendedVoters] = await pool.promise().query(
            "SELECT COUNT(*) as suspended FROM users WHERE role = 'voter' AND status = 'suspended'"
        );

        // Get total candidates
        const [candidateCount] = await pool.promise().query(
            "SELECT COUNT(*) as total FROM candidates"
        );

        // Get approved candidates
        const [approvedCandidates] = await pool.promise().query(
            "SELECT COUNT(*) as approved FROM candidates WHERE is_approved = 1"
        );

        // Get pending candidates
        const [pendingCandidates] = await pool.promise().query(
            "SELECT COUNT(*) as pending FROM candidates WHERE is_approved = 0"
        );

        // Get rejected candidates
        const [rejectedCandidates] = await pool.promise().query(
            "SELECT COUNT(*) as rejected FROM candidates WHERE status = 'rejected'"
        );

        // Get total votes cast
        const [votesCount] = await pool.promise().query(
            "SELECT COUNT(*) as total FROM votes"
        );

        // Get system uptime (mock data for now)
        const systemUptime = 98.2;

        res.json({
            success: true,
            stats: {
                totalElections: electionCount[0].total,
                activeElections: activeElections[0].active,
                totalVoters: voterCount[0].total,
                verifiedVoters: verifiedVoters[0].verified,
                pendingVoters: pendingVoters[0].pending,
                suspendedVoters: suspendedVoters[0].suspended,
                totalCandidates: candidateCount[0].total,
                approvedCandidates: approvedCandidates[0].approved,
                pendingCandidates: pendingCandidates[0].pending,
                rejectedCandidates: rejectedCandidates[0].rejected,
                totalVotesCast: votesCount[0].total,
                systemUptimePercentage: systemUptime
            }
        });
    } catch (error) {
        console.error('Dashboard stats error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to fetch dashboard statistics' 
        });
    }
});

// 2. Get Recent Activity
app.get('/api/admin/recent-activity', authenticateToken, authorizeRoles('admin'), async (req, res) => {
    try {
        const [activities] = await pool.promise().query(`
            SELECT 
                aa.action_id,
                aa.action_type,
                aa.action_details,
                aa.affected_entity_type,
                aa.affected_entity_id,
                aa.created_at,
                u.username as admin_name,
                u.full_name as admin_full_name
            FROM admin_actions aa
            JOIN users u ON aa.admin_id = u.user_id
            ORDER BY aa.created_at DESC
            LIMIT 20
        `);

        res.json({
            success: true,
            activities
        });
    } catch (error) {
        console.error('Recent activity error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to fetch recent activity' 
        });
    }
});

// 3. Get Active Elections List
app.get('/api/admin/active-elections', authenticateToken, authorizeRoles('admin'), async (req, res) => {
    try {
        const [elections] = await pool.promise().query(`
            SELECT 
                e.election_id,
                e.election_name,
                e.description,
                e.start_date,
                e.end_date,
                e.status,
                e.total_voters,
                e.total_votes_cast,
                e.turnout_percentage,
                COUNT(DISTINCT p.position_id) as total_positions,
                COUNT(DISTINCT c.candidate_id) as total_candidates,
                (DATEDIFF(e.end_date, NOW())) as days_remaining,
                CASE 
                    WHEN NOW() < e.start_date THEN 'upcoming'
                    WHEN NOW() BETWEEN e.start_date AND e.end_date THEN 'active'
                    ELSE 'ended'
                END as current_status
            FROM elections e
            LEFT JOIN positions p ON e.election_id = p.election_id
            LEFT JOIN candidates c ON p.position_id = c.position_id
            WHERE e.status = 'active'
            GROUP BY e.election_id
            ORDER BY e.start_date
        `);

        res.json({
            success: true,
            elections
        });
    } catch (error) {
        console.error('Active elections error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to fetch active elections' 
        });
    }
});

// ============================================
// ADMIN ELECTION MANAGEMENT API ROUTES
// ============================================

// 4. Get All Elections (Admin View)
app.get('/api/admin/elections', authenticateToken, authorizeRoles('admin'), async (req, res) => {
    try {
        const { status, search } = req.query;
        
        let query = `
            SELECT 
                e.*,
                u.username as created_by_username,
                u.full_name as created_by_name,
                COUNT(DISTINCT p.position_id) as total_positions,
                COUNT(DISTINCT c.candidate_id) as total_candidates,
                COUNT(DISTINCT vr.user_id) as registered_voters
            FROM elections e
            LEFT JOIN users u ON e.created_by = u.user_id
            LEFT JOIN positions p ON e.election_id = p.election_id
            LEFT JOIN candidates c ON p.position_id = c.position_id
            LEFT JOIN voter_registrations vr ON e.election_id = vr.election_id AND vr.registration_status = 'approved'
        `;
        
        const params = [];
        const conditions = [];
        
        if (status && status !== 'all') {
            conditions.push('e.status = ?');
            params.push(status);
        }
        
        if (search) {
            conditions.push('(e.election_name LIKE ? OR e.description LIKE ?)');
            params.push(`%${search}%`, `%${search}%`);
        }
        
        if (conditions.length > 0) {
            query += ' WHERE ' + conditions.join(' AND ');
        }
        
        query += ' GROUP BY e.election_id ORDER BY e.start_date DESC';
        
        const [elections] = await pool.promise().query(query, params);

        res.json({
            success: true,
            elections
        });
    } catch (error) {
        console.error('Get elections error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to fetch elections' 
        });
    }
});

// 5. Create New Election
app.post('/api/admin/elections', authenticateToken, authorizeRoles('admin'), [
    body('electionName').trim().notEmpty().withMessage('Election name is required'),
    body('description').optional().trim(),
    body('startDate').isISO8601().withMessage('Valid start date is required'),
    body('endDate').isISO8601().withMessage('Valid end date is required'),
    body('isSecretBallot').optional().isBoolean(),
    body('resultsVisible').optional().isIn(['immediate', 'after_vote', 'after_election']),
    body('allowWriteIns').optional().isBoolean(),
    body('minVotesPerVoter').optional().isInt({ min: 1 }),
    body('maxVotesPerVoter').optional().isInt({ min: 1 })
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ 
            success: false, 
            errors: errors.array() 
        });
    }

    const {
        electionName,
        description,
        startDate,
        endDate,
        isSecretBallot = true,
        resultsVisible = 'after_election',
        allowWriteIns = false,
        minVotesPerVoter = 1,
        maxVotesPerVoter = 1
    } = req.body;

    try {
        // Start transaction
        const connection = await pool.promise().getConnection();
        await connection.beginTransaction();

        try {
            // Create election
            const [electionResult] = await connection.query(
                `INSERT INTO elections (
                    election_name,
                    description,
                    start_date,
                    end_date,
                    created_by,
                    is_secret_ballot,
                    results_visible,
                    allow_write_ins,
                    min_votes_per_voter,
                    max_votes_per_voter,
                    status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'draft')`,
                [
                    electionName,
                    description,
                    new Date(startDate),
                    new Date(endDate),
                    req.user.userId,
                    isSecretBallot,
                    resultsVisible,
                    allowWriteIns,
                    minVotesPerVoter,
                    maxVotesPerVoter
                ]
            );

            const electionId = electionResult.insertId;

            // Log admin action
            await connection.query(
                `INSERT INTO admin_actions (
                    admin_id,
                    action_type,
                    action_details,
                    affected_entity_type,
                    affected_entity_id,
                    ip_address,
                    user_agent
                ) VALUES (?, ?, ?, ?, ?, ?, ?)`,
                [
                    req.user.userId,
                    'create_election',
                    `Created new election: ${electionName}`,
                    'elections',
                    electionId,
                    req.ip,
                    req.headers['user-agent']
                ]
            );

            await connection.commit();
            connection.release();

            res.status(201).json({
                success: true,
                message: 'Election created successfully',
                electionId
            });
        } catch (error) {
            await connection.rollback();
            connection.release();
            throw error;
        }
    } catch (error) {
        console.error('Create election error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to create election' 
        });
    }
});

// 6. Update Election
app.put('/api/admin/elections/:id', authenticateToken, authorizeRoles('admin'), async (req, res) => {
    const electionId = req.params.id;
    const updates = req.body;

    try {
        // Get current election data
        const [currentElection] = await pool.promise().query(
            'SELECT * FROM elections WHERE election_id = ?',
            [electionId]
        );

        if (currentElection.length === 0) {
            return res.status(404).json({ 
                success: false, 
                error: 'Election not found' 
            });
        }

        // Build update query
        const allowedFields = [
            'election_name', 'description', 'start_date', 'end_date', 
            'status', 'is_secret_ballot', 'results_visible', 'allow_write_ins',
            'min_votes_per_voter', 'max_votes_per_voter'
        ];
        
        const updateFields = {};
        const values = [];
        
        for (const field of allowedFields) {
            if (updates[field] !== undefined) {
                updateFields[field] = updates[field];
                values.push(updates[field]);
            }
        }

        if (Object.keys(updateFields).length === 0) {
            return res.status(400).json({ 
                success: false, 
                error: 'No valid fields to update' 
            });
        }

        const setClause = Object.keys(updateFields).map(field => `${field} = ?`).join(', ');
        values.push(electionId);

        await pool.promise().query(
            `UPDATE elections 
             SET ${setClause}, updated_at = CURRENT_TIMESTAMP
             WHERE election_id = ?`,
            values
        );

        // Log admin action
        await pool.promise().query(
            `INSERT INTO admin_actions (
                admin_id,
                action_type,
                action_details,
                affected_entity_type,
                affected_entity_id,
                ip_address,
                user_agent
            ) VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [
                req.user.userId,
                'update_election',
                `Updated election: ${currentElection[0].election_name}`,
                'elections',
                electionId,
                req.ip,
                req.headers['user-agent']
            ]
        );

        res.json({
            success: true,
            message: 'Election updated successfully'
        });
    } catch (error) {
        console.error('Update election error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to update election' 
        });
    }
});

// 7. Delete Election
app.delete('/api/admin/elections/:id', authenticateToken, authorizeRoles('admin'), async (req, res) => {
    const electionId = req.params.id;

    try {
        // Get election name before deletion for logging
        const [election] = await pool.promise().query(
            'SELECT election_name FROM elections WHERE election_id = ?',
            [electionId]
        );

        if (election.length === 0) {
            return res.status(404).json({ 
                success: false, 
                error: 'Election not found' 
            });
        }

        // Start transaction
        const connection = await pool.promise().getConnection();
        await connection.beginTransaction();

        try {
            // Delete election (cascade will handle related records)
            await connection.query(
                'DELETE FROM elections WHERE election_id = ?',
                [electionId]
            );

            // Log admin action
            await connection.query(
                `INSERT INTO admin_actions (
                    admin_id,
                    action_type,
                    action_details,
                    affected_entity_type,
                    affected_entity_id,
                    ip_address,
                    user_agent
                ) VALUES (?, ?, ?, ?, ?, ?, ?)`,
                [
                    req.user.userId,
                    'delete_election',
                    `Deleted election: ${election[0].election_name}`,
                    'elections',
                    electionId,
                    req.ip,
                    req.headers['user-agent']
                ]
            );

            await connection.commit();
            connection.release();

            res.json({
                success: true,
                message: 'Election deleted successfully'
            });
        } catch (error) {
            await connection.rollback();
            connection.release();
            throw error;
        }
    } catch (error) {
        console.error('Delete election error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to delete election' 
        });
    }
});

// 8. Get Election Details with Positions
app.get('/api/admin/elections/:id/details', authenticateToken, authorizeRoles('admin'), async (req, res) => {
    const electionId = req.params.id;

    try {
        // Get election details
        const [elections] = await pool.promise().query(
            `SELECT 
                e.*,
                u.username as created_by_username,
                u.full_name as created_by_name
             FROM elections e
             LEFT JOIN users u ON e.created_by = u.user_id
             WHERE e.election_id = ?`,
            [electionId]
        );

        if (elections.length === 0) {
            return res.status(404).json({ 
                success: false, 
                error: 'Election not found' 
            });
        }

        const election = elections[0];

        // Get positions for this election
        const [positions] = await pool.promise().query(
            `SELECT 
                p.*,
                COUNT(DISTINCT c.candidate_id) as candidate_count,
                COUNT(DISTINCT v.vote_id) as votes_cast
             FROM positions p
             LEFT JOIN candidates c ON p.position_id = c.position_id AND c.is_active = TRUE
             LEFT JOIN votes v ON p.position_id = v.position_id AND v.election_id = ?
             WHERE p.election_id = ?
             GROUP BY p.position_id
             ORDER BY p.sort_order`,
            [electionId, electionId]
        );

        election.positions = positions;

        // Get registration statistics
        const [registrationStats] = await pool.promise().query(
            `SELECT 
                COUNT(*) as total_registrations,
                SUM(CASE WHEN registration_status = 'approved' THEN 1 ELSE 0 END) as approved,
                SUM(CASE WHEN registration_status = 'pending' THEN 1 ELSE 0 END) as pending,
                SUM(CASE WHEN registration_status = 'rejected' THEN 1 ELSE 0 END) as rejected,
                SUM(CASE WHEN has_voted = 1 THEN 1 ELSE 0 END) as voted
             FROM voter_registrations 
             WHERE election_id = ?`,
            [electionId]
        );

        election.registrationStats = registrationStats[0];

        res.json({
            success: true,
            election
        });
    } catch (error) {
        console.error('Get election details error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to fetch election details' 
        });
    }
});

// ============================================
// ADMIN CANDIDATE MANAGEMENT API ROUTES
// ============================================

// 9. Get All Candidates
app.get('/api/admin/candidates', authenticateToken, authorizeRoles('admin'), async (req, res) => {
    try {
        const { status, electionId, search } = req.query;
        
        let query = `
            SELECT 
                c.*,
                p.position_name,
                p.election_id,
                e.election_name,
                u.username as user_username,
                u.email as user_email,
                u.full_name as user_full_name,
                a.full_name as approved_by_name,
                COUNT(v.vote_id) as total_votes
            FROM candidates c
            JOIN positions p ON c.position_id = p.position_id
            JOIN elections e ON p.election_id = e.election_id
            LEFT JOIN users u ON c.user_id = u.user_id
            LEFT JOIN users a ON c.approved_by = a.user_id
            LEFT JOIN votes v ON c.candidate_id = v.candidate_id
        `;
        
        const params = [];
        const conditions = [];
        
        if (status && status !== 'all') {
            if (status === 'approved') {
                conditions.push('c.is_approved = 1');
            } else if (status === 'pending') {
                conditions.push('c.is_approved = 0');
            } else {
                conditions.push('c.status = ?');
                params.push(status);
            }
        }
        
        if (electionId && electionId !== 'all') {
            conditions.push('p.election_id = ?');
            params.push(electionId);
        }
        
        if (search) {
            conditions.push('(c.candidate_name LIKE ? OR p.position_name LIKE ? OR e.election_name LIKE ?)');
            params.push(`%${search}%`, `%${search}%`, `%${search}%`);
        }
        
        if (conditions.length > 0) {
            query += ' WHERE ' + conditions.join(' AND ');
        }
        
        query += ' GROUP BY c.candidate_id ORDER BY c.registration_date DESC';
        
        const [candidates] = await pool.promise().query(query, params);

        res.json({
            success: true,
            candidates
        });
    } catch (error) {
        console.error('Get candidates error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to fetch candidates' 
        });
    }
});

// 10. Create New Candidate
app.post('/api/admin/candidates', authenticateToken, authorizeRoles('admin'), [
    body('positionId').isInt().withMessage('Valid position ID is required'),
    body('candidateName').trim().notEmpty().withMessage('Candidate name is required'),
    body('candidateParty').optional().trim(),
    body('biography').optional().trim(),
    body('manifesto').optional().trim(),
    body('contactEmail').optional().isEmail(),
    body('contactPhone').optional().trim(),
    body('websiteUrl').optional().trim()
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ 
            success: false, 
            errors: errors.array() 
        });
    }

    const {
        positionId,
        candidateName,
        candidateParty,
        biography,
        manifesto,
        contactEmail,
        contactPhone,
        websiteUrl,
        socialMedia
    } = req.body;

    try {
        const [result] = await pool.promise().query(
            `INSERT INTO candidates (
                position_id,
                candidate_name,
                candidate_party,
                biography,
                manifesto,
                contact_email,
                contact_phone,
                website_url,
                social_media,
                is_approved,
                status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                positionId,
                candidateName,
                candidateParty,
                biography,
                manifesto,
                contactEmail,
                contactPhone,
                websiteUrl,
                socialMedia ? JSON.stringify(socialMedia) : null,
                1, // Auto-approve when created by admin
                'approved'
            ]
        );

        const candidateId = result.insertId;

        // Log admin action
        await pool.promise().query(
            `INSERT INTO admin_actions (
                admin_id,
                action_type,
                action_details,
                affected_entity_type,
                affected_entity_id,
                ip_address,
                user_agent
            ) VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [
                req.user.userId,
                'add_candidate',
                `Added new candidate: ${candidateName}`,
                'candidates',
                candidateId,
                req.ip,
                req.headers['user-agent']
            ]
        );

        res.status(201).json({
            success: true,
            message: 'Candidate added successfully',
            candidateId
        });
    } catch (error) {
        console.error('Add candidate error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to add candidate' 
        });
    }
});

// 11. Update Candidate
app.put('/api/admin/candidates/:id', authenticateToken, authorizeRoles('admin'), async (req, res) => {
    const candidateId = req.params.id;
    const updates = req.body;

    try {
        // Get current candidate data
        const [currentCandidate] = await pool.promise().query(
            'SELECT candidate_name FROM candidates WHERE candidate_id = ?',
            [candidateId]
        );

        if (currentCandidate.length === 0) {
            return res.status(404).json({ 
                success: false, 
                error: 'Candidate not found' 
            });
        }

        // Build update query
        const allowedFields = [
            'candidate_name', 'candidate_party', 'biography', 'manifesto',
            'contact_email', 'contact_phone', 'website_url', 'social_media',
            'is_active', 'is_approved', 'status'
        ];
        
        const updateFields = {};
        const values = [];
        
        for (const field of allowedFields) {
            if (updates[field] !== undefined) {
                updateFields[field] = updates[field];
                
                // Handle JSON fields
                if (field === 'social_media' && updates[field]) {
                    values.push(JSON.stringify(updates[field]));
                } else {
                    values.push(updates[field]);
                }
            }
        }

        if (Object.keys(updateFields).length === 0) {
            return res.status(400).json({ 
                success: false, 
                error: 'No valid fields to update' 
            });
        }

        // If approval status changed, update approval_date and approved_by
        if (updates.is_approved !== undefined) {
            if (updates.is_approved) {
                updateFields.approval_date = new Date();
                updateFields.approved_by = req.user.userId;
                values.push(updateFields.approval_date, updateFields.approved_by);
            } else {
                updateFields.approval_date = null;
                updateFields.approved_by = null;
                values.push(null, null);
            }
        }

        const setClause = Object.keys(updateFields).map(field => `${field} = ?`).join(', ');
        values.push(candidateId);

        await pool.promise().query(
            `UPDATE candidates 
             SET ${setClause}, updated_at = CURRENT_TIMESTAMP
             WHERE candidate_id = ?`,
            values
        );

        // Log admin action
        const actionType = updates.is_approved ? 'approve_candidate' : 
                          updates.status === 'rejected' ? 'reject_candidate' : 
                          'update_candidate';
        
        const actionDetails = updates.is_approved ? `Approved candidate: ${currentCandidate[0].candidate_name}` :
                             updates.status === 'rejected' ? `Rejected candidate: ${currentCandidate[0].candidate_name}` :
                             `Updated candidate: ${currentCandidate[0].candidate_name}`;

        await pool.promise().query(
            `INSERT INTO admin_actions (
                admin_id,
                action_type,
                action_details,
                affected_entity_type,
                affected_entity_id,
                ip_address,
                user_agent
            ) VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [
                req.user.userId,
                actionType,
                actionDetails,
                'candidates',
                candidateId,
                req.ip,
                req.headers['user-agent']
            ]
        );

        res.json({
            success: true,
            message: 'Candidate updated successfully'
        });
    } catch (error) {
        console.error('Update candidate error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to update candidate' 
        });
    }
});

// 12. Delete Candidate
app.delete('/api/admin/candidates/:id', authenticateToken, authorizeRoles('admin'), async (req, res) => {
    const candidateId = req.params.id;

    try {
        // Get candidate name before deletion for logging
        const [candidate] = await pool.promise().query(
            'SELECT candidate_name FROM candidates WHERE candidate_id = ?',
            [candidateId]
        );

        if (candidate.length === 0) {
            return res.status(404).json({ 
                success: false, 
                error: 'Candidate not found' 
            });
        }

        // Delete candidate
        await pool.promise().query(
            'DELETE FROM candidates WHERE candidate_id = ?',
            [candidateId]
        );

        // Log admin action
        await pool.promise().query(
            `INSERT INTO admin_actions (
                admin_id,
                action_type,
                action_details,
                affected_entity_type,
                affected_entity_id,
                ip_address,
                user_agent
            ) VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [
                req.user.userId,
                'delete_candidate',
                `Deleted candidate: ${candidate[0].candidate_name}`,
                'candidates',
                candidateId,
                req.ip,
                req.headers['user-agent']
            ]
        );

        res.json({
            success: true,
            message: 'Candidate deleted successfully'
        });
    } catch (error) {
        console.error('Delete candidate error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to delete candidate' 
        });
    }
});

// ============================================
// ADMIN VOTER MANAGEMENT API ROUTES
// ============================================

// 13. Get All Voters
app.get('/api/admin/voters', authenticateToken, authorizeRoles('admin'), async (req, res) => {
    try {
        const { status, search, electionId } = req.query;
        
        let query = `
            SELECT 
                u.*,
                COUNT(DISTINCT vr.registration_id) as total_registrations,
                COUNT(DISTINCT v.vote_id) as total_votes,
                GROUP_CONCAT(DISTINCT e.election_name) as elections_voted_in
            FROM users u
            LEFT JOIN voter_registrations vr ON u.user_id = vr.user_id
            LEFT JOIN votes v ON u.user_id = v.voter_id
            LEFT JOIN elections e ON v.election_id = e.election_id
            WHERE u.role = 'voter'
        `;
        
        const params = [];
        const conditions = [];
        
        if (status && status !== 'all') {
            conditions.push('u.status = ?');
            params.push(status);
        }
        
        if (search) {
            conditions.push('(u.username LIKE ? OR u.email LIKE ? OR u.full_name LIKE ?)');
            params.push(`%${search}%`, `%${search}%`, `%${search}%`);
        }
        
        if (electionId && electionId !== 'all') {
            query = `
                SELECT 
                    u.*,
                    vr.registration_status,
                    vr.has_voted,
                    vr.voted_at,
                    vr.voter_number
                FROM users u
                JOIN voter_registrations vr ON u.user_id = vr.user_id
                WHERE u.role = 'voter' AND vr.election_id = ?
            `;
            params.push(electionId);
            
            if (search) {
                query += ' AND (u.username LIKE ? OR u.email LIKE ? OR u.full_name LIKE ?)';
                params.push(`%${search}%`, `%${search}%`, `%${search}%`);
            }
        } else {
            if (conditions.length > 0) {
                query += ' AND ' + conditions.join(' AND ');
            }
            
            query += ' GROUP BY u.user_id ORDER BY u.registration_date DESC';
        }
        
        const [voters] = await pool.promise().query(query, params);

        res.json({
            success: true,
            voters
        });
    } catch (error) {
        console.error('Get voters error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to fetch voters' 
        });
    }
});

// 14. Update Voter Status
app.put('/api/admin/voters/:id/status', authenticateToken, authorizeRoles('admin'), [
    body('status').isIn(['active', 'pending', 'suspended', 'inactive']).withMessage('Invalid status'),
    body('reason').optional().trim()
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ 
            success: false, 
            errors: errors.array() 
        });
    }

    const voterId = req.params.id;
    const { status, reason } = req.body;

    try {
        // Get voter info before update
        const [voter] = await pool.promise().query(
            'SELECT username, full_name FROM users WHERE user_id = ?',
            [voterId]
        );

        if (voter.length === 0) {
            return res.status(404).json({ 
                success: false, 
                error: 'Voter not found' 
            });
        }

        // Update voter status
        await pool.promise().query(
            `UPDATE users 
             SET status = ?, updated_at = CURRENT_TIMESTAMP
             WHERE user_id = ?`,
            [status, voterId]
        );

        // Log admin action
        const actionType = status === 'suspended' ? 'suspend_voter' : 
                         status === 'active' ? 'activate_voter' : 
                         'update_voter_status';
        
        const actionDetails = status === 'suspended' ? `Suspended voter account: ${voter[0].full_name}` :
                             status === 'active' ? `Activated voter account: ${voter[0].full_name}` :
                             `Updated voter status to ${status}: ${voter[0].full_name}`;

        await pool.promise().query(
            `INSERT INTO admin_actions (
                admin_id,
                action_type,
                action_details,
                affected_entity_type,
                affected_entity_id,
                ip_address,
                user_agent
            ) VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [
                req.user.userId,
                actionType,
                actionDetails,
                'users',
                voterId,
                req.ip,
                req.headers['user-agent']
            ]
        );

        res.json({
            success: true,
            message: `Voter status updated to ${status}`
        });
    } catch (error) {
        console.error('Update voter status error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to update voter status' 
        });
    }
});



// Admin: Add new user directly
app.post('/api/admin/users', authenticateToken, authorizeRoles('admin'), [
    body('username').trim().notEmpty().withMessage('Username is required'),
    body('email').isEmail().withMessage('Valid email is required'),
    body('password').optional().isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
    body('fullName').trim().notEmpty().withMessage('Full name is required'),
    body('role').isIn(['voter', 'candidate', 'admin', 'auditor']).withMessage('Invalid role'),
    body('status').optional().isIn(['active', 'pending', 'suspended', 'inactive']),
    body('isVerified').optional().isBoolean(),
    body('phoneNumber').optional().trim(),
    body('address').optional().trim(),
    body('dateOfBirth').optional().isISO8601()
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ 
            success: false, 
            errors: errors.array() 
        });
    }

    const {
        username,
        email,
        password = 'TempPassword123', // Default password
        fullName,
        role,
        status = 'active',
        isVerified = true,
        phoneNumber,
        address,
        dateOfBirth
    } = req.body;

    try {
        // Check if username or email already exists
        const [existing] = await pool.promise().query(
            'SELECT user_id FROM users WHERE username = ? OR email = ?',
            [username, email]
        );

        if (existing.length > 0) {
            return res.status(409).json({ 
                success: false, 
                error: 'Username or email already exists' 
            });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert user
        const [result] = await pool.promise().query(
            `INSERT INTO users (
                username,
                email,
                password_hash,
                full_name,
                role,
                status,
                is_active,
                is_verified,
                phone_number,
                address,
                date_of_birth
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                username,
                email,
                hashedPassword,
                fullName,
                role,
                status,
                1, // is_active
                isVerified ? 1 : 0,
                phoneNumber,
                address,
                dateOfBirth
            ]
        );

        const userId = result.insertId;

        // Log admin action
        await pool.promise().query(
            `INSERT INTO admin_actions (
                admin_id,
                action_type,
                action_details,
                affected_entity_type,
                affected_entity_id,
                ip_address,
                user_agent
            ) VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [
                req.user.userId,
                'add_user',
                `Added new user: ${fullName} (${role})`,
                'users',
                userId,
                req.ip,
                req.headers['user-agent']
            ]
        );

        res.status(201).json({
            success: true,
            message: 'User added successfully',
            userId,
            user: {
                username,
                email,
                fullName,
                role,
                status
            }
        });

    } catch (error) {
        console.error('Add user error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to add user' 
        });
    }
});




// Admin: Bulk import users from CSV
app.post('/api/admin/users/import', authenticateToken, authorizeRoles('admin'), async (req, res) => {
    const { usersData } = req.body; // Array of user objects
    
    if (!Array.isArray(usersData) || usersData.length === 0) {
        return res.status(400).json({ 
            success: false, 
            error: 'No user data provided' 
        });
    }

    try {
        const connection = await pool.promise().getConnection();
        await connection.beginTransaction();

        const results = {
            total: usersData.length,
            successful: 0,
            failed: 0,
            errors: []
        };

        for (const userData of usersData) {
            try {
                // Check if user exists
                const [existing] = await connection.query(
                    'SELECT user_id FROM users WHERE username = ? OR email = ?',
                    [userData.username, userData.email]
                );

                if (existing.length > 0) {
                    results.failed++;
                    results.errors.push({
                        username: userData.username,
                        error: 'User already exists'
                    });
                    continue;
                }

                // Hash password (use default if not provided)
                const password = userData.password || 'DefaultPassword123';
                const hashedPassword = await bcrypt.hash(password, 10);

                // Insert user
                const [result] = await connection.query(
                    `INSERT INTO users (
                        username,
                        email,
                        password_hash,
                        full_name,
                        role,
                        status,
                        is_active,
                        is_verified,
                        phone_number,
                        address,
                        date_of_birth
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                    [
                        userData.username,
                        userData.email,
                        hashedPassword,
                        userData.fullName,
                        userData.role || 'voter',
                        userData.status || 'active',
                        1,
                        userData.isVerified !== false ? 1 : 0,
                        userData.phoneNumber,
                        userData.address,
                        userData.dateOfBirth
                    ]
                );

                results.successful++;

                // Log the addition
                await connection.query(
                    `INSERT INTO admin_actions (
                        admin_id,
                        action_type,
                        action_details,
                        affected_entity_type,
                        affected_entity_id,
                        ip_address,
                        user_agent
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)`,
                    [
                        req.user.userId,
                        'bulk_import_user',
                        `Imported user: ${userData.fullName}`,
                        'users',
                        result.insertId,
                        req.ip,
                        req.headers['user-agent']
                    ]
                );

            } catch (error) {
                results.failed++;
                results.errors.push({
                    username: userData.username,
                    error: error.message
                });
            }
        }

        await connection.commit();
        connection.release();

        res.json({
            success: true,
            message: `Bulk import completed: ${results.successful} successful, ${results.failed} failed`,
            results
        });

    } catch (error) {
        console.error('Bulk import error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to import users' 
        });
    }
});



// 15. Approve/Reject Voter Registration
app.put('/api/admin/voter-registrations/:id', authenticateToken, authorizeRoles('admin'), [
    body('registrationStatus').isIn(['approved', 'rejected']).withMessage('Invalid registration status'),
    body('rejectionReason').optional().trim()
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ 
            success: false, 
            errors: errors.array() 
        });
    }

    const registrationId = req.params.id;
    const { registrationStatus, rejectionReason } = req.body;

    try {
        // Get registration info
        const [registration] = await pool.promise().query(
            `SELECT 
                vr.*,
                u.full_name,
                e.election_name
             FROM voter_registrations vr
             JOIN users u ON vr.user_id = u.user_id
             JOIN elections e ON vr.election_id = e.election_id
             WHERE vr.registration_id = ?`,
            [registrationId]
        );

        if (registration.length === 0) {
            return res.status(404).json({ 
                success: false, 
                error: 'Registration not found' 
            });
        }

        const reg = registration[0];

        // Update registration
        await pool.promise().query(
            `UPDATE voter_registrations 
             SET registration_status = ?,
                 approved_by = ?,
                 approved_date = ?,
                 rejection_reason = ?
             WHERE registration_id = ?`,
            [
                registrationStatus,
                req.user.userId,
                new Date(),
                rejectionReason,
                registrationId
            ]
        );

        // Log admin action
        const actionType = registrationStatus === 'approved' ? 'approve_voter' : 'reject_voter';
        const actionDetails = registrationStatus === 'approved' ? 
            `Approved voter registration: ${reg.full_name} for ${reg.election_name}` :
            `Rejected voter registration: ${reg.full_name} for ${reg.election_name}`;

        await pool.promise().query(
            `INSERT INTO admin_actions (
                admin_id,
                action_type,
                action_details,
                affected_entity_type,
                affected_entity_id,
                ip_address,
                user_agent
            ) VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [
                req.user.userId,
                actionType,
                actionDetails,
                'voter_registrations',
                registrationId,
                req.ip,
                req.headers['user-agent']
            ]
        );

        res.json({
            success: true,
            message: `Voter registration ${registrationStatus} successfully`
        });
    } catch (error) {
        console.error('Update voter registration error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to update voter registration' 
        });
    }
});

// ============================================
// ADMIN REPORTS API ROUTES
// ============================================

// 16. Get Election Results Report
app.get('/api/admin/reports/election-results/:electionId', authenticateToken, authorizeRoles('admin'), async (req, res) => {
    const electionId = req.params.id;

    try {
        // Get election details
        const [election] = await pool.promise().query(
            'SELECT * FROM elections WHERE election_id = ?',
            [electionId]
        );

        if (election.length === 0) {
            return res.status(404).json({ 
                success: false, 
                error: 'Election not found' 
            });
        }

        // Get position-wise results
        const [results] = await pool.promise().query(`
            SELECT 
                p.position_id,
                p.position_name,
                c.candidate_id,
                c.candidate_name,
                c.candidate_party,
                COUNT(v.vote_id) as total_votes,
                ROUND((COUNT(v.vote_id) * 100.0) / NULLIF((
                    SELECT COUNT(*) 
                    FROM votes v2 
                    JOIN positions p2 ON v2.position_id = p2.position_id
                    WHERE p2.position_id = p.position_id
                ), 0), 2) as percentage
            FROM positions p
            LEFT JOIN candidates c ON p.position_id = c.position_id AND c.is_approved = 1
            LEFT JOIN votes v ON c.candidate_id = v.candidate_id AND v.election_id = ?
            WHERE p.election_id = ?
            GROUP BY p.position_id, c.candidate_id
            ORDER BY p.sort_order, total_votes DESC
        `, [electionId, electionId]);

        // Get voter turnout statistics
        const [turnout] = await pool.promise().query(`
            SELECT 
                COUNT(DISTINCT vr.user_id) as total_registered,
                COUNT(DISTINCT CASE WHEN vr.has_voted = 1 THEN vr.user_id END) as total_voted,
                ROUND((COUNT(DISTINCT CASE WHEN vr.has_voted = 1 THEN vr.user_id END) * 100.0) / 
                      NULLIF(COUNT(DISTINCT vr.user_id), 0), 2) as turnout_percentage
            FROM voter_registrations vr
            WHERE vr.election_id = ? AND vr.registration_status = 'approved'
        `, [electionId]);

        // Get voting method distribution
        const [votingMethods] = await pool.promise().query(`
            SELECT 
                voting_method,
                COUNT(*) as count,
                ROUND((COUNT(*) * 100.0) / NULLIF((
                    SELECT COUNT(*) FROM votes WHERE election_id = ?
                ), 0), 2) as percentage
            FROM votes
            WHERE election_id = ?
            GROUP BY voting_method
        `, [electionId, electionId]);

        // Generate report record
        const reportName = `${election[0].election_name} - Results Report`;
        const [reportResult] = await pool.promise().query(
            `INSERT INTO reports (
                report_name,
                report_type,
                parameters,
                generated_by,
                file_path,
                report_period_start,
                report_period_end
            ) VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [
                reportName,
                'election_results',
                JSON.stringify({ election_id: electionId, format: 'json' }),
                req.user.userId,
                `/reports/election_${electionId}_results_${Date.now()}.json`,
                election[0].start_date,
                new Date()
            ]
        );

        // Log admin action
        await pool.promise().query(
            `INSERT INTO admin_actions (
                admin_id,
                action_type,
                action_details,
                affected_entity_type,
                affected_entity_id,
                ip_address,
                user_agent
            ) VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [
                req.user.userId,
                'generate_report',
                `Generated report: ${reportName}`,
                'reports',
                reportResult.insertId,
                req.ip,
                req.headers['user-agent']
            ]
        );

        res.json({
            success: true,
            report: {
                election: election[0],
                results,
                statistics: {
                    turnout: turnout[0],
                    votingMethods
                },
                generatedAt: new Date().toISOString(),
                reportId: reportResult.insertId
            }
        });
    } catch (error) {
        console.error('Generate results report error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to generate election results report' 
        });
    }
});

// 17. Get System Reports List
app.get('/api/admin/reports', authenticateToken, authorizeRoles('admin'), async (req, res) => {
    try {
        const [reports] = await pool.promise().query(`
            SELECT 
                r.*,
                u.username as generated_by_username,
                u.full_name as generated_by_name
            FROM reports r
            LEFT JOIN users u ON r.generated_by = u.user_id
            ORDER BY r.generated_at DESC
        `);

        res.json({
            success: true,
            reports
        });
    } catch (error) {
        console.error('Get reports error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to fetch reports' 
        });
    }
});

// ============================================
// ADMIN SYSTEM SETTINGS API ROUTES
// ============================================

// 18. Get System Settings
app.get('/api/admin/settings', authenticateToken, authorizeRoles('admin'), async (req, res) => {
    try {
        const [settings] = await pool.promise().query(`
            SELECT * FROM system_settings 
            ORDER BY category, setting_key
        `);

        // Group settings by category
        const groupedSettings = settings.reduce((acc, setting) => {
            const category = setting.category || 'general';
            if (!acc[category]) {
                acc[category] = [];
            }
            
            // Parse JSON/Array settings
            if (setting.setting_type === 'json' && setting.setting_value) {
                setting.parsed_value = JSON.parse(setting.setting_value);
            } else if (setting.setting_type === 'array' && setting.setting_value) {
                setting.parsed_value = setting.setting_value.split(',');
            } else if (setting.setting_type === 'boolean') {
                setting.parsed_value = setting.setting_value === 'true' || setting.setting_value === '1';
            } else if (setting.setting_type === 'integer') {
                setting.parsed_value = parseInt(setting.setting_value);
            } else {
                setting.parsed_value = setting.setting_value;
            }
            
            acc[category].push(setting);
            return acc;
        }, {});

        res.json({
            success: true,
            settings: groupedSettings
        });
    } catch (error) {
        console.error('Get settings error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to fetch system settings' 
        });
    }
});

// 19. Update System Settings
app.put('/api/admin/settings/:key', authenticateToken, authorizeRoles('admin'), async (req, res) => {
    const settingKey = req.params.key;
    const { settingValue } = req.body;

    try {
        // Get current setting
        const [currentSetting] = await pool.promise().query(
            'SELECT * FROM system_settings WHERE setting_key = ?',
            [settingKey]
        );

        if (currentSetting.length === 0) {
            return res.status(404).json({ 
                success: false, 
                error: 'Setting not found' 
            });
        }

        const setting = currentSetting[0];
        let formattedValue = settingValue;

        // Format value based on type
        switch (setting.setting_type) {
            case 'json':
                formattedValue = JSON.stringify(settingValue);
                break;
            case 'array':
                formattedValue = Array.isArray(settingValue) ? 
                    settingValue.join(',') : String(settingValue);
                break;
            case 'boolean':
                formattedValue = settingValue ? 'true' : 'false';
                break;
            case 'integer':
                formattedValue = String(parseInt(settingValue));
                break;
            default:
                formattedValue = String(settingValue);
        }

        // Update setting
        await pool.promise().query(
            `UPDATE system_settings 
             SET setting_value = ?, updated_at = CURRENT_TIMESTAMP
             WHERE setting_key = ?`,
            [formattedValue, settingKey]
        );

        // Log admin action
        await pool.promise().query(
            `INSERT INTO admin_actions (
                admin_id,
                action_type,
                action_details,
                affected_entity_type,
                affected_entity_id,
                ip_address,
                user_agent
            ) VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [
                req.user.userId,
                'update_settings',
                `Updated system setting: ${settingKey}`,
                'system_settings',
                setting.setting_id,
                req.ip,
                req.headers['user-agent']
            ]
        );

        res.json({
            success: true,
            message: 'Setting updated successfully'
        });
    } catch (error) {
        console.error('Update setting error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to update setting' 
        });
    }
});

// ============================================
// ADMIN NOTIFICATIONS API ROUTES
// ============================================

// 20. Get Admin Notifications
app.get('/api/admin/notifications', authenticateToken, authorizeRoles('admin'), async (req, res) => {
    try {
        const { unreadOnly } = req.query;
        
        let query = `
            SELECT * FROM notifications 
            WHERE user_id = ?
        `;
        
        const params = [req.user.userId];
        
        if (unreadOnly === 'true') {
            query += ' AND is_read = FALSE';
        }
        
        query += ' ORDER BY created_at DESC LIMIT 50';
        
        const [notifications] = await pool.promise().query(query, params);

        res.json({
            success: true,
            notifications
        });
    } catch (error) {
        console.error('Get notifications error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to fetch notifications' 
        });
    }
});

// 21. Mark Notification as Read
app.put('/api/admin/notifications/:id/read', authenticateToken, authorizeRoles('admin'), async (req, res) => {
    const notificationId = req.params.id;

    try {
        await pool.promise().query(
            `UPDATE notifications 
             SET is_read = TRUE, read_at = CURRENT_TIMESTAMP
             WHERE notification_id = ? AND user_id = ?`,
            [notificationId, req.user.userId]
        );

        res.json({
            success: true,
            message: 'Notification marked as read'
        });
    } catch (error) {
        console.error('Mark notification read error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to update notification' 
        });
    }
});

// 22. Mark All Notifications as Read
app.put('/api/admin/notifications/mark-all-read', authenticateToken, authorizeRoles('admin'), async (req, res) => {
    try {
        await pool.promise().query(
            `UPDATE notifications 
             SET is_read = TRUE, read_at = CURRENT_TIMESTAMP
             WHERE user_id = ? AND is_read = FALSE`,
            [req.user.userId]
        );

        res.json({
            success: true,
            message: 'All notifications marked as read'
        });
    } catch (error) {
        console.error('Mark all notifications read error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to update notifications' 
        });
    }
});

// ============================================
// ADMIN AUDIT LOGS API ROUTES
// ============================================

// 23. Get Audit Logs
app.get('/api/admin/audit-logs', authenticateToken, authorizeRoles('admin'), async (req, res) => {
    try {
        const { actionType, tableName, startDate, endDate, limit = 100 } = req.query;
        
        let query = `
            SELECT 
                al.*,
                u.username as user_username,
                u.full_name as user_full_name
            FROM audit_logs al
            LEFT JOIN users u ON al.user_id = u.user_id
        `;
        
        const params = [];
        const conditions = [];
        
        if (actionType && actionType !== 'all') {
            conditions.push('al.action_type = ?');
            params.push(actionType);
        }
        
        if (tableName && tableName !== 'all') {
            conditions.push('al.table_name = ?');
            params.push(tableName);
        }
        
        if (startDate) {
            conditions.push('al.created_at >= ?');
            params.push(startDate);
        }
        
        if (endDate) {
            conditions.push('al.created_at <= ?');
            params.push(endDate);
        }
        
        if (conditions.length > 0) {
            query += ' WHERE ' + conditions.join(' AND ');
        }
        
        query += ' ORDER BY al.created_at DESC LIMIT ?';
        params.push(parseInt(limit));
        
        const [logs] = await pool.promise().query(query, params);

        res.json({
            success: true,
            logs
        });
    } catch (error) {
        console.error('Get audit logs error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to fetch audit logs' 
        });
    }
});

// 24. Get Security Logs
app.get('/api/admin/security-logs', authenticateToken, authorizeRoles('admin'), async (req, res) => {
    try {
        const { severity, resolved, startDate, endDate, limit = 100 } = req.query;
        
        let query = `
            SELECT 
                sl.*,
                u.username as user_username,
                u.full_name as user_full_name,
                r.username as resolved_by_username
            FROM security_logs sl
            LEFT JOIN users u ON sl.user_id = u.user_id
            LEFT JOIN users r ON sl.resolved_by = r.user_id
        `;
        
        const params = [];
        const conditions = [];
        
        if (severity && severity !== 'all') {
            conditions.push('sl.severity = ?');
            params.push(severity);
        }
        
        if (resolved !== undefined) {
            conditions.push('sl.resolved = ?');
            params.push(resolved === 'true' ? 1 : 0);
        }
        
        if (startDate) {
            conditions.push('sl.created_at >= ?');
            params.push(startDate);
        }
        
        if (endDate) {
            conditions.push('sl.created_at <= ?');
            params.push(endDate);
        }
        
        if (conditions.length > 0) {
            query += ' WHERE ' + conditions.join(' AND ');
        }
        
        query += ' ORDER BY sl.created_at DESC LIMIT ?';
        params.push(parseInt(limit));
        
        const [logs] = await pool.promise().query(query, params);

        res.json({
            success: true,
            logs
        });
    } catch (error) {
        console.error('Get security logs error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to fetch security logs' 
        });
    }
});

// ============================================
// ADMIN UTILITY API ROUTES
// ============================================

// 25. Get Positions for Election
app.get('/api/admin/elections/:id/positions', authenticateToken, authorizeRoles('admin'), async (req, res) => {
    const electionId = req.params.id;

    try {
        const [positions] = await pool.promise().query(
            `SELECT * FROM positions 
             WHERE election_id = ? 
             ORDER BY sort_order`,
            [electionId]
        );

        res.json({
            success: true,
            positions
        });
    } catch (error) {
        console.error('Get positions error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to fetch positions' 
        });
    }
});

// 26. Get Admin Profile Info
app.get('/api/admin/profile', authenticateToken, authorizeRoles('admin'), async (req, res) => {
    try {
        const [admins] = await pool.promise().query(
            `SELECT 
                user_id,
                username,
                email,
                full_name,
                role,
                registration_date,
                last_login,
                profile_picture,
                phone_number,
                address
             FROM users 
             WHERE user_id = ?`,
            [req.user.userId]
        );

        if (admins.length === 0) {
            return res.status(404).json({ 
                success: false, 
                error: 'Admin not found' 
            });
        }

        res.json({
            success: true,
            admin: admins[0]
        });
    } catch (error) {
        console.error('Get admin profile error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to fetch admin profile' 
        });
    }
});

// 27. Update Admin Profile
app.put('/api/admin/profile', authenticateToken, authorizeRoles('admin'), [
    body('fullName').optional().trim().notEmpty().withMessage('Full name cannot be empty'),
    body('email').optional().isEmail().withMessage('Valid email is required'),
    body('phoneNumber').optional().trim(),
    body('address').optional().trim()
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ 
            success: false, 
            errors: errors.array() 
        });
    }

    const { fullName, email, phoneNumber, address } = req.body;

    try {
        const updates = {};
        const values = [];

        if (fullName) {
            updates.full_name = fullName;
            values.push(fullName);
        }

        if (email) {
            // Check if email is already taken by another user
            const [existing] = await pool.promise().query(
                'SELECT user_id FROM users WHERE email = ? AND user_id != ?',
                [email, req.user.userId]
            );

            if (existing.length > 0) {
                return res.status(409).json({ 
                    success: false, 
                    error: 'Email already taken' 
                });
            }

            updates.email = email;
            values.push(email);
        }

        if (phoneNumber !== undefined) {
            updates.phone_number = phoneNumber;
            values.push(phoneNumber);
        }

        if (address !== undefined) {
            updates.address = address;
            values.push(address);
        }

        if (Object.keys(updates).length === 0) {
            return res.status(400).json({ 
                success: false, 
                error: 'No updates provided' 
            });
        }

        const setClause = Object.keys(updates).map(key => `${key} = ?`).join(', ');
        values.push(req.user.userId);

        await pool.promise().query(
            `UPDATE users 
             SET ${setClause}, updated_at = CURRENT_TIMESTAMP
             WHERE user_id = ?`,
            values
        );

        res.json({
            success: true,
            message: 'Profile updated successfully'
        });
    } catch (error) {
        console.error('Update admin profile error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to update profile' 
        });
    }
});

// ============================================
// SYSTEM HEALTH AND INFO
// ============================================

// 28. System Health Check
app.get('/api/admin/health', authenticateToken, authorizeRoles('admin'), async (req, res) => {
    try {
        // Test database connection
        const [dbResult] = await pool.promise().query('SELECT 1 as status');
        
        // Get system statistics
        const [systemStats] = await pool.promise().query(`
            SELECT 
                'active_elections' as metric, COUNT(*) as value FROM elections WHERE status = 'active'
            UNION ALL
            SELECT 'total_voters', COUNT(*) FROM users WHERE role = 'voter'
            UNION ALL
            SELECT 'total_candidates', COUNT(*) FROM candidates
            UNION ALL
            SELECT 'pending_registrations', COUNT(*) FROM voter_registrations WHERE registration_status = 'pending'
            UNION ALL
            SELECT 'pending_candidates', COUNT(*) FROM candidates WHERE is_approved = 0
        `);

        const stats = systemStats.reduce((acc, row) => {
            acc[row.metric] = row.value;
            return acc;
        }, {});

        res.json({
            status: 'OK',
            timestamp: new Date().toISOString(),
            database: dbResult[0].status === 1 ? 'connected' : 'disconnected',
            uptime: process.uptime(),
            memory: process.memoryUsage(),
            statistics: stats
        });
    } catch (error) {
        console.error('Health check error:', error);
        res.status(500).json({ 
            status: 'ERROR',
            timestamp: new Date().toISOString(),
            error: error.message 
        });
    }
});

// ============================================
// ERROR HANDLING
// ============================================

// 404 Handler
app.use((req, res) => {
    res.status(404).json({
        success: false,
        error: 'Endpoint not found',
        path: req.path,
        method: req.method
    });
});

// Global error handler
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);

    res.status(500).json({
        success: false,
        error: 'Internal server error',
        message: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
});

// ============================================
// SERVER STARTUP
// ============================================

const PORT = process.env.PORT || 5000;
const HOST = process.env.HOST || '0.0.0.0';

app.listen(PORT, HOST, () => {
    console.log(`Voting System Admin API Server running on http://${HOST}:${PORT}`);
    console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`Database: ${process.env.DB_NAME || 'voting_system'}`);
    console.log(`Frontend URL: ${process.env.FRONTEND_URL || 'http://localhost:3000'}`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('SIGTERM signal received: closing HTTP server');
    pool.end(() => {
        console.log('Database connections closed');
        process.exit(0);
    });
});

process.on('SIGINT', () => {
    console.log('SIGINT signal received: closing HTTP server');
    pool.end(() => {
        console.log('Database connections closed');
        process.exit(0);
    });

});
