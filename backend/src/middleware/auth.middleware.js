const jwt = require('jsonwebtoken');
const User = require('../models/User.model');

const authMiddleware = {
    // Verify JWT token
    verifyToken: (req, res, next) => {
        try {
            const token = req.header('Authorization')?.replace('Bearer ', '');
            
            if (!token) {
                return res.status(401).json({
                    success: false,
                    message: 'Access denied. No token provided.'
                });
            }
            
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            req.userId = decoded.userId;
            req.userRole = decoded.role;
            next();
        } catch (error) {
            return res.status(401).json({
                success: false,
                message: 'Invalid or expired token.'
            });
        }
    },
    
    // Check if user is admin
    isAdmin: (req, res, next) => {
        if (req.userRole !== 'admin') {
            return res.status(403).json({
                success: false,
                message: 'Access denied. Admin privileges required.'
            });
        }
        next();
    },
    
    // Check if user is verified
    isVerified: async (req, res, next) => {
        try {
            const user = await User.findById(req.userId);
            
            if (!user) {
                return res.status(404).json({
                    success: false,
                    message: 'User not found.'
                });
            }
            
            if (!user.email_verified) {
                return res.status(403).json({
                    success: false,
                    message: 'Please verify your email first.'
                });
            }
            
            next();
        } catch (error) {
            res.status(500).json({
                success: false,
                message: 'Server error'
            });
        }
    },
    
    // Check if user is banned
    checkBanned: async (req, res, next) => {
        try {
            const connection = await require('../config/database').getConnection();
            const [rows] = await connection.execute(
                'SELECT is_banned, banned_reason FROM users WHERE id = ?',
                [req.userId]
            );
            connection.release();
            
            if (rows[0]?.is_banned) {
                return res.status(403).json({
                    success: false,
                    message: 'Your account has been banned.',
                    reason: rows[0].banned_reason
                });
            }
            
            next();
        } catch (error) {
            res.status(500).json({
                success: false,
                message: 'Server error'
            });
        }
    },
    
    // Rate limiting per user
    userRateLimit: (maxRequests, windowMs) => {
        const requests = new Map();
        
        return (req, res, next) => {
            const userId = req.userId;
            const now = Date.now();
            
            if (!requests.has(userId)) {
                requests.set(userId, []);
            }
            
            const userRequests = requests.get(userId);
            const windowStart = now - windowMs;
            
            // Remove old requests
            while (userRequests.length > 0 && userRequests[0] < windowStart) {
                userRequests.shift();
            }
            
            if (userRequests.length >= maxRequests) {
                return res.status(429).json({
                    success: false,
                    message: 'Too many requests. Please try again later.'
                });
            }
            
            userRequests.push(now);
            next();
        };
    }
};

module.exports = authMiddleware;
