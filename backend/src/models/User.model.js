const db = require('../config/database');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

class User {
    static async create(userData) {
        const connection = await db.getConnection();
        try {
            await connection.beginTransaction();
            
            // Generate unique ID if not provided
            const userId = userData.id || crypto.randomUUID();
            
            // Generate username from first and last name if not provided
            let username = userData.username;
            if (!username) {
                const baseUsername = `${userData.first_name.toLowerCase()}.${userData.last_name.toLowerCase()}`;
                username = await this.generateUniqueUsername(baseUsername);
            }
            
            // Hash password
            const salt = await bcrypt.genSalt(parseInt(process.env.SALT_ROUNDS));
            const passwordHash = await bcrypt.hash(userData.password, salt);
            
            // Generate verification token
            const verificationToken = crypto.randomBytes(32).toString('hex');
            const verificationExpires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours
            
            const [result] = await connection.execute(
                `INSERT INTO users (
                    id, first_name, last_name, username, email, password_hash,
                    verification_token, verification_expires, language
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [
                    userId, userData.first_name, userData.last_name, username,
                    userData.email, passwordHash, verificationToken,
                    verificationExpires, userData.language || 'en'
                ]
            );
            
            await connection.commit();
            
            return {
                id: userId,
                username,
                email: userData.email,
                verificationToken
            };
        } catch (error) {
            await connection.rollback();
            throw error;
        } finally {
            connection.release();
        }
    }
    
    static async generateUniqueUsername(baseUsername) {
        const connection = await db.getConnection();
        try {
            let username = baseUsername;
            let counter = 1;
            
            while (true) {
                const [rows] = await connection.execute(
                    'SELECT id FROM users WHERE username = ?',
                    [username]
                );
                
                if (rows.length === 0) {
                    return username;
                }
                
                username = `${baseUsername}${counter}`;
                counter++;
                
                // Safety break
                if (counter > 1000) {
                    throw new Error('Could not generate unique username');
                }
            }
        } finally {
            connection.release();
        }
    }
    
    static async findByEmail(email) {
        const connection = await db.getConnection();
        try {
            const [rows] = await connection.execute(
                'SELECT * FROM users WHERE email = ?',
                [email]
            );
            return rows[0] || null;
        } finally {
            connection.release();
        }
    }
    
    static async findById(id) {
        const connection = await db.getConnection();
        try {
            const [rows] = await connection.execute(
                'SELECT id, first_name, last_name, username, email, email_verified, subscription_type, language, created_at FROM users WHERE id = ?',
                [id]
            );
            return rows[0] || null;
        } finally {
            connection.release();
        }
    }
    
    static async verifyEmail(token) {
        const connection = await db.getConnection();
        try {
            const [rows] = await connection.execute(
                'SELECT id FROM users WHERE verification_token = ? AND verification_expires > NOW()',
                [token]
            );
            
            if (rows.length === 0) {
                return false;
            }
            
            await connection.execute(
                'UPDATE users SET email_verified = TRUE, verification_token = NULL, verification_expires = NULL WHERE id = ?',
                [rows[0].id]
            );
            
            return true;
        } finally {
            connection.release();
        }
    }
    
    static async updatePassword(userId, newPassword) {
        const connection = await db.getConnection();
        try {
            const salt = await bcrypt.genSalt(parseInt(process.env.SALT_ROUNDS));
            const passwordHash = await bcrypt.hash(newPassword, salt);
            
            await connection.execute(
                'UPDATE users SET password_hash = ? WHERE id = ?',
                [passwordHash, userId]
            );
            
            return true;
        } finally {
            connection.release();
        }
    }
    
    static async comparePassword(password, hash) {
        return await bcrypt.compare(password, hash);
    }
    
    static async updateLanguage(userId, language) {
        const connection = await db.getConnection();
        try {
            await connection.execute(
                'UPDATE users SET language = ? WHERE id = ?',
                [language, userId]
            );
            return true;
        } finally {
            connection.release();
        }
    }
    
    static async incrementMessages(userId, count = 1) {
        const connection = await db.getConnection();
        try {
            await connection.execute(
                'UPDATE users SET messages_used = messages_used + ? WHERE id = ?',
                [count, userId]
            );
            
            // Get updated count
            const [rows] = await connection.execute(
                'SELECT messages_used FROM users WHERE id = ?',
                [userId]
            );
            
            return rows[0].messages_used;
        } finally {
            connection.release();
        }
    }
    
    static async incrementAdsWatched(userId) {
        const connection = await db.getConnection();
        try {
            await connection.execute(
                'UPDATE users SET ads_watched = ads_watched + 1 WHERE id = ?',
                [userId]
            );
            
            // Get updated count
            const [rows] = await connection.execute(
                'SELECT ads_watched FROM users WHERE id = ?',
                [userId]
            );
            
            return rows[0].ads_watched;
        } finally {
            connection.release();
        }
    }
    
    static async getAllUsers(page = 1, limit = 20) {
        const connection = await db.getConnection();
        try {
            const offset = (page - 1) * limit;
            
            const [rows] = await connection.execute(
                `SELECT 
                    id, first_name, last_name, username, email, email_verified,
                    subscription_type, subscription_expires, messages_used,
                    ads_watched, language, is_banned, created_at
                FROM users 
                ORDER BY created_at DESC 
                LIMIT ? OFFSET ?`,
                [limit, offset]
            );
            
            const [countRows] = await connection.execute(
                'SELECT COUNT(*) as total FROM users'
            );
            
            return {
                users: rows,
                total: countRows[0].total,
                page,
                limit
            };
        } finally {
            connection.release();
        }
    }
    
    static async updateSubscription(userId, subscriptionType, expiresAt) {
        const connection = await db.getConnection();
        try {
            await connection.execute(
                'UPDATE users SET subscription_type = ?, subscription_expires = ? WHERE id = ?',
                [subscriptionType, expiresAt, userId]
            );
            return true;
        } finally {
            connection.release();
        }
    }
    
    static async banUser(userId, reason) {
        const connection = await db.getConnection();
        try {
            await connection.execute(
                'UPDATE users SET is_banned = TRUE, banned_reason = ? WHERE id = ?',
                [reason, userId]
            );
            return true;
        } finally {
            connection.release();
        }
    }
    
    static async unbanUser(userId) {
        const connection = await db.getConnection();
        try {
            await connection.execute(
                'UPDATE users SET is_banned = FALSE, banned_reason = NULL WHERE id = ?',
                [userId]
            );
            return true;
        } finally {
            connection.release();
        }
    }
}

module.exports = User;
