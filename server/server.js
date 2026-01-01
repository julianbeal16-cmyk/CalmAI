// server.js - CalmAI Complete Server
const express = require('express');
const https = require('https');
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const { Sequelize, DataTypes, Op } = require('sequelize');
const { OpenAI } = require('openai');
const axios = require('axios');
const WebSocket = require('ws');

class CalmAIServer {
    constructor() {
        this.app = express();
        this.server = null;
        this.wss = null;
        this.sequelize = null;
        this.openai = null;
        
        // AI Models configuration
        this.aiModels = {
            'gpt-4': null,
            'llama-3': null,
            'claude-3': null
        };
        
        // Verification codes storage (in production use Redis)
        this.verificationCodes = new Map();
        
        // Initialize
        this.init();
    }

    async init() {
        try {
            // 1. Create required directories
            this.createDirectories();
            
            // 2. Setup security
            this.setupSecurity();
            
            // 3. Connect to database
            await this.setupDatabase();
            
            // 4. Setup AI models (if API keys available)
            await this.setupAIModels();
            
            // 5. Setup middleware
            this.setupMiddleware();
            
            // 6. Setup routes
            this.setupRoutes();
            
            // 7. Setup WebSocket
            this.setupWebSocket();
            
            // 8. Start server
            this.startServer();
            
        } catch (error) {
            console.error('Initialization failed:', error);
            process.exit(1);
        }
    }

    createDirectories() {
        const dirs = ['public', 'database', 'ssl'];
        dirs.forEach(dir => {
            const dirPath = path.join(__dirname, dir);
            if (!fs.existsSync(dirPath)) {
                fs.mkdirSync(dirPath, { recursive: true });
            }
        });
        
        // Create SSL certificates if they don't exist
        const keyPath = path.join(__dirname, 'ssl/key.pem');
        const certPath = path.join(__dirname, 'ssl/cert.pem');
        
        if (!fs.existsSync(keyPath) || !fs.existsSync(certPath)) {
            console.log('Generating self-signed SSL certificates...');
            const selfsigned = require('selfsigned');
            const attrs = [{ name: 'commonName', value: 'localhost' }];
            const pems = selfsigned.generate(attrs, { days: 365 });
            
            fs.writeFileSync(keyPath, pems.private);
            fs.writeFileSync(certPath, pems.cert);
            console.log('SSL certificates generated successfully');
        }
    }

    setupSecurity() {
        // SSL options
        this.sslOptions = {
            key: fs.readFileSync(path.join(__dirname, 'ssl/key.pem')),
            cert: fs.readFileSync(path.join(__dirname, 'ssl/cert.pem'))
        };

        // Helmet security headers
        this.app.use(helmet({
            contentSecurityPolicy: {
                directives: {
                    defaultSrc: ["'self'"],
                    styleSrc: ["'self'", "'unsafe-inline'"],
                    scriptSrc: ["'self'", "'unsafe-inline'"],
                    imgSrc: ["'self'", "data:", "https:"],
                    connectSrc: ["'self'", "ws:", "wss:"]
                }
            },
            hsts: {
                maxAge: 31536000,
                includeSubDomains: true,
                preload: true
            }
        }));

        // Rate limiting
        const limiter = rateLimit({
            windowMs: 15 * 60 * 1000,
            max: 100,
            message: { error: 'Too many requests, please try again later.' },
            standardHeaders: true,
            legacyHeaders: false
        });

        this.app.use('/api/', limiter);

        // CORS
        this.app.use(cors({
            origin: ['http://localhost:3000', 'https://localhost:3000'],
            credentials: true
        }));
    }

    async setupDatabase() {
        // Database connection
        this.sequelize = new Sequelize({
            dialect: 'sqlite',
            storage: path.join(__dirname, 'database/calmai.db'),
            logging: false
        });

        // Define models
        this.models = {
            User: this.sequelize.define('User', {
                id: {
                    type: DataTypes.UUID,
                    defaultValue: DataTypes.UUIDV4,
                    primaryKey: true
                },
                username: {
                    type: DataTypes.STRING,
                    unique: true,
                    allowNull: false
                },
                email: {
                    type: DataTypes.STRING,
                    unique: true,
                    allowNull: false,
                    validate: {
                        isEmail: true
                    }
                },
                password_hash: {
                    type: DataTypes.STRING,
                    allowNull: false
                },
                salt: {
                    type: DataTypes.STRING,
                    allowNull: false
                },
                first_name: DataTypes.STRING,
                last_name: DataTypes.STRING,
                gender: DataTypes.ENUM('male', 'female'),
                birth_year: DataTypes.INTEGER,
                user_id: {
                    type: DataTypes.STRING,
                    unique: true,
                    defaultValue: () => `CAI-${Date.now().toString().slice(-6)}`
                },
                subscription_type: {
                    type: DataTypes.ENUM('free', 'premium', 'pro'),
                    defaultValue: 'free'
                },
                free_messages_used: {
                    type: DataTypes.INTEGER,
                    defaultValue: 0
                },
                ads_watched: {
                    type: DataTypes.INTEGER,
                    defaultValue: 0
                },
                last_login: DataTypes.DATE,
                is_active: {
                    type: DataTypes.BOOLEAN,
                    defaultValue: false
                },
                is_banned: {
                    type: DataTypes.BOOLEAN,
                    defaultValue: false
                },
                security_token: DataTypes.STRING
            }, {
                hooks: {
                    beforeCreate: async (user) => {
                        user.security_token = crypto.randomBytes(32).toString('hex');
                    }
                }
            }),

            Admin: this.sequelize.define('Admin', {
                id: {
                    type: DataTypes.UUID,
                    defaultValue: DataTypes.UUIDV4,
                    primaryKey: true
                },
                username: {
                    type: DataTypes.STRING,
                    unique: true,
                    allowNull: false
                },
                password_hash: DataTypes.STRING,
                salt: DataTypes.STRING,
                email: DataTypes.STRING,
                permissions: {
                    type: DataTypes.JSON,
                    defaultValue: {
                        users: true,
                        content: true,
                        ai: true,
                        payments: true,
                        settings: true
                    }
                },
                two_factor_enabled: {
                    type: DataTypes.BOOLEAN,
                    defaultValue: false
                }
            }),

            Content: this.sequelize.define('Content', {
                id: {
                    type: DataTypes.UUID,
                    defaultValue: DataTypes.UUIDV4,
                    primaryKey: true
                },
                type: DataTypes.ENUM('music', 'exercise', 'game', 'meditation'),
                title_ar: DataTypes.STRING,
                title_en: DataTypes.STRING,
                description_ar: DataTypes.TEXT,
                description_en: DataTypes.TEXT,
                category: DataTypes.STRING,
                duration: DataTypes.INTEGER,
                url: DataTypes.STRING,
                thumbnail_url: DataTypes.STRING,
                is_active: {
                    type: DataTypes.BOOLEAN,
                    defaultValue: true
                },
                access_level: {
                    type: DataTypes.ENUM('free', 'premium', 'all'),
                    defaultValue: 'all'
                }
            }),

            ChatSession: this.sequelize.define('ChatSession', {
                id: {
                    type: DataTypes.UUID,
                    defaultValue: DataTypes.UUIDV4,
                    primaryKey: true
                },
                user_id: DataTypes.UUID,
                ai_model: DataTypes.STRING,
                messages: {
                    type: DataTypes.JSON,
                    defaultValue: []
                },
                is_encrypted: {
                    type: DataTypes.BOOLEAN,
                    defaultValue: false
                },
                sentiment_score: DataTypes.FLOAT,
                warning_flags: DataTypes.JSON
            }),

            Subscription: this.sequelize.define('Subscription', {
                id: {
                    type: DataTypes.UUID,
                    defaultValue: DataTypes.UUIDV4,
                    primaryKey: true
                },
                user_id: DataTypes.UUID,
                plan: DataTypes.STRING,
                price: DataTypes.FLOAT,
                currency: DataTypes.STRING,
                start_date: DataTypes.DATE,
                end_date: DataTypes.DATE,
                status: DataTypes.ENUM('active', 'expired', 'cancelled'),
                payment_method: DataTypes.STRING,
                transaction_id: DataTypes.STRING
            }),

            SecurityLog: this.sequelize.define('SecurityLog', {
                id: {
                    type: DataTypes.UUID,
                    defaultValue: DataTypes.UUIDV4,
                    primaryKey: true
                },
                event_type: DataTypes.STRING,
                user_id: DataTypes.UUID,
                ip_address: DataTypes.STRING,
                user_agent: DataTypes.TEXT,
                details: DataTypes.JSON,
                severity: DataTypes.ENUM('low', 'medium', 'high', 'critical')
            }),

            BannedPhrase: this.sequelize.define('BannedPhrase', {
                id: {
                    type: DataTypes.UUID,
                    defaultValue: DataTypes.UUIDV4,
                    primaryKey: true
                },
                phrase: DataTypes.STRING,
                language: DataTypes.ENUM('ar', 'en', 'both'),
                severity: DataTypes.ENUM('low', 'medium', 'high'),
                action: DataTypes.ENUM('warn', 'block', 'alert')
            })
        };

        // Create tables
        await this.sequelize.sync({ force: false });
        console.log('✅ Database connected and synchronized');
    }

    async setupAIModels() {
        // Setup OpenAI if API key is available
        if (process.env.OPENAI_API_KEY && process.env.OPENAI_API_KEY.startsWith('sk-')) {
            this.openai = new OpenAI({
                apiKey: process.env.OPENAI_API_KEY
            });
            this.aiModels['gpt-4'] = this.openai;
            console.log('✅ OpenAI GPT-4 model initialized');
        } else {
            console.log('⚠️ OpenAI API key not found, using simulated AI responses');
            // Simulated AI for development
            this.aiModels['gpt-4'] = {
                chat: {
                    completions: {
                        create: async (params) => {
                            return {
                                choices: [{
                                    message: {
                                        content: "Hello! I'm your CalmAI assistant. How can I help you today? This is a simulated response since OpenAI API key is not configured."
                                    }
                                }]
                            };
                        }
                    }
                }
            };
        }
    }

    setupMiddleware() {
        // Body parser
        this.app.use(express.json({ limit: '10mb' }));
        this.app.use(express.urlencoded({ extended: true, limit: '10mb' }));
        
        // Serve static files
        this.app.use(express.static(path.join(__dirname, 'public')));
        
        // Request logger
        this.app.use((req, res, next) => {
            console.log(`${new Date().toISOString()} ${req.method} ${req.url}`);
            next();
        });
    }

    setupRoutes() {
        // Test route
        this.app.get('/api/test', (req, res) => {
            res.json({ 
                status: 'online', 
                message: 'CalmAI Server is running',
                timestamp: new Date().toISOString()
            });
        });

        // Auth routes
        this.app.post('/api/auth/signup', [
            body('email').isEmail().normalizeEmail(),
            body('password').isLength({ min: 8 }),
            body('first_name').trim().notEmpty(),
            body('last_name').trim().notEmpty()
        ], this.signup.bind(this));

        this.app.post('/api/auth/login', [
            body('email').isEmail().normalizeEmail(),
            body('password').notEmpty()
        ], this.login.bind(this));

        this.app.post('/api/auth/verify', this.verifyEmail.bind(this));
        this.app.post('/api/auth/resend-code', this.resendCode.bind(this));
        this.app.post('/api/auth/reset-password', this.resetPassword.bind(this));
        this.app.get('/api/auth/verify-token', this.verifyToken.bind(this));

        // User routes
        this.app.get('/api/user/me', this.authenticateToken.bind(this), this.getUserProfile.bind(this));
        this.app.get('/api/user/stats', this.authenticateToken.bind(this), this.getUserStats.bind(this));
        this.app.post('/api/user/mood', this.authenticateToken.bind(this), this.saveMood.bind(this));

        // AI Chat routes
        this.app.post('/api/ai/chat', this.authenticateToken.bind(this), [
            body('message').trim().notEmpty()
        ], this.chatWithAI.bind(this));
        
        this.app.get('/api/ai/chat-sessions', this.authenticateToken.bind(this), this.getChatSessions.bind(this));
        this.app.get('/api/ai/chat-sessions/:id', this.authenticateToken.bind(this), this.getChatSession.bind(this));

        // Content routes
        this.app.get('/api/content/:type', this.authenticateToken.bind(this), this.getContent.bind(this));

        // Subscription routes
        this.app.get('/api/payment/plans', this.authenticateToken.bind(this), this.getSubscriptionPlans.bind(this));
        this.app.post('/api/payment/create-subscription', this.authenticateToken.bind(this), this.createSubscription.bind(this));

        // Admin routes
        this.app.post('/api/admin/login', this.adminLogin.bind(this));
        this.app.get('/api/admin/users', this.authenticateAdmin.bind(this), this.getUsers.bind(this));
        this.app.get('/api/admin/stats', this.authenticateAdmin.bind(this), this.getAdminStats.bind(this));
        this.app.post('/api/admin/ban-user/:id', this.authenticateAdmin.bind(this), this.banUser.bind(this));
        this.app.post('/api/admin/send-notification', this.authenticateAdmin.bind(this), this.sendNotification.bind(this));
        this.app.get('/api/admin/activity', this.authenticateAdmin.bind(this), this.getActivityLogs.bind(this));
        
        // Banned phrases
        this.app.get('/api/admin/banned-phrases', this.authenticateAdmin.bind(this), this.getBannedPhrases.bind(this));
        this.app.post('/api/admin/banned-phrases', this.authenticateAdmin.bind(this), this.addBannedPhrase.bind(this));
        this.app.delete('/api/admin/banned-phrases/:id', this.authenticateAdmin.bind(this), this.deleteBannedPhrase.bind(this));

        // Serve HTML pages
        this.app.get('/', (req, res) => {
            res.sendFile(path.join(__dirname, 'public/index.html'));
        });

        this.app.get('/signup', (req, res) => {
            res.sendFile(path.join(__dirname, 'public/signup.html'));
        });

        this.app.get('/login', (req, res) => {
            res.sendFile(path.join(__dirname, 'public/login.html'));
        });

        this.app.get('/dashboard', (req, res) => {
            res.sendFile(path.join(__dirname, 'public/dashboard.html'));
        });

        this.app.get('/admin', (req, res) => {
            res.sendFile(path.join(__dirname, 'public/admin.html'));
        });

        // 404 handler
        this.app.use('*', (req, res) => {
            res.status(404).json({ error: 'Route not found' });
        });

        // Error handler
        this.app.use(this.errorHandler.bind(this));
    }

    setupWebSocket() {
        this.wss = new WebSocket.Server({ noServer: true });

        this.wss.on('connection', (ws) => {
            console.log('New WebSocket connection');
            
            ws.on('message', (message) => {
                try {
                    const data = JSON.parse(message);
                    
                    if (data.type === 'ping') {
                        ws.send(JSON.stringify({ type: 'pong', timestamp: Date.now() }));
                    }
                } catch (error) {
                    console.error('WebSocket message error:', error);
                }
            });
            
            ws.on('close', () => {
                console.log('WebSocket connection closed');
            });
        });
    }

    startServer() {
        const PORT = process.env.PORT || 3000;
        const HOST = process.env.HOST || 'localhost';
        
        if (process.env.ENABLE_SSL === 'true') {
            this.server = https.createServer(this.sslOptions, this.app);
            console.log(`✅ HTTPS Server started on https://${HOST}:${PORT}`);
        } else {
            this.server = http.createServer(this.app);
            console.log(`✅ HTTP Server started on http://${HOST}:${PORT}`);
        }
        
        // Attach WebSocket
        this.server.on('upgrade', (request, socket, head) => {
            this.wss.handleUpgrade(request, socket, head, (ws) => {
                this.wss.emit('connection', ws, request);
            });
        });
        
        this.server.listen(PORT, HOST, () => {
            console.log(`🚀 Server is running`);
            console.log(`📁 Database: ${path.join(__dirname, 'database/calmai.db')}`);
            console.log(`🔐 Security: ${process.env.ENABLE_SSL === 'true' ? 'HTTPS Enabled' : 'HTTP Only'}`);
            console.log(`🤖 AI Models: ${Object.keys(this.aiModels).join(', ')}`);
        });
    }

    // ========== HELPER METHODS ==========

    async generatePasswordHash(password) {
        const salt = await bcrypt.genSalt(12);
        const hash = await bcrypt.hash(password, salt);
        return { hash, salt };
    }

    async verifyPassword(password, hash, salt) {
        const hashedPassword = await bcrypt.hash(password, salt);
        return hashedPassword === hash;
    }

    async authenticateToken(req, res, next) {
        try {
            const authHeader = req.headers['authorization'];
            const token = authHeader && authHeader.split(' ')[1];
            
            if (!token) {
                return res.status(401).json({ error: 'Access token required' });
            }
            
            const decoded = jwt.verify(token, process.env.JWT_SECRET || 'calmai-super-secret-jwt-key-2024-dev-12345');
            const user = await this.models.User.findByPk(decoded.userId);
            
            if (!user || user.is_banned || !user.is_active) {
                return res.status(403).json({ error: 'Invalid or inactive account' });
            }
            
            req.user = user;
            next();
        } catch (error) {
            return res.status(403).json({ error: 'Invalid token' });
        }
    }

    async authenticateAdmin(req, res, next) {
        try {
            const authHeader = req.headers['authorization'];
            const token = authHeader && authHeader.split(' ')[1];
            
            if (!token) {
                return res.status(401).json({ error: 'Admin token required' });
            }
            
            const decoded = jwt.verify(token, process.env.ADMIN_JWT_SECRET || 'calmai-admin-super-secret-2024-dev-67890');
            const admin = await this.models.Admin.findByPk(decoded.adminId);
            
            if (!admin) {
                return res.status(403).json({ error: 'Invalid admin account' });
            }
            
            req.admin = admin;
            next();
        } catch (error) {
            return res.status(403).json({ error: 'Invalid admin token' });
        }
    }

    async logSecurityEvent(eventType, userId, details = {}) {
        try {
            await this.models.SecurityLog.create({
                event_type: eventType,
                user_id: userId,
                ip_address: details.ip || req?.ip || 'unknown',
                user_agent: details.userAgent || req?.headers['user-agent'] || 'unknown',
                details: details,
                severity: details.severity || 'medium'
            });
        } catch (error) {
            console.error('Failed to log security event:', error);
        }
    }

    // ========== AUTH HANDLERS ==========

    async signup(req, res) {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ errors: errors.array() });
            }

            const { email, password, first_name, last_name, birth_year, gender } = req.body;

            // Check if email exists
            const existingUser = await this.models.User.findOne({ where: { email } });
            if (existingUser) {
                return res.status(400).json({ error: 'Email already registered' });
            }

            // Generate username
            const baseUsername = `${first_name.toLowerCase()}_${last_name.toLowerCase()}`;
            let username = baseUsername;
            let counter = 1;

            while (await this.models.User.findOne({ where: { username } })) {
                username = `${baseUsername}${counter}`;
                counter++;
            }

            // Hash password
            const passwordData = await this.generatePasswordHash(password);

            // Create user
            const user = await this.models.User.create({
                username,
                email,
                password_hash: passwordData.hash,
                salt: passwordData.salt,
                first_name,
                last_name,
                birth_year: birth_year || 1990,
                gender: gender || 'male',
                user_id: `CAI-${Date.now().toString().slice(-6)}`
            });

            // Generate verification code
            const verificationCode = Math.floor(100000 + Math.random() * 900000);
            const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes
            
            this.verificationCodes.set(email, {
                code: verificationCode,
                expiresAt,
                userId: user.id
            });

            // Log event
            await this.logSecurityEvent('user_signup', user.id, {
                email,
                ip: req.ip
            });

            // Generate JWT (but user not active yet)
            const token = jwt.sign(
                { userId: user.id, email: user.email },
                process.env.JWT_SECRET || 'calmai-super-secret-jwt-key-2024-dev-12345',
                { expiresIn: '24h' }
            );

            res.status(201).json({
                success: true,
                message: 'Account created. Verification code sent.',
                user: {
                    id: user.id,
                    username: user.username,
                    email: user.email,
                    user_id: user.user_id
                },
                token,
                requires_verification: true,
                verification_code: verificationCode // In production, send via email
            });

        } catch (error) {
            console.error('Signup error:', error);
            res.status(500).json({ error: 'Internal server error' });
        }
    }

    async login(req, res) {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ errors: errors.array() });
            }

            const { email, password } = req.body;

            const user = await this.models.User.findOne({ where: { email } });
            if (!user) {
                await this.logSecurityEvent('login_failed_nonexistent', null, { email, ip: req.ip });
                return res.status(401).json({ error: 'Invalid credentials' });
            }

            if (user.is_banned) {
                await this.logSecurityEvent('login_attempt_banned', user.id, { ip: req.ip });
                return res.status(403).json({ error: 'Account is banned' });
            }

            if (!user.is_active) {
                return res.status(403).json({ 
                    error: 'Account not verified',
                    requires_verification: true 
                });
            }

            const isValid = await this.verifyPassword(password, user.password_hash, user.salt);
            if (!isValid) {
                await this.logSecurityEvent('login_failed_password', user.id, { ip: req.ip });
                return res.status(401).json({ error: 'Invalid credentials' });
            }

            // Update last login
            user.last_login = new Date();
            await user.save();

            // Generate JWT
            const token = jwt.sign(
                { 
                    userId: user.id, 
                    email: user.email,
                    subscription: user.subscription_type
                },
                process.env.JWT_SECRET || 'calmai-super-secret-jwt-key-2024-dev-12345',
                { expiresIn: '7d' }
            );

            await this.logSecurityEvent('login_success', user.id, { ip: req.ip });

            res.json({
                success: true,
                message: 'Login successful',
                user: {
                    id: user.id,
                    username: user.username,
                    email: user.email,
                    user_id: user.user_id,
                    first_name: user.first_name,
                    last_name: user.last_name,
                    subscription_type: user.subscription_type,
                    free_messages_used: user.free_messages_used
                },
                token
            });

        } catch (error) {
            console.error('Login error:', error);
            res.status(500).json({ error: 'Internal server error' });
        }
    }

    async verifyEmail(req, res) {
        try {
            const { email, code } = req.body;
            
            const verificationData = this.verificationCodes.get(email);
            if (!verificationData) {
                return res.status(400).json({ error: 'No verification request found' });
            }

            if (verificationData.expiresAt < new Date()) {
                this.verificationCodes.delete(email);
                return res.status(400).json({ error: 'Verification code expired' });
            }

            if (verificationData.code !== parseInt(code)) {
                return res.status(400).json({ error: 'Invalid verification code' });
            }

            // Activate user
            const user = await this.models.User.findByPk(verificationData.userId);
            if (user) {
                user.is_active = true;
                await user.save();
            }

            // Remove verification code
            this.verificationCodes.delete(email);

            res.json({
                success: true,
                message: 'Email verified successfully'
            });

        } catch (error) {
            console.error('Verification error:', error);
            res.status(500).json({ error: 'Verification failed' });
        }
    }

    async resendCode(req, res) {
        try {
            const { email } = req.body;
            
            const user = await this.models.User.findOne({ where: { email } });
            if (!user) {
                return res.status(404).json({ error: 'User not found' });
            }

            // Generate new code
            const verificationCode = Math.floor(100000 + Math.random() * 900000);
            const expiresAt = new Date(Date.now() + 10 * 60 * 1000);
            
            this.verificationCodes.set(email, {
                code: verificationCode,
                expiresAt,
                userId: user.id
            });

            res.json({
                success: true,
                message: 'Verification code resent',
                verification_code: verificationCode // In production, send via email
            });

        } catch (error) {
            console.error('Resend code error:', error);
            res.status(500).json({ error: 'Failed to resend code' });
        }
    }

    async verifyToken(req, res) {
        try {
            const authHeader = req.headers['authorization'];
            const token = authHeader && authHeader.split(' ')[1];
            
            if (!token) {
                return res.status(401).json({ error: 'Token required' });
            }
            
            const decoded = jwt.verify(token, process.env.JWT_SECRET || 'calmai-super-secret-jwt-key-2024-dev-12345');
            const user = await this.models.User.findByPk(decoded.userId);
            
            if (!user) {
                return res.status(404).json({ error: 'User not found' });
            }
            
            res.json({
                success: true,
                user: {
                    id: user.id,
                    username: user.username,
                    email: user.email,
                    first_name: user.first_name,
                    last_name: user.last_name,
                    subscription_type: user.subscription_type
                }
            });
            
        } catch (error) {
            res.status(403).json({ error: 'Invalid token' });
        }
    }

    async resetPassword(req, res) {
        try {
            const { email, new_password, verification_code } = req.body;
            
            // Simple verification for demo
            if (!verification_code || verification_code !== '123456') {
                return res.status(400).json({ error: 'Invalid verification code' });
            }
            
            const user = await this.models.User.findOne({ where: { email } });
            if (!user) {
                return res.status(404).json({ error: 'User not found' });
            }
            
            const passwordData = await this.generatePasswordHash(new_password);
            user.password_hash = passwordData.hash;
            user.salt = passwordData.salt;
            await user.save();
            
            await this.logSecurityEvent('password_reset', user.id, {
                method: 'verification_code'
            });
            
            res.json({
                success: true,
                message: 'Password reset successfully'
            });
            
        } catch (error) {
            console.error('Password reset error:', error);
            res.status(500).json({ error: 'Password reset failed' });
        }
    }

    // ========== USER HANDLERS ==========

    async getUserProfile(req, res) {
        try {
            const user = req.user;
            
            res.json({
                success: true,
                user: {
                    id: user.id,
                    username: user.username,
                    email: user.email,
                    first_name: user.first_name,
                    last_name: user.last_name,
                    user_id: user.user_id,
                    subscription_type: user.subscription_type,
                    free_messages_used: user.free_messages_used,
                    ads_watched: user.ads_watched,
                    last_login: user.last_login
                }
            });
        } catch (error) {
            console.error('Get user profile error:', error);
            res.status(500).json({ error: 'Failed to get profile' });
        }
    }

    async getUserStats(req, res) {
        try {
            const user = req.user;
            
            // Get chat sessions count
            const sessionsCount = await this.models.ChatSession.count({
                where: { user_id: user.id }
            });
            
            // Calculate days active
            const daysActive = Math.floor((new Date() - user.createdAt) / (1000 * 60 * 60 * 24)) + 1;
            
            // Mock data for demo
            res.json({
                success: true,
                stats: {
                    total_conversations: sessionsCount,
                    mindfulness_minutes: Math.floor(Math.random() * 300),
                    mood_score: Math.floor(Math.random() * 10) + 1,
                    achievements_count: Math.floor(Math.random() * 10),
                    messages_left: Math.max(0, 20 - user.free_messages_used),
                    login_streak: Math.floor(Math.random() * 30),
                    days_active: daysActive,
                    messages_sent: sessionsCount * 2,
                    meditation_sessions: Math.floor(Math.random() * 20)
                }
            });
        } catch (error) {
            console.error('Get user stats error:', error);
            res.status(500).json({ error: 'Failed to get stats' });
        }
    }

    async saveMood(req, res) {
        try {
            const { mood } = req.body;
            const user = req.user;
            
            // Log mood event
            await this.logSecurityEvent('mood_check', user.id, { mood });
            
            res.json({
                success: true,
                message: 'Mood saved successfully'
            });
        } catch (error) {
            console.error('Save mood error:', error);
            res.status(500).json({ error: 'Failed to save mood' });
        }
    }

    // ========== AI CHAT HANDLERS ==========

    async chatWithAI(req, res) {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ errors: errors.array() });
            }

            const { message, session_id, ai_model = 'gpt-4' } = req.body;
            const user = req.user;

            // Check free message limit
            if (user.subscription_type === 'free') {
                if (user.free_messages_used >= 20) {
                    return res.status(402).json({
                        error: 'Free message limit reached. Please upgrade or watch an ad.',
                        requires_upgrade: true
                    });
                }
                user.free_messages_used += 1;
                await user.save();
            }

            // Check for banned phrases
            const bannedPhrases = await this.models.BannedPhrase.findAll();
            const messageLower = message.toLowerCase();
            
            for (const phrase of bannedPhrases) {
                if (messageLower.includes(phrase.phrase.toLowerCase())) {
                    await this.logSecurityEvent('banned_phrase_detected', user.id, {
                        phrase: phrase.phrase,
                        message: message.substring(0, 50)
                    });
                    return res.status(400).json({ 
                        error: 'Message contains prohibited content' 
                    });
                }
            }

            // Find or create session
            let session;
            if (session_id) {
                session = await this.models.ChatSession.findByPk(session_id);
                if (!session || session.user_id !== user.id) {
                    return res.status(404).json({ error: 'Session not found' });
                }
            } else {
                session = await this.models.ChatSession.create({
                    user_id: user.id,
                    ai_model: ai_model,
                    messages: []
                });
            }

            // Add user message
            const userMessage = {
                role: 'user',
                content: message,
                timestamp: new Date().toISOString()
            };
            
            session.messages.push(userMessage);

            // Get AI response
            let aiResponse;
            try {
                const response = await this.aiModels['gpt-4'].chat.completions.create({
                    model: "gpt-4",
                    messages: [
                        {
                            role: "system",
                            content: `You are CalmAI, a mental health and wellness assistant. 
                            Be empathetic, supportive, and professional. 
                            Respond in the same language as the user's message.
                            Never provide medical advice.
                            Always encourage seeking professional help when needed.
                            User name: ${user.first_name} ${user.last_name}`
                        },
                        ...session.messages.map(msg => ({
                            role: msg.role,
                            content: msg.content
                        }))
                    ],
                    temperature: 0.7,
                    max_tokens: 500
                });
                
                aiResponse = response.choices[0].message.content;
            } catch (aiError) {
                console.error('AI API error:', aiError);
                aiResponse = "Hello! I'm your CalmAI assistant. I'm here to support you. How can I help you today?";
            }

            // Add AI response
            const aiMessage = {
                role: 'assistant',
                content: aiResponse,
                timestamp: new Date().toISOString(),
                ai_model: ai_model
            };
            
            session.messages.push(aiMessage);
            await session.save();

            res.json({
                success: true,
                session_id: session.id,
                response: aiResponse,
                usage: {
                    free_messages_used: user.free_messages_used,
                    subscription: user.subscription_type
                }
            });

        } catch (error) {
            console.error('Chat error:', error);
            res.status(500).json({ error: 'Failed to process chat request' });
        }
    }

    async getChatSessions(req, res) {
        try {
            const user = req.user;
            
            const sessions = await this.models.ChatSession.findAll({
                where: { user_id: user.id },
                order: [['createdAt', 'DESC']],
                limit: 10
            });
            
            res.json({
                success: true,
                sessions: sessions.map(session => ({
                    id: session.id,
                    created_at: session.createdAt,
                    message_count: session.messages.length,
                    ai_model: session.ai_model
                }))
            });
        } catch (error) {
            console.error('Get chat sessions error:', error);
            res.status(500).json({ error: 'Failed to get chat sessions' });
        }
    }

    async getChatSession(req, res) {
        try {
            const { id } = req.params;
            const user = req.user;
            
            const session = await this.models.ChatSession.findOne({
                where: { 
                    id: id,
                    user_id: user.id 
                }
            });
            
            if (!session) {
                return res.status(404).json({ error: 'Session not found' });
            }
            
            res.json({
                success: true,
                session: {
                    id: session.id,
                    messages: session.messages,
                    created_at: session.createdAt,
                    ai_model: session.ai_model
                }
            });
        } catch (error) {
            console.error('Get chat session error:', error);
            res.status(500).json({ error: 'Failed to get chat session' });
        }
    }

    // ========== CONTENT HANDLERS ==========

    async getContent(req, res) {
        try {
            const { type } = req.params;
            const user = req.user;
            
            let whereCondition = { 
                type: type,
                is_active: true 
            };
            
            // Filter by subscription level
            if (user.subscription_type === 'free') {
                whereCondition.access_level = ['free', 'all'];
            }
            
            const content = await this.models.Content.findAll({
                where: whereCondition,
                order: [['createdAt', 'DESC']]
            });
            
            // Default content if none exists
            if (content.length === 0) {
                const defaultContent = this.getDefaultContent(type);
                res.json({
                    success: true,
                    content: defaultContent
                });
                return;
            }
            
            res.json({
                success: true,
                content: content.map(item => ({
                    id: item.id,
                    type: item.type,
                    title: user.language === 'ar' ? item.title_ar : item.title_en,
                    description: user.language === 'ar' ? item.description_ar : item.description_en,
                    category: item.category,
                    duration: item.duration,
                    url: item.url || `https://example.com/${type}.mp3`,
                    thumbnail_url: item.thumbnail_url || `https://picsum.photos/300/200?random=${item.id}`,
                    access_level: item.access_level
                }))
            });
            
        } catch (error) {
            console.error('Get content error:', error);
            res.status(500).json({ error: 'Failed to fetch content' });
        }
    }

    getDefaultContent(type) {
        const contentMap = {
            music: [
                {
                    id: '1',
                    type: 'music',
                    title: 'Calming Piano Melodies',
                    title_ar: 'موسيقى بيانو مهدئة',
                    description: 'Relaxing piano music for stress relief',
                    description_ar: 'موسيقى بيانو مريحة لتخفيف التوتر',
                    category: 'relaxation',
                    duration: 1800,
                    url: 'https://example.com/calming-piano.mp3',
                    thumbnail_url: 'https://picsum.photos/300/200?random=1',
                    access_level: 'all'
                }
            ],
            meditation: [
                {
                    id: '2',
                    type: 'meditation',
                    title: '10-Minute Mindfulness',
                    title_ar: 'تأمل اليقظة لمدة 10 دقائق',
                    description: 'Guided meditation for beginners',
                    description_ar: 'تأمل موجه للمبتدئين',
                    category: 'mindfulness',
                    duration: 600,
                    url: 'https://example.com/mindfulness.mp3',
                    thumbnail_url: 'https://picsum.photos/300/200?random=2',
                    access_level: 'all'
                }
            ],
            exercise: [
                {
                    id: '3',
                    type: 'exercise',
                    title: 'Breathing Exercise',
                    title_ar: 'تمرين التنفس',
                    description: '4-7-8 breathing technique',
                    description_ar: 'تقنية التنفس 4-7-8',
                    category: 'breathing',
                    duration: 300,
                    url: 'https://example.com/breathing.mp4',
                    thumbnail_url: 'https://picsum.photos/300/200?random=3',
                    access_level: 'all'
                }
            ],
            game: [
                {
                    id: '4',
                    type: 'game',
                    title: 'Color Harmony Game',
                    title_ar: 'لعبة تناغم الألوان',
                    description: 'Relaxing color matching game',
                    description_ar: 'لعبة مطابقة الألوان المهدئة',
                    category: 'relaxation',
                    duration: 0,
                    url: '/games/color-harmony',
                    thumbnail_url: 'https://picsum.photos/300/200?random=4',
                    access_level: 'all'
                }
            ]
        };
        
        return contentMap[type] || [];
    }

    // ========== SUBSCRIPTION HANDLERS ==========

    async getSubscriptionPlans(req, res) {
        const plans = [
            {
                id: 'free',
                name_en: 'Free',
                name_ar: 'مجاني',
                price: 0,
                currency: 'USD',
                features: [
                    { en: '20 messages monthly', ar: '٢٠ رسالة شهريًا' },
                    { en: 'Basic content', ar: 'محتوى أساسي' },
                    { en: 'Limited ads', ar: 'إعلانات محدودة' }
                ],
                color: '#5d8aa8'
            },
            {
                id: 'premium',
                name_en: 'Premium',
                name_ar: 'مميز',
                price: 9.99,
                currency: 'USD',
                features: [
                    { en: 'Unlimited messages', ar: 'رسائل غير محدودة' },
                    { en: 'Advanced content', ar: 'محتوى متقدم' },
                    { en: 'No ads', ar: 'بدون إعلانات' },
                    { en: 'Priority support', ar: 'دعم سريع' }
                ],
                color: '#7bcfa9'
            },
            {
                id: 'pro',
                name_en: 'Pro',
                name_ar: 'احترافي',
                price: 19.99,
                currency: 'USD',
                features: [
                    { en: 'All Premium features', ar: 'كل مميزات المميز' },
                    { en: 'Advanced sessions', ar: 'جلسات متقدمة' },
                    { en: 'Detailed analytics', ar: 'تحليل مفصل' },
                    { en: 'Personal coach', ar: 'مدرب شخصي' }
                ],
                color: '#ffb347'
            }
        ];
        
        res.json({
            success: true,
            plans: plans
        });
    }

    async createSubscription(req, res) {
        try {
            const { plan } = req.body;
            const user = req.user;
            
            const plans = {
                'free': { price: 0, duration: 30 },
                'premium': { price: 9.99, duration: 30 },
                'pro': { price: 19.99, duration: 30 }
            };
            
            const selectedPlan = plans[plan];
            if (!selectedPlan) {
                return res.status(400).json({ error: 'Invalid plan' });
            }
            
            // Create subscription record
            const subscription = await this.models.Subscription.create({
                user_id: user.id,
                plan: plan,
                price: selectedPlan.price,
                currency: 'USD',
                start_date: new Date(),
                end_date: new Date(Date.now() + selectedPlan.duration * 24 * 60 * 60 * 1000),
                status: 'active',
                payment_method: 'demo',
                transaction_id: `TXN-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`
            });
            
            // Update user subscription
            user.subscription_type = plan;
            await user.save();
            
            await this.logSecurityEvent('subscription_created', user.id, {
                plan: plan,
                price: selectedPlan.price,
                transaction_id: subscription.transaction_id
            });
            
            res.json({
                success: true,
                message: 'Subscription created successfully',
                subscription: {
                    id: subscription.id,
                    plan: subscription.plan,
                    end_date: subscription.end_date
                }
            });
            
        } catch (error) {
            console.error('Create subscription error:', error);
            res.status(500).json({ error: 'Failed to create subscription' });
        }
    }

    // ========== ADMIN HANDLERS ==========

    async adminLogin(req, res) {
        try {
            const { username, password } = req.body;
            
            // Check if admin exists, if not create default admin
            let admin = await this.models.Admin.findOne({ where: { username } });
            
            if (!admin && username === 'admin') {
                // Create default admin
                const passwordData = await this.generatePasswordHash('admin123');
                admin = await this.models.Admin.create({
                    username: 'admin',
                    password_hash: passwordData.hash,
                    salt: passwordData.salt,
                    email: 'admin@calmai.com',
                    permissions: {
                        users: true,
                        content: true,
                        ai: true,
                        payments: true,
                        settings: true
                    }
                });
            }
            
            if (!admin) {
                return res.status(401).json({ error: 'Invalid credentials' });
            }
            
            const isValid = await this.verifyPassword(password, admin.password_hash, admin.salt);
            if (!isValid) {
                return res.status(401).json({ error: 'Invalid credentials' });
            }
            
            // Generate admin JWT
            const token = jwt.sign(
                { adminId: admin.id, username: admin.username },
                process.env.ADMIN_JWT_SECRET || 'calmai-admin-super-secret-2024-dev-67890',
                { expiresIn: '24h' }
            );
            
            res.json({
                success: true,
                message: 'Admin login successful',
                admin: {
                    id: admin.id,
                    username: admin.username,
                    email: admin.email,
                    permissions: admin.permissions
                },
                token
            });
            
        } catch (error) {
            console.error('Admin login error:', error);
            res.status(500).json({ error: 'Internal server error' });
        }
    }

    async getUsers(req, res) {
        try {
            const users = await this.models.User.findAll({
                attributes: [
                    'id', 'username', 'email', 'first_name', 'last_name',
                    'user_id', 'subscription_type', 'free_messages_used',
                    'ads_watched', 'last_login', 'is_active', 'is_banned',
                    'createdAt'
                ],
                order: [['createdAt', 'DESC']],
                limit: 50
            });
            
            res.json({
                success: true,
                users: users,
                count: users.length
            });
            
        } catch (error) {
            console.error('Get users error:', error);
            res.status(500).json({ error: 'Failed to fetch users' });
        }
    }

    async getAdminStats(req, res) {
        try {
            const totalUsers = await this.models.User.count();
            const activeUsers = await this.models.User.count({ 
                where: { is_active: true, is_banned: false } 
            });
            const premiumUsers = await this.models.User.count({ 
                where: { subscription_type: ['premium', 'pro'] } 
            });
            const bannedUsers = await this.models.User.count({ 
                where: { is_banned: true } 
            });
            
            const totalSessions = await this.models.ChatSession.count();
            const totalContent = await this.models.Content.count();
            
            res.json({
                success: true,
                stats: {
                    users: {
                        total: totalUsers,
                        active: activeUsers,
                        premium: premiumUsers,
                        banned: bannedUsers
                    },
                    activity: {
                        chat_sessions: totalSessions,
                        content_items: totalContent
                    }
                }
            });
            
        } catch (error) {
            console.error('Get admin stats error:', error);
            res.status(500).json({ error: 'Failed to fetch stats' });
        }
    }

    async banUser(req, res) {
        try {
            const { id } = req.params;
            const { reason } = req.body;
            
            const user = await this.models.User.findByPk(id);
            if (!user) {
                return res.status(404).json({ error: 'User not found' });
            }
            
            user.is_banned = true;
            await user.save();
            
            await this.logSecurityEvent('user_banned', id, {
                admin_id: req.admin.id,
                reason: reason || 'No reason provided'
            });
            
            res.json({
                success: true,
                message: 'User banned successfully'
            });
            
        } catch (error) {
            console.error('Ban user error:', error);
            res.status(500).json({ error: 'Failed to ban user' });
        }
    }

    async sendNotification(req, res) {
        try {
            const { title, message, target } = req.body;
            
            // In production, implement actual notification system
            console.log('Admin notification:', { title, message, target });
            
            res.json({
                success: true,
                message: 'Notification queued for sending'
            });
            
        } catch (error) {
            console.error('Send notification error:', error);
            res.status(500).json({ error: 'Failed to send notification' });
        }
    }

    async getActivityLogs(req, res) {
        try {
            const logs = await this.models.SecurityLog.findAll({
                order: [['createdAt', 'DESC']],
                limit: 50
            });
            
            res.json({
                success: true,
                logs: logs
            });
            
        } catch (error) {
            console.error('Get activity logs error:', error);
            res.status(500).json({ error: 'Failed to fetch activity logs' });
        }
    }

    async getBannedPhrases(req, res) {
        try {
            const phrases = await this.models.BannedPhrase.findAll({
                order: [['createdAt', 'DESC']]
            });
            
            res.json({
                success: true,
                phrases: phrases
            });
            
        } catch (error) {
            console.error('Get banned phrases error:', error);
            res.status(500).json({ error: 'Failed to fetch banned phrases' });
        }
    }

    async addBannedPhrase(req, res) {
        try {
            const { phrase, language, severity, action } = req.body;
            
            const bannedPhrase = await this.models.BannedPhrase.create({
                phrase,
                language: language || 'both',
                severity: severity || 'medium',
                action: action || 'block'
            });
            
            res.json({
                success: true,
                message: 'Banned phrase added',
                phrase: bannedPhrase
            });
            
        } catch (error) {
            console.error('Add banned phrase error:', error);
            res.status(500).json({ error: 'Failed to add banned phrase' });
        }
    }

    async deleteBannedPhrase(req, res) {
        try {
            const { id } = req.params;
            
            const deleted = await this.models.BannedPhrase.destroy({
                where: { id }
            });
            
            if (deleted === 0) {
                return res.status(404).json({ error: 'Phrase not found' });
            }
            
            res.json({
                success: true,
                message: 'Banned phrase deleted'
            });
            
        } catch (error) {
            console.error('Delete banned phrase error:', error);
            res.status(500).json({ error: 'Failed to delete banned phrase' });
        }
    }

    // ========== ERROR HANDLER ==========

    errorHandler(err, req, res, next) {
        console.error('Global error:', err);
        
        const statusCode = err.status || 500;
        const message = process.env.NODE_ENV === 'production' 
            ? 'Something went wrong' 
            : err.message;
        
        res.status(statusCode).json({
            error: message,
            request_id: req.id || uuidv4()
        });
    }
}

// Create and start server
const server = new CalmAIServer();

// Handle graceful shutdown
process.on('SIGTERM', () => {
    console.log('SIGTERM received, shutting down gracefully...');
    if (server.server) {
        server.server.close(() => {
            console.log('Server closed');
            process.exit(0);
        });
    }
});

process.on('SIGINT', () => {
    console.log('SIGINT received, shutting down gracefully...');
    if (server.server) {
        server.server.close(() => {
            console.log('Server closed');
            process.exit(0);
        });
    }
});

module.exports = server;
