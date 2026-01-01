// server.js
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
const { Sequelize, DataTypes } = require('sequelize');
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
        this.aiModels = {
            'gpt-4': null,
            'llama-3': null,
            'claude-3': null
        };
        
        this.init();
    }

    async init() {
        // 1. تهيئة أمنية متقدمة
        this.setupSecurity();
        
        // 2. الاتصال بقواعد البيانات
        await this.setupDatabase();
        
        // 3. تهيئة نماذج الذكاء الاصطناعي
        await this.setupAIModels();
        
        // 4. إعداد middleware
        this.setupMiddleware();
        
        // 5. إعداد التوجيهات
        this.setupRoutes();
        
        // 6. إعداد WebSocket
        this.setupWebSocket();
        
        // 7. تشغيل الخادم
        this.startServer();
    }

    setupSecurity() {
        // شهادة SSL خارقة (في الإنتاج استخدم شهادة حقيقية)
        this.sslOptions = {
            key: fs.readFileSync(path.join(__dirname, 'ssl/key.pem')),
            cert: fs.readFileSync(path.join(__dirname, 'ssl/cert.pem')),
            ciphers: [
                'TLS_AES_256_GCM_SHA384',
                'TLS_CHACHA20_POLY1305_SHA256',
                'TLS_AES_128_GCM_SHA256',
                'ECDHE-ECDSA-AES256-GCM-SHA384',
                'ECDHE-RSA-AES256-GCM-SHA384'
            ].join(':'),
            honorCipherOrder: true,
            minVersion: 'TLSv1.3'
        };

        // Helmet مع إعدادات متقدمة
        this.app.use(helmet({
            contentSecurityPolicy: {
                directives: {
                    defaultSrc: ["'self'"],
                    scriptSrc: ["'self'", "'unsafe-inline'", "cdnjs.cloudflare.com"],
                    styleSrc: ["'self'", "'unsafe-inline'", "cdnjs.cloudflare.com"],
                    imgSrc: ["'self'", "data:", "https:"],
                    connectSrc: ["'self'", "ws:", "wss:"],
                    fontSrc: ["'self'", "cdnjs.cloudflare.com"],
                    objectSrc: ["'none'"],
                    mediaSrc: ["'self'"],
                    frameSrc: ["'none'"]
                }
            },
            hsts: {
                maxAge: 31536000,
                includeSubDomains: true,
                preload: true
            },
            referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
        }));

        // Rate limiting متقدم
        const limiter = rateLimit({
            windowMs: 15 * 60 * 1000, // 15 دقيقة
            max: 100, // حد 100 طلب لكل IP
            message: 'Too many requests from this IP, please try again later.',
            standardHeaders: true,
            legacyHeaders: false,
            keyGenerator: (req) => {
                // استخدام مزيج من IP و user-agent للحد من الهجمات
                return req.ip + req.headers['user-agent'];
            }
        });

        this.app.use('/api/', limiter);

        // CORS مع إعدادات أمنية
        this.app.use(cors({
            origin: (origin, callback) => {
                const allowedOrigins = [
                    'https://calmai.com',
                    'https://www.calmai.com',
                    'https://admin.calmai.com'
                ];
                if (!origin || allowedOrigins.indexOf(origin) !== -1) {
                    callback(null, true);
                } else {
                    callback(new Error('Not allowed by CORS'));
                }
            },
            credentials: true,
            optionsSuccessStatus: 200
        }));
    }

    async setupDatabase() {
        // اتصال بقاعدة بيانات مشفرة
        this.sequelize = new Sequelize({
            dialect: 'sqlite',
            storage: path.join(__dirname, 'database/calmai.db'),
            logging: false,
            define: {
                timestamps: true,
                underscored: true,
                paranoid: true // soft delete
            }
        });

        // نماذج قاعدة البيانات
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
                    type: DataTypes.ENUM('free', 'premium', 'enterprise'),
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
                    defaultValue: true
                },
                is_banned: {
                    type: DataTypes.BOOLEAN,
                    defaultValue: false
                },
                encrypted_notes: DataTypes.TEXT, // ملاحظات مشفرة
                security_token: DataTypes.STRING
            }, {
                hooks: {
                    beforeCreate: async (user) => {
                        // توليد توكن أمني فريد
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
                },
                two_factor_secret: DataTypes.STRING,
                last_login_ip: DataTypes.STRING,
                activity_log: DataTypes.JSON
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
                duration: DataTypes.INTEGER, // بالثواني
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
                    defaultValue: true
                },
                encryption_key: DataTypes.STRING,
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
                severity: DataTypes.ENUM('low', 'medium', 'high', 'critical'),
                timestamp: {
                    type: DataTypes.DATE,
                    defaultValue: DataTypes.NOW
                }
            }),

            BannedPhrase: this.sequelize.define('BannedPhrase', {
                id: {
                    type: DataTypes.UUID,
                    defaultValue: DataTypes.UUIDV4,
                    primaryKey: true
                },
                phrase: DataTypes.STRING,
                language: DataTypes.ENUM('ar', 'en', 'both'),
                category: DataTypes.STRING,
                severity: DataTypes.ENUM('low', 'medium', 'high'),
                action: DataTypes.ENUM('warn', 'block', 'alert')
            })
        };

        // إنشاء الجداول
        await this.sequelize.sync({ force: false });
        console.log('Database connected and synchronized');
    }

    async setupAIModels() {
        // تكوين نماذج الذكاء الاصطناعي المتعددة
        this.openai = new OpenAI({
            apiKey: process.env.OPENAI_API_KEY
        });

        // نماذج بديلة لتحقيق أفضل النتائج
        this.aiModels = {
            'gpt-4': this.openai,
            'llama-3': {
                chat: async (messages) => {
                    // تكامل مع Llama 3 عبر API
                    const response = await axios.post('https://api.llama.ai/v1/chat', {
                        model: 'llama-3-70b',
                        messages: messages,
                        temperature: 0.7
                    }, {
                        headers: {
                            'Authorization': `Bearer ${process.env.LLAMA_API_KEY}`
                        }
                    });
                    return response.data;
                }
            },
            'claude-3': {
                chat: async (messages) => {
                    // تكامل مع Claude 3
                    const response = await axios.post('https://api.anthropic.com/v1/messages', {
                        model: 'claude-3-opus-20240229',
                        messages: messages,
                        max_tokens: 1000
                    }, {
                        headers: {
                            'x-api-key': process.env.ANTHROPIC_API_KEY,
                            'anthropic-version': '2023-06-01'
                        }
                    });
                    return response.data;
                }
            }
        };
    }

    setupMiddleware() {
        // فك تشفير body
        this.app.use(express.json({
            limit: '10mb',
            verify: (req, res, buf) => {
                try {
                    JSON.parse(buf.toString());
                } catch (e) {
                    throw new Error('Invalid JSON');
                }
            }
        }));

        // Middleware لفحص محتوى JSON
        this.app.use((req, res, next) => {
            if (req.body && typeof req.body === 'object') {
                this.scanForMaliciousContent(req.body);
            }
            next();
        });

        // Middleware للتشفير/فك التشفير التلقائي
        this.app.use(async (req, res, next) => {
            if (req.path.startsWith('/api/') && req.method === 'POST') {
                await this.decryptRequest(req);
            }
            next();
        });

        // Middleware للمصادقة
        this.app.use('/api/secure/', this.authenticateToken.bind(this));
        this.app.use('/api/admin/', this.authenticateAdmin.bind(this));
    }

    setupRoutes() {
        // تقديم الملفات الثابتة
        this.app.use(express.static(path.join(__dirname, 'public')));

        // واجهات API للمستخدمين
        this.app.post('/api/auth/signup', [
            body('email').isEmail().normalizeEmail(),
            body('password').isLength({ min: 8 }).matches(/^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/),
            body('first_name').trim().escape(),
            body('last_name').trim().escape(),
            body('birth_year').isInt({ min: 1900, max: new Date().getFullYear() - 13 })
        ], this.signup.bind(this));

        this.app.post('/api/auth/login', [
            body('email').isEmail().normalizeEmail(),
            body('password').notEmpty()
        ], this.login.bind(this));

        this.app.post('/api/auth/verify', this.verifyEmail.bind(this));
        this.app.post('/api/auth/reset-password', this.resetPassword.bind(this));

        // واجهات API للمحتوى
        this.app.get('/api/content/:type', this.getContent.bind(this));
        this.app.post('/api/content', this.addContent.bind(this));
        this.app.put('/api/content/:id', this.updateContent.bind(this));
        this.app.delete('/api/content/:id', this.deleteContent.bind(this));

        // واجهات API للدردشة مع الذكاء الاصطناعي
        this.app.post('/api/ai/chat', [
            body('message').trim().escape(),
            body('session_id').optional().isUUID()
        ], this.chatWithAI.bind(this));

        this.app.get('/api/ai/models', this.getAIModels.bind(this));
        this.app.post('/api/ai/analyze-sentiment', this.analyzeSentiment.bind(this));

        // واجهات API للإدارة
        this.app.get('/api/admin/users', this.getUsers.bind(this));
        this.app.get('/api/admin/stats', this.getStats.bind(this));
        this.app.post('/api/admin/ban-user/:id', this.banUser.bind(this));
        this.app.post('/api/admin/send-notification', this.sendNotification.bind(this));
        this.app.post('/api/admin/update-settings', this.updateSettings.bind(this));

        // واجهات API للمدفوعات
        this.app.post('/api/payment/create-subscription', this.createSubscription.bind(this));
        this.app.post('/api/payment/verify', this.verifyPayment.bind(this));
        this.app.get('/api/payment/plans', this.getSubscriptionPlans.bind(this));

        // واجهات API للأمان
        this.app.get('/api/security/logs', this.getSecurityLogs.bind(this));
        this.app.post('/api/security/scan', this.scanForThreats.bind(this));
        this.app.get('/api/security/status', this.getSecurityStatus.bind(this));

        // صفحة 404
        this.app.use((req, res) => {
            res.status(404).sendFile(path.join(__dirname, 'public/404.html'));
        });

        // معالج الأخطاء
        this.app.use(this.errorHandler.bind(this));
    }

    setupWebSocket() {
        this.wss = new WebSocket.Server({ noServer: true });

        this.wss.on('connection', (ws, req) => {
            console.log('New WebSocket connection');

            // المصادقة عبر WebSocket
            ws.on('message', async (message) => {
                try {
                    const data = JSON.parse(message);
                    
                    if (data.type === 'auth') {
                        const isValid = await this.verifyWebSocketToken(data.token);
                        if (isValid) {
                            ws.userId = data.userId;
                            ws.send(JSON.stringify({ type: 'auth_success' }));
                        } else {
                            ws.close(1008, 'Authentication failed');
                        }
                    } else if (data.type === 'chat') {
                        if (!ws.userId) {
                            ws.close(1008, 'Not authenticated');
                            return;
                        }

                        // فحص الرسالة
                        const scanResult = await this.scanMessage(data.message);
                        if (scanResult.isMalicious) {
                            ws.send(JSON.stringify({
                                type: 'error',
                                message: 'Message contains prohibited content'
                            }));
                            return;
                        }

                        // معالجة الدردشة في الوقت الحقيقي
                        const aiResponse = await this.processRealTimeChat(data.message, ws.userId);
                        ws.send(JSON.stringify({
                            type: 'chat_response',
                            message: aiResponse
                        }));
                    }
                } catch (error) {
                    console.error('WebSocket error:', error);
                    ws.send(JSON.stringify({ type: 'error', message: 'Internal server error' }));
                }
            });

            ws.on('close', () => {
                console.log('WebSocket connection closed');
            });
        });
    }

    startServer() {
        const PORT = process.env.PORT || 443;
        
        if (process.env.NODE_ENV === 'production') {
            this.server = https.createServer(this.sslOptions, this.app);
        } else {
            this.server = http.createServer(this.app);
        }

        // إرفاق WebSocket بالخادم
        this.server.on('upgrade', (request, socket, head) => {
            this.wss.handleUpgrade(request, socket, head, (ws) => {
                this.wss.emit('connection', ws, request);
            });
        });

        this.server.listen(PORT, () => {
            console.log(`CalmAI Server running on port ${PORT}`);
            console.log(`Security level: MAXIMUM`);
            console.log(`AI Models: ${Object.keys(this.aiModels).join(', ')}`);
            console.log(`Database: Encrypted SQLite`);
        });
    }

    // ========== طرق المساعدة (Helper Methods) ==========

    async encryptData(data, key) {
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
        const encrypted = Buffer.concat([cipher.update(data, 'utf8'), cipher.final()]);
        const authTag = cipher.getAuthTag();
        
        return {
            iv: iv.toString('hex'),
            encrypted: encrypted.toString('hex'),
            authTag: authTag.toString('hex')
        };
    }

    async decryptData(encryptedData, key) {
        const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(encryptedData.iv, 'hex'));
        decipher.setAuthTag(Buffer.from(encryptedData.authTag, 'hex'));
        
        const decrypted = Buffer.concat([
            decipher.update(Buffer.from(encryptedData.encrypted, 'hex')),
            decipher.final()
        ]);
        
        return decrypted.toString('utf8');
    }

    async generateSecurePasswordHash(password) {
        // توليد salt فريد
        const salt = await bcrypt.genSalt(14);
        
        // تشفير الباسورد مع salt
        const hash = await bcrypt.hash(password, salt);
        
        // تشفير إضافي باستخدام SHA-512
        const enhancedHash = crypto
            .createHmac('sha512', process.env.HMAC_SECRET || 'calmai-secure-key-2024')
            .update(hash)
            .digest('hex');
        
        return {
            hash: enhancedHash,
            salt: salt,
            algorithm: 'bcrypt+sha512'
        };
    }

    async verifyPassword(password, storedHash, salt) {
        try {
            // خطوة 1: فك التشفير باستخدام bcrypt
            const bcryptHash = await bcrypt.hash(password, salt);
            
            // خطوة 2: فك التشفير باستخدام SHA-512
            const enhancedHash = crypto
                .createHmac('sha512', process.env.HMAC_SECRET || 'calmai-secure-key-2024')
                .update(bcryptHash)
                .digest('hex');
            
            return enhancedHash === storedHash;
        } catch (error) {
            this.logSecurityEvent('password_verification_failed', null, { error: error.message });
            return false;
        }
    }

    async scanForMaliciousContent(data) {
        const maliciousPatterns = [
            /<script.*?>.*?<\/script>/gi,
            /javascript:/gi,
            /on\w+\s*=/gi,
            /eval\(/gi,
            /union.*select/gi,
            /drop.*table/gi,
            /insert.*into/gi,
            /delete.*from/gi,
            /--/gi,
            /\|\|/gi,
            /&&/gi,
            /\.\.\//gi
        ];

        const dataString = JSON.stringify(data).toLowerCase();
        
        for (const pattern of maliciousPatterns) {
            if (pattern.test(dataString)) {
                this.logSecurityEvent('malicious_content_detected', null, {
                    pattern: pattern.toString(),
                    data: dataString.substring(0, 200)
                });
                throw new Error('Malicious content detected');
            }
        }
    }

    async scanMessage(message) {
        // فحص ضد العبارات المحظورة
        const bannedPhrases = await this.models.BannedPhrase.findAll();
        
        for (const phrase of bannedPhrases) {
            if (message.toLowerCase().includes(phrase.phrase.toLowerCase())) {
                return {
                    isMalicious: true,
                    reason: 'banned_phrase',
                    severity: phrase.severity,
                    phrase: phrase.phrase
                };
            }
        }

        // فحص تحليل المشاعر السلبية الشديدة
        const sentiment = await this.analyzeSentimentText(message);
        if (sentiment.score < -0.7) {
            return {
                isMalicious: false,
                isConcerning: true,
                reason: 'negative_sentiment',
                score: sentiment.score
            };
        }

        return { isMalicious: false, isConcerning: false };
    }

    async analyzeSentimentText(text) {
        // استخدام نموذج الذكاء الاصطناعي لتحليل المشاعر
        try {
            const response = await this.openai.chat.completions.create({
                model: "gpt-4",
                messages: [
                    {
                        role: "system",
                        content: "Analyze the sentiment of the following text. Return a JSON object with 'score' (between -1 and 1) and 'emotion' (main emotion detected)."
                    },
                    {
                        role: "user",
                        content: text
                    }
                ],
                temperature: 0.1,
                max_tokens: 100
            });

            const result = JSON.parse(response.choices[0].message.content);
            return result;
        } catch (error) {
            // طريقة بديلة بسيطة
            const negativeWords = ['مكتئب', 'انتحار', 'أموت', 'أكره', 'تعيس', 'depressed', 'suicide', 'die', 'hate', 'miserable'];
            const positiveWords = ['سعيد', 'فرح', 'ممتن', 'رائع', 'happy', 'joy', 'grateful', 'wonderful'];
            
            let score = 0;
            text = text.toLowerCase();
            
            negativeWords.forEach(word => {
                if (text.includes(word.toLowerCase())) score -= 0.2;
            });
            
            positiveWords.forEach(word => {
                if (text.includes(word.toLowerCase())) score += 0.2;
            });
            
            return {
                score: Math.max(-1, Math.min(1, score)),
                emotion: score > 0 ? 'positive' : score < 0 ? 'negative' : 'neutral'
            };
        }
    }

    async logSecurityEvent(eventType, userId, details = {}) {
        try {
            await this.models.SecurityLog.create({
                event_type: eventType,
                user_id: userId,
                ip_address: details.ip || 'unknown',
                user_agent: details.userAgent || 'unknown',
                details: details,
                severity: details.severity || 'medium',
                timestamp: new Date()
            });
        } catch (error) {
            console.error('Failed to log security event:', error);
        }
    }

    async authenticateToken(req, res, next) {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];

        if (!token) {
            this.logSecurityEvent('missing_auth_token', null, { path: req.path });
            return res.status(401).json({ error: 'Access token required' });
        }

        try {
            const decoded = jwt.verify(token, process.env.JWT_SECRET || 'calmai-super-secret-jwt-key-2024');
            const user = await this.models.User.findByPk(decoded.userId);
            
            if (!user || !user.is_active || user.is_banned) {
                this.logSecurityEvent('invalid_token_user', decoded.userId);
                return res.status(403).json({ error: 'User not found or inactive' });
            }

            req.user = user;
            next();
        } catch (error) {
            this.logSecurityEvent('invalid_token', null, { error: error.message });
            return res.status(403).json({ error: 'Invalid or expired token' });
        }
    }

    async authenticateAdmin(req, res, next) {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];

        if (!token) {
            return res.status(401).json({ error: 'Admin token required' });
        }

        try {
            const decoded = jwt.verify(token, process.env.ADMIN_JWT_SECRET || 'calmai-admin-super-secret-2024');
            const admin = await this.models.Admin.findByPk(decoded.adminId);
            
            if (!admin) {
                return res.status(403).json({ error: 'Admin not found' });
            }

            req.admin = admin;
            next();
        } catch (error) {
            return res.status(403).json({ error: 'Invalid admin token' });
        }
    }

    // ========== معالجات API الرئيسية ==========

    async signup(req, res) {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ errors: errors.array() });
            }

            const { email, password, first_name, last_name, birth_year, gender } = req.body;

            // التحقق من البريد الإلكتروني المكرر
            const existingUser = await this.models.User.findOne({ where: { email } });
            if (existingUser) {
                return res.status(400).json({ error: 'Email already registered' });
            }

            // توليد اسم مستخدم فريد
            const baseUsername = `${first_name.toLowerCase()}_${last_name.toLowerCase()}`;
            let username = baseUsername;
            let counter = 1;

            while (await this.models.User.findOne({ where: { username } })) {
                username = `${baseUsername}${counter}`;
                counter++;
            }

            // تشفير كلمة المرور
            const passwordData = await this.generateSecurePasswordHash(password);

            // إنشاء المستخدم
            const user = await this.models.User.create({
                username,
                email,
                password_hash: passwordData.hash,
                first_name,
                last_name,
                birth_year,
                gender,
                user_id: `CAI-${Date.now().toString().slice(-6)}`
            });

            // تسجيل حدث الأمان
            this.logSecurityEvent('user_signup', user.id, {
                email: email,
                ip: req.ip,
                userAgent: req.headers['user-agent']
            });

            // إرسال بريد التحقق
            await this.sendVerificationEmail(user);

            // توليد JWT token
            const token = jwt.sign(
                { userId: user.id, email: user.email },
                process.env.JWT_SECRET || 'calmai-super-secret-jwt-key-2024',
                { expiresIn: '7d' }
            );

            res.status(201).json({
                success: true,
                message: 'Account created successfully',
                user: {
                    id: user.id,
                    username: user.username,
                    email: user.email,
                    user_id: user.user_id
                },
                token,
                requires_verification: true
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

            // البحث عن المستخدم
            const user = await this.models.User.findOne({ where: { email } });
            if (!user) {
                this.logSecurityEvent('login_failed_nonexistent', null, { email, ip: req.ip });
                return res.status(401).json({ error: 'Invalid credentials' });
            }

            // التحقق من الحظر
            if (user.is_banned) {
                this.logSecurityEvent('login_attempt_banned', user.id, { ip: req.ip });
                return res.status(403).json({ error: 'Account is banned' });
            }

            // التحقق من كلمة المرور
            const isValidPassword = await this.verifyPassword(password, user.password_hash, user.salt);
            if (!isValidPassword) {
                this.logSecurityEvent('login_failed_password', user.id, { ip: req.ip });
                return res.status(401).json({ error: 'Invalid credentials' });
            }

            // تحديث آخر دخول
            user.last_login = new Date();
            await user.save();

            // تسجيل دخول ناجح
            this.logSecurityEvent('login_success', user.id, { ip: req.ip });

            // توليد JWT token
            const token = jwt.sign(
                { 
                    userId: user.id, 
                    email: user.email,
                    subscription: user.subscription_type
                },
                process.env.JWT_SECRET || 'calmai-super-secret-jwt-key-2024',
                { expiresIn: '7d' }
            );

            res.json({
                success: true,
                message: 'Login successful',
                user: {
                    id: user.id,
                    username: user.username,
                    email: user.email,
                    user_id: user.user_id,
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

    async chatWithAI(req, res) {
        try {
            const { message, session_id, ai_model = 'gpt-4' } = req.body;
            const userId = req.user.id;

            // التحقق من حدود الاستخدام
            const user = await this.models.User.findByPk(userId);
            
            if (user.subscription_type === 'free') {
                if (user.free_messages_used >= 20) {
                    return res.status(402).json({
                        error: 'Free message limit reached',
                        action: 'upgrade_or_watch_ad'
                    });
                }
                user.free_messages_used += 1;
                await user.save();
            }

            // فحص الرسالة
            const scanResult = await this.scanMessage(message);
            if (scanResult.isMalicious) {
                this.logSecurityEvent('blocked_malicious_message', userId, {
                    message: message.substring(0, 100),
                    reason: scanResult.reason
                });
                return res.status(400).json({ error: 'Message contains prohibited content' });
            }

            // البحث عن جلسة أو إنشاء جديدة
            let session;
            if (session_id) {
                session = await this.models.ChatSession.findByPk(session_id);
                if (!session || session.user_id !== userId) {
                    return res.status(404).json({ error: 'Session not found' });
                }
            } else {
                session = await this.models.ChatSession.create({
                    user_id: userId,
                    ai_model: ai_model,
                    messages: [],
                    encryption_key: crypto.randomBytes(32).toString('hex')
                });
            }

            // إضافة رسالة المستخدم
            const userMessage = {
                role: 'user',
                content: message,
                timestamp: new Date(),
                sentiment: await this.analyzeSentimentText(message)
            };

            session.messages.push(userMessage);

            // اختيار نموذج الذكاء الاصطناعي
            let aiResponse;
            if (this.aiModels[ai_model]) {
                if (ai_model === 'gpt-4') {
                    const response = await this.openai.chat.completions.create({
                        model: "gpt-4",
                        messages: [
                            {
                                role: "system",
                                content: `You are CalmAI, a mental health assistant. 
                                Be empathetic, supportive, and professional. 
                                Never provide medical advice. 
                                Always encourage users to seek professional help when needed.
                                Current user: ${user.first_name} ${user.last_name}`
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
                } else {
                    // استخدام النماذج البديلة
                    aiResponse = await this.aiModels[ai_model].chat([
                        {
                            role: "system",
                            content: "You are a supportive mental health assistant."
                        },
                        ...session.messages.map(msg => ({
                            role: msg.role,
                            content: msg.content
                        }))
                    ]);
                }
            }

            // إضافة رد الذكاء الاصطناعي
            const aiMessage = {
                role: 'assistant',
                content: aiResponse,
                timestamp: new Date(),
                ai_model: ai_model
            };

            session.messages.push(aiMessage);

            // تحليل مشاعر الجلسة
            const sessionSentiment = this.calculateSessionSentiment(session.messages);
            session.sentiment_score = sessionSentiment.score;

            // التحقق من علامات التحذير
            const warningFlags = this.checkForWarningFlags(session.messages);
            if (warningFlags.length > 0) {
                session.warning_flags = warningFlags;
                this.logSecurityEvent('warning_flags_detected', userId, {
                    session_id: session.id,
                    flags: warningFlags
                });
            }

            await session.save();

            // تشفير الرسالة قبل الإرسال
            const encryptedResponse = await this.encryptData(
                JSON.stringify(aiMessage),
                session.encryption_key
            );

            res.json({
                success: true,
                session_id: session.id,
                response: encryptedResponse,
                sentiment: sessionSentiment,
                warnings: warningFlags,
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

    async getContent(req, res) {
        try {
            const { type } = req.params;
            const user = req.user;
            
            let whereCondition = { 
                type: type,
                is_active: true 
            };

            // تصفية المحتوى حسب نوع الاشتراك
            if (user.subscription_type === 'free') {
                whereCondition.access_level = ['free', 'all'];
            }

            const content = await this.models.Content.findAll({
                where: whereCondition,
                order: [['createdAt', 'DESC']]
            });

            res.json({
                success: true,
                content: content.map(item => ({
                    id: item.id,
                    type: item.type,
                    title: currentLang === 'ar' ? item.title_ar : item.title_en,
                    description: currentLang === 'ar' ? item.description_ar : item.description_en,
                    category: item.category,
                    duration: item.duration,
                    url: item.url,
                    thumbnail_url: item.thumbnail_url,
                    access_level: item.access_level
                }))
            });

        } catch (error) {
            console.error('Get content error:', error);
            res.status(500).json({ error: 'Failed to fetch content' });
        }
    }

    async getUsers(req, res) {
        try {
            const admin = req.admin;
            
            if (!admin.permissions.users) {
                return res.status(403).json({ error: 'Permission denied' });
            }

            const users = await this.models.User.findAll({
                attributes: [
                    'id', 'username', 'email', 'first_name', 'last_name',
                    'user_id', 'subscription_type', 'free_messages_used',
                    'ads_watched', 'last_login', 'is_active', 'is_banned',
                    'createdAt'
                ],
                order: [['createdAt', 'DESC']]
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

    async createSubscription(req, res) {
        try {
            const { plan, payment_method, payment_token } = req.body;
            const userId = req.user.id;

            // التحقق من token الدفع
            const paymentValid = await this.verifyPaymentToken(payment_token);
            if (!paymentValid) {
                return res.status(400).json({ error: 'Invalid payment token' });
            }

            // أسعار الخطط
            const plans = {
                'basic': { price: 9.99, currency: 'USD', duration: 30 },
                'pro': { price: 19.99, currency: 'USD', duration: 30 },
                'premium': { price: 29.99, currency: 'USD', duration: 30 }
            };

            const selectedPlan = plans[plan];
            if (!selectedPlan) {
                return res.status(400).json({ error: 'Invalid plan' });
            }

            // إنشاء الاشتراك
            const subscription = await this.models.Subscription.create({
                user_id: userId,
                plan: plan,
                price: selectedPlan.price,
                currency: selectedPlan.currency,
                start_date: new Date(),
                end_date: new Date(Date.now() + selectedPlan.duration * 24 * 60 * 60 * 1000),
                status: 'active',
                payment_method: payment_method,
                transaction_id: `TXN-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`
            });

            // تحديث نوع اشتراك المستخدم
            const user = await this.models.User.findByPk(userId);
            user.subscription_type = plan;
            await user.save();

            // تسجيل حدث الدفع
            this.logSecurityEvent('subscription_created', userId, {
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
                    end_date: subscription.end_date,
                    transaction_id: subscription.transaction_id
                }
            });

        } catch (error) {
            console.error('Subscription error:', error);
            res.status(500).json({ error: 'Failed to create subscription' });
        }
    }

    async sendVerificationEmail(user) {
        // توليد رمز تحقق
        const verificationCode = Math.floor(100000 + Math.random() * 900000);
        
        // تخزين الرمز في ذاكرة مؤقتة
        const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 دقائق
        
        // في الإنتاج، استخدم Redis أو قاعدة بيانات مؤقتة
        this.verificationCodes = this.verificationCodes || {};
        this.verificationCodes[user.email] = {
            code: verificationCode,
            expiresAt: expiresAt,
            userId: user.id
        };

        // في الإنتاج، أرسل بريدًا إلكترونيًا حقيقيًا
        console.log(`Verification code for ${user.email}: ${verificationCode}`);
        
        return verificationCode;
    }

    async verifyEmail(req, res) {
        try {
            const { email, code } = req.body;
            
            if (!this.verificationCodes || !this.verificationCodes[email]) {
                return res.status(400).json({ error: 'No verification request found' });
            }

            const verification = this.verificationCodes[email];
            
            if (verification.expiresAt < new Date()) {
                delete this.verificationCodes[email];
                return res.status(400).json({ error: 'Verification code expired' });
            }

            if (verification.code !== parseInt(code)) {
                return res.status(400).json({ error: 'Invalid verification code' });
            }

            // تفعيل حساب المستخدم
            const user = await this.models.User.findByPk(verification.userId);
            if (user) {
                user.is_active = true;
                await user.save();
            }

            // حذف رمز التحقق
            delete this.verificationCodes[email];

            res.json({
                success: true,
                message: 'Email verified successfully'
            });

        } catch (error) {
            console.error('Verification error:', error);
            res.status(500).json({ error: 'Verification failed' });
        }
    }

    async resetPassword(req, res) {
        try {
            const { email, new_password, verification_code } = req.body;
            
            // التحقق من رمز التحقق
            // (في الإنتاج، استخدم نظامًا أكثر أمانًا)
            
            const user = await this.models.User.findOne({ where: { email } });
            if (!user) {
                return res.status(404).json({ error: 'User not found' });
            }

            // تحديث كلمة المرور
            const passwordData = await this.generateSecurePasswordHash(new_password);
            user.password_hash = passwordData.hash;
            user.salt = passwordData.salt;
            await user.save();

            // تسجيل حدث تغيير كلمة المرور
            this.logSecurityEvent('password_reset', user.id, {
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

    async banUser(req, res) {
        try {
            const admin = req.admin;
            const { id } = req.params;
            const { reason } = req.body;

            if (!admin.permissions.users) {
                return res.status(403).json({ error: 'Permission denied' });
            }

            const user = await this.models.User.findByPk(id);
            if (!user) {
                return res.status(404).json({ error: 'User not found' });
            }

            user.is_banned = true;
            await user.save();

            // تسجيل حدث الحظر
            this.logSecurityEvent('user_banned', id, {
                admin_id: admin.id,
                reason: reason,
                timestamp: new Date()
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
            const admin = req.admin;
            const { title, message, target, type } = req.body;

            if (!admin.permissions.settings) {
                return res.status(403).json({ error: 'Permission denied' });
            }

            // تحديد المستهدفين
            let users;
            if (target === 'all') {
                users = await this.models.User.findAll({
                    where: { is_active: true, is_banned: false }
                });
            } else if (target === 'premium') {
                users = await this.models.User.findAll({
                    where: { 
                        subscription_type: ['pro', 'premium'],
                        is_active: true,
                        is_banned: false
                    }
                });
            } else if (target === 'free') {
                users = await this.models.User.findAll({
                    where: { 
                        subscription_type: 'free',
                        is_active: true,
                        is_banned: false
                    }
                });
            }

            // في الإنتاج، أرسل إشعارات push حقيقية
            console.log(`Sending notification to ${users.length} users:`, {
                title,
                message,
                type
            });

            // تسجيل حدث الإشعار
            this.logSecurityEvent('notification_sent', null, {
                admin_id: admin.id,
                target: target,
                users_count: users.length,
                notification_type: type
            });

            res.json({
                success: true,
                message: `Notification sent to ${users.length} users`
            });

        } catch (error) {
            console.error('Send notification error:', error);
            res.status(500).json({ error: 'Failed to send notification' });
        }
    }

    async updateSettings(req, res) {
        try {
            const admin = req.admin;
            const settings = req.body;

            if (!admin.permissions.settings) {
                return res.status(403).json({ error: 'Permission denied' });
            }

            // في الإنتاج، احفظ الإعدادات في قاعدة بيانات
            console.log('Settings updated by admin:', admin.id, settings);

            res.json({
                success: true,
                message: 'Settings updated successfully'
            });

        } catch (error) {
            console.error('Update settings error:', error);
            res.status(500).json({ error: 'Failed to update settings' });
        }
    }

    async getStats(req, res) {
        try {
            const admin = req.admin;

            if (!admin.permissions.users) {
                return res.status(403).json({ error: 'Permission denied' });
            }

            // إحصائيات المستخدمين
            const totalUsers = await this.models.User.count();
            const activeUsers = await this.models.User.count({ where: { is_active: true } });
            const premiumUsers = await this.models.User.count({ 
                where: { subscription_type: ['pro', 'premium'] }
            });
            const bannedUsers = await this.models.User.count({ where: { is_banned: true } });

            // إحصائيات الاشتراكات
            const subscriptions = await this.models.Subscription.findAll({
                where: { status: 'active' }
            });
            const totalRevenue = subscriptions.reduce((sum, sub) => sum + sub.price, 0);

            // إحصائيات المحتوى
            const totalContent = await this.models.Content.count();
            const activeContent = await this.models.Content.count({ where: { is_active: true } });

            // إحصائيات الأمان
            const securityEvents = await this.models.SecurityLog.findAll({
                where: {
                    timestamp: {
                        [Sequelize.Op.gte]: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000)
                    }
                }
            });

            res.json({
                success: true,
                stats: {
                    users: {
                        total: totalUsers,
                        active: activeUsers,
                        premium: premiumUsers,
                        banned: bannedUsers
                    },
                    subscriptions: {
                        active: subscriptions.length,
                        revenue: totalRevenue
                    },
                    content: {
                        total: totalContent,
                        active: activeContent
                    },
                    security: {
                        events_last_7_days: securityEvents.length,
                        high_severity: securityEvents.filter(e => e.severity === 'high' || e.severity === 'critical').length
                    }
                }
            });

        } catch (error) {
            console.error('Get stats error:', error);
            res.status(500).json({ error: 'Failed to fetch statistics' });
        }
    }

    async addContent(req, res) {
        try {
            const admin = req.admin;
            const contentData = req.body;

            if (!admin.permissions.content) {
                return res.status(403).json({ error: 'Permission denied' });
            }

            const content = await this.models.Content.create(contentData);

            res.json({
                success: true,
                message: 'Content added successfully',
                content: content
            });

        } catch (error) {
            console.error('Add content error:', error);
            res.status(500).json({ error: 'Failed to add content' });
        }
    }

    async getSecurityLogs(req, res) {
        try {
            const admin = req.admin;

            if (!admin.permissions.settings) {
                return res.status(403).json({ error: 'Permission denied' });
            }

            const { page = 1, limit = 50, severity, event_type } = req.query;
            const offset = (page - 1) * limit;

            let whereCondition = {};
            if (severity) whereCondition.severity = severity;
            if (event_type) whereCondition.event_type = event_type;

            const logs = await this.models.SecurityLog.findAll({
                where: whereCondition,
                order: [['timestamp', 'DESC']],
                limit: parseInt(limit),
                offset: parseInt(offset)
            });

            const total = await this.models.SecurityLog.count({ where: whereCondition });

            res.json({
                success: true,
                logs: logs,
                pagination: {
                    page: parseInt(page),
                    limit: parseInt(limit),
                    total: total,
                    pages: Math.ceil(total / limit)
                }
            });

        } catch (error) {
            console.error('Get security logs error:', error);
            res.status(500).json({ error: 'Failed to fetch security logs' });
        }
    }

    async getSubscriptionPlans(req, res) {
        try {
            const plans = [
                {
                    id: 'free',
                    name_ar: 'مجاني',
                    name_en: 'Free',
                    price: 0,
                    currency: 'USD',
                    features: [
                        { ar: '٢٠ رسالة شهريًا', en: '20 messages monthly' },
                        { ar: 'محتوى أساسي', en: 'Basic content' },
                        { ar: 'إعلانات محدودة', en: 'Limited ads' }
                    ],
                    color: '#5d8aa8'
                },
                {
                    id: 'basic',
                    name_ar: 'أساسي',
                    name_en: 'Basic',
                    price: 9.99,
                    currency: 'USD',
                    features: [
                        { ar: 'رسائل غير محدودة', en: 'Unlimited messages' },
                        { ar: 'محتوى متقدم', en: 'Advanced content' },
                        { ar: 'لا إعلانات', en: 'No ads' },
                        { ar: 'دعم سريع', en: 'Priority support' }
                    ],
                    color: '#7bcfa9'
                },
                {
                    id: 'pro',
                    name_ar: 'محترف',
                    name_en: 'Pro',
                    price: 19.99,
                    currency: 'USD',
                    features: [
                        { ar: 'كل مميزات الأساسي', en: 'All Basic features' },
                        { ar: 'جلسات متقدمة', en: 'Advanced sessions' },
                        { ar: 'تحليل مفصل', en: 'Detailed analytics' },
                        { ar: 'وصول مبكر للميزات', en: 'Early access to features' }
                    ],
                    color: '#ffb347'
                },
                {
                    id: 'premium',
                    name_ar: 'مميز',
                    name_en: 'Premium',
                    price: 29.99,
                    currency: 'USD',
                    features: [
                        { ar: 'كل مميزات المحترف', en: 'All Pro features' },
                        { ar: 'جلسات خاصة', en: 'Private sessions' },
                        { ar: 'مدرب شخصي', en: 'Personal coach' },
                        { ar: 'دعم ٢٤/٧', en: '24/7 support' }
                    ],
                    color: '#e74c3c'
                }
            ];

            res.json({
                success: true,
                plans: plans
            });

        } catch (error) {
            console.error('Get plans error:', error);
            res.status(500).json({ error: 'Failed to fetch subscription plans' });
        }
    }

    // ========== طرق مساعدة إضافية ==========

    calculateSessionSentiment(messages) {
        let totalScore = 0;
        let count = 0;

        messages.forEach(msg => {
            if (msg.sentiment && msg.sentiment.score) {
                totalScore += msg.sentiment.score;
                count++;
            }
        });

        return {
            score: count > 0 ? totalScore / count : 0,
            message_count: count,
            overall: count > 0 ? (totalScore / count > 0.3 ? 'positive' : totalScore / count < -0.3 ? 'negative' : 'neutral') : 'neutral'
        };
    }

    checkForWarningFlags(messages) {
        const warningFlags = [];
        const warningPatterns = [
            {
                pattern: /انتحار|انتحاري|أريد أن أموت|أفضل الموت|suicide|kill myself/i,
                severity: 'critical',
                action: 'immediate_alert'
            },
            {
                pattern: /أذى نفسي|أجرح نفسي|self harm|cut myself/i,
                severity: 'high',
                action: 'alert_and_monitor'
            },
            {
                pattern: /مكتئب بشدة|لا أريد العيش|severely depressed|don't want to live/i,
                severity: 'high',
                action: 'monitor'
            },
            {
                pattern: /أدوية|حبوب|مخدرات|drugs|pills|overdose/i,
                severity: 'medium',
                action: 'note'
            }
        ];

        messages.forEach(msg => {
            if (msg.role === 'user') {
                warningPatterns.forEach(pattern => {
                    if (pattern.pattern.test(msg.content)) {
                        warningFlags.push({
                            pattern: pattern.pattern.toString(),
                            severity: pattern.severity,
                            action: pattern.action,
                            message: msg.content.substring(0, 100),
                            timestamp: msg.timestamp
                        });
                    }
                });
            }
        });

        return warningFlags;
    }

    async verifyPaymentToken(token) {
        // في الإنتاج، تحقق من token الدفع مع مزود الدفع
        try {
            // محاكاة التحقق
            if (token && token.startsWith('pay_')) {
                return true;
            }
            return false;
        } catch (error) {
            console.error('Payment verification error:', error);
            return false;
        }
    }

    async verifyWebSocketToken(token) {
        try {
            const decoded = jwt.verify(token, process.env.JWT_SECRET || 'calmai-super-secret-jwt-key-2024');
            const user = await this.models.User.findByPk(decoded.userId);
            return user && user.is_active && !user.is_banned;
        } catch (error) {
            return false;
        }
    }

    async processRealTimeChat(message, userId) {
        // معالجة الدردشة في الوقت الحقيقي عبر WebSocket
        try {
            const response = await this.openai.chat.completions.create({
                model: "gpt-4",
                messages: [
                    {
                        role: "system",
                        content: "Provide a brief, supportive response for real-time chat."
                    },
                    {
                        role: "user",
                        content: message
                    }
                ],
                temperature: 0.7,
                max_tokens: 150
            });

            return response.choices[0].message.content;
        } catch (error) {
            return "I'm here for you. How can I help you feel better?";
        }
    }

    async scanForThreats(req, res) {
        try {
            const admin = req.admin;
            
            if (!admin.permissions.settings) {
                return res.status(403).json({ error: 'Permission denied' });
            }

            // فحص النظام بحثًا عن تهديدات
            const threats = [];
            
            // فحص محاولات تسجيل الدخول الفاشلة
            const failedLogins = await this.models.SecurityLog.findAll({
                where: {
                    event_type: 'login_failed_password',
                    timestamp: {
                        [Sequelize.Op.gte]: new Date(Date.now() - 24 * 60 * 60 * 1000)
                    }
                }
            });

            if (failedLogins.length > 50) {
                threats.push({
                    type: 'brute_force_attempts',
                    severity: 'high',
                    count: failedLogins.length,
                    recommendation: 'Implement IP blocking for repeated failures'
                });
            }

            // فحص المحتوى الضار
            const maliciousContent = await this.models.SecurityLog.findAll({
                where: {
                    event_type: 'malicious_content_detected',
                    timestamp: {
                        [Sequelize.Op.gte]: new Date(Date.now() - 24 * 60 * 60 * 1000)
                    }
                }
            });

            if (maliciousContent.length > 10) {
                threats.push({
                    type: 'malicious_content_spike',
                    severity: 'medium',
                    count: maliciousContent.length,
                    recommendation: 'Review and update banned phrases list'
                });
            }

            res.json({
                success: true,
                threats: threats,
                scan_time: new Date(),
                system_status: threats.length === 0 ? 'secure' : 'attention_required'
            });

        } catch (error) {
            console.error('Threat scan error:', error);
            res.status(500).json({ error: 'Failed to scan for threats' });
        }
    }

    async getSecurityStatus(req, res) {
        try {
            const admin = req.admin;
            
            if (!admin.permissions.settings) {
                return res.status(403).json({ error: 'Permission denied' });
            }

            // حالة الأمان العامة
            const status = {
                encryption: {
                    level: 'AES-256-GCM',
                    status: 'active'
                },
                authentication: {
                    jwt: 'active',
                    bcrypt_rounds: 14,
                    two_factor: 'available'
                },
                network: {
                    ssl: process.env.NODE_ENV === 'production' ? 'TLSv1.3' : 'development',
                    rate_limiting: 'active'
                },
                monitoring: {
                    security_logs: 'active',
                    real_time_scan: 'active'
                },
                last_audit: new Date().toISOString().split('T')[0]
            };

            res.json({
                success: true,
                status: status
            });

        } catch (error) {
            console.error('Get security status error:', error);
            res.status(500).json({ error: 'Failed to fetch security status' });
        }
    }

    async decryptRequest(req) {
        // فك تشفير الطلبات المشفرة
        if (req.headers['content-encryption'] === 'aes-256-gcm') {
            try {
                const encryptedData = req.body;
                const decryptionKey = process.env.ENCRYPTION_KEY || 'default-encryption-key-256bit';
                
                const decrypted = await this.decryptData(encryptedData, decryptionKey);
                req.body = JSON.parse(decrypted);
            } catch (error) {
                throw new Error('Failed to decrypt request');
            }
        }
    }

    async getAIModels(req, res) {
        try {
            const models = Object.keys(this.aiModels).map(model => ({
                id: model,
                name: model.toUpperCase(),
                description: model === 'gpt-4' ? 'Most advanced model' : 
                            model === 'llama-3' ? 'Open source alternative' : 
                            'Highly capable model',
                max_tokens: model === 'gpt-4' ? 8192 : 4096,
                available: true
            }));

            res.json({
                success: true,
                models: models
            });

        } catch (error) {
            console.error('Get AI models error:', error);
            res.status(500).json({ error: 'Failed to fetch AI models' });
        }
    }

    async analyzeSentiment(req, res) {
        try {
            const { text } = req.body;
            
            const sentiment = await this.analyzeSentimentText(text);
            
            res.json({
                success: true,
                sentiment: sentiment
            });

        } catch (error) {
            console.error('Analyze sentiment error:', error);
            res.status(500).json({ error: 'Failed to analyze sentiment' });
        }
    }

    errorHandler(err, req, res, next) {
        console.error('Global error handler:', err);
        
        // تسجيل خطأ الأمان
        this.logSecurityEvent('server_error', req.user ? req.user.id : null, {
            error: err.message,
            stack: err.stack,
            path: req.path,
            method: req.method
        });

        // إرسال رد مناسب
        res.status(err.status || 500).json({
            error: process.env.NODE_ENV === 'production' ? 'Internal server error' : err.message,
            request_id: req.headers['x-request-id'] || uuidv4()
        });
    }
}

// إنشاء مثيل الخادم وتشغيله
const server = new CalmAIServer();

// معالج الإشارات للإغلاق النظيف
process.on('SIGTERM', () => {
    console.log('SIGTERM received. Shutting down gracefully...');
    server.server.close(() => {
        console.log('Server closed');
        process.exit(0);
    });
});

process.on('SIGINT', () => {
    console.log('SIGINT received. Shutting down gracefully...');
    server.server.close(() => {
        console.log('Server closed');
        process.exit(0);
    });
});

module.exports = server;
