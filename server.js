// ========== CalmAI Server - النسخة الموحدة الكاملة ==========
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const compression = require('compression');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');
const hpp = require('hpp');
const morgan = require('morgan');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const http = require('http');
const socketIO = require('socket.io');
const redis = require('ioredis');
const cron = require('node-cron');
const nodemailer = require('nodemailer');
const validator = require('validator');
const moment = require('moment');
const { body, validationResult } = require('express-validator');

// ========== تهيئة التطبيق ==========
const app = express();
const server = http.createServer(app);
const io = socketIO(server, {
  cors: {
    origin: process.env.FRONTEND_URL || "http://localhost:3000",
    credentials: true
  }
});
const redisClient = new redis(process.env.REDIS_URL || 'redis://localhost:6379');

// ========== إنشاء المجلدات الافتراضية ==========
const defaultDirs = ['uploads', 'uploads/images', 'uploads/audio', 'uploads/videos', 'logs'];
defaultDirs.forEach(dir => {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
});

// ========== Middleware الأساسية ==========
app.use(helmet());
app.use(cors({
  origin: process.env.FRONTEND_URL || "http://localhost:3000",
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']
}));

const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000,
  max: parseInt(process.env.RATE_LIMIT_MAX) || 100,
  message: 'Too many requests from this IP, please try again later.'
});
app.use('/api/', limiter);

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(mongoSanitize());
app.use(xss());
app.use(hpp());
app.use(compression());

if (process.env.NODE_ENV === 'development') {
  app.use(morgan('dev'));
}

app.use('/uploads', express.static('uploads'));

// ========== نماذج MongoDB ==========

// نموذج المستخدم
const userSchema = new mongoose.Schema({
  firstName: { type: String, required: true, trim: true, minlength: 2, maxlength: 50 },
  lastName: { type: String, required: true, trim: true, minlength: 2, maxlength: 50 },
  username: { type: String, required: true, unique: true, lowercase: true, trim: true, minlength: 3, maxlength: 30 },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true, validate: validator.isEmail },
  password: { type: String, required: true, minlength: 8, select: false },
  gender: { type: String, enum: ['male', 'female'], default: 'male' },
  birthYear: { type: Number, min: 1900, max: new Date().getFullYear() - 13 },
  country: { type: String, default: 'SA', uppercase: true, maxlength: 2 },
  city: { type: String, trim: true },
  language: { type: String, enum: ['ar', 'en'], default: 'ar' },
  userId: { type: String, unique: true, uppercase: true },
  subscription: { type: String, enum: ['free', 'basic', 'pro', 'premium'], default: 'free' },
  subscriptionExpiry: { type: Date },
  adsWatched: { type: Number, default: 0, min: 0 },
  freeMessages: { type: Number, default: 20, min: 0 },
  totalMessagesSent: { type: Number, default: 0, min: 0 },
  isVerified: { type: Boolean, default: false },
  verificationCode: { type: String },
  verificationExpiry: { type: Date },
  resetPasswordToken: { type: String },
  resetPasswordExpiry: { type: Date },
  lastLogin: { type: Date },
  loginCount: { type: Number, default: 0, min: 0 },
  totalBreathingExercises: { type: Number, default: 0, min: 0 },
  totalMeditationTime: { type: Number, default: 0, min: 0 },
  totalGamesPlayed: { type: Number, default: 0, min: 0 },
  totalMusicMinutes: { type: Number, default: 0, min: 0 },
  streakDays: { type: Number, default: 0, min: 0 },
  lastActiveDate: { type: Date, default: Date.now },
  isActive: { type: Boolean, default: true },
  isBanned: { type: Boolean, default: false },
  banReason: { type: String },
  warnings: { type: Number, default: 0, max: 3 },
  role: { type: String, enum: ['user', 'moderator', 'admin', 'super_admin'], default: 'user' },
  permissions: [{ type: String }],
  devices: [{
    deviceId: String,
    deviceName: String,
    platform: String,
    lastUsed: Date,
    ipAddress: String,
    isCurrent: Boolean
  }],
  refreshTokens: [{
    token: String,
    expires: Date,
    device: String
  }],
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
}, { timestamps: true });

userSchema.pre('save', async function(next) {
  this.updatedAt = new Date();
  
  if (this.isModified('password')) {
    this.password = await bcrypt.hash(this.password, 12);
  }
  
  if (!this.userId) {
    const count = await mongoose.model('User').countDocuments();
    this.userId = `CAI-${(count + 1).toString().padStart(6, '0')}`;
  }
  
  next();
});

userSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

userSchema.methods.canSendMessage = function() {
  if (this.subscription !== 'free') return true;
  return this.freeMessages > 0;
};

userSchema.methods.useFreeMessage = async function() {
  if (this.subscription === 'free' && this.freeMessages > 0) {
    this.freeMessages -= 1;
    await this.save();
    return true;
  }
  return false;
};

const User = mongoose.model('User', userSchema);

// نموذج الدردشة
const chatSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  sessionId: { type: String, required: true, index: true },
  message: { type: String, required: true, trim: true, minlength: 1, maxlength: 2000 },
  response: { type: String, trim: true, maxlength: 5000 },
  language: { type: String, enum: ['ar', 'en'], default: 'ar' },
  sentiment: { type: String, enum: ['very_negative', 'negative', 'neutral', 'positive', 'very_positive'], default: 'neutral' },
  sentimentScore: { type: Number, min: -1, max: 1, default: 0 },
  category: { type: String, enum: ['stress', 'anxiety', 'depression', 'sleep', 'relationships', 'work', 'health', 'general', 'crisis'], default: 'general' },
  urgency: { type: String, enum: ['low', 'medium', 'high', 'crisis'], default: 'low' },
  isFlagged: { type: Boolean, default: false },
  flagReason: { type: String },
  metadata: {
    ipAddress: String,
    userAgent: String,
    device: String
  },
  createdAt: { type: Date, default: Date.now, index: true },
  updatedAt: { type: Date, default: Date.now }
}, { timestamps: true });

const Chat = mongoose.model('Chat', chatSchema);

// نموذج الموسيقى
const musicSchema = new mongoose.Schema({
  titleAr: { type: String, required: true, trim: true, maxlength: 100 },
  titleEn: { type: String, required: true, trim: true, maxlength: 100 },
  descriptionAr: { type: String, trim: true, maxlength: 500 },
  descriptionEn: { type: String, trim: true, maxlength: 500 },
  audioUrl: { type: String, required: true },
  thumbnailUrl: { type: String, default: '/defaults/music-thumbnail.jpg' },
  duration: { type: Number, required: true, min: 30, max: 7200 },
  category: { type: String, enum: ['relaxation', 'meditation', 'sleep', 'focus', 'nature', 'instrumental', 'healing', 'binaural'], required: true },
  isPremium: { type: Boolean, default: false },
  isActive: { type: Boolean, default: true },
  plays: { type: Number, default: 0, min: 0 },
  likes: { type: Number, default: 0, min: 0 },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  createdAt: { type: Date, default: Date.now }
}, { timestamps: true });

const Music = mongoose.model('Music', musicSchema);

// نموذج التمارين
const exerciseSchema = new mongoose.Schema({
  titleAr: { type: String, required: true, trim: true, maxlength: 100 },
  titleEn: { type: String, required: true, trim: true, maxlength: 100 },
  descriptionAr: { type: String, trim: true, maxlength: 500 },
  descriptionEn: { type: String, trim: true, maxlength: 500 },
  contentAr: { type: String, required: true },
  contentEn: { type: String, required: true },
  duration: { type: Number, required: true, min: 1, max: 180 },
  difficulty: { type: String, enum: ['beginner', 'intermediate', 'advanced'], default: 'beginner' },
  category: { type: String, enum: ['yoga', 'meditation', 'breathing', 'stretching', 'mindfulness', 'visualization', 'body_scan', 'gratitude', 'journaling'], required: true },
  isPremium: { type: Boolean, default: false },
  isActive: { type: Boolean, default: true },
  completions: { type: Number, default: 0, min: 0 },
  likes: { type: Number, default: 0, min: 0 },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  createdAt: { type: Date, default: Date.now }
}, { timestamps: true });

const Exercise = mongoose.model('Exercise', exerciseSchema);

// نموذج الإعلانات
const adSchema = new mongoose.Schema({
  title: { type: String, required: true, trim: true, maxlength: 100 },
  description: { type: String, trim: true, maxlength: 500 },
  imageUrl: { type: String, required: true },
  link: { type: String, required: true },
  targetCountries: [{ type: String, uppercase: true, maxlength: 2 }],
  targetGender: { type: String, enum: ['male', 'female', 'both'], default: 'both' },
  budget: { type: Number, required: true, min: 0 },
  spent: { type: Number, default: 0, min: 0 },
  impressions: { type: Number, default: 0, min: 0 },
  clicks: { type: Number, default: 0, min: 0 },
  status: { type: String, enum: ['draft', 'pending', 'active', 'paused', 'completed'], default: 'draft' },
  isActive: { type: Boolean, default: false },
  startDate: { type: Date, required: true },
  endDate: { type: Date, required: true },
  advertiserId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  createdAt: { type: Date, default: Date.now }
}, { timestamps: true });

const Ad = mongoose.model('Ad', adSchema);

// ========== دوال المساعدة ==========
const helpers = {
  generateVerificationCode: (length = 6) => {
    const chars = '0123456789';
    let code = '';
    for (let i = 0; i < length; i++) {
      code += chars[Math.floor(Math.random() * chars.length)];
    }
    return code;
  },
  
  generateUniqueId: (prefix = '') => {
    const timestamp = Date.now().toString(36);
    const random = Math.random().toString(36).substr(2, 5);
    return `${prefix}${timestamp}${random}`.toUpperCase();
  }
};

// ========== مصادقة التوكن ==========
const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({ success: false, error: 'مطلوب توكن للوصول' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId).select('-password');
    
    if (!user) return res.status(401).json({ success: false, error: 'المستخدم غير موجود' });
    if (!user.isActive) return res.status(403).json({ success: false, error: 'الحساب غير مفعل' });
    if (user.isBanned) return res.status(403).json({ success: false, error: 'الحساب محظور', reason: user.banReason });

    req.user = user;
    next();
  } catch (error) {
    if (error.name === 'JsonWebTokenError') {
      return res.status(403).json({ success: false, error: 'توكن غير صالح' });
    }
    if (error.name === 'TokenExpiredError') {
      return res.status(403).json({ success: false, error: 'انتهت صلاحية التوكن' });
    }
    res.status(500).json({ success: false, error: 'خطأ في المصادقة' });
  }
};

const authenticateAdmin = (req, res, next) => {
  if (!req.user || !['admin', 'super_admin'].includes(req.user.role)) {
    return res.status(403).json({ success: false, error: 'صلاحيات غير كافية' });
  }
  next();
};

const generateTokens = (user) => {
  const accessToken = jwt.sign(
    { userId: user._id, email: user.email, role: user.role, subscription: user.subscription },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN || '7d' }
  );

  const refreshToken = jwt.sign(
    { userId: user._id },
    process.env.JWT_REFRESH_SECRET,
    { expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '30d' }
  );

  return { accessToken, refreshToken };
};

// ========== رفع الملفات ==========
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    let folder = 'uploads';
    if (file.mimetype.startsWith('image/')) folder = 'uploads/images';
    else if (file.mimetype.startsWith('audio/')) folder = 'uploads/audio';
    else if (file.mimetype.startsWith('video/')) folder = 'uploads/videos';
    
    if (!fs.existsSync(folder)) fs.mkdirSync(folder, { recursive: true });
    cb(null, folder);
  },
  filename: (req, file, cb) => {
    const uniqueName = crypto.randomBytes(16).toString('hex');
    const extension = path.extname(file.originalname);
    cb(null, `${uniqueName}${extension}`);
  }
});

const upload = multer({
  storage: storage,
  limits: { fileSize: parseInt(process.env.MAX_FILE_SIZE) || 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowedTypes = process.env.ALLOWED_FILE_TYPES || 'image/jpeg,image/png,image/gif,audio/mpeg,audio/mp3,video/mp4';
    const allowedMimeTypes = allowedTypes.split(',');
    allowedMimeTypes.includes(file.mimetype) ? cb(null, true) : cb(new Error('نوع الملف غير مسموح'), false);
  }
});

// ========== التحقق من المدخلات ==========
const validate = (validations) => {
  return async (req, res, next) => {
    await Promise.all(validations.map(validation => validation.run(req)));
    const errors = validationResult(req);
    
    if (errors.isEmpty()) return next();
    
    const errorMessages = errors.array().map(err => ({
      field: err.path,
      message: err.msg
    }));
    
    return res.status(400).json({
      success: false,
      message: 'أخطاء في التحقق',
      errors: errorMessages
    });
  };
};

// ========== البريد الإلكتروني ==========
const emailTransporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: parseInt(process.env.EMAIL_PORT) || 587,
  secure: false,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

const sendEmail = async (to, subject, html) => {
  try {
    await emailTransporter.sendMail({
      from: process.env.EMAIL_FROM || `"CalmAI" <${process.env.EMAIL_USER}>`,
      to,
      subject,
      html
    });
    return { success: true };
  } catch (error) {
    console.error('Email error:', error);
    return { success: false, error: error.message };
  }
};

// ========== الردود الذكية (محاكاة الذكاء الاصطناعي) ==========
const aiResponses = {
  generateResponse: (message, language = 'ar') => {
    const responsesAr = [
      "أنا هنا لمساعدتك. هل يمكنك أن تخبرني أكثر عن ما تشعر به؟",
      "شكراً لمشاركة مشاعرك. حاول أن تأخذ نفساً عميقاً وتسترخي قليلاً.",
      "أفهم ما تمر به. تذكر أن المشاعر مؤقتة وأنت أقوى مما تظن.",
      "دعنا نركز على الحلول معاً. ما هو أول شيء يمكنك فعله لتحسين حالتك؟",
      "لا بأس أن تشعر بهذه الطريقة. الجميع يمر بأوقات صعبة."
    ];
    
    const responsesEn = [
      "I'm here to help you. Can you tell me more about how you're feeling?",
      "Thank you for sharing your feelings. Try to take a deep breath and relax a bit.",
      "I understand what you're going through. Remember that feelings are temporary and you're stronger than you think.",
      "Let's focus on solutions together. What's the first thing you can do to improve your situation?",
      "It's okay to feel this way. Everyone goes through difficult times."
    ];
    
    const responses = language === 'ar' ? responsesAr : responsesEn;
    return responses[Math.floor(Math.random() * responses.length)];
  }
};

// ========== إدارة Socket.IO ==========
const onlineUsers = new Map();
const userSockets = new Map();

io.on('connection', (socket) => {
  console.log('🔌 New client connected:', socket.id);

  socket.on('authenticate', async (token) => {
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      const user = await User.findById(decoded.userId);
      
      if (user) {
        onlineUsers.set(socket.id, user._id);
        userSockets.set(user._id.toString(), socket.id);
        
        socket.join(`user_${user._id}`);
        socket.emit('authenticated', {
          userId: user._id,
          username: user.username,
          subscription: user.subscription
        });
        
        await redisClient.setex(`user:online:${user._id}`, 300, 'true');
        console.log(`✅ User authenticated: ${user.username} (${socket.id})`);
      }
    } catch (error) {
      socket.emit('authentication_error', { message: 'Authentication failed' });
    }
  });

  socket.on('chat_message', async (data) => {
    try {
      const { userId, message, language = 'ar' } = data;
      
      if (!userId || !message) {
        socket.emit('chat_error', { message: 'Invalid message data' });
        return;
      }

      const user = await User.findById(userId);
      if (!user) {
        socket.emit('chat_error', { message: 'User not found' });
        return;
      }

      // التحقق من الرسائل المجانية
      if (user.subscription === 'free') {
        if (user.freeMessages <= 0) {
          socket.emit('free_messages_exhausted', {
            message: language === 'ar'
              ? 'لقد استنفدت عدد الرسائل المجانية. يرجى ترقية اشتراكك أو مشاهدة إعلان'
              : 'You have exhausted your free messages. Please upgrade your subscription or watch an ad'
          });
          return;
        }
        user.freeMessages -= 1;
        await user.save();
      }

      // حفظ الرسالة
      const chat = new Chat({
        userId: userId,
        sessionId: socket.id,
        message: message,
        language: language,
        metadata: {
          ipAddress: socket.handshake.address,
          userAgent: socket.handshake.headers['user-agent']
        }
      });
      
      await chat.save();
      
      // تحديث إحصائيات المستخدم
      user.totalMessagesSent += 1;
      user.lastActiveDate = new Date();
      await user.save();

      // محاكاة معالجة الذكاء الاصطناعي
      setTimeout(async () => {
        try {
          const aiResponse = aiResponses.generateResponse(message, language);
          
          chat.response = aiResponse;
          chat.responseTime = Date.now() - chat.createdAt;
          await chat.save();
          
          socket.emit('chat_response', {
            response: aiResponse,
            timestamp: new Date(),
            messageId: chat._id
          });
        } catch (error) {
          socket.emit('chat_error', { message: 'An error occurred' });
        }
      }, 1000);
      
    } catch (error) {
      socket.emit('chat_error', { message: 'An error occurred' });
    }
  });

  socket.on('disconnect', async () => {
    const userId = onlineUsers.get(socket.id);
    if (userId) {
      onlineUsers.delete(socket.id);
      userSockets.delete(userId.toString());
      await redisClient.del(`user:online:${userId}`);
      console.log(`❌ User disconnected: ${userId} (${socket.id})`);
    }
  });
});

// ========== Routes ==========

// ---- المصادقة ----
app.post('/api/v1/auth/signup', 
  validate([
    body('firstName').trim().notEmpty().withMessage('الاسم الأول مطلوب'),
    body('lastName').trim().notEmpty().withMessage('اسم العائلة مطلوب'),
    body('username').trim().notEmpty().withMessage('اسم المستخدم مطلوب'),
    body('email').trim().notEmpty().withMessage('البريد الإلكتروني مطلوب').isEmail().withMessage('بريد إلكتروني غير صالح'),
    body('password').notEmpty().withMessage('كلمة المرور مطلوبة').isLength({ min: 8 }).withMessage('كلمة المرور يجب أن تكون على الأقل 8 أحرف'),
    body('confirmPassword').custom((value, { req }) => value === req.body.password).withMessage('كلمتا المرور غير متطابقتين')
  ]),
  async (req, res) => {
    try {
      const { firstName, lastName, username, email, password } = req.body;

      const existingUser = await User.findOne({
        $or: [{ email: email.toLowerCase() }, { username: username.toLowerCase() }]
      });

      if (existingUser) {
        return res.status(400).json({
          success: false,
          error: existingUser.email === email.toLowerCase() 
            ? 'البريد الإلكتروني مسجل مسبقاً'
            : 'اسم المستخدم مسجل مسبقاً'
        });
      }

      const verificationCode = helpers.generateVerificationCode();
      const user = new User({
        firstName,
        lastName,
        username: username.toLowerCase(),
        email: email.toLowerCase(),
        password,
        verificationCode,
        verificationExpiry: new Date(Date.now() + 10 * 60 * 1000)
      });

      await user.save();

      // إرسال بريد التحقق
      const verificationLink = `${process.env.FRONTEND_URL}/verify-email?code=${verificationCode}&email=${user.email}`;
      await sendEmail(user.email, 'تأكيد بريدك الإلكتروني - CalmAI', `
        <h2>مرحباً ${user.firstName}!</h2>
        <p>شكراً لتسجيلك في CalmAI. رمز التحقق الخاص بك هو: <strong>${verificationCode}</strong></p>
        <p>أو يمكنك النقر على الرابط: <a href="${verificationLink}">تأكيد البريد الإلكتروني</a></p>
        <p>ينتهي الرمز خلال 10 دقائق.</p>
      `);

      res.status(201).json({
        success: true,
        message: 'تم إنشاء الحساب بنجاح',
        data: { userId: user.userId, email: user.email, verificationRequired: true }
      });
    } catch (error) {
      res.status(500).json({ success: false, error: 'حدث خطأ أثناء إنشاء الحساب' });
    }
  }
);

app.post('/api/v1/auth/login', 
  validate([
    body('email').trim().notEmpty().withMessage('البريد الإلكتروني مطلوب').isEmail().withMessage('بريد إلكتروني غير صالح'),
    body('password').notEmpty().withMessage('كلمة المرور مطلوبة')
  ]),
  async (req, res) => {
    try {
      const { email, password } = req.body;
      const user = await User.findOne({ email: email.toLowerCase() }).select('+password');

      if (!user) {
        return res.status(401).json({ success: false, error: 'البريد الإلكتروني أو كلمة المرور غير صحيحة' });
      }

      if (!user.isActive) return res.status(403).json({ success: false, error: 'الحساب غير مفعل' });
      if (user.isBanned) return res.status(403).json({ success: false, error: 'الحساب محظور', reason: user.banReason });

      const isValidPassword = await user.comparePassword(password);
      if (!isValidPassword) {
        return res.status(401).json({ success: false, error: 'البريد الإلكتروني أو كلمة المرور غير صحيحة' });
      }

      if (!user.isVerified) {
        return res.status(200).json({
          success: true,
          message: 'يرجى التحقق من بريدك الإلكتروني',
          verificationRequired: true,
          email: user.email
        });
      }

      user.lastLogin = new Date();
      user.loginCount += 1;
      await user.save();

      const { accessToken, refreshToken } = generateTokens(user);
      
      user.refreshTokens.push({
        token: refreshToken,
        expires: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
        device: req.headers['user-agent'] || 'Unknown'
      });
      await user.save();

      res.json({
        success: true,
        message: 'تم تسجيل الدخول بنجاح',
        data: {
          user: {
            id: user._id,
            userId: user.userId,
            firstName: user.firstName,
            lastName: user.lastName,
            email: user.email,
            username: user.username,
            subscription: user.subscription,
            language: user.language,
            freeMessages: user.freeMessages
          },
          tokens: { accessToken, refreshToken }
        }
      });
    } catch (error) {
      res.status(500).json({ success: false, error: 'حدث خطأ أثناء تسجيل الدخول' });
    }
  }
);

app.post('/api/v1/auth/verify-email', async (req, res) => {
  try {
    const { email, code } = req.body;
    const user = await User.findOne({
      email: email.toLowerCase(),
      verificationCode: code,
      verificationExpiry: { $gt: new Date() }
    });

    if (!user) {
      return res.status(400).json({ success: false, error: 'رمز التحقق غير صالح أو منتهي الصلاحية' });
    }

    user.isVerified = true;
    user.verificationCode = null;
    user.verificationExpiry = null;
    await user.save();

    const { accessToken, refreshToken } = generateTokens(user);

    res.json({
      success: true,
      message: 'تم تفعيل الحساب بنجاح',
      data: {
        user: {
          id: user._id,
          userId: user.userId,
          firstName: user.firstName,
          lastName: user.lastName,
          email: user.email
        },
        tokens: { accessToken, refreshToken }
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, error: 'حدث خطأ أثناء التحقق' });
  }
});

// ---- المستخدمين ----
app.get('/api/v1/users/me', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select('-password');
    res.json({ success: true, data: { user } });
  } catch (error) {
    res.status(500).json({ success: false, error: 'حدث خطأ أثناء جلب البيانات' });
  }
});

app.put('/api/v1/users/profile', authenticateToken, async (req, res) => {
  try {
    const updates = req.body;
    const allowedUpdates = ['firstName', 'lastName', 'gender', 'birthYear', 'country', 'city', 'language'];
    
    const filteredUpdates = {};
    Object.keys(updates).forEach(key => {
      if (allowedUpdates.includes(key)) filteredUpdates[key] = updates[key];
    });

    const user = await User.findByIdAndUpdate(
      req.user._id,
      filteredUpdates,
      { new: true, runValidators: true }
    ).select('-password');

    res.json({
      success: true,
      message: 'تم تحديث الملف الشخصي بنجاح',
      data: { user }
    });
  } catch (error) {
    res.status(500).json({ success: false, error: 'حدث خطأ أثناء التحديث' });
  }
});

app.get('/api/v1/users/stats', authenticateToken, async (req, res) => {
  try {
    const stats = {
      totalMessages: req.user.totalMessagesSent,
      freeMessages: req.user.freeMessages,
      totalMeditation: req.user.totalMeditationTime,
      totalExercises: req.user.totalBreathingExercises,
      totalGames: req.user.totalGamesPlayed,
      streakDays: req.user.streakDays,
      subscription: req.user.subscription
    };
    
    res.json({ success: true, data: { stats } });
  } catch (error) {
    res.status(500).json({ success: false, error: 'حدث خطأ' });
  }
});

// ---- المحتوى ----
app.get('/api/v1/content/music', authenticateToken, async (req, res) => {
  try {
    const { category, limit = 20, page = 1 } = req.query;
    const query = { isActive: true };
    if (category) query.category = category;
    
    const music = await Music.find(query)
      .skip((page - 1) * limit)
      .limit(parseInt(limit))
      .sort({ createdAt: -1 });
    
    const total = await Music.countDocuments(query);
    
    res.json({
      success: true,
      data: { music, total, page: parseInt(page), totalPages: Math.ceil(total / limit) }
    });
  } catch (error) {
    res.status(500).json({ success: false, error: 'حدث خطأ' });
  }
});

app.get('/api/v1/content/exercises', authenticateToken, async (req, res) => {
  try {
    const { category, difficulty, limit = 20, page = 1 } = req.query;
    const query = { isActive: true };
    if (category) query.category = category;
    if (difficulty) query.difficulty = difficulty;
    
    const exercises = await Exercise.find(query)
      .skip((page - 1) * limit)
      .limit(parseInt(limit))
      .sort({ createdAt: -1 });
    
    const total = await Exercise.countDocuments(query);
    
    res.json({
      success: true,
      data: { exercises, total, page: parseInt(page), totalPages: Math.ceil(total / limit) }
    });
  } catch (error) {
    res.status(500).json({ success: false, error: 'حدث خطأ' });
  }
});

// ---- الدردشة ----
app.get('/api/v1/chat/history', authenticateToken, async (req, res) => {
  try {
    const { limit = 50, page = 1 } = req.query;
    const chats = await Chat.find({ userId: req.user._id })
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(parseInt(limit));
    
    const total = await Chat.countDocuments({ userId: req.user._id });
    
    res.json({
      success: true,
      data: { chats, total, page: parseInt(page) }
    });
  } catch (error) {
    res.status(500).json({ success: false, error: 'حدث خطأ' });
  }
});

// ---- الإعلانات ----
app.get('/api/v1/ads', authenticateToken, async (req, res) => {
  try {
    const ads = await Ad.find({ 
      isActive: true,
      status: 'active',
      startDate: { $lte: new Date() },
      endDate: { $gte: new Date() }
    }).limit(10);
    
    res.json({ success: true, data: { ads } });
  } catch (error) {
    res.status(500).json({ success: false, error: 'حدث خطأ' });
  }
});

app.post('/api/v1/ads/:id/click', authenticateToken, async (req, res) => {
  try {
    const ad = await Ad.findById(req.params.id);
    if (!ad) return res.status(404).json({ success: false, error: 'الإعلان غير موجود' });
    
    ad.clicks += 1;
    await ad.save();
    
    // منح المستخدم رصيد
    const user = req.user;
    user.adsWatched += 1;
    await user.save();
    
    res.json({ success: true, message: 'تم تسجيل النقرة' });
  } catch (error) {
    res.status(500).json({ success: false, error: 'حدث خطأ' });
  }
});

// ---- الإدارة ----
app.get('/api/v1/admin/dashboard', authenticateToken, authenticateAdmin, async (req, res) => {
  try {
    const [
      totalUsers,
      activeUsers,
      premiumUsers,
      totalMessages,
      totalAds
    ] = await Promise.all([
      User.countDocuments(),
      User.countDocuments({ isActive: true, isBanned: false }),
      User.countDocuments({ subscription: { $ne: 'free' } }),
      Chat.countDocuments(),
      Ad.countDocuments()
    ]);
    
    const dashboard = {
      users: { total: totalUsers, active: activeUsers, premium: premiumUsers, online: onlineUsers.size },
      content: { totalMessages },
      ads: { total: totalAds }
    };
    
    res.json({ success: true, data: { dashboard } });
  } catch (error) {
    res.status(500).json({ success: false, error: 'حدث خطأ' });
  }
});

app.get('/api/v1/admin/users', authenticateToken, authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 20, search = '' } = req.query;
    const query = {};
    
    if (search) {
      query.$or = [
        { email: { $regex: search, $options: 'i' } },
        { username: { $regex: search, $options: 'i' } },
        { firstName: { $regex: search, $options: 'i' } },
        { lastName: { $regex: search, $options: 'i' } }
      ];
    }
    
    const users = await User.find(query)
      .select('-password')
      .skip((page - 1) * limit)
      .limit(parseInt(limit))
      .sort({ createdAt: -1 });
    
    const total = await User.countDocuments(query);
    
    res.json({
      success: true,
      data: { users, total, page: parseInt(page), totalPages: Math.ceil(total / limit) }
    });
  } catch (error) {
    res.status(500).json({ success: false, error: 'حدث خطأ' });
  }
});

app.post('/api/v1/admin/users/:id/ban', authenticateToken, authenticateAdmin, async (req, res) => {
  try {
    const { reason } = req.body;
    const user = await User.findById(req.params.id);
    
    if (!user) return res.status(404).json({ success: false, error: 'المستخدم غير موجود' });
    
    user.isBanned = true;
    user.banReason = reason;
    user.bannedAt = new Date();
    user.bannedBy = req.user._id;
    await user.save();
    
    // إرسال بريد إشعار
    await sendEmail(user.email, 'تم حظر حسابك - CalmAI', `
      <h2>عزيزي ${user.firstName},</h2>
      <p>تم حظر حسابك في CalmAI للأسباب التالية:</p>
      <p><strong>${reason}</strong></p>
      <p>إذا كنت تعتقد أن هذا خطأ، فيمكنك التواصل مع الدعم.</p>
    `);
    
    res.json({ success: true, message: 'تم حظر المستخدم بنجاح' });
  } catch (error) {
    res.status(500).json({ success: false, error: 'حدث خطأ' });
  }
});

// ---- الاشتراكات ----
app.get('/api/v1/subscription/plans', authenticateToken, async (req, res) => {
  const plans = {
    free: {
      name: 'مجاني',
      price: 0,
      features: ['20 رسالة مجانية', 'محتوى أساسي', 'إعلانات'],
      messageLimit: 20
    },
    basic: {
      name: 'أساسي',
      price: 29,
      features: ['رسائل غير محدودة', 'محتوى كامل', 'إعلانات محدودة'],
      messageLimit: -1
    },
    pro: {
      name: 'محترف',
      price: 79,
      features: ['بدون إعلانات', 'دعم أولوية', 'محتوى حصري'],
      messageLimit: -1
    },
    premium: {
      name: 'متميز',
      price: 149,
      features: ['جلسات خاصة', 'دعم 24/7', 'جميع المزايا'],
      messageLimit: -1
    }
  };
  
  res.json({ success: true, data: { plans } });
});

app.post('/api/v1/subscription/upgrade', authenticateToken, async (req, res) => {
  try {
    const { plan } = req.body;
    const user = req.user;
    
    const plans = ['free', 'basic', 'pro', 'premium'];
    if (!plans.includes(plan)) {
      return res.status(400).json({ success: false, error: 'خطة غير صالحة' });
    }
    
    user.subscription = plan;
    user.subscriptionExpiry = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 يوم
    await user.save();
    
    // إرسال بريد التأكيد
    await sendEmail(user.email, 'تم ترقية اشتراكك - CalmAI', `
      <h2>تهانياً ${user.firstName}!</h2>
      <p>تم ترقية اشتراكك إلى الخطة <strong>${plan}</strong> بنجاح.</p>
      <p>تنتهي صلاحية الاشتراك في: ${user.subscriptionExpiry.toLocaleDateString('ar-SA')}</p>
      <p>استمتع بمزاياك الجديدة!</p>
    `);
    
    res.json({ success: true, message: 'تم ترقية الاشتراك بنجاح' });
  } catch (error) {
    res.status(500).json({ success: false, error: 'حدث خطأ' });
  }
});

// ========== المهام المجدولة ==========
cron.schedule('0 0 * * *', async () => {
  try {
    // تجديد الرسائل المجانية للمستخدمين المجانيين
    await User.updateMany(
      { subscription: 'free', isActive: true, isBanned: false },
      { $set: { freeMessages: 20 } }
    );
    console.log('🔄 تم تجديد الرسائل المجانية');
  } catch (error) {
    console.error('Error in scheduled task:', error);
  }
});

// ========== نقاط التفتيش ==========
app.get('/health', async (req, res) => {
  try {
    const dbStatus = mongoose.connection.readyState === 1 ? 'connected' : 'disconnected';
    const redisStatus = await redisClient.ping() === 'PONG' ? 'connected' : 'disconnected';
    
    res.json({
      status: 'healthy',
      timestamp: new Date(),
      database: dbStatus,
      redis: redisStatus,
      onlineUsers: onlineUsers.size
    });
  } catch (error) {
    res.status(500).json({ status: 'unhealthy', error: error.message });
  }
});

// ========== معالجة الأخطاء ==========
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    error: 'الصفحة غير موجودة',
    path: req.originalUrl
  });
});

app.use((err, req, res, next) => {
  console.error('Global Error:', err);
  res.status(500).json({
    success: false,
    error: 'حدث خطأ داخلي في السيرفر',
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
  });
});

// ========== اتصال قاعدة البيانات وتشغيل السيرفر ==========
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/calmai', {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('✅ MongoDB connected successfully'))
.catch(err => {
  console.error('❌ MongoDB connection error:', err);
  process.exit(1);
});

const PORT = process.env.PORT || 5000;

server.listen(PORT, () => {
  console.log(`
  🚀 CalmAI Server Started Successfully!
  
  📍 Port: ${PORT}
  🌐 Environment: ${process.env.NODE_ENV || 'development'}
  🔌 WebSocket: ws://localhost:${PORT}
  
  🔗 Health Check: http://localhost:${PORT}/health
  
  ⏰ Scheduled tasks are running...
  `);
});

// ========== الإغلاق الناعم ==========
process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);

function gracefulShutdown() {
  console.log('🛑 Closing server gracefully...');
  
  server.close(async () => {
    await mongoose.connection.close();
    await redisClient.quit();
    console.log('👋 Server shutdown complete');
    process.exit(0);
  });
  
  setTimeout(() => {
    console.error('⏰ Forcing shutdown');
    process.exit(1);
  }, 10000);
}
