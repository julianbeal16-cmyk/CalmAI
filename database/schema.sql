-- Create database
CREATE DATABASE IF NOT EXISTS calmai_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE calmai_db;

-- Users table
CREATE TABLE users (
    id VARCHAR(36) PRIMARY KEY DEFAULT (UUID()),
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    username VARCHAR(100) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    email_verified BOOLEAN DEFAULT FALSE,
    verification_token VARCHAR(100),
    verification_expires DATETIME,
    reset_token VARCHAR(100),
    reset_expires DATETIME,
    subscription_type ENUM('free', 'premium') DEFAULT 'free',
    subscription_expires DATETIME,
    messages_used INT DEFAULT 0,
    ads_watched INT DEFAULT 0,
    language ENUM('en', 'ar') DEFAULT 'en',
    is_banned BOOLEAN DEFAULT FALSE,
    banned_reason TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_email (email),
    INDEX idx_username (username),
    INDEX idx_subscription (subscription_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Admin settings table
CREATE TABLE admin_settings (
    id INT PRIMARY KEY AUTO_INCREMENT,
    setting_key VARCHAR(100) UNIQUE NOT NULL,
    setting_value TEXT,
    setting_type ENUM('string', 'number', 'boolean', 'json') DEFAULT 'string',
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Games table
CREATE TABLE games (
    id INT PRIMARY KEY AUTO_INCREMENT,
    title_en VARCHAR(255) NOT NULL,
    title_ar VARCHAR(255),
    description_en TEXT,
    description_ar TEXT,
    game_code LONGTEXT NOT NULL,
    game_type ENUM('html', 'link') NOT NULL,
    game_url VARCHAR(500),
    category VARCHAR(100),
    is_active BOOLEAN DEFAULT TRUE,
    created_by VARCHAR(36),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Exercises table
CREATE TABLE exercises (
    id INT PRIMARY KEY AUTO_INCREMENT,
    title_en VARCHAR(255) NOT NULL,
    title_ar VARCHAR(255),
    description_en TEXT,
    description_ar TEXT,
    content_en LONGTEXT,
    content_ar LONGTEXT,
    duration_minutes INT,
    difficulty ENUM('easy', 'medium', 'hard'),
    category ENUM('yoga', 'meditation', 'breathing', 'relaxation'),
    is_active BOOLEAN DEFAULT TRUE,
    created_by VARCHAR(36),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Media content table
CREATE TABLE media_content (
    id INT PRIMARY KEY AUTO_INCREMENT,
    title_en VARCHAR(255) NOT NULL,
    title_ar VARCHAR(255),
    description_en TEXT,
    description_ar TEXT,
    media_url TEXT NOT NULL,
    media_type ENUM('music', 'video', 'article', 'link'),
    thumbnail_url TEXT,
    duration_seconds INT,
    is_active BOOLEAN DEFAULT TRUE,
    created_by VARCHAR(36),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Notifications table
CREATE TABLE notifications (
    id INT PRIMARY KEY AUTO_INCREMENT,
    title_en VARCHAR(255) NOT NULL,
    title_ar VARCHAR(255),
    content_en TEXT NOT NULL,
    content_ar TEXT,
    notification_type ENUM('info', 'warning', 'success', 'promotion'),
    target_users ENUM('all', 'free', 'premium', 'specific') DEFAULT 'all',
    is_active BOOLEAN DEFAULT TRUE,
    starts_at DATETIME,
    expires_at DATETIME,
    created_by VARCHAR(36),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Payment plans table
CREATE TABLE payment_plans (
    id INT PRIMARY KEY AUTO_INCREMENT,
    name_en VARCHAR(255) NOT NULL,
    name_ar VARCHAR(255),
    description_en TEXT,
    description_ar TEXT,
    price DECIMAL(10, 2) NOT NULL,
    currency VARCHAR(3) DEFAULT 'USD',
    duration_days INT NOT NULL,
    messages_limit INT NOT NULL,
    features JSON,
    is_active BOOLEAN DEFAULT TRUE,
    stripe_price_id VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- User payments table
CREATE TABLE user_payments (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id VARCHAR(36) NOT NULL,
    plan_id INT NOT NULL,
    amount DECIMAL(10, 2) NOT NULL,
    currency VARCHAR(3) DEFAULT 'USD',
    payment_method VARCHAR(50),
    transaction_id VARCHAR(100) UNIQUE,
    status ENUM('pending', 'completed', 'failed', 'refunded') DEFAULT 'pending',
    starts_at DATETIME,
    expires_at DATETIME,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (plan_id) REFERENCES payment_plans(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- AI chat logs (only for moderation, not storing conversations)
CREATE TABLE ai_chat_logs (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id VARCHAR(36) NOT NULL,
    message_hash VARCHAR(64) NOT NULL, -- Hash of the message for privacy
    violation_type ENUM('none', 'inappropriate', 'harmful', 'banned_topic') DEFAULT 'none',
    is_reviewed BOOLEAN DEFAULT FALSE,
    reviewed_by VARCHAR(36),
    review_notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (reviewed_by) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_message_hash (message_hash)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Banned words/phrases for AI moderation
CREATE TABLE banned_content (
    id INT PRIMARY KEY AUTO_INCREMENT,
    content_type ENUM('word', 'phrase', 'topic') NOT NULL,
    content_en VARCHAR(500) NOT NULL,
    content_ar VARCHAR(500),
    severity ENUM('low', 'medium', 'high') DEFAULT 'medium',
    action ENUM('flag', 'block', 'warn') DEFAULT 'block',
    is_active BOOLEAN DEFAULT TRUE,
    created_by VARCHAR(36),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Ads campaigns table
CREATE TABLE ad_campaigns (
    id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(255) NOT NULL,
    ad_type ENUM('banner', 'interstitial', 'rewarded') NOT NULL,
    ad_code LONGTEXT,
    ad_url VARCHAR(500),
    reward_messages INT DEFAULT 5,
    impressions INT DEFAULT 0,
    clicks INT DEFAULT 0,
    budget DECIMAL(10, 2),
    is_active BOOLEAN DEFAULT TRUE,
    starts_at DATETIME,
    ends_at DATETIME,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- User ad views table
CREATE TABLE user_ad_views (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id VARCHAR(36) NOT NULL,
    ad_id INT NOT NULL,
    view_type ENUM('impression', 'click', 'reward') NOT NULL,
    messages_earned INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (ad_id) REFERENCES ad_campaigns(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Insert default admin settings
INSERT INTO admin_settings (setting_key, setting_value, setting_type, description) VALUES
('privacy_policy_en', 'Default privacy policy text...', 'string', 'Privacy Policy in English'),
('privacy_policy_ar', 'نص سياسة الخصوصية الافتراضي...', 'string', 'Privacy Policy in Arabic'),
('terms_of_service_en', 'Default terms of service...', 'string', 'Terms of Service in English'),
('terms_of_service_ar', 'نص شروط الخدمة الافتراضي...', 'string', 'Terms of Service in Arabic'),
('free_messages_limit', '20', 'number', 'Free messages per day'),
('ad_reward_messages', '5', 'number', 'Messages earned per ad watched'),
('site_name_en', 'CalmAI', 'string', 'Site name in English'),
('site_name_ar', 'كالم إيه آي', 'string', 'Site name in Arabic'),
('welcome_message_en', 'Your safe space for mental wellness and support', 'string', 'Welcome message in English'),
('welcome_message_ar', 'مساحتك الآمنة للراحة النفسية والدعم', 'string', 'Welcome message in Arabic'),
('default_language', 'en', 'string', 'Default site language');

-- Insert default payment plan
INSERT INTO payment_plans (name_en, name_ar, description_en, description_ar, price, duration_days, messages_limit, features) VALUES
('Weekly Premium', 'بريميوم أسبوعي', '100 AI messages for 7 days', '١٠٠ رسالة ذكاء اصطناعي لمدة ٧ أيام', 10.00, 7, 100, '["Unlimited access to games", "Premium support", "No ads"]');

-- Create admin user (password will be hashed in app)
-- Default password: Admin123!
INSERT INTO users (id, first_name, last_name, username, email, password_hash, email_verified, subscription_type) 
VALUES ('admin-1234-5678', 'Admin', 'System', 'admin', 'admin@calmai.com', '$2a$12$YourHashedPasswordHere', TRUE, 'premium');
