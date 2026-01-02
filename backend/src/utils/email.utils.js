const nodemailer = require('nodemailer');
const fs = require('fs').promises;
const path = require('path');
require('dotenv').config();

class EmailService {
    constructor() {
        this.transporter = nodemailer.createTransport({
            host: process.env.EMAIL_HOST,
            port: process.env.EMAIL_PORT,
            secure: process.env.EMAIL_PORT == 465,
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASSWORD
            },
            tls: {
                rejectUnauthorized: false
            }
        });
        
        // Load email templates
        this.loadTemplates();
    }
    
    async loadTemplates() {
        try {
            const templatesDir = path.join(__dirname, '../../templates');
            
            this.templates = {
                verification: await fs.readFile(
                    path.join(templatesDir, 'verification.html'),
                    'utf8'
                ),
                welcome: await fs.readFile(
                    path.join(templatesDir, 'welcome.html'),
                    'utf8'
                ),
                resetPassword: await fs.readFile(
                    path.join(templatesDir, 'reset-password.html'),
                    'utf8'
                )
            };
        } catch (error) {
            console.error('Error loading email templates:', error);
            this.templates = {
                verification: '<p>Please verify your email: {{verificationLink}}</p>',
                welcome: '<h1>Welcome to CalmAI!</h1>',
                resetPassword: '<p>Reset password: {{resetLink}}</p>'
            };
        }
    }
    
    async sendVerificationEmail(email, name, verificationLink, language = 'en') {
        const subject = language === 'ar' 
            ? 'تفعيل حسابك في CalmAI'
            : 'Verify Your CalmAI Account';
        
        const template = this.templates.verification
            .replace(/{{name}}/g, name)
            .replace(/{{verificationLink}}/g, verificationLink)
            .replace(/{{language}}/g, language);
        
        return this.sendEmail({
            to: email,
            subject,
            html: template
        });
    }
    
    async sendWelcomeEmail(email, name, language = 'en') {
        const subject = language === 'ar'
            ? 'مرحباً بك في CalmAI!'
            : 'Welcome to CalmAI!';
        
        const template = this.templates.welcome
            .replace(/{{name}}/g, name)
            .replace(/{{language}}/g, language);
        
        return this.sendEmail({
            to: email,
            subject,
            html: template
        });
    }
    
    async sendResetPasswordEmail(email, name, resetLink, language = 'en') {
        const subject = language === 'ar'
            ? 'إعادة تعيين كلمة المرور'
            : 'Reset Your Password';
        
        const template = this.templates.resetPassword
            .replace(/{{name}}/g, name)
            .replace(/{{resetLink}}/g, resetLink)
            .replace(/{{language}}/g, language);
        
        return this.sendEmail({
            to: email,
            subject,
            html: template
        });
    }
    
    async sendEmail(mailOptions) {
        const defaultOptions = {
            from: process.env.EMAIL_FROM,
            replyTo: process.env.EMAIL_FROM
        };
        
        const options = { ...defaultOptions, ...mailOptions };
        
        try {
            const info = await this.transporter.sendMail(options);
            console.log('Email sent:', info.messageId);
            return { success: true, messageId: info.messageId };
        } catch (error) {
            console.error('Error sending email:', error);
            return { success: false, error: error.message };
        }
    }
}

module.exports = new EmailService();
