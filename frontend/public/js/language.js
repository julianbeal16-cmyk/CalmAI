class LanguageManager {
    constructor() {
        this.currentLang = localStorage.getItem('calmai_lang') || 'en';
        this.translations = {};
        this.init();
    }

    async init() {
        await this.loadTranslations();
        this.applyLanguage(this.currentLang);
        this.setupEventListeners();
    }

    async loadTranslations() {
        try {
            const response = await fetch('translations.json');
            this.translations = await response.json();
        } catch (error) {
            console.error('Failed to load translations:', error);
            this.translations = this.getDefaultTranslations();
        }
    }

    getDefaultTranslations() {
        return {
            en: {
                // Navigation
                site_name: "CalmAI",
                nav_home: "Home",
                nav_features: "Features",
                nav_about: "About",
                nav_login: "Login",
                nav_register: "Get Started",
                
                // Hero
                hero_title: "Your Safe Space for Mental Wellness",
                hero_subtitle: "Find peace, support, and tools for your mental health journey in a secure and compassionate environment.",
                hero_cta: "Start Your Journey",
                hero_learn: "Learn More",
                
                // Features
                features_title: "How CalmAI Supports You",
                feature1_title: "AI Support Chat",
                feature1_desc: "Talk to our compassionate AI assistant anytime, with conversations stored securely on your device.",
                feature2_title: "Relaxing Games",
                feature2_desc: "Enjoy calming games designed to reduce stress and improve mood.",
                feature3_title: "Mindfulness Exercises",
                feature3_desc: "Guided meditation, yoga, and breathing exercises for daily practice.",
                feature4_title: "Complete Privacy",
                feature4_desc: "Your conversations stay on your device. We respect your privacy.",
                
                // About
                about_title: "About CalmAI",
                about_text: "CalmAI is a mental health support platform designed to provide accessible, private, and compassionate support. Our mission is to make mental wellness tools available to everyone, with complete respect for your privacy and security.",
                stat_private: "Private",
                stat_available: "Available",
                stat_ads: "No Ads",
                
                // Footer
                footer_tagline: "Your safe space for mental wellness",
                footer_links: "Links",
                footer_legal: "Legal",
                footer_privacy: "Privacy Policy",
                footer_terms: "Terms of Service",
                footer_contact: "Contact",
                footer_email: "support@calmai.com",
                footer_copyright: "© 2024 CalmAI. All rights reserved.",
                
                // Register
                register_title: "Create Your Account",
                register_subtitle: "Join CalmAI for personalized mental wellness support",
                register_first_name: "First Name *",
                register_first_name_ph: "John",
                register_last_name: "Last Name *",
                register_last_name_ph: "Doe",
                register_email: "Email Address *",
                register_email_ph: "john@example.com",
                register_username: "Username *",
                register_username_ph: "john.doe",
                register_suggest: "Suggest",
                register_username_hint: "Suggested based on your name. You can change it.",
                register_password: "Password *",
                register_confirm_password: "Confirm Password *",
                register_language: "Preferred Language",
                register_agree: "I agree to the",
                register_and: "and",
                register_submit: "Create Account",
                register_have_account: "Already have an account?",
                
                // Login
                login_title: "Welcome Back",
                login_subtitle: "Sign in to continue your mental wellness journey",
                login_email: "Email Address",
                login_email_ph: "john@example.com",
                login_password: "Password",
                login_remember: "Remember me",
                login_forgot: "Forgot password?",
                login_submit: "Sign In",
                login_or: "Or continue with",
                login_google: "Google",
                login_apple: "Apple",
                login_no_account: "Don't have an account?",
                
                // Language
                lang_english: "English",
                lang_arabic: "العربية",
                
                // Password
                password_strength: "Strength: ",
                password_weak: "Weak",
                password_medium: "Medium",
                password_strong: "Strong",
                password_very_strong: "Very Strong",
                
                // Modal
                privacy_title: "Privacy Policy",
                terms_title: "Terms of Service"
            },
            ar: {
                // Navigation
                site_name: "كالم إيه آي",
                nav_home: "الرئيسية",
                nav_features: "المميزات",
                nav_about: "عنّا",
                nav_login: "تسجيل الدخول",
                nav_register: "ابدأ الآن",
                
                // Hero
                hero_title: "مساحتك الآمنة للراحة النفسية",
                hero_subtitle: "ابحث عن السلام والدعم والأدوات لرحلة صحتك النفسية في بيئة آمنة ومتعاطفة.",
                hero_cta: "ابدأ رحلتك",
                hero_learn: "اعرف المزيد",
                
                // Features
                features_title: "كيف يدعمك كالم إيه آي",
                feature1_title: "محادثة الدعم بالذكاء الاصطناعي",
                feature1_desc: "تحدث إلى مساعد الذكاء الاصطناعي المتعاطف في أي وقت، مع تخزين المحادثات بأمان على جهازك.",
                feature2_title: "ألعاب مهدئة",
                feature2_desc: "استمتع بألعاب مهدئة مصممة لتقليل التوتر وتحسين المزاج.",
                feature3_title: "تمارين اليقظة الذهنية",
                feature3_desc: "تمارين تأمل ويوغا وتنفس موجهة للممارسة اليومية.",
                feature4_title: "خصوصية كاملة",
                feature4_desc: "محادثاتك تبقى على جهازك. نحن نحترم خصوصيتك.",
                
                // About
                about_title: "عن كالم إيه آي",
                about_text: "كالم إيه آي هو منصة دعم الصحة النفسية المصممة لتقديم دعم سهل الوصول وخاص ومتعاطف. مهمتنا هي جعل أدوات الصحة النفسية متاحة للجميع، مع الاحترام الكامل لخصوصيتك وأمانك.",
                stat_private: "خاص",
                stat_available: "متاح",
                stat_ads: "بدون إعلانات",
                
                // Footer
                footer_tagline: "مساحتك الآمنة للراحة النفسية",
                footer_links: "روابط",
                footer_legal: "قانوني",
                footer_privacy: "سياسة الخصوصية",
                footer_terms: "شروط الخدمة",
                footer_contact: "اتصل بنا",
                footer_email: "support@calmai.com",
                footer_copyright: "© ٢٠٢٤ كالم إيه آي. جميع الحقوق محفوظة.",
                
                // Register
                register_title: "إنشاء حسابك",
                register_subtitle: "انضم إلى كالم إيه آي للحصول على دعم الصحة النفسية المخصص",
                register_first_name: "الاسم الأول *",
                register_first_name_ph: "محمد",
                register_last_name: "اسم العائلة *",
                register_last_name_ph: "أحمد",
                register_email: "البريد الإلكتروني *",
                register_email_ph: "mohamed@example.com",
                register_username: "اسم المستخدم *",
                register_username_ph: "mohamed.ahmad",
                register_suggest: "اقتراح",
                register_username_hint: "مقترح بناءً على اسمك. يمكنك تغييره.",
                register_password: "كلمة المرور *",
                register_confirm_password: "تأكيد كلمة المرور *",
                register_language: "اللغة المفضلة",
                register_agree: "أوافق على",
                register_and: "و",
                register_submit: "إنشاء الحساب",
                register_have_account: "لديك حساب بالفعل؟",
                
                // Login
                login_title: "مرحباً بعودتك",
                login_subtitle: "سجل الدخول لمواصلة رحلة صحتك النفسية",
                login_email: "البريد الإلكتروني",
                login_email_ph: "mohamed@example.com",
                login_password: "كلمة المرور",
                login_remember: "تذكرني",
                login_forgot: "نسيت كلمة المرور؟",
                login_submit: "تسجيل الدخول",
                login_or: "أو تابع باستخدام",
                login_google: "جوجل",
                login_apple: "آبل",
                login_no_account: "ليس لديك حساب؟",
                
                // Language
                lang_english: "English",
                lang_arabic: "العربية",
                
                // Password
                password_strength: "القوة: ",
                password_weak: "ضعيفة",
                password_medium: "متوسطة",
                password_strong: "قوية",
                password_very_strong: "قوية جداً",
                
                // Modal
                privacy_title: "سياسة الخصوصية",
                terms_title: "شروط الخدمة"
            }
        };
    }

    applyLanguage(lang) {
        this.currentLang = lang;
        localStorage.setItem('calmai_lang', lang);
        
        // Update HTML lang attribute
        document.documentElement.lang = lang;
        document.documentElement.dir = lang === 'ar' ? 'rtl' : 'ltr';
        
        // Update all translatable elements
        this.updateTextContent(lang);
        
        // Update language toggle button
        this.updateLanguageToggle(lang);
    }

    updateTextContent(lang) {
        const translations = this.translations[lang];
        
        // Update elements with data-i18n attribute
        document.querySelectorAll('[data-i18n]').forEach(element => {
            const key = element.getAttribute('data-i18n');
            if (translations[key]) {
                element.textContent = translations[key];
            }
        });
        
        // Update placeholder attributes
        document.querySelectorAll('[data-i18n-placeholder]').forEach(element => {
            const key = element.getAttribute('data-i18n-placeholder');
            if (translations[key]) {
                element.placeholder = translations[key];
            }
        });
        
        // Update page title
        const titleElement = document.querySelector('title[data-i18n]');
        if (titleElement) {
            const key = titleElement.getAttribute('data-i18n');
            if (translations[key]) {
                document.title = translations[key];
            }
        }
    }

    updateLanguageToggle(lang) {
        const toggleBtn = document.getElementById('langToggle');
        if (!toggleBtn) return;
        
        toggleBtn.setAttribute('data-lang', lang);
        
        const langText = toggleBtn.querySelector('.lang-text');
        if (langText) {
            langText.textContent = lang === 'en' ? 'العربية' : 'English';
        }
    }

    setupEventListeners() {
        const toggleBtn = document.getElementById('langToggle');
        if (toggleBtn) {
            toggleBtn.addEventListener('click', () => {
                const newLang = this.currentLang === 'en' ? 'ar' : 'en';
                this.applyLanguage(newLang);
                
                // Trigger custom event for other components
                document.dispatchEvent(new CustomEvent('languageChanged', {
                    detail: { language: newLang }
                }));
            });
        }
    }

    getCurrentLanguage() {
        return this.currentLang;
    }

    translate(key) {
        return this.translations[this.currentLang]?.[key] || key;
    }
}

// Initialize language manager
const languageManager = new LanguageManager();
