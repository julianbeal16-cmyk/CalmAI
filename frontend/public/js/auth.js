class AuthManager {
    constructor() {
        this.api = api;
        this.currentLanguage = localStorage.getItem('calmai_lang') || 'en';
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.setupPasswordStrength();
        this.checkSession();
    }

    setupEventListeners() {
        // Login form
        const loginForm = document.getElementById('loginForm');
        if (loginForm) {
            loginForm.addEventListener('submit', (e) => this.handleLogin(e));
            
            // Toggle password visibility
            const toggleBtn = document.getElementById('togglePassword');
            if (toggleBtn) {
                toggleBtn.addEventListener('click', () => this.togglePasswordVisibility('password'));
            }
        }

        // Register form
        const registerForm = document.getElementById('registerForm');
        if (registerForm) {
            registerForm.addEventListener('submit', (e) => this.handleRegister(e));
            
            // Username suggestion
            const suggestBtn = document.getElementById('suggestUsername');
            if (suggestBtn) {
                suggestBtn.addEventListener('click', () => this.suggestUsername());
            }
            
            // Toggle password visibility
            const togglePass = document.getElementById('togglePassword');
            const toggleConfirm = document.getElementById('toggleConfirmPassword');
            
            if (togglePass) {
                togglePass.addEventListener('click', () => this.togglePasswordVisibility('password'));
            }
            if (toggleConfirm) {
                toggleConfirm.addEventListener('click', () => this.togglePasswordVisibility('confirmPassword'));
            }
            
            // Real-time password validation
            const passwordInput = document.getElementById('password');
            if (passwordInput) {
                passwordInput.addEventListener('input', () => this.checkPasswordStrength());
            }
            
            const confirmInput = document.getElementById('confirmPassword');
            if (confirmInput) {
                confirmInput.addEventListener('input', () => this.validateConfirmPassword());
            }
        }

        // Policy links
        const privacyLink = document.getElementById('privacyLink');
        const termsLink = document.getElementById('termsLink');
        
        if (privacyLink) {
            privacyLink.addEventListener('click', (e) => {
                e.preventDefault();
                this.showPolicy('privacy');
            });
        }
        
        if (termsLink) {
            termsLink.addEventListener('click', (e) => {
                e.preventDefault();
                this.showPolicy('terms');
            });
        }
    }

    async handleLogin(e) {
        e.preventDefault();
        
        const form = e.target;
        const submitBtn = form.querySelector('#submitBtn');
        const originalText = submitBtn.textContent;
        
        // Clear previous errors
        this.clearErrors();
        
        // Get form data
        const formData = {
            email: document.getElementById('email').value.trim(),
            password: document.getElementById('password').value,
            rememberMe: document.getElementById('rememberMe')?.checked || false
        };
        
        // Validation
        if (!this.validateEmail(formData.email)) {
            this.showError('emailError', this.translate('login_invalid_email'));
            return;
        }
        
        if (!formData.password) {
            this.showError('passwordError', this.translate('login_password_required'));
            return;
        }
        
        // Disable submit button
        submitBtn.disabled = true;
        submitBtn.textContent = this.translate('login_loading');
        
        try {
            const response = await this.api.login(formData);
            
            if (response.success) {
                this.showMessage('success', this.translate('login_success'));
                
                // Store remember me preference
                if (formData.rememberMe) {
                    localStorage.setItem('calmai_remember', 'true');
                }
                
                // Redirect to dashboard after delay
                setTimeout(() => {
                    window.location.href = 'dashboard.html';
                }, 1500);
            } else {
                this.showMessage('error', response.message || this.translate('login_failed'));
            }
        } catch (error) {
            this.showMessage('error', error.message || this.translate('login_error'));
        } finally {
            submitBtn.disabled = false;
            submitBtn.textContent = originalText;
        }
    }

    async handleRegister(e) {
        e.preventDefault();
        
        const form = e.target;
        const submitBtn = form.querySelector('#submitBtn');
        const originalText = submitBtn.textContent;
        
        // Clear previous errors
        this.clearErrors();
        
        // Get form data
        const formData = {
            firstName: document.getElementById('firstName').value.trim(),
            lastName: document.getElementById('lastName').value.trim(),
            email: document.getElementById('email').value.trim(),
            username: document.getElementById('username').value.trim(),
            password: document.getElementById('password').value,
            confirmPassword: document.getElementById('confirmPassword').value,
            language: document.getElementById('language').value,
            agreeTerms: document.getElementById('agreeTerms').checked
        };
        
        // Validation
        let isValid = true;
        
        if (!formData.firstName) {
            this.showError('firstNameError', this.translate('register_first_name_required'));
            isValid = false;
        }
        
        if (!formData.lastName) {
            this.showError('lastNameError', this.translate('register_last_name_required'));
            isValid = false;
        }
        
        if (!this.validateEmail(formData.email)) {
            this.showError('emailError', this.translate('register_invalid_email'));
            isValid = false;
        }
        
        if (!formData.username) {
            this.showError('usernameError', this.translate('register_username_required'));
            isValid = false;
        } else if (!this.validateUsername(formData.username)) {
            this.showError('usernameError', this.translate('register_invalid_username'));
            isValid = false;
        }
        
        if (!formData.password) {
            this.showError('passwordError', this.translate('register_password_required'));
            isValid = false;
        } else if (!this.validatePasswordStrength(formData.password)) {
            this.showError('passwordError', this.translate('register_weak_password'));
            isValid = false;
        }
        
        if (formData.password !== formData.confirmPassword) {
            this.showError('confirmPasswordError', this.translate('register_password_mismatch'));
            isValid = false;
        }
        
        if (!formData.agreeTerms) {
            this.showError('termsError', this.translate('register_agree_required'));
            isValid = false;
        }
        
        if (!isValid) return;
        
        // Disable submit button
        submitBtn.disabled = true;
        submitBtn.textContent = this.translate('register_loading');
        
        try {
            const response = await this.api.register({
                first_name: formData.firstName,
                last_name: formData.lastName,
                email: formData.email,
                username: formData.username,
                password: formData.password,
                language: formData.language
            });
            
            if (response.success) {
                this.showMessage('success', this.translate('register_success'));
                
                // Update UI for email verification
                const formContainer = document.querySelector('.auth-form');
                if (formContainer) {
                    formContainer.innerHTML = `
                        <div class="verification-sent">
                            <div class="verification-icon">
                                <i class="fas fa-envelope-circle-check"></i>
                            </div>
                            <h2>${this.translate('register_verification_sent')}</h2>
                            <p>${this.translate('register_verification_message')}</p>
                            <p class="email-sent-to">
                                <strong>${this.translate('register_email_sent_to')}:</strong><br>
                                ${formData.email}
                            </p>
                            <div class="verification-actions">
                                <button onclick="location.href='login.html'" class="btn btn-outline">
                                    ${this.translate('nav_login')}
                                </button>
                                <button onclick="location.href='index.html'" class="btn btn-primary">
                                    ${this.translate('nav_home')}
                                </button>
                            </div>
                        </div>
                    `;
                }
            } else {
                this.showMessage('error', response.message || this.translate('register_failed'));
            }
        } catch (error) {
            this.showMessage('error', error.message || this.translate('register_error'));
        } finally {
            submitBtn.disabled = false;
            submitBtn.textContent = originalText;
        }
    }

    suggestUsername() {
        const firstName = document.getElementById('firstName').value.trim().toLowerCase();
        const lastName = document.getElementById('lastName').value.trim().toLowerCase();
        
        if (!firstName || !lastName) {
            this.showMessage('warning', this.translate('register_enter_names'));
            return;
        }
        
        // Generate username
        let username = `${firstName}.${lastName}`;
        
        // Remove special characters and spaces
        username = username.replace(/[^a-z0-9.]/g, '');
        
        // Add random number if username is short
        if (username.length < 6) {
            username += Math.floor(Math.random() * 1000);
        }
        
        document.getElementById('username').value = username;
    }

    checkPasswordStrength() {
        const password = document.getElementById('password').value;
        const strengthBar = document.querySelector('.strength-bar');
        const strengthValue = document.getElementById('strengthValue');
        
        if (!password) {
            strengthBar.style.width = '0%';
            strengthBar.style.backgroundColor = '#ddd';
            strengthValue.textContent = this.translate('password_strength');
            return;
        }
        
        let strength = 0;
        
        // Length check
        if (password.length >= 8) strength += 25;
        if (password.length >= 12) strength += 25;
        
        // Complexity checks
        if (/[A-Z]/.test(password)) strength += 25;
        if (/[0-9]/.test(password)) strength += 15;
        if (/[^A-Za-z0-9]/.test(password)) strength += 10;
        
        // Update UI
        strengthBar.style.width = `${strength}%`;
        
        let strengthText = '';
        let color = '#ff4444';
        
        if (strength < 50) {
            strengthText = this.translate('password_weak');
            color = '#ff4444';
        } else if (strength < 75) {
            strengthText = this.translate('password_medium');
            color = '#ffa726';
        } else if (strength < 90) {
            strengthText = this.translate('password_strong');
            color = '#4CAF50';
        } else {
            strengthText = this.translate('password_very_strong');
            color = '#2E7D32';
        }
        
        strengthBar.style.backgroundColor = color;
        strengthValue.textContent = strengthText;
    }

    validatePasswordStrength(password) {
        // At least 8 characters
        if (password.length < 8) return false;
        
        // At least one uppercase letter
        if (!/[A-Z]/.test(password)) return false;
        
        // At least one lowercase letter
        if (!/[a-z]/.test(password)) return false;
        
        // At least one number
        if (!/[0-9]/.test(password)) return false;
        
        return true;
    }

    validateConfirmPassword() {
        const password = document.getElementById('password').value;
        const confirmPassword = document.getElementById('confirmPassword').value;
        const errorElement = document.getElementById('confirmPasswordError');
        
        if (password && confirmPassword && password !== confirmPassword) {
            this.showError('confirmPasswordError', this.translate('register_password_mismatch'));
            return false;
        } else {
            this.clearError('confirmPasswordError');
            return true;
        }
    }

    validateEmail(email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
    }

    validateUsername(username) {
        const usernameRegex = /^[a-zA-Z0-9_.-]{3,30}$/;
        return usernameRegex.test(username);
    }

    togglePasswordVisibility(fieldId) {
        const field = document.getElementById(fieldId);
        const toggleBtn = document.getElementById(`toggle${fieldId.charAt(0).toUpperCase() + fieldId.slice(1)}`);
        
        if (!field || !toggleBtn) return;
        
        if (field.type === 'password') {
            field.type = 'text';
            toggleBtn.innerHTML = '<i class="fas fa-eye-slash"></i>';
        } else {
            field.type = 'password';
            toggleBtn.innerHTML = '<i class="fas fa-eye"></i>';
        }
    }

    showError(elementId, message) {
        const element = document.getElementById(elementId);
        if (element) {
            element.textContent = message;
            element.style.display = 'block';
        }
    }

    clearError(elementId) {
        const element = document.getElementById(elementId);
        if (element) {
            element.textContent = '';
            element.style.display = 'none';
        }
    }

    clearErrors() {
        const errorElements = document.querySelectorAll('.error-message');
        errorElements.forEach(element => {
            element.textContent = '';
            element.style.display = 'none';
        });
        
        this.hideMessage();
    }

    showMessage(type, message) {
        const container = document.getElementById('messageContainer');
        if (!container) return;
        
        container.innerHTML = `
            <div class="message message-${type}">
                <i class="fas fa-${type === 'success' ? 'check-circle' : 'exclamation-circle'}"></i>
                <span>${message}</span>
            </div>
        `;
        container.style.display = 'block';
        
        // Auto-hide success messages
        if (type === 'success') {
            setTimeout(() => {
                this.hideMessage();
            }, 5000);
        }
    }

    hideMessage() {
        const container = document.getElementById('messageContainer');
        if (container) {
            container.style.display = 'none';
        }
    }

    async showPolicy(type) {
        try {
            const response = await this.api.request(`/policy/${type}`);
            
            const modal = document.getElementById('policyModal');
            const modalTitle = document.getElementById('modalTitle');
            const policyContent = document.getElementById('policyContent');
            
            if (modal && modalTitle && policyContent) {
                modalTitle.textContent = type === 'privacy' 
                    ? this.translate('privacy_title') 
                    : this.translate('terms_title');
                
                policyContent.innerHTML = response.content || '<p>Policy content not available.</p>';
                
                modal.style.display = 'flex';
                
                // Close modal handlers
                const closeBtn = modal.querySelector('.modal-close');
                if (closeBtn) {
                    closeBtn.onclick = () => {
                        modal.style.display = 'none';
                    };
                }
                
                modal.onclick = (e) => {
                    if (e.target === modal) {
                        modal.style.display = 'none';
                    }
                };
            }
        } catch (error) {
            console.error('Failed to load policy:', error);
        }
    }

    checkSession() {
        if (this.api.isAuthenticated()) {
            // Check if we're on auth pages
            const currentPage = window.location.pathname;
            const authPages = ['/login.html', '/register.html', '/forgot-password.html'];
            
            if (authPages.some(page => currentPage.includes(page))) {
                window.location.href = 'dashboard.html';
            }
        }
    }

    setupPasswordStrength() {
        const passwordInput = document.getElementById('password');
        if (passwordInput) {
            passwordInput.addEventListener('input', () => this.checkPasswordStrength());
        }
    }

    translate(key) {
        // Simple translation fallback
        const translations = {
            'en': {
                'login_invalid_email': 'Please enter a valid email address',
                'login_password_required': 'Password is required',
                'login_loading': 'Signing in...',
                'login_success': 'Login successful! Redirecting...',
                'login_failed': 'Login failed. Please check your credentials.',
                'login_error': 'An error occurred. Please try again.',
                'register_first_name_required': 'First name is required',
                'register_last_name_required': 'Last name is required',
                'register_invalid_email': 'Please enter a valid email address',
                'register_username_required': 'Username is required',
                'register_invalid_username': 'Username can only contain letters, numbers, dots, dashes, and underscores',
                'register_password_required': 'Password is required',
                'register_weak_password': 'Password must be at least 8 characters with uppercase, lowercase, and number',
                'register_password_mismatch': 'Passwords do not match',
                'register_agree_required': 'You must agree to the terms and conditions',
                'register_loading': 'Creating account...',
                'register_success': 'Account created successfully! Please check your email for verification.',
                'register_failed': 'Registration failed. Please try again.',
                'register_error': 'An error occurred. Please try again.',
                'register_enter_names': 'Please enter your first and last name',
                'register_verification_sent': 'Verification Email Sent!',
                'register_verification_message': 'Please check your email and click the verification link to activate your account.',
                'register_email_sent_to': 'Email sent to'
            },
            'ar': {
                'login_invalid_email': 'يرجى إدخال عنوان بريد إلكتروني صحيح',
                'login_password_required': 'كلمة المرور مطلوبة',
                'login_loading': 'جاري تسجيل الدخول...',
                'login_success': 'تم تسجيل الدخول بنجاح! جاري التوجيه...',
                'login_failed': 'فشل تسجيل الدخول. يرجى التحقق من بيانات الاعتماد.',
                'login_error': 'حدث خطأ. يرجى المحاولة مرة أخرى.',
                'register_first_name_required': 'الاسم الأول مطلوب',
                'register_last_name_required': 'اسم العائلة مطلوب',
                'register_invalid_email': 'يرجى إدخال عنوان بريد إلكتروني صحيح',
                'register_username_required': 'اسم المستخدم مطلوب',
                'register_invalid_username': 'يمكن أن يحتوي اسم المستخدم على أحرف وأرقام ونقاط وشرطات وشرطات سفلية فقط',
                'register_password_required': 'كلمة المرور مطلوبة',
                'register_weak_password': 'يجب أن تحتوي كلمة المرور على 8 أحرف على الأقل مع أحرف كبيرة وصغيرة وأرقام',
                'register_password_mismatch': 'كلمات المرور غير متطابقة',
                'register_agree_required': 'يجب أن توافق على الشروط والأحكام',
                'register_loading': 'جاري إنشاء الحساب...',
                'register_success': 'تم إنشاء الحساب بنجاح! يرجى التحقق من بريدك الإلكتروني للتأكيد.',
                'register_failed': 'فشل التسجيل. يرجى المحاولة مرة أخرى.',
                'register_error': 'حدث خطأ. يرجى المحاولة مرة أخرى.',
                'register_enter_names': 'يرجى إدخال اسمك الأول واسم العائلة',
                'register_verification_sent': 'تم إرسال بريد التأكيد!',
                'register_verification_message': 'يرجى التحقق من بريدك الإلكتروني والنقر على رابط التأكيد لتفعيل حسابك.',
                'register_email_sent_to': 'تم إرسال البريد إلى'
            }
        };
        
        return translations[this.currentLanguage]?.[key] || key;
    }
}

// Initialize auth manager when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.authManager = new AuthManager();
});
