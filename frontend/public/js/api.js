class CalmAIAPI {
    constructor() {
        this.baseURL = 'http://localhost:5000/api';
        this.token = localStorage.getItem('calmai_token');
    }

    async request(endpoint, options = {}) {
        const url = `${this.baseURL}${endpoint}`;
        
        const headers = {
            'Content-Type': 'application/json',
            ...options.headers
        };

        if (this.token) {
            headers['Authorization'] = `Bearer ${this.token}`;
        }

        const config = {
            ...options,
            headers,
            credentials: 'include'
        };

        try {
            const response = await fetch(url, config);
            
            if (response.status === 401) {
                // Token expired or invalid
                this.clearAuth();
                window.location.href = '/login.html';
                return;
            }

            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.message || 'Request failed');
            }

            return data;
        } catch (error) {
            console.error('API Request failed:', error);
            throw error;
        }
    }

    setToken(token) {
        this.token = token;
        localStorage.setItem('calmai_token', token);
    }

    clearAuth() {
        this.token = null;
        localStorage.removeItem('calmai_token');
        localStorage.removeItem('calmai_user');
    }

    // Auth endpoints
    async register(userData) {
        return this.request('/auth/register', {
            method: 'POST',
            body: JSON.stringify(userData)
        });
    }

    async login(credentials) {
        const response = await this.request('/auth/login', {
            method: 'POST',
            body: JSON.stringify(credentials)
        });

        if (response.success && response.token) {
            this.setToken(response.token);
            localStorage.setItem('calmai_user', JSON.stringify(response.user));
        }

        return response;
    }

    async verifyEmail(token) {
        return this.request(`/auth/verify-email/${token}`, {
            method: 'GET'
        });
    }

    async logout() {
        await this.request('/auth/logout');
        this.clearAuth();
    }

    // User endpoints
    async getProfile() {
        return this.request('/users/profile');
    }

    async updateProfile(userData) {
        return this.request('/users/profile', {
            method: 'PUT',
            body: JSON.stringify(userData)
        });
    }

    async changePassword(passwords) {
        return this.request('/users/change-password', {
            method: 'POST',
            body: JSON.stringify(passwords)
        });
    }

    async updateLanguage(language) {
        return this.request('/users/language', {
            method: 'PUT',
            body: JSON.stringify({ language })
        });
    }

    // AI Chat endpoints
    async sendMessage(message) {
        return this.request('/ai/chat', {
            method: 'POST',
            body: JSON.stringify({ message })
        });
    }

    async getMessageLimit() {
        return this.request('/ai/limit');
    }

    async watchAd() {
        return this.request('/ai/watch-ad', {
            method: 'POST'
        });
    }

    // Games endpoints
    async getGames() {
        return this.request('/games');
    }

    // Exercises endpoints
    async getExercises() {
        return this.request('/exercises');
    }

    // Media endpoints
    async getMedia() {
        return this.request('/media');
    }

    // Notifications
    async getNotifications() {
        return this.request('/notifications');
    }

    // Admin endpoints
    async adminGetUsers(page = 1) {
        return this.request(`/admin/users?page=${page}`);
    }

    async adminUpdateUser(userId, data) {
        return this.request(`/admin/users/${userId}`, {
            method: 'PUT',
            body: JSON.stringify(data)
        });
    }

    async adminGetStats() {
        return this.request('/admin/stats');
    }

    async adminUpdateSettings(settings) {
        return this.request('/admin/settings', {
            method: 'PUT',
            body: JSON.stringify(settings)
        });
    }

    // Check if user is authenticated
    isAuthenticated() {
        return !!this.token;
    }

    // Get current user
    getCurrentUser() {
        const userStr = localStorage.getItem('calmai_user');
        return userStr ? JSON.parse(userStr) : null;
    }
}

// Create global API instance
const api = new CalmAIAPI();
