const mysql = require('mysql2/promise');
require('dotenv').config();

class Database {
    constructor() {
        this.pool = mysql.createPool({
            host: process.env.DB_HOST,
            user: process.env.DB_USER,
            password: process.env.DB_PASSWORD,
            database: process.env.DB_NAME,
            port: process.env.DB_PORT || 3306,
            waitForConnections: true,
            connectionLimit: 10,
            queueLimit: 0,
            charset: 'utf8mb4',
            timezone: '+00:00'
        });
        
        // Test connection
        this.testConnection();
    }
    
    async testConnection() {
        try {
            const connection = await this.pool.getConnection();
            console.log('Database connected successfully');
            connection.release();
        } catch (error) {
            console.error('Database connection failed:', error.message);
            process.exit(1);
        }
    }
    
    async getConnection() {
        return await this.pool.getConnection();
    }
    
    async query(sql, params) {
        const connection = await this.getConnection();
        try {
            const [rows] = await connection.execute(sql, params);
            return rows;
        } finally {
            connection.release();
        }
    }
    
    async transaction(callback) {
        const connection = await this.getConnection();
        try {
            await connection.beginTransaction();
            const result = await callback(connection);
            await connection.commit();
            return result;
        } catch (error) {
            await connection.rollback();
            throw error;
        } finally {
            connection.release();
        }
    }
    
    // Security: Parameterized queries to prevent SQL injection
    escape(value) {
        return mysql.escape(value);
    }
}

module.exports = new Database();
