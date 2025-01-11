CREATE TABLE users (
    username VARCHAR(255) PRIMARY KEY,
    password VARCHAR(512) NOT NULL,
    cookie VARCHAR(512) NOT NULL,
    checked_count INTEGER DEFAULT 0,
    secret_key VARCHAR(512) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP
);

CREATE TABLE user_logs (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) REFERENCES users(username),
    checked_count INTEGER NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_user_logs_username ON user_logs(username);
CREATE INDEX idx_user_logs_timestamp ON user_logs(timestamp);