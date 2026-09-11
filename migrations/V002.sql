-- A short-lived, single-use token allowing userId to set a new password
-- without knowing the old one, issued after they prove control of their
-- account email. tokenHash is SHA-256 of the token sent in the reset email;
-- the raw token is never stored.
CREATE TABLE IF NOT EXISTS passwordResets (
    id SERIAL PRIMARY KEY,
    userId BIGINT UNSIGNED NOT NULL,
    tokenHash CHAR(64) NOT NULL,
    expiresAt TIMESTAMP NOT NULL,
    usedAt TIMESTAMP NULL DEFAULT NULL,
    createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT unique_password_reset_token_hash UNIQUE (tokenHash),
    FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE
);
