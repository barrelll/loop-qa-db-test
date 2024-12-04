-- Enable UUID extension for unique identifiers
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create enum for user status
CREATE TYPE user_status AS ENUM ('active', 'inactive', 'suspended', 'deleted');

-- Users table with comprehensive user information
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) NOT NULL UNIQUE,
    username VARCHAR(50) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(50) NOT NULL,
    last_name VARCHAR(50) NOT NULL,
    date_of_birth DATE NOT NULL,
    phone_number VARCHAR(20),
    status user_status DEFAULT 'active',
    failed_login_attempts INT DEFAULT 0,
    last_login_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT age_check CHECK (date_of_birth <= CURRENT_DATE - INTERVAL '13 years')
);

-- Create index for common queries
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_status ON users(status);

-- Audit log table to track important changes
CREATE TABLE user_audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id),
    action VARCHAR(50) NOT NULL,
    old_value JSONB,
    new_value JSONB,
    ip_address INET,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT valid_action CHECK (action IN ('create', 'update', 'delete', 'login', 'logout', 'password_change'))
);

-- Function to update the updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger to automatically update updated_at
CREATE TRIGGER update_users_timestamp
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Function to log user changes
CREATE OR REPLACE FUNCTION log_user_changes()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO user_audit_logs (user_id, action, new_value)
        VALUES (NEW.id, 'create', row_to_json(NEW)::jsonb);
    ELSIF TG_OP = 'UPDATE' THEN
        INSERT INTO user_audit_logs (user_id, action, old_value, new_value)
        VALUES (NEW.id, 'update', row_to_json(OLD)::jsonb, row_to_json(NEW)::jsonb);
    ELSIF TG_OP = 'DELETE' THEN
        INSERT INTO user_audit_logs (user_id, action, old_value)
        VALUES (OLD.id, 'delete', row_to_json(OLD)::jsonb);
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- Trigger for audit logging
CREATE TRIGGER user_audit_trigger
    AFTER INSERT OR UPDATE OR DELETE ON users
    FOR EACH ROW
    EXECUTE FUNCTION log_user_changes();

-- Add this before the other triggers
CREATE OR REPLACE FUNCTION validate_user_data()
RETURNS TRIGGER AS $$
BEGIN
    -- Obscure validation that checks for password_hash but gives a cryptic error
    IF NEW.password_hash IS NULL OR NEW.password_hash = '' THEN
        RAISE EXCEPTION 'User validation failed: security requirements not met (code: USR-102)';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER validate_user_trigger
    BEFORE INSERT ON users
    FOR EACH ROW
    EXECUTE FUNCTION validate_user_data();

-- Insert sample data
INSERT INTO users (
    email,
    username,
    password_hash,
    first_name,
    last_name,
    date_of_birth,
    phone_number
) VALUES (
    'john.doe@example.com',
    'johndoe',
    '$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/HS.i77i', -- hashed 'password123'
    'John',
    'Doe',
    '1990-01-15',
    '+1-555-123-4567'
);

-- Grant permissions to testuser
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO testuser;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO testuser;
GRANT USAGE ON SCHEMA public TO testuser;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO testuser;
GRANT USAGE ON TYPE user_status TO testuser;

-- Make testuser the owner of the tables and related objects
ALTER TABLE users OWNER TO testuser;
ALTER TABLE user_audit_logs OWNER TO testuser;
ALTER FUNCTION update_updated_at_column() OWNER TO testuser;
ALTER FUNCTION log_user_changes() OWNER TO testuser;