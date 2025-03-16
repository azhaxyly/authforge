package repository

import (
	"database/sql"
	"fmt"
	"time"

	"authforge/internal/config"
	"authforge/internal/logger"

	_ "github.com/lib/pq"
)

func NewPostgresDB(cfg *config.Config) (*sql.DB, error) {
	connStr := fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		cfg.Database.Host,
		cfg.Database.Port,
		cfg.Database.User,
		cfg.Database.Password,
		cfg.Database.DBName,
	)
	logger.Info("Connecting to PostgreSQL with connection string: ", connStr)

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		logger.Error("Error opening DB: ", err)
		return nil, fmt.Errorf("error opening DB: %w", err)
	}

	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(25)
	db.SetConnMaxLifetime(5 * time.Minute)

	if err := db.Ping(); err != nil {
		logger.Error("Error pinging DB: ", err)
		return nil, fmt.Errorf("error pinging DB: %w", err)
	}

	logger.Info("Successfully connected to the database")
	return db, nil
}

func RunMigrations(db *sql.DB) error {
	createUsersTable := `
	CREATE TABLE IF NOT EXISTS users (
		id SERIAL PRIMARY KEY,
		email VARCHAR(255) NOT NULL UNIQUE,
		password_hash VARCHAR(255) NOT NULL,
		is_active BOOLEAN DEFAULT FALSE,
		created_at TIMESTAMP NOT NULL,
		updated_at TIMESTAMP NOT NULL,
		failed_login_attempts INTEGER DEFAULT 0,
		last_failed_login TIMESTAMP
	);
	`
	_, err := db.Exec(createUsersTable)
	if err != nil {
		return fmt.Errorf("failed to create users table: %w", err)
	}
	logger.Info("Users table created successfully")

	createConfirmationTokensTable := `
	CREATE TABLE IF NOT EXISTS confirmation_tokens (
		id SERIAL PRIMARY KEY,
		user_id INTEGER NOT NULL,
		token VARCHAR(255) NOT NULL,
		expires_at TIMESTAMP NOT NULL,
		created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		CONSTRAINT fk_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
	);
	`
	_, err = db.Exec(createConfirmationTokensTable)
	if err != nil {
		return fmt.Errorf("failed to create confirmation_tokens table: %w", err)
	}
	logger.Info("Confirmation_tokens table created successfully")

	createPasswordResetTokensTable := `
	CREATE TABLE IF NOT EXISTS password_reset_tokens (
		id SERIAL PRIMARY KEY,
		user_id INTEGER NOT NULL,
		token VARCHAR(255) NOT NULL,
		expires_at TIMESTAMP NOT NULL,
		created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		used BOOLEAN DEFAULT FALSE,
		CONSTRAINT fk_user_reset FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
	);
	`
	_, err = db.Exec(createPasswordResetTokensTable)
	if err != nil {
		return fmt.Errorf("failed to create password_reset_tokens table: %w", err)
	}
	logger.Info("Password_reset_tokens table created successfully")

	return nil
}

func DropTables(db *sql.DB) error {
	dropPasswordResetTokens := `DROP TABLE IF EXISTS password_reset_tokens;`
	_, err := db.Exec(dropPasswordResetTokens)
	if err != nil {
		return fmt.Errorf("failed to drop password_reset_tokens table: %w", err)
	}
	logger.Info("Password_reset_tokens table dropped successfully")

	dropConfirmationTokens := `DROP TABLE IF EXISTS confirmation_tokens;`
	_, err = db.Exec(dropConfirmationTokens)
	if err != nil {
		return fmt.Errorf("failed to drop confirmation_tokens table: %w", err)
	}
	logger.Info("Confirmation_tokens table dropped successfully")

	dropUsers := `DROP TABLE IF EXISTS users;`
	_, err = db.Exec(dropUsers)
	if err != nil {
		return fmt.Errorf("failed to drop users table: %w", err)
	}
	logger.Info("Users table dropped successfully")

	return nil
}
