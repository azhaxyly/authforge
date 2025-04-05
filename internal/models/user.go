package models

import (
	"time"

	"github.com/golang-jwt/jwt/v4"
)

type User struct {
	ID                  int64     `json:"id" db:"id"`
	Email               string    `json:"email" db:"email"`
	PasswordHash        string    `json:"-" db:"password_hash"`
	IsActive            bool      `json:"isActive" db:"is_active"`
	CreatedAt           time.Time `json:"createdAt" db:"created_at"`
	UpdatedAt           time.Time `json:"updatedAt" db:"updated_at"`
	FailedLoginAttempts int       `json:"failedLoginAttempts" db:"failed_login_attempts"`
	LastFailedLogin     time.Time `json:"lastFailedLogin" db:"last_failed_login"`
	Role                string    `json:"role" db:"role"`
}

type CustomClaims struct {
	UserID int64  `json:"user_id"`
	Role   string `json:"role"`
	jwt.RegisteredClaims
}
