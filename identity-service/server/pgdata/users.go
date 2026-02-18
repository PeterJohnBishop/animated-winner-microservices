package pgdata

import (
	"crypto/rand"
	"database/sql"
	"fmt"
	"identity-service/server/auth"
	"math/big"
	"net/http"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Created  int64  `json:"created"`
	Updated  int64  `json:"updated"`
}

func CreateUsersTable(db *sql.DB) error {
	query := `
	CREATE TABLE IF NOT EXISTS identity (
		id TEXT UNIQUE NOT NULL PRIMARY KEY,
		name TEXT UNIQUE NOT NULL,
		email TEXT UNIQUE NOT NULL,
		password TEXT NOT NULL,
		created BIGINT DEFAULT (EXTRACT(EPOCH FROM now())),
    	updated BIGINT DEFAULT (EXTRACT(EPOCH FROM now()))
	);`

	_, err := db.Exec(query)
	return err
}

const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func GenerateUserID() (string, error) {
	b := make([]byte, 8)
	for i := range b {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", err
		}
		b[i] = charset[num.Int64()]
	}

	final := fmt.Sprintf("id_%s", string(b))
	return final, nil
}

func HashedPassword(password string) (string, error) {
	hashedPassword, error := bcrypt.GenerateFromPassword([]byte(password), 10)
	return string(hashedPassword), error
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func RegisterUser(db *sql.DB, c *gin.Context) {
	var user User

	if err := c.ShouldBindJSON(&user); err != nil {
		fmt.Println("Failed to bind JSON:", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	fmt.Println("Registering user with email:", user.Email)

	userId, err := GenerateUserID()
	fmt.Println("Generated user ID:", userId)

	hashedPassword, err := HashedPassword(user.Password)
	if err != nil {
		fmt.Println("Error hashing password:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}
	fmt.Println("Password hashed successfully")

	query := `INSERT INTO identity (id, name, email, password)
		VALUES ($1, $2, $3, $4)`
	_, err = db.ExecContext(c, query, userId, user.Name, user.Email, hashedPassword)
	if err != nil {
		fmt.Println("Database insert error:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	access, refresh, err := auth.GenerateTokens(userId)
	if err != nil {
		fmt.Println("Failed to generate tokens:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate tokens"})
		return
	}

	auth.StoreTokens(userId, access, refresh)

	fmt.Println("User registered and logged in successfully:", userId)
	c.JSON(http.StatusCreated, gin.H{
		"message":      "User created and logged in!",
		"token":        access,
		"refreshToken": refresh,
		"user": gin.H{
			"id":    userId,
			"name":  user.Name,
			"email": user.Email,
			// omit password hash
		},
	})
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func Login(db *sql.DB, c *gin.Context) {
	var req LoginRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		fmt.Println("Failed to bind JSON:", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}
	fmt.Println("Login attempt for email:", req.Email)

	var user User
	query := `SELECT id, name, email, password, created, updated FROM identity WHERE email = $1`
	err := db.QueryRowContext(c, query, req.Email).Scan(
		&user.ID, &user.Name, &user.Email, &user.Password,
		&user.Created, &user.Updated,
	)
	if err == sql.ErrNoRows {
		fmt.Println("No user found with email:", req.Email)
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	} else if err != nil {
		fmt.Println("Database query error:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	fmt.Println("User found:", user.ID)

	if !CheckPasswordHash(req.Password, user.Password) {
		fmt.Println("Password verification failed for user:", user.ID)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Password Verification Failed"})
		return
	}
	fmt.Println("Password verified for user:", user.ID)

	access, refresh, err := auth.GenerateTokens(user.ID)
	if err != nil {
		fmt.Println("Failed to generate tokens:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate tokens"})
		return
	}

	auth.StoreTokens(user.ID, access, refresh)

	fmt.Println("Login successful for user:", user.ID)
	c.JSON(http.StatusOK, gin.H{
		"message":      "Login Success",
		"token":        access,
		"refreshToken": refresh,
		"user": gin.H{
			"id":    user.ID,
			"name":  user.Name,
			"email": user.Email,
			// omit password hash
		},
	})
}

func Refresh(c *gin.Context) {
	var body struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.RefreshToken == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing refresh token"})
		return
	}

	claims, err := auth.ValidateToken(body.RefreshToken, true)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid refresh token"})
		return
	}

	newAccess, _, err := auth.GenerateTokens(claims.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate new token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"access_token": newAccess})
}

func GetUsers(db *sql.DB, c *gin.Context) {
	fmt.Println("Fetching all users")
	rows, err := db.QueryContext(c, "SELECT id, name, email, password, created, updated FROM identity;")
	if err != nil {
		fmt.Println("Query failed:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var user User
		if err := rows.Scan(&user.ID, &user.Name, &user.Email, &user.Password, &user.Created, &user.Updated); err != nil {
			fmt.Println("Row scan failed:", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		fmt.Println("Row iteration error:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	fmt.Println("Total users fetched:", len(users))
	c.JSON(http.StatusOK, users)
}

func GetUserByID(db *sql.DB, c *gin.Context) {
	id := c.Param("id")
	fmt.Println("Fetching user with ID:", id)

	var user User
	query := `SELECT id, name, email, password, created, updated FROM identity WHERE id = $1`
	err := db.QueryRowContext(c, query, id).Scan(&user.ID, &user.Name, &user.Email, &user.Password, &user.Created, &user.Updated)
	if err == sql.ErrNoRows {
		fmt.Println("User not found:", id)
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	} else if err != nil {
		fmt.Println("Query error:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	fmt.Println("User fetched:", user.ID)
	c.JSON(http.StatusOK, user)
}

func UpdateUser(db *sql.DB, c *gin.Context) {
	var user User

	if err := c.ShouldBindJSON(&user); err != nil {
		fmt.Println("Failed to bind JSON:", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	query := `UPDATE identity SET name=$1, email=$2, updated=EXTRACT(EPOCH FROM now()) WHERE id=$3`
	result, err := db.ExecContext(c, query, user.Name, user.Email, user.ID)
	if err != nil {
		fmt.Println("Update query failed:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		fmt.Println("Failed to retrieve rows affected:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if rowsAffected == 0 {
		fmt.Println("No rows updated for ID:", user.ID)
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	fmt.Println("User updated successfully:", user.ID)
	c.JSON(http.StatusOK, gin.H{"message": "User updated!"})
}

func DeleteUserByID(db *sql.DB, c *gin.Context) {
	id := c.Param("id")
	fmt.Println("Deleting user with ID:", id)

	query := `DELETE FROM identity WHERE id = $1`
	result, err := db.ExecContext(c, query, id)
	if err != nil {
		fmt.Println("Delete query failed:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		fmt.Println("Failed to retrieve rows affected:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if rowsAffected == 0 {
		fmt.Println("No user found to delete with ID:", id)
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	fmt.Println("User deleted successfully:", id)
	c.JSON(http.StatusOK, gin.H{"message": "User deleted!"})
}

type UpdatePasswordRequest struct {
	ID          string `json:"id"`
	CurrentPass string `json:"currentPassword"`
	NewPass     string `json:"newPassword"`
}

func UpdatePassword(db *sql.DB, c *gin.Context) {
	var req UpdatePasswordRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		fmt.Println("Failed to bind JSON:", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var storedHash string
	query := `SELECT password FROM identity WHERE id = $1`
	err := db.QueryRowContext(c, query, req.ID).Scan(&storedHash)
	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	} else if err != nil {
		fmt.Println("DB error fetching password:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}

	if !CheckPasswordHash(req.CurrentPass, storedHash) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Current password is incorrect"})
		return
	}

	newHash, err := HashedPassword(req.NewPass)
	if err != nil {
		fmt.Println("Error hashing new password:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	updateQuery := `UPDATE identity SET password=$1, updated=EXTRACT(EPOCH FROM now()) WHERE id=$2`
	_, err = db.ExecContext(c, updateQuery, newHash, req.ID)
	if err != nil {
		fmt.Println("Error updating password:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update password"})
		return
	}

	auth.RevokeTokens(req.ID)

	fmt.Println("Password updated successfully and tokens revoked for user:", req.ID)
	c.JSON(http.StatusOK, gin.H{"message": "Password updated successfully. Please log in again."})
}

func Logout(c *gin.Context) {
	id := c.Param("id")
	fmt.Println("Logout user with ID:", id)

	auth.RevokeTokens(id)

	c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully, tokens revoked"})
}
