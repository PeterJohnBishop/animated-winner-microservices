package server

import (
	"database/sql"
	"identity-service/server/pgdata"

	"github.com/gin-gonic/gin"
)

func addOpenRoutes(r *gin.Engine, db *sql.DB) {
	r.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"service": "identity-service",
		})
	})
	r.POST("/login", func(c *gin.Context) {
		pgdata.Login(db, c)
	})
	r.POST("/new", func(c *gin.Context) {
		pgdata.RegisterUser(db, c)
	})
	r.POST("/logout/:id", func(c *gin.Context) {
		pgdata.Logout(c)
	})
}

func addProtectedRoutes(r *gin.RouterGroup, db *sql.DB) {

	r.GET("/users", func(c *gin.Context) {
		pgdata.GetUsers(db, c)
	})
	r.GET("/users/:id", func(c *gin.Context) {
		pgdata.GetUserByID(db, c)
	})
	r.PUT("/users", func(c *gin.Context) {
		pgdata.UpdateUser(db, c)
	})
	r.PUT("/users/password", func(c *gin.Context) {
		pgdata.UpdatePassword(db, c)
	})
	r.DELETE("/users/:id", func(c *gin.Context) {
		pgdata.DeleteUserByID(db, c)
	})
	r.POST("/refresh", func(c *gin.Context) {
		pgdata.Refresh(c)
	})
}
