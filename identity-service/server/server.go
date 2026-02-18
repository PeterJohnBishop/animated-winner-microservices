package server

import (
	"database/sql"
	"identity-service/server/auth"
	"identity-service/server/pgdata"
	"log"
	"os"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

var db *sql.DB

func ServeGin() {

	appPort := os.Getenv("APP_PORT")
	if appPort == "" {
		appPort = "8080"
	}

	// POSTGRES
	var sqlService pgdata.PgDataService
	db := sqlService.ConnectPSQL()
	if db == nil {
		log.Fatal("Error: Unable to connect to Postgres.")
	}

	pgdata.CreateUsersTable(db)

	// SERVER
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()

	// CORS
	r.Use(cors.New(cors.Config{
		AllowOriginFunc: func(origin string) bool {
			if strings.HasPrefix(origin, "http://localhost") ||
				strings.HasPrefix(origin, "http://127.0.0.1") ||
				strings.HasPrefix(origin, "http://identity-service") {
				return true
			}
			return false
		},
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,

		MaxAge: 12 * time.Hour,
	}))

	protected := r.Group("/auth")
	protected.Use(auth.JWTMiddleware())
	addOpenRoutes(r, db)
	addProtectedRoutes(protected, db)

	log.Printf("Serving Gin at :%s", appPort)
	r.Run(":" + appPort)
}
