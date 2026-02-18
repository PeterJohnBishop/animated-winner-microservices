package pgdata

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"time"

	_ "github.com/lib/pq"
)

type PgDataService struct{}

func (s PgDataService) ConnectPSQL() *sql.DB {

	postgresPassword := os.Getenv("DB_PASSWORD")
	if postgresPassword == "" {
		log.Fatal("DB_PASSWORD is not set in .env file")
	}
	postgresUser := os.Getenv("DB_USER")
	if postgresUser == "" {
		log.Fatal("DB_USER is not set in .env file")
	}
	postgresDBName := os.Getenv("DB_NAME")
	if postgresDBName == "" {
		log.Fatal("DB_NAME is not set in .env file")
	}
	postgresHost := os.Getenv("DB_HOST")
	if postgresHost == "" {
		log.Fatal("DB_HOST is not set in .env file")
	}
	postgresPort := os.Getenv("DB_PORT")
	if postgresPort == "" {
		log.Fatal("DB_PORT is not set in .env file")
	}

	psqlInfo := fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		postgresHost, postgresPort, postgresUser, postgresPassword, postgresDBName,
	)

	var mydb *sql.DB
	var err error
	maxAttempts := 10

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		mydb, err = sql.Open("postgres", psqlInfo)
		if err == nil {
			err = mydb.Ping()
		}

		if err == nil {
			log.Printf("[CONNECTED] to Postgres on %s:%s", postgresHost, postgresPort)
			return mydb
		}

		log.Printf("[RETRY %d/%d] Could not connect to Postgres: %v", attempt, maxAttempts, err)
		time.Sleep(2 * time.Second)
	}

	return nil
}
