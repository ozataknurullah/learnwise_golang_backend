package utils

import (
	"context"
	"log"

	"github.com/ozataknurullah/learn_wise_backend/database"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

var userCollection *mongo.Collection = database.OpenCollection(database.Client, "user")

// HashPassword hashes the provided password using bcrypt
func HashPassword(password string) string {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	if err != nil {
		log.Panic(err)
	}
	return string(bytes)
}

// VerifyPassword compares a hashed password with the provided plain text password
func VerifyPassword(hashedPassword string, providedPassword string) (bool, string) {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(providedPassword))
	if err != nil {
		return false, "email or password invalid"
	}
	return true, ""
}

// UserExists checks if a user exists in the collection by a given field and value
func UserExists(ctx context.Context, field string, value string) bool {
	count, err := userCollection.CountDocuments(ctx, bson.M{field: value})
	if err != nil {
		log.Printf("Error occurred while checking if user exists for field %s: %v", field, err)
		return false // Assume false to continue gracefully if there's an error
	}
	return count > 0
}
