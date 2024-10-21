package controllers

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/ozataknurullah/learn_wise_backend/database"
	helper "github.com/ozataknurullah/learn_wise_backend/helpers"
	"github.com/ozataknurullah/learn_wise_backend/models"
	utils "github.com/ozataknurullah/learn_wise_backend/utils"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var accessToken, refreshToken string
var userCollection *mongo.Collection = database.OpenCollection(database.Client, "user")
var validate = validator.New()

func Signup() gin.HandlerFunc {
	return func(c *gin.Context) {
		var dbCtx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		defer cancel()

		var user models.User

		// Bind the incoming JSON to the user model
		if err := c.BindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body. Please provide valid user information."})
			return
		}

		// Validate the user struct
		validationErr := validate.Struct(user)
		if validationErr != nil {
			var errorMessages []string
			for _, err := range validationErr.(validator.ValidationErrors) {
				// Ignore User_id field validation since it is generated internally
				if err.Field() == "User_id" {
					continue
				}
				errorMessage := fmt.Sprintf("Field '%s' failed validation: %s", err.Field(), err.ActualTag())
				errorMessages = append(errorMessages, errorMessage)
			}
			if len(errorMessages) > 0 {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Validation failed. Please check the provided fields.", "details": errorMessages})
				return
			}
		}
		// Check if email already exists
		if utils.UserExists(dbCtx, "email", *user.Email) {
			c.JSON(http.StatusConflict, gin.H{"error": "An account with this email already exists."})
			return
		}

		// Check if phone number already exists
		if utils.UserExists(dbCtx, "phone", *user.Phone) {
			c.JSON(http.StatusConflict, gin.H{"error": "An account with this phone number already exists."})
			return
		}

		// Hash the password
		password := utils.HashPassword(*user.Password)
		user.Password = &password

		// Create user info
		user.Created_at, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
		user.Updated_at, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
		user.ID = primitive.NewObjectID()
		userIDHex := user.ID.Hex()
		user.User_id = &userIDHex

		// Generate JWT tokens
		accessToken, refreshToken, tokenErr := helper.GenerateAllTokens(*user.Email, *user.First_name, *user.Last_name, *user.User_type, *user.User_id)
		if tokenErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate authentication tokens. Please try again later."})
			return
		}
		user.Token = &accessToken
		user.Refresh_token = &refreshToken

		// Add the user to the database
		resultInsertionNumber, insertErr := userCollection.InsertOne(dbCtx, user)
		if insertErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user account. Please try again later."})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "User created successfully.", "user_id": resultInsertionNumber})
	}
}

func Login() gin.HandlerFunc {
	return func(c *gin.Context) {
		var dbCtx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		defer cancel()

		var user models.User
		var foundUser models.User

		if err := c.BindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		err := userCollection.FindOne(dbCtx, bson.M{"email": user.Email}).Decode(&foundUser)
		defer cancel()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "email or password is incorrect"})
			return
		}

		passwordIsValid, msg := utils.VerifyPassword(*user.Password, *foundUser.Password)
		if !passwordIsValid {
			c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
			return
		}

		if foundUser.Email == nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "user not found"})
		}

		accessToken, refreshToken, _ := helper.GenerateAllTokens(*foundUser.Email, *foundUser.First_name, *foundUser.Last_name, *foundUser.User_type, *foundUser.User_id)
		helper.UpdateAllTokens(accessToken, refreshToken, *foundUser.User_id)
		err = userCollection.FindOne(dbCtx, bson.M{"user_id": foundUser.User_id}).Decode(&foundUser)

		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		// Kullanıcı bilgilerini dönme
		c.JSON(http.StatusOK, gin.H{
			"message": "Login successful",
			"user":    foundUser,
		})
	}
}

// UpdateUser handles updating user details, allowing users to update their own details or an admin to update any user
func UpdateUser() gin.HandlerFunc {
	return func(c *gin.Context) {
		userId := c.Param("user_id")

		// Allow users to update their own details or admins to update any user's details
		tokenUserId := c.GetString("uid")
		userType := c.GetString("user_type")

		if tokenUserId != userId && userType != "ADMIN" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized to update this user"})
			return
		}

		var dbCtx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		defer cancel()

		var user models.User
		if err := c.BindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		var updateObj primitive.D

		// Update fields if they are provided
		if user.First_name != nil {
			updateObj = append(updateObj, bson.E{Key: "first_name", Value: user.First_name})
		}

		if user.Last_name != nil {
			updateObj = append(updateObj, bson.E{Key: "last_name", Value: user.Last_name})
		}

		if user.Email != nil {
			if utils.UserExists(dbCtx, "email", *user.Email) {
				c.JSON(http.StatusConflict, gin.H{"error": "This email is already in use by another user"})
				return
			}
			updateObj = append(updateObj, bson.E{Key: "email", Value: user.Email})
		}

		if user.Phone != nil {
			if utils.UserExists(dbCtx, "phone", *user.Phone) {
				c.JSON(http.StatusConflict, gin.H{"error": "This phone number is already in use by another user"})
				return
			}
			updateObj = append(updateObj, bson.E{Key: "phone", Value: user.Phone})
		}

		// Set updated_at timestamp
		user.Updated_at = time.Now()
		updateObj = append(updateObj, bson.E{Key: "updated_at", Value: user.Updated_at})

		upsert := false
		filter := bson.M{"user_id": userId}
		opt := options.UpdateOptions{
			Upsert: &upsert,
		}

		result, err := userCollection.UpdateOne(
			dbCtx,
			filter,
			bson.D{
				{Key: "$set", Value: updateObj},
			},
			&opt,
		)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "User update failed"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "User updated successfully", "result": result})
	}
}

func DeleteUser() gin.HandlerFunc {
	return func(c *gin.Context) {
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		defer cancel()
		userId := c.Param("user_id")
		var user models.User

		// Kullanıcının e-posta ve şifre bilgilerini alma
		var credentials struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}

		if err := c.BindJSON(&credentials); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
			return
		}

		// Kullanıcıyı veritabanında bulma
		err := userCollection.FindOne(ctx, bson.M{"user_id": userId, "email": credentials.Email}).Decode(&user)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}

		// Şifre doğrulama
		isValid, msg := utils.VerifyPassword(*user.Password, credentials.Password)
		if !isValid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": msg})
			return
		}

		// Kullanıcı tipi kontrolü: Kullanıcı kendi hesabını silebilir veya ADMIN diğer kullanıcıları silebilir
		tokenUserId := c.GetString("uid")
		userType := c.GetString("user_type")
		if userType != "ADMIN" && tokenUserId != userId {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized to delete this user"})
			return
		}

		// Kullanıcı silme işlemi
		filter := bson.M{"user_id": userId}
		result, err := userCollection.DeleteOne(ctx, filter)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "User deletion failed"})
			return
		}

		if result.DeletedCount == 0 {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "User deleted successfully"})
	}
}

func GetUsers() gin.HandlerFunc {
	return func(c *gin.Context) {
		//user type control
		if err := helper.CheckUserType(c, "ADMIN"); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		//context and timeout control
		var dbCtx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		defer cancel()

		// page and record count
		recordPerPage, err := strconv.Atoi(c.Query("recordPerPage"))
		if err != nil || recordPerPage < 1 {
			recordPerPage = 10
		}
		page, err1 := strconv.Atoi(c.Query("page"))
		if err1 != nil || page < 1 {
			page = 1
		}

		startIndex := (page - 1) * recordPerPage
		startIndexQuery := c.Query("startIndex")
		if startIndexQuery != "" {
			startIndex, err = strconv.Atoi(startIndexQuery)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid startIndex value"})
				return
			}
		}

		matchStage := bson.D{{Key: "$match", Value: bson.D{{}}}}
		groupStage := bson.D{{Key: "$group", Value: bson.D{
			{Key: "_id", Value: bson.D{{Key: "_id", Value: "null"}}},
			{Key: "total_count", Value: bson.D{{Key: "$sum", Value: 1}}},
			{Key: "data", Value: bson.D{{Key: "$push", Value: "$$ROOT"}}},
		}}}
		projectStage := bson.D{
			{Key: "$project", Value: bson.D{
				{Key: "_id", Value: 0},
				{Key: "total_count", Value: 1},
				{Key: "user_items", Value: bson.D{{Key: "$slice", Value: []interface{}{"$data", startIndex, recordPerPage}}}},
			}}}

		//return the databse query and the results
		result, err := userCollection.Aggregate(dbCtx, mongo.Pipeline{
			matchStage, groupStage, projectStage,
		})

		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "error occured while listing user items"})
			return
		}

		var allUsers []bson.M
		if err = result.All(dbCtx, &allUsers); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error occurred while parsing users data"})
			return
		}
		c.JSON(http.StatusOK, allUsers[0])
	}
}

func GetUser() gin.HandlerFunc {
	return func(c *gin.Context) {
		userId := c.Param("user_id")

		if err := helper.MatchUserTypeToUid(c, userId); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		defer cancel()

		var user models.User
		err := userCollection.FindOne(ctx, bson.M{"user_id": userId}).Decode(&user)

		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, user)
	}
}
