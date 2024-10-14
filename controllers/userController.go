package controllers

import (
	"context"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/ozataknurullah/learn_wise_backend/database"
	"github.com/ozataknurullah/learn_wise_backend/helpers"
	helper "github.com/ozataknurullah/learn_wise_backend/helpers"
	"github.com/ozataknurullah/learn_wise_backend/models"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

var accessToken, refreshToken string
var userCollection *mongo.Collection = database.OpenCollection(database.Client, "user")
var validate = validator.New()

func HashPassword(password string) string {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	if err != nil {
		log.Panic(err)
	}
	return string(bytes)
}

func VerifyPasword(userPassword string, providedPassword string) (bool, string) {
	err := bcrypt.CompareHashAndPassword([]byte(providedPassword), []byte(userPassword))
	check := true
	msg := ""

	if err != nil {
		msg = "email or password invalid"
		check = false
	}

	return check, msg
}

func Signup() gin.HandlerFunc {
	return func(c *gin.Context) {
		var dbCtx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		defer cancel()

		var user models.User

		if err := c.BindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		validationErr := validate.Struct(user)
		if validationErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": validationErr.Error()})
			return
		}

		//checking the mail and the phone
		if userExists(dbCtx, "email", user.Email) {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "error occured while checking for the email"})
			return
		}

		if userExists(dbCtx, "phone", user.Phone) {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "error occured while checking for the phone"})
			return
		}

		// hash the password
		password := HashPassword(*user.Password)
		user.Password = &password

		//create user info
		user.Created_at, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
		user.Updated_at, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
		user.ID = primitive.NewObjectID()
		userIDHex := user.ID.Hex()
		user.User_id = &userIDHex

		accessToken, refreshToken, _ = helper.GenerateAllTokens(*user.Email, *user.First_name, *user.Last_name, *user.User_type, *user.User_id)
		user.Token = &accessToken
		user.Refresh_token = &refreshToken

		// add the user to the database
		resultInsertionNumber, insertErr := userCollection.InsertOne(dbCtx, user)
		if insertErr != nil {
			msg := "User item was not created"
			c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
			return
		}

		c.JSON(http.StatusOK, resultInsertionNumber)
	}
}

// check the users if they exist
func userExists(ctx context.Context, field string, value *string) bool {
	count, err := userCollection.CountDocuments(ctx, bson.M{field: *value})
	if err != nil {
		log.Panic(err)
	}
	return count > 0
}

func Login() gin.HandlerFunc {
	return func(c *gin.Context) {
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		var user models.User
		var foundUser models.User

		if err := c.BindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		err := userCollection.FindOne(ctx, bson.M{"email": user.Email}).Decode(&foundUser)
		defer cancel()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "emial or password is incorrect"})
			return
		}

		passwordIsValid, msg := VerifyPasword(*user.Password, *foundUser.Password)
		defer cancel()
		if passwordIsValid != true {
			c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
			return
		}

		if foundUser.Email == nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "user not found"})
		}

		accessToken, refreshToken, _ := helper.GenerateAllTokens(*foundUser.Email, *foundUser.First_name, *foundUser.Last_name, *foundUser.User_type, *foundUser.User_id)
		helper.UpdateAllTokens(accessToken, refreshToken, *foundUser.User_id)
		err = userCollection.FindOne(ctx, bson.M{"user_id": foundUser.User_id}).Decode(&foundUser)

		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, foundUser)
	}
}

func UpdateUser() gin.HandlerFunc {
	return func(c *gin.Context) {
		userId := c.Param("user_id")

		if err := helper.CheckUserType(c, "ADMIN"); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized access"})
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

		if user.First_name != nil {
			updateObj = append(updateObj, bson.E{Key: "first_name", Value: user.First_name})
		}

		if user.Last_name != nil {
			updateObj = append(updateObj, bson.E{Key: "last_name", Value: user.Last_name})
		}

		if user.Email != nil {
			if userExists(dbCtx, "email", user.Email) {
				c.JSON(http.StatusConflict, gin.H{"error": "This email is already in use by another user"})
				return
			}
			updateObj = append(updateObj, bson.E{Key: "email", Value: user.Email})
		}

		if user.Phone != nil {
			if userExists(dbCtx, "phone", user.Phone) {
				c.JSON(http.StatusConflict, gin.H{"error": "This phone number is already in use by another user"})
				return
			}
			updateObj = append(updateObj, bson.E{Key: "phone", Value: user.Phone})
		}

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
		userId := c.Param("user_id")

		// Kullanıcı tipi kontrolü: ADMIN yetkisi
		if err := helpers.CheckUserType(c, "ADMIN"); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized access"})
			return
		}

		// Context ve zaman aşımı tanımlaması
		var dbCtx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		defer cancel()

		// Kullanıcı silme işlemi
		filter := bson.M{"user_id": userId}
		result, err := userCollection.DeleteOne(dbCtx, filter)
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

		var user models.User
		err := userCollection.FindOne(ctx, bson.M{"user_id": user.User_id}).Decode(&user)
		defer cancel()

		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, user)
	}
}
