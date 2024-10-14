package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/ozataknurullah/learn_wise_backend/controllers"
)

func UserRoutes(router *gin.Engine) {
	router.POST("/user/signup", controllers.Signup())
	router.POST("/user/login", controllers.Login())
	router.GET("/user/:user_id", controllers.GetUser())
	router.GET("/users", controllers.GetUsers())
	router.PATCH("/user/:user_id", controllers.UpdateUser()) // Güncelleme işlemi
	router.DELETE("/user/:user_id", controllers.DeleteUser())
}
