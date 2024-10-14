package routes

import (
	controller "github.com/ozataknurullah/learn_wise_backend/controllers"
	"github.com/ozataknurullah/learn_wise_backend/middleware"

	"github.com/gin-gonic/gin"
)

func UserRoutes(incomingRoutes *gin.Engine) {
	incomingRoutes.Use(middleware.Authenticate())
	incomingRoutes.GET("/users", controller.GetUsers())
	incomingRoutes.GET("/users/:user_id", controller.GetUser())
}
