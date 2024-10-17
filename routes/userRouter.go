package routes

import (
	"github.com/gin-gonic/gin"
	controller "github.com/ozataknurullah/learn_wise_backend/controllers"
	"github.com/ozataknurullah/learn_wise_backend/middleware"
)

func UserRoutes(incomingRoutes *gin.Engine) {
	incomingRoutes.Use(middleware.Authenticate())
	incomingRoutes.GET("/user/:user_id", controller.GetUser())
	incomingRoutes.GET("/users", controller.GetUsers())
	incomingRoutes.PATCH("/user/update/:user_id", controller.UpdateUser())
	incomingRoutes.DELETE("/user/delete/:user_id", controller.DeleteUser())
}
