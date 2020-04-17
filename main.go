package main

import (
	"github.com/gin-gonic/gin"
	"net/http"
	"tryhuaweimobileservices/safetydetect"
)

type LoginRequest struct {
	CaptchaToken string `json:"captcha_token"`
	UserName     string `json:"user_name"`
	Password     string `json:"password"`
}

type ResponseError struct {
	Message string `json:"message"`
}

func handleLogin(c *gin.Context) {
	var loginData LoginRequest
	err := c.Bind(&loginData)

	if err != nil {
		c.JSON(http.StatusBadRequest, ResponseError{
			Message: "Failed to parse request body",
		})
		return
	}

	if loginData.CaptchaToken == "" {
		c.JSON(http.StatusBadRequest, ResponseError{
			Message: "There is no captcha token provided",
		})
		return
	}

	success, err := safetydetect.VerifyCaptcha(loginData.CaptchaToken)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ResponseError{
			Message: err.Error(),
		})
		return
	}

	if !success {
		c.JSON(http.StatusOK, gin.H{
			"captcha_success": success,
			"login_success":   false,
		})
		return
	}

	// login logic
	if loginData.UserName == "user1" && loginData.Password == "password" {
		c.JSON(http.StatusOK, gin.H{
			"captcha_success": success,
			"login_success":   true,
		})
		return
	}
}

func main() {
	r := gin.Default()
	r.POST("/login", handleLogin)

	r.Run(":8080")
}
