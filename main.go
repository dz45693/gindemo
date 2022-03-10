package main

import (
	"demo/middleware"
	"fmt"
	"github.com/gin-gonic/gin"
	"os"
)

func main() {
	go func() {
		gateway := gin.Default()
		gateway.Use(middleware.AesGcmDecrypt())
		gateway.Use(middleware.GateWay())
		gateway.Run(":8080")
	}()

	// 1.创建路由
	r := gin.Default()
	r.Use(middleware.Logger())

	r.GET("/", func(c *gin.Context) {
		c.Writer.WriteString("pong")
	})

	r.GET("/demo", func(c *gin.Context) {
		req := ReqObj{}
		err := c.ShouldBindQuery(&req)
		if err != nil {
			fmt.Print(err)
		}
		response(c, 200, "ok", req)
	})

	r.POST("/test", func(c *gin.Context) {
		req := ReqObj{}
		err := c.ShouldBind(&req)
		if err != nil {
			fmt.Print(err)
		}
		response(c, 200, "ok", req)
	})

	r.POST("/upload", func(c *gin.Context) {
		file, err := c.FormFile("file")
		if err != nil {
			fmt.Print(err)
		}
		folder := c.Request.FormValue("folder")
		tmp, _ := os.Getwd()
		filePath := tmp + "/upload/" + folder + "/" + file.Filename
		c.SaveUploadedFile(file, filePath)
	})

	r.Run(":8000")
}

type ReqObj struct {
	Name       string `json:"name" form:"name"`
	Age        int64  `json:"age"  form:"age"`
	UpdateTime int64  `json:"update_time"  form:"update_time"`
	Folder     string `json:"folder"  form:"folder"`
}

func response(c *gin.Context, code int, msg string, data interface{}) {
	mapData := make(map[string]interface{}, 0)
	mapData["code"] = code
	mapData["msg"] = msg
	mapData["data"] = data
	c.JSON(200, data)
	c.Abort()
	return
}
