package middleware

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"io/ioutil"
	"time"
)

type BodyLogWriter struct {
	gin.ResponseWriter
	body *bytes.Buffer
}

func (w BodyLogWriter) Write(b []byte) (int, error) {
	w.body.Write(b)
	return w.ResponseWriter.Write(b)
}
func (w BodyLogWriter) WriteString(s string) (int, error) {
	w.body.WriteString(s)
	return w.ResponseWriter.WriteString(s)
}

// 打印日志
func Logger() gin.HandlerFunc {
	return func(c *gin.Context) {
		/*
			var buf bytes.Buffer
			tee := io.TeeReader(c.Request.Body, &buf)
			requestBody, _ := ioutil.ReadAll(tee)
			c.Request.Body = ioutil.NopCloser(&buf)
		*/
		requestBody, _ := c.GetRawData()
		c.Request.Body = ioutil.NopCloser(bytes.NewBuffer(requestBody))

		bodyLogWriter := &BodyLogWriter{body: bytes.NewBufferString(""), ResponseWriter: c.Writer}
		c.Writer = bodyLogWriter

		start := time.Now()

		//handler
		c.Next()

		//log
		end := time.Now()
		responseBody := bodyLogWriter.body.String()
		logField := map[string]interface{}{
			"uri":             c.Request.URL.Path,
			"raw_query":       c.Request.URL.RawQuery,
			"start_timestamp": start.Format("2006-01-02 15:04:05"),
			"end_timestamp":   end.Format("2006-01-02 15:04:05"),
			"server_name":     c.Request.Host,
			"remote_addr":     c.ClientIP(),
			"proto":           c.Request.Proto,
			"referer":         c.Request.Referer(),
			"request_method":  c.Request.Method,
			"response_time":   end.Sub(start).Milliseconds(), // 毫秒
			"content_type":    c.Request.Header.Get("Content-Type"),
			"status":          c.Writer.Status(),
			"user_agent":      c.Request.UserAgent(),
			//"trace_id":        c.Writer.Header().Get("X-Request-Trace-Id"),
			"request_body":  string(requestBody),
			"response_body": responseBody,
			"response_err":  c.Errors.Last(),
		}

		//jsonByte, _ := json.MarshalIndent(logField, "", "\t")
		//	fmt.Print(string(jsonByte))
		bf2 := bytes.NewBuffer([]byte{})
		jsonEncoder := json.NewEncoder(bf2)
		jsonEncoder.SetEscapeHTML(false)
		jsonEncoder.SetIndent("","\t")
		jsonEncoder.Encode(logField)
		fmt.Println(bf2.String())
	}
}
