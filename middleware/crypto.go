package middleware

import (
	"bytes"
	"demo/aes"
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/shopspring/decimal"
	"io/ioutil"
	"mime/multipart"
	"net/url"
	"runtime/debug"
	"strings"
)

type aesWriter struct {
	gin.ResponseWriter
	body *bytes.Buffer
}

func (w *aesWriter) Write(b []byte) (int, error) {
	return w.body.Write(b)
}

func (w *aesWriter) WriteString(s string) (int, error) {
	return w.body.WriteString(s)
}

//只有经过token 验证的才会加密 和解密
//handleFile 表示是否处理上传文件， 默认网关不处理上传文件的encryptString数据， 如果处理会导致具体服务无法接收到具体参数
func AesGcmDecrypt() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if e := recover(); e != nil {
				stack := debug.Stack()
				log("AesGcmDecrypt Recovery: err:%v, stack:%v", e, string(stack))
			}
		}()

		if c.Request.Method != "GET" && c.Request.Method != "POST" {
			c.Next()
		} else {
			md5key := aes.GetAesKey("gavin12345678")
			log("AesGcmDecrypt start url:%s  ,md5key:%s, Method:%s, Header:%+v", c.Request.URL.String(), md5key, c.Request.Method, c.Request.Header)
			handleAes(c, md5key)
		}
	}
}

//请求和返回都加密 解密
func handleAes(c *gin.Context, md5key string) {
	if c.Request.Method != "GET" && c.Request.Method != "POST" {
		return
	}

	contentType := c.Request.Header.Get("Content-Type")
	isJsonRequest := strings.Contains(contentType, "application/json")
	isFileRequest := strings.Contains(contentType, "multipart/form-data")

	if c.Request.Method == "GET" {
		err := parseQuery(c, md5key)
		if err != nil {
			log("handleAes parseQuery  err:%v", err)
			//这里输出应该密文 一旦加密解密调试好 这里就不会走进来
			response(c, 2001, "系统错误", err.Error())
			return
		}
	} else if c.Request.Method == "POST" && isJsonRequest {
		err := parseJson(c, md5key)
		if err != nil {
			log("handleAes parseJson err:%v", err)
			//这里输出应该密文 一旦加密解密调试好 这里就不会走进来
			response(c, 2001, "系统错误", err.Error())
			return
		}
	} else if c.Request.Method == "POST" && isFileRequest {
		err := parseFile(c, md5key)
		if err != nil {
			log("handleAes parseFile err:%v", err)
			//这里输出应该密文 一旦加密解密调试好 这里就不会走进来
			response(c, 2001, "系统错误", err.Error())
			return
		}
	}

	///截取 response body
	oldWriter := c.Writer
	blw := &aesWriter{body: bytes.NewBufferString(""), ResponseWriter: c.Writer}
	c.Writer = blw

	// 走流程
	c.Next()

	///获取返回数据
	responseByte := blw.body.Bytes()

	//日志
	c.Writer = oldWriter
	//如果返回的不是json格式 那么直接返回,应为文件下载之类的不应该加密
	if !isJsonResponse(c) {
		_, _ = c.Writer.Write(responseByte)
		return
	}

	///加密
	encryptStr, err := aes.GcmEncrypt(md5key, string(responseByte))
	if err != nil {
		log("handleAes GcmEncrypt err:%v", err)
		response(c, 2001, "系统错误", err.Error())
		return
	}

	_, _ = c.Writer.WriteString(encryptStr)
}

func parseJson(c *gin.Context, md5key string) error {
	//读取数据 body处理
	payload, err := c.GetRawData()
	if err != nil {
		return err
	}

	///解密body数据 请求的json是{"encryptString":{value}} value含有gcm的12字节nonce,实际长度大于32
	if payload != nil && len(payload) > 20 {
		var jsonData encryptJson
		log("AesGcmDecrypt  parseJson url:%s md5key:%s,old data:%s,", c.Request.URL.String(), md5key, string(payload))

		err := json.Unmarshal(payload, &jsonData)
		if err != nil {
			log("AesGcmDecrypt parseJson Unmarshal err:%v", err)
			return err
		}

		payloadText := jsonData.EncryptString
		if len(payloadText) > 0 {
			payloadText, err = aes.GcmDecrypt(md5key, payloadText)
			if err != nil {
				log("AesGcmDecrypt parseJson GcmDecryptByte err:%v", err)
				return err
			}
			payload = []byte(payloadText)
			log("AesGcmDecrypt  parseJson url:%s md5key:%s,encryptString:%s,decrypt data:%s", c.Request.URL.String(), md5key, jsonData.EncryptString, payloadText)
		}
	}

	c.Request.Body = ioutil.NopCloser(bytes.NewBuffer(payload))

	return nil
}

//处理get url的解密
func parseQuery(c *gin.Context, md5Key string) error {
	encryptString := c.Query("encryptString")
	log("AesGcmDecrypt parseQuery url:%s, md5key:%s, encryptString:%s", c.Request.URL.String(), md5Key, encryptString)

	if len(encryptString) < 1 {
		return nil
	}

	//解密
	plaintext, err := aes.GcmDecrypt(md5Key, encryptString)
	if err != nil {
		return err
	}

	if len(plaintext) < 3 {
		//plaintext 应该是json 串 {}
		return nil
	}

	queryData := make(map[string]interface{}, 0)
	err = json.Unmarshal([]byte(plaintext), &queryData)
	if err != nil {
		return err
	}

	var args []string
	for k, v := range queryData {
		args = append(args, fmt.Sprintf("%s=%s", k, url.QueryEscape(getStr(v))))
	}

	queryString := strings.Join(args, "&")
	c.Request.URL.RawQuery = queryString

	log("AesGcmDecrypt parseQuery  url:%s, md5key:%s, encryptString:%s, decrypt data:%s", c.Request.URL.String(), md5Key, encryptString, queryString)
	return nil
}

//处理文件上传
func parseFile(c *gin.Context, md5Key string) error {
	defaultMaxMemory := 32 << 20 //默认大小
	err := c.Request.ParseMultipartForm(int64(defaultMaxMemory))
	if err != nil {
		return err
	}

	encryptString := c.Request.MultipartForm.Value["encryptString"][0]
	log("AesGcmDecrypt parseFile url:%s, md5key:%s, encryptString:%s", c.Request.URL.String(), md5Key, encryptString)

	if len(encryptString) < 1 {
		return nil
	}

	plaintext, err := aes.GcmDecrypt(md5Key, encryptString)
	if err != nil {
		return err
	}

	if len(plaintext) < 3 {
		//plaintext 应该是json 串 {}
		return nil
	}

	formData := make(map[string]interface{}, 0)
	err = json.Unmarshal([]byte(plaintext), &formData)
	if err != nil {
		return err
	}

	//准备重写数据
	bodyBuf := &bytes.Buffer{}
	wr := multipart.NewWriter(bodyBuf)

	//准备普通form数据
	for k, v := range formData {
		val := getStr(v)
		err = wr.WriteField(k, val)
		if err != nil {
			log("AesGcmDecrypt parseFile WriteField :%s=%s, err:%v", k, val, err)
		}
	}

	//准备file form数据
	for name := range c.Request.MultipartForm.File {
		fileInfo := c.Request.MultipartForm.File[name][0]
		fileWr, err := wr.CreateFormFile(name, fileInfo.Filename)
		if err != nil {
			log("AesGcmDecrypt parseFile CreateFormFile :%s=%s, err:%v", name, fileInfo.Filename, err)
		}

		fileObj, err := fileInfo.Open()
		if err != nil {
			log("AesGcmDecrypt parseFile Open file :%s, err:%v", name, err)
		}

		fileByte, err := ioutil.ReadAll(fileObj)
		if err != nil {
			log("AesGcmDecrypt parseFile ReadAll file:%s, err:%v", name, err)
		}

		_ = fileObj.Close()
		_, _ = fileWr.Write(fileByte)
	}

	//写结尾标志
	_ = wr.Close()
	c.Request.Header.Set("Content-Type", wr.FormDataContentType())
	c.Request.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBuf.Bytes()))

	return nil
}

func isJsonResponse(c *gin.Context) bool {
	contentType := c.Writer.Header().Get("Content-Type")
	return strings.Contains(contentType, "application/json")
}

func getStr(v interface{}) string {
	val := ""
	switch v.(type) {
	case float64:
		tmp, _ := decimal.NewFromString(fmt.Sprintf("%.10f", v))
		val = tmp.String()
	default:
		val = fmt.Sprintf("%v", v)
	}
	return val
}

type encryptJson struct {
	EncryptString string `json:"encryptString"`
}

func log(format string, arg ...interface{}) {
	fmt.Print(fmt.Sprintf(format, arg))
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