package middleware

import (
	"bytes"
	"demo/aes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/shopspring/decimal"
	"io"
	"io/ioutil"
	"mime"
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

		if c.Request.Method == "OPTIONS" {
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
	contentType := c.Request.Header.Get("Content-Type")
	isJsonRequest := strings.Contains(contentType, "application/json")
	isFileRequest := strings.Contains(contentType, "multipart/form-data")
	isFormUrl := strings.Contains(contentType, "application/x-www-form-urlencoded")

	if c.Request.Method == "GET" {
		err := parseQuery(c, md5key)
		if err != nil {
			log("handleAes parseQuery  err:%v", err)
			//这里输出应该密文 一旦加密解密调试好 这里就不会走进来
			response(c, 2001, "系统错误", err.Error())
			return
		}
	} else if isJsonRequest {
		err := parseJson(c, md5key)
		if err != nil {
			log("handleAes parseJson err:%v", err)
			//这里输出应该密文 一旦加密解密调试好 这里就不会走进来
			response(c, 2001, "系统错误", err.Error())
			return
		}
	} else if isFormUrl {
		err := parseForm(c, md5key)
		if err != nil {
			log("handleAes parseForm err:%v", err)
			//这里输出应该密文 一旦加密解密调试好 这里就不会走进来
			response(c, 2001, "系统错误", err.Error())
			return
		}
	} else if isFileRequest {
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

//处理json
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

func parseForm(c *gin.Context, md5key string) error {
	//读取数据 body处理
	payload, err := c.GetRawData()
	if err != nil {
		return err
	}

	///解密body数据 请求的json是"encryptString= value含有gcm的12字节nonce,实际长度大于32
	if payload != nil && len(payload) > 20 {
		var jsonData encryptJson
		log("AesGcmDecrypt  parseForm url:%s md5key:%s,old data:%s,", c.Request.URL.String(), md5key, string(payload))

		values, err := url.ParseQuery(string(payload))
		if err != nil {
			log("AesGcmDecrypt parseForm ParseQuery err:%v", err)
			return err
		}

		payloadText := values.Get("encryptString")
		if len(payloadText) > 0 {
			mapData, err := gcmDecryptString(md5key, payloadText)
			if err != nil {
				log("AesGcmDecrypt parseForm gcmDecryptString err:%v", err)
				return err
			}

			for k, v := range mapData {
				values.Add(k, getStr(v))
			}

			formData := values.Encode()
			log("AesGcmDecrypt  parseForm url:%s md5key:%s,encryptString:%s,decrypt data:%s", c.Request.URL.String(), md5key, jsonData.EncryptString, formData)
			payload = []byte(formData)
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

	queryData, err := gcmDecryptString(md5Key, encryptString)
	if err != nil {
		return err
	}

	var args []string
	for k, v := range queryData {
		//args = append(args, fmt.Sprintf("%s=%s", k, url.QueryEscape(getStr(v))))
		args = append(args, fmt.Sprintf("%s=%s", k, getStr(v)))
	}

	queryString := strings.Join(args, "&")
	c.Request.URL.RawQuery = queryString

	log("AesGcmDecrypt parseQuery  url:%s, md5key:%s, encryptString:%s, decrypt data:%s", c.Request.URL.String(), md5Key, encryptString, queryString)
	return nil
}

func parseFile(c *gin.Context, md5Key string) error {
	contentType := c.Request.Header.Get("Content-Type")
	_, params, _ := mime.ParseMediaType(contentType)
	boundary, ok := params["boundary"]
	if !ok {
		return errors.New("no multipart boundary param in Content-Type")
	}

	//准备重写数据
	bodyBuf := &bytes.Buffer{}
	wr := multipart.NewWriter(bodyBuf)
	mr := multipart.NewReader(c.Request.Body, boundary)
	for {
		p, err := mr.NextPart() //p的类型为Part
		if err == io.EOF {
			break
		}

		if err != nil {
			log("NextPart err:%v", err)
			break
		}

		fileByte, err := ioutil.ReadAll(p)
		if err != nil {
			log("ReadAll err:%v", err)
			break
		}

		pName := p.FormName()
		fileName := p.FileName()
		if len(fileName) < 1 {
			if pName == "encryptString" {
				formData, err := gcmDecryptString(md5Key, string(fileByte))
				if err != nil {
					log("AesGcmDecrypt writeFile gcmDecryptString err:%v", err)
					break
				}

				for k, v := range formData {
					val := getStr(v)
					err = wr.WriteField(k, val)
					if err != nil {
						log("AesGcmDecrypt writeFile WriteField :%s=%s, err:%v", k, val, err)
						break
					}
				}
			} else {
				wr.WriteField(pName, string(fileByte))
			}
		} else {
			tmp, err := wr.CreateFormFile(pName, fileName)
			if err != nil {
				log("AesGcmDecrypt parseFile CreateFormFile err:%v", err)
				continue
			}
			tmp.Write(fileByte)
		}
	}

	//写结尾标志
	_ = wr.Close()
	c.Request.Header.Set("Content-Type", wr.FormDataContentType())
	c.Request.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBuf.Bytes()))

	return nil
}

func gcmDecryptString(md5Key, encryptString string) (map[string]interface{}, error) {
	formData := make(map[string]interface{}, 0)
	if len(encryptString) < 1 {
		return formData, nil
	}

	plaintext, err := aes.GcmDecrypt(md5Key, encryptString)
	if err != nil {
		return formData, err
	}

	if len(plaintext) < 3 {
		//plaintext 应该是json 串 {}
		return formData, nil
	}

	err = json.Unmarshal([]byte(plaintext), &formData)
	if err != nil {
		return formData, err
	}

	return formData, nil
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
	fmt.Print(fmt.Sprintf(format, arg...))
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
