package middleware

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/valyala/fasthttp"
	"io/ioutil"
	"runtime/debug"
	"time"
)

var fastClient *fasthttp.Client

func init() {
	fastClient = &fasthttp.Client{}
	fastClient.MaxIdemponentCallAttempts = 1
	fastClient.ReadTimeout = time.Second * 60
}

func GetHttpClient() *fasthttp.Client {
	return fastClient
}
func GateWay() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if e := recover(); e != nil {
				stack := debug.Stack()
				log("GateWay Recovery: err:%v, stack:%v", e, string(stack))
			}
		}()

		err := Forward(c)
		if err != nil {
			response(c, 9999, "系统错误", err.Error())
		}
		return
	}
}

func Forward(ctx *gin.Context) error {
	req := &fasthttp.Request{}

	//请求-获取服务地址
	host := "http://localhost:8000/" + ctx.Request.URL.String()
	//请求-url
	req.SetRequestURI(host)

	//请求-header
	for k, v := range ctx.Request.Header {
		req.Header.Set(k, v[0])
	}

	//请求-body
	data, err := ioutil.ReadAll(ctx.Request.Body)
	if err != nil {
		log("Forward err:%v", err)
		return fmt.Errorf("系统错误")
	}
	req.SetBody(data)

	//请求-方法
	req.Header.SetMethod(ctx.Request.Method)

	//请求-发送
	resp := &fasthttp.Response{}

	//请求-新增调用链
	/*
		err = opentracing.GlobalTracer().Inject(
			opentracing.SpanFromContext(ctx.Request.Context()).Context(),
			opentracing.TextMap,
			HTTPHeadersCarrier{&req.Header},
		)
	*/

	err = GetHttpClient().Do(req, resp)
	if err != nil {
		log("Forward GetHttpClient DO err:%v", err)
		return fmt.Errorf("系统错误")
	}

	//请求-响应
	ContentType := fmt.Sprintf("%s", resp.Header.Peek("Content-Type"))
	ctx.Data(resp.StatusCode(), ContentType, resp.Body())

	return nil
}

type HTTPHeadersCarrier struct {
	*fasthttp.RequestHeader
}

func (c HTTPHeadersCarrier) Set(key, val string) {
	h := c.RequestHeader
	h.Add(key, val)
}
