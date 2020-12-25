/*
状态信息
*/
package http

import (
	"fmt"
	"github.com/valyala/fasthttp"
	"runtime"
	"time"
	"github.com/truexf/imagine/magic"
)

const version = "1.0.0"

var serviceBootTime time.Time

func init() {
	serviceBootTime = time.Now()
}

type Status struct {
}

func HandleStatus(ctx *fasthttp.RequestCtx) {
	status := `adapter server is running
===============================
Version        : %s
BootTime       : %s
%s
goroutine count: %d

magic statis
------------
%s
`
	ret := fmt.Sprintf(status,
		version,
		serviceBootTime.String(),
		GetServer().GetStatus(),
		runtime.NumGoroutine(),
		magic.GetMaster().Status())
	ctx.WriteString(ret)
}
