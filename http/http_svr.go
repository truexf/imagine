/*
web server
基于fasthttp的web server路由框架
*/
package http

import (
	"fmt"
	"github.com/golang/glog"
	"github.com/truexf/gocfg"
	"github.com/valyala/fasthttp"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"github.com/truexf/imagine/common"
)

var GlogV3 glog.Verbose = false
var GlogV4 glog.Verbose = false
var GlogV5 glog.Verbose = false

type Adapter interface {
	Handle(path string, ctx *fasthttp.RequestCtx) error
}

type RequestHandler struct {
	name string
	//	handler fasthttp.RequestHandler
	adapter Adapter

	//status
	WaitingRequests    int64
	fiveMinuteRequests [301]int64
	fiveMinuteDuration [301]int64
	allRequests        int64
	allDuration        int64
}

func NewRequestHandler(name string, adapter Adapter) *RequestHandler {
	if name == "" || adapter == nil {
		return nil
	}
	ret := new(RequestHandler)
	ret.name = name
	ret.adapter = adapter
	for i := 0; i < len(ret.fiveMinuteRequests); i++ {
		ret.fiveMinuteRequests[i] = 0
	}
	for i := 0; i < len(ret.fiveMinuteDuration); i++ {
		ret.fiveMinuteRequests[i] = 0
	}

	return ret
}

func (m *RequestHandler) HandleRequest(path string, ctx *fasthttp.RequestCtx) {
	atomic.AddInt64(&m.WaitingRequests, 1)
	defer atomic.AddInt64(&m.WaitingRequests, -1)
	idx := _adapter_server.currentSecond
	tm := time.Now()
	atomic.AddInt64(&(m.fiveMinuteRequests[idx]), 1)
	atomic.AddInt64(&m.allRequests, 1)
	atomic.AddInt64(&(_adapter_server.fiveMinuteRequests[idx]), 1)
	atomic.AddInt64(&_adapter_server.allRequests, 1)
	defer func(tm time.Time) {
		dur := int64(time.Now().Sub(tm))
		atomic.AddInt64(&(m.fiveMinuteDuration[idx]), dur)
		atomic.AddInt64(&m.allDuration, dur)
		atomic.AddInt64(&(_adapter_server.fiveMinuteDuration[idx]), dur)
		atomic.AddInt64(&_adapter_server.allDuration, dur)
	}(tm)
	if err := m.adapter.Handle(path, ctx); err != nil {
		glog.Errorf("adapterHandle fail, %s\n", err.Error())
		ctx.SetStatusCode(204)
	}
}

func (m *RequestHandler) GetStatus() string {
	ret := `%s, WaitingRequests: %d
5 minute requests: %d, average duration: %d
all requests     : %d, average duration: %d
`
	idx := _adapter_server.currentSecond
	var dur5 int64 = 0
	var req5 int64 = 0
	for i := 0; i < 300; i++ {
		if idx > 300 {
			idx = 0
		}
		dur5 += m.fiveMinuteDuration[idx]
		req5 += m.fiveMinuteRequests[idx]
		idx++
	}
	req5Ori := req5
	if req5 <= 0 {
		req5 = 1
	}

	averageDur5 := dur5 / req5 / int64(time.Millisecond)
	reqAll := m.allRequests
	if reqAll <= 0 {
		reqAll = 1
	}
	averageDurAll := m.allDuration / reqAll / int64(time.Millisecond)
	return fmt.Sprintf(ret, m.name, m.WaitingRequests, req5Ori, averageDur5, m.allRequests, averageDurAll)
}

type AdapterServer struct {
	httpServer *fasthttp.Server
	handleMux  map[string]*RequestHandler
	listener   *net.TCPListener
	//requestTimeout int64

	//status
	WaitingRequests    int64
	fiveMinuteRequests [301]int64
	fiveMinuteDuration [301]int64
	currentSecond      int
	allRequests        int64
	allDuration        int64

	config *gocfg.GoConfig
}

func (m *AdapterServer) SetConfig(cfg *gocfg.GoConfig) {
	m.config = cfg
}
func (m *AdapterServer) ticktack() {
	tm := time.Now().Second()
	for {
		<-time.After(time.Millisecond * 300)
		tmNow := time.Now().Second()
		idx := m.currentSecond
		if tmNow != tm {
			idx++
			if idx > 300 {
				idx = 0
			}
			m.currentSecond = idx
			idxNext := idx + 1
			if idxNext > 300 {
				idxNext = 0
			}
			atomic.StoreInt64(&(m.fiveMinuteRequests[idxNext]), 0)
			atomic.StoreInt64(&(m.fiveMinuteDuration[idxNext]), 0)

			for _, v := range m.handleMux {
				atomic.StoreInt64(&(v.fiveMinuteRequests[idxNext]), 0)
				atomic.StoreInt64(&(v.fiveMinuteDuration[idxNext]), 0)
			}

			tm = tmNow
		}
	}
}

func (m *AdapterServer) GetStatus() string {
	ret := `
WaitingRequests: %d
5 minute requests: %d, average duration: %d
all requests     : %d, average duration: %d
path status      : 
%s
`
	idx := _adapter_server.currentSecond
	var dur5 int64 = 0
	var req5 int64 = 0
	for i := 0; i < 300; i++ {
		if idx > 300 {
			idx = 0
		}
		dur5 += m.fiveMinuteDuration[idx]
		req5 += m.fiveMinuteRequests[idx]
		idx++
	}
	req5Ori := req5
	if req5 <= 0 {
		req5 = 1
	}

	averageDur5 := dur5 / req5 / int64(time.Millisecond)
	reqAll := m.allRequests
	if reqAll <= 0 {
		reqAll = 1
	}
	averageDurAll := m.allDuration / reqAll / int64(time.Millisecond)

	handlerStatus := ""
	for _, v := range m.handleMux {
		if handlerStatus != "" {
			handlerStatus += "\n"
		}
		handlerStatus += v.GetStatus()
	}
	return fmt.Sprintf(ret, m.WaitingRequests, req5Ori, averageDur5, m.allRequests, averageDurAll, handlerStatus)
}

var _adapter_server *AdapterServer = nil

func GetServer() *AdapterServer {
	return _adapter_server
}

type ServerLogger struct {
}

//Printf(format string, args ...interface{})
func (m *ServerLogger) Printf(format string, args ...interface{}) {
	//s := fmt.Sprintf(format,args...)
	glog.Infof(format, args...)
}

func RegisterAdapter(path string, adapter Adapter) {
	if path == "" || adapter == nil || path[:1] != "/" {
		return
	}
	_, ok := _adapter_server.handleMux[path]
	if ok {
		glog.Errorf("service handle repeated, %s\n", path)
		return
	}
	handler := NewRequestHandler(path, adapter)
	_adapter_server.handleMux[path] = handler
	GlogV3.Infof("service [%s] registered.\n", path)
}

func (s *AdapterServer) Startup(onStartup func()) error {
	GlogV3 = glog.V(3)
	GlogV4 = glog.V(4)
	GlogV5 = glog.V(5)
	//s.requestTimeout = int64(config.IntDefault("server", "request_timeout", 300))

	for i := 0; i < len(s.fiveMinuteRequests); i++ {
		s.fiveMinuteRequests[i] = 0
	}
	for i := 0; i < len(s.fiveMinuteDuration); i++ {
		s.fiveMinuteDuration[i] = 0
	}

	s.handleMux = make(map[string]*RequestHandler)
	s.httpServer = &fasthttp.Server{
		Handler: func(ctx *fasthttp.RequestCtx) {
			if GlogV5 {
				GlogV5.Infof("Request uri: %s\n", string(ctx.URI().RequestURI()))
			}
			atomic.AddInt64(&s.WaitingRequests, 1)
			defer atomic.AddInt64(&s.WaitingRequests, -1)
			path := string(ctx.Path())
			if path == "/log" {
				s.HandleLog(ctx)
			} else if path == "/status" {
				HandleStatus(ctx)
			} else if handle, ok := s.handleMux[path]; ok {
				defer func() {
					if e := recover(); e != nil {
						os.Stderr.Write([]byte(fmt.Sprintf("%s unexcepted error: %s\n", time.Now().String(), e)))
						buf := make([]byte, 8192)
						n := runtime.Stack(buf, true)
						if n > 0 {
							buf = buf[:n]
							os.Stderr.Write(buf)
						} else {
							os.Stderr.Write([]byte("no stack trace\n"))
						}
						os.Stderr.Sync()
					}
				}()
				handle.HandleRequest(path, ctx)
			} else {
				ctx.Error("service not found\n", fasthttp.StatusNotFound)
			}
		},
		Logger: new(ServerLogger),
	}

	//load config & set config to httpServer
	config := s.config
	svr := s.httpServer
	svr.Concurrency = config.GetIntDefault("fasthttp", "concurrency_limit", 0)
	svr.DisableKeepalive = config.GetBoolDefault("fasthttp", "disable_keep_alive", false)
	svr.ReadBufferSize = config.GetIntDefault("fasthttp", "read_buf_size", 0)
	svr.WriteBufferSize = config.GetIntDefault("fasthttp", "write_buf_size", 0)
	svr.ReadTimeout = time.Second * time.Duration(config.GetIntDefault("fasthttp", "read_timeout_second", 0))
	svr.WriteTimeout = time.Second * time.Duration(config.GetIntDefault("fasthttp", "write_timeout_second", 0))
	svr.MaxConnsPerIP = config.GetIntDefault("fasthttp", "conns_per_ip_limit", 0)
	svr.MaxRequestsPerConn = config.GetIntDefault("fasthttp", "requests_per_conn_limit", 0)
	svr.IdleTimeout = time.Second * time.Duration(config.GetIntDefault("fasthttp", "keep_alive_duration_limit_second", 0))
	svr.MaxRequestBodySize = config.GetIntDefault("fasthttp", "request_body_size_limit", 0)
	svr.LogAllErrors = config.GetBoolDefault("fasthttp", "log_all_errors", false)
	svr.DisableHeaderNamesNormalizing = config.GetBoolDefault("fasthttp", "header_normalize", false)

	addr := ":" + config.Get("server", "port", "9095")
	tcpAddr, eAddr := net.ResolveTCPAddr("tcp4", addr)
	if eAddr != nil {
		glog.Errorf("resolve addr fail, %s\n", eAddr.Error())
		return eAddr
	}

	evn := os.Environ()
	isRestart := false
	for _, v := range evn {
		if strings.HasPrefix(v, "restart=") {
			isRestart = true
			break
		}
	}
	var lsn *net.TCPListener = nil
	var err error = nil
	if !isRestart {
		fmt.Println("not restart")
		lsn, err = net.ListenTCP("tcp4", tcpAddr)
	} else {
		fmt.Println("is restart")
		file := os.NewFile(uintptr(3), "listener") //stdin 0, stdout 1, stderr 2, listener 3
		l, e := net.FileListener(file)
		if e != nil {
			file.Close()
			return fmt.Errorf("FileListener fail, %s\n", e.Error())
		}
		if e := file.Close(); e != nil {
			return fmt.Errorf("close old listener fail, %s\n", e.Error())
		}
		lsn = l.(*net.TCPListener)
	}
	if err == nil {
		s.listener = lsn
		_adapter_server = s
		go svr.Serve(lsn)
		if ppid := os.Getppid(); ppid > 1 {
			syscall.Kill(ppid, syscall.SIGTERM)
		}
		glog.Infoln("service started.")
		if onStartup != nil {
			onStartup()
		}
		go s.ticktack()
	}
	return err
}

func Restart() (err error) {
	lsnFile, eFile := _adapter_server.listener.File()
	if eFile == nil {
		fmt.Println("restart, lsnFile not nil")
		// defer lsnFile.Close()
		// syscall.CloseOnExec(int(lsnFile.Fd()))
	} else {
		fmt.Println("restart listener file get failed.")
		return
	}

	// Use the original binary location. This works with symlinks such that if
	// the file it points to has been changed we will use the updated symlink.
	argv0, err := exec.LookPath(os.Args[0])
	if err != nil {
		return err
	}

	// In order to keep the working directory the same as when we started.
	wd, err := os.Getwd()
	if err != nil {
		return err
	}

	// Pass on the environment and replace the old count key with the new one.
	var env []string
	for _, v := range os.Environ() {
		if !strings.HasPrefix(v, "restart=") {
			env = append(env, v)
		}
	}
	env = append(env, "restart=1")

	allFiles := []*os.File{os.Stdin, os.Stdout, os.Stderr}
	if eFile == nil {
		allFiles = append(allFiles, lsnFile)
	}
	_, err = os.StartProcess(argv0, os.Args, &os.ProcAttr{
		Dir:   wd,
		Env:   env,
		Files: allFiles,
	})
	return err
}

func (s *AdapterServer) HandleLog(ctx *fasthttp.RequestCtx) {
	v := ctx.FormValue("v")
	if v == nil {
		ctx.WriteString("cannt find query arg: v\n")
		return
	}
	vStr := string(v)
	if vStr != "3" && vStr != "4" && vStr != "5" {
		if vInt, err := strconv.Atoi(vStr); err == nil && vInt > 0 {
			common.SetLogNumber(uint64(vInt))
		}
		info := fmt.Sprintf("set common log verbosity to %s\n", vStr)
		ctx.WriteString(info)
	} else {
		//vInt,_ := strconv.Atoi(vStr)
		// glog.SetV(glog.Level(vInt))
		a := glog.Level(0)
		a.Set(vStr)
		GlogV3 = glog.V(3)
		GlogV4 = glog.V(4)
		GlogV5 = glog.V(5)
		info := fmt.Sprintf("Set glog verbosity to %s\n", v)
		glog.Infof(info)
		ctx.WriteString(info)
	}
}
