package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/golang/glog"
	"github.com/truexf/gocfg"
	"github.com/truexf/goutil"
	"github.com/truexf/imagine/common"
	"github.com/truexf/imagine/http"
	"github.com/truexf/imagine/magic"
	"github.com/truexf/imagine/storage"
)

func ignoreHup() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGHUP)
	signal.Notify(c, syscall.SIGUSR2)
	for {
		sig := <-c
		if sig == syscall.SIGUSR2 {
			fmt.Println("restart...")
			http.Restart()
		} else {
			fmt.Println("get signal: SIGHUP")
		}
	}
}

func CreateConfig() *gocfg.GoConfig {
	exePath, err := os.Executable()
	if err != nil {
		glog.Errorf("os.Executable fail,%s", err.Error())
		return nil
	}
	exePath, _ = filepath.EvalSymlinks(exePath)
	fn := filepath.Dir(exePath) + "/config/imagine.ini"
	ret, e := gocfg.NewGoConfig(fn)
	if e != nil {
		glog.Errorf("load config file %s fail, %s", fn, e.Error())
		return nil
	}
	return ret
}

var (
	masterInstance *magic.Master
)

var fdRedirectErr *os.File = nil

func RedirectStdErr(path string) string {
	if path == "" || !common.FileExists(path) {
		glog.Errorf("%s is invalid path,redirect stdio fail.\n", path)
		return ""
	}
	fn := path
	if fn[len(path)-1:] != "/" {
		fn += "/"
	}
	fn += fmt.Sprintf("slave_out_%d", syscall.Getpid())
	var e error
	fdRedirectErr, e = os.OpenFile(fn, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0755)
	if e != nil {
		glog.Errorf("openfile %s fail, %s\n", fn, e.Error())
		return ""
	}

	if e := syscall.Close(2); e == nil {
		if eDup := syscall.Dup2(int(fdRedirectErr.Fd()), 2); eDup != nil {
			glog.Errorf("dup2 fail,%s\n", eDup.Error())
		} else {
			os.Stderr = fdRedirectErr
			glog.Infof("redirect stderr to %s success.\n", fn)
		}
	} else {
		glog.Errorf("close fd2 fail, %s\n", e.Error())
	}
	return fn
}

func main() {
	goutil.Daemonize(1, 1)
	go ignoreHup()
	flag.Parse()
	defer glog.Flush()

	config := CreateConfig()
	if config == nil {
		fmt.Println("create config fail")
		os.Exit(0)
	}

	if len(os.Args) > 5 && os.Args[4] == "slave-mode" {
		//i'm slave process
		runtime.GOMAXPROCS(3)
		fn := RedirectStdErr(config.Get("slave", "stdlog-path", "/tmp"))
		os.Stderr.WriteString("redirect stderr to " + fn + "\n")
		//communicating by unix
		magic.NewSlave(config).StartUnixServer(os.Args[5])
	} else {
		//i'm master process
		common.StartGoroutineMonitor(common.GetExePath(), time.Second*5, config.GetIntDefault("monitor", "goroutine-warn-num", 500))
		ossObj := storage.NewOss(config)
		if ossObj == nil {
			fmt.Println("new oss object fail")
			os.Exit(0)
		}
		storage.SetStorage(ossObj)
		masterInstance = magic.NewMaster(config)

		//start httpsvr
		svr := new(http.AdapterServer)
		svr.SetConfig(config)
		fmt.Println("starting...")
		if e := svr.Startup(OnAdapterServerStartup); e != nil {
			fmt.Printf("start adapter-server fail, %s\n", e.Error())
			os.Exit(0)
		} else {
			fmt.Println("started.")
		}

		stopChan := make(chan int)
		<-stopChan
	}
	return
}

func OnAdapterServerStartup() {
	fmt.Println("http svr startup.")
	//todo: call RegisterAdapter here
	http.RegisterAdapter("/magic", masterInstance)
	http.RegisterAdapter("/magic_status", masterInstance)
}
