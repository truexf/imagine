package common

import (
	"fmt"
	"github.com/golang/glog"
	"io/ioutil"
	"path/filepath"
	"runtime"
	"time"
)

func StartGoroutineMonitor(statisPath string, monitorInterval time.Duration, maxGroutineNum int) {
	if !FileExists(statisPath) {
		panic(fmt.Sprintf("monitor path: %s not exists"))
	}
	go func() {
		for {
			<-time.After(monitorInterval)
			num := runtime.NumGoroutine()
			if num > maxGroutineNum {
				stack := make([]byte, 1024*1024*10)
				n := runtime.Stack(stack, true)
				if n > 0 {
					fn := filepath.Join(statisPath, time.Now().Format("20060102150405.stack"))
					err := ioutil.WriteFile(fn, stack[:n], 0666)
					if err != nil {
						glog.Errorf("numgoutine > %d, write stack to file [%s] fail, %s\n", maxGroutineNum, fn, err.Error())
					} else {
						glog.Errorf("numgoutine > %d, stack wrote to file [%s]\n", maxGroutineNum, fn)
						return
					}
				} else {
					glog.Errorf("numgoroutine > %d, get stack fail.", maxGroutineNum)
				}
			}
		}
	}()
}
