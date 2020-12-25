/*
slave进程的实现
启动后通过unix-socket连接master进程，读取图片处理请求，处理图片，返回给master;
同时启动一个goroutine检测与master进程的通讯是否中断，如果断开则退出当前进程
*/
package magic

import (
	"net"
	"bytes"
	"time"
	"os"
	"syscall"
	"github.com/golang/glog"
	"fmt"
	"io"
	"runtime"
	"strconv"
	"encoding/json"
	"encoding/base64"
	"github.com/truexf/gocfg"
)

type MasterConnUnix struct {
	connection *net.UnixConn
	buffer bytes.Buffer
}


type Slave struct {
	masterConn *net.UnixConn
	magic *Magic
	lastSlaveTime int64
	conf *gocfg.GoConfig
}

func NewSlave(cfg *gocfg.GoConfig) *Slave {
	return &Slave{conf: cfg}
}

func (m *Slave) StartUnixServer(masterAddr string) {
	m.magic = newMagic()
	addr := masterAddr
	unixAddr, addrErr := net.ResolveUnixAddr("unix", addr)
	if addrErr != nil {
		glog.Errorf("invalid master addr: %s\n", addr)
		glog.Flush()
		<-time.After(time.Second * 1)
		os.Exit(0)
	}
	conn, err := net.DialUnix("unix", nil, unixAddr)
	if err == nil {
		glog.V(3).Infof("connect master %s success\n", addr)
		m.lastSlaveTime = time.Now().Unix()
		m.masterConn = conn
		go m.slaveForUnix(conn, addr)
	} else {
		glog.Errorf("connect master %s fail,%s\n", addr, err.Error())
	}

	for {
		<-time.After(time.Second * 1)
		if time.Now().Unix()-m.lastSlaveTime > 1800 {
			glog.Infof("more than 30 minutes no request, process terminated.")
			glog.Flush()
			<-time.After(time.Second * 1)
			os.Exit(0)
		}
		if syscall.Getppid() <= 1 {
			glog.Infof("master not found,process terminated.")
			glog.Flush()
			<-time.After(time.Second * 1)
			os.Exit(0)
		}
	}
}

func (m *Slave) slaveForUnix(masterConn *net.UnixConn, addr string) {
	defer m.closeMasterConnUnix(masterConn)
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
			<-time.After(time.Second * 1)
			os.Exit(0)
		}
	}()
	var masterObj MasterConnUnix
	masterObj.connection = masterConn
	buf := make([]byte, 4096)
	status := 3 //1 size uncomplete, 2 data uncomplete, 3 init
	dataSize := 0
	for {
		n, err := masterConn.Read(buf)
		if n > 0 {
			if status == 3 {
				status = 1
			}
			m.lastSlaveTime = time.Now().Unix()
			if glog.V(5) {
				glog.V(5).Infof("read master data %s\n", string(buf[:n]))
			}
			_, err := masterObj.buffer.Write(buf[:n])
			if err != nil {
				glog.Errorf("write buf fail, %s", err.Error())
				break
			}

			if status == 1 {
				if masterObj.buffer.Len() < 8 {
					//packet head,data size,8 bytes hex number
					continue
				}
				hexSize := string(masterObj.buffer.Bytes()[:8])
				n, err := strconv.ParseInt(hexSize, 16, 32)
				if err != nil {
					glog.Errorf("parse packet size fail, %s", err.Error())
					break
				}
				dataSize = int(n)
				status = 2
				if masterObj.buffer.Len() == 8 {
					continue
				}
			}

			if status == 2 {
				if masterObj.buffer.Len() - 8 >= dataSize {
					req,err := m.imagineRequestFromPacket(masterObj.buffer.Bytes()[8:8+dataSize])
					if err != nil {
						glog.Errorf("unmarshal from request packet fail")
						break
					}
					img, err := m.magic.processImage(req)
					if err != nil {
						m.WriteResponse(-1, fmt.Sprintf("process image fail, %s", err.Error()),nil)
					} else {
						m.WriteResponse(0,"", img)
					}
					masterObj.buffer.Reset()
					status = 3
					continue
				}
			}
		}
		if err != nil {
			if err != io.EOF {
				glog.Errorf("master disconnect unexcepted,%s\n", err.Error())
			} else {
				glog.V(3).Infof("master disconnected, io eof.")
			}
			break
		}
	}

	glog.V(3).Infof("master disconnected %s\n", addr)

}

func (m *Slave) imagineRequestFromPacket(data []byte) (*ImagineRequest, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("request data is nil")
	}
	var ret ImagineRequest
	if err := json.Unmarshal(data, &ret); err != nil {
		return nil, err
	}
	return &ret,nil
}

func (m *Slave) WriteResponse(errCode int, errMsg string, imgData []byte) error {
	var ret *ImagineResponse
	if len(imgData) > 0 {
		dataB64 := make([]byte, 0, base64.RawURLEncoding.EncodedLen(len(imgData)))
		base64.RawURLEncoding.Encode(dataB64, imgData)
		ret = &ImagineResponse{ErrCode: errCode, ErrMsg: errMsg, ImageB64: dataB64}
	} else {
		ret = &ImagineResponse{ErrCode: errCode, ErrMsg: errMsg, ImageB64: nil}
	}
	bts,_ := json.Marshal(ret)
	writeNum := 0
	for {
		n,err := m.masterConn.Write(bts[writeNum:])
		if err != nil {
			return err
		}
		if n == 0 {
			return fmt.Errorf("0 bytes written")
		}
		writeNum += n
		if writeNum >= len(bts) {
			break
		}
	}
	return nil
}

func (m *Slave) closeMasterConnUnix(conn *net.UnixConn) {
	conn.Close()
	glog.V(3).Infof("master conn %s closed,process terminated\n", conn.RemoteAddr().String())
	os.Exit(0)
}

