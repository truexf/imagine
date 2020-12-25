/*
代表master进程
--创建n个slave进程
--从web server拿到图片处理请求，
--选择一个slave进程将请求转发给他，
--等待salve的处理结果，并将结果返回给web server
*/
package magic

import (
	"encoding/json"
	"fmt"
	"github.com/golang/glog"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
	"bytes"
	"github.com/truexf/imagine/common"
	"os/exec"
	"github.com/truexf/gocfg"
	"encoding/base64"
	"github.com/valyala/fasthttp"
	"net/http"
	"github.com/truexf/imagine/storage"
)

//server side
type SlaveConnUnix struct {
	lock       sync.Mutex
	connection *net.UnixConn
}

type Master struct {
	lock        sync.Mutex
	currentConn int32
	slaves      []*SlaveConnUnix
	tcpListener *net.UnixListener
	addr        string
	slaveNums   int
	slaveLogPath string
}

var masterInstance *Master

func NewMaster(cfg *gocfg.GoConfig) *Master {
	glog.V(5).Infoln("Master")
	ret := new(Master)
	ret.currentConn = 0
	ret.slaves = make([]*SlaveConnUnix, 0)
	ret.slaveNums = cfg.GetIntDefault("default","slave-num",10)
	ret.slaveLogPath = cfg.Get("slave","glog-path", filepath.Join(common.GetExePath(),"slavelogs"))
	return ret
}

func GetMaster() *Master {
	return masterInstance
}

func (m *Master) GetConnCount() int {
	m.lock.Lock()
	defer m.lock.Unlock()
	return len(m.slaves)
}

func (m *Master) Status() string {
	return "nothing"
}

func (m *Master) StartListen() {
	fn := filepath.Join(common.GetExePath(),fmt.Sprintf("imagine_unix_%d", time.Now().Unix()))
	os.Remove(fn)
	uxAddr, err := net.ResolveUnixAddr("unix", fn)
	if err != nil {
		glog.Errorln(err.Error())
		return
	}
	lsn, errLsn := net.ListenUnix("unix", uxAddr)
	if errLsn != nil {
		glog.Errorf("listen unix [%s] fail,%s\n", fn, errLsn.Error())
	}
	m.addr = lsn.Addr().String()
	glog.V(3).Infof("master listen on %s success.\n", m.addr)
	m.createSlaveProcess(fn)
	for {
		conn, errAccept := lsn.AcceptUnix()
		if errAccept != nil {
			glog.Errorf("accept slave connection fail,%s\n", errAccept)
			continue
		}
		glog.V(5).Infof("accept slave conn %s\n", conn.RemoteAddr().String())
		slaveConn := new(SlaveConnUnix)
		slaveConn.connection = conn
		m.AddSlaveConn(slaveConn)
	}
}

func (m *Master) AddSlaveConn(conn *SlaveConnUnix) {
	glog.V(5).Infoln("add slave conn")
	m.lock.Lock()
	defer m.lock.Unlock()
	m.slaves = append(m.slaves, conn)
}
func (m *Master) RemoveSlaveConn(conn *SlaveConnUnix) {
	if conn == nil {
		return
	}
	m.lock.Lock()
	defer m.lock.Unlock()
	glog.V(3).Infof("slave conn %s closed\n", conn.connection.RemoteAddr().String())
	conn.connection.Close()
	removePos := -1
	for i, v := range m.slaves {
		if conn == v {
			removePos = i
			break
		}
	}
	if removePos > -1 {
		for i := removePos + 1; i < len(m.slaves); i++ {
			if i > 0 {
				m.slaves[i-1] = m.slaves[i]
			}
		}
		m.slaves = m.slaves[:len(m.slaves)-1]
	}
	glog.V(3).Infoln("RemoveSlaveConn success")
}

func (m *Master) GetHandleConn() *SlaveConnUnix {
	glog.V(5).Infoln("GetHandleConn")
	m.lock.Lock()
	defer m.lock.Unlock()
	if len(m.slaves) == 0 {
		return nil
	}
	m.currentConn++
	if m.currentConn >= int32(len(m.slaves)) {
		m.currentConn = 0
	}
	return m.slaves[m.currentConn]
}

func (m *Master) HandleRequest(req *ImagineRequest) (*ImagineResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("req is nil")
	}
	glog.V(5).Infof("handle request %s\n", req.Method)
	conn := m.GetHandleConn()
	if conn == nil {
		glog.Errorln("no slave conn,handle fail.")
		return nil, fmt.Errorf("no slave conn")
	}

	conn.lock.Lock()
	defer conn.lock.Unlock()

	//set read & write timeout
	if err := conn.connection.SetReadDeadline(time.Now().Add(time.Second * 30)); err != nil {
		glog.Errorf("set read deadline fail,%s\n", err.Error())
		m.RemoveSlaveConn(conn)
		return nil, fmt.Errorf("set read deadline fail, %s", err.Error())
	}
	if err := conn.connection.SetWriteDeadline(time.Now().Add(time.Second * 15)); err != nil {
		glog.Errorf("set write deadline fail,%s\n", err.Error())
		m.RemoveSlaveConn(conn)
		return nil, fmt.Errorf("set write deadline fail, %s", err.Error())
	}
	//reset deadline
	defer func() {
		if err := conn.connection.SetReadDeadline(time.Time{}); err != nil {
			glog.Errorf("set read deadline fail,%s\n", err.Error())
			m.RemoveSlaveConn(conn)
		}
		if err := conn.connection.SetWriteDeadline(time.Time{}); err != nil {
			glog.Errorf("set write deadline fail,%s\n", err.Error())
			m.RemoveSlaveConn(conn)
		}
	}()

	//write request
	btsReq,_ := json.Marshal(req)
	var bufReq bytes.Buffer
	sizeHex := fmt.Sprintf("%08x", len(btsReq))
	bufReq.WriteString(sizeHex)
	bufReq.Write(btsReq)
	_, e := conn.connection.Write(bufReq.Bytes())
	if e != nil {
		m.RemoveSlaveConn(conn)
		glog.Errorf("slave conn write data fial,%s\n", e.Error())
		return nil, fmt.Errorf("slave conn write data fial,%s\n", e.Error())
	}
	if glog.V(5) {
		glog.Infof("slave conn write success, %d", bufReq.Len())
	}

	//receive response
	buf := make([]byte, 8192*2)
	var buffer bytes.Buffer
	status := 3 //1 size uncomplete, 2 data uncomplete, 3 init
	dataSize := 0
	for {
		n, err := conn.connection.Read(buf)
		if n > 0 {
			if status == 3 {
				status = 1
			}
			if glog.V(5) {
				glog.Infof("read slave data %s\n", string(buf[:n]))
			}
			_, err := buffer.Write(buf[:n])
			if err != nil {
				glog.Errorf("write buf fail, %s", err.Error())
				return nil, fmt.Errorf("write buf fail, %s", err.Error())
			}

			if status == 1 {
				if buffer.Len() < 8 {
					//packet head,data size,8 bytes hex number
					continue
				}
				hexSize := string(buffer.Bytes()[:8])
				n, err := strconv.ParseInt(hexSize, 16, 32)
				if err != nil {
					glog.Errorf("parse packet size fail, %s", err.Error())
					return nil, fmt.Errorf("parse packet size fail, %s", err.Error())
				}
				dataSize = int(n)
				status = 2
				if buffer.Len() == 8 {
					continue
				}
			}

			if status == 2 {
				if buffer.Len() - 8 >= dataSize {
					resp,err := m.imagineResponseFromPacket(buffer.Bytes()[8:8+dataSize])
					if err != nil {
						glog.Errorf("unmarshal from response packet fail", err.Error())
						return nil, fmt.Errorf("unmarshal from response packet fail", err.Error())
					}
					status = 3
					return resp,nil
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
	return nil, fmt.Errorf("unexcepted error")
}

func (m *Master) imagineResponseFromPacket(data []byte) (*ImagineResponse, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("response data is nil")
	}
	var ret ImagineResponse
	if err := json.Unmarshal(data, &ret); err != nil {
		return nil, err
	}
	if len(ret.ImageB64) > 0 && len(ret.Image) == 0 {
		ret.Image = make([]byte,base64.RawURLEncoding.DecodedLen(len(ret.ImageB64)))
		if n,err := base64.RawURLEncoding.Decode(ret.Image,ret.ImageB64); err != nil {
			return nil, err
		} else {
			ret.Image = ret.Image[:n]
		}
	}
	return &ret,nil
}


func (m *Master) createSlaveProcess(masterAddr string) {
	glog.V(3).Infof("slave nums: %d\n", m.slaveNums)
	go func() {
		for i := 0; i < m.slaveNums; i++ {
			go m.createSlaveProcessInternal(masterAddr)
			glog.V(3).Infof("create slave %d\n", i)
			<-time.After(time.Second * 2) //for different logpath
		}
	}()
	go func() { //detect if would create a new SlaveProcess
		<-time.After(time.Second * 100)
		for {
			if m.GetConnCount() < m.slaveNums {
				go m.createSlaveProcessInternal(masterAddr)
			}
			<-time.After(time.Second * 5)
		}
	}()
}

func (m *Master) createSlaveProcessInternal(masterAddr string) {
	glog.V(5).Infoln("createSlaveProcessInternal")
	logdir := m.slaveLogPath
	if !common.FileExists(logdir) {
		os.Mkdir(logdir, 0755)
	}
	if !common.FileExists(logdir) {
		logdir = "/tmp"
	}
	logLevel := "-v=3"
	errToStd := "-logtostderr=0"
	if common.FileExists("/tmp/imagine.slave") {
		logLevel = "-v=5"
	}
	exeFile,_ := common.ExePath()
	cmdline := fmt.Sprintf("%s %s %s %s slave-mode %s",
		exeFile,
		fmt.Sprintf("-log_dir=%s", logdir),
		logLevel,
		errToStd,
		masterAddr)
	glog.V(3).Infof("create slave process %s\n", cmdline)
	cmd := exec.Command("bash", "-c", cmdline, "&")
	cmd.Run()
}

func (m *Master) HandleMagic(ctx *fasthttp.RequestCtx) error {
	params := ctx.FormValue("param")
	if len(params) == 0 {
		return fmt.Errorf("invalid param")
	}
	paramPlain := common.Decrypt(nil, params)

	var req ImagineRequest
	if err := json.Unmarshal(paramPlain, &req); err != nil {
		glog.Errorf("invalid param, %s", err.Error())
		return fmt.Errorf("invalid param")
	}

	//check storage
	uri := string(ctx.RequestURI())
	key := common.StringMd5Default(uri,"")
	st := storage.GetStorage()
	if st != nil {
		bts, err := st.Read(key)
		if err != nil {
			glog.Errorf("get image from storage fail, %s", err.Error())
			st.Delete(key)
		} else {
			ctx.Response.Header.Set("Content-Type", "image/"+req.Format)
			ctx.Response.Header.Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
			ctx.Response.Header.Set("Cache-Control", fmt.Sprintf("max-age=%d", int64(3600*24*30)))
			ctx.Response.Header.Set("Expires", time.Now().Add(time.Hour*24*30).UTC().Format(http.TimeFormat))
			ctx.SetBody(bts)
			return nil
		}
	}

	//process image
	resp, err := m.HandleRequest(&req)
	if err != nil {
		glog.Errorf("process magic [%s] fail, %s", string(params), err.Error())
		return fmt.Errorf("process image fail")
	}
	if resp == nil {
		return fmt.Errorf("process image fail, unknown error")
	}
	if resp.ErrCode != 0 {
		bts, _ := json.Marshal(resp)
		ctx.SetStatusCode(200)
		ctx.SetBody(bts)
		return nil
	}
	ctx.Response.Header.Set("Content-Type", "image/"+req.Format)
	ctx.Response.Header.Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
	ctx.Response.Header.Set("Cache-Control", fmt.Sprintf("max-age=%d", int64(3600*24*30)))
	ctx.Response.Header.Set("Expires", time.Now().Add(time.Hour*24*30).UTC().Format(http.TimeFormat))
	ctx.SetBody(resp.Image)

	//save to storage
	if st != nil {
		if err := st.Write(key, resp.Image, req.CacheSeconds); err != nil {
			glog.Errorf("write image to storage fail, %s", err.Error())
		}
	}

	return nil
}

func (m *Master) Handle(path string, ctx *fasthttp.RequestCtx) error {
	switch path {
	case "/magic":
		return m.HandleMagic(ctx)
	case "/magic_status":
		ctx.SetBodyString(m.Status())
	default:
		ctx.SetStatusCode(404)
	}
	return nil
}