package storage

import (
	"bytes"
	"github.com/aliyun/aliyun-oss-go-sdk/oss"
	"github.com/golang/glog"
	"io"
	"sync"
	"github.com/truexf/gocfg"
)

var ossLock sync.Mutex

type ossPacket struct {
	key  string
	data []byte
	Delete bool
}
type Oss struct {
	endPoint   string
	key        string
	secret     string
	bucket     string
	reader     *oss.Bucket
	writer     *oss.Bucket
	writeQueue chan *ossPacket
	readLock   sync.Mutex
}

func NewOss(conf *gocfg.GoConfig) *Oss {
	endpoint := conf.Get("oss", "endpoint","")
	key := conf.Get("oss", "key", "")
	secret := conf.Get("oss", "secret", "")
	bucket := conf.Get("oss", "bucket", "")
	if endpoint == "" || key == "" || secret == "" || bucket == "" {
		return nil
	}
	ossLock.Lock()
	defer ossLock.Unlock()

	ret := new(Oss)
	ret.endPoint = endpoint
	ret.key = key
	ret.secret = secret
	ret.bucket = bucket

	reader, err := oss.New(endpoint, key, secret)
	if err != nil {
		glog.Errorf("create oss client fail, %s\n", err.Error())
		return nil
	} else {
		ret.reader, err = reader.Bucket(bucket)
		if err != nil {
			glog.Errorf("get bucket fail,%s\n", err.Error())
			return nil
		}
	}
	writer, err := oss.New(endpoint, key, secret)
	if err != nil {
		glog.Errorf("create oss client fail, %s\n", err.Error())
		return nil
	} else {
		ret.writer, err = writer.Bucket(bucket)
		if err != nil {
			glog.Errorf("get bucket fail,%s\n", err.Error())
			return nil
		}
	}
	ret.writeQueue = make(chan *ossPacket, 8192)

	go ret.writeLoop()
	return ret
}

func (m *Oss) writeLoop() {
	for {
		pkt := <-m.writeQueue
		if pkt.Delete {
			if err := m.writer.DeleteObject(pkt.key); err != nil {
				glog.Errorf("delete oss key: %s fail, %s", pkt.key, err.Error())
			}
		} else {
			err := m.writer.PutObject(pkt.key, bytes.NewReader(pkt.data))
			if err != nil {
				glog.Errorf("oss putobject [%s] fail,%s\n", pkt.key, err.Error())
			} else {
				if glog.V(5) {
					glog.Infof("oss putobject %s ok\n", pkt.key)
				}
			}
		}
	}
}

func (m *Oss) Write(keyParam string, dataParam []byte, expireSecond int64) (err error) {
	if len(keyParam) == 0 || len(dataParam) == 0 {
		return nil
	}
	realKey := "magic-" + keyParam
	m.writeQueue <- &ossPacket{key: realKey, data: dataParam}
	return nil
}

func (m *Oss) Read(paramKey string) (retData []byte, retErr error) {
	key := "magic-" + paramKey
	m.readLock.Lock()
	defer m.readLock.Unlock()
	dataReader, err := m.reader.GetObject(key)
	if err != nil {
		glog.Errorf("oss read [%s] fail, %s\n", key, err.Error())
		return nil, err
	}
	data := make([]byte, 0, 1024*512)
	packet := make([]byte, 8192)
	for {
		if len(data) > 8*1024*1024 {
			glog.Errorln("oss read data is too big,>8M")
			return nil, bytes.ErrTooLarge
		}
		n := 0
		n, err := dataReader.Read(packet)

		if n > 0 {
			data = append(data, packet[:n]...)
		}
		if err != nil {
			if err == io.EOF {
				break
			} else {
				glog.Errorf("oss read buffer fail,%s\n ", err.Error)
				return nil, err
			}
		}
	}
	if glog.V(5) {
		glog.Infof("oss getobject %s ok \n", key)
	}
	return data, nil
}

func (m *Oss) Delete(key string) {
	realKey := "magic-" + key
	m.writeQueue <- &ossPacket{key: realKey, Delete: true}
}

func (m *Oss) Exists(key string) bool {
	ret,_ := m.Read(key)
	return ret != nil
}