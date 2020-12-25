package common

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rc4"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/cespare/xxhash"
	"github.com/valyala/fasthttp"
	"io"
	"math"
	"math/rand"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var _hostName string
var _logNumber uint64 = 0

func init() {
	var err error
	_hostName, err = os.Hostname()
	if err != nil {
		_hostName = "0"
	}
}

func SetLogNumber(n uint64) {
	_logNumber = n
}

func GetLogNumber() uint64 {
	return _logNumber
}

func TrimJsonComment(jsn string) string {
	btsList := SplitByLine(jsn)
	sRet := ""
	for _, v := range btsList {
		v1 := strings.TrimSpace(v)
		if len(v1) >= 2 && v1[:2] == "//" {
			continue
		}
		if sRet == "" {
			sRet += "\n"
		}
		sRet += v
	}
	return sRet
}

type ClearStdoutHandle struct {
}

type ClearStdoutHandle2 struct {
}

func (m *ClearStdoutHandle2) Handle(path string, ctx *fasthttp.RequestCtx) error {
	remoteIp := RemoteIp(ctx)
	if strings.Index(remoteIp, "127.0.0.1") < 0 && strings.Index(remoteIp, "192.168") < 0 {
		ctx.SetStatusCode(404)
		return nil
	}
	ClearStdout()
	return nil
}

func (m *ClearStdoutHandle) Handle(ctx *fasthttp.RequestCtx) error {
	remoteIp := RemoteIp(ctx)
	if strings.Index(remoteIp, "127.0.0.1") < 0 && strings.Index(remoteIp, "192.168") < 0 {
		ctx.SetStatusCode(404)
		return nil
	}
	ClearStdout()
	return nil
}
func ClearStdout() {
	if err := syscall.Ftruncate(syscall.Stdout, 0); err == nil {
		syscall.Seek(syscall.Stdout, 0, 0)
	}
}

func FastHttpGet(uri string, timeoutMilliSecond int, response *fasthttp.Response) error {
	if response == nil {
		return fmt.Errorf("param response is nil")
	}
	httpRequest := fasthttp.AcquireRequest()
	if httpRequest == nil {
		return fmt.Errorf("acquire request fail")
	}
	defer fasthttp.ReleaseRequest(httpRequest)
	httpRequest.SetRequestURI(uri)
	httpRequest.Header.SetMethod("GET")

	if timeoutMilliSecond <= 0 {
		return fasthttp.Do(httpRequest, response)
	}
	return fasthttp.DoTimeout(httpRequest, response, time.Duration(timeoutMilliSecond)*time.Millisecond)
}

func FastHttpPost(uri string, postData []byte, contentType string, timeoutMilliSecond int, response *fasthttp.Response) error {
	if response == nil {
		return fmt.Errorf("param response is nil")
	}
	httpRequest := fasthttp.AcquireRequest()
	if httpRequest == nil {
		return fmt.Errorf("acquire request fail")
	}
	defer fasthttp.ReleaseRequest(httpRequest)
	httpRequest.SetRequestURI(uri)
	httpRequest.Header.SetMethod("POST")
	httpRequest.SetBody(postData)
	if contentType == "" {
		httpRequest.Header.SetContentType("application/octet-stream")
	} else {
		httpRequest.Header.SetContentType(contentType)
	}
	httpRequest.Header.SetContentLength(len(postData))

	if timeoutMilliSecond <= 0 {
		return fasthttp.Do(httpRequest, response)
	}
	return fasthttp.DoTimeout(httpRequest, response, time.Duration(timeoutMilliSecond)*time.Millisecond)
}

func InSliceInt(i int, sls []int) bool {
	for _, v := range sls {
		if v == i {
			return true
		}
	}
	return false
}
func InSlice(s string, sls []string, caseIgnore bool) bool {
	for _, v := range sls {
		if caseIgnore {
			if strings.EqualFold(s, v) {
				return true
			}
		} else {
			if s == v {
				return true
			}
		}
	}
	return false
}

func DeleteSlice(from []string, value string) []string {
	ret := make([]string, 0, len(from))
	for i := 0; i < len(from); i++ {
		if from[i] != value {
			ret = append(ret, from[i])
		}
	}
	return ret
}

func DeleteSliceInt(from []int, value int) []int {
	ret := make([]int, 0, len(from))
	for i := 0; i < len(from); i++ {
		if from[i] != value {
			ret = append(ret, from[i])
		}
	}
	return ret
}

func Base64Padding(b64_string string) string {
	switch len(b64_string) % 4 {
	case 3:
		return b64_string + "="
	case 2:
		return b64_string + "=="
	default:
		return b64_string
	}
}

func GetExePath() string {
	exePath, err := os.Executable()
	if err != nil {
		return ""
	}
	exePath, _ = filepath.EvalSymlinks(exePath)
	return filepath.Dir(exePath)
}

func RemoteIp2(req *fasthttp.Request) string {
	if req == nil {
		return ""
	}
	clientIp := ""
	req.Header.VisitAll(func(key []byte, value []byte) {
		if strings.EqualFold(string(key), "X-Forwarded-For") {
			sl := strings.Split(string(value), ",")
			if len(sl) > 0 {
				clientIp = sl[0]
				return
			}
		}
	})
	return clientIp
}

type IpRange struct {
	B uint32
	E uint32
}

func IsLanIp(ipv4 string) bool {
	//10.0.0.0~10.255.255.255
	//172.16.0.0~172.31.255.255
	//192.168.0.0~192.168.255.255
	rangeList := []IpRange{IpRange{B: 0x0a000000, E: 0x0affffff},
		IpRange{B:0xac100000, E: 0xac1fffff},
		IpRange{B:0xc0a80000, E: 0xc0a8ffff},
	}
	ipv4Uint := Ipv4Int(ipv4)
	for _,v := range rangeList {
		if ipv4Uint > v.B && ipv4Uint < v.E {
			return true
		}
	}
	return false
}

func MultiXFF(ctx *fasthttp.RequestCtx) bool {
	ret := false
	ctx.Request.Header.VisitAll(func(key []byte, value []byte) {
		if strings.EqualFold(string(key), "X-Forwarded-For") {
			sl := strings.Split(string(value), ",")
			ret = len(sl) > 1
			return
		}
	})
	return ret
}

func RemoteIp(ctx *fasthttp.RequestCtx) string {
	if ctx == nil {
		return ""
	}
	clientIp := ""
	ctx.Request.Header.VisitAll(func(key []byte, value []byte) {
		if strings.EqualFold(string(key), "X-Real-IP") {
			clientIp = string(value)
			if clientIp != "" {
				return
			}
		}
	})
	if clientIp == "" {
		ctx.Request.Header.VisitAll(func(key []byte, value []byte) {
			if strings.EqualFold(string(key), "X-Forwarded-For") {
				sl := strings.Split(string(value), ",")
				if len(sl) > 0 {
					clientIp = sl[len(sl)-1]
					return
				}
			}
		})
	}
	if clientIp == "" {
		clientIp = ctx.RemoteIP().String()
	}
	return clientIp
}

func LeftRuneStr(s string, count int) string {
	return leftRuneStr(s, count)
}
func leftRuneStr(s string, count int) string {
	cnt := 0
	for i, _ := range s {
		cnt++
		if cnt > count {
			fmt.Println(cnt)
			return s[:i]
		}
	}
	return s
}

func RightRunStr(s string, count int) string {
	return rightRunStr(s, count)
}
func rightRunStr(s string, count int) string {
	n := lenRuneStr(s)
	if n <= count {
		return s
	}
	return s[n-count:]
}

func LenRuneStr(s string) int {
	return lenRuneStr(s)
}
func lenRuneStr(s string) int {
	ret := 0
	for i, _ := range s {
		ret++
		if i == 0 {
		}
	}
	return ret
}

func SubRuneStr(s string, start int, count int) string {
	return subRuneStr(s, start, count)
}
func subRuneStr(s string, start int, count int) string {
	if s == "" || start < 0 || count <= 0 {
		return ""
	}
	cnt := 0
	idx := -1
	istart := -1
	iend := -1
	for i, _ := range s {
		idx++
		if istart == -1 && idx == start {
			istart = i
		}
		if istart > -1 {
			cnt++
		}
		if cnt > count {
			iend = i
			return s[istart:iend]
		}
	}
	if istart > -1 {
		if iend > -1 {
			return s[istart:iend]
		} else {
			return s[istart:]
		}
	}
	return ""
}

func FileExists(file string) bool {
	_, err := os.Stat(file)
	return err == nil
}

func IsDir(fn string) bool {
	st, err := os.Stat(fn)
	return err == nil && st.IsDir()
}

func FileModTime(file string) string {
	fi, err := os.Stat(file)
	if err != nil {
		return ""
	} else {
		return fi.ModTime().String()
	}
}

func SplitLR(s string, separator string) (l string, r string) {
	ret := strings.Split(s, separator)
	if len(ret) == 1 {
		return ret[0], ""
	} else {
		return ret[0], strings.Join(ret[1:], separator)
	}
}

func SplitByLine(s string) (ret []string) {
	if s == "" {
		return make([]string, 0)
	}
	ret3 := make([]string, 0)
	ret2 := make([]string, 0)
	tmp := make([]string, 0)
	ret1 := strings.Split(s, "\r\n")
	var j int
	j = len(ret1)
	for i := 0; i < j; i++ {
		tmp = strings.Split(ret1[i], "\r")
		x := len(tmp)
		for k := 0; k < x; k++ {
			ret2 = append(ret2, tmp[k])
		}
	}
	j = len(ret2)
	for i := 0; i < j; i++ {
		tmp = strings.Split(ret2[i], "\n")
		x := len(tmp)
		for k := 0; k < x; k++ {
			ret3 = append(ret3, tmp[k])
		}
	}
	return ret3
}

func FileMd5(fn string) (string, error) {
	f, err := os.Open(fn)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := md5.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func BytesMd5(b []byte) (string, error) {
	h := md5.New()
	retn := 0
	for {
		btmp := b[retn:]
		n, e := h.Write(btmp)
		retn += n
		if e != nil && retn < len(b) {
			return "", e
		}
		if retn >= len(b) {
			break
		}
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func StringMd5(s string) (string, error) {
	return BytesMd5([]byte(s))
}
func StringMd5Default(s string, dft string) string {
	ret, err := StringMd5(s)
	if err != nil {
		return dft
	}
	return ret
}

func Sha1String(data string) string {
	sha1 := sha1.New()
	sha1.Write([]byte(data))
	return hex.EncodeToString(sha1.Sum([]byte(nil)))
}

func Md5(b []byte) ([]byte, error) {
	h := md5.New()
	retn := 0
	for {
		btmp := b[retn:]
		n, e := h.Write(btmp)
		retn += n
		if e != nil && retn < len(b) {
			return nil, e
		}
		if retn >= len(b) {
			break
		}
	}
	return h.Sum(nil), nil
}
func Gzip(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, err := zw.Write(data)
	if err != nil {
		return nil, fmt.Errorf(err.Error())
	}
	zw.Flush()
	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf(err.Error())
	}
	return buf.Bytes(), nil
}

func Gunzip(data []byte) ([]byte, error) {
	buf := bytes.NewBuffer(data)
	zr, eNew := gzip.NewReader(buf)
	if eNew != nil {
		return nil, eNew
	}
	var bufRet bytes.Buffer
	_, err := io.Copy(&bufRet, zr)
	if err != nil {
		return nil, fmt.Errorf(err.Error())
	}
	zr.Close()
	return bufRet.Bytes(), nil
}

func Rc4(key []byte, data []byte) []byte {
	c, e := rc4.NewCipher(key)
	if e != nil {
		fmt.Println("fail.")
		return nil
	}
	bs := make([]byte, len(data))
	c.XORKeyStream(bs, data)
	return bs
}

func EncryptStr(level string, data string) string {
	k := "encrykey1^"
	if level == "ax" {
		k = "encrykey2^"
	} else if level == "ae" {
		k = "encrykey3^"
	} else if level == "by" {
		k = "encrykey3^"
	} else if level == "sz" {
		k = "encrykey4^"
	}
	btsRet := Rc4([]byte(k), []byte(data))
	return base64.RawURLEncoding.EncodeToString(btsRet)
}

func DecryptStr(level string, data string) string {
	bts, err := base64.RawURLEncoding.DecodeString(data)
	if err != nil {
		return ""
	}
	k := "encrykey1^"
	if level == "ax" {
		k = "encrykey2^"
	} else if level == "ae" {
		k = "encrykey3^"
	} else if level == "by" {
		k = "encrykey3^"
	} else if level == "sz" {
		k = "encrykey4^"
	}
	return string(Rc4([]byte(k), bts))
}

func Encrypt(level []byte, data []byte) []byte {
	k := []byte("encrykey1^")
	if bytes.Equal(level, []byte("ax")) {
		k = []byte("encrykey2^")
	} else if bytes.Equal(level, []byte("ae")) {
		k = []byte("encrykey3^")
	} else if bytes.Equal(level, []byte("by")) {
		k = []byte("encrykey3^")
	} else if bytes.Equal(level, []byte("sz")) {
		k = []byte("encrykey4^")
	}
	return Rc4(k, data)
}

func Decrypt(level []byte, data []byte) []byte {
	l := base64.RawURLEncoding.DecodedLen(len(data))
	bts := make([]byte, l, l+10)
	n, err := base64.RawURLEncoding.Decode(bts, data)
	if err != nil {
		return nil
	}
	bts = bts[:n]
	k := []byte("encrykey1^")
	if bytes.Equal(level, []byte("ax")) {
		k = []byte("encrykey2^")
	} else if bytes.Equal(level, []byte("ae")) {
		k = []byte("encrykey3^")
	} else if bytes.Equal(level, []byte("by")) {
		k = []byte("encrykey3^")
	} else if bytes.Equal(level, []byte("sz")) {
		k = []byte("encrykey4^")
	}
	return Rc4(k, bts)
}

func ExePath() (string, error) {
	exePath, err := os.Executable()
	if err != nil {
		return "", err
	}
	exePath, err = filepath.EvalSymlinks(exePath)
	if err != nil {
		return "", err
	}
	return exePath, nil
}

var base36 = []byte{
	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
	'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
	'U', 'V', 'W', 'X', 'Y', 'Z'}

var index = map[byte]int{
	'0': 0, '1': 1, '2': 2, '3': 3, '4': 4,
	'5': 5, '6': 6, '7': 7, '8': 8, '9': 9,
	'A': 10, 'B': 11, 'C': 12, 'D': 13, 'E': 14,
	'F': 15, 'G': 16, 'H': 17, 'I': 18, 'J': 19,
	'K': 20, 'L': 21, 'M': 22, 'N': 23, 'O': 24,
	'P': 25, 'Q': 26, 'R': 27, 'S': 28, 'T': 29,
	'U': 30, 'V': 31, 'W': 32, 'X': 33, 'Y': 34,
	'Z': 35,
	'a': 10, 'b': 11, 'c': 12, 'd': 13, 'e': 14,
	'f': 15, 'g': 16, 'h': 17, 'i': 18, 'j': 19,
	'k': 20, 'l': 21, 'm': 22, 'n': 23, 'o': 24,
	'p': 25, 'q': 26, 'r': 27, 's': 28, 't': 29,
	'u': 30, 'v': 31, 'w': 32, 'x': 33, 'y': 34,
	'z': 35,
}

func EncodeBase36(value int64) string {

	var res [16]byte
	var i int
	for i = len(res) - 1; value != 0; i-- {
		res[i] = base36[value%36]
		value /= 36
	}
	ret := string(res[i+1:])
	return strings.ToLower(ret)
}

func DecodeBase36(s string) int64 {

	res := int64(0)
	l := len(s) - 1
	for idx := range s {
		c := s[l-idx]
		byteOffset := index[c]
		res += int64(byteOffset) * int64(math.Pow(36, float64(idx)))
	}
	return res
}

// Convert uint to net.IP
func Inet_ntoa(ipnr int64) net.IP {
	var bytes [4]byte
	bytes[0] = byte(ipnr & 0xFF)
	bytes[1] = byte((ipnr >> 8) & 0xFF)
	bytes[2] = byte((ipnr >> 16) & 0xFF)
	bytes[3] = byte((ipnr >> 24) & 0xFF)

	return net.IPv4(bytes[3], bytes[2], bytes[1], bytes[0])
}

// Convert net.IP to int64
func Inet_aton(ipnr net.IP) int64 {
	bits := strings.Split(ipnr.String(), ".")
	if len(bits) < 4 {
		bits = strings.Split("127.0.0.1", ".")
	}

	b0, _ := strconv.Atoi(bits[0])
	b1, _ := strconv.Atoi(bits[1])
	b2, _ := strconv.Atoi(bits[2])
	b3, _ := strconv.Atoi(bits[3])

	var sum int64

	sum += int64(b0) << 24
	sum += int64(b1) << 16
	sum += int64(b2) << 8
	sum += int64(b3)

	return sum
}

func GetHostName() string {
	return _hostName
}

func JsonMarshal(t interface{}) ([]byte, error) {
	buffer := &bytes.Buffer{}
	encoder := json.NewEncoder(buffer)
	encoder.SetEscapeHTML(false)
	err := encoder.Encode(t)
	return buffer.Bytes(), err
}

func JsonMarshalIndent(t interface{}) ([]byte, error) {
	buffer := &bytes.Buffer{}
	encoder := json.NewEncoder(buffer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "    ")
	err := encoder.Encode(t)
	return buffer.Bytes(), err
}

func NewUUID(length int) string {
	h := _hostName
	d := fmt.Sprintf("%d-%d-%s,%d,%d", time.Now().Nanosecond(), rand.Intn(12345), h, os.Getpid(), os.Getppid())
	ret, err := StringMd5(d)
	if err != nil {
		return ""
	}
	if length < len(ret) {
		return ret[:length]
	} else if length > len(ret) {
		return ret + strings.Repeat("0", length-len(ret))
	}
	return ret
}

func NewMac() string {
	a := []byte{'A', 'B', 'C', 'D', 'E'}
	a1 := []byte{'a', 'b', 'c', 'd', 'e'}
	b := []byte{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'}
	lenA := len(a)
	lenB := len(b)
	ret := make([]byte, 0, 20)
	var ax *[]byte
	rx := rand.Intn(16)
	if rx%2 == 0 {
		ax = &a
	} else {
		ax = &a1
	}
	for i := 0; i < 6; i++ {
		ai := rand.Intn(lenA)
		if ai == lenA {
			ai--
		}
		bi := rand.Intn(lenB)
		if bi == lenB {
			bi--
		}
		bi1 := rand.Intn(lenB)
		if bi1 == lenB {
			bi1--
		}
		if len(ret) > 0 {
			ret = append(ret, ':')
		}
		if ai%3 == 1 {
			ret = append(ret, b[bi])
			ret = append(ret, b[bi1])
		} else if ai%2 == 0 {
			ret = append(ret, b[bi])
			ret = append(ret, (*ax)[ai])
		} else {
			ret = append(ret, (*ax)[ai])
			ret = append(ret, b[bi])
		}
	}
	return string(ret)
}

//加密相关 begin
var paddingErr error = errors.New("Error Padding")

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padText...)
}

func PKCS5UnPadding(origData []byte, blockSize int) ([]byte, error) {
	length := len(origData)
	unPadding := int(origData[length-1])
	if unPadding > 0 && unPadding <= blockSize {
		return origData[:(length - unPadding)], nil
	}
	return origData[:], paddingErr
}

func AesEcbPkcs5Encrypt(data []byte, keyHex string) ([]byte, error) {
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, err
	}
	//key = PKCS5Padding(key,aes.BlockSize)
	if len(key) != aes.BlockSize {
		return nil, fmt.Errorf("key for aes must be 16 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	fmt.Println(block.BlockSize())
	dataPadding := PKCS5Padding(data, aes.BlockSize)
	ret := make([]byte, len(dataPadding))
	src := dataPadding
	dst := ret
	for len(src) > 0 {
		block.Encrypt(dst, src[:aes.BlockSize])
		src = src[aes.BlockSize:]
		dst = dst[aes.BlockSize:]
	}
	return ret, nil
}

func AesEcbPkcs5Decrypt(data []byte, keyHex string) ([]byte, error) {
	if len(data)%aes.BlockSize > 0 {
		return nil, fmt.Errorf("data size to descrypt is not multple 128 bits.")
	}
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, err
	}
	//key = PKCS5Padding(key,aes.BlockSize)
	if len(key) != aes.BlockSize {
		return nil, fmt.Errorf("key for aes must be 16 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	fmt.Println(block.BlockSize())
	ret := make([]byte, len(data))
	src := data
	dst := ret
	for len(src) > 0 {
		block.Decrypt(dst, src[:aes.BlockSize])
		src = src[aes.BlockSize:]
		dst = dst[aes.BlockSize:]
	}
	return PKCS5UnPadding(ret, aes.BlockSize)
}

func AesCbcPkcs5Encrypt(data []byte, keyHex string) ([]byte, error) {
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, err
	}
	if len(key) != aes.BlockSize {
		return nil, fmt.Errorf("key for aes must be 16 bytes")
	}
	dataPadding := PKCS5Padding(data, aes.BlockSize)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCEncrypter(block, key)
	crypted := make([]byte, len(dataPadding))
	mode.CryptBlocks(crypted, dataPadding)
	return crypted, nil
}

func AesCbcPkcs5Decrypt(data []byte, keyHex string) ([]byte, error) {
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, err
	}
	if len(key) != aes.BlockSize {
		return nil, fmt.Errorf("key for aes must be 16 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	mode := cipher.NewCBCDecrypter(block, key)
	crypted := make([]byte, len(data))
	mode.CryptBlocks(crypted, data)
	return PKCS5UnPadding(crypted, aes.BlockSize)
}

//加密相关 end.

func IsInteger(v interface{}) bool {
	if v == nil {
		return false
	}
	rv := reflect.ValueOf(v)
	switch kd := rv.Kind(); kd {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return true
	}
	return false
}

func IsString(v interface{}) bool {
	if v == nil {
		return false
	}
	rv := reflect.ValueOf(v)
	return rv.Kind() == reflect.String
}

func IsFloat(v interface{}) bool {
	if v == nil {
		return false
	}
	rv := reflect.ValueOf(v)
	switch kd := rv.Kind(); kd {
	case reflect.Float64, reflect.Float32:
		return true
	}
	return false
}

func IsSlice(v interface{}) bool {
	if v == nil {
		return false
	}
	rv := reflect.ValueOf(v)
	return rv.Kind() == reflect.Slice
}

func IsMap(v interface{}) bool {
	if v == nil {
		return false
	}
	rv := reflect.ValueOf(v)
	return rv.Kind() == reflect.Map
}

func GetFloatValueDefault(v interface{}, dft float64) float64 {
	ret,ok := GetFloatValue(v)
	if ok {
		return ret
	}
	return dft
}

func GetFloatValue(v interface{}) (float64, bool) {
	if v == nil {
		return 0, true
	}
	rv := reflect.ValueOf(v)
	switch kd := rv.Kind(); kd {
	case reflect.Slice:
		return 0, false
	case reflect.String:
		vs := v.(string)
		if ret, err := strconv.ParseFloat(vs, 64); err != nil {
			return 0, false
		} else {
			return ret, true
		}
	case reflect.Float64:
		return v.(float64), true
	case reflect.Float32:
		return float64(v.(float32)), true
	case reflect.Int:
		return float64(v.(int)), true
	case reflect.Int8:
		return float64(v.(int8)), true
	case reflect.Int16:
		return float64(v.(int16)), true
	case reflect.Int32:
		return float64(v.(int32)), true
	case reflect.Int64:
		return float64(v.(int64)), true
	case reflect.Uint:
		return float64(v.(uint)), true
	case reflect.Uint8:
		return float64(v.(uint8)), true
	case reflect.Uint16:
		return float64(v.(uint16)), true
	case reflect.Uint32:
		return float64(v.(uint32)), true
	case reflect.Uint64:
		return float64(v.(uint64)), true
	case reflect.Uintptr:
		return float64(v.(uintptr)), true
	default:
		return 0, false
	}
}

func GetIntValueDefault(v interface{}, dft int64) int64 {
	ret,ok := GetIntValue(v)
	if ok {
		return ret
	}
	return dft
}
func GetIntValue(v interface{}) (int64, bool) {
	if v == nil {
		return 0, true
	}
	rv := reflect.ValueOf(v)
	switch kd := rv.Kind(); kd {
	case reflect.Slice:
		return 0, false
	case reflect.String:
		vs := v.(string)
		if ret, err := strconv.ParseInt(vs, 0, 64); err != nil {
			if retFloat, err := strconv.ParseFloat(vs, 64); err != nil {
				return 0, false
			} else {
				return int64(retFloat), true
			}
		} else {
			return ret, true
		}
	case reflect.Float64:
		return int64(v.(float64)), true
	case reflect.Float32:
		return int64(v.(float32)), true
	case reflect.Int:
		return int64(v.(int)), true
	case reflect.Int8:
		return int64(v.(int8)), true
	case reflect.Int16:
		return int64(v.(int16)), true
	case reflect.Int32:
		return int64(v.(int32)), true
	case reflect.Int64:
		return v.(int64), true
	case reflect.Uint:
		return int64(v.(uint)), true
	case reflect.Uint8:
		return int64(v.(uint8)), true
	case reflect.Uint16:
		return int64(v.(uint16)), true
	case reflect.Uint32:
		return int64(v.(uint32)), true
	case reflect.Uint64:
		return int64(v.(uint64)), true
	case reflect.Uintptr:
		return int64(v.(uintptr)), true
	default:
		return 0, false
	}
}

func GetStringValue(v interface{}) string {
	if v == nil {
		return ""
	}
	rv := reflect.ValueOf(v)
	switch kd := rv.Kind(); kd {
	case reflect.Slice:
		return ""
	case reflect.String:
		return v.(string)
	case reflect.Float64, reflect.Float32:
		return fmt.Sprintf("%f", v)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return fmt.Sprintf("%d", v)
	default:
		return ""
	}
	return ""
}

func UrlEncodedMarshal(structObj interface{}) string {
	vl := reflect.ValueOf(structObj)
	if vl.Kind() == reflect.Ptr {
		vl = reflect.Indirect(vl)
	}
	if vl.Kind() != reflect.Struct {
		return ""
	}
	tp := vl.Type()
	ret := ""
	for i := 0; i < tp.NumField(); i++ {
		kv := "%s=%s"
		tag := tp.Field(i).Tag.Get("json")
		if tag == "" {
			tag = tp.Field(i).Name
		}
		value := GetStringValue(vl.Field(i).Interface())
		if value == "" {
			continue
		}
		tagList := strings.Split(tag, ",")
		if ret != "" {
			ret += "&"
		}
		ret += fmt.Sprintf(kv, tagList[0], url.QueryEscape(value))
	}
	return ret
}

func Fnv32(key string) uint32 {
	hash := uint32(2166136261)
	const prime32 = uint32(16777619)
	for i := 0; i < len(key); i++ {
		hash *= prime32
		hash ^= uint32(key[i])
	}
	return hash
}

func XXHash(data []byte) uint64 {
	return xxhash.Sum64(data)
}

func XXHashStr(s string) uint64 {
	return xxhash.Sum64String(s)
}

func JoinIntSlice(lst []int, split string) string {
	if len(lst) == 0 {
		return ""
	}
	ret := ""
	for _, v := range lst {
		if ret != "" {
			ret += split
		}
		ret += strconv.Itoa(v)
	}
	return ret
}

func SplitByComma(str string) []string {
	sl := strings.Split(str, ",")
	ret := make([]string, 0, len(sl))
	for _, v := range sl {
		lst := strings.Split(v, "，")
		for _, vv := range lst {
			ret = append(ret, vv)
		}
	}
	return ret
}

func GetPlainBody(resp *fasthttp.Response) []byte {
	if resp == nil {
		return nil
	}
	encoding := string(resp.Header.Peek("Content-Encoding"))
	if strings.Index(encoding, "gzip") >= 0 {
		if bts, err := resp.BodyGunzip(); err != nil {
			return nil
		} else {
			return bts
		}
	} else if strings.Index(encoding, "deflate") >= 0 {
		if bts, err := resp.BodyInflate(); err != nil {
			return nil
		} else {
			return bts
		}
	}

	return resp.Body()
}

func GetPlainBody2(req *fasthttp.Request) []byte {
	if req == nil {
		return nil
	}
	encoding := string(req.Header.Peek("Content-Encoding"))
	if strings.Index(encoding, "gzip") >= 0 {
		if bts, err := req.BodyGunzip(); err != nil {
			return nil
		} else {
			return bts
		}
	} else if strings.Index(encoding, "deflate") >= 0 {
		if bts, err := req.BodyInflate(); err != nil {
			return nil
		} else {
			return bts
		}
	}

	return req.Body()
}

func ParseDomain(urls []string) []string {
	if len(urls) == 0 {
		return nil
	}
	ret := make([]string, 0, len(urls))
	for _, v := range urls {
		u, err := url.ParseRequestURI(v)
		if err == nil {
			ret = append(ret, u.Hostname())
		}
	}
	return ret
}

func DistinctStrings(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	ret := make([]string, 0, len(s))
	for _, v := range s {
		if v == "" {
			continue
		}
		exists := false
		for _, vv := range ret {
			if vv == v {
				exists = true
				break
			}
		}
		if !exists {
			ret = append(ret, v)
		}
	}

	return ret
}

func FormatTmDay(tm string, year bool) string {
	if len(tm) < 8 {
		return tm
	}
	if year {
		return fmt.Sprintf("%s-%s-%s", tm[:4], tm[4:6], tm[6:8])
	} else {
		return fmt.Sprintf("%s-%s", tm[4:6], tm[6:8])
	}
}

func FormatTmHour(tm string, year bool) string {
	if len(tm) < 10 {
		return tm
	}
	if year {
		return fmt.Sprintf("%s-%s-%s %s:00", tm[:4], tm[4:6], tm[6:8], tm[8:10])
	} else {
		return fmt.Sprintf("%s-%s %s:00", tm[4:6], tm[6:8], tm[8:10])
	}
}

func FormatTmMinute(tm string, year bool) string {
	if len(tm) < 12 {
		return tm
	}
	if year {
		return fmt.Sprintf("%s-%s-%s %s:%s", tm[:4], tm[4:6], tm[6:8], tm[8:10], tm[10:12])
	} else {
		return fmt.Sprintf("%s-%s %s:%s", tm[4:6], tm[6:8], tm[8:10], tm[10:12])
	}
}

func Ipv4Int(ip string) uint32 {
	list := strings.Split(ip, ".")
	if len(list) != 4 {
		return 0
	}
	b1, err := strconv.Atoi(list[0])
	if err != nil || b1 > 255 || b1 < 0 {
		return 0
	}
	b2, err := strconv.Atoi(list[1])
	if err != nil || b2 > 255 || b2 < 0 {
		return 0
	}
	b3, err := strconv.Atoi(list[2])
	if err != nil || b3 > 255 || b3 < 0 {
		return 0
	}
	b4, err := strconv.Atoi(list[3])
	if err != nil || b4 > 255 || b4 < 0 {
		return 0
	}
	b1Byte := uint32(b1)
	b2Byte := uint32(b2)
	b3Byte := uint32(b3)
	b4Byte := uint32(b4)
	return b1Byte<<24 | b2Byte<<16 | b3Byte<<8 | b4Byte
}

func FormatIntThousands(i int64) string {
	s := strconv.FormatInt(i, 10)
	bts := []byte(s)
	ret := make([]byte, len(bts)*2)
	n := 0
	retN := len(ret) - 1
	for i := len(bts) - 1; i >= 0; i-- {
		ret[retN] = bts[i]
		n++
		retN--
		if n == 3 && i > 0 {
			ret[retN] = ','
			retN--
			n = 0
		}
	}
	return string(ret[retN:])
}

func FormatFloatThousands(f float64, fmtStr string) string {
	s := fmt.Sprintf(fmtStr, f)
	l, r := SplitLR(s, ".")
	bts := []byte(l)
	ret := make([]byte, len(bts)*2)
	n := 0
	retN := len(ret) - 1
	for i := len(bts) - 1; i >= 0; i-- {
		ret[retN] = bts[i]
		n++
		retN--
		if n == 3 && i > 0 {
			ret[retN] = ','
			retN--
			n = 0
		}
	}
	x := string(ret[retN:])
	if r != "" {
		return x + "." + r
	}
	return x
}

func SliceReplace(sls []string, replacement map[string]string) []string {
	if len(sls) == 0 || len(replacement) == 0 {
		return sls
	}
	ret := make([]string, 0, len(sls))
	for _, v := range sls {
		s := v
		for o, n := range replacement {
			s = strings.Replace(s, o, n, -1)
		}
		ret = append(ret, s)
	}
	return ret
}

func StringReplace(str string, replacement map[string]string) string {
	if len(str) == 0 || len(replacement) == 0 {
		return str
	}
	s := str
	for o, n := range replacement {
		s = strings.Replace(s, o, n, -1)
	}
	return s
}

//=================json unmarshal=================
type JsonInt int
type JsonStr string

func (m *JsonInt) UnmarshalJSON(bts []byte) error {
	if len(bts) == 0 {
		return nil
	}
	b := 0
	e := len(bts)
	if e > 2 {
		if bts[0] == '"' {
			b++
		}
		if bts[e-1] == '"' {
			e--
		}
	}
	if e == b {
		e++
	}
	i, err := strconv.Atoi(string(bts[b:e]))
	if err != nil {
		*m = 0
	} else {
		*m = JsonInt(i)
	}
	return nil
}

func (m *JsonStr) UnmarshalJSON(bts []byte) error {
	if len(bts) == 0 {
		return nil
	}
	b := 0
	e := len(bts)
	if e > 2 {
		if bts[0] == '"' {
			b++
		}
		if bts[e-1] == '"' {
			e--
		}
	}
	if e == b {
		e++
	}
	s := string(bts[b:e])
	*m = JsonStr(s)
	return nil
}

//=================================================

func BoolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

//tmStr hh:mm:ss
func ParseDuration(tmStr string) time.Duration {
	var ret time.Duration = 0
	lst := strings.Split(tmStr, ":")
	if len(lst) >= 2 {
		h, hErr := strconv.Atoi(lst[0])
		m, mErr := strconv.Atoi(lst[1])
		if hErr == nil && mErr == nil {
			ret = ret + (time.Hour * time.Duration(h))
			ret = ret + (time.Minute * time.Duration(m))
		}
	}
	if len(lst) == 3 && len(lst[2]) >= 2 {
		s, sErr := strconv.Atoi(lst[2][:2])
		if sErr == nil {
			ret = ret + (time.Second * time.Duration(s))
		}
	}
	return ret
}

type KeyValuePair struct {
	Key   string      `json:"key"`
	Value interface{} `json:"value"`
}

type JsonSlice []*KeyValuePair

func (m JsonSlice) Len() int {
	return len(m)
}
func (m JsonSlice) Less(i, j int) bool {
	return m[i].Key < m[j].Key
}

func (m JsonSlice) Swap(i, j int) {
	m[i], m[j] = m[j], m[i]
}

func (m JsonSlice) UrlEncodedMarshal(exceptList []string) string {
	ret := ""
	for _, v := range m {
		except := false
		for _, x := range exceptList {
			if v.Key == x {
				except = true
				break
			}
		}
		if except {
			continue
		}
		kv := "%s=%s"
		value := GetStringValue(v.Value)
		if value == "" {
			continue
		}
		if ret != "" {
			ret += "&"
		}
		ret += fmt.Sprintf(kv, v.Key, url.QueryEscape(value))
	}
	return ret
}

func StructToSlice(structObj interface{}) JsonSlice {
	vl := reflect.ValueOf(structObj)
	if vl.Kind() == reflect.Ptr {
		vl = reflect.Indirect(vl)
	}
	if vl.Kind() != reflect.Struct {
		return nil
	}
	tp := vl.Type()
	ret := make([]*KeyValuePair, 0, 0)
	for i := 0; i < tp.NumField(); i++ {
		tag := tp.Field(i).Tag.Get("json")
		if tag == "" {
			tag = tp.Field(i).Name
		}
		tagList := strings.Split(tag, ",")
		ret = append(ret, &KeyValuePair{Key: tagList[0], Value: vl.Field(i).Interface()})
	}
	return ret
}

func JsonMapToSlice(mp map[string]interface{}) JsonSlice {
	if mp == nil {
		return nil
	}
	ret := make([]*KeyValuePair, 0, len(mp))
	for k, v := range mp {
		ret = append(ret, &KeyValuePair{Key: k, Value: v})
	}
	return JsonSlice(ret)
}

func Int64ToBytes(i int64) []byte {
	var buf = make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(i))
	return buf
}

func BytesToInt64(buf []byte) int64 {
	if len(buf) > 7 {
		return int64(binary.BigEndian.Uint64(buf))
	}
	return 0
}

//Here's how to call it:
//
//data := `{"a": "b", "a":true,"c":["field_3 string 1","field3 string2"], "d": {"e": 1, "e": 2}}`
//if err := check(json.NewDecoder(strings.NewReader(data)), nil); err != nil {
//log.Fatal(err)
//}
func CheckJsonDuplicate(d *json.Decoder, path []string) error {
	// Get next token from JSON
	t, err := d.Token()
	if err != nil {
		return err
	}

	delim, ok := t.(json.Delim)

	// There's nothing to do for simple values (strings, numbers, bool, nil)
	if !ok {
		return nil
	}

	switch delim {
	case '{':
		keys := make(map[string]bool)
		for d.More() {
			// Get field key
			t, err := d.Token()
			if err != nil {
				return err
			}
			key := t.(string)

			// Check for duplicates
			if keys[key] {
				return fmt.Errorf("Duplicate %s\n", strings.Join(append(path, key), "/"))
			}
			keys[key] = true

			// Check value
			if err := CheckJsonDuplicate(d, append(path, key)); err != nil {
				return err
			}
		}
		// Consume trailing }
		if _, err := d.Token(); err != nil {
			return err
		}

	case '[':
		i := 0
		for d.More() {
			if err := CheckJsonDuplicate(d, append(path, strconv.Itoa(i))); err != nil {
				return err
			}
			i++
		}
		// Consume trailing ]
		if _, err := d.Token(); err != nil {
			return err
		}

	}
	return nil
}

func MaxInt64(list ...int64) int64 {
	ret := int64(math.MinInt64)
	for _, v := range list {
		if v > ret {
			ret = v
		}
	}
	return ret
}

func MaxInt(list ...int) int {
	ret := math.MinInt64
	for _, v := range list {
		if v > ret {
			ret = v
		}
	}
	return ret
}

func MaxFloat64(list ...float64) float64 {
	if len(list) == 0 {
		return math.MaxFloat64
	}
	ret := list[0]
	for _, v := range list {
		if v > ret {
			ret = v
		}
	}
	return ret
}

func MinInt64(list ...int64) int64 {
	ret := int64(math.MaxInt64)
	for _, v := range list {
		if v < ret {
			ret = v
		}
	}
	return ret
}

func MinInt(list ...int) int {
	ret := math.MaxInt64
	for _, v := range list {
		if v < ret {
			ret = v
		}
	}
	return ret
}

func MinFloat64(list ...float64) float64 {
	ret := math.MaxFloat64
	for _, v := range list {
		if v < ret {
			ret = v
		}
	}
	return ret
}
