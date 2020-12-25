package magic

type ImagineRequest struct {
	Method string `json:"method"` //magick method: crop, resize, overlap, text...
	Params map[string]string `json:"params"`
	Format string `json:"format"` //final image: format, jpeg, png, ...
	CacheSeconds int64  //缓存驻留时间（秒）
}

type ImagineResponse struct {
	ErrCode int `json:"err_code"`
	ErrMsg string `json:"err_msg"`
	ImageB64 []byte `json:"imageb64"` //base64.RawURLEncoding
	Image []byte `json:"image"`
}
