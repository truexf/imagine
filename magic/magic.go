package magic

import "fmt"

type Magic struct {
}

func newMagic() *Magic {
	return &Magic{}
}

func (m *Magic) processImage(req *ImagineRequest) (imageRet []byte, err error) {
	return nil, fmt.Errorf("unknown")
}
