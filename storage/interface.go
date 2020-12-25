package storage

type Storage interface {
	Write(key string, data []byte, expireSecond int64) (err error)
	Read(key string) (data []byte, err error)
	Delete(key string)
	Exists(key string) bool
}

var (
	storageInstance Storage
)
func GetStorage() Storage {
	return storageInstance
}

func SetStorage(st Storage) {
	storageInstance = st
}
