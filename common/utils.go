package common

import (
	"crypto/md5"
	"fmt"
)

func Md5(b []byte) []byte {
	h := md5.New()
	h.Write(b)
	return h.Sum(nil)
}

func Md5ToString(b []byte) string {

	hash := Md5(b)
	if hash != nil {
		return fmt.Sprintf("%x", hash)
	}
	return ""
}
