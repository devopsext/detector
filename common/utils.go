package common

import (
	"crypto/md5"
	"fmt"
	"time"

	"github.com/devopsext/utils"
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

func Duration(s string, def time.Duration) time.Duration {

	r := def
	if !utils.IsEmpty(s) {
		d, err := time.ParseDuration(s)
		if err == nil {
			r = d
		}
	}
	return r
}
