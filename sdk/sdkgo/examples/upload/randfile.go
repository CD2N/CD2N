package upload

import (
	"crypto/rand"
	"os"
)

func GenRandFile(fpath string, fsize int64) error {
	block := 1024 * 1024
	randomData := make([]byte, block)
	count := (fsize + (fsize - fsize%int64(block))) / int64(block)
	mnt := 0
	f, err := os.Create(fpath)
	if err != nil {
		return err
	}
	defer f.Close()
	for count > 0 && mnt < 10 {
		n, err := rand.Read(randomData)
		if err != nil {
			return err
		}
		if n != block {
			mnt++
			continue
		}
		if _, err = f.Write(randomData); err != nil {
			return err
		}
		mnt = 0
		count--
	}
	return nil
}
