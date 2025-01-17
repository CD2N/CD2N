package main

import (
	"github.com/CD2N/CD2N/sdk/sdkgo/examples/upload"
)

func main() {
	// paramsNum := 4
	// if len(os.Args) < paramsNum+1 {
	// 	log.Fatal("Wrong parameter list")
	// }
	//log.Println("params: baseUrl,territory,fpath,mnemonic")
	territory := "test1"
	baseUrl := "http://127.0.0.1:1306"
	fpath := "./upload/upload.go"
	mnemonic := "father weird payment camp saddle assault dune knee network prize enemy liquid"

	upload.UploadFileExamples(baseUrl, territory, fpath, mnemonic)
}
