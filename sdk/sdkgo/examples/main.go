package main

import (
	"context"
	"log"

	"github.com/CD2N/CD2N/sdk/sdkgo/examples/upload"
)

func main() {
	// paramsNum := 4
	// if len(os.Args) < paramsNum+1 {
	// 	log.Fatal("Wrong parameter list")
	// }
	//log.Println("params: baseUrl,territory,fpath,mnemonic")
	// territory := "test1"
	// baseUrl := "http://154.194.34.206:1306"
	// fpath := "./upload/upload.go"
	// mnemonic := "father weird payment camp saddle assault dune knee network prize enemy liquid"

	// upload.UploadFileExamples(baseUrl, territory, fpath, mnemonic)
	c := upload.NewUploadController()
	err := c.LoadJsonConfig("./config.json")
	if err != nil {
		log.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Controller(ctx)
	c.UploadFile(ctx)
	err = c.SaveJsonConfig("./config.json")
	if err != nil {
		log.Fatal(err)
	}
}
