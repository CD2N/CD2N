package client

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/CD2N/CD2N/retriever/config"
	"github.com/CD2N/CD2N/sdk/sdkgo/logger"
	"github.com/ipfs/boxo/files"
	"github.com/ipfs/boxo/path"
	"github.com/ipfs/go-cid"
	"github.com/ipfs/kubo/client/rpc"
	"github.com/pkg/errors"
)

type CidMap struct {
	Did string `json:"did"`
	Cid string `json:"cid"`
}

func NewIpfsClient(url string) (*rpc.HttpApi, error) {

	node, err := rpc.NewURLApiWithClient(url, http.DefaultClient)
	if err != nil {
		return nil, errors.Wrap(err, "new ipfs client error")
	}

	return node, nil
}

func AddFileToIpfs(cli *rpc.HttpApi, ctx context.Context, fpath string) (string, error) {

	f, err := os.Open(fpath)
	if err != nil {
		return "", errors.Wrap(err, "add file to ipfs error")
	}
	defer f.Close()
	p, err := cli.Unixfs().Add(ctx, files.NewReaderFile(f))
	if err != nil {
		return "", errors.Wrap(err, "add file to ipfs error")
	}
	//cli.Routing().Provide(ctx, p) //timeout
	CID := p.RootCid().String()
	return CID, nil
}

func AddDataToIpfs(cli *rpc.HttpApi, ctx context.Context, data []byte) (string, error) {
	buf := bytes.NewBuffer(data)
	p, err := cli.Unixfs().Add(ctx, files.NewReaderFile(buf))
	if err != nil {
		return "", errors.Wrap(err, "add data to ipfs error")
	}
	cli.Routing().Provide(ctx, p)
	return p.RootCid().String(), nil
}

func GetDataInIpfs(cli *rpc.HttpApi, ctx context.Context, CID string) ([]byte, error) {
	c, err := cid.Decode(CID)
	if err != nil {
		return nil, errors.Wrap(err, "get file from ipfs error")
	}
	// reader, err := cli.Block().Get(ctx, path.FromCid(c))
	// if err != nil {
	// 	return nil, errors.Wrap(err, "get file from ipfs error")
	// }

	fnode, err := cli.Unixfs().Get(ctx, path.FromCid(c))
	if err != nil {
		return nil, errors.Wrap(err, "get file from ipfs error")
	}

	buf := bytes.NewBuffer(nil)
	_, err = buf.ReadFrom(files.ToFile(fnode))
	if err != nil {
		return nil, errors.Wrap(err, "get file from ipfs error")
	}
	return buf.Bytes(), nil
}

func GetFileInIpfs(cli *rpc.HttpApi, ctx context.Context, CID, fpath string) error {
	c, err := cid.Decode(CID)
	if err != nil {
		return errors.Wrap(err, "get file from ipfs error")
	}
	fnode, err := cli.Unixfs().Get(ctx, path.FromCid(c))
	if err != nil {
		return errors.Wrap(err, "get file from ipfs error")
	}

	f, err := os.Create(fpath)
	if err != nil {
		return errors.Wrap(err, "get file from ipfs error")
	}
	defer f.Close()
	_, err = io.Copy(f, files.ToFile(fnode))
	if err != nil {
		return errors.Wrap(err, "get file from ipfs error")
	}
	return nil
}

func QueryFileInIpfs(cli *rpc.HttpApi, ctx context.Context, CID string) (bool, error) {
	c, err := cid.Decode(CID)
	if err != nil {
		return false, errors.Wrap(err, "query file from ipfs error")
	}
	fnode, err := cli.Unixfs().Get(ctx, path.FromCid(c))
	if err != nil {
		return false, errors.Wrap(err, "query file from ipfs error")
	}
	defer fnode.Close()
	size, err := fnode.Size()
	if err != nil {
		return false, errors.Wrap(err, "query file from ipfs error")
	}
	return size > 0, nil
}

func PinFileInIpfs(cli *rpc.HttpApi, ctx context.Context, CID string) error {
	c, err := cid.Decode(CID)
	if err != nil {
		return errors.Wrap(err, "pinning file in ipfs error")
	}
	err = cli.Pin().Add(ctx, path.FromCid(c))
	if err != nil {
		return errors.Wrap(err, "pinning file in ipfs error")
	}
	return nil
}

func RemoveFileFromIpfs(cli *rpc.HttpApi, ctx context.Context, CID string) error {
	c, err := cid.Decode(CID)
	if err != nil {
		return errors.Wrap(err, "remove file from ipfs error")
	}
	err = cli.Pin().Rm(ctx, path.FromCid(c))
	if err != nil {
		return errors.Wrap(err, "remove file from ipfs error")
	}
	return nil
}

func LsPinedFiles(cli *rpc.HttpApi, ctx context.Context, handle func(string, int64)) error {
	ch, err := cli.Pin().Ls(ctx)
	if err != nil {
		return errors.Wrap(err, "ls pined files error")
	}
	ticker := time.NewTicker(time.Second * 2)
	for {
		select {
		case <-ctx.Done():
			return nil
		case p := <-ch:
			if p.Err() != nil {
				return errors.Wrap(err, "ls pined files error")
			}
			n, err := cli.Unixfs().Get(ctx, p.Path())
			if err != nil {
				continue
			}
			size, err := n.Size()
			if err != nil {
				continue
			}
			handle(p.Path().RootCid().String(), size)
		case <-ticker.C:
			return errors.Wrap(errors.New("timeout"), "ls pined files error")
		}
		ticker.Reset(time.Second * 2)
	}
}

func PubMessageInIpfs(cli *rpc.HttpApi, ctx context.Context, key string, msg []byte) error {
	err := cli.PubSub().Publish(ctx, key, msg)
	return errors.Wrap(err, "publish message to ipfs error")
}

func SubscribeMessageInIpfs(cli *rpc.HttpApi, ctx context.Context, key string, handle func([]byte)) error {
	sub, err := cli.PubSub().Subscribe(ctx, key)
	if err != nil {
		return errors.Wrap(err, "subscribe message from ipfs error")
	}
	defer sub.Close()
	errCount := 0
	for {
		select {
		case <-ctx.Done():
			return errors.Wrap(errors.New("context done"), "subscribe message from ipfs error")
		default:
		}
		msg, err := sub.Next(ctx)
		if err != nil {
			logger.GetLogger(config.LOG_RETRIEVE).Error(err)
			errCount++
			if errCount >= 15 {
				return errors.Wrap(err, "subscribe message from ipfs error")
			}
			continue
		}
		errCount = 0
		if msg != nil {
			handle(msg.Data())
		}
	}
}
