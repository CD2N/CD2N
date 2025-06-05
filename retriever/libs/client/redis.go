package client

import (
	"context"
	"encoding/json"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/pkg/errors"
)

const (
	//the cnd node provides user data to the provider
	CHANNEL_PROVIDE = "provide_task"
	//the cnd node requests the provider to retrieve data
	CHANNEL_RETRIEVE = "retrieve_task"
)

func NewRedisClient(addr, username, password string) *redis.Client {
	client := redis.NewClient(&redis.Options{
		Addr:     addr,
		Username: username,
		Password: password,
		DB:       0,
	})
	return client
}

func PublishMessage(cli *redis.Client, ctx context.Context, channel string, data any) error {
	jbytes, err := json.Marshal(data)
	if err != nil {
		return errors.Wrap(err, "publish message error")
	}
	err = cli.Publish(ctx, channel, string(jbytes)).Err()
	return errors.Wrap(err, "publish message error")
}

func GetMessage(cli *redis.Client, ctx context.Context, key string) []byte {
	cmd := cli.Get(ctx, key)
	if cmd == nil {
		return nil
	}
	data, err := cmd.Bytes()
	if err != nil {
		return nil
	}
	return data
}

func SetMessage(cli *redis.Client, ctx context.Context, key string, data []byte, exp time.Duration) error {
	cmd := cli.Set(ctx, key, data, exp)
	if cmd == nil {
		return errors.New("set message error")
	}
	return cmd.Err()
}

func SetNxMessage(cli *redis.Client, ctx context.Context, key string, data []byte, exp time.Duration) (bool, error) {
	cmd := cli.SetNX(ctx, key, data, exp)
	if cmd == nil {
		return false, errors.New("setNx message error")
	}
	return cmd.Result()
}

func DeleteMessage(cli *redis.Client, ctx context.Context, key ...string) error {
	cmd := cli.Del(ctx, key...)
	if cmd == nil {
		return errors.New("delete message error")
	}
	return cmd.Err()
}
