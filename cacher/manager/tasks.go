package manager

const (
	DEFAULT_TASK_CHANNEL_SIZE = 10240
	TIME_LAYOUT               = "2006/01/02 15:04:05"
)

type Event interface {
	Status() int
	Result() any
	Error() error
}

type Callback func(Event)

type Task struct {
	Tid       string `json:"tid"`
	Exp       int64  `json:"exp"`
	Acc       string `json:"acc"`
	Addr      string `json:"addr"`
	Did       string `json:"did"`
	ExtData   string `json:"extdata"`
	Timestamp string `json:"timestamp"`
}
