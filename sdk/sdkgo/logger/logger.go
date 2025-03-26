package logger

import (
	"sync"

	"github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
)

var (
	logger *Logger
)

type Logger struct {
	//txLogger
	loggers map[string]*logrus.Logger
	rw      *sync.RWMutex
}

func GetGlobalLogger() *Logger {
	if logger == nil {
		InitGlobalLogger()
	}
	return logger
}

func InitGlobalLogger() *Logger {
	logger = &Logger{
		loggers: make(map[string]*logrus.Logger),
		rw:      &sync.RWMutex{},
	}
	return logger
}

func (lg *Logger) RegisterLogger(name, fpath, formatter string) (*logrus.Logger, error) {

	logger := logrus.New()

	switch formatter {
	case "Json", "JSON", "json":
		logger.SetFormatter(&logrus.JSONFormatter{})
	default:
		logger.SetFormatter(&logrus.TextFormatter{})
	}

	if fpath != "" {
		l := &lumberjack.Logger{
			Filename:   fpath,
			MaxSize:    100,
			MaxBackups: 5,
			MaxAge:     30,
			Compress:   true,
		}
		logger.SetOutput(l)
	}

	lg.rw.Lock()
	lg.loggers[name] = logger
	lg.rw.Unlock()
	logger.Info("register a logger: ", name)
	return logger, nil
}

func (lg *Logger) GetLogger(name string) *logrus.Logger {
	lg.rw.RLock()
	defer lg.rw.RUnlock()
	return lg.loggers[name]
}

func GetLogger(name string) *logrus.Logger {
	if logger != nil {
		logger.rw.RLock()
		defer logger.rw.RUnlock()
		return logger.loggers[name]
	}
	return nil
}
