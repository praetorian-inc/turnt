// Copyright 2025 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package logger

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
)

type LogLevel int

const (
	LogError LogLevel = iota
	LogInfo
	LogVerbose
)

type Logger struct {
	level      LogLevel
	output     io.Writer
	logger     *log.Logger
	fileHandle *os.File
	mu         sync.RWMutex
}

var (
	instance *Logger
	once     sync.Once
)

type Config struct {
	Level     LogLevel
	LogFile   string
	UseStdout bool
	UseFile   bool
}

func getLogger() *Logger {
	once.Do(func() {
		instance = &Logger{
			level:  LogInfo,
			output: os.Stdout,
			logger: log.New(os.Stdout, "", log.LstdFlags),
		}
	})
	return instance
}

func Init(config Config) error {
	logger := getLogger()
	logger.mu.Lock()
	defer logger.mu.Unlock()

	logger.level = config.Level

	if logger.fileHandle != nil {
		logger.fileHandle.Close()
	}

	var writers []io.Writer
	if config.UseStdout {
		writers = append(writers, os.Stdout)
	}
	if config.UseFile && config.LogFile != "" {
		dir := filepath.Dir(config.LogFile)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create log directory: %v", err)
		}

		file, err := os.OpenFile(config.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return fmt.Errorf("failed to open log file: %v", err)
		}
		logger.fileHandle = file
		writers = append(writers, file)
	}

	if len(writers) > 1 {
		logger.output = io.MultiWriter(writers...)
	} else if len(writers) == 1 {
		logger.output = writers[0]
	}

	logger.logger = log.New(logger.output, "", log.LstdFlags)
	return nil
}

func Close() error {
	return getLogger().Close()
}

func SetLevel(level LogLevel) {
	getLogger().SetLevel(level)
}

func Error(format string, v ...interface{}) {
	getLogger().Error(format, v...)
}

func Info(format string, v ...interface{}) {
	getLogger().Info(format, v...)
}

func Debug(format string, v ...interface{}) {
	getLogger().Verbose(format, v...)
}

func Verbose(format string, v ...interface{}) {
	getLogger().Verbose(format, v...)
}

func init() {
	instance = &Logger{
		level:  LogInfo,
		output: os.Stdout,
		logger: log.New(os.Stdout, "", log.LstdFlags),
	}
}

func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.fileHandle != nil {
		return l.fileHandle.Close()
	}
	return nil
}

func (l *Logger) SetLevel(level LogLevel) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.level = level
}

func (l *Logger) Error(format string, v ...interface{}) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.level >= LogError {
		l.logger.Printf("[ERROR] "+format, v...)
	}
}

func (l *Logger) Info(format string, v ...interface{}) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.level >= LogInfo {
		l.logger.Printf("[INFO] "+format, v...)
	}
}

func (l *Logger) Verbose(format string, v ...interface{}) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.level >= LogVerbose {
		l.logger.Printf("[VERBOSE] "+format, v...)
	}
}
