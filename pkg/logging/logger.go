package logging

import (
    "encoding/json"
    "log"
    "os"
    "path/filepath"
    "time"
)

type Entry struct {
    Time string `json:"time"`
    Level string `json:"level"`
    Component string `json:"component"`
    Message string `json:"message"`
}

var logFilePath = filepath.Join("logs", "huntsuite.log")

func Log(component, level, message string) {
    e := Entry{
        Time: time.Now().Format(time.RFC3339),
        Level: level,
        Component: component,
        Message: message,
    }
    b, _ := json.Marshal(e)
    log.Println(string(b))
    f, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
    if err == nil {
        defer f.Close()
        f.Write(append(b, '\n'))
    }
}
