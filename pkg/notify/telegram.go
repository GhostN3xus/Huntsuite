package notify

import (
    "bytes"
    "fmt"
    "io"
    "mime/multipart"
    "net/http"
    "os"
    "path/filepath"

    "huntsuite/pkg/config"
)


// SendMessage sends a plain text message via Telegram Bot API
func SendMessage(botToken, chatID, text string) error {
    url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", botToken)
    resp, err := http.PostForm(url, map[string][]string{
        "chat_id": {chatID},
        "text": {text},
        "parse_mode": {"Markdown"},
    })
    if err != nil {
        return err
    }
    defer resp.Body.Close()
    if resp.StatusCode != 200 {
        body, _ := io.ReadAll(resp.Body)
        return fmt.Errorf("telegram sendMessage failed: %s", string(body))
    }
    return nil
}

// SendDocument uploads a file (report) to Telegram chat
func SendDocument(botToken, chatID, filePath, caption string) error {
    url := fmt.Sprintf("https://api.telegram.org/bot%s/sendDocument", botToken)
    file, err := os.Open(filePath)
    if err != nil {
        return err
    }
    defer file.Close()

    var b bytes.Buffer
    w := multipart.NewWriter(&b)
    fw, err := w.CreateFormFile("document", filepath.Base(filePath))
    if err != nil {
        return err
    }
    if _, err := io.Copy(fw, file); err != nil {
        return err
    }
    // add chat_id and caption fields
    _ = w.WriteField("chat_id", chatID)
    if caption != "" {
        _ = w.WriteField("caption", caption)
    }
    w.Close()

    req, err := http.NewRequest("POST", url, &b)
    if err != nil {
        return err
    }
    req.Header.Set("Content-Type", w.FormDataContentType())
    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        return err
    }
    defer resp.Body.Close()
    if resp.StatusCode != 200 {
        body, _ := io.ReadAll(resp.Body)
        return fmt.Errorf("telegram sendDocument failed: %s", string(body))
    }
    return nil
}

// AutoNotify checks env vars and sends message + document if available.
func AutoNotify(reportPath, summary string) error {
    botToken := os.Getenv("HUNTSUITE_TELEGRAM_TOKEN")
    chatID := os.Getenv("HUNTSUITE_TELEGRAM_CHAT_ID")
    if botToken == "" || chatID == "" {
        // try config file
        cfg, _ := config.Load()
        if botToken == "" {
            botToken = cfg.TelegramToken
        }
        if chatID == "" {
            chatID = cfg.TelegramChatID
        }
    }

    chatID := os.Getenv("HUNTSUITE_TELEGRAM_CHAT_ID")
    if botToken == "" || chatID == "" {
        return nil // nothing to do
    }
    // send short message
    msg := "[HuntSuite] " + summary
    if err := SendMessage(botToken, chatID, msg); err != nil {
        return err
    }
    if reportPath != "" {
        if err := SendDocument(botToken, chatID, reportPath, "HuntSuite report"); err != nil {
            return err
        }
    }
    return nil
}
