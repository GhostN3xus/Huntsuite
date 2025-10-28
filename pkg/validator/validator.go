package validator

import (
    "context"
    "database/sql"
    "fmt"
    "log"
    "net/http"
    "time"

    _ "github.com/mattn/go-sqlite3"
    "huntsuite/pkg/oob"
    "huntsuite/pkg/report"
)

type Finding struct {
    ID int64
    Target string
    Path string
    Type string
    Time string
    Proof string
    Confidence float64
}

func InitDB(path string) (*sql.DB, error) {
    db, err := sql.Open("sqlite3", path)
    if err != nil { return nil, err }
    stmt := `CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target TEXT,
        path TEXT,
        type TEXT,
        time TEXT,
        proof TEXT,
        confidence REAL
    );`
    if _, err := db.Exec(stmt); err != nil {
        return nil, err
    }
    return db, nil
}

func SaveFinding(db *sql.DB, f Finding) (int64, error) {
    res, err := db.Exec("INSERT INTO findings(target,path,type,time,proof,confidence) VALUES(?,?,?,?,?,?)",
        f.Target, f.Path, f.Type, f.Time, f.Proof, f.Confidence)
    if err != nil { return 0, err }
    return res.LastInsertId()
}

func ProbeSSRF(db *sql.DB, target string, param string) (*Finding, error) {
    d, _ := oob.ExecInteractWithTimeout(5 * time.Second)
    if d == "" {
        client, _ := oob.NewInteractClient()
        d = client.Domain
    }
    token := fmt.Sprintf("ssrf-%d", time.Now().UnixNano())
    oobURL := fmt.Sprintf("http://%s/%s", d, token)

    probe := fmt.Sprintf("%s?%s=%s", target, param, oobURL)
    client := &http.Client{Timeout: 10 * time.Second}
    resp, err := client.Get(probe)
    if err != nil {
        return nil, err
    }
    resp.Body.Close()

    f := Finding{
        Target: target,
        Path: param,
        Type: "ssrf-oob",
        Time: time.Now().Format(time.RFC3339),
        Proof: oobURL,
        Confidence: 0.5,
    }
    id, err := SaveFinding(db, f)
    if err == nil {
        f.ID = id
    }
    report.WriteJSONReport("validated_findings", f)
    return &f, nil
}
