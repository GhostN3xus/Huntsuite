package proxy

import (
    "io"
    "log"
    "net"
    "net/http"
    "time"
)

type ProxyConfig struct {
    ListenAddr    string
    InjectPayload func(req *http.Request)
}

func StartForwardProxy(cfg ProxyConfig) error {
    handler := func(w http.ResponseWriter, r *http.Request) {
        start := time.Now()
        log.Printf("[proxy] %s %s from %s", r.Method, r.URL.String(), r.RemoteAddr)

        if cfg.InjectPayload != nil {
            cfg.InjectPayload(r)
        }

        if r.Method == http.MethodConnect {
            handleConnect(w, r)
            return
        }

        outReq := r.Clone(r.Context())
        transport := http.DefaultTransport
        resp, err := transport.RoundTrip(outReq)
        if err != nil {
            http.Error(w, "bad gateway: "+err.Error(), http.StatusBadGateway)
            log.Printf("[proxy] roundtrip error: %v", err)
            return
        }
        defer resp.Body.Close()

        for k, vv := range resp.Header {
            for _, v := range vv {
                w.Header().Add(k, v)
            }
        }
        w.WriteHeader(resp.StatusCode)
        io.Copy(w, resp.Body)

        log.Printf("[proxy] completed %s %s in %v -> %d", r.Method, r.URL, time.Since(start), resp.StatusCode)
    }

    server := &http.Server{
        Addr:    cfg.ListenAddr,
        Handler: http.HandlerFunc(handler),
    }
    log.Printf("[proxy] starting forward proxy on %s", cfg.ListenAddr)
    return server.ListenAndServe()
}

func handleConnect(w http.ResponseWriter, r *http.Request) {
    hij, ok := w.(http.Hijacker)
    if !ok {
        http.Error(w, "hijacking not supported", http.StatusInternalServerError)
        return
    }
    clientConn, _, err := hij.Hijack()
    if err != nil {
        http.Error(w, err.Error(), http.StatusServiceUnavailable)
        return
    }
    destConn, err := net.Dial("tcp", r.Host)
    if err != nil {
        clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
        clientConn.Close()
        return
    }
    clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

    go io.Copy(destConn, clientConn)
    go io.Copy(clientConn, destConn)
}
