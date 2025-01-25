 package main

 import (
     "encoding/hex"
     "fmt"
     "io"
     "log"
     "math/rand"
     "net"
     "net/http"
     "strings"
     "sync"
     "time"

     "github.com/gin-gonic/gin"
     "golang.org/x/time/rate"
 )

 type ServerEntry struct {
     HostName    string        `json:"host_name"`
     MapName     string        `json:"map_name"`
     GameMode    string        `json:"game_mode"`
     MaxPlayers  int           `json:"max_players"`
     IP          string        `json:"ip"`
     Port        int           `json:"port"`
     Players     []PlayerInfo  `json:"players"`
     LastUpdated time.Time     `json:"-"`
     Validated   bool          `json:"validated"`
 }

 type PlayerInfo struct {
     Name string `json:"name"`
     Gen  int    `json:"gen"`
     Lvl  int    `json:"lvl"`
     Team int    `json:"team"`
 }

 type MasterServer struct {
     servers   map[string]*ServerEntry
     mu        sync.RWMutex
     limiter   *rate.Limiter
     challenges map[string]chan bool
 }

 func NewMasterServer() *MasterServer {
     return &MasterServer{
         servers:    make(map[string]*ServerEntry),
         limiter:    rate.NewLimiter(rate.Every(10*time.Second/15), 15),
         challenges: make(map[string]chan bool),
     }
 }

func getPublicIP() (string, error) {
    client := &http.Client{
        Timeout: 5 * time.Second,
    }
    resp, err := client.Get("http://eth0.me")
    if err != nil {
        return "", fmt.Errorf("failed to fetch public IP: %v", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
    }

    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return "", fmt.Errorf("failed to read response body: %v", err)
    }

    ip := strings.TrimSpace(string(body))
    if net.ParseIP(ip) == nil {
        return "", fmt.Errorf("invalid IP address received: %s", ip)
    }

    return ip, nil
}

func (ms *MasterServer) HandleHeartbeat(c *gin.Context) {
     var heartbeat struct {
         HostName   string       `json:"host_name"`
         MapName    string       `json:"map_name"`
         GameMode   string       `json:"game_mode"`
         MaxPlayers int          `json:"max_players"`
         Port       int          `json:"port"`
         Players    []PlayerInfo `json:"players"`
     }

     if err := c.ShouldBindJSON(&heartbeat); err != nil {
         log.Printf("Invalid heartbeat format from %s: %v", c.ClientIP(), err)
         c.AbortWithStatus(http.StatusBadRequest)
         return
     }

     // Add port validation
     if heartbeat.Port <= 0 || heartbeat.Port > 65535 {
         log.Printf("Invalid port number %d in heartbeat from %s", heartbeat.Port, c.ClientIP())
         c.AbortWithStatus(http.StatusBadRequest)
         return
     }

     clientIP := c.Request.RemoteAddr
     
     key := fmt.Sprintf("%s:%d", clientIP, heartbeat.Port)

     ms.mu.Lock()
     defer ms.mu.Unlock()

     entry := &ServerEntry{
         HostName:    heartbeat.HostName,
         MapName:     heartbeat.MapName,
         GameMode:    heartbeat.GameMode,
         MaxPlayers:  heartbeat.MaxPlayers,
         IP:          resolvedIP,
         Port:        heartbeat.Port,
         Players:     heartbeat.Players,
         LastUpdated: time.Now(),
         Validated:   false,
     }

     ms.servers[key] = entry
     go ms.PerformValidation(resolvedIP, heartbeat.Port)

     c.Status(http.StatusOK)
 }

func (ms *MasterServer) PerformValidation(ip string, port int) {
    log.Printf("[Validation] Starting validation for %s:%d", ip, port)
    
    nonce := make([]byte, 4)
    rand.Read(nonce)
    nonceStr := "0x" + hex.EncodeToString(nonce)

    conn, err := net.DialTimeout("udp", fmt.Sprintf("%s:%d", ip, port), 2*time.Second)
    if err != nil {
        log.Printf("[Validation] Connection failed to %s:%d: %v", ip, port, err)
        return
    }
    defer conn.Close()

    challengePacket := make([]byte, 23)
    copy(challengePacket[0:4], []byte{0xFF, 0xFF, 0xFF, 0xFF})
    challengePacket[4] = 0x48
    copy(challengePacket[5:12], "connect")
    copy(challengePacket[12:22], nonceStr)
    challengePacket[22] = 0x00

    log.Printf("[Validation] Sending challenge to %s:%d (nonce: %s)", ip, port, nonceStr)
    conn.SetDeadline(time.Now().Add(2 * time.Second))
    _, err = conn.Write(challengePacket)
    if err != nil {
        log.Printf("[Validation] Failed to send challenge to %s:%d: %v", ip, port, err)
        return
    }

    resp := make([]byte, 1024)
    n, err := conn.Read(resp)
    if err != nil {
        log.Printf("[Validation] Response read failed from %s:%d: %v", ip, port, err)
        return
    }
    if n < 25 {
        log.Printf("[Validation] Short response from %s:%d (%d bytes)", ip, port, n)
        return
    }

    log.Printf("[Validation] Received %d byte response from %s:%d", n, ip, port)
    if !validateResponse(resp[:n], nonceStr) {
        log.Printf("[Validation] Validation failed for %s:%d", ip, port)
        return
    }

    ms.mu.Lock()
    defer ms.mu.Unlock()
    key := fmt.Sprintf("%s:%d", ip, port)
    if server, exists := ms.servers[key]; exists {
        log.Printf("[Validation] Successfully validated %s:%d (%s)", ip, port, server.HostName)
        server.Validated = true
    }
 }

func validateResponse(resp []byte, nonce string) bool {
    if len(resp) < 25 {
        log.Printf("[Validation] Response too short: %d bytes", len(resp))
        return false
    }

    headerValid := resp[0] == 0xFF && resp[1] == 0xFF && resp[2] == 0xFF && resp[3] == 0xFF && resp[4] == 0x49
    if !headerValid {
        log.Printf("[Validation] Invalid header bytes: 0x%X 0x%X 0x%X 0x%X 0x%X", 
            resp[0], resp[1], resp[2], resp[3], resp[4])
        return false
    }

    connectStr := string(resp[9:16])
    if connectStr != "connect" {
        log.Printf("[Validation] Invalid connect string: %q", connectStr)
        return false
    }

    responseNonce := string(resp[16:26])
    if responseNonce != nonce {
        log.Printf("[Validation] Nonce mismatch. Expected %q, got %q", nonce, responseNonce)
        return false
    }

    return true
 }

 func (ms *MasterServer) GetServers(c *gin.Context) {
     ms.mu.RLock()
     defer ms.mu.RUnlock()

     validServers := make([]*ServerEntry, 0)
     for _, s := range ms.servers {
         if s.Validated && time.Since(s.LastUpdated) < 30*time.Second {
             validServers = append(validServers, s)
         }
     }

     c.JSON(http.StatusOK, validServers)
 }

func (ms *MasterServer) CleanupOldEntries() {
    for range time.Tick(30 * time.Second) {
        ms.mu.Lock()
        for k, s := range ms.servers {
            if time.Since(s.LastUpdated) > 90*time.Second {
                log.Printf("[Cleanup] Removing server %s (%s:%d) Last updated: %v ago, Validated: %v",
                    s.HostName, s.IP, s.Port, time.Since(s.LastUpdated), s.Validated)
                delete(ms.servers, k)
            }
        }
        ms.mu.Unlock()
    }
 }

func fetchCloudflareIPs() ([]string, error) {
    client := &http.Client{Timeout: 10 * time.Second}
    resp, err := client.Get("https://www.cloudflare.com/ips-v4")
    if err != nil {
        return nil, fmt.Errorf("failed to fetch Cloudflare IPs: %v", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
    }

    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return nil, fmt.Errorf("failed to read response body: %v", err)
    }

    ips := strings.Split(strings.TrimSpace(string(body)), "\n")
    if len(ips) == 0 {
        return nil, fmt.Errorf("empty Cloudflare IP list received")
    }

    return ips, nil
}

func main() {
    gin.SetMode(gin.ReleaseMode)
    
    // Fetch Cloudflare IPs
    cfIPs, err := fetchCloudflareIPs()
    if err != nil {
        log.Printf("Warning: %v. Using hardcoded fallback IPs", err)
        // Fallback to the latest known IPs
        cfIPs = []string{
            "173.245.48.0/20",
            "103.21.244.0/22",
            "103.22.200.0/22",
            "103.31.4.0/22",
            "141.101.64.0/18",
            "108.162.192.0/18",
            "190.93.240.0/20",
            "188.114.96.0/20",
            "197.234.240.0/22",
            "198.41.128.0/17",
            "162.158.0.0/15",
            "104.16.0.0/13",
            "104.24.0.0/14",
            "172.64.0.0/13",
            "131.0.72.0/22",
        }
    }

    ms := NewMasterServer()
    go ms.CleanupOldEntries()

    r := gin.Default()
    
    // Configure trusted Cloudflare proxies
    r.SetTrustedProxies(cfIPs)

     // Add Cloudflare IP handling middleware
     r.Use(func(c *gin.Context) {
         if cfConnectingIP := c.GetHeader("CF-Connecting-IP"); cfConnectingIP != "" {
             c.Request.RemoteAddr = cfConnectingIP
         }
         c.Next()
     })

     r.Use(func(c *gin.Context) {
         if !ms.limiter.Allow() {
             c.AbortWithStatus(http.StatusTooManyRequests)
             return
         }
         c.Next()
     })

     r.POST("/heartbeat", ms.HandleHeartbeat)
     r.DELETE("/heartbeat/:port", ms.HandleDelete)
     r.GET("/servers", ms.GetServers)

     r.Run(":80")
 }

 func (ms *MasterServer) HandleDelete(c *gin.Context) {
     port := c.Param("port")
     clientIP := c.Request.RemoteAddr
     key := fmt.Sprintf("%s:%s", clientIP, port)

     ms.mu.Lock()
     defer ms.mu.Unlock()
     delete(ms.servers, key)

     c.Status(http.StatusOK)
 }
