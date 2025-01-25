 package main

 import (
     "encoding/hex"
     "fmt"
     "log"
     "math/rand"
     "net"
     "net/http"
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
         c.AbortWithStatus(http.StatusBadRequest)
         return
     }

     key := fmt.Sprintf("%s:%d", c.ClientIP(), heartbeat.Port)

     ms.mu.Lock()
     defer ms.mu.Unlock()

     entry := &ServerEntry{
         HostName:    heartbeat.HostName,
         MapName:     heartbeat.MapName,
         GameMode:    heartbeat.GameMode,
         MaxPlayers:  heartbeat.MaxPlayers,
         IP:          c.ClientIP(),
         Port:        heartbeat.Port,
         Players:     heartbeat.Players,
         LastUpdated: time.Now(),
         Validated:   false,
     }

     ms.servers[key] = entry
     go ms.PerformValidation(c.ClientIP(), heartbeat.Port)

     c.Status(http.StatusOK)
 }

 func (ms *MasterServer) PerformValidation(ip string, port int) {
     nonce := make([]byte, 4)
     rand.Read(nonce)
     nonceStr := "0x" + hex.EncodeToString(nonce)

     conn, err := net.DialTimeout("udp", fmt.Sprintf("%s:%d", ip, port), 2*time.Second)
     if err != nil {
         return
     }
     defer conn.Close()

     challengePacket := make([]byte, 23)
     copy(challengePacket[0:4], []byte{0xFF, 0xFF, 0xFF, 0xFF})
     challengePacket[4] = 0x48
     copy(challengePacket[5:12], "connect")
     copy(challengePacket[12:22], nonceStr)
     challengePacket[22] = 0x00

     conn.SetDeadline(time.Now().Add(2 * time.Second))
     conn.Write(challengePacket)

     resp := make([]byte, 1024)
     n, err := conn.Read(resp)
     if err != nil || n < 25 {
         return
     }

     if !validateResponse(resp, nonceStr) {
         return
     }

     ms.mu.Lock()
     defer ms.mu.Unlock()

     key := fmt.Sprintf("%s:%d", ip, port)
     if server, exists := ms.servers[key]; exists {
         server.Validated = true
     }
 }

 func validateResponse(resp []byte, nonce string) bool {
     if len(resp) < 25 {
         return false
     }

     // Check header and command
     if !(resp[0] == 0xFF && resp[1] == 0xFF && resp[2] == 0xFF && resp[3] == 0xFF && resp[4] == 0x49) {
         return false
     }

     // Check 'connect' string
     if string(resp[9:16]) != "connect" {
         return false
     }

     // Check nonce
     return string(resp[16:26]) == nonce
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
                 delete(ms.servers, k)
             }
         }
         ms.mu.Unlock()
     }
 }

 func main() {
     ms := NewMasterServer()
     go ms.CleanupOldEntries()

     r := gin.Default()

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

     r.Run(":8080")
 }

 func (ms *MasterServer) HandleDelete(c *gin.Context) {
     port := c.Param("port")
     key := fmt.Sprintf("%s:%s", c.ClientIP(), port)

     ms.mu.Lock()
     defer ms.mu.Unlock()
     delete(ms.servers, key)

     c.Status(http.StatusOK)
 }
