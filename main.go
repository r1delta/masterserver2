// ms.go
package main

import (
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"github.com/joho/godotenv"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/time/rate"
)

// ServerEntry holds info about a registered game server.
type ServerEntry struct {
	HostName    string       `json:"host_name"`
	MapName     string       `json:"map_name"`
	GameMode    string       `json:"game_mode"`
	MaxPlayers  int          `json:"max_players"`
	IP          string       `json:"ip"`
	Port        int          `json:"port"`
	Players     []PlayerInfo `json:"players"`
	LastUpdated time.Time    `json:"-"`
	Validated   bool         `json:"validated"`
}

// PlayerInfo represents a player on the game server.
type PlayerInfo struct {
	Name string `json:"name"`
	Gen  int    `json:"gen"`
	Lvl  int    `json:"lvl"`
	Team int    `json:"team"`
}

// DiscordAuthPayload is used for Discord authentication endpoints.
type DiscordAuthPayload struct {
	DiscordId   string `json:"discord_id"`
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	PomeloName  string `json:"pomelo_name"`
}

// isValidMapName returns true if the given map name is valid.
func isValidMapName(name string) bool {
	for _, c := range name {
		if !unicode.IsLower(c) && !unicode.IsDigit(c) && c != '_' {
			return false
		}
	}
	return true
}

// isValidGameMode returns true if the given game mode is valid.
func isValidGameMode(mode string) bool {
	for _, c := range mode {
		if !unicode.IsLower(c) && !unicode.IsDigit(c) && c != '_' {
			return false
		}
	}
	return true
}

// MasterServer holds the in–memory state of registered servers and related data.
type MasterServer struct {
	servers        map[string]*ServerEntry // key: "ip:port"
	challenges     map[string]time.Time    // last challenge time per key
	lastHeartbeats map[string]time.Time    // last heartbeat time per key
	db             *sql.DB

	// Per-IP rate limiters (keyed by client IP)
	limiters   map[string]*rate.Limiter
	limiterMu  sync.Mutex
	serversMu  sync.RWMutex
	challengeMu sync.Mutex
}

// getLimiter returns a rate limiter for the given IP (creating one if needed).
func (ms *MasterServer) getLimiter(ip string) *rate.Limiter {
	ms.limiterMu.Lock()
	defer ms.limiterMu.Unlock()
	limiter, exists := ms.limiters[ip]
	if !exists {
		// Allow up to 5 requests per second with burst capacity 5.
		limiter = rate.NewLimiter(rate.Every(200*time.Millisecond), 5)
		ms.limiters[ip] = limiter
	}
	return limiter
}

// rateLimitMiddleware applies per–IP rate limiting.
func (ms *MasterServer) rateLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Use CF-Connecting-IP if available.
		clientIP := c.GetHeader("CF-Connecting-IP")
		if clientIP == "" {
			clientIP = c.ClientIP()
		}
		limiter := ms.getLimiter(clientIP)
		if !limiter.Allow() {
			c.AbortWithStatus(http.StatusTooManyRequests)
			return
		}
		c.Next()
	}
}

// HandlePerServerToken issues a JWT to a server using its Discord–based credentials.
func (ms *MasterServer) HandlePerServerToken(c *gin.Context) {
	// Get token from Authorization header.
	var authToken string
	if auth := c.GetHeader("Authorization"); auth != "" {
		if strings.HasPrefix(auth, "Bearer ") {
			authToken = strings.TrimPrefix(auth, "Bearer ")
		} else {
			log.Printf("Invalid authorization header from %s: %s", c.ClientIP(), auth)
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}
	}

	// Get the server IP from the JSON body.
	var server struct {
		IP string `json:"ip"`
	}
	if err := c.ShouldBindJSON(&server); err != nil {
		log.Printf("Invalid server IP format from %s: %v", c.ClientIP(), err)
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
	if server.IP == "" {
		log.Printf("Invalid server IP from %s: missing field", c.ClientIP())
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	if authToken == "" {
		log.Printf("Missing authorization header from %s", c.ClientIP())
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	// Lookup user info based on token.
	var discordId, discordName, pomeloName string
	row := ms.db.QueryRow("SELECT discord_id, pomelo_name, username FROM discord_auth WHERE token = ?", authToken)
	if err := row.Scan(&discordId, &discordName, &pomeloName); err != nil {
		log.Printf("Failed to query token from database: %v", err)
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "An error occurred"})
		return
	}

	// Read the private key from file (path configurable via env variable).
	keyPath := os.Getenv("JWT_PRIVATE_KEY_FILE")
	if keyPath == "" {
		keyPath = "new_key.pem"
	}
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		log.Fatalf("Error reading private key file: %v", err)
	}

	// Parse the EC private key.
	privateKey, err := jwt.ParseECPrivateKeyFromPEM(keyData)
	if err != nil {
		log.Fatalf("Error parsing EC private key: %v", err)
	}

	// Create a token including server_ip and client_ip.
	tokenClaims := jwt.MapClaims{
		"di":   discordId,
		"dn": discordName,
		"p":  pomeloName,
		"s":    server.IP,
//		"c":    c.ClientIP(),
		"e":          time.Now().Add(5 * time.Minute).Unix(),
	}
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodES256, tokenClaims)
	serverToken, err := jwtToken.SignedString(privateKey)
	if err != nil {
		log.Printf("Failed to create JWT token: %v", err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token":      serverToken,
		"discord_id": discordId,
		"username":   discordName,
		"pomelo_name": pomeloName,
	})
}

// HandleDiscordAuth handles the Discord OAuth2 code exchange.
func (ms *MasterServer) HandleDiscordAuth(c *gin.Context) {
	code, exists := c.GetQuery("code")
	if !exists || code == "" {
		log.Printf("Invalid Discord auth code from %s: missing 'code' query parameter", c.ClientIP())
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid Discord auth code"})
		return
	}

	log.Printf("Discord auth code received: %s", code)

	// Exchange the code for an access token.
	CLIENT_SECRET := os.Getenv("CLIENT_SECRET")
	REDIRECT_URI := os.Getenv("REDIRECT_URI")
	formData := url.Values{}
	formData.Set("grant_type", "authorization_code")
	formData.Set("code", code)
	formData.Set("redirect_uri", REDIRECT_URI)
	formData.Set("client_id", os.Getenv("CLIENT_ID"))
	formData.Set("client_secret", CLIENT_SECRET)

	req, err := http.NewRequest("POST", "https://discord.com/api/oauth2/token", strings.NewReader(formData.Encode()))
	if err != nil {
		log.Printf("Failed to create token exchange request: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create request"})
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("Failed to exchange code for token: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error exchanging code"})
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Failed to read token response body: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error reading response"})
		return
	}
	if resp.StatusCode != http.StatusOK {
		log.Printf("Unexpected status code from Discord: %d, body: %s", resp.StatusCode, string(body))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error from Discord"})
		return
	}

	var tokenResponse struct {
		TokenType    string `json:"token_type"`
		AccessToken  string `json:"access_token"`
		ExpiresIn    int    `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
		Scope        string `json:"scope"`
	}
	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		log.Printf("Failed to decode token response: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decode token response"})
		return
	}

	// Get user info from Discord.
	req, err = http.NewRequest("GET", "https://discord.com/api/v10/users/@me", nil)
	if err != nil {
		log.Printf("Failed to create user info request: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user info request"})
		return
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tokenResponse.AccessToken))
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("Failed to get user info: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error getting user info"})
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Printf("Unexpected status code when fetching user info: %d", resp.StatusCode)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error fetching user info"})
		return
	}

	var userResponse struct {
		ID       string `json:"id"`
		Username string `json:"username"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&userResponse); err != nil {
		log.Printf("Failed to decode user response: %v", err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	// Check if token already exists.
	var existingToken string
	err = ms.db.QueryRow("SELECT token FROM discord_auth WHERE discord_id = ?", userResponse.ID).Scan(&existingToken)
	if err == nil {
		c.JSON(http.StatusOK, gin.H{"token": existingToken})
		return
	} else if err != sql.ErrNoRows {
		log.Printf("Database error when querying discord_auth: %v", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Please join the R1Delta Discord server."})
		return
	}

	// For now, if no record exists, return an error (invite join required).
	c.JSON(http.StatusUnauthorized, gin.H{"error": "Please join the R1Delta Discord server."})
}

// HandleUser returns user info for a given Discord token.
func (ms *MasterServer) HandleUser(c *gin.Context) {
	var token string
	if auth := c.GetHeader("Authorization"); auth != "" {
		if strings.HasPrefix(auth, "Bearer ") {
			token = strings.TrimPrefix(auth, "Bearer ")
		} else {
			log.Printf("Invalid authorization header from %s: %s", c.ClientIP(), auth)
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}
	}
	if token == "" {
		log.Printf("Missing authorization header from %s", c.ClientIP())
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	var discordId, discordName, displayName string
	row := ms.db.QueryRow("SELECT discord_id, username, display_name FROM discord_auth WHERE token = ?", token)
	if err := row.Scan(&discordId, &discordName, &displayName); err != nil {
		log.Printf("Database error when scanning user info: %v", err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"discord_id":  discordId,
		"username":    discordName,
		"display_name": displayName,
	})
}

// HandleDiscordAuthChunk processes a batch of Discord auth payloads.
func (ms *MasterServer) HandleDiscordAuthChunk(c *gin.Context) {
	var payload []DiscordAuthPayload
	if err := c.ShouldBindJSON(&payload); err != nil {
		log.Printf("Invalid Discord auth payload from %s: %v", c.ClientIP(), err)
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
	// Check master server token.
	var msToken string
	if auth := c.GetHeader("Authorization"); auth != "" {
		if strings.HasPrefix(auth, "Bearer ") {
			msToken = strings.TrimPrefix(auth, "Bearer ")
			log.Printf("Master server token received: %s", msToken)
		} else {
			log.Printf("Invalid authorization header from %s: %s", c.ClientIP(), auth)
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}
	}
	if msToken == "" || msToken != os.Getenv("MS_TOKEN") {
		log.Printf("Unauthorized master server token from %s", c.ClientIP())
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	if len(payload) == 0 {
		log.Printf("Empty Discord auth payload from %s", c.ClientIP())
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
	log.Printf("Discord auth chunk payload received: %+v", payload)

	// Load the Discord JWT signing secret from environment.
	jwtSecret := os.Getenv("JWT_DISCORD_SECRET")
	if jwtSecret == "" {
		log.Fatal("JWT_DISCORD_SECRET environment variable not set")
	}

	for _, p := range payload {
		if p.DiscordId == "" || p.Username == "" {
			log.Printf("Missing fields in Discord auth payload from %s", c.ClientIP())
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}
		// Check if token exists.
		var token string
		err := ms.db.QueryRow("SELECT token FROM discord_auth WHERE discord_id = ?", p.DiscordId).Scan(&token)
		if err != nil {
			if err == sql.ErrNoRows {
				// Create a new token.
				tkn := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
					"discord_id":   p.DiscordId,
					"username":     p.Username,
					"display_name": p.DisplayName,
					"pomelo_name":  p.PomeloName,
					//"exp":          time.Now().Add(24 * time.Hour).Unix(),
				})
				token, err = tkn.SignedString([]byte(jwtSecret))
				if err != nil {
					log.Printf("Failed to create Discord JWT token: %v", err)
					c.AbortWithStatus(http.StatusInternalServerError)
					return
				}
				_, err = ms.db.Exec("INSERT INTO discord_auth (discord_id, username, token, display_name, pomelo_name) VALUES (?, ?, ?, ?, ?)",
					p.DiscordId, p.Username, token, p.DisplayName, p.PomeloName)
				if err != nil {
					log.Printf("Failed to store Discord token in database: %v", err)
					c.AbortWithStatus(http.StatusInternalServerError)
					return
				}
			} else {
				log.Printf("Database error querying discord_auth: %v", err)
				c.AbortWithStatus(http.StatusInternalServerError)
				return
			}
		} else {
			// Update display name and pomelo name.
			_, err = ms.db.Exec("UPDATE discord_auth SET display_name = ?, pomelo_name = ? WHERE discord_id = ?",
				p.DisplayName, p.PomeloName, p.DiscordId)
			if err != nil {
				log.Printf("Failed to update discord_auth for %s: %v", p.DiscordId, err)
				// Continue processing next payload.
				continue
			}
		}
	}
	c.JSON(http.StatusOK, gin.H{"ok": "ok"})
}

// HandleDiscordDelete deletes a Discord auth record.
func (ms *MasterServer) HandleDiscordDelete(c *gin.Context) {
	var payload DiscordAuthPayload
	if err := c.ShouldBindJSON(&payload); err != nil {
		log.Printf("Invalid payload from %s: %v", c.ClientIP(), err)
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
	if payload.DiscordId == "" {
		log.Printf("Missing DiscordId in payload from %s", c.ClientIP())
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
	var msToken string
	if auth := c.GetHeader("Authorization"); auth != "" {
		if strings.HasPrefix(auth, "Bearer ") {
			msToken = strings.TrimPrefix(auth, "Bearer ")
			log.Printf("Master server token received: %s", msToken)
		} else {
			log.Printf("Invalid authorization header from %s: %s", c.ClientIP(), auth)
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}
	}
	if msToken == "" || msToken != os.Getenv("MS_TOKEN") {
		log.Printf("Unauthorized master server token from %s", c.ClientIP())
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	_, err := ms.db.Exec("DELETE FROM discord_auth WHERE discord_id = ?", payload.DiscordId)
	if err != nil {
		log.Printf("Failed to delete Discord auth record for %s: %v", payload.DiscordId, err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	c.Status(http.StatusOK)
}

// HandleDiscordClientAuth processes a Discord auth payload from a client.
func (ms *MasterServer) HandleDiscordClientAuth(c *gin.Context) {
	var payload DiscordAuthPayload
	if err := c.ShouldBindJSON(&payload); err != nil {
		log.Printf("Invalid Discord auth payload from %s: %v", c.ClientIP(), err)
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
	if payload.DiscordId == "" {
		log.Printf("Missing DiscordId in payload from %s", c.ClientIP())
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
	var msToken string
	if auth := c.GetHeader("Authorization"); auth != "" {
		if strings.HasPrefix(auth, "Bearer ") {
			msToken = strings.TrimPrefix(auth, "Bearer ")
			log.Printf("Master server token received: %s", msToken)
		} else {
			log.Printf("Invalid authorization header from %s: %s", c.ClientIP(), auth)
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}
	}
	if msToken == "" || msToken != os.Getenv("MS_TOKEN") {
		log.Printf("Unauthorized master server token from %s", c.ClientIP())
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	log.Printf("Discord client auth payload received: %+v", payload)

	// Check for existing token.
	var token string
	err := ms.db.QueryRow("SELECT token FROM discord_auth WHERE discord_id = ?", payload.DiscordId).Scan(&token)
	if err != nil {
		if err == sql.ErrNoRows {
			// Load Discord JWT secret from env.
			jwtSecret := os.Getenv("JWT_DISCORD_SECRET")
			if jwtSecret == "" {
				log.Fatal("JWT_DISCORD_SECRET not set")
			}
			tkn := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
				"discord_id":   payload.DiscordId,
				"username":     payload.Username,
				"display_name": payload.DisplayName,
				"pomelo_name":  payload.PomeloName,
				//"exp":          time.Now().Add(24 * time.Hour).Unix(), (permanent auth token never expires otherwise you'd need to relogin and that'd be really fucking annoying, if you need to regen your token you can just rejoin the discord)
			})
			token, err = tkn.SignedString([]byte(jwtSecret))
			if err != nil {
				log.Printf("Failed to create Discord JWT token: %v", err)
				c.AbortWithStatus(http.StatusInternalServerError)
				return
			}
			_, err = ms.db.Exec("INSERT INTO discord_auth (discord_id, username, token, display_name, pomelo_name) VALUES (?, ?, ?, ?, ?)",
				payload.DiscordId, payload.Username, token, payload.DisplayName, payload.PomeloName)
			if err != nil {
				log.Printf("Failed to store Discord token in database: %v", err)
				c.AbortWithStatus(http.StatusInternalServerError)
				return
			}
		} else {
			log.Printf("Database error querying discord_auth: %v", err)
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
	} else {
		// Update display name, pomelo name, and username.
		_, err = ms.db.Exec("UPDATE discord_auth SET display_name = ?, pomelo_name = ?, username = ? WHERE discord_id = ?",
			payload.DisplayName, payload.PomeloName, payload.Username, payload.DiscordId)
		if err != nil {
			log.Printf("Failed to update Discord auth record: %v", err)
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
	}
	c.JSON(http.StatusOK, gin.H{"token": token})
}

// HandleHeartbeat processes a heartbeat from a game server.
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

	// Validate port.
	if heartbeat.Port <= 1024 || heartbeat.Port > 65535 {
		log.Printf("Invalid port number %d in heartbeat from %s", heartbeat.Port, c.ClientIP())
		c.String(http.StatusBadRequest, "Invalid port number (must be 1025-65535)")
		c.Abort()
		return
	}

	// Sanitize hostname
	hostname := heartbeat.HostName
	if len(hostname) > 64 {
	    hostname = hostname[:64]
	}
	// Replace any special characters with underscores
	hostname = strings.Map(func(r rune) rune {
	    if strings.ContainsRune("\";<>{}()", r) {
	        return '_'
	    }
	    return r
	}, hostname)
	if len(hostname) < 3 {
	    hostname = "Unnamed R1Delta Server"
	}
	heartbeat.HostName = hostname

	// Validate map name.
	if heartbeat.MapName == "" || len(heartbeat.MapName) > 32 || !isValidMapName(heartbeat.MapName) {
		log.Printf("Invalid map name %q from %s", heartbeat.MapName, c.ClientIP())
		c.String(http.StatusBadRequest, "Invalid map name format (lowercase letters, numbers, underscores only)")
		c.Abort()
		return
	}

	// Validate game mode.
	if heartbeat.GameMode == "" || len(heartbeat.GameMode) > 32 || !isValidGameMode(heartbeat.GameMode) {
		log.Printf("Invalid game mode %q from %s", heartbeat.GameMode, c.ClientIP())
		c.String(http.StatusBadRequest, "Invalid game mode format (lowercase letters, numbers, underscores only)")
		c.Abort()
		return
	}

	// Validate max players.
	if heartbeat.MaxPlayers <= 1 || heartbeat.MaxPlayers >= 20 {
		log.Printf("Invalid max players %d from %s", heartbeat.MaxPlayers, c.ClientIP())
		c.String(http.StatusBadRequest, "Invalid max players (must be 2-19)")
		c.Abort()
		return
	}
	if len(heartbeat.Players) > heartbeat.MaxPlayers {
	    log.Printf("Too many players (%d) vs max players (%d) from %s", len(heartbeat.Players), heartbeat.MaxPlayers, c.ClientIP())
	    c.String(http.StatusBadRequest, "Player count exceeds max players")
	    c.Abort()
	    return
	}
	// Validate player names.
	for _, player := range heartbeat.Players {
		if strings.TrimSpace(player.Name) == "" {
			log.Printf("Empty player name in heartbeat from %s", c.ClientIP())
			c.String(http.StatusBadRequest, "Player names cannot be empty")
			c.Abort()
			return
		}
	}

	// Determine the IP of the connecting server.
	clientIP := c.Request.RemoteAddr
	ip, _, err := net.SplitHostPort(clientIP)
	if err != nil {
		ip = clientIP
	}
	// Override loopback with public IP if necessary.
	if ip == "127.0.0.1" || ip == "::1" {
		publicIP, err := getPublicIP()
		if err != nil {
			log.Printf("Could not determine public IP for loopback override: %v", err)
		} else {
			ip = publicIP
			log.Printf("Overriding loopback IP with public IP: %s", ip)
		}
	}

	key := fmt.Sprintf("%s:%d", ip, heartbeat.Port)

	ms.serversMu.Lock()
	defer ms.serversMu.Unlock()

	// Limit maximum servers per IP to 5.
	if _, exists := ms.servers[key]; !exists {
		count := 0
		for _, s := range ms.servers {
			if s.IP == ip {
				count++
			}
		}
		if count >= 5 {
			log.Printf("Too many servers (%d) for IP %s", count, ip)
			c.String(http.StatusBadRequest, "Maximum 5 servers per IP")
			c.Abort()
			return
		}
	}

	entry := &ServerEntry{
		HostName:    heartbeat.HostName,
		MapName:     heartbeat.MapName,
		GameMode:    heartbeat.GameMode,
		MaxPlayers:  heartbeat.MaxPlayers,
		IP:          ip,
		Port:        heartbeat.Port,
		Players:     heartbeat.Players,
		LastUpdated: time.Now(),
		Validated:   false,
	}

	// Check last heartbeat and challenge times.
	prevHeartbeat, heartbeatExists := ms.lastHeartbeats[key]
	_, challengeExists := ms.challenges[key]
	ms.lastHeartbeats[key] = time.Now()
	if !challengeExists || (heartbeatExists && time.Since(prevHeartbeat) > 30*time.Second) {
		go ms.PerformValidation(ip, heartbeat.Port)
		ms.challengeMu.Lock()
		ms.challenges[key] = time.Now()
		ms.challengeMu.Unlock()
	} else {
		entry.Validated = true
	}

	ms.servers[key] = entry
	c.Status(http.StatusOK)
}

// PerformValidation sends a UDP challenge to the server and marks it validated on success.
func (ms *MasterServer) PerformValidation(ip string, port int) {
	log.Printf("[Validation] Starting validation for %s:%d", ip, port)
	nonce := make([]byte, 4)
	if _, err := rand.Read(nonce); err != nil {
		log.Printf("[Validation] Failed to generate nonce for %s:%d: %v", ip, port, err)
		return
	}
	nonceStr := "0x" + hex.EncodeToString(nonce)

	addr := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("udp", addr, 2*time.Second)
	if err != nil {
		log.Printf("[Validation] Connection failed to %s:%d: %v", ip, port, err)
		return
	}
	defer conn.Close()

	// Construct challenge packet.
	challengePacket := make([]byte, 23)
	copy(challengePacket[0:4], []byte{0xFF, 0xFF, 0xFF, 0xFF})
	challengePacket[4] = 0x48
	copy(challengePacket[5:12], "connect")
	copy(challengePacket[12:22], nonceStr)
	challengePacket[22] = 0x00

	log.Printf("[Validation] Sending challenge to %s:%d (nonce: %s)", ip, port, nonceStr)
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write(challengePacket); err != nil {
		log.Printf("[Validation] Failed to send challenge to %s:%d: %v", ip, port, err)
		return
	}

	respBuf := make([]byte, 1024)
	n, err := conn.Read(respBuf)
	if err != nil {
		log.Printf("[Validation] Failed to read response from %s:%d: %v", ip, port, err)
		return
	}
	if n < 25 {
		log.Printf("[Validation] Short response (%d bytes) from %s:%d", n, ip, port)
		return
	}

	log.Printf("[Validation] Received %d bytes from %s:%d", n, ip, port)
	if !validateResponse(respBuf[:n], nonceStr) {
		log.Printf("[Validation] Validation failed for %s:%d", ip, port)
		return
	}

	// Mark the server as validated.
	ms.serversMu.Lock()
	defer ms.serversMu.Unlock()
	key := fmt.Sprintf("%s:%d", ip, port)
	if server, exists := ms.servers[key]; exists {
		log.Printf("[Validation] Successfully validated %s:%d (%s)", ip, port, server.HostName)
		server.Validated = true
	}
}

// validateResponse checks that the challenge response is correct.
func validateResponse(resp []byte, nonce string) bool {
	if len(resp) < 25 {
		log.Printf("[Validation] Response too short: %d bytes", len(resp))
		return false
	}
	headerValid := resp[0] == 0xFF && resp[1] == 0xFF && resp[2] == 0xFF && resp[3] == 0xFF && resp[4] == 0x49
	if !headerValid {
		log.Printf("[Validation] Invalid header in response: %X %X %X %X %X", resp[0], resp[1], resp[2], resp[3], resp[4])
		return false
	}
	connectStr := string(resp[9:16])
	if connectStr != "connect" {
		log.Printf("[Validation] Expected 'connect', got %q", connectStr)
		return false
	}
	responseNonce := string(resp[16:26])
	if responseNonce != nonce {
		log.Printf("[Validation] Nonce mismatch: expected %q, got %q", nonce, responseNonce)
		return false
	}
	return true
}

// GetServers returns the list of currently validated servers.
func (ms *MasterServer) GetServers(c *gin.Context) {
	ms.serversMu.RLock()
	defer ms.serversMu.RUnlock()
	validServers := make([]*ServerEntry, 0)
	for _, s := range ms.servers {
		if s.Validated && time.Since(s.LastUpdated) < 30*time.Second {
			validServers = append(validServers, s)
		}
	}
	c.JSON(http.StatusOK, validServers)
}

// CleanupOldEntries periodically removes stale server entries.
func (ms *MasterServer) CleanupOldEntries() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		ms.serversMu.Lock()
		for k, s := range ms.servers {
			if time.Since(s.LastUpdated) > 90*time.Second {
				log.Printf("[Cleanup] Removing server %s (%s:%d), last updated %v ago, validated=%v",
					s.HostName, s.IP, s.Port, time.Since(s.LastUpdated), s.Validated)
				delete(ms.servers, k)
			}
		}
		ms.serversMu.Unlock()
	}
}

// fetchCloudflareIPs retrieves Cloudflare proxy IP ranges.
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
		return nil, fmt.Errorf("failed to read Cloudflare IPs: %v", err)
	}
	ips := strings.Split(strings.TrimSpace(string(body)), "\n")
	if len(ips) == 0 {
		return nil, fmt.Errorf("empty Cloudflare IP list received")
	}
	return ips, nil
}

// getPublicIP returns the public IP address by querying an external service.
func getPublicIP() (string, error) {
	client := &http.Client{Timeout: 5 * time.Second}
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
		return "", fmt.Errorf("failed to read public IP response: %v", err)
	}
	ip := strings.TrimSpace(string(body))
	if net.ParseIP(ip) == nil {
		return "", fmt.Errorf("invalid IP address received: %s", ip)
	}
	return ip, nil
}

// HandleDelete removes a server entry based on its port.
func (ms *MasterServer) HandleDelete(c *gin.Context) {
	port := c.Param("port")
	clientIP := c.Request.RemoteAddr
	ip, _, err := net.SplitHostPort(clientIP)
	if err != nil {
		ip = clientIP
	}
	key := fmt.Sprintf("%s:%s", ip, port)
	ms.serversMu.Lock()
	delete(ms.servers, key)
	ms.serversMu.Unlock()
	c.Status(http.StatusOK)
}

// NewMasterServer creates and initializes a MasterServer instance.
func NewMasterServer() *MasterServer {
	return &MasterServer{
		servers:        make(map[string]*ServerEntry),
		challenges:     make(map[string]time.Time),
		lastHeartbeats: make(map[string]time.Time),
		limiters:       make(map[string]*rate.Limiter),
	}
}

func main() {
	// Load environment variables.
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found – using environment variables")
	}

	// Set Gin to release mode.
	gin.SetMode(gin.ReleaseMode)

	// Open SQLite database.
	db, err := sql.Open("sqlite3", "r1delta.db")
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	// Set WAL mode.
	_, err = db.Exec("PRAGMA journal_mode = WAL")
	if err != nil {
		log.Fatalf("Failed to set WAL mode: %v", err)
	}

	// Fetch Cloudflare IP ranges.
	cfIPs, err := fetchCloudflareIPs()
	if err != nil {
		log.Printf("Warning: %v. Using fallback Cloudflare IPs.", err)
		cfIPs = []string{
			"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
			"103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
			"190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
			"198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
			"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
		}
	}

	// Initialize master server instance.
	ms := NewMasterServer()
	ms.db = db

	// Start the cleanup goroutine.
	go ms.CleanupOldEntries()
	gin.SetMode(gin.ReleaseMode)
	// Set up Gin.
	r := gin.Default()

        r.RemoteIPHeaders = []string{"CF-Connecting-IP"}
	// Configure trusted proxies.
	if err := r.SetTrustedProxies(cfIPs); err != nil {
	    log.Fatalf("Failed to set trusted proxies: %v", err)
	}



	r.Use(ms.rateLimitMiddleware())

	// Set up routes.
	r.POST("/heartbeat", ms.HandleHeartbeat)
	r.DELETE("/heartbeat/:port", ms.HandleDelete)
	r.GET("/servers", ms.GetServers)
	r.GET("/discord-auth", ms.HandleDiscordAuth)
	r.POST("/discord-auth", ms.HandleDiscordClientAuth)
	r.POST("/discord-auth-chunk", ms.HandleDiscordAuthChunk)
	r.DELETE("/discord-auth", ms.HandleDiscordDelete)
	r.GET("/user", ms.HandleUser)
	r.POST("/server-token", ms.HandlePerServerToken)

	// Start server on port 80.
	if err := r.Run(":80"); err != nil {
		log.Fatalf("Failed to run server: %v", err)
	}
}
