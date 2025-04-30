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
	"strconv" // <-- Added missing import
	"strings"
	"sync"
	"time"
	"unicode"

	"regexp"
	"github.com/oschwald/geoip2-golang"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"github.com/joho/godotenv"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/time/rate"
)

// ---------- Region codes ----------
const (
	RegionNAE = "[NAEst]" // North America – East
	RegionNAC = "[NACen]" // North America – Central
	RegionNAW = "[NAWst]" // North America – West
	RegionCAM = "[CAmer]" // Central America
	RegionSAM = "[SAmer]" // South America
	RegionEWE = "[EUWst]" // Europe – West
	RegionEEE = "[EUEst]" // Europe – East
	RegionRUS = "[Rusia]" // Russia
	RegionASE = "[AsiaE]" // Asia – East
	RegionASS = "[AsiaS]" // Asia – South
	RegionAEA = "[AsSEA]" // Asia – Southeast
	RegionOCE = "[Ocean]" // Oceania
	RegionMEA = "[MEast]" // Middle East
	RegionAFR = "[Afric]" // Africa
	RegionLOC = "[LOCAL]"  // Private / loopback IPs detected by master server
	RegionUNK = "[UNKNW]"  // Unknown or GeoIP failed
)

// longitude cut-offs (refined)
const (
	naWestCut    = -105.0 // < −105 → West
	naCentralCut =  -90.0 // −105..−90 → Central ; ≥ −90 → East
	euWestCut    =   20.0 // < 20 E → EU-West
)

// pre-compiled once for prefix-strip: [[XXXXX]]␠
var stripPrefix = regexp.MustCompile(`^\[[A-Za-z]{5}\]\s*`)


// ServerEntry holds info about a registered game server.
type ServerEntry struct {
	HostName    string       `json:"host_name"`
	MapName     string       `json:"map_name"`
	GameMode    string       `json:"game_mode"`
	MaxPlayers  int          `json:"max_players"`
	Description string       `json:"description"`
	Playlist    string       `json:"playlist"`
	PlaylistDisplayName string `json:"playlist_display_name"`
	HasPassword bool         `json:"has_password"`
	TotalPlayers int         `json:"total_players"`
	IP          string       `json:"ip"`
	Version     string       `json:"version"` // Added Version field
	Port        int          `json:"port"`
	Players     []PlayerInfo `json:"players"`
	LastUpdated time.Time    `json:"-"` // Exclude from JSON
	Validated   bool         `json:"validated"`
}

// PlayerInfo represents a player on the game server.
type PlayerInfo struct {
	Name string `json:"name"`
	Gen  int    `json:"gen"`
	Lvl  int    `json:"lvl"`
	Team int    `json:"team"`
}

// DiscordAuthPayload is used for Discord authentication endpoints (primarily bot sync).
type DiscordAuthPayload struct {
	DiscordId   string `json:"discord_id"`
	Username    string `json:"username"` // Discord username (e.g., "pomelo_name")
	DisplayName string `json:"display_name"` // Global display name (e.g., "Pomelo")
	PomeloName  string `json:"pomelo_name"` // Deprecated username format (e.g., "Pomelo#1234") - Use Username/DisplayName
}

// isValidMapName returns true if the given map name is valid.
func isValidMapName(name string) bool {
	// Allow only lowercase letters, numbers, and underscores
	for _, c := range name {
		if !unicode.IsLower(c) && !unicode.IsDigit(c) && c != '_' {
			return false
		}
	}
	return true
}

// isValidGameMode returns true if the given game mode is valid.
func isValidGameMode(mode string) bool {
	// Allow only lowercase letters, numbers, and underscores
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
	challenges     map[string]time.Time    // last challenge initiation time per key
	lastHeartbeats map[string]time.Time    // last heartbeat time per key (redundant with ServerEntry?) - Let's rely on ServerEntry.LastUpdated
	db             *sql.DB
	geoip          *geoip2.Reader

	// Per-IP rate limiters (keyed by client IP)
	limiters   map[string]*rate.Limiter
	limiterMu  sync.Mutex
	serversMu  sync.RWMutex
	challengeMu sync.Mutex
}

// determineRegionCode maps a GeoIP “City” record to one of the 5-letter codes.
func determineRegionCode(rec *geoip2.City) string {
	// Check if rec is nil or if Continent data exists via Code
	// Fix: rec.Continent is a struct, cannot compare to nil. Check Code field.
	if rec == nil || rec.Continent.Code == "" { return RegionUNK }

	cc := rec.Country.IsoCode

	// Fix: Location is a non-pointer struct. Check if its data is meaningful, not if the struct itself is nil.
	// Declare variables before checking for location data.
	var lon float64
	// Check if Location data is meaningful (e.g., non-zero lat/lon)
	hasLoc := rec.Location.Latitude != 0 || rec.Location.Longitude != 0
	if hasLoc {
		lon = rec.Location.Longitude
	} else {
		// If no location data, lon remains its zero value (0.0).
		// The code below relies on the `!hasLoc` checks within the NA/EU cases
		// to default the region if location data is missing. This is fine.
	}


	// country overrides (fast path) - these don't typically depend on longitude
	if cc == "RU"      { return RegionRUS }
	if _, ok := map[string]struct{}{
		"BZ":{}, "CR":{}, "SV":{}, "GT":{}, "HN":{}, "NI":{}, "PA":{}, "MX":{},
	}[cc]; ok { return RegionCAM }
	if _, ok := map[string]struct{}{
		"AE":{}, "BH":{}, "CY":{}, "EG":{}, "IR":{}, "IQ":{}, "IL":{}, "JO":{},
		"KW":{}, "LB":{}, "OM":{}, "PS":{}, "QA":{}, "SA":{}, "SY":{}, "TR":{}, "YE":{},
	}[cc]; ok { return RegionMEA }
	if _, ok := map[string]struct{}{
		"AF":{}, "BD":{}, "BT":{}, "IN":{}, "MV":{}, "NP":{}, "PK":{}, "LK":{},
	}[cc]; ok { return RegionASS }
	if _, ok := map[string]struct{}{
		"BN":{}, "KH":{}, "ID":{}, "LA":{}, "MY":{}, "MM":{}, "PH":{}, "SG":{},
		"TH":{}, "TL":{}, "VN":{},
	}[cc]; ok { return RegionAEA }

	switch rec.Continent.Code {
	case "NA":
		if !hasLoc { return RegionNAE } // Default NA region if no detailed location
		switch { // Use the calculated 'lon' here
		case lon < naWestCut:    return RegionNAW
		case lon < naCentralCut: return RegionNAC
		default:                 return RegionNAE
		}
	case "EU":
		if !hasLoc { return RegionEWE } // Default EU region if no detailed location
		if lon < euWestCut { return RegionEWE } // Use the calculated 'lon' here
		return RegionEEE
	case "AS":
		return RegionASE // defaults; sub-regions handled earlier
	case "SA":
		return RegionSAM
	case "AF":
		return RegionAFR
	case "OC":
		return RegionOCE
	default:
		return RegionUNK
	}
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
		// Use the IP resolved by Gin after trusted proxies are configured.
		clientIP := c.ClientIP()
		limiter := ms.getLimiter(clientIP)
		if !limiter.Allow() {
			log.Printf("Rate limited IP: %s", clientIP) // Log rate limiting
			c.AbortWithStatus(http.StatusTooManyRequests)
			return
		}
		c.Next()
	}
}

// HandlePerServerToken issues a JWT to a server using its Discord–based credentials (permanent token).
// Endpoint: POST /server-token
// Authentication: Bearer <permanent_master_auth_token>
// Body: { "ip": "server_public_ip" }
// Response: { "token": "short_lived_server_auth_token", "discord_id": "...", "username": "...", "pomelo_name": "..." }
func (ms *MasterServer) HandlePerServerToken(c *gin.Context) {
	// Get permanent token from Authorization header.
	var permanentAuthToken string
	if auth := c.GetHeader("Authorization"); auth != "" {
		if strings.HasPrefix(auth, "Bearer ") {
			permanentAuthToken = strings.TrimPrefix(auth, "Bearer ")
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
		log.Printf("Invalid server IP from %s: missing field 'ip'", c.ClientIP())
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	if permanentAuthToken == "" {
		log.Printf("Missing authorization header from %s", c.ClientIP())
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	// Lookup user info based on the permanent token.
	var discordId, username, displayName, pomeloName string
	// Select all fields associated with the permanent token
	row := ms.db.QueryRow("SELECT discord_id, username, display_name, pomelo_name FROM discord_auth WHERE token = ?", permanentAuthToken)
	if err := row.Scan(&discordId, &username, &displayName, &pomeloName); err != nil {
		if err == sql.ErrNoRows {
             log.Printf("Permanent master token not found or invalid from %s", c.ClientIP())
             c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid permanent auth token"})
        } else {
            log.Printf("Failed to query permanent token from database: %v", err)
            c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "An error occurred"})
        }
		return
	}

	// Read the EC private key from file (used for signing short-lived server tokens).
	keyPath := os.Getenv("JWT_PRIVATE_KEY_FILE")
	if keyPath == "" {
		keyPath = "new_key.pem" // Default key file name
	}
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		// This is a critical server configuration error
		log.Fatalf("Error reading EC private key file %q: %v", keyPath, err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Server configuration error (missing key)"})
		return
	}

	// Parse the EC private key.
	privateKey, err := jwt.ParseECPrivateKeyFromPEM(keyData)
	if err != nil {
		// This is a critical server configuration error
		log.Fatalf("Error parsing EC private key from %q: %v", keyPath, err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Server configuration error (bad key)"})
		return
	}

	// Create a short-lived server auth token.
	// Claims structure seen in C++: "di", "dn", "p", "e", "s"
	tokenClaims := jwt.MapClaims{
		"di":   discordId, // Discord User ID
		"dn": displayName, // Discord Global Display Name
		"p":  pomeloName,  // Discord Old Username format (if needed by client)
		"s":    server.IP, // Server's public IP provided in the request body
		"e":          time.Now().Add(5 * time.Minute).Unix(), // Expiration (5 minutes)
	}
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodES256, tokenClaims)
	serverAuthToken, err := jwtToken.SignedString(privateKey)
	if err != nil {
		log.Printf("Failed to create EC JWT token for server %s from user %s: %v", server.IP, discordId, err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	// Return the short-lived server auth token and associated user info.
	c.JSON(http.StatusOK, gin.H{
		"token":      serverAuthToken, // The short-lived token
		"discord_id": discordId,
		"username":   displayName, // Return display_name as "username" for compatibility with C++? Or username from DB? C++ uses "dn" claim which is displayName. Let's use displayName.
		"display_name": displayName, // Explicitly add display_name
		"pomelo_name": pomeloName,
	})
}

// HandleDiscordAuth handles the Discord OAuth2 code exchange flow from the client.
// Endpoint: GET /discord-auth?code=...
// Authentication: None initially, uses code from Discord redirect
// Response: { "token": "permanent_master_auth_token", "access_token": "...", "discord_id": "...", "username": "...", "pomelo_name": "..." }
func (ms *MasterServer) HandleDiscordAuth(c *gin.Context) {
	code, exists := c.GetQuery("code")
	if !exists || code == "" {
		log.Printf("Invalid Discord auth code from %s: missing 'code' query parameter", c.ClientIP())
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid Discord auth code"})
		return
	}

	log.Printf("Discord auth code received: %s (from %s)", code, c.ClientIP())

	// Exchange the code for an access token.
	CLIENT_SECRET := os.Getenv("CLIENT_SECRET")
	REDIRECT_URI := os.Getenv("REDIRECT_URI")
	CLIENT_ID := os.Getenv("CLIENT_ID")

    if CLIENT_SECRET == "" || REDIRECT_URI == "" || CLIENT_ID == "" {
        log.Fatalf("Missing Discord environment variables (CLIENT_ID, CLIENT_SECRET, REDIRECT_URI)")
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Server configuration error"})
        return
    }

	formData := url.Values{}
	formData.Set("grant_type", "authorization_code")
	formData.Set("code", code)
	formData.Set("redirect_uri", REDIRECT_URI)
	formData.Set("client_id", CLIENT_ID)
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
		log.Printf("Unexpected status code from Discord /oauth2/token: %d, body: %s", resp.StatusCode, string(body))
        var errorResponse struct { Error string `json:"error"`; ErrorDescription string `json:"error_description"` }
        if jsonErr := json.Unmarshal(body, &errorResponse); jsonErr == nil && errorResponse.ErrorDescription != "" {
             c.JSON(resp.StatusCode, gin.H{"error": fmt.Sprintf("Discord API error: %s", errorResponse.ErrorDescription)})
        } else {
             c.JSON(resp.StatusCode, gin.H{"error": "Error from Discord API"})
        }
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
		log.Printf("Failed to decode token response: %v (body: %s)", err, string(body))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decode token response"})
		return
	}

	// Get user info from Discord using the access token.
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
		ID            string `json:"id"`
		Username      string `json:"username"`       // New username (pomelo_name replacement)
		GlobalName    string `json:"global_name"`    // Global display name
		Discriminator string `json:"discriminator"`  // Old discriminator (may be "0")
		Avatar        string `json:"avatar"`
		// Add other fields if needed
	}
	if err := json.NewDecoder(resp.Body).Decode(&userResponse); err != nil {
		log.Printf("Failed to decode user response: %v", err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

    // Determine display name and pomelo name (for backward compatibility)
    displayName := userResponse.GlobalName // Discord's Global Name
    if displayName == "" {
        displayName = userResponse.Username // Fallback to new username
    }
    // Simulate old pomelo_name#discriminator format if needed
    pomeloName := userResponse.Username // Start with new username
    if userResponse.Discriminator != "0" && userResponse.Discriminator != "" {
        pomeloName = fmt.Sprintf("%s#%s", userResponse.Username, userResponse.Discriminator)
    }


	// Check if record already exists for this discord_id.
	var existingToken string
	var existingUsername, existingDisplayName, existingPomeloName string
	err = ms.db.QueryRow("SELECT token, username, display_name, pomelo_name FROM discord_auth WHERE discord_id = ?", userResponse.ID).Scan(&existingToken, &existingUsername, &existingDisplayName, &existingPomeloName)

	if err == nil {
        // Record exists. Update username, display_name, and pomelo_name if they changed.
        // This also ensures the latest names from Discord are in our DB.
        _, err = ms.db.Exec("UPDATE discord_auth SET username = ?, display_name = ?, pomelo_name = ? WHERE discord_id = ?",
            userResponse.Username, displayName, pomeloName, userResponse.ID)
        if err != nil {
             log.Printf("Failed to update discord_auth for existing user %s (%s) during auth: %v", userResponse.ID, userResponse.Username, err)
             // Log error but proceed, client still gets the existing token
        } else {
            log.Printf("Updated discord_auth for existing user %s (%s) during auth.", userResponse.ID, userResponse.Username)
        }
		// Return the existing token and the latest user info from DB/Discord
		c.JSON(http.StatusOK, gin.H{
            "token": existingToken, // Return existing permanent token
            "access_token": tokenResponse.AccessToken, // Return Discord access token (as client expects it)
            "discord_id": userResponse.ID,
            "username": userResponse.Username, // Return Discord's new username
            "display_name": displayName, // Return determined display name
            "pomelo_name": pomeloName, // Return determined pomelo name (old format)
        })
		return
	} else if err != sql.ErrNoRows {
		log.Printf("Database error when querying discord_auth for %s (%s): %v", userResponse.ID, userResponse.Username, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error during login"})
		return
	}

	// If err is sql.ErrNoRows, the user is not in our `discord_auth` table.
    // Create a new entry and a new permanent token (HS256).
    log.Printf("Registering new user %s (%s) via OAuth flow.", userResponse.ID, userResponse.Username)

    jwtSecret := os.Getenv("JWT_DISCORD_SECRET")
    if jwtSecret == "" {
        log.Fatalf("JWT_DISCORD_SECRET environment variable not set") // Critical error
        c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Server configuration error"})
        return
    }

    // Create a new permanent master auth token (signed with HS256).
    tkn := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
        "discord_id":   userResponse.ID,
        "username":     userResponse.Username,
        "display_name": displayName,
        "pomelo_name":  pomeloName,
        // Permanent token doesn't expire according to C++ comment
    })
    permanentToken, err := tkn.SignedString([]byte(jwtSecret))
    if err != nil {
        log.Printf("Failed to create permanent master auth token for %s (%s): %v", userResponse.ID, userResponse.Username, err)
        c.AbortWithStatus(http.StatusInternalServerError)
        return
    }

    // Insert the new user record into the database.
    _, err = ms.db.Exec("INSERT INTO discord_auth (discord_id, username, token, display_name, pomelo_name) VALUES (?, ?, ?, ?, ?)",
        userResponse.ID, userResponse.Username, permanentToken, displayName, pomeloName)
    if err != nil {
        log.Printf("Failed to store new user record in database for %s (%s): %v", userResponse.ID, userResponse.Username, err)
        c.AbortWithStatus(http.StatusInternalServerError)
        return
    }

    log.Printf("Successfully registered and issued token for user %s (%s).", userResponse.ID, userResponse.Username)

	// Return the new permanent token and Discord access token.
	c.JSON(http.StatusOK, gin.H{
        "token": permanentToken, // The new permanent master token
        "access_token": tokenResponse.AccessToken, // Return Discord access token (as client expects it)
        "discord_id": userResponse.ID,
        "username": userResponse.Username, // Return Discord's new username
        "display_name": displayName, // Return determined display name
        "pomelo_name": pomeloName, // Return determined pomelo name (old format)
    })
}

// HandleUser returns user info for a given permanent master auth token.
// Endpoint: GET /user
// Authentication: Bearer <permanent_master_auth_token>
// Response: { "discord_id": "...", "username": "...", "display_name": "...", "pomelo_name": "..." }
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

	var discordId, username, displayName, pomeloName string
	row := ms.db.QueryRow("SELECT discord_id, username, display_name, pomelo_name FROM discord_auth WHERE token = ?", token)
	if err := row.Scan(&discordId, &username, &displayName, &pomeloName); err != nil {
		if err == sql.ErrNoRows {
			log.Printf("Permanent master token not found: %s (from %s)", token, c.ClientIP())
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		} else {
			log.Printf("Database error when scanning user info for token %s (from %s): %v", token, c.ClientIP(), err)
			c.AbortWithStatus(http.StatusInternalServerError)
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"discord_id":  discordId,
		"username":    username,     // Return Discord's new username
		"display_name": displayName, // Return Global Display Name
		"pomelo_name": pomeloName,  // Return old username format
	})
}

// HandleDiscordAuthChunk processes a batch of Discord auth payloads (from a bot).
// Endpoint: POST /discord-auth-chunk
// Authentication: Bearer <MS_TOKEN>
// Body: [ { "discord_id": "...", "username": "...", "display_name": "...", "pomelo_name": "..." }, ... ]
// Response: { "status": "processed" } or error
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
			log.Printf("Master server token received (chunk) from %s", c.ClientIP())
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
		c.JSON(http.StatusOK, gin.H{"status": "processed"}) // Return OK for empty payload
		return
	}
	log.Printf("Discord auth chunk payload received (%d entries) from %s", len(payload), c.ClientIP())

	// Load the Discord JWT signing secret from environment (used for generating permanent tokens).
	jwtSecret := os.Getenv("JWT_DISCORD_SECRET")
	if jwtSecret == "" {
		log.Fatalf("JWT_DISCORD_SECRET environment variable not set") // Critical error
        c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Server configuration error"})
        return
	}

	// Use a transaction for batch inserts/updates
	tx, err := ms.db.Begin()
	if err != nil {
		log.Printf("Failed to start transaction: %v", err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	defer tx.Rollback() // Rollback on error

	// Prepare statements
	insertStmt, err := tx.Prepare("INSERT INTO discord_auth (discord_id, username, token, display_name, pomelo_name) VALUES (?, ?, ?, ?, ?)")
	if err != nil {
		log.Printf("Failed to prepare INSERT statement: %v", err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	defer insertStmt.Close()

	// Update statement includes username, display_name, and pomelo_name
	updateStmt, err := tx.Prepare("UPDATE discord_auth SET username = ?, display_name = ?, pomelo_name = ? WHERE discord_id = ?")
	if err != nil {
		log.Printf("Failed to prepare UPDATE statement: %v", err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	defer updateStmt.Close()

	// Select statement only needs to check for existence
	selectStmt, err := tx.Prepare("SELECT 1 FROM discord_auth WHERE discord_id = ?") // SELECT 1 is efficient
	if err != nil {
		log.Printf("Failed to prepare SELECT statement: %v", err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	defer selectStmt.Close()

    processedCount := 0

	for _, p := range payload {
		if p.DiscordId == "" || p.Username == "" { // Username is required for registration
			log.Printf("Skipping entry with missing DiscordId or Username from %s: %+v", c.ClientIP(), p)
			continue // Skip this specific invalid entry, don't abort the whole batch
		}
		// Check if record exists.
		var exists bool
		err := selectStmt.QueryRow(p.DiscordId).Scan(&exists)

		if err != nil && err != sql.ErrNoRows {
            log.Printf("Database error querying discord_auth for %s: %v", p.DiscordId, err)
            continue // Log error and continue with the next payload
		}

		// Fix: Declare 'token' variable outside the conditional blocks so it's in scope for line 677 (and 682).
		var token string

        if err == sql.ErrNoRows {
            // Record does not exist, create a new one.
            log.Printf("Bot sync registering new user: %s (%s)", p.DiscordId, p.Username)

            // Create a new permanent master auth token (signed with HS256).
            tkn := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
                "discord_id":   p.DiscordId,
                "username":     p.Username,
                "display_name": p.DisplayName,
                "pomelo_name":  p.PomeloName,
                // Permanent token doesn't expire
            })
			// Fix: Assign to the 'token' variable declared above. This is line 677.
            token, err = tkn.SignedString([]byte(jwtSecret))
            if err != nil {
                log.Printf("Failed to create Discord JWT token for %s: %v", p.DiscordId, err)
                continue // Log error and continue, don't abort batch
            }
			// Fix: Use the 'token' variable. This is line 682.
            _, err = insertStmt.Exec(p.DiscordId, p.Username, token, p.DisplayName, p.PomeloName)
            if err != nil {
                log.Printf("Failed to store Discord token in database for %s: %v", p.DiscordId, err)
                continue // Log error and continue
            }
        } else {
            // Record exists, update username, display_name, and pomelo_name.
            // Bot sync provides the latest names.
            _, err = updateStmt.Exec(p.Username, p.DisplayName, p.PomeloName, p.DiscordId)
            if err != nil {
                log.Printf("Failed to update discord_auth for %s: %v", p.DiscordId, err)
                // Log error and continue processing next payload.
                continue
            }
             // log.Printf("Bot sync updated user: %s (%s)", p.DiscordId, p.Username) // Optional: Log updates
        }
		// Fix: Increment processedCount for both new inserts and updates.
        processedCount++
	}

	// Commit the transaction.
	if err := tx.Commit(); err != nil {
		log.Printf("Failed to commit transaction: %v", err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	log.Printf("Discord auth chunk processed %d entries successfully from %s", processedCount, c.ClientIP())
	c.JSON(http.StatusOK, gin.H{"status": "processed", "count": processedCount})
}

// HandleDiscordDelete deletes a Discord auth record (from a bot).
// Endpoint: DELETE /discord-auth
// Authentication: Bearer <MS_TOKEN>
// Body: { "discord_id": "..." }
// Response: 200 or 404 or 500
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
	// Check master server token.
	var msToken string
	if auth := c.GetHeader("Authorization"); auth != "" {
		if strings.HasPrefix(auth, "Bearer ") {
			msToken = strings.TrimPrefix(auth, "Bearer ")
			log.Printf("Master server token received (delete) from %s", c.ClientIP())
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

    // Use a transaction even for a single delete for atomicity (optional but good practice)
    tx, err := ms.db.Begin()
    if err != nil {
        log.Printf("Failed to start delete transaction: %v", err)
        c.AbortWithStatus(http.StatusInternalServerError)
        return
    }
    defer tx.Rollback()

	result, err := tx.Exec("DELETE FROM discord_auth WHERE discord_id = ?", payload.DiscordId)
	if err != nil {
		log.Printf("Failed to delete Discord auth record for %s (from %s): %v", payload.DiscordId, c.ClientIP(), err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

    rowsAffected, err := result.RowsAffected()
    if err != nil {
        log.Printf("Failed to get rows affected for deletion of %s (from %s): %v", payload.DiscordId, c.ClientIP(), err)
         // Log but continue, delete might have succeeded
    }

	if rowsAffected > 0 {
	    log.Printf("Deleted Discord auth record for %s (from %s).", payload.DiscordId, c.ClientIP())
        if err := tx.Commit(); err != nil {
             log.Printf("Failed to commit delete transaction for %s: %v", payload.DiscordId, err)
             c.AbortWithStatus(http.StatusInternalServerError)
             return
        }
        c.Status(http.StatusOK)
    } else {
        log.Printf("Attempted to delete non-existent Discord auth record for %s (from %s).", payload.DiscordId, c.ClientIP())
        if err := tx.Commit(); err != nil { // Still commit even if no rows affected
             log.Printf("Failed to commit delete transaction (no rows affected) for %s: %v", payload.DiscordId, err)
             c.AbortWithStatus(http.StatusInternalServerError)
             return
        }
        c.Status(http.StatusNotFound) // Indicate it wasn't found
    }
}

// HandleDiscordClientAuth processes a Discord auth payload from a client (e.g., the game client).
// This endpoint's purpose is unclear from the C++ snippets provided, but assuming it's an internal/bot endpoint for single adds/updates.
// Endpoint: POST /discord-auth (or maybe /discord-auth-single?)
// Authentication: Bearer <MS_TOKEN> (Assumption based on payload structure similar to chunk)
// Body: { "discord_id": "...", "username": "...", "display_name": "...", "pomelo_name": "..." }
// Response: { "token": "permanent_master_auth_token" } or error
// NOTE: Renaming this endpoint to /discord-auth-single might be less confusing if its purpose is single bot sync.
// The current path POST /discord-auth conflicts semantically with GET /discord-auth for OAuth.
// Let's assume the POST /discord-auth endpoint is intended for bot sync of a single user.
func (ms *MasterServer) HandleDiscordClientAuth(c *gin.Context) {
	var payload DiscordAuthPayload
	if err := c.ShouldBindJSON(&payload); err != nil {
		log.Printf("Invalid Discord auth payload from %s: %v", c.ClientIP(), err)
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
	// Require DiscordId and Username for any sync/add operation
	if payload.DiscordId == "" || payload.Username == "" {
		log.Printf("Missing DiscordId or Username in payload from %s", c.ClientIP())
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

    // Check master server token - ASSUMPTION: This is a bot/internal endpoint
	var msToken string
	if auth := c.GetHeader("Authorization"); auth != "" {
		if strings.HasPrefix(auth, "Bearer ") {
			msToken = strings.TrimPrefix(auth, "Bearer ")
			log.Printf("Master server token received (single sync) from %s", c.ClientIP())
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

	log.Printf("Discord single auth payload received from %s: %+v", c.ClientIP(), payload)

	// Load Discord JWT secret from env (for generating permanent tokens).
	jwtSecret := os.Getenv("JWT_DISCORD_SECRET")
	if jwtSecret == "" {
		log.Fatalf("JWT_DISCORD_SECRET not set") // Critical error
        c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Server configuration error"})
        return
	}

	// Check for existing token.
	var token string
	err := ms.db.QueryRow("SELECT token FROM discord_auth WHERE discord_id = ?", payload.DiscordId).Scan(&token)

	if err != nil {
		if err == sql.ErrNoRows {
			// Record does not exist, create a new one.
            log.Printf("Single sync registering new user: %s (%s)", payload.DiscordId, payload.Username)
			tkn := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
				"discord_id":   payload.DiscordId,
				"username":     payload.Username,
				"display_name": payload.DisplayName,
				"pomelo_name":  payload.PomeloName,
				// Permanent token doesn't expire
			})
			token, err = tkn.SignedString([]byte(jwtSecret))
			if err != nil {
				log.Printf("Failed to create Discord JWT token for %s: %v", payload.DiscordId, err)
				c.AbortWithStatus(http.StatusInternalServerError)
				return
			}
            // Insert username, display_name, and pomelo_name
			_, err = ms.db.Exec("INSERT INTO discord_auth (discord_id, username, token, display_name, pomelo_name) VALUES (?, ?, ?, ?, ?)",
				payload.DiscordId, payload.Username, token, payload.DisplayName, payload.PomeloName)
			if err != nil {
				log.Printf("Failed to store Discord token in database for %s: %v", payload.DiscordId, err)
				c.AbortWithStatus(http.StatusInternalServerError)
				return
			}
		} else {
			log.Printf("Database error querying discord_auth for %s: %v", payload.DiscordId, err)
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
	} else {
		// Record exists, update username, display_name, and pomelo_name.
        // This assumes the single sync also sends the latest names.
		_, err = ms.db.Exec("UPDATE discord_auth SET username = ?, display_name = ?, pomelo_name = ? WHERE discord_id = ?",
			payload.Username, payload.DisplayName, payload.PomeloName, payload.DiscordId)
		if err != nil {
			log.Printf("Failed to update Discord auth record for %s: %v", payload.DiscordId, err)
			// Log error but continue, client (bot) still gets the existing token
		} else {
            // log.Printf("Single sync updated user: %s", payload.DiscordId) // Optional: Log update
        }
	}

    // Return the permanent token.
	c.JSON(http.StatusOK, gin.H{"token": token})
}


// HandleHeartbeat processes a heartbeat from a game server.
// Endpoint: POST /heartbeat
// Authentication: None required initially, validation happens via UDP challenge
// Body: { "host_name": "...", "map_name": "...", ... }
func (ms *MasterServer) HandleHeartbeat(c *gin.Context) {
	var heartbeat struct {
		HostName   string       `json:"host_name"`
		MapName    string       `json:"map_name"`
		GameMode   string       `json:"game_mode"`
		MaxPlayers int          `json:"max_players"`
		Version    string 	    `json:"version"`
		Description string      `json:"description"`
		Playlist   string       `json:"playlist"`
		PlaylistDisplayName string `json:"playlist_display_name"`
		Port       int          `json:"port"`
		HasPassword bool        `json:"has_password"`
		Players    []PlayerInfo `json:"players"` // Array of players
        // TotalPlayers field is computed from len(Players)
	}
	if err := c.ShouldBindJSON(&heartbeat); err != nil {
		log.Printf("Invalid heartbeat format from %s: %v", c.ClientIP(), err)
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

    // Get the client IP (this is the server's public IP from the master server's perspective)
	ip := c.ClientIP()

	// Validate port.
	if heartbeat.Port <= 1024 || heartbeat.Port > 65535 {
		log.Printf("Invalid port number %d in heartbeat from %s:%d", heartbeat.Port, ip, heartbeat.Port)
		c.String(http.StatusBadRequest, "Invalid port number (must be 1025-65535)")
		c.Abort()
		return
	}

	// Sanitize hostname
	hostname := heartbeat.HostName
	if len(hostname) > 64 {
	    hostname = hostname[:64]
	}
	// Replace any potentially problematic characters
	hostname = strings.Map(func(r rune) rune {
	    // Keep letters, numbers, spaces, and some common punctuation. Remove others.
        // Added ' ' back, removed square brackets as they are used for region.
	    if unicode.IsLetter(r) || unicode.IsDigit(r) || unicode.IsSpace(r) || strings.ContainsRune("!@#$%^&*()-_+=.,?", r) {
            return r
        }
	    return '_' // Replace disallowed characters with underscore
	}, hostname)
	// Trim leading/trailing underscores or spaces that might result from sanitization
    hostname = strings.Trim(hostname, "_ ")

	if len(hostname) < 3 { // After sanitization
	    hostname = "Unnamed R1Delta Server"
	}
	heartbeat.HostName = hostname


	// Disallow specific map names if needed
	if strings.Contains(heartbeat.MapName, "mp_npe") {
		log.Printf("Ignoring heartbeat from %s:%d on disallowed map '%s'", ip, heartbeat.Port, heartbeat.MapName)
		c.Status(http.StatusOK) // Indicate successful processing, but server won't be listed
		return
	}

	// Validate map name.
	if heartbeat.MapName == "" || len(heartbeat.MapName) > 32 || !isValidMapName(heartbeat.MapName)  {
		log.Printf("Invalid map name %q from %s:%d", heartbeat.MapName, ip, heartbeat.Port)
		c.String(http.StatusBadRequest, "Invalid map name format (lowercase letters, numbers, underscores only)")
		c.Abort()
		return
	}

	// Validate game mode.
	if heartbeat.GameMode == "" || len(heartbeat.GameMode) > 32 || !isValidGameMode(heartbeat.GameMode) {
		log.Printf("Invalid game mode %q from %s:%d", heartbeat.GameMode, ip, heartbeat.Port)
		c.String(http.StatusBadRequest, "Invalid game mode format (lowercase letters, numbers, underscores only)")
		c.Abort()
		return
	}

    // Validate max players. <-- Added back
 	if heartbeat.MaxPlayers <= 1 || heartbeat.MaxPlayers > 128 { // Assuming reasonable max players, e.g., up to 128
 		log.Printf("Invalid max players %d from %s:%d", heartbeat.MaxPlayers, ip, heartbeat.Port)
 		c.String(http.StatusBadRequest, "Invalid max players (must be 2-128)") // Adjust range as needed
 		c.Abort()
 		return
 	}

    // Validate player count doesn't exceed max players. <-- Added back
    // Note: It's TotalPlayers that matters for the list, derived from len(Players).
    // The validation should use len(heartbeat.Players).
 	if len(heartbeat.Players) > heartbeat.MaxPlayers {
 	    log.Printf("Too many players (%d) vs max players (%d) from %s:%d", len(heartbeat.Players), heartbeat.MaxPlayers, ip, heartbeat.Port)
 	    c.String(http.StatusBadRequest, "Player count exceeds max players")
 	    c.Abort()
 	    return
 	}


	// ---------- REGION-PREFIX LOGIC ----------
	var regionCode string
	// Parse the IP and check for errors
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		log.Printf("Invalid IP address parsed from c.ClientIP() for heartbeat: %s", ip)
		regionCode = RegionUNK // Treat as unknown if IP is invalid
	} else if parsedIP.IsLoopback() || parsedIP.IsPrivate() {
		regionCode = RegionLOC // Mark as local if it's a private/loopback IP
	} else if ms.geoip != nil {
		rec, geoipErr := ms.geoip.City(parsedIP) // Use a specific error variable for geoip
		if geoipErr != nil {
			log.Printf("GeoIP lookup failed for %s: %v", ip, geoipErr) // Use specific error variable
			regionCode = RegionUNK // Treat as unknown if GeoIP fails
		} else {
			regionCode = determineRegionCode(rec) // Determine region from GeoIP record
		}
	} else {
        // GeoIP database not loaded (should be fatal, but handle defensively)
        // Logged at startup if failed. Just assign UNK.
        regionCode = RegionUNK
    }

	// strip any old [[XXXXX]] prefix then prepend new one
	cleanName := stripPrefix.ReplaceAllString(heartbeat.HostName, "")
	cleanName = strings.TrimSpace(cleanName)
	// Ensure there's a space between region code and name only if there's a name
	if cleanName == "" {
		heartbeat.HostName = regionCode // Just the region code if no original name
	} else {
		heartbeat.HostName = fmt.Sprintf("%s %s", regionCode, cleanName)
	}
	// ---------- END REGION-PREFIX LOGIC ----------

	key := fmt.Sprintf("%s:%d", ip, heartbeat.Port) // Key is IP:Port

	ms.serversMu.Lock()
	defer ms.serversMu.Unlock()

	// Retrieve existing server entry if it exists to preserve validation status.
	existingEntry, serverExists := ms.servers[key]

	// Limit maximum servers per IP to 5.
	if !serverExists {
		count := 0
		for _, s := range ms.servers {
			// Only count servers from the same IP.
			if s.IP == ip { // Compare against the derived IP from c.ClientIP()
				count++
			}
		}
		if count >= 5 {
			log.Printf("Too many servers (%d) for IP %s from %s", count, ip, c.ClientIP())
			c.String(http.StatusBadRequest, "Maximum 5 servers per IP")
			c.Abort()
			return
		}
	}

    // Create or update the server entry
	entry := &ServerEntry{
		HostName:    heartbeat.HostName,
		MapName:     heartbeat.MapName,
		GameMode:    heartbeat.GameMode,
		MaxPlayers:  heartbeat.MaxPlayers,
		HasPassword: heartbeat.HasPassword,
		Description: heartbeat.Description,
		Playlist:   heartbeat.Playlist,
		TotalPlayers: len(heartbeat.Players), // Calculate TotalPlayers from len(Players)
		Version:     heartbeat.Version, // Store Version
		PlaylistDisplayName: heartbeat.PlaylistDisplayName,
		IP:          ip, // Store the derived IP
		Port:        heartbeat.Port,
		Players:     heartbeat.Players, // Store the player list
		LastUpdated: time.Now(),
		// Preserve existing validation status if server already exists, otherwise default to false.
        // If a server stops heartbeating and is removed, the next heartbeat is treated as new (Validated: false).
		Validated:   serverExists && existingEntry.Validated,
	}

    // Store/update the server entry
    ms.servers[key] = entry
    log.Printf("Received heartbeat from %s:%d (Hostname: %s, Players: %d/%d, Validated: %t)",
        ip, heartbeat.Port, entry.HostName, entry.TotalPlayers, entry.MaxPlayers, entry.Validated)


	// Trigger validation if needed.
    // Only re-validate if it's a new entry, or if it was previously unvalidated,
    // or if the last challenge attempt was more than ChallengeInterval ago.
    // Avoid challenging on *every* heartbeat if the server is already validated.
    const ChallengeInterval = 5 * time.Minute // How often to re-validate a validated server

    ms.challengeMu.Lock()
    lastChallengeTime, challengeAttemptedRecently := ms.challenges[key]
    ms.challengeMu.Unlock()

    // Decide if we need to challenge:
    // 1. Server is new (not in map before this heartbeat).
    // 2. Server exists but is not currently validated.
    // 3. Server exists, is validated, but it's been a while since the last challenge attempt.
    needsChallenge := !serverExists ||
                      !entry.Validated ||
                      (entry.Validated && !challengeAttemptedRecently) || // Challenge if validated but no challenge record? (Shouldn't happen if challengeAttemptedRecently is true whenever a challenge is initiated)
                      (entry.Validated && challengeAttemptedRecently && time.Since(lastChallengeTime) > ChallengeInterval)


    if needsChallenge {
        log.Printf("Triggering validation for %s:%d (New: %t, Validated: %t, Last Challenge: %v)",
            ip, heartbeat.Port, !serverExists, entry.Validated, lastChallengeTime)
        // Mark challenge attempt time *before* starting the goroutine
        ms.challengeMu.Lock()
        ms.challenges[key] = time.Now()
        ms.challengeMu.Unlock()
        go ms.PerformValidation(ip, heartbeat.Port) // Use the derived IP
    } else {
        //log.Printf("Validation not needed for %s:%d (Validated: %t, Last Challenge: %v)",
        //    ip, heartbeat.Port, entry.Validated, lastChallengeTime)
    }


	c.Status(http.StatusOK)
}

// PerformValidation sends a UDP challenge to the server and marks it validated on success.
func (ms *MasterServer) PerformValidation(ip string, port int) {
	key := fmt.Sprintf("%s:%d", ip, port) // Use IP:Port as key
	log.Printf("[Validation] Starting validation for %s", key) // Log key

    // Check if the server entry still exists in the map. It might have been removed by cleanup.
    ms.serversMu.RLock()
    _, exists := ms.servers[key]
    ms.serversMu.RUnlock()
    if !exists {
        log.Printf("[Validation] Server %s disappeared from map before validation could start.", key)
        return // Server removed, no need to validate
    }


	nonce := make([]byte, 4)
	if _, err := rand.Read(nonce); err != nil {
		log.Printf("[Validation] Failed to generate nonce for %s: %v", key, err)
		// Don't mark as unvalidated for internal master server error
		return
	}
	nonceStr := "0x" + hex.EncodeToString(nonce)

	addr := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("udp", addr, 2*time.Second) // Use a short timeout
	if err != nil {
		log.Printf("[Validation] Connection failed to %s: %v", key, err)
		// Mark server as unvalidated due to connection failure
		ms.serversMu.Lock()
        if server, exists := ms.servers[key]; exists { // Re-check existence
             server.Validated = false // Mark as not validated
             log.Printf("[Validation] Marked %s as unvalidated due to connection failure", key)
        }
		ms.serversMu.Unlock()
		return
	}
	defer conn.Close()

	// Construct challenge packet.
	// FF FF FF FF 48 63 6F 6E 6E 65 63 74 <nonce 10 bytes including 0x> 00
	// FF FF FF FF  H  c  o  n  n  e  c  t <nonce> 00
	// Total length = 4 + 1 + 7 + 10 + 1 = 23 bytes
	challengePacket := make([]byte, 23)
	copy(challengePacket[0:4], []byte{0xFF, 0xFF, 0xFF, 0xFF}) // Header
	challengePacket[4] = 0x48 // S2C_CHALLENGE (This seems correct based on Half-Life/Source protocol variants)
	copy(challengePacket[5:12], "connect") // Command string
	copy(challengePacket[12:22], nonceStr) // Nonce (10 bytes including 0x)
	challengePacket[22] = 0x00 // Null terminator

	log.Printf("[Validation] Sending challenge to %s (nonce: %s)", key, nonceStr)
	conn.SetDeadline(time.Now().Add(3 * time.Second)) // Increase deadline slightly for read/write combined
	if _, err := conn.Write(challengePacket); err != nil {
		log.Printf("[Validation] Failed to send challenge to %s: %v", key, err)
		// Mark server as unvalidated due to write failure
        ms.serversMu.Lock()
        if server, exists := ms.servers[key]; exists { // Re-check existence
             server.Validated = false
             log.Printf("[Validation] Marked %s as unvalidated due to write failure", key)
        }
        ms.serversMu.Unlock()
		return
	}

	respBuf := make([]byte, 1024) // Use a reasonable buffer size
    // The read deadline is set by conn.SetDeadline above
	n, err := conn.Read(respBuf)
	if err != nil {
		// Timeout or other read error
		log.Printf("[Validation] Failed to read response from %s: %v", key, err)
		// Server failed validation (no response or error)
		ms.serversMu.Lock()
        if server, exists := ms.servers[key]; exists { // Re-check existence
             server.Validated = false // Mark as not validated
             log.Printf("[Validation] Marked %s as unvalidated due to read error", key)
        }
		ms.serversMu.Unlock()
		return
	}
	if n < 26 { // Minimum expected response length based on validateResponse logic
		log.Printf("[Validation] Short response (%d bytes) from %s", n, key)
		ms.serversMu.Lock()
        if server, exists := ms.servers[key]; exists { // Re-check existence
             server.Validated = false // Mark as not validated
             log.Printf("[Validation] Marked %s as unvalidated due to short response", key)
        }
		ms.serversMu.Unlock()
		return
	}

	log.Printf("[Validation] Received %d bytes from %s", n, key)

	// validateResponse checks structure and nonce. It also logs internal failures.
	if !validateResponse(respBuf[:n], nonceStr) {
		log.Printf("[Validation] Validation failed for %s", key)
		// Mark server as not validated
		ms.serversMu.Lock()
		if server, exists := ms.servers[key]; exists { // Re-check existence
			server.Validated = false
			log.Printf("[Validation] Marked %s as unvalidated due to validation mismatch", key)
		}
		ms.serversMu.Unlock()
		return
	}

	// Mark the server as validated on success.
	ms.serversMu.Lock()
	defer ms.serversMu.Unlock() // Ensure lock is released after the update

	if server, exists := ms.servers[key]; exists { // Re-check existence one last time
		if !server.Validated {
            log.Printf("[Validation] Successfully validated %s (%s)", key, server.HostName)
        } // No need to log if it was already validated
		server.Validated = true
	} else {
        // This case is unexpected if heartbeat always adds/updates.
        // It might happen if the server was removed by cleanup just before this line executes.
        log.Printf("[Validation] Server %s not found in map after successful validation attempt?", key)
    }
}

// validateResponse checks that the challenge response is correct.
// Expected format (assuming S2C_CONNECTION response to S2C_CHALLENGE):
// FF FF FF FF 49 <some_bytes_before_connect> connect <our_nonce> ...
// Based on typical protocols, <some_bytes_before_connect> might be 4 bytes (challenge number)
// Our S2C_CHALLENGE packet was FF FF FF FF 48 "connect" <nonce> 00
// Server's expected response based on C++ code seems to check at index 9 for "connect" and index 16 for nonce.
// This implies: FF FF FF FF 49 <4 bytes: server's challenge number> connect <10 bytes: our nonce>
// Total length up to end of nonce = 5 (header+cmd) + 4 (challenge) + 7 ("connect") + 10 (nonce) = 26 bytes.
func validateResponse(resp []byte, nonce string) bool {
	if len(resp) < 26 { // Need at least header (5) + challenge (4) + connect (7) + nonce (10)
		log.Printf("[Validation] Response too short: %d bytes", len(resp))
		return false
	}
	// Check header and command byte
	// Command byte for S2C_CONNECTION response is typically 0x49 (73)
	headerValid := resp[0] == 0xFF && resp[1] == 0xFF && resp[2] == 0xFF && resp[3] == 0xFF && resp[4] == 0x49
	if !headerValid {
		log.Printf("[Validation] Invalid header/command (expected FF FF FF FF 49) in response: %X", resp[:5])
		return false
	}

    // Check for "connect" string - Assuming it starts at index 9
	connectStr := string(resp[9:16]) // Index 9 to 15 (7 bytes)
	if connectStr != "connect" {
		log.Printf("[Validation] Expected 'connect' at index 9-15, got %q", connectStr)
		return false
	}

    // Check for the returned nonce - Assuming it starts at index 16
	responseNonce := string(resp[16:26]) // Index 16 to 25 (10 bytes)
	if responseNonce != nonce {
		log.Printf("[Validation] Nonce mismatch: expected %q, got %q", nonce, responseNonce)
		return false
	}

	// Basic checks passed
	return true
}

// GetServers returns the list of currently validated servers.
// Endpoint: GET /servers
// Authentication: None required
// Response: JSON array of ServerEntry objects
func (ms *MasterServer) GetServers(c *gin.Context) {
	ms.serversMu.RLock()
	defer ms.serversMu.RUnlock()
	validServers := make([]*ServerEntry, 0)
	cutoff := time.Now().Add(-90 * time.Second) // Match cleanup interval

	for _, s := range ms.servers {
		// Server must be validated AND recently updated
		if s.Validated && s.LastUpdated.After(cutoff) {
			validServers = append(validServers, s)
		}
	}

	c.JSON(http.StatusOK, validServers)
}

// GetPlayerCount returns the total player count across all validated servers.
// Endpoint: GET /players
// Authentication: None required
// Response: JSON integer (total player count)
func (ms *MasterServer) GetPlayerCount(c *gin.Context) {
	ms.serversMu.RLock()
	defer ms.serversMu.RUnlock()
	var playerCount = 0
	cutoff := time.Now().Add(-90 * time.Second) // Match cleanup interval consistency
	for _, s := range ms.servers {
		// Only count players from validated AND recently updated servers
		if s.Validated && s.LastUpdated.After(cutoff) {
			playerCount += s.TotalPlayers
		}
	}
	// Just return the integer count as JSON
	c.JSON(http.StatusOK, playerCount)
}

// CleanupOldEntries periodically removes stale server entries.
func (ms *MasterServer) CleanupOldEntries() {
	ticker := time.NewTicker(30 * time.Second) // Check every 30 seconds
	defer ticker.Stop()
	for range ticker.C {
		ms.serversMu.Lock()
        keysToDelete := []string{}
		for k, s := range ms.servers {
            // Remove server if it hasn't sent a heartbeat in 90 seconds
			if time.Since(s.LastUpdated) > 90*time.Second {
				log.Printf("[Cleanup] Removing server %s (%s), last updated %v ago, validated=%v",
					s.HostName, k, time.Since(s.LastUpdated), s.Validated)
                keysToDelete = append(keysToDelete, k)
			}
		}
        for _, k := range keysToDelete {
            delete(ms.servers, k)
            // Also remove associated challenge and heartbeat entries
            ms.challengeMu.Lock()
            delete(ms.challenges, k)
            ms.challengeMu.Unlock()
             // lastHeartbeats map is not used anymore, removal was based on old logic.
        }
		ms.serversMu.Unlock()
        if len(keysToDelete) > 0 {
            log.Printf("[Cleanup] Removed %d old server entries.", len(keysToDelete))
        }
	}
}

// fetchCloudflareIPs retrieves Cloudflare proxy IP ranges.
// Used to configure Gin's trusted proxies.
func fetchCloudflareIPs() ([]string, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get("https://www.cloudflare.com/ips-v4")
	if err != nil {
		return nil, fmt.Errorf("failed to fetch Cloudflare IPs: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code from Cloudflare IPs endpoint: %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read Cloudflare IPs: %v", err)
	}
	ips := strings.Split(strings.TrimSpace(string(body)), "\n")
	if len(ips) == 0 {
		return nil, fmt.Errorf("empty Cloudflare IP list received")
	}
    log.Printf("Fetched %d Cloudflare IPv4 ranges.", len(ips))

    // Also fetch IPv6 ranges if needed
    respV6, err := client.Get("https://www.cloudflare.com/ips-v6")
    if err != nil {
        log.Printf("Warning: Failed to fetch Cloudflare IPv6 IPs: %v", err)
        // Continue with only IPv4 if IPv6 fails
        return ips, nil
    }
    defer respV6.Body.Close()
    if respV6.StatusCode != http.StatusOK {
        log.Printf("Warning: Unexpected status code from Cloudflare IPs (v6) endpoint: %d", respV6.StatusCode)
         return ips, nil // Continue with only IPv4
    }
    bodyV6, err := io.ReadAll(respV6.Body)
    if err != nil {
        log.Printf("Warning: Failed to read Cloudflare IPv6 IPs: %v", err)
        return ips, nil // Continue with only IPv4
    }
    ipsV6 := strings.Split(strings.TrimSpace(string(bodyV6)), "\n")
     if len(ipsV6) > 0 {
        log.Printf("Fetched %d Cloudflare IPv6 ranges.", len(ipsV6))
        ips = append(ips, ipsV6...)
     }


	return ips, nil
}

// getPublicIP returns the public IP address by querying an external service.
// Not used in this code currently but potentially useful elsewhere.
// Kept for reference.
func getPublicIP() (string, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://eth0.me") // Example service
	if err != nil {
		return "", fmt.Errorf("failed to fetch public IP: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code from eth0.me: %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read public IP response: %v", err)
	}
	ip := strings.TrimSpace(string(body))
	if net.ParseIP(ip) == nil {
		return "", fmt.Errorf("invalid IP address received from eth0.me: %s", ip)
	}
	return ip, nil
}

// HandleDelete removes a server entry based on its port.
// Endpoint: DELETE /heartbeat/:port
// Authentication: Assumes clientIP == serverIP. Rate limited.
// Path Param: port (int)
// Response: 200 or 400 or 404 or 500
func (ms *MasterServer) HandleDelete(c *gin.Context) {
	portStr := c.Param("port")
    port, err := strconv.Atoi(portStr)
    if err != nil {
        log.Printf("Invalid port '%s' in delete request from %s: %v", portStr, c.ClientIP(), err)
        c.AbortWithStatus(http.StatusBadRequest)
        return
    }
    if port <= 1024 || port > 65535 {
        log.Printf("Invalid port number %d in delete request from %s", port, c.ClientIP())
        c.String(http.StatusBadRequest, "Invalid port number (must be 1025-65535)")
		c.Abort()
        return
    }

	clientIP := c.ClientIP() // Get IP of the client sending the request

	key := fmt.Sprintf("%s:%d", clientIP, port) // Key is IP:Port

	ms.serversMu.Lock()
	defer ms.serversMu.Unlock()

    if _, exists := ms.servers[key]; !exists {
         log.Printf("Attempted to delete non-existent server: %s (from %s)", key, c.ClientIP())
         c.Status(http.StatusNotFound) // Indicate the server wasn't found
         return
    }

	delete(ms.servers, key)
    // Also clean up associated challenge and heartbeat entries
    ms.challengeMu.Lock()
    delete(ms.challenges, key)
    ms.challengeMu.Unlock()
    // lastHeartbeats map not used anymore

	log.Printf("Deleted server entry: %s (requested by %s)", key, c.ClientIP())
	c.Status(http.StatusOK)
}

// NewMasterServer creates and initializes a MasterServer instance.
func NewMasterServer() *MasterServer {
	return &MasterServer{
		servers:        make(map[string]*ServerEntry),
		challenges:     make(map[string]time.Time),
		// lastHeartbeats map is effectively replaced by ServerEntry.LastUpdated
		limiters:       make(map[string]*rate.Limiter),
        // DB and GeoIP are set after creation in main
	}
}

// LogRequestMiddleware logs basic request info.
func LogRequestMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        // c.ClientIP() already handles X-Forwarded-For/CF-Connecting-IP after trusted proxies are set.
        log.Printf("DEBUG: Received request: Method=%s Path=%s ClientIP=%s RemoteAddr=%s CF-Ray=%s",
            c.Request.Method,
            c.Request.URL.Path,
            c.ClientIP(), // Use ClientIP which respects trusted proxies
            c.Request.RemoteAddr, // IP Go sees directly (Cloudflare edge or direct)
            c.GetHeader("CF-Ray"),           // Cloudflare Ray ID
        )
        c.Next() // Continue processing
    }
}


func main() {
	// Load environment variables.
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found – using environment variables")
	}

	// Check essential environment variables EARLY.
    if os.Getenv("MS_TOKEN") == "" {
        log.Fatalf("MS_TOKEN environment variable not set! This token is required for internal/bot endpoints.")
    }
    if os.Getenv("JWT_DISCORD_SECRET") == "" {
        log.Fatalf("JWT_DISCORD_SECRET environment variable not set! This secret is required for signing permanent user tokens.")
    }
    if os.Getenv("JWT_PRIVATE_KEY_FILE") == "" {
         log.Fatalf("JWT_PRIVATE_KEY_FILE environment variable not set! This file path is required for loading the key to sign server tokens.")
    } else if _, err := os.Stat(os.Getenv("JWT_PRIVATE_KEY_FILE")); os.IsNotExist(err) {
         log.Fatalf("JWT_PRIVATE_KEY_FILE %q not found!", os.Getenv("JWT_PRIVATE_KEY_FILE"))
    }
     if os.Getenv("CLIENT_ID") == "" || os.Getenv("CLIENT_SECRET") == "" || os.Getenv("REDIRECT_URI") == "" {
         log.Fatalf("Discord OAuth environment variables (CLIENT_ID, CLIENT_SECRET, REDIRECT_URI) not set! These are required for the client OAuth flow.")
     }


	// Set Gin to release mode.
	gin.SetMode(gin.ReleaseMode)

	// Open SQLite database.
	db, err := sql.Open("sqlite3", "r1delta.db")
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

    // Create table if it doesn't exist
	sqlStmt := `CREATE TABLE IF NOT EXISTS discord_auth (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    discord_id TEXT NOT NULL UNIQUE,
    username TEXT NOT NULL, -- Discord's new username
    token TEXT NOT NULL UNIQUE, -- Permanent master server token (HS256)
    display_name TEXT, -- Discord's global display name
    pomelo_name TEXT, -- Discord's old username#discriminator format (if needed)
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);`
    _, err = db.Exec(sqlStmt)
    if err != nil {
        log.Fatalf("Failed to create discord_auth table: %v", err)
    }


	// Set WAL mode for better concurrency/performance with SQLite
	_, err = db.Exec("PRAGMA journal_mode = WAL;")
	if err != nil {
		log.Printf("Warning: Failed to set WAL mode: %v", err)
        // Not fatal, but log the issue
	} else {
        log.Println("Database journal_mode set to WAL.")
    }

	// Set connection limits for SQLite
    db.SetMaxOpenConns(10) // Adjust based on expected load
    db.SetMaxIdleConns(5)
    db.SetConnMaxLifetime(5 * time.Minute)
    log.Println("Database connection pool settings applied.")


	// --- GeoIP init ------------------------------------------------------
	dbPath := os.Getenv("GEOIP_DB_PATH")
	if dbPath == "" { dbPath = "GeoLite2-City.mmdb" }

	geoipRdr, err := geoip2.Open(dbPath)
	if err != nil {
        // Make GeoIP loading non-fatal, but log clearly that it failed.
		log.Printf("WARNING: Cannot open GeoIP DB %q: %v. Regional prefixes will not be available.", dbPath, err)
        geoipRdr = nil // Explicitly set to nil if it failed
	} else {
        log.Printf("GeoIP database loaded from %s", dbPath)
    }
	if geoipRdr != nil {
        defer geoipRdr.Close() // Close reader on program exit
    }
	// ---------------------------------------------------------------------


	// Fetch Cloudflare IP ranges.
	cfIPs, err := fetchCloudflareIPs()
	if err != nil {
		log.Printf("Warning: Failed to fetch Cloudflare IPs: %v. Using hardcoded fallback IPs.", err)
		// Hardcoded list might need updates over time. Using the fetched list is better.
		cfIPs = []string{
			"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
			"103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
			"190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
			"198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
			"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
            // Add IPv6 fallbacks if necessary
            "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
            "2405:b500::/32", "2405:8100::/48", "2a06:98c0::/29",
            "2c0f:f248::/32",
		}
        log.Printf("Using hardcoded fallback Cloudflare IPs (%d entries).", len(cfIPs))
	} else {
         log.Printf("Successfully fetched Cloudflare IPs (%d entries).", len(cfIPs))
    }


	// Initialize master server instance.
	ms := NewMasterServer()
	ms.db    = db
	ms.geoip = geoipRdr // Assign the reader (can be nil if loading failed)

	// Start the cleanup goroutine.
	go ms.CleanupOldEntries()

	// Set up Gin.
	r := gin.New() // Use gin.New() to manually add middleware
    r.Use(gin.Logger()) // Add default logger middleware (logs basic request info)
    r.Use(gin.Recovery()) // Add default recovery middleware (catches panics)
    r.Use(LogRequestMiddleware()) // Add custom request logger (more detail)

	// Configure trusted proxies.
	// This is CRITICAL if running behind Cloudflare (or any proxy)
	// to get the real client IP from headers like CF-Connecting-IP.
	if len(cfIPs) > 0 {
        if err := r.SetTrustedProxies(cfIPs); err != nil {
            log.Fatalf("Failed to set trusted proxies: %v", err)
        } else {
            log.Println("Trusted proxies configured.")
        }
    } else {
         log.Println("No trusted proxies configured (empty list). ClientIP will use RemoteAddr.")
    }
     // Ensure the correct headers are prioritized for resolving the client IP
     r.RemoteIPHeaders = []string{"CF-Connecting-IP", "X-Forwarded-For", "X-Real-IP"}


	r.Use(ms.rateLimitMiddleware()) // Apply per-IP rate limiting AFTER trusted proxies are set

	// Set up routes.
	r.POST("/heartbeat", ms.HandleHeartbeat)
	r.DELETE("/heartbeat/:port", ms.HandleDelete) // Port is path parameter
	r.GET("/servers", ms.GetServers)
	r.GET("/players",ms.GetPlayerCount)

	// Discord/Auth endpoints
	r.GET("/discord-auth", ms.HandleDiscordAuth) // CLIENT OAuth2 callback handler (No MS_TOKEN)
	// Re-mapping POST /discord-auth to be a bot endpoint requiring MS_TOKEN,
	// similar to discord-auth-chunk but for a single user.
	r.POST("/discord-auth", ms.HandleDiscordClientAuth) // BOT/INTERNAL single user sync (Requires MS_TOKEN)
	r.POST("/discord-auth-chunk", ms.HandleDiscordAuthChunk) // BOT/INTERNAL bulk user sync (Requires MS_TOKEN)
	r.DELETE("/discord-auth", ms.HandleDiscordDelete) // BOT/INTERNAL delete user (Requires MS_TOKEN)
	r.GET("/user", ms.HandleUser) // CLIENT get user info by token (Requires permanent token)

	r.POST("/server-token", ms.HandlePerServerToken) // SERVER gets JWT using permanent token (Requires permanent token)

	r.Static("/files", "public") // Serve static files

	// Start server.
    port := os.Getenv("PORT")
    if port == "" {
        port = "80" // Default to 80
    }
    listenAddr := fmt.Sprintf(":%s", port)
    log.Printf("Starting server on %s...", listenAddr)
	if err := r.Run(listenAddr); err != nil {
		log.Fatalf("Failed to run server: %v", err)
	}
}
