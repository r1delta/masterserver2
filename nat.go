package main

// NAT traversal support for game servers that are not directly reachable.
//
// The master server acts as:
//   - a UDP rendezvous point: servers register their game socket's public
//     mapping ("R1NX" SRV_REGISTER) so the master can validate them through
//     that mapping and ask them to hole-punch towards connecting clients;
//   - a signalling channel for clients (POST /nat/connect) that want to
//     reach a server by any of its advertised transports;
//   - a Cloudflare TURN credential broker for servers that cannot be reached
//     directly (only when CF_TURN_KEY_ID / CF_TURN_API_TOKEN are configured).
//
// The wire format of the UDP control packets is shared with the game DLL
// (r1delta/p2p/p2p_protocol.h). All integers are big-endian.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
)

// ---------- Wire format ----------

const (
	natMagic   = "\xff\xff\xff\xffR1NX"
	natVersion = 1
	natHdrLen  = len(natMagic) + 2

	pktSrvRegister  = 0x01 // server -> master: token[16]
	pktRegisterAck  = 0x02 // master -> peer: observed ip[4] port[2] flags[1] (server ip[4] port[2] if flags&1)
	pktCliRegister  = 0x03 // client -> master: ticket[16]
	pktPunchRequest = 0x04 // master -> server: ticket[16] client ip[4] port[2] mac[16]
	pktPunch        = 0x05 // peer <-> peer: ticket[16] role[1]
	pktPing         = 0x06 // client -> server (any transport): probe[8] time[8]
	pktPong         = 0x07 // server -> client: probe[8] time[8] flags[1]
	pktPunchReqAck  = 0x08 // server -> master: ticket[16] client ip[4] port[2]

	ackFlagHasServer = 0x01
)

func natHeader(kind byte) []byte {
	b := make([]byte, 0, 64)
	b = append(b, natMagic...)
	b = append(b, natVersion, kind)
	return b
}

// parseNatPacket returns the packet type and payload if pkt is an R1NX packet.
func parseNatPacket(pkt []byte) (byte, []byte, bool) {
	if len(pkt) < natHdrLen || string(pkt[:len(natMagic)]) != natMagic {
		return 0, nil, false
	}
	if pkt[len(natMagic)] != natVersion {
		return 0, nil, false
	}
	return pkt[len(natMagic)+1], pkt[natHdrLen:], true
}

func appendAddr4(b []byte, ap netip.AddrPort) []byte {
	a4 := ap.Addr().Unmap().As4()
	b = append(b, a4[:]...)
	return binary.BigEndian.AppendUint16(b, ap.Port())
}

func readAddr4(b []byte) (netip.AddrPort, bool) {
	if len(b) < 6 {
		return netip.AddrPort{}, false
	}
	a := netip.AddrFrom4([4]byte{b[0], b[1], b[2], b[3]})
	return netip.AddrPortFrom(a, binary.BigEndian.Uint16(b[4:6])), true
}

func encodeRegisterAck(observed netip.AddrPort, server *netip.AddrPort) []byte {
	b := appendAddr4(natHeader(pktRegisterAck), observed)
	if server != nil && server.IsValid() {
		b = append(b, ackFlagHasServer)
		b = appendAddr4(b, *server)
	} else {
		b = append(b, 0)
	}
	return b
}

// encodePunchRequest authenticates the request with the server's
// registration token (HMAC-SHA256, truncated to 16 bytes) so a spoofed source
// address alone cannot make a game server punch at a third party.
func encodePunchRequest(ticket [16]byte, client netip.AddrPort, serverToken [16]byte) []byte {
	b := natHeader(pktPunchRequest)
	b = append(b, ticket[:]...)
	b = appendAddr4(b, client)
	mac := hmac.New(sha256.New, serverToken[:])
	mac.Write(b[natHdrLen:])
	return append(b, mac.Sum(nil)[:16]...)
}

// ---------- Advertised transports ----------

// Transports are the alternative ways a server can be reached, as advertised
// in its heartbeat and republished in /servers.
type Transports struct {
	EOS       *EOSTransport       `json:"eos,omitempty"`
	Iroh      *IrohTransport      `json:"iroh,omitempty"`
	Tailcat   *TailcatTransport   `json:"tailcat,omitempty"`
	Tailscale *TailscaleTransport `json:"tailscale,omitempty"`
	Turn      *TurnTransport      `json:"turn,omitempty"`
}

type EOSTransport struct {
	PUID string `json:"puid"`
}

type IrohTransport struct {
	ID    string   `json:"id"`
	Relay string   `json:"relay,omitempty"`
	Addrs []string `json:"addrs,omitempty"`
}

type TailcatTransport struct {
	Addr string `json:"addr"`
}

type TailscaleTransport struct {
	IPs []string `json:"ips"`
}

type TurnTransport struct {
	Relay string `json:"relay"`
}

// Reachability records which paths the master managed to validate the server
// through.
type Reachability struct {
	Direct bool `json:"direct"` // plain UDP to ip:port
	Punch  bool `json:"punch"`  // through the rendezvous-registered NAT mapping
	Turn   bool `json:"turn"`   // through the advertised TURN relay
}

// NatInfo is the "nat" object a server sends in its heartbeat.
type NatInfo struct {
	WantTurn     bool     `json:"want_turn"`
	LAN          []string `json:"lan"`
	UPnP         string   `json:"upnp"`
	UPnPExternal string   `json:"upnp_external"`
}

var (
	hexPUIDRe    = regexp.MustCompile(`^[0-9a-f]{32}$`)
	irohIDRe     = regexp.MustCompile(`^[0-9a-z]{52,64}$`)
	tailcatRe    = regexp.MustCompile(`^tc[A-Za-z0-9_-]{8,1000}$`)
	tailscaleV4  = netip.MustParsePrefix("100.64.0.0/10")
	tailscaleV6  = netip.MustParsePrefix("fd7a:115c:a1e0::/48")
	errBadAddr   = errors.New("bad address")
	maxListAddrs = 8
)

func parsePublicAddrPort(s string) (netip.AddrPort, error) {
	ap, err := netip.ParseAddrPort(strings.TrimSpace(s))
	if err != nil || ap.Port() == 0 {
		return netip.AddrPort{}, errBadAddr
	}
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), nil
}

// sanitizeTransports drops anything malformed so that /servers only ever
// republishes well-formed data. It never fails; bad entries are removed.
// heartbeatIP is the address the heartbeat came from; advertised iroh direct
// addresses must be on it so clients are never pointed at third parties.
func sanitizeTransports(t *Transports, heartbeatIP string) *Transports {
	if t == nil {
		return nil
	}
	out := &Transports{}
	any := false
	if t.EOS != nil {
		puid := strings.ToLower(strings.TrimSpace(t.EOS.PUID))
		if hexPUIDRe.MatchString(puid) {
			out.EOS = &EOSTransport{PUID: puid}
			any = true
		}
	}
	if t.Iroh != nil {
		id := strings.ToLower(strings.TrimSpace(t.Iroh.ID))
		if irohIDRe.MatchString(id) {
			it := &IrohTransport{ID: id}
			if u, err := url.Parse(t.Iroh.Relay); err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" && len(t.Iroh.Relay) <= 256 {
				it.Relay = u.String()
			}
			for _, a := range t.Iroh.Addrs {
				if len(it.Addrs) >= maxListAddrs {
					break
				}
				if ap, err := parsePublicAddrPort(a); err == nil && ap.Addr().String() == heartbeatIP {
					it.Addrs = append(it.Addrs, ap.String())
				}
			}
			out.Iroh = it
			any = true
		}
	}
	if t.Tailcat != nil {
		addr := strings.TrimSpace(t.Tailcat.Addr)
		if tailcatRe.MatchString(addr) {
			out.Tailcat = &TailcatTransport{Addr: addr}
			any = true
		}
	}
	if t.Tailscale != nil {
		ts := &TailscaleTransport{}
		for _, s := range t.Tailscale.IPs {
			if len(ts.IPs) >= 4 {
				break
			}
			a, err := netip.ParseAddr(strings.TrimSpace(s))
			if err != nil {
				continue
			}
			a = a.Unmap()
			if tailscaleV4.Contains(a) || tailscaleV6.Contains(a) {
				ts.IPs = append(ts.IPs, a.String())
			}
		}
		if len(ts.IPs) > 0 {
			out.Tailscale = ts
			any = true
		}
	}
	if t.Turn != nil {
		if ap, err := parsePublicAddrPort(t.Turn.Relay); err == nil && ap.Addr().Is4() && !ap.Addr().IsPrivate() && !ap.Addr().IsLoopback() {
			out.Turn = &TurnTransport{Relay: ap.String()}
			any = true
		}
	}
	if !any {
		return nil
	}
	return out
}

// sanitizeLAN keeps up to four private IPv4 host:port candidates.
func sanitizeLAN(in []string) []string {
	var out []string
	for _, s := range in {
		if len(out) >= 4 {
			break
		}
		ap, err := parsePublicAddrPort(s)
		if err != nil || !ap.Addr().Is4() || !ap.Addr().IsPrivate() {
			continue
		}
		out = append(out, ap.String())
	}
	return out
}

// ---------- Rendezvous service ----------

type punchTicket struct {
	id        [16]byte
	serverKey string
	httpIP    netip.Addr
	created   time.Time
	client    netip.AddrPort          // learned from CLI_REGISTER
	acked     map[netip.AddrPort]bool // punch requests the server confirmed, by client endpoint
}

type natServerState struct {
	token    [16]byte
	mapped   netip.AddrPort
	mappedAt time.Time
}

// Rendezvous owns the UDP rendezvous socket and the associated state. All of
// its maps are guarded by mu; it never takes MasterServer.serversMu while
// holding mu.
type Rendezvous struct {
	conn       *net.UDPConn
	publicAddr string // advertised "ip:port"

	mu       sync.Mutex
	byKey    map[string]*natServerState // server key -> state
	byToken  map[[16]byte]string        // token -> server key
	tickets  map[[16]byte]*punchTicket
	waiters  map[netip.AddrPort]chan []byte // pending validation replies
	onMapped func(serverKey string)         // called (without mu) when a server first registers
}

const (
	ticketTTL              = 30 * time.Second
	mappingTTL             = 60 * time.Second
	maxTicketsPerKey       = 64
	maxTicketsPerRequester = 8
)

func newRendezvous(conn *net.UDPConn, publicAddr string) *Rendezvous {
	return &Rendezvous{
		conn:       conn,
		publicAddr: publicAddr,
		byKey:      make(map[string]*natServerState),
		byToken:    make(map[[16]byte]string),
		tickets:    make(map[[16]byte]*punchTicket),
		waiters:    make(map[netip.AddrPort]chan []byte),
	}
}

// startRendezvous opens the UDP socket described by RENDEZVOUS_LISTEN
// (default ":37999") and figures out the address to advertise
// (RENDEZVOUS_PUBLIC_ADDR, or the discovered public IP + listen port).
// Returns nil when disabled or when the socket cannot be opened.
func startRendezvous() *Rendezvous {
	listen := os.Getenv("RENDEZVOUS_LISTEN")
	if listen == "" {
		listen = ":37999"
	}
	if strings.EqualFold(listen, "off") {
		log.Println("[NAT] Rendezvous disabled (RENDEZVOUS_LISTEN=off)")
		return nil
	}
	laddr, err := net.ResolveUDPAddr("udp4", listen)
	if err != nil {
		log.Printf("[NAT] Bad RENDEZVOUS_LISTEN %q: %v", listen, err)
		return nil
	}
	conn, err := net.ListenUDP("udp4", laddr)
	if err != nil {
		log.Printf("[NAT] Cannot open rendezvous socket on %s: %v", listen, err)
		return nil
	}
	public := os.Getenv("RENDEZVOUS_PUBLIC_ADDR")
	if public == "" {
		ip, err := getPublicIP()
		if err != nil {
			log.Printf("[NAT] Could not determine public IP for rendezvous (%v); set RENDEZVOUS_PUBLIC_ADDR", err)
			conn.Close()
			return nil
		}
		public = net.JoinHostPort(ip, strconv.Itoa(conn.LocalAddr().(*net.UDPAddr).Port))
	}
	rv := newRendezvous(conn, public)
	go rv.readLoop()
	go rv.gcLoop()
	log.Printf("[NAT] Rendezvous listening on %s, advertised as %s", conn.LocalAddr(), public)
	return rv
}

func (rv *Rendezvous) send(to netip.AddrPort, pkt []byte) {
	if _, err := rv.conn.WriteToUDPAddrPort(pkt, to); err != nil {
		log.Printf("[NAT] send to %s failed: %v", to, err)
	}
}

// TokenFor returns (creating if needed) the registration token of a server.
func (rv *Rendezvous) TokenFor(serverKey string) [16]byte {
	rv.mu.Lock()
	defer rv.mu.Unlock()
	st, ok := rv.byKey[serverKey]
	if !ok {
		st = &natServerState{}
		crand.Read(st.token[:])
		rv.byKey[serverKey] = st
		rv.byToken[st.token] = serverKey
	}
	return st.token
}

// Mapped returns the server's registered public mapping, if fresh.
func (rv *Rendezvous) Mapped(serverKey string) (netip.AddrPort, bool) {
	rv.mu.Lock()
	defer rv.mu.Unlock()
	st, ok := rv.byKey[serverKey]
	if !ok || !st.mapped.IsValid() || time.Since(st.mappedAt) > mappingTTL {
		return netip.AddrPort{}, false
	}
	return st.mapped, true
}

// Forget drops all state of a server (called when its entry is removed).
func (rv *Rendezvous) Forget(serverKey string) {
	rv.mu.Lock()
	defer rv.mu.Unlock()
	if st, ok := rv.byKey[serverKey]; ok {
		delete(rv.byToken, st.token)
		delete(rv.byKey, serverKey)
	}
	for id, t := range rv.tickets {
		if t.serverKey == serverKey {
			delete(rv.tickets, id)
		}
	}
}

// NewTicket creates a punch ticket for a client that wants to reach serverKey.
func (rv *Rendezvous) NewTicket(serverKey string, httpIP netip.Addr) ([16]byte, error) {
	rv.mu.Lock()
	defer rv.mu.Unlock()
	n, mine := 0, 0
	var oldest *punchTicket
	for _, t := range rv.tickets {
		if t.serverKey != serverKey {
			continue
		}
		n++
		if t.httpIP == httpIP.Unmap() {
			mine++
		}
		if oldest == nil || t.created.Before(oldest.created) {
			oldest = t
		}
	}
	if mine >= maxTicketsPerRequester {
		return [16]byte{}, errors.New("too many pending connection attempts")
	}
	// One requester flooding a server must not lock everyone else out:
	// evict the oldest ticket rather than refusing new ones.
	if n >= maxTicketsPerKey && oldest != nil {
		delete(rv.tickets, oldest.id)
	}
	t := &punchTicket{serverKey: serverKey, httpIP: httpIP.Unmap(), created: time.Now(), acked: map[netip.AddrPort]bool{}}
	crand.Read(t.id[:])
	rv.tickets[t.id] = t
	return t.id, nil
}

// pushPunchRequest asks the server (through its registered mapping) to punch
// towards / permit the client. It resends a few times until acknowledged.
func (rv *Rendezvous) pushPunchRequest(ticket [16]byte, client netip.AddrPort) {
	rv.mu.Lock()
	t, ok := rv.tickets[ticket]
	var token [16]byte
	if ok {
		if st := rv.byKey[t.serverKey]; st != nil {
			token = st.token
		}
	}
	rv.mu.Unlock()
	if !ok {
		return
	}
	pkt := encodePunchRequest(ticket, client, token)
	go func() {
		for _, delay := range []time.Duration{0, 250 * time.Millisecond, 500 * time.Millisecond, time.Second} {
			time.Sleep(delay)
			rv.mu.Lock()
			t, ok := rv.tickets[ticket]
			if !ok || t.acked[client] {
				rv.mu.Unlock()
				return
			}
			st := rv.byKey[t.serverKey]
			var mapped netip.AddrPort
			if st != nil && time.Since(st.mappedAt) <= mappingTTL {
				mapped = st.mapped
			}
			rv.mu.Unlock()
			if !mapped.IsValid() {
				return
			}
			rv.send(mapped, pkt)
		}
	}()
}

// Challenge sends pkt to addr from the rendezvous socket and waits for the
// first datagram coming back from exactly that address.
func (rv *Rendezvous) Challenge(addr netip.AddrPort, pkt []byte, timeout time.Duration) ([]byte, error) {
	ch := make(chan []byte, 1)
	rv.mu.Lock()
	if _, busy := rv.waiters[addr]; busy {
		rv.mu.Unlock()
		return nil, errors.New("validation already in flight")
	}
	rv.waiters[addr] = ch
	rv.mu.Unlock()
	defer func() {
		rv.mu.Lock()
		delete(rv.waiters, addr)
		rv.mu.Unlock()
	}()

	deadline := time.After(timeout)
	resend := time.NewTicker(time.Second)
	defer resend.Stop()
	rv.send(addr, pkt)
	for {
		select {
		case resp := <-ch:
			return resp, nil
		case <-resend.C:
			rv.send(addr, pkt)
		case <-deadline:
			return nil, errors.New("timeout")
		}
	}
}

func (rv *Rendezvous) readLoop() {
	buf := make([]byte, 2048)
	for {
		n, from, err := rv.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("[NAT] rendezvous read error: %v", err)
			time.Sleep(10 * time.Millisecond)
			continue
		}
		from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
		pkt := append([]byte(nil), buf[:n]...)
		rv.handle(from, pkt)
	}
}

func (rv *Rendezvous) handle(from netip.AddrPort, pkt []byte) {
	rv.mu.Lock()
	if ch, ok := rv.waiters[from]; ok {
		if _, _, isNat := parseNatPacket(pkt); !isNat {
			select {
			case ch <- pkt:
			default:
			}
			rv.mu.Unlock()
			return
		}
	}
	rv.mu.Unlock()

	kind, payload, ok := parseNatPacket(pkt)
	if !ok || !from.Addr().Is4() {
		return
	}
	switch kind {
	case pktSrvRegister:
		if len(payload) < 16 {
			return
		}
		var token [16]byte
		copy(token[:], payload[:16])
		rv.mu.Lock()
		key, known := rv.byToken[token]
		// The mapping must belong to the host that sent the heartbeats, or a
		// leaked token could point clients (and validation) anywhere.
		if known && serverHost(key) != from.Addr().String() {
			known = false
		}
		first := false
		if known {
			st := rv.byKey[key]
			first = !st.mapped.IsValid() || st.mapped != from
			st.mapped = from
			st.mappedAt = time.Now()
		}
		cb := rv.onMapped
		rv.mu.Unlock()
		if !known {
			return
		}
		rv.send(from, encodeRegisterAck(from, nil))
		if first {
			log.Printf("[NAT] Server %s registered mapping %s", key, from)
			if cb != nil {
				go cb(key)
			}
		}

	case pktCliRegister:
		if len(payload) < 16 {
			return
		}
		var id [16]byte
		copy(id[:], payload[:16])
		rv.mu.Lock()
		t, ok := rv.tickets[id]
		if !ok || time.Since(t.created) > ticketTTL {
			rv.mu.Unlock()
			return
		}
		// Only accept the UDP endpoint if it comes from the same public IP
		// that requested the ticket over HTTP; this stops a ticket being used
		// to point a server's punch packets at a third party.
		if !t.httpIP.Is4() || t.httpIP != from.Addr() {
			rv.mu.Unlock()
			return
		}
		changed := t.client != from
		t.client = from
		var server *netip.AddrPort
		if st := rv.byKey[t.serverKey]; st != nil && st.mapped.IsValid() && time.Since(st.mappedAt) <= mappingTTL {
			m := st.mapped
			server = &m
		}
		rv.mu.Unlock()
		rv.send(from, encodeRegisterAck(from, server))
		if changed {
			rv.pushPunchRequest(id, from)
		}

	case pktPunchReqAck:
		if len(payload) < 22 {
			return
		}
		var id [16]byte
		copy(id[:], payload[:16])
		// The ack names the client endpoint it answers, so a late ack for
		// an earlier (e.g. permission-only) request cannot cancel the
		// resends of a newer one.
		acked, _ := readAddr4(payload[16:])
		rv.mu.Lock()
		if t, ok := rv.tickets[id]; ok {
			if st := rv.byKey[t.serverKey]; st != nil && st.mapped == from {
				t.acked[acked] = true
			}
		}
		rv.mu.Unlock()
	}
}

func (rv *Rendezvous) gcLoop() {
	for range time.Tick(10 * time.Second) {
		rv.mu.Lock()
		for id, t := range rv.tickets {
			if time.Since(t.created) > ticketTTL {
				delete(rv.tickets, id)
			}
		}
		rv.mu.Unlock()
	}
}

// ---------- Cloudflare TURN credentials ----------

type TurnCredentials struct {
	URLs       []string `json:"urls"`
	Username   string   `json:"username"`
	Credential string   `json:"credential"`
	Expires    int64    `json:"expires"`
}

type TurnBroker struct {
	keyID          string
	apiToken       string
	ttl            time.Duration
	endpoint       string // overridable for tests
	revokeEndpoint string // format: key id, username; "" disables revocation
	client         *http.Client

	mu        sync.Mutex
	cache     map[string]*TurnCredentials // server key -> creds
	mintTimes []time.Time                 // global mint rate limiting
}

const (
	turnMintsPerMinute = 60
	// A host may have several servers, but TURN credentials are relay
	// bandwidth we pay for: cap how many distinct servers per IP get them.
	turnServersPerIP = 3
)

func newTurnBrokerFromEnv() *TurnBroker {
	keyID := os.Getenv("CF_TURN_KEY_ID")
	token := os.Getenv("CF_TURN_API_TOKEN")
	if keyID == "" || token == "" {
		log.Println("[NAT] Cloudflare TURN not configured (CF_TURN_KEY_ID / CF_TURN_API_TOKEN); TURN relay disabled")
		return nil
	}
	ttl := 12 * time.Hour
	if s := os.Getenv("CF_TURN_TTL"); s != "" {
		if secs, err := strconv.Atoi(s); err == nil && secs >= 600 {
			ttl = time.Duration(secs) * time.Second
		}
	}
	// CF_TURN_API_URL overrides the credential endpoint (a format string
	// taking the key id), e.g. for a self-hosted TURN credential service.
	endpoint := os.Getenv("CF_TURN_API_URL")
	revokeEndpoint := os.Getenv("CF_TURN_REVOKE_URL")
	if endpoint == "" {
		endpoint = "https://rtc.live.cloudflare.com/v1/turn/keys/%s/credentials/generate-ice-servers"
		if revokeEndpoint == "" {
			revokeEndpoint = "https://rtc.live.cloudflare.com/v1/turn/keys/%s/credentials/%s/revoke"
		}
	}
	log.Printf("[NAT] Cloudflare TURN broker enabled (ttl %s)", ttl)
	return &TurnBroker{
		keyID:          keyID,
		apiToken:       token,
		ttl:            ttl,
		endpoint:       endpoint,
		revokeEndpoint: revokeEndpoint,
		client:         &http.Client{Timeout: 5 * time.Second},
		cache:          make(map[string]*TurnCredentials),
	}
}

// Get returns cached credentials for the server or mints new ones.
func (tb *TurnBroker) Get(serverKey string) (*TurnCredentials, error) {
	tb.mu.Lock()
	cached, haveCached := tb.cache[serverKey]
	if haveCached && time.Until(time.Unix(cached.Expires, 0)) > tb.ttl/4 {
		tb.mu.Unlock()
		return cached, nil
	}
	if !haveCached {
		host := serverHost(serverKey)
		n := 0
		for k := range tb.cache {
			if serverHost(k) == host {
				n++
			}
		}
		if n >= turnServersPerIP {
			tb.mu.Unlock()
			return nil, errors.New("too many relayed servers for this IP")
		}
	}
	now := time.Now()
	kept := tb.mintTimes[:0]
	for _, t := range tb.mintTimes {
		if now.Sub(t) < time.Minute {
			kept = append(kept, t)
		}
	}
	tb.mintTimes = kept
	if len(tb.mintTimes) >= turnMintsPerMinute {
		tb.mu.Unlock()
		return nil, errors.New("turn credential mint rate limited")
	}
	tb.mintTimes = append(tb.mintTimes, now)
	tb.mu.Unlock()

	creds, err := tb.mint()
	if err != nil {
		return nil, err
	}
	tb.mu.Lock()
	tb.cache[serverKey] = creds
	tb.mu.Unlock()
	return creds, nil
}

// Forget drops a server's cached credentials and revokes them at Cloudflare,
// so credentials handed to a server that went away cannot keep relaying.
func serverHost(serverKey string) string {
	if ap, err := netip.ParseAddrPort(serverKey); err == nil {
		return ap.Addr().String()
	}
	return serverKey
}

// Has reports whether credentials were issued to this server.
func (tb *TurnBroker) Has(serverKey string) bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	_, ok := tb.cache[serverKey]
	return ok
}

func (tb *TurnBroker) Forget(serverKey string) {
	tb.mu.Lock()
	creds := tb.cache[serverKey]
	delete(tb.cache, serverKey)
	tb.mu.Unlock()
	if creds != nil && tb.revokeEndpoint != "" {
		go tb.revoke(creds.Username)
	}
}

func (tb *TurnBroker) revoke(username string) {
	req, err := http.NewRequest("POST", fmt.Sprintf(tb.revokeEndpoint, tb.keyID, url.PathEscape(username)), nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+tb.apiToken)
	resp, err := tb.client.Do(req)
	if err != nil {
		log.Printf("[NAT] TURN credential revoke failed: %v", err)
		return
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		log.Printf("[NAT] TURN credential revoke returned %d", resp.StatusCode)
	}
}

type iceServer struct {
	URLs       json.RawMessage `json:"urls"`
	Username   string          `json:"username"`
	Credential string          `json:"credential"`
}

func (tb *TurnBroker) mint() (*TurnCredentials, error) {
	body, _ := json.Marshal(map[string]int64{"ttl": int64(tb.ttl / time.Second)})
	req, err := http.NewRequest("POST", fmt.Sprintf(tb.endpoint, tb.keyID), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tb.apiToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := tb.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("cloudflare turn api status %d", resp.StatusCode)
	}
	return parseCloudflareICE(resp.Body, tb.ttl)
}

// parseCloudflareICE accepts both the current {"iceServers":[...]} array
// shape and the legacy single-object shape.
func parseCloudflareICE(r interface{ Read([]byte) (int, error) }, ttl time.Duration) (*TurnCredentials, error) {
	var raw struct {
		ICEServers json.RawMessage `json:"iceServers"`
	}
	if err := json.NewDecoder(r).Decode(&raw); err != nil {
		return nil, err
	}
	var servers []iceServer
	if len(raw.ICEServers) > 0 && raw.ICEServers[0] == '[' {
		if err := json.Unmarshal(raw.ICEServers, &servers); err != nil {
			return nil, err
		}
	} else {
		var one iceServer
		if err := json.Unmarshal(raw.ICEServers, &one); err != nil {
			return nil, err
		}
		servers = []iceServer{one}
	}
	out := &TurnCredentials{Expires: time.Now().Add(ttl).Unix()}
	for _, s := range servers {
		var urls []string
		if len(s.URLs) > 0 && s.URLs[0] == '[' {
			json.Unmarshal(s.URLs, &urls)
		} else {
			var u string
			json.Unmarshal(s.URLs, &u)
			urls = []string{u}
		}
		for _, u := range urls {
			// The game only speaks TURN over UDP.
			if strings.HasPrefix(u, "turn:") && strings.Contains(u, "transport=udp") {
				out.URLs = append(out.URLs, u)
			}
		}
		if s.Username != "" {
			out.Username = s.Username
			out.Credential = s.Credential
		}
	}
	if out.Username == "" || len(out.URLs) == 0 {
		return nil, errors.New("cloudflare turn response without udp turn credentials")
	}
	return out, nil
}

// ---------- HTTP: POST /nat/connect ----------

type natConnectRequest struct {
	Server string `json:"server"` // "ip:port" as listed in /servers
}

type natConnectResponse struct {
	Ticket       string       `json:"ticket,omitempty"`
	Rendezvous   string       `json:"rendezvous,omitempty"`
	ServerMapped string       `json:"server_mapped,omitempty"`
	LAN          []string     `json:"lan,omitempty"`
	ClientIP     string       `json:"client_ip"`
	P2P          bool         `json:"p2p"`
	Identity     string       `json:"identity,omitempty"` // signed client IP for this server (see identitySigner)
	Reach        Reachability `json:"reach"`
	Transports   *Transports  `json:"transports,omitempty"`
}

// HandleNatConnect is called by a client right before it connects to a
// listed server. It returns everything the client needs to probe all of the
// server's transports and, if the server is registered with the rendezvous,
// asks the server to open a TURN permission / hole-punch towards the client.
func (ms *MasterServer) HandleNatConnect(c *gin.Context) {
	var req natConnectRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
	ap, err := parsePublicAddrPort(req.Server)
	if err != nil {
		c.String(http.StatusBadRequest, "invalid server address")
		return
	}
	key := ap.String()
	clientIP, _ := netip.ParseAddr(c.ClientIP())
	clientIP = clientIP.Unmap()

	ms.serversMu.RLock()
	entry, ok := ms.servers[key]
	var resp natConnectResponse
	var serverIP netip.Addr
	if ok {
		resp.P2P = entry.P2P
		resp.Reach = entry.Reach
		resp.Transports = entry.Transports
		serverIP, _ = netip.ParseAddr(entry.IP)
		if serverIP.Unmap() == clientIP && clientIP.IsValid() {
			// Same public IP: the server's LAN addresses are the best bet.
			resp.LAN = append([]string(nil), entry.LAN...)
		}
	}
	ms.serversMu.RUnlock()
	if !ok {
		c.String(http.StatusNotFound, "unknown server")
		return
	}
	resp.ClientIP = clientIP.String()
	if ms.identity != nil {
		if token, err := ms.identity.Sign(clientIP, key); err == nil {
			resp.Identity = token
		}
	}

	if ms.rendezvous != nil {
		ticket, err := ms.rendezvous.NewTicket(key, clientIP)
		if err != nil {
			c.String(http.StatusTooManyRequests, err.Error())
			return
		}
		resp.Ticket = hex.EncodeToString(ticket[:])
		resp.Rendezvous = ms.rendezvous.publicAddr
		if mapped, ok := ms.rendezvous.Mapped(key); ok {
			resp.ServerMapped = mapped.String()
			// Port 0 == "permission only": lets a TURN-relayed server accept
			// the client before its UDP registration arrives.
			if clientIP.Is4() {
				ms.rendezvous.pushPunchRequest(ticket, netip.AddrPortFrom(clientIP, 0))
			}
		}
	}
	c.JSON(http.StatusOK, resp)
}

// ---------- Validation through alternative paths ----------

// challengeVia runs the standard connect challenge through the rendezvous
// socket towards addr (a NAT mapping or a TURN relay address).
func (ms *MasterServer) challengeVia(addr netip.AddrPort) bool {
	if ms.rendezvous == nil || !addr.IsValid() {
		return false
	}
	pkt, nonce := buildChallengePacket()
	if pkt == nil {
		return false
	}
	resp, err := ms.rendezvous.Challenge(addr, pkt, 3*time.Second)
	if err != nil {
		log.Printf("[Validation] challenge via %s failed: %v", addr, err)
		return false
	}
	return validateResponse(resp, nonce)
}

func buildChallengePacket() ([]byte, string) {
	nonce := make([]byte, 4)
	if _, err := crand.Read(nonce); err != nil {
		return nil, ""
	}
	nonceStr := "0x" + hex.EncodeToString(nonce)
	pkt := make([]byte, 23)
	copy(pkt[0:4], []byte{0xFF, 0xFF, 0xFF, 0xFF})
	pkt[4] = 0x48
	copy(pkt[5:12], "connect")
	copy(pkt[12:22], nonceStr)
	pkt[22] = 0x00
	return pkt, nonceStr
}

// ---------- Heartbeat response ----------

type heartbeatResponse struct {
	Rendezvous string           `json:"rendezvous,omitempty"`
	Token      string           `json:"token,omitempty"`
	PublicIP   string           `json:"public_ip"`
	Reach      Reachability     `json:"reach"`
	Validated  bool             `json:"validated"`
	Identity   bool             `json:"identity"` // clients get attested identities (servers may require them)
	Turn       *TurnCredentials `json:"turn,omitempty"`
}

// forgetNatState drops rendezvous / TURN state of a removed server.
func (ms *MasterServer) forgetNatState(key string) {
	if ms.rendezvous != nil {
		ms.rendezvous.Forget(key)
	}
	if ms.turn != nil {
		ms.turn.Forget(key)
	}
}

// onServerMapped re-validates an unvalidated server as soon as it registers
// a NAT mapping, instead of waiting for its next heartbeat.
func (ms *MasterServer) onServerMapped(key string) {
	ms.serversMu.RLock()
	entry, ok := ms.servers[key]
	needs := ok && !entry.Validated
	var ip string
	var port int
	if ok {
		ip, port = entry.IP, entry.Port
	}
	ms.serversMu.RUnlock()
	if !needs {
		return
	}
	ms.challengeMu.Lock()
	ms.challenges[key] = time.Now()
	ms.challengeMu.Unlock()
	ms.PerformValidation(ip, port)
}

// ---------- Client identity attestation ----------
//
// Game servers reached through EOS, iroh, tailcat or TURN see fake peer
// addresses, so IP bans could be dodged by switching transport. The master
// therefore signs a short-lived statement "the client at IP X wants to talk
// to server T" that the client presents over whatever route it picked; the
// server checks it against the same public key the game already embeds for
// server auth tokens and bans on X.
//
// Token (129 bytes, sent hex encoded over HTTP and raw inside R1NX IDENTIFY):
//   "R1ID" | version=1 | client IPv4[4] | expires unix[8] | nonce[16] |
//   SHA-256(target)[32] | ECDSA P-256 signature r[32] s[32] over SHA-256 of
//   everything before it.
// target is the server's listing key "ip:port", or "iroh:<endpoint id>",
// "tailcat:<address>", "eos:<puid>" for servers reached by an overlay address.

const identityTTL = 5 * time.Minute

type identitySigner struct {
	key *ecdsa.PrivateKey
}

// newIdentitySignerFromEnv loads ATTEST_KEY_FILE (default: the server-token
// key JWT_PRIVATE_KEY_FILE / new_key.pem). Returns nil if unavailable.
func newIdentitySignerFromEnv() *identitySigner {
	path := os.Getenv("ATTEST_KEY_FILE")
	if path == "" {
		path = os.Getenv("JWT_PRIVATE_KEY_FILE")
	}
	if path == "" {
		path = "new_key.pem"
	}
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		log.Printf("[NAT] Identity attestation disabled: cannot read %s: %v", path, err)
		return nil
	}
	key, err := jwt.ParseECPrivateKeyFromPEM(pemBytes)
	if err != nil || key.Curve != elliptic.P256() {
		log.Printf("[NAT] Identity attestation disabled: %s is not a P-256 EC key (%v)", path, err)
		return nil
	}
	log.Printf("[NAT] Identity attestation enabled (key %s)", path)
	return &identitySigner{key: key}
}

func (s *identitySigner) Sign(client netip.Addr, target string) (string, error) {
	client = client.Unmap()
	if !client.Is4() {
		return "", errors.New("identity tokens need an IPv4 client address")
	}
	payload := make([]byte, 0, 129)
	payload = append(payload, "R1ID"...)
	payload = append(payload, 1)
	ip := client.As4()
	payload = append(payload, ip[:]...)
	payload = binary.BigEndian.AppendUint64(payload, uint64(time.Now().Add(identityTTL).Unix()))
	nonce := make([]byte, 16)
	crand.Read(nonce)
	payload = append(payload, nonce...)
	th := sha256.Sum256([]byte(target))
	payload = append(payload, th[:]...)
	digest := sha256.Sum256(payload)
	r, sv, err := ecdsa.Sign(crand.Reader, s.key, digest[:])
	if err != nil {
		return "", err
	}
	payload = append(payload, r.FillBytes(make([]byte, 32))...)
	payload = append(payload, sv.FillBytes(make([]byte, 32))...)
	return hex.EncodeToString(payload), nil
}

// HandleNatAttest issues an identity token for a server the client reaches
// by an overlay address rather than through the server list.
// Endpoint: POST /nat/attest {"target": "iroh:<id>" | "tailcat:<addr>" | "eos:<puid>" | "ip:port"}
func (ms *MasterServer) HandleNatAttest(c *gin.Context) {
	if ms.identity == nil {
		c.String(http.StatusServiceUnavailable, "identity attestation not configured")
		return
	}
	var req struct {
		Target string `json:"target"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.Target == "" || len(req.Target) > 1024 {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
	clientIP, err := netip.ParseAddr(c.ClientIP())
	if err != nil {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
	token, err := ms.identity.Sign(clientIP, req.Target)
	if err != nil {
		c.String(http.StatusBadRequest, err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{"identity": token, "client_ip": clientIP.Unmap().String()})
}
