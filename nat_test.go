package main

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
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestNatPacketRoundTrip(t *testing.T) {
	obs := netip.MustParseAddrPort("1.2.3.4:5678")
	srv := netip.MustParseAddrPort("5.6.7.8:37015")
	kind, payload, ok := parseNatPacket(encodeRegisterAck(obs, &srv))
	if !ok || kind != pktRegisterAck {
		t.Fatalf("bad ack parse: %v %d", ok, kind)
	}
	got, _ := readAddr4(payload)
	if got != obs || payload[6] != ackFlagHasServer {
		t.Fatalf("ack observed = %v flags=%d", got, payload[6])
	}
	gotSrv, _ := readAddr4(payload[7:])
	if gotSrv != srv {
		t.Fatalf("ack server = %v", gotSrv)
	}

	var ticket [16]byte
	for i := range ticket {
		ticket[i] = byte(i)
	}
	var token [16]byte
	token[0] = 7
	kind, payload, ok = parseNatPacket(encodePunchRequest(ticket, obs, token))
	if !ok || kind != pktPunchRequest || !bytes.Equal(payload[:16], ticket[:]) || len(payload) != 38 {
		t.Fatalf("bad punch request")
	}
	mac := hmac.New(sha256.New, token[:])
	mac.Write(payload[:22])
	if !bytes.Equal(mac.Sum(nil)[:16], payload[22:38]) {
		t.Fatalf("punch request mac mismatch")
	}
	if a, _ := readAddr4(payload[16:]); a != obs {
		t.Fatalf("punch request addr = %v", a)
	}
	if _, _, ok := parseNatPacket([]byte("\xff\xff\xff\xffHconnect")); ok {
		t.Fatalf("engine packet parsed as NAT packet")
	}
}

func TestSanitizeTransports(t *testing.T) {
	in := &Transports{
		EOS:       &EOSTransport{PUID: "0002ABCDEF0123456789abcdef012345"},
		Iroh:      &IrohTransport{ID: strings.Repeat("ab", 32), Relay: "https://euw1-1.relay.iroh.network./", Addrs: []string{"1.2.3.4:1", "garbage", "[2001:db8::1]:5"}},
		Tailcat:   &TailcatTransport{Addr: "tcomFwWCCcjS5nKNqAod034nWoJZW0LZqDhhC8U_dKdnDRYQ8uNGFpGQEu"},
		Tailscale: &TailscaleTransport{IPs: []string{"100.100.1.2", "8.8.8.8", "fd7a:115c:a1e0::1"}},
		Turn:      &TurnTransport{Relay: "10.0.0.1:3478"},
	}
	out := sanitizeTransports(in, "1.2.3.4")
	if out.EOS == nil || out.EOS.PUID != "0002abcdef0123456789abcdef012345" {
		t.Errorf("eos = %+v", out.EOS)
	}
	if out.Iroh == nil || len(out.Iroh.Addrs) != 1 || out.Iroh.Relay == "" {
		t.Errorf("iroh = %+v", out.Iroh)
	}
	if out.Tailcat == nil {
		t.Errorf("tailcat dropped")
	}
	if out.Tailscale == nil || len(out.Tailscale.IPs) != 2 {
		t.Errorf("tailscale = %+v", out.Tailscale)
	}
	if out.Turn != nil {
		t.Errorf("private turn relay accepted: %+v", out.Turn)
	}
	if sanitizeTransports(&Transports{EOS: &EOSTransport{PUID: "nope"}}, "1.2.3.4") != nil {
		t.Errorf("all-invalid transports should sanitize to nil")
	}
	lan := sanitizeLAN([]string{"192.168.1.5:37015", "8.8.8.8:1", "10.0.0.2:0", "172.16.0.1:37015"})
	if len(lan) != 2 {
		t.Errorf("lan = %v", lan)
	}
}

func TestRendezvousRejectsUnusableAdvertisedAddress(t *testing.T) {
	t.Setenv("RENDEZVOUS_LISTEN", "127.0.0.1:0")
	for _, public := range []string{"not-an-address", "203.0.113.10:0", "[2001:db8::1]:37999", "0.0.0.0:37999"} {
		t.Run(public, func(t *testing.T) {
			t.Setenv("RENDEZVOUS_PUBLIC_ADDR", public)
			if rv := startRendezvous(); rv != nil {
				rv.conn.Close()
				t.Fatalf("rendezvous advertised unusable endpoint %q", public)
			}
		})
	}
}

func TestParseCloudflareICE(t *testing.T) {
	arrayShape := `{"iceServers":[{"urls":["stun:stun.cloudflare.com:3478"]},{"urls":["turn:turn.cloudflare.com:3478?transport=udp","turn:turn.cloudflare.com:3478?transport=tcp","turns:turn.cloudflare.com:5349?transport=tcp"],"username":"u","credential":"c"}]}`
	c, err := parseCloudflareICE(strings.NewReader(arrayShape), time.Hour)
	if err != nil || c.Username != "u" || c.Credential != "c" || len(c.URLs) != 1 {
		t.Fatalf("array shape: %+v %v", c, err)
	}
	legacy := `{"iceServers":{"urls":["turn:turn.cloudflare.com:3478?transport=udp"],"username":"u2","credential":"c2"}}`
	c, err = parseCloudflareICE(strings.NewReader(legacy), time.Hour)
	if err != nil || c.Username != "u2" || len(c.URLs) != 1 {
		t.Fatalf("legacy shape: %+v %v", c, err)
	}
	if _, err := parseCloudflareICE(strings.NewReader(`{"iceServers":[]}`), time.Hour); err == nil {
		t.Fatalf("empty response should fail")
	}
}

func TestTurnBrokerCaches(t *testing.T) {
	calls := 0
	cf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Authorization") != "Bearer tok" || !strings.Contains(r.URL.Path, "/keyid/") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"iceServers":[{"urls":["turn:turn.cloudflare.com:3478?transport=udp"],"username":"u","credential":"c"}]}`))
	}))
	defer cf.Close()
	tb := &TurnBroker{keyID: "keyid", apiToken: "tok", ttl: time.Hour, endpoint: cf.URL + "/v1/turn/keys/%s/x",
		client: cf.Client(), cache: map[string]*TurnCredentials{}}
	for i := 0; i < 3; i++ {
		if _, err := tb.Get("1.2.3.4:37015"); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 {
		t.Fatalf("expected one mint, got %d", calls)
	}
	for port := 2; port <= 3; port++ {
		if _, err := tb.Get("1.2.3.4:" + strconv.Itoa(37015+port)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := tb.Get("1.2.3.4:37099"); err == nil {
		t.Fatalf("per-IP TURN cap not enforced")
	}
	if _, err := tb.Get("5.6.7.8:37015"); err != nil {
		t.Fatalf("other IPs must still get credentials: %v", err)
	}
}

// fakeGameServer simulates an R1Delta server behind a port-restricted NAT:
// it answers the connect challenge only when it comes from the rendezvous
// socket, registers with the rendezvous, and acknowledges punch requests.
type fakeGameServer struct {
	conn     *net.UDPConn
	rvAddr   netip.AddrPort
	mu       sync.Mutex
	token    []byte
	punchReq []netip.AddrPort
}

func (f *fakeGameServer) loop(t *testing.T) {
	buf := make([]byte, 2048)
	for {
		n, from, err := f.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
		if from != f.rvAddr {
			continue // "NAT" drops unsolicited traffic
		}
		pkt := buf[:n]
		if kind, payload, ok := parseNatPacket(pkt); ok {
			if kind == pktPunchRequest {
				f.mu.Lock()
				mac := hmac.New(sha256.New, f.token)
				f.mu.Unlock()
				mac.Write(payload[:22])
				if len(payload) < 38 || !bytes.Equal(mac.Sum(nil)[:16], payload[22:38]) {
					continue // not from the master
				}
				client, _ := readAddr4(payload[16:])
				f.mu.Lock()
				f.punchReq = append(f.punchReq, client)
				f.mu.Unlock()
				ack := append(natHeader(pktPunchReqAck), payload[:22]...)
				f.conn.WriteToUDPAddrPort(ack, from)
			}
			continue
		}
		if n >= 22 && pkt[4] == 0x48 {
			resp := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x49, 1, 2, 3, 4}
			resp = append(resp, "connect"...)
			resp = append(resp, pkt[12:22]...)
			f.conn.WriteToUDPAddrPort(resp, from)
		}
	}
}

func (f *fakeGameServer) register() {
	f.mu.Lock()
	tok := f.token
	f.mu.Unlock()
	pkt := append(natHeader(pktSrvRegister), tok...)
	f.conn.WriteToUDPAddrPort(pkt, f.rvAddr)
}

func TestRendezvousEndToEnd(t *testing.T) {
	gin.SetMode(gin.TestMode)

	rvConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	rvAddr := rvConn.LocalAddr().(*net.UDPAddr).AddrPort()
	rv := newRendezvous(rvConn, rvAddr.String())
	go rv.readLoop()
	defer rvConn.Close()

	ms := NewMasterServer()
	ms.rendezvous = rv
	rv.onMapped = ms.onServerMapped

	srvConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer srvConn.Close()
	srvPort := srvConn.LocalAddr().(*net.UDPAddr).Port
	fake := &fakeGameServer{conn: srvConn, rvAddr: rvAddr}
	go fake.loop(t)

	r := gin.New()
	r.POST("/heartbeat", ms.HandleHeartbeat)
	r.POST("/nat/connect", ms.HandleNatConnect)

	doHeartbeat := func() heartbeatResponse {
		hb := map[string]any{
			"host_name": "test server", "map_name": "mp_lobby", "game_mode": "tdm",
			"max_players": 12, "port": srvPort, "version": "3.0.0",
			"players":    []any{},
			"transports": map[string]any{"eos": map[string]any{"puid": strings.Repeat("0", 32)}},
			"nat":        map[string]any{"lan": []string{"192.168.0.10:37015"}, "want_turn": true},
		}
		body, _ := json.Marshal(hb)
		req := httptest.NewRequest("POST", "/heartbeat", bytes.NewReader(body))
		req.RemoteAddr = "127.0.0.1:50000"
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("heartbeat status %d: %s", w.Code, w.Body.String())
		}
		var resp heartbeatResponse
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("heartbeat response %q: %v", w.Body.String(), err)
		}
		return resp
	}

	resp := doHeartbeat()
	if resp.Token == "" || resp.Rendezvous != rvAddr.String() {
		t.Fatalf("heartbeat response missing rendezvous info: %+v", resp)
	}
	tok, _ := hex.DecodeString(resp.Token)
	fake.mu.Lock()
	fake.token = tok
	fake.mu.Unlock()
	fake.register()

	key := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(srvPort)).String()
	deadline := time.Now().Add(10 * time.Second)
	for {
		ms.serversMu.RLock()
		e := ms.servers[key]
		ok := e != nil && e.Validated && e.Reach.Punch
		ms.serversMu.RUnlock()
		if ok {
			break
		}
		if time.Now().After(deadline) {
			ms.serversMu.RLock()
			t.Fatalf("server never validated through rendezvous: %+v", ms.servers[key])
		}
		time.Sleep(50 * time.Millisecond)
	}
	ms.serversMu.RLock()
	if ms.servers[key].Reach.Direct {
		t.Errorf("direct path should have failed (fake NAT)")
	}
	ms.serversMu.RUnlock()

	// Client side: ask for a ticket, then register over UDP.
	body, _ := json.Marshal(natConnectRequest{Server: key})
	req := httptest.NewRequest("POST", "/nat/connect", bytes.NewReader(body))
	req.RemoteAddr = "127.0.0.1:50001"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("nat/connect status %d: %s", w.Code, w.Body.String())
	}
	var cr natConnectResponse
	json.Unmarshal(w.Body.Bytes(), &cr)
	if cr.Ticket == "" || cr.ServerMapped != key || len(cr.LAN) != 1 || cr.Transports == nil || cr.Transports.EOS == nil || !cr.P2P {
		t.Fatalf("unexpected nat/connect response: %s", w.Body.String())
	}

	cliConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer cliConn.Close()
	ticket, _ := hex.DecodeString(cr.Ticket)
	cliConn.WriteToUDPAddrPort(append(natHeader(pktCliRegister), ticket...), rvAddr)
	cliConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 256)
	n, _, err := cliConn.ReadFromUDPAddrPort(buf)
	if err != nil {
		t.Fatalf("no register ack for client: %v", err)
	}
	kind, payload, ok := parseNatPacket(buf[:n])
	if !ok || kind != pktRegisterAck || payload[6]&ackFlagHasServer == 0 {
		t.Fatalf("bad client ack %x", buf[:n])
	}
	observed, _ := readAddr4(payload)
	if observed != cliConn.LocalAddr().(*net.UDPAddr).AddrPort() {
		t.Fatalf("observed %v", observed)
	}

	// The fake server must have been told about the client endpoint.
	deadline = time.Now().Add(3 * time.Second)
	for {
		fake.mu.Lock()
		var found bool
		for _, a := range fake.punchReq {
			if a == observed {
				found = true
			}
		}
		fake.mu.Unlock()
		if found {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("server never received a punch request for %v", observed)
		}
		time.Sleep(20 * time.Millisecond)
	}

	// A registration from a different public IP must be rejected.
	rv.mu.Lock()
	var id [16]byte
	copy(id[:], ticket)
	rv.tickets[id].httpIP = netip.MustParseAddr("9.9.9.9")
	rv.tickets[id].client = netip.AddrPort{}
	rv.mu.Unlock()
	cliConn.WriteToUDPAddrPort(append(natHeader(pktCliRegister), ticket...), rvAddr)
	cliConn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, _, err := cliConn.ReadFromUDPAddrPort(buf); err == nil {
		t.Fatalf("ticket accepted from an IP that did not request it")
	}
}

func TestIdentitySigner(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s := &identitySigner{key: key}
	tokHex, err := s.Sign(netip.MustParseAddr("203.0.113.9"), "iroh:abc")
	if err != nil {
		t.Fatal(err)
	}
	tok, _ := hex.DecodeString(tokHex)
	if len(tok) != 129 || string(tok[:4]) != "R1ID" || tok[4] != 1 {
		t.Fatalf("bad token layout %x", tok)
	}
	if !bytes.Equal(tok[5:9], []byte{203, 0, 113, 9}) {
		t.Fatalf("bad ip %v", tok[5:9])
	}
	exp := int64(binary.BigEndian.Uint64(tok[9:17]))
	if d := exp - time.Now().Unix(); d < 200 || d > 400 {
		t.Fatalf("unexpected expiry in %ds", d)
	}
	th := sha256.Sum256([]byte("iroh:abc"))
	if !bytes.Equal(tok[33:65], th[:]) {
		t.Fatalf("bad target hash")
	}
	digest := sha256.Sum256(tok[:65])
	r := new(big.Int).SetBytes(tok[65:97])
	sv := new(big.Int).SetBytes(tok[97:129])
	if !ecdsa.Verify(&key.PublicKey, digest[:], r, sv) {
		t.Fatalf("signature does not verify")
	}
	if _, err := s.Sign(netip.MustParseAddr("2001:db8::1"), "x"); err == nil {
		t.Fatalf("IPv6 clients must be refused")
	}

	gin.SetMode(gin.TestMode)
	ms := NewMasterServer()
	ms.identity = s
	r2 := gin.New()
	r2.POST("/nat/attest", ms.HandleNatAttest)
	req := httptest.NewRequest("POST", "/nat/attest", strings.NewReader(`{"target":"tailcat:tcXYZ"}`))
	req.RemoteAddr = "198.51.100.4:1234"
	w := httptest.NewRecorder()
	r2.ServeHTTP(w, req)
	var resp struct {
		Identity string `json:"identity"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp)
	tok, _ = hex.DecodeString(resp.Identity)
	if w.Code != 200 || len(tok) != 129 || !bytes.Equal(tok[5:9], []byte{198, 51, 100, 4}) {
		t.Fatalf("attest: %d %s", w.Code, w.Body.String())
	}
}
