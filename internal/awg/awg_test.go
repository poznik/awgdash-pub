package awg

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

const sampleConf = `[Interface]
Address = 10.20.0.1/16
MTU = 1280
PostUp = iptables -t nat -A POSTROUTING -s 10.20.0.0/16 -o eth0 -j MASQUERADE
# комментарий, который обязан сохраниться
ListenPort = 443
PrivateKey = cHJpdmF0ZS1rZXktbmUtbG9naXJvdmF0eS1uaWtvZ2RhPT0=
Jc = 6
Jmin = 20
Jmax = 90
S1 = 40
S2 = 30
S3 = 12
S4 = 24
H1 = 100000001-100000999
H2 = 200000001-200000999
H3 = 300000001-300000999
H4 = 400000001-400000999
I1 = <b 0xc70000000108><r 8><b 0x00004100><r 4>
ContentPaddingAddition = 0

[Peer]
PublicKey = PEER1PUBKEYPEER1PUBKEYPEER1PUBKEYPEER1PUBKE=
AdvancedSecurity = off
AllowedIPs = 10.20.0.2/32
Endpoint = 198.51.100.7:10852

[Peer]
PublicKey = PEER2PUBKEYPEER2PUBKEYPEER2PUBKEYPEER2PUBKE=
PresharedKey = cHNrLXBzay1wc2stcHNrLXBzay1wc2stcHNrLXBzay1wc2s9
AllowedIPs = 10.20.0.6/32, 192.168.50.0/24
PersistentKeepalive = 21
`

const sampleDump = "cHJpdg==\tSERVERPUBKEYSERVERPUBKEYSERVERPUBKEYSERVERP=\t443\t6\t20\t90\t40\t30\t12\t24\t100000001-100000999\t200000001-200000999\t300000001-300000999\t400000001-400000999\t<b 0xc70000000108><r 8><b 0x00004100><r 4>\t(null)\t(null)\t(null)\t(null)\t(none)\t0\t0\t0\t0\t0\t0\toff\n" +
	"PEER1PUBKEYPEER1PUBKEYPEER1PUBKEYPEER1PUBKE=\t(none)\t203.0.113.5:51489\t10.20.0.2/32\t1787293688\t254526584\t988956746\toff\n" +
	"PEER2PUBKEYPEER2PUBKEYPEER2PUBKEYPEER2PUBKE=\tcHNr\t(none)\t10.20.0.6/32,192.168.50.0/24\t0\t0\t0\t21\n"

func TestParseRenderRoundTrip(t *testing.T) {
	c, err := Parse([]byte(sampleConf))
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Param("listenport"); got != "443" {
		t.Fatalf("ListenPort = %q", got)
	}
	if len(c.Peers) != 2 {
		t.Fatalf("peers = %d", len(c.Peers))
	}
	if c.Peers[0].Extra[0].Key != "AdvancedSecurity" || c.Peers[0].Extra[0].Value != "off" {
		t.Fatalf("extra = %+v", c.Peers[0].Extra)
	}
	if len(c.Peers[1].AllowedIPs) != 2 || c.Peers[1].PersistentKeepalive != "21" {
		t.Fatalf("peer2 = %+v", c.Peers[1])
	}
	// Секция Interface — байт в байт (без хвостовой пустой строки).
	wantIface := sampleConf[:strings.Index(sampleConf, "\n[Peer]")] + "\n"
	wantIface = strings.TrimRight(wantIface, "\n") + "\n"
	if !bytes.Equal(c.Interface, []byte(wantIface)) {
		t.Fatalf("Interface изменилась:\n%s\n---\n%s", c.Interface, wantIface)
	}
	out := c.Render()
	c2, err := Parse(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(c2.Render(), out) {
		t.Fatal("повторный Render отличается")
	}
	if !bytes.Equal(c2.Interface, c.Interface) || len(c2.Peers) != 2 || c2.Peers[1].PresharedKey != c.Peers[1].PresharedKey {
		t.Fatal("round-trip потерял данные")
	}
	if c.SaveConfigEnabled() {
		t.Fatal("SaveConfig не задан, а прочитан как true")
	}
}

func TestParseErrors(t *testing.T) {
	for _, bad := range []string{"[Peer]\nPublicKey = x\n", "Address = 1\n[Interface]\n", "[Interface]\n[Peer]\nAllowedIPs = 10.0.0.2/32\n", "[Interface]\n[Other]\n"} {
		if _, err := Parse([]byte(bad)); err == nil {
			t.Errorf("ожидалась ошибка для %q", bad)
		}
	}
}

func TestParseDump(t *testing.T) {
	id, peers, err := ParseDump(sampleDump)
	if err != nil {
		t.Fatal(err)
	}
	if !id.IsAWG || id.ListenPort != 443 || id.PublicKey != "SERVERPUBKEYSERVERPUBKEYSERVERPUBKEYSERVERP=" {
		t.Fatalf("iface = %+v", id)
	}
	if id.Obf["I1"] != "<b 0xc70000000108><r 8><b 0x00004100><r 4>" || id.Obf["I2"] != "" || id.Obf["H4"] != "400000001-400000999" {
		t.Fatalf("obf = %+v", id.Obf)
	}
	if id.FwMark != "off" || len(id.Extra) != 7 {
		t.Fatalf("extra/fwmark = %v %q", id.Extra, id.FwMark)
	}
	if len(peers) != 2 {
		t.Fatalf("peers = %d", len(peers))
	}
	p := peers[0]
	if p.HasPSK || p.Endpoint != "203.0.113.5:51489" || p.Rx != 254526584 || p.Tx != 988956746 || p.Keepalive != 0 {
		t.Fatalf("peer0 = %+v", p)
	}
	if p.LatestHandshake.Unix() != 1787293688 || !p.Online(time.Unix(1787293688+100, 0), 180*time.Second) || p.Online(time.Unix(1787293688+181, 0), 180*time.Second) {
		t.Fatalf("handshake/online: %+v", p)
	}
	q := peers[1]
	if !q.HasPSK || q.Endpoint != "" || !q.LatestHandshake.IsZero() || q.Keepalive != 21 || len(q.AllowedIPs) != 2 {
		t.Fatalf("peer1 = %+v", q)
	}
}

func TestParseDumpPlainWireGuard(t *testing.T) {
	id, peers, err := ParseDump("priv\tpub\t51820\toff\npk\t(none)\t(none)\t10.0.0.2/32\t0\t0\t0\toff\n")
	if err != nil || id.IsAWG || id.ListenPort != 51820 || len(peers) != 1 {
		t.Fatalf("plain: %v %+v %d", err, id, len(peers))
	}
}

func TestVerify(t *testing.T) {
	c, _ := Parse([]byte(sampleConf))
	id, _, _ := ParseDump(sampleDump)
	r := Verify(c, id)
	if !r.OK || r.Matched != 12 {
		t.Fatalf("verify: %+v", r)
	}
	id.Obf["H1"] = "1-2"
	r = Verify(c, id)
	if r.OK || len(r.Diffs) != 1 || r.Diffs[0].Key != "H1" {
		t.Fatalf("verify diff: %+v", r)
	}
}

// Ноль в рантайме и отсутствие строки в файле — одно состояние: служебный интерфейс
// (в файле нет S3 и S4) давал 10/12 и красил сервер в «поломку», хотя ядро настроено как файл.
func TestVerifyZeroEqualsUnset(t *testing.T) {
	const conf = `[Interface]
Address = 10.90.0.1/24
ListenPort = 51821
PrivateKey = cHJpdmF0ZS1rZXktbmUtbG9naXJvdmF0eS1uaWtvZ2RhPT0=
Jc = 4
Jmin = 10
Jmax = 50
S1 = 35
S2 = 22
H1 = 11111111
H2 = 222222222
H3 = 333333333
H4 = 444444444
`
	// Дамп с нулями там, где в файле строк нет вовсе (S3, S4) и где параметр не задан (I1..I5).
	dump := "cHJpdg==\tMGMTPUBKEYMGMTPUBKEYMGMTPUBKEYMGMTPUBKEYMGE=\t51821\t4\t10\t50\t35\t22\t0\t0\t" +
		"11111111\t222222222\t333333333\t444444444\t(null)\t(null)\t(null)\t(null)\t(null)\t0\toff\n"

	c, err := Parse([]byte(conf))
	if err != nil {
		t.Fatal(err)
	}
	id, _, err := ParseDump(dump)
	if err != nil {
		t.Fatal(err)
	}
	if r := Verify(c, id); !r.OK || r.Matched != 12 {
		t.Fatalf("незаданный параметр и ноль обязаны сходиться: %+v", r.Diffs)
	}

	// Настоящее расхождение прятаться не должно: в ядре размер есть, в файле его нет.
	id.Obf["S3"] = "13"
	r := Verify(c, id)
	if r.OK || len(r.Diffs) != 1 || r.Diffs[0].Key != "S3" || r.Diffs[0].Runtime != "13" {
		t.Fatalf("расхождение S3 должно ловиться: %+v", r)
	}

	// И наоборот: параметр задан в файле, а ядро его потеряло.
	c2, err := Parse([]byte(conf + "S4 = 17\n"))
	if err != nil {
		t.Fatal(err)
	}
	id2, _, _ := ParseDump(dump)
	r = Verify(c2, id2)
	if r.OK || len(r.Diffs) != 1 || r.Diffs[0].Key != "S4" || r.Diffs[0].File != "17" {
		t.Fatalf("потеря заданного параметра должна ловиться: %+v", r)
	}
}
