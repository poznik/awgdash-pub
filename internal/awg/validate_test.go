package awg

import "testing"

// PeerSpec.Validate отбивает значения, которые нельзя писать в файл конфига (находка №9):
// перевод строки дописал бы произвольные строки [Peer], неверный ключ пережил бы запись
// и всплыл перезагрузкой, когда awg-quick не поднимет интерфейс.
func TestPeerSpecValidate(t *testing.T) {
	good := PeerSpec{PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", AllowedIPs: []string{"10.20.0.9/32"}}
	if err := good.Validate(); err != nil {
		t.Fatalf("нормальный пир отклонён: %v", err)
	}
	bad := map[string]PeerSpec{
		"перевод строки в ключе":  {PublicKey: "AAAA\nPrivateKey = x", AllowedIPs: []string{"10.20.0.9/32"}},
		"мусор вместо ключа":      {PublicKey: "не-ключ", AllowedIPs: []string{"10.20.0.9/32"}},
		"пустой ключ":             {PublicKey: "", AllowedIPs: []string{"10.20.0.9/32"}},
		"без allowed-ips":         {PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},
		"адрес не префикс":        {PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", AllowedIPs: []string{"10.20.0.9"}},
		"перевод строки в адресе": {PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", AllowedIPs: []string{"10.20.0.9/32\nEndpoint = x"}},
		"битый PSK":               {PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", PresharedKey: "короткий", AllowedIPs: []string{"10.20.0.9/32"}},
	}
	for name, spec := range bad {
		if err := spec.Validate(); err == nil {
			t.Errorf("%s: принято, ожидался отказ", name)
		}
	}
}
