package hub

import (
	"context"
	"testing"

	"github.com/poznik/awgdash-pub/internal/awgtest"
	"github.com/poznik/awgdash-pub/internal/store"
)

// Человек с единственным разрешённым сервером получает устройство именно на нём. Форма портала
// при одном варианте выбор не показывает, и раньше пустое поле означало «сервер панели» —
// ограничение обходилось само собой, без всякой подделки формы.
func TestPortalDefaultRespectsAllowedServers(t *testing.T) {
	ctx := context.Background()
	h, _, local := testHub(t)
	own(t, h, local)

	// Второй сервер парка с собственным интерфейсом. Узел у него тот же (модель awg одна на
	// тест), но для хаба это отдельная машина.
	kz, err := h.Store.AddServer(ctx, store.NewServer{Slug: "kz", Title: "Казахстан", SSHHost: "kz", NodePort: 10089})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := awgtest.WriteConf(h.Node.ConfDir, "awg-kz"); err != nil {
		t.Fatal(err)
	}
	h.servers.put(&Server{ID: kz.ID, Slug: "kz", Title: "Казахстан", Agent: LocalAgent{N: h.Node}})
	remote, err := h.Store.UpsertInterface(ctx, kz.ID, "awg-kz", store.InterfaceFacts{
		Subnet: "10.30.0.0/24", ServerAddress: "10.30.0.1/24", ListenPort: 443, MTU: 1280, IsAWG: true,
		ServerPublicKey: awgtest.ServerPublicKey})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Store.SetInterfaceMode(ctx, remote, ModeOwn); err != nil {
		t.Fatal(err)
	}

	id, _, err := h.Store.CreateUser(ctx, store.User{Name: "Портальный", SelfService: true, MaxDevices: 5,
		AllowedInterfaces: []int64{remote}})
	if err != nil {
		t.Fatal(err)
	}
	u, err := h.Store.UserByID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}

	dev, err := h.PortalAddDevice(ctx, u, "Телефон", "phone", 0, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if dev.InterfaceID != remote {
		t.Fatalf("устройство село на интерфейс %d, а разрешён был только %d", dev.InterfaceID, remote)
	}
}
