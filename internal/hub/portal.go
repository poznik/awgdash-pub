package hub

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/poznik/awgdash-pub/internal/clientconf"
	"github.com/poznik/awgdash-pub/internal/store"
)

// ErrNoSelfService — пользователю не разрешено заводить устройства самому (FR-5.2).
var ErrNoSelfService = errors.New("самообслуживание для этого пользователя выключено")

// PortalDevice — устройство глазами его владельца: без ключей и служебных полей.
type PortalDevice struct {
	ID          int64
	Name        string
	Preset      string
	Address     string
	Online      bool
	OnInterface bool
	Disabled    bool
	LastSeen    time.Time
	Rx24, Tx24  uint64
	RxMonth     uint64
	TxMonth     uint64
}

// PortalGroup — устройства одного интерфейса: у каждого сервера свой заголовок и свои endpoint'ы.
type PortalGroup struct {
	Interface string
	Title     string
	Endpoints []store.Endpoint
	Devices   []PortalDevice
	// Retired — сервер выведен из парка: конфиги этой группы больше не подключатся, и портал
	// их не показывает вовсе (SPEC FR-10.6) — мёртвый QR хуже, чем его отсутствие.
	Retired bool
}

// PortalPage — всё, что показывает страница пользователя.
type PortalPage struct {
	User      store.User
	Groups    []PortalGroup
	CanAdd    bool
	Left      int // сколько устройств ещё можно завести
	Total     int
	AddIface  int64
	AddIfName string
	// Choices — куда пользователю разрешено сажать новое устройство. Показывается выбором,
	// только если вариантов больше одного (FR-5.2).
	Choices []PortalChoice
}

// PortalChoice — сервер парка глазами пользователя: он выбирает страну, а не интерфейс.
type PortalChoice struct {
	InterfaceID int64
	Title       string
	Interface   string
}

// Portal собирает страницу пользователя по его токену (FR-5.1). Токен уже проверен вызывающим.
func (h *Hub) Portal(ctx context.Context, u store.User) (PortalPage, error) {
	page := PortalPage{User: u}
	devices, err := h.Store.DevicesByUser(ctx, u.ID)
	if err != nil {
		return page, err
	}
	page.Total = len(devices)
	page.Left = u.MaxDevices - len(devices)
	page.CanAdd = u.SelfService && !u.Disabled() && page.Left > 0

	servers, err := h.Store.Servers(ctx)
	if err != nil {
		return page, err
	}
	titles := map[int64]string{}
	retired := map[int64]bool{}
	for _, s := range servers {
		titles[s.ID] = s.Title
		retired[s.ID] = s.Retired()
	}
	ifaces, err := h.Store.Interfaces(ctx, 0)
	if err != nil {
		return page, err
	}

	// Месячный трафик — одним запросом на все пиры пользователя.
	peerIDs := make([]int64, 0, len(devices))
	for _, d := range devices {
		if d.PeerID != 0 {
			peerIDs = append(peerIDs, d.PeerID)
		}
	}
	month, err := h.Store.TrafficSince(ctx, peerIDs, time.Now().AddDate(0, 0, -30))
	if err != nil {
		return page, err
	}

	byIface := map[int64][]PortalDevice{}
	for _, d := range devices {
		pd := PortalDevice{
			ID: d.ID, Name: d.Name, Preset: d.Preset, Address: d.Address,
			Online: d.Online(), OnInterface: d.OnInterface, Disabled: d.Status != "active",
			LastSeen: d.LastHandshake, Rx24: d.Rx24, Tx24: d.Tx24,
		}
		if m, ok := month[d.PeerID]; ok {
			pd.RxMonth, pd.TxMonth = m[0], m[1]
		}
		byIface[d.InterfaceID] = append(byIface[d.InterfaceID], pd)
	}
	for _, iface := range ifaces {
		list, ok := byIface[iface.ID]
		if !ok && iface.ID != u.DefaultInterfaceID {
			continue
		}
		title := titles[iface.ServerID]
		if title == "" {
			title = iface.Name
		}
		page.Groups = append(page.Groups, PortalGroup{
			Interface: iface.Name, Title: title, Endpoints: clientconf.Endpoints(iface), Devices: list,
			Retired: retired[iface.ServerID],
		})
		if retired[iface.ServerID] {
			continue
		}
		if page.AddIface == 0 && (iface.ID == u.DefaultInterfaceID || len(page.Groups) == 1) {
			page.AddIface, page.AddIfName = iface.ID, iface.Name
		}
	}
	// Варианты для нового устройства — все разрешённые серверы парка, а не только те,
	// где устройства уже есть: иначе на второй сервер не переехать.
	choices, err := h.IfaceChoices(ctx, &u)
	if err != nil {
		return page, err
	}
	// Наблюдаемых в списке уже нет: IfaceChoices отдаёт только интерфейсы под управлением
	// панели — на прочих самообслуживание выдало бы конфиг, который не подключится (FR-5.2).
	for _, c := range choices {
		page.Choices = append(page.Choices, PortalChoice{InterfaceID: c.InterfaceID, Title: c.Label(), Interface: c.Interface})
	}
	// По умолчанию — сервер, на котором работает панель: он идёт первым в списке.
	if len(page.Choices) > 0 {
		page.AddIface, page.AddIfName = page.Choices[0].InterfaceID, page.Choices[0].Interface
	}
	return page, nil
}

// PortalAddDevice заводит устройство от лица пользователя (FR-5.2).
func (h *Hub) PortalAddDevice(ctx context.Context, u store.User, name, preset string, ifaceID int64, ip string) (store.Device, error) {
	if !u.SelfService {
		return store.Device{}, ErrNoSelfService
	}
	if u.Disabled() {
		return store.Device{}, errors.New("доступ приостановлен — напишите администратору")
	}
	iface := ifaceID
	// Выбор из портала проверяется: список серверов приходит из формы, и доверять ей нельзя.
	if iface != 0 && !u.Allows(iface) {
		return store.Device{}, errors.New("этот сервер вам не разрешён")
	}
	// Тем же порядком отклоняется наблюдаемый интерфейс: он и не предлагался, но форму
	// можно подделать, а устройство на нём получит конфиг, который не подключится.
	if iface != 0 {
		i, err := h.Interface(ctx, iface)
		if err != nil {
			return store.Device{}, err
		}
		if i.Mode != ModeOwn {
			return store.Device{}, errors.New("на этом сервере устройства пока не выдаются — напишите администратору")
		}
	}
	if iface == 0 {
		// Сервер не выбран — сажаем на первый разрешённый этому человеку: без фильтра сюда
		// подставлялся сервер панели, и человек с единственным разрешённым чужим сервером
		// получал устройство мимо ограничения.
		choices, err := h.IfaceChoices(ctx, &u)
		if err != nil {
			return store.Device{}, err
		}
		if len(choices) == 0 {
			return store.Device{}, errors.New("сервера для нового устройства сейчас нет — напишите администратору")
		}
		iface = choices[0].InterfaceID
	}
	if preset != store.PresetRouter {
		preset = store.PresetPhone
	}
	dev, err := h.CreateDevice(ctx, NewDevice{
		UserID: u.ID, InterfaceID: iface, Name: name, Preset: preset,
		CreatedBy: "user", Actor: store.UserActor(u.ID), IP: ip,
	})
	if err != nil {
		return store.Device{}, err
	}
	h.event(ctx, "self_service_device", "info", iface, dev.ID,
		fmt.Sprintf("«%s» сам добавил устройство «%s» (%s)", u.Name, dev.Name, dev.Address))
	return dev, nil
}

// PortalRenameDevice переименовывает своё устройство.
func (h *Hub) PortalRenameDevice(ctx context.Context, u store.User, deviceID int64, name, ip string) error {
	d, err := h.ownDevice(ctx, u, deviceID)
	if err != nil {
		return err
	}
	if !u.SelfService {
		return ErrNoSelfService
	}
	old := d.Name
	d.Name = name
	if err := h.UpdateDevice(ctx, d, store.UserActor(u.ID), ip); err != nil {
		return err
	}
	h.event(ctx, "self_service_rename", "info", d.InterfaceID, d.ID,
		fmt.Sprintf("«%s» переименовал устройство «%s» в «%s»", u.Name, old, name))
	return nil
}

// PortalDeleteDevice удаляет своё устройство: мягко, администратор сможет вернуть (FR-5.2).
func (h *Hub) PortalDeleteDevice(ctx context.Context, u store.User, deviceID int64, ip string) error {
	d, err := h.ownDevice(ctx, u, deviceID)
	if err != nil {
		return err
	}
	if !u.SelfService {
		return ErrNoSelfService
	}
	if err := h.DeleteDevice(ctx, deviceID, store.UserActor(u.ID), ip); err != nil {
		return err
	}
	h.event(ctx, "self_service_delete", "warn", d.InterfaceID, d.ID,
		fmt.Sprintf("«%s» удалил своё устройство «%s» (%s)", u.Name, d.Name, d.Address))
	return nil
}

// PortalConfig выдаёт конфиг своего устройства.
func (h *Hub) PortalConfig(ctx context.Context, u store.User, deviceID int64, endpoint, ip string) (Config, error) {
	if _, err := h.ownDevice(ctx, u, deviceID); err != nil {
		return Config{}, err
	}
	return h.DeviceConfig(ctx, deviceID, endpoint, store.UserActor(u.ID), ip)
}

// ownDevice проверяет, что устройство принадлежит этому пользователю: чужой id в адресе
// не должен открывать чужие ключи.
func (h *Hub) ownDevice(ctx context.Context, u store.User, deviceID int64) (store.Device, error) {
	d, err := h.Store.DeviceByID(ctx, deviceID)
	if err != nil {
		return store.Device{}, err
	}
	if d.UserID != u.ID || !d.DeletedAt.IsZero() {
		return store.Device{}, store.ErrNotFound
	}
	return d, nil
}
