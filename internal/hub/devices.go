package hub

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/poznik/awgdash-pub/internal/awg"
	"github.com/poznik/awgdash-pub/internal/clientconf"
	"github.com/poznik/awgdash-pub/internal/node"
	"github.com/poznik/awgdash-pub/internal/qr"
	"github.com/poznik/awgdash-pub/internal/store"
	"github.com/poznik/awgdash-pub/internal/wgkey"
)

// ModeOwn — интерфейсом владеет панель: только в этом режиме она пишет пиров (SPEC §4.4).
const ModeOwn = "own"

// NewDevice — запрос на создание устройства (FR-3.1).
type NewDevice struct {
	UserID      int64
	InterfaceID int64
	Name        string
	Preset      string
	Overrides   store.Overrides
	Note        string
	CreatedBy   string // admin | user | import
	Actor       string // для аудита
	IP          string
}

// CreateDevice заводит устройство: ключи и адрес — на хабе, пир — на интерфейсе (если режим own).
// В режиме observe запись не выполняется: устройство появляется в БД и встанет на интерфейс при
// переходе в own — так соблюдается правило «на интерфейсе один писатель».
func (h *Hub) CreateDevice(ctx context.Context, req NewDevice) (store.Device, error) {
	iface, err := h.Interface(ctx, req.InterfaceID)
	if err != nil {
		return store.Device{}, err
	}
	// Сервер выведен из парка: заводить на нём устройство бессмысленно — оно не подключится,
	// а человек получит мёртвый конфиг (SPEC FR-10.6).
	if srv, err := h.Store.ServerByID(ctx, iface.ServerID); err == nil && srv.Retired() {
		return store.Device{}, fmt.Errorf("сервер %s выведен из парка — выберите живой", srv.Title)
	}
	pair, err := wgkey.Generate()
	if err != nil {
		return store.Device{}, err
	}
	psk := ""
	if iface.PSKEnabled {
		if psk, err = wgkey.PSK(); err != nil {
			return store.Device{}, err
		}
	}
	addr, err := h.Store.NextAddress(ctx, iface)
	if err != nil {
		return store.Device{}, err
	}
	preset := req.Preset
	if preset == "" {
		preset = store.PresetPhone
	}
	// Имя не вписали — берём то самое, что форма показывала серым: имя по умолчанию живёт на
	// сервере, а не в поле ввода, иначе его приходится стирать перед тем, как назвать своё.
	if strings.TrimSpace(req.Name) == "" {
		name, err := h.Store.DefaultDeviceName(ctx, req.UserID)
		if err != nil {
			return store.Device{}, err
		}
		req.Name = name
	}
	dev := store.Device{
		UserID: req.UserID, InterfaceID: iface.ID, Name: req.Name, Preset: preset,
		PrivateKey: pair.Private, PublicKey: pair.Public, PresharedKey: psk,
		Address: addr, Overrides: req.Overrides, Status: "active", CreatedBy: req.CreatedBy, Note: req.Note,
	}
	id, err := h.Store.CreateDevice(ctx, dev)
	if err != nil {
		return store.Device{}, err
	}
	dev.ID = id
	if err := h.applyDevice(ctx, iface, dev); err != nil {
		// Пир не встал — устройства в БД быть не должно: адрес и имя освобождаются.
		if delErr := h.Store.DeleteDevice(ctx, id); delErr == nil {
			h.Store.PurgeDeleted(ctx, 0)
		}
		return store.Device{}, err
	}
	h.audit(ctx, req.Actor, "device.create", "device", id, req.IP, map[string]any{
		"user_id": req.UserID, "interface": iface.Name, "name": dev.Name, "address": addr, "preset": preset,
	})
	h.event(ctx, "device_created", "info", iface.ID, id, fmt.Sprintf("устройство «%s» создано (%s)", dev.Name, addr))
	return h.Store.DeviceByID(ctx, id)
}

// SetDeviceStatus включает или выключает устройство: пир снимается и возвращается теми же ключами (FR-3.3).
func (h *Hub) SetDeviceStatus(ctx context.Context, id int64, status, actor, ip string) error {
	dev, err := h.Store.DeviceByID(ctx, id)
	if err != nil {
		return err
	}
	if err := h.Store.SetDeviceStatus(ctx, id, status); err != nil {
		return err
	}
	dev.Status = status
	iface, err := h.Interface(ctx, dev.InterfaceID)
	if err != nil {
		return err
	}
	if err := h.applyDevice(ctx, iface, dev); err != nil {
		h.Store.SetDeviceStatus(ctx, id, invertStatus(status))
		return err
	}
	h.audit(ctx, actor, "device."+status, "device", id, ip, map[string]any{"name": dev.Name, "interface": iface.Name})
	return nil
}

// DeleteDevice мягко удаляет устройство и снимает его пир (FR-3.4).
func (h *Hub) DeleteDevice(ctx context.Context, id int64, actor, ip string) error {
	dev, err := h.Store.DeviceByID(ctx, id)
	if err != nil {
		return err
	}
	iface, err := h.Interface(ctx, dev.InterfaceID)
	if err != nil {
		return err
	}
	if err := h.removePeer(ctx, iface, dev.PublicKey); err != nil {
		return err
	}
	if err := h.Store.DeleteDevice(ctx, id); err != nil {
		return err
	}
	h.audit(ctx, actor, "device.delete", "device", id, ip, map[string]any{"name": dev.Name, "interface": iface.Name, "address": dev.Address})
	h.event(ctx, "device_deleted", "info", iface.ID, id, fmt.Sprintf("устройство «%s» удалено", dev.Name))
	return nil
}

// RotateKeys перевыпускает ключи устройства, сохраняя адрес (FR-3.5).
func (h *Hub) RotateKeys(ctx context.Context, id int64, actor, ip string) (store.Device, error) {
	dev, err := h.Store.DeviceByID(ctx, id)
	if err != nil {
		return store.Device{}, err
	}
	iface, err := h.Interface(ctx, dev.InterfaceID)
	if err != nil {
		return store.Device{}, err
	}
	pair, err := wgkey.Generate()
	if err != nil {
		return store.Device{}, err
	}
	psk := dev.PresharedKey
	if iface.PSKEnabled {
		if psk, err = wgkey.PSK(); err != nil {
			return store.Device{}, err
		}
	}
	oldPub := dev.PublicKey
	if err := h.Store.RotateKeys(ctx, id, pair.Private, pair.Public, psk); err != nil {
		return store.Device{}, err
	}
	dev.PrivateKey, dev.PublicKey, dev.PresharedKey = pair.Private, pair.Public, psk
	if err := h.removePeer(ctx, iface, oldPub); err != nil {
		return store.Device{}, err
	}
	if err := h.applyDevice(ctx, iface, dev); err != nil {
		return store.Device{}, err
	}
	h.audit(ctx, actor, "device.rotate_keys", "device", id, ip, map[string]any{"name": dev.Name, "interface": iface.Name})
	h.event(ctx, "device_keys_rotated", "warn", iface.ID, id, fmt.Sprintf("у устройства «%s» перевыпущены ключи — прежний конфиг больше не работает", dev.Name))
	return h.Store.DeviceByID(ctx, id)
}

// SetUserStatus включает или выключает пользователя вместе со всеми его устройствами (FR-2.2).
func (h *Hub) SetUserStatus(ctx context.Context, userID int64, status, actor, ip string) error {
	if err := h.Store.SetUserStatus(ctx, userID, status); err != nil {
		return err
	}
	devs, err := h.Store.DevicesByUser(ctx, userID)
	if err != nil {
		return err
	}
	for _, d := range devs {
		iface, err := h.Interface(ctx, d.InterfaceID)
		if err != nil {
			return err
		}
		if err := h.applyDevice(ctx, iface, d); err != nil {
			return err
		}
	}
	u, err := h.Store.UserByID(ctx, userID)
	if err != nil {
		return err
	}
	h.audit(ctx, actor, "user."+status, "user", userID, ip, map[string]any{"name": u.Name, "devices": len(devs)})
	h.event(ctx, "user_"+status, "info", 0, 0, fmt.Sprintf("пользователь «%s» %s (устройств: %d)", u.Name, map[string]string{"active": "включён", "disabled": "отключён"}[status], len(devs)))
	return nil
}

// DeleteUser мягко удаляет пользователя, предварительно сняв пиры его устройств (FR-2.3).
func (h *Hub) DeleteUser(ctx context.Context, userID int64, actor, ip string) error {
	u, err := h.Store.UserByID(ctx, userID)
	if err != nil {
		return err
	}
	devs, err := h.Store.DevicesByUser(ctx, userID)
	if err != nil {
		return err
	}
	for _, d := range devs {
		iface, err := h.Interface(ctx, d.InterfaceID)
		if err != nil {
			return err
		}
		if err := h.removePeer(ctx, iface, d.PublicKey); err != nil {
			return err
		}
	}
	if err := h.Store.DeleteUser(ctx, userID); err != nil {
		return err
	}
	h.audit(ctx, actor, "user.delete", "user", userID, ip, map[string]any{"name": u.Name, "devices": len(devs)})
	h.event(ctx, "user_deleted", "warn", 0, 0, fmt.Sprintf("пользователь «%s» удалён (устройств: %d)", u.Name, len(devs)))
	return nil
}

// Config собирает конфиг устройства и QR к нему (FR-4.1, FR-4.4). Выдача отмечается в аудите.
type Config struct {
	Device   store.Device
	Endpoint store.Endpoint
	Text     string
	SVG      string
	FileName string
	TooLong  bool
}

// DeviceConfig выдаёт конфиг устройства для выбранного варианта endpoint.
func (h *Hub) DeviceConfig(ctx context.Context, deviceID int64, endpointLabel, actor, ip string) (Config, error) {
	dev, err := h.Store.DeviceByID(ctx, deviceID)
	if err != nil {
		return Config{}, err
	}
	iface, err := h.Interface(ctx, dev.InterfaceID)
	if err != nil {
		return Config{}, err
	}
	// Конфиг с выведенного сервера не подключится никогда — выдавать его хуже, чем отказать
	// и объяснить (SPEC FR-10.6).
	if srv, err := h.Store.ServerByID(ctx, iface.ServerID); err == nil && srv.Retired() {
		return Config{}, fmt.Errorf("сервер %s выведен из парка — заведите устройство на живом сервере", srv.Title)
	}
	ep, err := clientconf.EndpointByLabel(iface, endpointLabel)
	if err != nil {
		return Config{}, err
	}
	text, err := clientconf.Build(iface, dev, ep)
	if err != nil {
		return Config{}, err
	}
	svg, err := qr.SVG(text)
	if err != nil {
		return Config{}, err
	}
	if err := h.Store.MarkIssued(ctx, deviceID); err != nil {
		return Config{}, err
	}
	// В аудит попадает только факт выдачи: ни ключей, ни текста конфига (FR-4.6).
	h.audit(ctx, actor, "device.config_issued", "device", deviceID, ip, map[string]any{
		"name": dev.Name, "interface": iface.Name, "endpoint": ep.Label,
	})
	return Config{
		Device: dev, Endpoint: ep, Text: text, SVG: svg,
		FileName: clientconf.FileName(dev.UserName, dev.Name), TooLong: qr.TooLong(text),
	}, nil
}

// ReconcileInterface приводит интерфейс к желаемому состоянию из БД (SPEC §4.3).
func (h *Hub) ReconcileInterface(ctx context.Context, ifaceID int64, actor, ip string) (node.ReconcileResult, error) {
	iface, err := h.Interface(ctx, ifaceID)
	if err != nil {
		return node.ReconcileResult{}, err
	}
	if iface.Mode != ModeOwn {
		return node.ReconcileResult{}, fmt.Errorf("интерфейс %s в режиме %s — панель им не владеет", iface.Name, iface.Mode)
	}
	desired, err := h.desiredPeers(ctx, iface)
	if err != nil {
		return node.ReconcileResult{}, err
	}
	agent, err := h.Agent(iface.ServerID)
	if err != nil {
		return node.ReconcileResult{}, err
	}
	res, err := agent.Reconcile(ctx, iface.Name, desired, false)
	if err != nil {
		h.guardEvent(ctx, iface, err)
		return res, err
	}
	if res.Changed() {
		h.audit(ctx, actor, "interface.reconcile", "interface", iface.ID, ip, map[string]any{
			"interface": iface.Name, "added": len(res.Added), "updated": len(res.Updated), "removed": len(res.Removed),
		})
	}
	return res, nil
}

// PlanReconcile считает разницу между БД и интерфейсом, ничего не меняя (в том числе в observe).
func (h *Hub) PlanReconcile(ctx context.Context, ifaceID int64) (node.ReconcileResult, error) {
	iface, err := h.Interface(ctx, ifaceID)
	if err != nil {
		return node.ReconcileResult{}, err
	}
	desired, err := h.desiredPeers(ctx, iface)
	if err != nil {
		return node.ReconcileResult{}, err
	}
	agent, err := h.Agent(iface.ServerID)
	if err != nil {
		return node.ReconcileResult{}, err
	}
	return agent.PlanReconcile(ctx, iface.Name, desired, true)
}

// desiredPeers — желаемое состояние интерфейса: активные устройства активных пользователей.
func (h *Hub) desiredPeers(ctx context.Context, iface store.Interface) ([]awg.PeerSpec, error) {
	devs, err := h.Store.DevicesByInterface(ctx, iface.ID, true)
	if err != nil {
		return nil, err
	}
	out := make([]awg.PeerSpec, 0, len(devs))
	for _, d := range devs {
		out = append(out, peerSpec(d))
	}
	return out, nil
}

// peerSpec — как устройство выглядит на сервере: адрес /32 и PSK, без клиентских AllowedIPs.
// addrPrefix — адрес устройства как префикс для allowed-ips. Обычно в БД лежит голый адрес
// (10.20.0.7), и маску /32 добавляет панель. У усыновлённых служебных пиров там уже записан
// префикс: у межсерверных туннелей ru это 0.0.0.0/0, и вторая маска превращала его в мусор
// «0.0.0.0/0/32» — такая строка ушла бы в конфиг интерфейса, а сверка на ней спотыкалась.
func addrPrefix(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" || strings.Contains(addr, "/") {
		return addr
	}
	return addr + "/32"
}

func peerSpec(d store.Device) awg.PeerSpec {
	return awg.PeerSpec{PublicKey: d.PublicKey, PresharedKey: d.PresharedKey, AllowedIPs: []string{addrPrefix(d.Address)}}
}

// applyDevice ставит или снимает пир по текущему состоянию устройства и его владельца.
func (h *Hub) applyDevice(ctx context.Context, iface store.Interface, d store.Device) error {
	if iface.Mode != ModeOwn {
		return nil // observe: панель наблюдает, но не пишет
	}
	active := d.Active()
	if active {
		u, err := h.Store.UserByID(ctx, d.UserID)
		if err != nil {
			return err
		}
		active = !u.Disabled() && u.DeletedAt.IsZero()
	}
	agent, err := h.Agent(iface.ServerID)
	if err != nil {
		return err
	}
	if active {
		err = agent.ApplyPeer(ctx, iface.Name, peerSpec(d))
	} else {
		err = agent.RemovePeer(ctx, iface.Name, d.PublicKey)
	}
	if err != nil {
		h.guardEvent(ctx, iface, err)
		return err
	}
	// Пир записан, но «стоит ли он на интерфейсе» панель знает только из обхода — а он раз в
	// пятнадцать секунд. Всё это время свежесозданное устройство честно показывалось красным
	// «нет на интерфейсе», хотя работало. Внеочередная выборка закрывает окно; она же дешёвая:
	// SampleNow не чаще раза в пять секунд на интерфейс.
	h.SampleNow(ctx, iface.ID)
	return nil
}

// removePeer снимает пир, если панель владеет интерфейсом.
func (h *Hub) removePeer(ctx context.Context, iface store.Interface, pub string) error {
	if iface.Mode != ModeOwn || pub == "" {
		return nil
	}
	agent, err := h.Agent(iface.ServerID)
	if err != nil {
		return err
	}
	if err := agent.RemovePeer(ctx, iface.Name, pub); err != nil {
		h.guardEvent(ctx, iface, err)
		return err
	}
	return nil
}

// Interface возвращает интерфейс по id.
func (h *Hub) Interface(ctx context.Context, id int64) (store.Interface, error) {
	list, err := h.Store.Interfaces(ctx, 0)
	if err != nil {
		return store.Interface{}, err
	}
	for _, i := range list {
		if i.ID == id {
			return i, nil
		}
	}
	return store.Interface{}, fmt.Errorf("интерфейс %d не найден", id)
}

// guardEvent превращает отказ охранной проверки в событие `guard` (FR-1.3).
func (h *Hub) guardEvent(ctx context.Context, iface store.Interface, err error) {
	var ge *node.GuardError
	if !errors.As(err, &ge) {
		return
	}
	h.event(ctx, "guard", "warn", iface.ID, 0, fmt.Sprintf("запись в %s отклонена: %s", iface.Name, ge.Reason))
}

func (h *Hub) audit(ctx context.Context, actor, action, targetType string, targetID int64, ip string, details map[string]any) {
	if actor == "" {
		actor = store.ActorAdmin
	}
	if err := h.Store.AddAudit(ctx, store.AuditEntry{Actor: actor, Action: action, TargetType: targetType, TargetID: targetID, IP: ip, Details: details}); err != nil {
		h.Log.Warn("аудит", "action", action, "err", err)
	}
	// Любое записанное действие меняет состояние панели — значит, нужна свежая копия (FR-9.3).
	h.MarkChanged()
}

func (h *Hub) event(ctx context.Context, kind, severity string, ifaceID, deviceID int64, message string) {
	h.eventOn(ctx, h.ServerID, kind, severity, ifaceID, deviceID, message)
}

// eventOn — событие, привязанное к конкретному серверу парка.
func (h *Hub) eventOn(ctx context.Context, serverID int64, kind, severity string, ifaceID, deviceID int64, message string) {
	e := store.Event{Kind: kind, Severity: severity, ServerID: serverID, InterfaceID: ifaceID, DeviceID: deviceID, Message: message}
	if err := h.Store.AddEvent(ctx, e); err != nil {
		h.Log.Warn("событие", "kind", kind, "err", err)
	}
}

func invertStatus(s string) string {
	if s == "active" {
		return "disabled"
	}
	return "active"
}

// ModeCheck — одна предпроверка перед переходом в own (FR-1.2).
type ModeCheck struct {
	Title string `json:"title"`
	OK    bool   `json:"ok"`
	Note  string `json:"note,omitempty"`
}

// ModeReadiness — готовность интерфейса к режиму own: список проверок и нераспределённые пиры.
type ModeReadiness struct {
	Interface  string      `json:"interface"`
	Mode       string      `json:"mode"`
	Ready      bool        `json:"ready"`
	Checks     []ModeCheck `json:"checks"`
	Unassigned []string    `json:"unassigned"`
}

// ModeReadiness собирает проверки, не меняя ничего: их же показывает кнопка «перейти в own».
// live=false берёт последние известные факты из БД и кэша — так страницу можно открывать часто,
// не дёргая systemctl и awg на каждый показ; live=true спрашивает узел заново.
func (h *Hub) ModeReadiness(ctx context.Context, ifaceID int64, live bool) (ModeReadiness, error) {
	iface, err := h.Interface(ctx, ifaceID)
	if err != nil {
		return ModeReadiness{}, err
	}
	out := ModeReadiness{Interface: iface.Name, Mode: iface.Mode}
	add := func(title string, ok bool, note string) {
		out.Checks = append(out.Checks, ModeCheck{Title: title, OK: ok, Note: note})
	}

	agent, err := h.Agent(iface.ServerID)
	if err != nil {
		return out, err
	}
	fm := h.ForeignManagerOf(iface.ServerID)
	if live {
		fm = agent.ForeignManagerActive(ctx)
	}
	add("чужой менеджер пиров неактивен", fm == "", fm)

	if live {
		raw, err := agent.ConfRaw(ctx, iface.Name)
		if err != nil {
			return out, err
		}
		conf, err := awg.Parse(raw)
		if err != nil {
			return out, err
		}
		add("SaveConfig = false", !conf.SaveConfigEnabled(), "")
		res, err := agent.Verify(ctx, iface.Name)
		if err != nil {
			add("обфускация файла и рантайма совпадает", false, err.Error())
		} else {
			add("обфускация файла и рантайма совпадает", res.OK, fmt.Sprintf("%d/%d", res.Matched, res.Total))
		}
	} else {
		add("SaveConfig = false", !iface.SaveConfig, "")
		verified := iface.LastVerifyOK != nil && *iface.LastVerifyOK
		note := "сверка " + iface.LastVerifiedAt.Format("15:04")
		if iface.LastVerifiedAt.IsZero() {
			note = "сверки ещё не было"
		}
		add("обфускация файла и рантайма совпадает", verified, note)
	}

	peers, err := h.Store.Peers(ctx, iface.ID, false)
	if err != nil {
		return out, err
	}
	for _, p := range peers {
		if !p.DeviceID.Valid {
			out.Unassigned = append(out.Unassigned, p.PublicKey+" ("+p.AllowedIPs+")")
		}
	}
	add("все пиры интерфейса сопоставлены устройствам", len(out.Unassigned) == 0,
		fmt.Sprintf("нераспределённых: %d", len(out.Unassigned)))

	out.Ready = true
	for _, c := range out.Checks {
		if !c.OK {
			out.Ready = false
		}
	}
	return out, nil
}

// SwitchInterfaceMode переключает режим интерфейса. Переход в own разрешён только когда все
// предпроверки зелёные; возврат в observe возможен всегда — это откат (SPEC §10).
func (h *Hub) SwitchInterfaceMode(ctx context.Context, ifaceID int64, mode, actor, ip string) (ModeReadiness, error) {
	rd, err := h.ModeReadiness(ctx, ifaceID, true)
	if err != nil {
		return rd, err
	}
	if mode == ModeOwn && !rd.Ready {
		return rd, fmt.Errorf("интерфейс %s не готов к режиму own: %s", rd.Interface, failedChecks(rd))
	}
	if err := h.Store.SetInterfaceMode(ctx, ifaceID, mode); err != nil {
		return rd, err
	}
	rd.Mode = mode
	h.audit(ctx, actor, "interface.mode", "interface", ifaceID, ip, map[string]any{"interface": rd.Interface, "mode": mode})
	h.event(ctx, "interface_mode", "warn", ifaceID, 0, fmt.Sprintf("интерфейс %s переведён в режим %s", rd.Interface, mode))
	return rd, nil
}

func failedChecks(rd ModeReadiness) string {
	var out []string
	for _, c := range rd.Checks {
		if c.OK {
			continue
		}
		s := c.Title
		if c.Note != "" {
			s += " (" + c.Note + ")"
		}
		out = append(out, s)
	}
	return strings.Join(out, "; ")
}

// ---------- пользователи ----------

// NewUser — запрос на создание пользователя (FR-2.1).
type NewUser struct {
	Name        string
	Note        string
	SelfService bool
	MaxDevices  int
	InterfaceID int64
	// Allowed — на какие интерфейсы пользователю разрешено сажать устройства из портала.
	Allowed   []int64
	ExpiresAt time.Time
	Actor     string
	IP        string
}

// CreateUser заводит пользователя и сразу выдаёт персональную ссылку.
func (h *Hub) CreateUser(ctx context.Context, req NewUser) (store.User, string, error) {
	id, token, err := h.Store.CreateUser(ctx, store.User{
		Name: req.Name, Note: req.Note, SelfService: req.SelfService, MaxDevices: req.MaxDevices,
		DefaultInterfaceID: req.InterfaceID, AllowedInterfaces: req.Allowed, ExpiresAt: req.ExpiresAt,
	})
	if err != nil {
		return store.User{}, "", err
	}
	h.audit(ctx, req.Actor, "user.create", "user", id, req.IP, map[string]any{"name": req.Name, "self_service": req.SelfService})
	h.event(ctx, "user_created", "info", 0, 0, fmt.Sprintf("пользователь «%s» создан", req.Name))
	u, err := h.Store.UserByID(ctx, id)
	return u, token, err
}

// UpdateUser сохраняет правки карточки и приводит пиры к новому состоянию:
// смена владельца или лимита может выключить устройства.
func (h *Hub) UpdateUser(ctx context.Context, u store.User, actor, ip string) error {
	if err := h.Store.UpdateUser(ctx, u); err != nil {
		return err
	}
	h.audit(ctx, actor, "user.update", "user", u.ID, ip, map[string]any{"name": u.Name, "max_devices": u.MaxDevices, "self_service": u.SelfService})
	return h.applyUserDevices(ctx, u.ID)
}

// RestoreUser достаёт пользователя из корзины; устройства возвращаются выключенными.
func (h *Hub) RestoreUser(ctx context.Context, userID int64, actor, ip string) error {
	if err := h.Store.RestoreUser(ctx, userID); err != nil {
		return err
	}
	u, err := h.Store.UserByID(ctx, userID)
	if err != nil {
		return err
	}
	h.audit(ctx, actor, "user.restore", "user", userID, ip, map[string]any{"name": u.Name})
	h.event(ctx, "user_restored", "info", 0, 0, fmt.Sprintf("пользователь «%s» восстановлен, устройства выключены", u.Name))
	return nil
}

// IssueLink перевыпускает персональную ссылку: прежняя перестаёт работать (FR-2.4).
func (h *Hub) IssueLink(ctx context.Context, userID int64, actor, ip string) (string, error) {
	token, err := h.Store.IssueLink(ctx, userID)
	if err != nil {
		return "", err
	}
	u, _ := h.Store.UserByID(ctx, userID)
	h.audit(ctx, actor, "user.link_reissued", "user", userID, ip, map[string]any{"name": u.Name})
	h.event(ctx, "user_link_reissued", "warn", 0, 0, fmt.Sprintf("у пользователя «%s» перевыпущена ссылка — прежняя больше не работает", u.Name))
	return token, nil
}

// UpdateDevice сохраняет правки устройства (имя, пресет, переопределения, владелец).
func (h *Hub) UpdateDevice(ctx context.Context, d store.Device, actor, ip string) error {
	before, err := h.Store.DeviceByID(ctx, d.ID)
	if err != nil {
		return err
	}
	if err := h.Store.UpdateDevice(ctx, d); err != nil {
		return err
	}
	h.audit(ctx, actor, "device.update", "device", d.ID, ip, map[string]any{"name": d.Name, "preset": d.Preset})
	// Смена владельца могла сделать устройство активным или наоборот.
	if before.UserID != d.UserID {
		fresh, err := h.Store.DeviceByID(ctx, d.ID)
		if err != nil {
			return err
		}
		iface, err := h.Interface(ctx, fresh.InterfaceID)
		if err != nil {
			return err
		}
		return h.applyDevice(ctx, iface, fresh)
	}
	return nil
}

// RestoreDevice достаёт устройство из корзины выключенным (FR-3.4).
func (h *Hub) RestoreDevice(ctx context.Context, id int64, actor, ip string) error {
	if err := h.Store.RestoreDevice(ctx, id); err != nil {
		return err
	}
	d, err := h.Store.DeviceByID(ctx, id)
	if err != nil {
		return err
	}
	h.audit(ctx, actor, "device.restore", "device", id, ip, map[string]any{"name": d.Name, "address": d.Address})
	return nil
}

// applyUserDevices приводит пиры всех устройств пользователя к текущему состоянию.
func (h *Hub) applyUserDevices(ctx context.Context, userID int64) error {
	devs, err := h.Store.DevicesByUser(ctx, userID)
	if err != nil {
		return err
	}
	for _, d := range devs {
		iface, err := h.Interface(ctx, d.InterfaceID)
		if err != nil {
			return err
		}
		if err := h.applyDevice(ctx, iface, d); err != nil {
			return err
		}
	}
	return nil
}

// AdoptPeer превращает наблюдаемый, но ничей пир в устройство (FR-1.6). Ключи такого устройства
// панели неизвестны: конфиг для него не выдать, зато видно, чей он и сколько тратит.
func (h *Hub) AdoptPeer(ctx context.Context, ifaceID int64, publicKey string, userID int64, name, actor, ip string) (store.Device, error) {
	iface, err := h.Interface(ctx, ifaceID)
	if err != nil {
		return store.Device{}, err
	}
	peers, err := h.Store.Peers(ctx, ifaceID, false)
	if err != nil {
		return store.Device{}, err
	}
	var addr string
	for _, p := range peers {
		if p.PublicKey == publicKey {
			addr = strings.TrimSpace(strings.Split(p.AllowedIPs, ",")[0])
			addr = strings.TrimSuffix(addr, "/32")
		}
	}
	if addr == "" {
		return store.Device{}, fmt.Errorf("пир %s не найден на интерфейсе %s", publicKey, iface.Name)
	}
	// PSK берём из файла интерфейса: без него reconcile снял бы preshared-key с живого пира,
	// и клиент, у которого PSK прописан в конфиге, перестал бы подключаться.
	psk := ""
	agent, agentErr := h.Agent(iface.ServerID)
	if confPeers, err := agentConfPeers(ctx, agent, agentErr, iface.Name); err == nil {
		for _, p := range confPeers {
			if p.PublicKey == publicKey {
				psk = p.PresharedKey
			}
		}
	}
	id, err := h.Store.CreateDevice(ctx, store.Device{
		UserID: userID, InterfaceID: ifaceID, Name: name, PublicKey: publicKey, Address: addr,
		PresharedKey: psk, CreatedBy: "import", Note: "перенесён с интерфейса, приватный ключ неизвестен",
	})
	if err != nil {
		return store.Device{}, err
	}
	h.audit(ctx, actor, "device.adopt", "device", id, ip, map[string]any{"name": name, "interface": iface.Name, "address": addr})
	return h.Store.DeviceByID(ctx, id)
}

// agentConfPeers — вспомогательное: пиры файла у агента интерфейса, с уже случившейся
// ошибкой поиска агента. Отдельная функция, чтобы не городить вложенные проверки на месте.
func agentConfPeers(ctx context.Context, a Agent, err error, iface string) ([]awg.Peer, error) {
	if err != nil {
		return nil, err
	}
	return a.ConfPeers(ctx, iface)
}
