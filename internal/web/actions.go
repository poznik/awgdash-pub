package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/poznik/awgdash-pub/internal/auth"
	"github.com/poznik/awgdash-pub/internal/backup"
	"github.com/poznik/awgdash-pub/internal/hub"
	"github.com/poznik/awgdash-pub/internal/store"
)

// ---------- пользователи ----------

func (s *Server) userCreate(w http.ResponseWriter, r *http.Request, sc sessionCtx) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	req := hub.NewUser{
		Name:        strings.TrimSpace(r.PostFormValue("name")),
		Note:        strings.TrimSpace(r.PostFormValue("note")),
		SelfService: r.PostFormValue("self_service") != "",
		MaxDevices:  formInt(r, "max_devices", 5),
		Allowed:     formIDs(r, "allowed_iface"),
		ExpiresAt:   formDate(r, "expires_at"),
		Actor:       store.ActorAdmin,
		IP:          s.clientIP(r),
	}
	u, _, err := s.Hub.CreateUser(ctx, req)
	if err != nil {
		s.back(w, r, "/users", err)
		return
	}
	s.done(w, r, "/users/"+itoa(u.ID), "пользователь создан, ссылка выдана")
}

func (s *Server) userUpdate(w http.ResponseWriter, r *http.Request, sc sessionCtx) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	id := atoi64(r.PathValue("id"))
	u, err := s.Hub.Store.UserByID(ctx, id)
	if err != nil {
		s.back(w, r, "/users", err)
		return
	}
	u.Name = strings.TrimSpace(r.PostFormValue("name"))
	u.Note = strings.TrimSpace(r.PostFormValue("note"))
	u.SelfService = r.PostFormValue("self_service") != ""
	u.MaxDevices = formInt(r, "max_devices", u.MaxDevices)
	// Список разрешённых серверов приходит чекбоксами; форма без них (один интерфейс в парке)
	// оставляет прежнее значение, а не обнуляет его.
	if _, ok := r.PostForm["allowed_iface_present"]; ok {
		u.AllowedInterfaces = formIDs(r, "allowed_iface")
	}
	u.ExpiresAt = formDate(r, "expires_at")
	if v := formInt64(r, "interface_id"); v != 0 {
		u.DefaultInterfaceID = v
	}
	if err := s.Hub.UpdateUser(ctx, u, store.ActorAdmin, s.clientIP(r)); err != nil {
		s.back(w, r, "/users/"+itoa(id), err)
		return
	}
	s.done(w, r, "/users/"+itoa(id), "сохранено")
}

func (s *Server) userStatus(w http.ResponseWriter, r *http.Request, sc sessionCtx) {
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	id := atoi64(r.PathValue("id"))
	status := r.PostFormValue("status")
	if err := s.Hub.SetUserStatus(ctx, id, status, store.ActorAdmin, s.clientIP(r)); err != nil {
		s.back(w, r, "/users/"+itoa(id), err)
		return
	}
	msg := "пользователь включён, устройства вернулись на интерфейс"
	if status == "disabled" {
		msg = "пользователь отключён, его пиры сняты"
	}
	s.done(w, r, "/users/"+itoa(id), msg)
}

func (s *Server) userDelete(w http.ResponseWriter, r *http.Request, sc sessionCtx) {
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	id := atoi64(r.PathValue("id"))
	if err := s.Hub.DeleteUser(ctx, id, store.ActorAdmin, s.clientIP(r)); err != nil {
		s.back(w, r, "/users/"+itoa(id), err)
		return
	}
	s.done(w, r, "/users?trash=1", "пользователь в корзине, окончательная очистка через 30 дней")
}

func (s *Server) userRestore(w http.ResponseWriter, r *http.Request, sc sessionCtx) {
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	id := atoi64(r.PathValue("id"))
	if err := s.Hub.RestoreUser(ctx, id, store.ActorAdmin, s.clientIP(r)); err != nil {
		s.back(w, r, "/users?trash=1", err)
		return
	}
	s.done(w, r, "/users/"+itoa(id), "пользователь восстановлен, устройства выключены")
}

func (s *Server) userLink(w http.ResponseWriter, r *http.Request, sc sessionCtx) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	id := atoi64(r.PathValue("id"))
	if _, err := s.Hub.IssueLink(ctx, id, store.ActorAdmin, s.clientIP(r)); err != nil {
		s.back(w, r, "/users/"+itoa(id), err)
		return
	}
	s.done(w, r, "/users/"+itoa(id), "ссылка перевыпущена, прежняя больше не работает")
}

// ---------- устройства ----------

func (s *Server) deviceCreate(w http.ResponseWriter, r *http.Request, sc sessionCtx) {
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	userID := atoi64(r.PathValue("id"))
	u, err := s.Hub.Store.UserByID(ctx, userID)
	if err != nil {
		s.back(w, r, "/users", err)
		return
	}
	// Сервер выбирается у устройства, а не у человека: пустое поле означает «тот, где панель».
	ifaceID := formInt64(r, "interface_id")
	if ifaceID != 0 && !u.Allows(ifaceID) {
		s.back(w, r, "/users/"+itoa(userID), errors.New("этот сервер пользователю не разрешён"))
		return
	}
	if ifaceID == 0 {
		def, err := s.Hub.DefaultInterface(ctx)
		if err != nil {
			s.back(w, r, "/users/"+itoa(userID), err)
			return
		}
		ifaceID = def
	}
	dev, err := s.Hub.CreateDevice(ctx, hub.NewDevice{
		UserID: userID, InterfaceID: ifaceID,
		Name:   strings.TrimSpace(r.PostFormValue("name")),
		Preset: r.PostFormValue("preset"),
		// Переопределения задаются сразу при создании: иначе конфиг придётся перевыпускать.
		Overrides: store.Overrides{
			AllowedIPs: strings.TrimSpace(r.PostFormValue("allowed_ips")),
			DNS:        strings.TrimSpace(r.PostFormValue("dns")),
			MTU:        formInt(r, "mtu", 0),
			Keepalive:  formInt(r, "keepalive", 0),
		},
		CreatedBy: "admin", Actor: store.ActorAdmin, IP: s.clientIP(r),
	})
	if err != nil {
		s.back(w, r, "/users/"+itoa(userID), err)
		return
	}
	s.done(w, r, "/devices/"+itoa(dev.ID)+"/config", "устройство создано — вот конфиг")
}

func (s *Server) deviceStatus(w http.ResponseWriter, r *http.Request, sc sessionCtx) {
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	id := atoi64(r.PathValue("id"))
	back := s.deviceBack(ctx, id)
	status := r.PostFormValue("status")
	if err := s.Hub.SetDeviceStatus(ctx, id, status, store.ActorAdmin, s.clientIP(r)); err != nil {
		s.back(w, r, back, err)
		return
	}
	msg := "устройство включено, пир вернулся"
	if status == "disabled" {
		msg = "устройство отключено, пир снят"
	}
	s.done(w, r, back, msg)
}

func (s *Server) deviceDelete(w http.ResponseWriter, r *http.Request, sc sessionCtx) {
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	id := atoi64(r.PathValue("id"))
	back := s.deviceBack(ctx, id)
	if err := s.Hub.DeleteDevice(ctx, id, store.ActorAdmin, s.clientIP(r)); err != nil {
		s.back(w, r, back, err)
		return
	}
	s.done(w, r, back, "устройство в корзине, адрес держится за ним 30 дней")
}

func (s *Server) deviceRestore(w http.ResponseWriter, r *http.Request, sc sessionCtx) {
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	id := atoi64(r.PathValue("id"))
	back := s.deviceBack(ctx, id)
	if err := s.Hub.RestoreDevice(ctx, id, store.ActorAdmin, s.clientIP(r)); err != nil {
		s.back(w, r, back, err)
		return
	}
	s.done(w, r, back, "устройство восстановлено выключенным")
}

func (s *Server) deviceRotate(w http.ResponseWriter, r *http.Request, sc sessionCtx) {
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	id := atoi64(r.PathValue("id"))
	if _, err := s.Hub.RotateKeys(ctx, id, store.ActorAdmin, s.clientIP(r)); err != nil {
		s.back(w, r, s.deviceBack(ctx, id), err)
		return
	}
	s.done(w, r, "/devices/"+itoa(id)+"/config", "ключи перевыпущены — прежний конфиг больше не работает")
}

func (s *Server) deviceUpdate(w http.ResponseWriter, r *http.Request, sc sessionCtx) {
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	id := atoi64(r.PathValue("id"))
	d, err := s.Hub.Store.DeviceByID(ctx, id)
	if err != nil {
		s.back(w, r, "/users", err)
		return
	}
	d.Name = strings.TrimSpace(r.PostFormValue("name"))
	if v := r.PostFormValue("preset"); v != "" {
		d.Preset = v
	}
	d.Overrides = store.Overrides{
		AllowedIPs: strings.TrimSpace(r.PostFormValue("allowed_ips")),
		DNS:        strings.TrimSpace(r.PostFormValue("dns")),
		MTU:        formInt(r, "mtu", 0),
		Keepalive:  formInt(r, "keepalive", 0),
	}
	if err := s.Hub.UpdateDevice(ctx, d, store.ActorAdmin, s.clientIP(r)); err != nil {
		s.back(w, r, "/devices/"+itoa(id), err)
		return
	}
	// Конфиг показываем только тому устройству, для которого его есть из чего собрать: у
	// усыновлённого пира приватного ключа у панели нет, и страница выдачи ответила бы ошибкой.
	if !d.HasKey() {
		s.done(w, r, "/devices/"+itoa(id), "сохранено; конфиг панель выдать не может — приватный ключ ей неизвестен")
		return
	}
	s.done(w, r, "/devices/"+itoa(id)+"/config", "сохранено; переустановите конфиг на устройстве")
}

// deviceMove передаёт устройство другому человеку (FR-3.9). Ключи и адрес остаются прежними:
// клиент переезда не замечает, переустанавливать конфиг не нужно.
func (s *Server) deviceMove(w http.ResponseWriter, r *http.Request, sc sessionCtx) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	id := atoi64(r.PathValue("id"))
	back := "/devices/" + itoa(id)
	to := formInt64(r, "user_id")
	if to == 0 {
		s.back(w, r, back, errors.New("не выбран новый владелец"))
		return
	}
	owner, err := s.Hub.Store.UserByID(ctx, to)
	if err != nil {
		s.back(w, r, back, errors.New("новый владелец не найден"))
		return
	}
	res, err := s.Hub.MoveDevices(ctx, hub.MoveRequest{
		DeviceIDs: []int64{id}, ToUserID: to, RaiseLimit: r.PostFormValue("raise_limit") != "",
		Actor: store.ActorAdmin, IP: s.clientIP(r),
	})
	if err != nil {
		s.back(w, r, back, err)
		return
	}
	s.done(w, r, back, sayMove(res, owner.Name))
}

// userMerge сводит двух людей в одного: устройства переезжают, опустевшего можно удалить тем же
// действием (FR-2.7).
func (s *Server) userMerge(w http.ResponseWriter, r *http.Request, sc sessionCtx) {
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	from := atoi64(r.PathValue("id"))
	back := "/users/" + itoa(from)
	to := formInt64(r, "user_id")
	if to == 0 {
		s.back(w, r, back, errors.New("не выбрано, к кому переносить"))
		return
	}
	res, err := s.Hub.MergeUsers(ctx, hub.MergeRequest{
		FromUserID: from, ToUserID: to,
		RaiseLimit:    r.PostFormValue("raise_limit") != "",
		DeleteEmptied: r.PostFormValue("delete_emptied") != "",
		Actor:         store.ActorAdmin, IP: s.clientIP(r),
	})
	if err != nil {
		s.back(w, r, back, err)
		return
	}
	s.done(w, r, "/users/"+itoa(to), sayMerge(res))
}

// deviceBack — куда возвращаться после действия с устройством: в карточку его владельца.
func (s *Server) deviceBack(ctx context.Context, deviceID int64) string {
	d, err := s.Hub.Store.DeviceByID(ctx, deviceID)
	if err != nil {
		return "/users"
	}
	return "/users/" + itoa(d.UserID)
}

// ---------- интерфейс ----------

func (s *Server) interfaceMode(w http.ResponseWriter, r *http.Request, sc sessionCtx) {
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	name := r.PathValue("name")
	iface, err := s.interfaceRef(ctx, name)
	if err != nil {
		s.back(w, r, "/interfaces", err)
		return
	}
	mode := r.PostFormValue("mode")
	rd, err := s.Hub.SwitchInterfaceMode(ctx, iface.ID, mode, store.ActorAdmin, s.clientIP(r))
	if err != nil {
		s.back(w, r, ifacePath(iface), err)
		return
	}
	s.done(w, r, ifacePath(iface), "режим интерфейса: "+rd.Mode)
}

func (s *Server) interfaceReconcile(w http.ResponseWriter, r *http.Request, sc sessionCtx) {
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	name := r.PathValue("name")
	iface, err := s.interfaceRef(ctx, name)
	if err != nil {
		s.back(w, r, "/interfaces", err)
		return
	}
	res, err := s.Hub.ReconcileInterface(ctx, iface.ID, store.ActorAdmin, s.clientIP(r))
	if err != nil {
		s.back(w, r, ifacePath(iface), err)
		return
	}
	if !res.Changed() {
		s.done(w, r, ifacePath(iface), "интерфейс уже совпадает с панелью")
		return
	}
	s.done(w, r, ifacePath(iface), "поставлено "+itoa(int64(len(res.Added)))+", обновлено "+itoa(int64(len(res.Updated)))+", снято "+itoa(int64(len(res.Removed))))
}

// peerAdopt заводит устройство для наблюдаемого, но ничьего пира (FR-1.6).
func (s *Server) peerAdopt(w http.ResponseWriter, r *http.Request, sc sessionCtx) {
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	name := r.PathValue("name")
	iface, err := s.interfaceRef(ctx, name)
	if err != nil {
		s.back(w, r, "/interfaces", err)
		return
	}
	pub := r.PostFormValue("public_key")
	userID := formInt64(r, "user_id")
	devName := strings.TrimSpace(r.PostFormValue("name"))
	if devName == "" {
		devName = adoptName(pub)
	}
	// Привязать пира можно и со страницы интерфейса, и из общего списка ничьих: возвращаемся
	// туда, откуда пришли. Чужие адреса не принимаем — только свои пути.
	back := ifacePath(iface)
	if v := r.PostFormValue("back"); strings.HasPrefix(v, "/") && !strings.HasPrefix(v, "//") {
		back = v
	}
	if userID == 0 {
		s.back(w, r, back, errors.New("не выбран владелец"))
		return
	}
	if _, err := s.Hub.AdoptPeer(ctx, iface.ID, pub, userID, devName, store.ActorAdmin, s.clientIP(r)); err != nil {
		s.back(w, r, back, err)
		return
	}
	s.done(w, r, back, "пир привязан к устройству; приватный ключ панели неизвестен")
}

// interfaceEndpoints сохраняет список вариантов endpoint: строки формы приходят параллельными
// массивами label[]/host[]/port[], основной отмечен номером строки.
func (s *Server) interfaceEndpoints(w http.ResponseWriter, r *http.Request, sc sessionCtx) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	name := r.PathValue("name")
	iface, err := s.interfaceRef(ctx, name)
	if err != nil {
		s.back(w, r, "/interfaces", err)
		return
	}
	labels, hosts, ports := r.PostForm["label"], r.PostForm["host"], r.PostForm["port"]
	primary := r.PostFormValue("primary")
	eps := make([]store.Endpoint, 0, len(hosts))
	for i := range hosts {
		e := store.Endpoint{Host: strings.TrimSpace(hosts[i]), Primary: itoa(int64(i)) == primary}
		if i < len(labels) {
			e.Label = strings.TrimSpace(labels[i])
		}
		if i < len(ports) {
			e.Port, _ = strconv.Atoi(strings.TrimSpace(ports[i]))
		}
		eps = append(eps, e)
	}
	if err := s.Hub.SetEndpoints(ctx, iface.ID, eps, store.ActorAdmin, s.clientIP(r)); err != nil {
		s.back(w, r, ifacePath(iface), err)
		return
	}
	s.done(w, r, ifacePath(iface), "варианты endpoint сохранены")
}

// interfaceDefaults сохраняет умолчания клиентского конфига: DNS, keepalive, AllowedIPs. Все три
// разом — так их принимает хранилище, и порознь они не читаются: пустой AllowedIPs оставил бы
// конфиг без маршрутов.
func (s *Server) interfaceDefaults(w http.ResponseWriter, r *http.Request, sc sessionCtx) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	name := r.PathValue("name")
	iface, err := s.interfaceRef(ctx, name)
	if err != nil {
		s.back(w, r, "/interfaces", err)
		return
	}
	dns := r.PostFormValue("dns")
	allowed := r.PostFormValue("allowed_ips")
	keepalive := formInt(r, "keepalive", iface.DefaultKeepalive)
	if err := s.Hub.SetInterfaceDefaults(ctx, iface.ID, dns, keepalive, allowed, store.ActorAdmin, s.clientIP(r)); err != nil {
		s.back(w, r, ifacePath(iface), err)
		return
	}
	s.done(w, r, ifacePath(iface), "умолчания сохранены — их получат конфиги следующей выдачи")
}

// interfaceForget убирает из панели интерфейс, которого больше нет на сервере (FR-1.9). Живой
// интерфейс так не убрать: хаб отказывает, пока обход его находит.
func (s *Server) interfaceForget(w http.ResponseWriter, r *http.Request, sc sessionCtx) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	name := r.PathValue("name")
	iface, err := s.interfaceRef(ctx, name)
	if err != nil {
		s.back(w, r, "/interfaces", err)
		return
	}
	b, err := s.Hub.ForgetInterface(ctx, iface.ID, store.ActorAdmin, s.clientIP(r))
	if err != nil {
		s.back(w, r, ifacePath(iface), err)
		return
	}
	s.done(w, r, "/", name+" убран из панели: снято "+plural(b.Devices, "устройство", "устройства", "устройств")+
		" и "+plural(b.Peers, "пир", "пира", "пиров"))
}

// ifacePath — адрес страницы интерфейса.
func ifacePath(i store.Interface) string { return "/interfaces/" + itoa(i.ID) }

// interfaceRef находит интерфейс по тому, что стоит в адресе. Канонический вид — идентификатор
// (`/interfaces/7`), как у людей и устройств: одно и то же имя живёт на разных машинах парка, и
// по имени панель показывала бы первый попавшийся. Имя принимается ради старых ссылок и ручного
// ввода; при совпадении имён берётся интерфейс той машины, что раньше попала в парк.
func (s *Server) interfaceRef(ctx context.Context, ref string) (store.Interface, error) {
	list, err := s.Hub.Store.Interfaces(ctx, 0)
	if err != nil {
		return store.Interface{}, err
	}
	if id := atoi64(ref); id > 0 {
		for _, i := range list {
			if i.ID == id {
				return i, nil
			}
		}
		return store.Interface{}, errors.New("интерфейс не найден")
	}
	for _, i := range list {
		if i.Name == ref {
			return i, nil
		}
	}
	return store.Interface{}, errors.New("интерфейс " + ref + " не найден")
}

// ---------- второй фактор ----------

// totpNew готовит новый секрет: страница настроек покажет QR, а включит его подтверждение кодом.
func (s *Server) totpNew(w http.ResponseWriter, r *http.Request, sc sessionCtx) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	secret, _, err := auth.NewTOTP("awgdash", sc.Admin.Username)
	if err != nil {
		s.back(w, r, "/settings", err)
		return
	}
	if err := s.Hub.Store.SetTOTP(ctx, sc.Admin.ID, secret, false); err != nil {
		s.back(w, r, "/settings", err)
		return
	}
	s.audit(r, store.ActorAdmin, "admin.totp_new", "admin", sc.Admin.ID, map[string]any{"username": sc.Admin.Username})
	s.done(w, r, "/settings", "секрет готов — отсканируйте QR и подтвердите кодом")
}

// totpEnable включает второй фактор, если код с телефона сходится.
func (s *Server) totpEnable(w http.ResponseWriter, r *http.Request, sc sessionCtx) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if sc.Admin.TOTPSecret == "" {
		s.back(w, r, "/settings", errors.New("секрет не подготовлен"))
		return
	}
	if !auth.VerifyTOTP(sc.Admin.TOTPSecret, r.PostFormValue("code"), time.Now()) {
		s.back(w, r, "/settings", errors.New("код не подошёл — проверьте время на телефоне и попробуйте ещё раз"))
		return
	}
	if err := s.Hub.Store.SetTOTP(ctx, sc.Admin.ID, sc.Admin.TOTPSecret, true); err != nil {
		s.back(w, r, "/settings", err)
		return
	}
	s.audit(r, store.ActorAdmin, "admin.totp_enabled", "admin", sc.Admin.ID, map[string]any{"username": sc.Admin.Username})
	s.done(w, r, "/settings", "второй фактор включён")
}

func (s *Server) totpDisable(w http.ResponseWriter, r *http.Request, sc sessionCtx) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if err := s.Hub.Store.SetTOTP(ctx, sc.Admin.ID, "", false); err != nil {
		s.back(w, r, "/settings", err)
		return
	}
	s.audit(r, store.ActorAdmin, "admin.totp_reset", "admin", sc.Admin.ID, map[string]any{"username": sc.Admin.Username})
	s.done(w, r, "/settings", "второй фактор выключен — вход снова по одному паролю")
}

// sessionsRevoke закрывает все сессии, кроме текущей.
func (s *Server) sessionsRevoke(w http.ResponseWriter, r *http.Request, sc sessionCtx) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	sessions, err := s.Hub.Store.Sessions(ctx, sc.Admin.ID)
	if err != nil {
		s.back(w, r, "/settings", err)
		return
	}
	closed := 0
	for _, ses := range sessions {
		if ses.ID == sc.Session.ID {
			continue
		}
		if err := s.Hub.Store.DeleteSession(ctx, ses.ID); err != nil {
			s.back(w, r, "/settings", err)
			return
		}
		closed++
	}
	s.audit(r, store.ActorAdmin, "admin.sessions_revoked", "admin", sc.Admin.ID, map[string]any{"closed": closed})
	s.done(w, r, "/settings", "закрыто сессий: "+itoa(int64(closed)))
}

// usersPurge очищает корзину: мягко удалённые пользователи и устройства уходят насовсем,
// их адреса освобождаются. Обычно это делает ретеншн через 30 дней — кнопка нужна, когда
// место в подсети нужно сейчас.
func (s *Server) usersPurge(w http.ResponseWriter, r *http.Request, sc sessionCtx) {
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	users, devices, err := s.Hub.Store.PurgeDeleted(ctx, 0)
	if err != nil {
		s.back(w, r, "/users?trash=1", err)
		return
	}
	s.audit(r, store.ActorAdmin, "trash.purge", "user", 0, map[string]any{
		"users": users, "devices": devices,
	})
	if users == 0 && devices == 0 {
		s.done(w, r, "/users?trash=1", "в корзине нечего было чистить")
		return
	}
	s.done(w, r, "/users?trash=1", fmt.Sprintf("корзина очищена: удалено %s и %s",
		plural(int(users), "пользователь", "пользователя", "пользователей"),
		plural(int(devices), "устройство", "устройства", "устройств")))
}

// brandSave задаёт имя панели: вкладка браузера и левый верхний угол. Хранится в настройках,
// поэтому переживает перезапуск и переезд на другую машину.
func (s *Server) brandSave(w http.ResponseWriter, r *http.Request, sc sessionCtx) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	name := strings.TrimSpace(r.FormValue("brand"))
	if err := s.Hub.Store.SetBrand(ctx, name); err != nil {
		s.back(w, r, "/settings", err)
		return
	}
	if name == "" {
		name = store.DefaultBrand
	}
	s.SetBrandCache(name)
	s.audit(r, store.ActorAdmin, "panel.brand", "panel", 0, map[string]any{"brand": name})
	s.done(w, r, "/settings", "панель теперь называется «"+name+"»")
}

// ---------- серверы ----------

// serverBySlug находит сервер парка по слагу из адреса.
func (s *Server) serverBySlug(ctx context.Context, slug string) (store.Server, error) {
	return s.Hub.Store.ServerBySlug(ctx, slug)
}

// serverRetire выводит сервер из парка: опрос прекращается, устройства на нём перестают
// считаться работающими, портал их гасит (SPEC FR-10.6).
func (s *Server) serverRetire(w http.ResponseWriter, r *http.Request, sc sessionCtx) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	slug := r.PathValue("slug")
	srv, err := s.serverBySlug(ctx, slug)
	if err != nil {
		s.back(w, r, "/", err)
		return
	}
	if err := s.Hub.RetireServer(ctx, srv.ID); err != nil {
		s.back(w, r, "/servers/"+slug, err)
		return
	}
	b, _ := s.Hub.Store.Belongings(ctx, srv.ID)
	s.audit(r, store.ActorAdmin, "server.retire", "server", srv.ID, map[string]any{
		"slug": srv.Slug, "devices": b.Devices, "users": b.Users,
	})
	msg := srv.Title + " выведен из парка"
	if b.Devices > 0 {
		msg += "; устройств на нём осталось: " + itoa(int64(b.Devices))
	}
	s.done(w, r, "/servers/"+slug, msg)
}

// serverReturn возвращает выведенный сервер в парк.
func (s *Server) serverReturn(w http.ResponseWriter, r *http.Request, sc sessionCtx) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	slug := r.PathValue("slug")
	srv, err := s.serverBySlug(ctx, slug)
	if err != nil {
		s.back(w, r, "/", err)
		return
	}
	if err := s.Hub.ReturnServer(ctx, srv.ID); err != nil {
		s.back(w, r, "/servers/"+slug, err)
		return
	}
	s.audit(r, store.ActorAdmin, "server.return", "server", srv.ID, map[string]any{"slug": srv.Slug})
	s.done(w, r, "/servers/"+slug, srv.Title+" снова в парке — опрос возобновлён")
}

// serverDelete убирает выведенный сервер из панели вместе с его интерфейсами, пирами,
// устройствами и историей (SPEC FR-10.7). Пользователи остаются.
func (s *Server) serverDelete(w http.ResponseWriter, r *http.Request, sc sessionCtx) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	slug := r.PathValue("slug")
	srv, err := s.serverBySlug(ctx, slug)
	if err != nil {
		s.back(w, r, "/", err)
		return
	}
	b, _ := s.Hub.Store.Belongings(ctx, srv.ID)
	if err := s.Hub.DeleteServer(ctx, srv.ID); err != nil {
		s.back(w, r, "/servers/"+slug, err)
		return
	}
	s.audit(r, store.ActorAdmin, "server.delete", "server", srv.ID, map[string]any{
		"slug": srv.Slug, "interfaces": b.Interfaces, "peers": b.Peers, "devices": b.Devices,
	})
	s.done(w, r, "/", srv.Title+" убран из панели: интерфейсов "+itoa(int64(b.Interfaces))+
		", устройств "+itoa(int64(b.Devices)))
}

// ---------- вспомогательное ----------

// done и back возвращают на страницу с сообщением: после POST всегда редирект, чтобы обновление
// страницы не повторяло действие.
func (s *Server) done(w http.ResponseWriter, r *http.Request, path, msg string) {
	http.Redirect(w, r, path+sep(path)+"ok="+url.QueryEscape(msg), http.StatusSeeOther)
}

func (s *Server) back(w http.ResponseWriter, r *http.Request, path string, err error) {
	http.Redirect(w, r, path+sep(path)+"err="+url.QueryEscape(err.Error()), http.StatusSeeOther)
}

func sep(path string) string {
	if strings.Contains(path, "?") {
		return "&"
	}
	return "?"
}

func formInt(r *http.Request, name string, def int) int {
	v, err := strconv.Atoi(strings.TrimSpace(r.PostFormValue(name)))
	if err != nil {
		return def
	}
	return v
}

func formInt64(r *http.Request, name string) int64 {
	v, _ := strconv.ParseInt(strings.TrimSpace(r.PostFormValue(name)), 10, 64)
	return v
}

// formDate читает поле <input type="date">; пустое поле означает «без срока».
func formDate(r *http.Request, name string) time.Time {
	v := strings.TrimSpace(r.PostFormValue(name))
	if v == "" {
		return time.Time{}
	}
	t, err := time.Parse("2006-01-02", v)
	if err != nil {
		return time.Time{}
	}
	return t
}

func itoa(v int64) string { return strconv.FormatInt(v, 10) }

// notifySave сохраняет настройки оповещателя (FR-13.3). Пороги приходят числами; пустое поле
// означает «оставить как было», а не «ноль»: ноль выключил бы проверку целиком.
func (s *Server) notifySave(w http.ResponseWriter, r *http.Request, sc sessionCtx) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	cfg, err := s.Hub.Store.Notify(ctx)
	if err != nil {
		s.back(w, r, "/settings", err)
		return
	}
	cfg.Enabled = r.FormValue("enabled") != ""
	cfg.QuietEnabled = r.FormValue("quiet") != ""
	cfg.QuietFrom = atoiDefault(r.FormValue("quiet_from"), cfg.QuietFrom, 0, 23)
	cfg.QuietTo = atoiDefault(r.FormValue("quiet_to"), cfg.QuietTo, 0, 23)
	cfg.DiskHigh = atoiDefault(r.FormValue("disk_high"), cfg.DiskHigh, 1, 100)
	cfg.MemHigh = atoiDefault(r.FormValue("mem_high"), cfg.MemHigh, 1, 100)
	cfg.DroughtMin = atoiDefault(r.FormValue("drought_min"), cfg.DroughtMin, 1, 10000)
	if v, err := strconv.ParseFloat(strings.TrimSpace(r.FormValue("load_high")), 64); err == nil && v > 0 {
		cfg.LoadHigh = v
	}
	if v, err := strconv.ParseFloat(strings.TrimSpace(r.FormValue("spike_gb")), 64); err == nil && v >= 0 {
		cfg.SpikeGB = v
	}
	cfg.Off = nil
	for _, k := range notifyKinds {
		if r.FormValue("off_"+k.kind) != "" {
			cfg.Off = append(cfg.Off, k.kind)
		}
	}
	if err := s.Hub.Store.SetNotify(ctx, cfg); err != nil {
		s.back(w, r, "/settings", err)
		return
	}
	s.audit(r, store.ActorAdmin, "settings.notify", "settings", 0, map[string]any{
		"enabled": cfg.Enabled, "quiet": cfg.QuietEnabled, "off": len(cfg.Off)})
	s.done(w, r, "/settings", "настройки оповещений сохранены")
}

// atoiDefault читает целое в границах; всё, что не разобралось, оставляет прежнее значение.
func atoiDefault(raw string, def, min, max int) int {
	v, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || v < min || v > max {
		return def
	}
	return v
}

// backupNow снимает копию по кнопке из панели. Работа занимает секунды, поэтому делается
// синхронно: администратор должен увидеть результат, а не «запущено».
func (s *Server) backupNow(w http.ResponseWriter, r *http.Request, sc sessionCtx) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	kind := backup.KindConfig
	if r.FormValue("kind") == "full" {
		kind = backup.KindFull
	}
	path, err := s.Hub.RunBackup(ctx, kind)
	if err != nil {
		s.back(w, r, "/settings", err)
		return
	}
	s.audit(r, store.ActorAdmin, "backup.now", "backup", 0, map[string]any{"kind": string(kind), "file": filepath.Base(path)})
	msg := "копия готова: " + filepath.Base(path)
	if s.Hub.Bot != nil && kind == backup.KindConfig {
		msg += "; отправлена в Telegram"
	}
	s.done(w, r, "/settings", msg)
}

// formIDs собирает список числовых значений одного поля формы (чекбоксы серверов).
func formIDs(r *http.Request, name string) []int64 {
	var out []int64
	for _, v := range r.PostForm[name] {
		if id := atoi64(v); id != 0 {
			out = append(out, id)
		}
	}
	return out
}
