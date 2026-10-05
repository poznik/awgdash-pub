package web

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/poznik/awgdash-pub/internal/hub"
	"github.com/poznik/awgdash-pub/internal/store"
)

// Портал пользователей (SPEC §6.5). Вход — только по персональной ссылке: сессий нет,
// перечисления нет, страница отдаётся целиком одним запросом.
const (
	portalTokenDelay = 500 * time.Millisecond // задержка на неверный токен (FR-5.3)
	portalRateLimit  = 10                     // попыток в минуту с адреса
)

// portalData — данные страницы портала. Своя структура: у портала нет ни рельсы, ни админских счётчиков.
type portalData struct {
	Title string
	// Brand — имя сервиса из настроек: во вкладке браузера у человека будет оно, а не «VPN».
	Brand   string
	CSS     string // стили встраиваются в страницу: у портала бюджет 40 КБ и один запрос
	Page    hub.PortalPage
	Token   string
	Flash   string
	Error   string
	Config  *hub.Config
	Device  int64
	Current string
}

// registerPortal вешает маршруты портала.
func (s *Server) registerPortal(mux *http.ServeMux) {
	mux.HandleFunc("GET /u/{token}", s.portalPage)
	mux.HandleFunc("GET /u/{token}/devices/{id}", s.portalDevice)
	mux.HandleFunc("GET /u/{token}/devices/{id}/conf", s.portalConf)
	mux.HandleFunc("POST /u/{token}/devices", s.portalAdd)
	mux.HandleFunc("POST /u/{token}/devices/{id}/rename", s.portalRename)
	mux.HandleFunc("POST /u/{token}/devices/{id}/delete", s.portalDelete)
}

// portalUser проверяет ссылку. Любая неудача выглядит одинаково: 404 с задержкой, без подсказок
// о том, существовал ли токен (FR-5.3).
func (s *Server) portalUser(w http.ResponseWriter, r *http.Request) (store.User, bool) {
	if !s.portalHostAllowed(r) {
		http.NotFound(w, r)
		return store.User{}, false
	}
	ip := s.clientIP(r)
	if _, blocked := s.Portal.blocked(ip); blocked {
		http.Error(w, "слишком много попыток, подождите", http.StatusTooManyRequests)
		return store.User{}, false
	}
	token := r.PathValue("token")
	u, err := s.Hub.Store.UserByToken(r.Context(), token)
	if err != nil || u.Disabled() {
		s.Portal.fail(ip)
		time.Sleep(portalTokenDelay)
		http.NotFound(w, r)
		return store.User{}, false
	}
	s.Hub.Store.TouchLink(r.Context(), token)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	return u, true
}

// portalHostAllowed — портал отвечает на своём имени и на localhost (туннель для проверки).
// На имени админки его нет: разделение по Host — часть FR-13.1.
func (s *Server) portalHostAllowed(r *http.Request) bool {
	if !s.forwardedOK(r) {
		return false
	}
	host := strings.ToLower(hostOnly(s.requestHost(r)))
	if s.AdminHost != "" && host == strings.ToLower(s.AdminHost) {
		return false
	}
	if s.PortalHost == "" {
		return true
	}
	return host == strings.ToLower(s.PortalHost) || s.isLocalHost(r)
}

// sameSitePost — форма портала пришла со своей же страницы. Токен и так секрет, но проверка
// происхождения не даёт чужому сайту слать запросы вслепую.
func (s *Server) sameSitePost(w http.ResponseWriter, r *http.Request) error {
	limitBody(w, r, maxLoginBody)
	if err := r.ParseForm(); err != nil {
		return errors.New("не разобрана форма")
	}
	return s.checkOrigin(r)
}

func (s *Server) portalPage(w http.ResponseWriter, r *http.Request) {
	u, ok := s.portalUser(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	page, err := s.Hub.Portal(ctx, u)
	if err != nil {
		s.fail(w, err)
		return
	}
	q := r.URL.Query()
	s.render(w, "portal.html", portalData{
		Brand: s.Brand(),
		Title: u.Name, CSS: s.portalCSS(), Page: page, Token: r.PathValue("token"),
		Flash: q.Get("ok"), Error: q.Get("err"),
	})
}

// portalDevice показывает конфиг устройства: QR, текст и варианты endpoint (FR-4.5).
func (s *Server) portalDevice(w http.ResponseWriter, r *http.Request) {
	u, ok := s.portalUser(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	cfg, err := s.Hub.PortalConfig(ctx, u, atoi64(r.PathValue("id")), r.URL.Query().Get("ep"), s.clientIP(r))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	page, err := s.Hub.Portal(ctx, u)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, "portal.html", portalData{
		Brand: s.Brand(),
		Title: cfg.Device.Name, CSS: s.portalCSS(), Page: page, Token: r.PathValue("token"),
		Config: &cfg, Device: cfg.Device.ID, Current: cfg.Endpoint.Label,
	})
}

func (s *Server) portalConf(w http.ResponseWriter, r *http.Request) {
	u, ok := s.portalUser(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	cfg, err := s.Hub.PortalConfig(ctx, u, atoi64(r.PathValue("id")), r.URL.Query().Get("ep"), s.clientIP(r))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename*=UTF-8''"+urlPathEscape(cfg.FileName))
	w.Write([]byte(cfg.Text))
}

func (s *Server) portalAdd(w http.ResponseWriter, r *http.Request) {
	u, ok := s.portalUser(w, r)
	if !ok {
		return
	}
	if err := s.sameSitePost(w, r); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	dev, err := s.Hub.PortalAddDevice(ctx, u, strings.TrimSpace(r.PostFormValue("name")), r.PostFormValue("preset"),
		atoi64(r.PostFormValue("interface_id")), s.clientIP(r))
	if err != nil {
		s.back(w, r, "/u/"+r.PathValue("token"), err)
		return
	}
	// Сразу открываем конфиг: человек добавил устройство ради него.
	s.done(w, r, "/u/"+r.PathValue("token")+"/devices/"+itoa(dev.ID), "устройство добавлено")
}

func (s *Server) portalRename(w http.ResponseWriter, r *http.Request) {
	u, ok := s.portalUser(w, r)
	if !ok {
		return
	}
	if err := s.sameSitePost(w, r); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	back := "/u/" + r.PathValue("token")
	if err := s.Hub.PortalRenameDevice(ctx, u, atoi64(r.PathValue("id")), strings.TrimSpace(r.PostFormValue("name")), s.clientIP(r)); err != nil {
		s.back(w, r, back, err)
		return
	}
	s.done(w, r, back, "имя изменено")
}

func (s *Server) portalDelete(w http.ResponseWriter, r *http.Request) {
	u, ok := s.portalUser(w, r)
	if !ok {
		return
	}
	if err := s.sameSitePost(w, r); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	back := "/u/" + r.PathValue("token")
	if err := s.Hub.PortalDeleteDevice(ctx, u, atoi64(r.PathValue("id")), s.clientIP(r)); err != nil {
		s.back(w, r, back, err)
		return
	}
	s.done(w, r, back, "устройство удалено; администратор сможет его вернуть")
}

// portalCSS — стили портала одной строкой: страница должна приезжать одним запросом и укладываться
// в 40 КБ на мобильной сети, поэтому внешние файлы и шрифты не подключаются (FR-5.5).
func (s *Server) portalCSS() string {
	if a, ok := s.assets["portal.css"]; ok {
		return string(a.body)
	}
	return ""
}
