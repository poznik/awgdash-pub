package hub

import (
	"context"
	"errors"

	"github.com/poznik/awgdash-pub/internal/store"
)

// ErrNoInterfaces — в парке нет ни одного интерфейса: сажать устройство некуда.
var ErrNoInterfaces = errors.New("в парке нет интерфейсов — панель ещё не увидела ни одного")

// ErrNoOwnInterfaces — интерфейсы есть, но все под наблюдением: пир панель на них не поставит.
var ErrNoOwnInterfaces = errors.New("все интерфейсы парка в режиме наблюдения — панель на них пиры не ставит; возьмите интерфейс под управление")

// Выбор сервера при создании устройства (решение 2026-08-24: пользователь не привязан
// к серверу, привязаны его устройства).

// IfaceChoice — вариант «куда посадить устройство»: человек выбирает страну, а не интерфейс.
type IfaceChoice struct {
	InterfaceID int64
	ServerID    int64
	Server      string // человеческое имя сервера
	Slug        string
	Flag        string // эмодзи-флаг страны
	Interface   string
	Subnet      string
	Local       bool // сервер, на котором работает сама панель
	// Own — панель владеет пирами этого интерфейса. На наблюдаемом (observe) устройство
	// заведётся в базе, но пир не встанет: человек получит конфиг, который не подключится.
	Own bool
	// Умолчания интерфейса — то, что подставится в конфиг, если «тонкости» оставить пустыми
	// (FR-1.8). Форма создания устройства показывает их вместо слов «как на интерфейсе».
	DNS        string
	MTU        int
	Keepalive  int
	AllowedIPs string
}

// Label — флаг страны и название сервера, как это видит человек в списке.
func (c IfaceChoice) Label() string {
	if c.Flag == "" {
		return c.Server
	}
	return c.Flag + " " + c.Server
}

// IfaceChoices — куда можно сажать устройства: только интерфейсы под управлением панели.
// Наблюдаемые в выбор не попадают ни в портале, ни в панели (FR-3.1, FR-5.2): устройство на
// них завелось бы в базе, а человек получил бы конфиг, который никогда не подключится.
func (h *Hub) IfaceChoices(ctx context.Context, filter *store.User) ([]IfaceChoice, error) {
	list, err := h.AllIfaceChoices(ctx, filter)
	if err != nil {
		return nil, err
	}
	out := make([]IfaceChoice, 0, len(list))
	for _, c := range list {
		if c.Own {
			out = append(out, c)
		}
	}
	return out, nil
}

// AllIfaceChoices — весь парк, включая наблюдаемые. Нужен там, где интерфейс не место посадки,
// а предмет настройки: какие серверы разрешены человеку в портале. filter — пользователь, для
// которого считаем (пустой список разрешённых означает «любой сервер»); nil даёт весь парк.
func (h *Hub) AllIfaceChoices(ctx context.Context, filter *store.User) ([]IfaceChoice, error) {
	ifaces, err := h.Store.Interfaces(ctx, 0)
	if err != nil {
		return nil, err
	}
	servers, err := h.Store.Servers(ctx)
	if err != nil {
		return nil, err
	}
	byID := map[int64]store.Server{}
	for _, s := range servers {
		byID[s.ID] = s
	}
	out := make([]IfaceChoice, 0, len(ifaces))
	for _, i := range ifaces {
		if filter != nil && !filter.Allows(i.ID) {
			continue
		}
		srv := byID[i.ServerID]
		// Выведенный сервер не предлагается ни в панели, ни в портале: устройство на нём
		// не заработает, а мёртвый конфиг хуже отсутствия конфига (SPEC FR-10.6).
		if srv.Retired() {
			continue
		}
		title := srv.Title
		if title == "" {
			title = srv.Slug
		}
		if title == "" {
			title = i.Name
		}
		out = append(out, IfaceChoice{InterfaceID: i.ID, ServerID: i.ServerID, Server: title, Slug: srv.Slug,
			Flag: srv.Flag(), Interface: i.Name, Subnet: i.Subnet, Local: srv.Local(), Own: i.Mode == ModeOwn,
			DNS: i.DefaultDNS, MTU: i.MTU, Keepalive: i.DefaultKeepalive, AllowedIPs: i.DefaultAllowedIPs})
	}
	// Локальный сервер первым: он же предлагается по умолчанию.
	for i := range out {
		if out[i].Local && i != 0 {
			out[0], out[i] = out[i], out[0]
			break
		}
	}
	return out, nil
}

// DefaultInterface — куда сажать устройство, если сервер не выбран: интерфейс той машины,
// где работает панель.
func (h *Hub) DefaultInterface(ctx context.Context) (int64, error) {
	choices, err := h.IfaceChoices(ctx, nil)
	if err != nil {
		return 0, err
	}
	// Список уже очищен от наблюдаемых, а локальный сервер стоит первым: панель предлагает
	// свою же машину, если выбор не сделан.
	if len(choices) > 0 {
		return choices[0].InterfaceID, nil
	}
	// Пустой список означает либо пустой парк, либо парк из одних наблюдаемых интерфейсов —
	// это разные беды, и говорить о них надо разными словами.
	all, err := h.AllIfaceChoices(ctx, nil)
	if err != nil {
		return 0, err
	}
	if len(all) == 0 {
		return 0, ErrNoInterfaces
	}
	return 0, ErrNoOwnInterfaces
}

// Состав парка меняется на ходу: реестр узлов сверяется сразу после записи, а не при
// следующем запуске панели (FR-10.8). Иначе выведенный сервер продолжал бы опрашиваться,
// а вернувшийся — молчать.

// RetireServer выводит сервер из парка и снимает его узел с опроса (FR-10.6).
func (h *Hub) RetireServer(ctx context.Context, id int64) error {
	if err := h.Store.RetireServer(ctx, id); err != nil {
		return err
	}
	h.reloadServers(ctx)
	return nil
}

// ReturnServer возвращает выведенный сервер в парк и сразу берёт его узел в работу.
func (h *Hub) ReturnServer(ctx context.Context, id int64) error {
	if err := h.Store.ReturnServer(ctx, id); err != nil {
		return err
	}
	h.reloadServers(ctx)
	return nil
}

// DeleteServer убирает сервер из панели вместе с его хозяйством и вычищает из реестра (FR-10.7).
func (h *Hub) DeleteServer(ctx context.Context, id int64) error {
	if err := h.Store.DeleteServer(ctx, id); err != nil {
		return err
	}
	h.reloadServers(ctx)
	return nil
}

// SetServerEnabled включает и выключает опрос сервера, не трогая его данные.
func (h *Hub) SetServerEnabled(ctx context.Context, id int64, on bool) error {
	if err := h.Store.SetServerEnabled(ctx, id, on); err != nil {
		return err
	}
	h.reloadServers(ctx)
	return nil
}
