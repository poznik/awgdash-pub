package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/poznik/awgdash-pub/internal/hub"
	"github.com/poznik/awgdash-pub/internal/store"
)

// Очередь «Надо сделать» и вердикт собираются из одних и тех же фактов и обязаны сходиться:
// вердикт называет самое тяжёлое дело, очередь показывает все (PLAN-UI §1.2).
func TestParkTasksAndVerdict(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	now := time.Now()

	// Сервер отвечает, но диск за порогом и ядро ждёт перезагрузки.
	if err := e.store.InsertHostMetric(ctx, store.HostMetric{ServerID: 1, TS: now, CPU: 5,
		MemUsed: 500_000_000, MemTotal: 2_000_000_000,
		DiskUsed: 38_000_000_000, DiskTotal: 40_000_000_000, Load1: 0.3}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.store.DB().ExecContext(ctx, `UPDATE servers SET reboot_required = 1, last_seen_at = ? WHERE id = 1`, now.Unix()); err != nil {
		t.Fatal(err)
	}
	// Интерфейс поднят: иначе всё остальное про него — уже мелочь рядом с «не поднят».
	if _, err := e.store.DB().ExecContext(ctx, `UPDATE interfaces SET unit_active = 1 WHERE id = ?`, e.iface.ID); err != nil {
		t.Fatal(err)
	}
	// Пир, который панели не принадлежит.
	if _, err := e.store.DB().ExecContext(ctx, `INSERT INTO peers (interface_id, public_key, allowed_ips, in_conf, first_seen_at, last_seen_at)
		VALUES (?, 'ORPHAN=', '10.20.0.77/32', 1, ?, ?)`, e.iface.ID, now.Add(-time.Hour).Unix(), now.Unix()); err != nil {
		t.Fatal(err)
	}
	// Человек с истёкшим сроком.
	if _, _, err := e.store.CreateUser(ctx, store.User{Name: "Гости", MaxDevices: 5,
		DefaultInterfaceID: e.iface.ID, ExpiresAt: now.Add(-48 * time.Hour)}); err != nil {
		t.Fatal(err)
	}

	e.login(t)
	_, body := e.get(t, "/")

	want := []string{
		"диск занят на 95 %",        // порог 85 — критическое дело
		"нужна перезагрузка",        // предупреждение
		"1 пир без владельца",       // предупреждение
		"Истёк срок доступа: Гости", // предупреждение
	}
	for _, w := range want {
		if !strings.Contains(body, w) {
			t.Fatalf("в очереди дел нет %q", w)
		}
	}
	// Наблюдаемый интерфейс делом не считается: на каждой машине парка есть служебные туннели
	// под наблюдением, и очередь состояла бы из них.
	if strings.Contains(body, "режим observe") {
		t.Fatal("наблюдение снова попало в очередь дел")
	}
	// Вердикт называет самое тяжёлое: диск, а не перезагрузку.
	head := body[strings.Index(body, "verdict__line"):]
	head = head[:strings.Index(head, "</h1>")]
	if !strings.Contains(head, "диск занят на 95 %") {
		t.Fatalf("вердикт не назвал самое тяжёлое дело: %s", head)
	}
	// Критическое дело стоит выше предупреждений.
	if strings.Index(body, "диск занят на 95 %") > strings.Index(body, "1 пир без владельца") {
		t.Fatal("критическое дело оказалось ниже предупреждения")
	}
}

// Молчащий узел — отдельный разговор: вердикт говорит про парк, а не про пороги.
func TestParkVerdictSilentNode(t *testing.T) {
	e := newEnv(t)
	e.login(t)
	// Метрик нет вовсе — узел считается молчащим.
	_, body := e.get(t, "/")
	if !strings.Contains(body, "Панель не видит ни одного сервера.") {
		t.Fatal("вердикт не сказал, что связи с парком нет")
	}
	if !strings.Contains(body, "узел не отвечает") {
		t.Fatal("в очереди дел нет молчащего узла")
	}
}

// Предпросмотр сверки показывает, что изменится, и ничего не меняет (PLAN-UI §1.5).
func TestReconcilePreviewChangesNothing(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	csrf := e.login(t)

	// Отдаём интерфейс панели и заводим устройство — на интерфейсе оно уже стоит.
	if _, err := e.store.DB().ExecContext(ctx, `UPDATE interfaces SET mode = 'own', unit_active = 1 WHERE id = ?`, e.iface.ID); err != nil {
		t.Fatal(err)
	}
	userID, _, err := e.store.CreateUser(ctx, store.User{Name: "Анна", MaxDevices: 5, DefaultInterfaceID: e.iface.ID})
	if err != nil {
		t.Fatal(err)
	}
	e.post(t, "/users/"+itoa(userID)+"/devices/new", url.Values{
		"csrf": {csrf}, "name": {"Телефон"}, "preset": {"phone"}, "interface_id": {itoa(e.iface.ID)},
	})

	resp, body := e.get(t, "/interfaces/awg-t0?plan=1")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("предпросмотр: %d", resp.StatusCode)
	}
	if !strings.Contains(body, "Расхождений нет") && !strings.Contains(body, "Сверка изменит") {
		t.Fatal("предпросмотр ничего не сказал о расхождениях")
	}
	// Кнопка «привести к панели» появляется только когда есть что менять.
	if strings.Contains(body, "Расхождений нет") && strings.Contains(body, "Привести к панели") {
		t.Fatal("нечего менять, а кнопка сверки предлагается")
	}
	// В журнале действий записи о сверке быть не должно: предпросмотр ничего не делает.
	entries, _ := e.store.Audit(ctx, store.AuditFilter{Action: "interface.reconcile"})
	if len(entries) != 0 {
		t.Fatalf("предпросмотр записал в журнал %d действий", len(entries))
	}
}

// Сервер выведен из парка: устройства на нём честно показываются нерабочими, портал их гасит,
// конфиг не выдаётся, а вердикт обзора от этого не портится (SPEC FR-10.6).
func TestRetiredServerTellsTheTruth(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	csrf := e.login(t)

	// Локальный сервер жив: иначе вердикт заговорит про него, а не про выведенный.
	if err := e.store.InsertHostMetric(ctx, store.HostMetric{ServerID: 1, TS: time.Now(), CPU: 3,
		MemUsed: 400_000_000, MemTotal: 2_000_000_000, DiskUsed: 8_000_000_000, DiskTotal: 40_000_000_000, Load1: 0.2}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.store.DB().ExecContext(ctx, `UPDATE servers SET last_seen_at = ? WHERE id = 1`, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	if _, err := e.store.DB().ExecContext(ctx, `UPDATE interfaces SET unit_active = 1, mode = 'own' WHERE id = ?`, e.iface.ID); err != nil {
		t.Fatal(err)
	}

	// Второй сервер парка с собственным интерфейсом и устройством пользователя.
	kz, err := e.store.AddServer(ctx, store.NewServer{Slug: "kz", Title: "Казахстан", NodePort: 10089})
	if err != nil {
		t.Fatal(err)
	}
	kzIf, err := e.store.UpsertInterface(ctx, kz.ID, "awg-kz", store.InterfaceFacts{
		Subnet: "10.30.0.0/24", ServerAddress: "10.30.0.1/24", ListenPort: 443, MTU: 1280, IsAWG: true, UnitActive: true})
	if err != nil {
		t.Fatal(err)
	}
	uid, token, err := e.store.CreateUser(ctx, store.User{Name: "Анна", MaxDevices: 5, DefaultInterfaceID: kzIf})
	if err != nil {
		t.Fatal(err)
	}
	devID, err := e.store.CreateDevice(ctx, store.Device{UserID: uid, InterfaceID: kzIf, Name: "iPad",
		PrivateKey: "priv", PublicKey: "KZPUB=", Address: "10.30.0.2/32", Status: "active"})
	if err != nil {
		t.Fatal(err)
	}

	// Выводим сервер из парка.
	if resp, body := e.post(t, "/servers/kz/retire", url.Values{"csrf": {csrf}}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("вывод сервера: %d %s", resp.StatusCode, body)
	}

	_, dash := e.get(t, "/")
	// Выведенный сервер стоит последним в том же списке — приглушённой карточкой с действиями.
	if !strings.Contains(dash, "card--gone") || !strings.Contains(dash, "Вернуть в парк") {
		t.Fatal("на обзоре нет приглушённой карточки выведенного сервера")
	}
	if strings.Index(dash, "Германия") > strings.Index(dash, "card--gone") {
		t.Fatal("выведенный сервер оказался выше живого")
	}
	if !strings.Contains(dash, "осталось") {
		t.Fatal("на обзоре нет дела про оставшиеся устройства")
	}
	// Вердикт не должен считать выведенный сервер поломкой.
	head := dash[strings.Index(dash, "verdict__line"):]
	head = head[:strings.Index(head, "</h1>")]
	if strings.Contains(head, "молчит") || strings.Contains(head, "не видит") {
		t.Fatalf("выведенный сервер испортил вердикт: %s", head)
	}

	_, card := e.get(t, "/users/"+itoa(uid))
	if !strings.Contains(card, "сервер выведен") {
		t.Fatal("в карточке пользователя устройство не помечено как нерабочее")
	}

	// Конфиг такого устройства не выдаётся вовсе.
	resp, conf := e.get(t, "/devices/"+itoa(devID)+"/config")
	if resp.StatusCode == http.StatusOK && strings.Contains(conf, "Скачать .conf") {
		t.Fatal("панель выдала конфиг с выведенного сервера")
	}

	// Портал молчит про такие устройства и не показывает QR.
	resp, portal := e.withHost(t, "portal.example.com", "/u/"+token)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("портал: %d", resp.StatusCode)
	}
	if !strings.Contains(portal, "сервер закрыт") {
		t.Fatal("портал не сказал, что сервер закрыт")
	}
	if strings.Contains(portal, "QR и конфиг") {
		t.Fatal("портал предлагает конфиг с выведенного сервера")
	}
}

// Выведенный сервер не должен предлагаться при заведении устройства — ни в форме, ни если
// подставить его id руками.
func TestRetiredServerIsNotOffered(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	csrf := e.login(t)

	kz, err := e.store.AddServer(ctx, store.NewServer{Slug: "kz", Title: "Казахстан", NodePort: 10089})
	if err != nil {
		t.Fatal(err)
	}
	kzIf, err := e.store.UpsertInterface(ctx, kz.ID, "awg-kz", store.InterfaceFacts{
		Subnet: "10.30.0.0/24", ServerAddress: "10.30.0.1/24", ListenPort: 443, MTU: 1280, IsAWG: true, UnitActive: true})
	if err != nil {
		t.Fatal(err)
	}
	// Под управлением: наблюдаемый в форме не показывается и до вывода сервера (FR-3.1).
	if err := e.store.SetInterfaceMode(ctx, kzIf, hub.ModeOwn); err != nil {
		t.Fatal(err)
	}
	uid, _, err := e.store.CreateUser(ctx, store.User{Name: "Ирина", MaxDevices: 5, DefaultInterfaceID: e.iface.ID})
	if err != nil {
		t.Fatal(err)
	}
	// Пока сервер в парке — он в списке выбора.
	_, form := e.get(t, "/users/"+itoa(uid)+"/devices/new")
	if !strings.Contains(form, "Казахстан") {
		t.Fatal("живой сервер не предлагается в форме")
	}

	if resp, body := e.post(t, "/servers/kz/retire", url.Values{"csrf": {csrf}}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("вывод сервера: %d %s", resp.StatusCode, body)
	}

	_, form = e.get(t, "/users/"+itoa(uid)+"/devices/new")
	if strings.Contains(form, "Казахстан") {
		t.Fatal("выведенный сервер всё ещё предлагается в форме создания устройства")
	}
	// И подстановка руками отклоняется на сервере.
	resp, _ := e.post(t, "/users/"+itoa(uid)+"/devices/new", url.Values{
		"csrf": {csrf}, "name": {"Телефон"}, "preset": {"phone"}, "interface_id": {itoa(kzIf)},
	})
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "err=") {
		t.Fatalf("устройство завелось на выведенном сервере: %s", loc)
	}
}

// Возврат сервера в парк действует сразу: узел снова опрашивается, а не ждёт перезапуска
// панели (SPEC FR-10.8). До правки панель обещала возобновить опрос и не возобновляла —
// реестр узлов читался один раз, при старте.
func TestReturnedServerIsPolledAgain(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	csrf := e.login(t)

	kz, err := e.store.AddServer(ctx, store.NewServer{Slug: "kz", Title: "Казахстан", NodePort: 10089})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.hub.LoadServers(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := e.hub.Agent(kz.ID); err != nil {
		t.Fatalf("узел не попал в реестр: %v", err)
	}

	if resp, body := e.post(t, "/servers/kz/retire", url.Values{"csrf": {csrf}}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("вывод сервера: %d %s", resp.StatusCode, body)
	}
	if _, err := e.hub.Agent(kz.ID); err == nil {
		t.Fatal("выведенный сервер остался в опросе")
	}

	if resp, body := e.post(t, "/servers/kz/return", url.Values{"csrf": {csrf}}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("возврат сервера: %d %s", resp.StatusCode, body)
	}
	if _, err := e.hub.Agent(kz.ID); err != nil {
		t.Fatalf("вернувшийся сервер не взят в опрос: %v", err)
	}
}

// Интерфейс, снятый с сервера, вердикт не красит: туннель никто не ломал, просто в панели
// осталась запись. Панель говорит об этом делом и даёт кнопку убрать (FR-1.9).
func TestGoneInterfaceIsNotBreakage(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	now := time.Now()
	if _, err := e.store.DB().ExecContext(ctx, `UPDATE servers SET last_seen_at = ? WHERE id = 1`, now.Unix()); err != nil {
		t.Fatal(err)
	}
	if err := e.store.InsertHostMetric(ctx, store.HostMetric{ServerID: 1, TS: now, CPU: 5,
		MemUsed: 500_000_000, MemTotal: 2_000_000_000, DiskUsed: 4_000_000_000, DiskTotal: 40_000_000_000, Load1: 0.1}); err != nil {
		t.Fatal(err)
	}
	uid, _, err := e.store.CreateUser(ctx, store.User{Name: "Хозяин", MaxDevices: 5, DefaultInterfaceID: e.iface.ID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.hub.CreateDevice(ctx, hub.NewDevice{UserID: uid, InterfaceID: e.iface.ID, Name: "Телефон"}); err != nil {
		t.Fatal(err)
	}
	// Обход больше не находит интерфейс — панель помечает его «пропал».
	if _, err := e.store.MarkGoneInterfaces(ctx, 1, nil); err != nil {
		t.Fatal(err)
	}
	csrf := e.login(t)

	_, body := e.get(t, "/")
	if !strings.Contains(body, "awg-t0: исчез с сервера") {
		t.Fatal("на обзоре нет дела о пропавшем интерфейсе")
	}
	if strings.Contains(body, "awg-t0: интерфейс не поднят") {
		t.Fatal("пропавший интерфейс всё ещё выдаётся за неподнятый")
	}
	if strings.Contains(body, "поломка") {
		t.Fatal("вердикт сервера красный из-за записи, которую просто некому убрать")
	}

	iface0 := itoa(e.iface.ID)
	_, page := e.get(t, "/interfaces/"+iface0)
	if !strings.Contains(page, "Интерфейса нет на сервере") || !strings.Contains(page, `action="/interfaces/`+iface0+`/forget"`) {
		t.Fatal("на странице интерфейса нет ни объяснения, ни кнопки убрать")
	}

	loc := e.action(t, "/interfaces/"+iface0+"/forget", url.Values{}, csrf)
	if msg, bad := flashOf(t, loc); bad != "" || !strings.Contains(msg, "убран из панели") {
		t.Fatalf("убрать из панели: ok=%q err=%q", msg, bad)
	}
	if list, _ := e.store.Interfaces(ctx, 0); len(list) != 0 {
		t.Fatalf("интерфейс остался в панели: %+v", list)
	}
	if devs, _ := e.store.DevicesByUser(ctx, uid); len(devs) != 0 {
		t.Fatalf("устройства убранного интерфейса остались: %d", len(devs))
	}
	entries, _ := e.store.Audit(ctx, store.AuditFilter{Action: "interface.forget"})
	if len(entries) != 1 {
		t.Fatalf("записей в журнале: %d", len(entries))
	}
}

// Одно имя интерфейса живёт на разных машинах парка (три `awg-hub` между серверами). Панель
// обязана различать их: адрес страницы — идентификатор, действия применяются к тому интерфейсу,
// который открыли, а не к первому совпавшему по имени.
func TestSameInterfaceNameOnTwoServers(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	kz, err := e.store.AddServer(ctx, store.NewServer{Slug: "kz", Title: "Казахстан", NodePort: 10089})
	if err != nil {
		t.Fatal(err)
	}
	// То же имя, что у интерфейса на de: так и вышло в парке со служебными туннелями.
	twinID, err := e.store.UpsertInterface(ctx, kz.ID, "awg-t0", store.InterfaceFacts{
		Subnet: "10.30.0.0/24", ServerAddress: "10.30.0.1/24", ListenPort: 443, MTU: 1280, IsAWG: true})
	if err != nil {
		t.Fatal(err)
	}
	csrf := e.login(t)

	_, first := e.get(t, "/interfaces/"+itoa(e.iface.ID))
	if !strings.Contains(first, "Германия") {
		t.Fatal("страница первого интерфейса не называет его сервер")
	}
	_, second := e.get(t, "/interfaces/"+itoa(twinID))
	if !strings.Contains(second, "Казахстан") {
		t.Fatal("страница второго интерфейса показывает чужой сервер")
	}

	// Действие применяется к открытому интерфейсу.
	loc := e.action(t, "/interfaces/"+itoa(twinID)+"/defaults", url.Values{
		"dns": {"10.30.0.1"}, "keepalive": {"25"}, "allowed_ips": {"0.0.0.0/0"},
	}, csrf)
	if _, bad := flashOf(t, loc); bad != "" {
		t.Fatalf("сохранение умолчаний: %q", bad)
	}
	list, err := e.store.Interfaces(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range list {
		switch i.ID {
		case twinID:
			if i.DefaultDNS != "10.30.0.1" {
				t.Fatalf("умолчание не дошло до выбранного интерфейса: %q", i.DefaultDNS)
			}
		case e.iface.ID:
			if i.DefaultDNS == "10.30.0.1" {
				t.Fatal("умолчание уехало на однофамильца с другого сервера")
			}
		}
	}
}

// Наблюдаемый интерфейс — не работа для человека: панель на нём ничего не пишет. Служебные
// туннели под наблюдением есть на каждой машине парка, и раньше от них сервер вечно выглядел
// «требующим внимания», а очередь дел состояла из строк «режим observe».
func TestObservedInterfaceIsQuiet(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	now := time.Now()
	if _, err := e.store.DB().ExecContext(ctx, `UPDATE servers SET last_seen_at = ? WHERE id = 1`, now.Unix()); err != nil {
		t.Fatal(err)
	}
	if err := e.store.InsertHostMetric(ctx, store.HostMetric{ServerID: 1, TS: now, CPU: 3,
		MemUsed: 400_000_000, MemTotal: 4_000_000_000, DiskUsed: 4_000_000_000, DiskTotal: 40_000_000_000, Load1: 0.1}); err != nil {
		t.Fatal(err)
	}
	// Рабочий интерфейс под управлением панели и служебный туннель под наблюдением — рядом.
	if _, err := e.store.DB().ExecContext(ctx, `UPDATE interfaces SET mode = 'own', unit_active = 1 WHERE id = ?`, e.iface.ID); err != nil {
		t.Fatal(err)
	}
	hub, err := e.store.UpsertInterface(ctx, 1, "awg-hub", store.InterfaceFacts{
		Subnet: "10.100.0.0/30", ServerAddress: "10.100.0.1/30", ListenPort: 8444, MTU: 1420, IsAWG: true, UnitActive: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.store.DB().ExecContext(ctx, `UPDATE interfaces SET mode = 'observe' WHERE id = ?`, hub); err != nil {
		t.Fatal(err)
	}
	e.login(t)

	_, body := e.get(t, "/")
	if strings.Contains(body, "требует внимания") {
		t.Fatal("сервер жёлтый из-за наблюдаемого интерфейса")
	}
	if strings.Contains(body, "observe — только наблюдение") || strings.Contains(body, "панель владеет пирами") {
		t.Fatal("на карточке остались старые слова о режимах")
	}
	if !strings.Contains(body, ">наблюдение<") || !strings.Contains(body, ">управление<") {
		t.Fatal("режимы названы не так, как договорились")
	}
	// Наблюдаемая строка приглушена: класс отличает её от рабочей.
	if !strings.Contains(body, "card__foot--quiet") {
		t.Fatal("наблюдаемый интерфейс не приглушён")
	}
	// А неподнятый интерфейс красит вердикт независимо от режима: туннель не работает.
	if _, err := e.store.DB().ExecContext(ctx, `UPDATE interfaces SET unit_active = 0 WHERE id = ?`, hub); err != nil {
		t.Fatal(err)
	}
	if _, body = e.get(t, "/"); !strings.Contains(body, "не поднят") {
		t.Fatal("неподнятый интерфейс перестал попадать в дела")
	}
}

// В карточке сервера первым идёт то, чем панель управляет: наблюдаемые туннели есть на каждой
// машине парка, и рабочий интерфейс терялся среди них.
func TestManagedInterfacesGoFirst(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	now := time.Now()
	if _, err := e.store.DB().ExecContext(ctx, `UPDATE servers SET last_seen_at = ? WHERE id = 1`, now.Unix()); err != nil {
		t.Fatal(err)
	}
	// Наблюдаемый заведён раньше рабочего: по имени и по идентификатору он был бы первым.
	watch, err := e.store.UpsertInterface(ctx, 1, "awg-aaa", store.InterfaceFacts{
		Subnet: "10.100.0.0/30", ListenPort: 8444, MTU: 1420, IsAWG: true, UnitActive: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.store.DB().ExecContext(ctx, `UPDATE interfaces SET mode = 'observe' WHERE id = ?`, watch); err != nil {
		t.Fatal(err)
	}
	if _, err := e.store.DB().ExecContext(ctx, `UPDATE interfaces SET mode = 'own', unit_active = 1 WHERE id = ?`, e.iface.ID); err != nil {
		t.Fatal(err)
	}
	e.login(t)

	for _, path := range []string{"/", "/servers/de", "/interfaces"} {
		_, body := e.get(t, path)
		own, observed := strings.Index(body, "awg-t0"), strings.Index(body, "awg-aaa")
		if own < 0 || observed < 0 {
			t.Fatalf("%s: интерфейсы не показаны (own=%d, observe=%d)", path, own, observed)
		}
		if own > observed {
			t.Fatalf("%s: наблюдаемый интерфейс оказался выше управляемого", path)
		}
	}
}

// Пустая очередь дел карточки не занимает: «дел нет» и так сказано вердиктом наверху.
func TestEmptyTaskQueueIsHidden(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	now := time.Now()
	if _, err := e.store.DB().ExecContext(ctx, `UPDATE servers SET last_seen_at = ? WHERE id = 1`, now.Unix()); err != nil {
		t.Fatal(err)
	}
	if err := e.store.InsertHostMetric(ctx, store.HostMetric{ServerID: 1, TS: now, CPU: 2,
		MemUsed: 300_000_000, MemTotal: 4_000_000_000, DiskUsed: 3_000_000_000, DiskTotal: 40_000_000_000, Load1: 0.1}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.store.DB().ExecContext(ctx, `UPDATE interfaces SET mode = 'own', unit_active = 1 WHERE id = ?`, e.iface.ID); err != nil {
		t.Fatal(err)
	}
	// Свежая копия — тоже часть «дел нет»: без неё в очереди стоит «Резервных копий нет».
	e.putBackup(t, now)
	e.login(t)

	_, body := e.get(t, "/")
	if strings.Contains(body, "Надо сделать") {
		t.Fatalf("пустая очередь дел показана карточкой: %s", taskQueue(body))
	}

	// Появилось дело — появилась и карточка.
	if _, err := e.store.DB().ExecContext(ctx, `UPDATE servers SET reboot_required = 1 WHERE id = 1`); err != nil {
		t.Fatal(err)
	}
	if _, body = e.get(t, "/"); !strings.Contains(body, "Надо сделать") || !strings.Contains(body, "нужна перезагрузка") {
		t.Fatal("дело есть, а очереди нет")
	}
}

// Дело о копиях следует за возрастом последней: без копий и с копией старше двух суток оно в
// очереди, со свежей — молчит. Возраст берётся из времени файла, поэтому тест ставит его сам.
func TestBackupTaskFollowsCopyAge(t *testing.T) {
	e := newEnv(t)
	e.login(t)

	if _, body := e.get(t, "/"); !strings.Contains(body, "Резервных копий нет") {
		t.Fatalf("копий нет, а дела об этом нет: %s", taskQueue(body))
	}
	e.putBackup(t, time.Now().Add(-72*time.Hour))
	if _, body := e.get(t, "/"); !strings.Contains(body, "Копия не делалась") {
		t.Fatalf("копии трое суток, а дела об этом нет: %s", taskQueue(body))
	}
	e.putBackup(t, time.Now())
	if _, body := e.get(t, "/"); strings.Contains(body, "Копия не делалась") || strings.Contains(body, "Резервных копий нет") {
		t.Fatalf("копия свежая, а дело о копиях осталось: %s", taskQueue(body))
	}
}

// taskQueue вынимает из страницы названия дел: когда очередь не та, в отказе видно, какое
// именно дело в неё попало, а не только то, что карточка есть.
func taskQueue(body string) string {
	const mark = `<div class="task__what">`
	var out []string
	for {
		i := strings.Index(body, mark)
		if i < 0 {
			return strings.Join(out, "; ")
		}
		body = body[i+len(mark):]
		if j := strings.Index(body, "</div>"); j >= 0 {
			out = append(out, body[:j])
		}
	}
}
