package store

import (
	"context"
	"database/sql"
	"strings"
	"time"
)

// Totals — итоги трафика на любом уровне (устройство, пользователь, интерфейс, сервер): SPEC FR-6.3.
type Totals struct {
	DayRx, DayTx     uint64
	WeekRx, WeekTx   uint64
	MonthRx, MonthTx uint64
	AllRx, AllTx     uint64
}

// Point — одна корзина графика. Gap — панель в это время не работала: такой промежуток
// показывается разрывом, а не нулём (FR-6.7).
type Point struct {
	TS  int64
	Rx  uint64
	Tx  uint64
	Gap bool
}

// Speed — текущая скорость по последним дельтам (FR-6.6).
type Speed struct {
	RxBps, TxBps uint64
	Window       time.Duration
}

// StatsWindows — окна итогов. Сутки считаются по сырым записям, неделя и месяц — по часовым:
// сырые живут 48 часов, да и проход по ним ради месяца стоил бы слишком дорого.
const (
	windowDay   = 24 * time.Hour
	windowWeek  = 7 * 24 * time.Hour
	windowMonth = 30 * 24 * time.Hour
)

// m5Depth — до какой глубины можно опираться на пятиминутки (живут 14 дней, берём с запасом).
const m5Depth = 13 * 24 * time.Hour

// PeerTotals считает итоги по набору пиров. Пустой набор — нулевые итоги, а не ошибка:
// у пользователя может не быть ни одного устройства на интерфейсе.
func (s *Store) PeerTotals(ctx context.Context, peerIDs []int64) (Totals, error) {
	var t Totals
	if len(peerIDs) == 0 {
		return t, nil
	}
	ids := toArgs(peerIDs)
	ph := placeholders(len(peerIDs))

	day, err := s.sumTraffic(ctx, "traffic_raw", "ts", ids, ph, time.Now().Add(-windowDay))
	if err != nil {
		return t, err
	}
	week, err := s.sumTraffic(ctx, "traffic_1h", "bucket", ids, ph, time.Now().Add(-windowWeek))
	if err != nil {
		return t, err
	}
	month, err := s.sumTraffic(ctx, "traffic_1h", "bucket", ids, ph, time.Now().Add(-windowMonth))
	if err != nil {
		return t, err
	}
	t.DayRx, t.DayTx = day[0], day[1]
	t.WeekRx, t.WeekTx = week[0], week[1]
	t.MonthRx, t.MonthTx = month[0], month[1]

	// «Всё время» живёт в peer_state: там накопленные суммы, переживающие ретеншн и сбросы счётчиков.
	row := s.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(rx_total),0), COALESCE(SUM(tx_total),0) FROM peer_state WHERE peer_id IN (`+ph+`)`, ids...)
	if err := row.Scan(&t.AllRx, &t.AllTx); err != nil {
		return t, err
	}
	return t, nil
}

func (s *Store) sumTraffic(ctx context.Context, table, col string, ids []any, ph string, since time.Time) ([2]uint64, error) {
	var out [2]uint64
	args := append(append([]any{}, ids...), since.Unix())
	row := s.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(rx),0), COALESCE(SUM(tx),0) FROM `+table+`
		WHERE peer_id IN (`+ph+`) AND `+col+` >= ?`, args...)
	err := row.Scan(&out[0], &out[1])
	return out, err
}

// PeerSeries строит ряд по корзинам за период. Источник выбирается по длине окна: сутки — сырые
// записи, дальше — часовые агрегаты. Промежутки, когда панель молчала, помечаются Gap.
func (s *Store) PeerSeries(ctx context.Context, peerIDs []int64, serverID int64, since time.Time, bucket time.Duration) ([]Point, error) {
	// Берётся самый крупный агрегат, который умеет обслужить корзину. Обслужить значит «лечь в
	// каждую корзину»: часовые строки в получасовой корзине заполняют каждую вторую, и линия
	// падает в ноль через полчаса — суточный график рисовал такую «гребёнку», пока источник
	// выбирался по одной лишь глубине окна. Сырые записи за сутки — тысячи строк на пир, поэтому
	// они остаются для корзин мельче пятиминутки.
	table, col := "traffic_raw", "ts"
	switch {
	case bucket >= time.Hour || time.Since(since) > m5Depth:
		table, col = "traffic_1h", "bucket"
	case bucket >= 5*time.Minute:
		table, col = "traffic_5m", "bucket"
	}
	step := int64(bucket.Seconds())
	if step <= 0 {
		step = 3600
	}
	sums := map[int64][2]uint64{}
	if len(peerIDs) > 0 {
		ids := toArgs(peerIDs)
		args := append(append([]any{step}, ids...), since.Unix())
		rows, err := s.db.QueryContext(ctx, `SELECT `+col+` - `+col+` % ?, COALESCE(SUM(rx),0), COALESCE(SUM(tx),0)
			FROM `+table+` WHERE peer_id IN (`+placeholders(len(peerIDs))+`) AND `+col+` >= ? GROUP BY 1`, args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var b int64
			var rx, tx uint64
			if err := rows.Scan(&b, &rx, &tx); err != nil {
				rows.Close()
				return nil, err
			}
			sums[b] = [2]uint64{rx, tx}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}

	// Сердцебиение панели: метрики хоста пишутся раз в минуту, поэтому корзина без единой записи
	// метрик — это время, когда панель не работала.
	alive, err := s.aliveBuckets(ctx, serverID, since, step)
	if err != nil {
		return nil, err
	}

	from := since.Unix() - since.Unix()%step
	to := time.Now().Unix()
	out := make([]Point, 0, (to-from)/step+1)
	for b := from; b <= to; b += step {
		p := Point{TS: b}
		if v, ok := sums[b]; ok {
			p.Rx, p.Tx = v[0], v[1]
		} else if !alive[b] {
			p.Gap = true
		}
		out = append(out, p)
	}
	return out, nil
}

// aliveBuckets — в каких корзинах панель точно работала.
func (s *Store) aliveBuckets(ctx context.Context, serverID int64, since time.Time, step int64) (map[int64]bool, error) {
	alive := map[int64]bool{}
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT ts - ts % ? FROM host_metrics WHERE server_id = ? AND ts >= ?`,
		step, serverID, since.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var b int64
		if err := rows.Scan(&b); err != nil {
			return nil, err
		}
		alive[b] = true
	}
	return alive, rows.Err()
}

// PeerSpeed — скорость по последним дельтам: сумма за окно, делённая на окно (FR-6.6).
func (s *Store) PeerSpeed(ctx context.Context, peerIDs []int64, window time.Duration) (Speed, error) {
	sp := Speed{Window: window}
	if len(peerIDs) == 0 {
		return sp, nil
	}
	sum, err := s.sumTraffic(ctx, "traffic_raw", "ts", toArgs(peerIDs), placeholders(len(peerIDs)), time.Now().Add(-window))
	if err != nil {
		return sp, err
	}
	secs := uint64(window.Seconds())
	if secs == 0 {
		secs = 1
	}
	sp.RxBps, sp.TxBps = sum[0]/secs, sum[1]/secs
	return sp, nil
}

// PeerGrowth — сколько байт пир набрал за окно. Нужно для состояния «застрял»: хендшейка нет,
// а счётчики почти не растут (FR-6.2).
// LastTrafficAt — когда через пир последний раз шёл трафик. Нужно там, где рукопожатия нет:
// оно обнуляется вместе с интерфейсом, а история остаётся, и человеку важно услышать дату, а не
// «ни разу не подключалось». Смотрим все три горизонта: сырые записи живут сутки, пятиминутки
// две недели, часы дольше всех (FR-6.5).
func (s *Store) LastTrafficAt(ctx context.Context, peerIDs []int64) (map[int64]time.Time, error) {
	out := map[int64]time.Time{}
	if len(peerIDs) == 0 {
		return out, nil
	}
	ph := placeholders(len(peerIDs))
	q := `SELECT peer_id, MAX(ts) FROM traffic_raw WHERE peer_id IN (` + ph + `) AND rx + tx > 0 GROUP BY peer_id
		UNION ALL SELECT peer_id, MAX(bucket) FROM traffic_5m WHERE peer_id IN (` + ph + `) AND rx + tx > 0 GROUP BY peer_id
		UNION ALL SELECT peer_id, MAX(bucket) FROM traffic_1h WHERE peer_id IN (` + ph + `) AND rx + tx > 0 GROUP BY peer_id`
	args := toArgs(peerIDs)
	args = append(args, toArgs(peerIDs)...)
	args = append(args, toArgs(peerIDs)...)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var at sql.NullInt64
		if err := rows.Scan(&id, &at); err != nil {
			return nil, err
		}
		if !at.Valid || at.Int64 == 0 {
			continue
		}
		if t := time.Unix(at.Int64, 0); t.After(out[id]) {
			out[id] = t
		}
	}
	return out, rows.Err()
}

func (s *Store) PeerGrowth(ctx context.Context, peerIDs []int64, window time.Duration) (map[int64]uint64, error) {
	out := map[int64]uint64{}
	if len(peerIDs) == 0 {
		return out, nil
	}
	args := append(append([]any{}, toArgs(peerIDs)...), time.Now().Add(-window).Unix())
	rows, err := s.db.QueryContext(ctx, `SELECT peer_id, COALESCE(SUM(rx),0) + COALESCE(SUM(tx),0) FROM traffic_raw
		WHERE peer_id IN (`+placeholders(len(peerIDs))+`) AND ts >= ? GROUP BY peer_id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var n uint64
		if err := rows.Scan(&id, &n); err != nil {
			return nil, err
		}
		out[id] = n
	}
	return out, rows.Err()
}

// Day — строка таблицы «по дням» (FR-6.5).
type Day struct {
	Date   time.Time
	Rx, Tx uint64
}

// PeerDays — трафик по календарным дням за период, в указанной зоне: человек читает историю
// в своих сутках, а не в UTC.
func (s *Store) PeerDays(ctx context.Context, peerIDs []int64, since time.Time, loc *time.Location) ([]Day, error) {
	if len(peerIDs) == 0 {
		return nil, nil
	}
	args := append(append([]any{}, toArgs(peerIDs)...), since.Unix())
	rows, err := s.db.QueryContext(ctx, `SELECT bucket, COALESCE(SUM(rx),0), COALESCE(SUM(tx),0) FROM traffic_1h
		WHERE peer_id IN (`+placeholders(len(peerIDs))+`) AND bucket >= ? GROUP BY bucket ORDER BY bucket`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	byDay := map[string]*Day{}
	var order []string
	for rows.Next() {
		var b int64
		var rx, tx uint64
		if err := rows.Scan(&b, &rx, &tx); err != nil {
			return nil, err
		}
		local := time.Unix(b, 0).In(loc)
		day := time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, loc)
		key := day.Format("2006-01-02")
		if _, ok := byDay[key]; !ok {
			byDay[key] = &Day{Date: day}
			order = append(order, key)
		}
		byDay[key].Rx += rx
		byDay[key].Tx += tx
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]Day, 0, len(order))
	for i := len(order) - 1; i >= 0; i-- { // свежие дни сверху
		out = append(out, *byDay[order[i]])
	}
	return out, nil
}

// PeerIDsOf — пиры набора устройств (в том числе снятых с интерфейса: история остаётся).
func (s *Store) PeerIDsOf(ctx context.Context, deviceIDs []int64) ([]int64, error) {
	if len(deviceIDs) == 0 {
		return nil, nil
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM peers WHERE device_id IN (`+placeholders(len(deviceIDs))+`)`, toArgs(deviceIDs)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// InterfacePeerIDs — все пиры интерфейса, включая снятые: график интерфейса должен показывать
// и то, что было до удаления устройства.
func (s *Store) InterfacePeerIDs(ctx context.Context, ifaceID int64) ([]int64, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM peers WHERE interface_id = ?`, ifaceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// Vacuum ужимает файл БД после ретеншна (FR-6.8). Операция блокирующая, поэтому вызывается
// по расписанию, а не после каждой чистки.
func (s *Store) Vacuum(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `VACUUM`)
	return err
}

// DBSize — размер файла БД по данным самой SQLite (для страницы сервера и слежения за ростом).
func (s *Store) DBSize(ctx context.Context) (uint64, error) {
	var pages, pageSize uint64
	if err := s.db.QueryRowContext(ctx, `PRAGMA page_count`).Scan(&pages); err != nil {
		return 0, err
	}
	if err := s.db.QueryRowContext(ctx, `PRAGMA page_size`).Scan(&pageSize); err != nil {
		return 0, err
	}
	return pages * pageSize, nil
}

func toArgs(ids []int64) []any {
	out := make([]any, 0, len(ids))
	for _, id := range ids {
		out = append(out, id)
	}
	return out
}

func placeholders(n int) string {
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}

// PeerSpeeds — скорости пачкой: страница интерфейса и бот показывают, кто грузит канал, и
// спрашивать про каждого пира отдельным запросом при сотнях устройств слишком дорого.
func (s *Store) PeerSpeeds(ctx context.Context, peerIDs []int64, window time.Duration) (map[int64]Speed, error) {
	out := map[int64]Speed{}
	if len(peerIDs) == 0 {
		return out, nil
	}
	secs := uint64(window.Seconds())
	if secs == 0 {
		secs = 1
	}
	args := append(append([]any{}, toArgs(peerIDs)...), time.Now().Add(-window).Unix())
	rows, err := s.db.QueryContext(ctx, `SELECT peer_id, COALESCE(SUM(rx),0), COALESCE(SUM(tx),0) FROM traffic_raw
		WHERE peer_id IN (`+placeholders(len(peerIDs))+`) AND ts >= ? GROUP BY peer_id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var rx, tx uint64
		if err := rows.Scan(&id, &rx, &tx); err != nil {
			return nil, err
		}
		out[id] = Speed{RxBps: rx / secs, TxBps: tx / secs, Window: window}
	}
	return out, rows.Err()
}

// LastSampleAt — время последней разобранной выборки интерфейса. Хаб держит этот курсор в
// памяти; после перезапуска панели его надо восстановить, иначе она просит у узла весь его
// суточный буфер заново — на живом парке это десятки мегабайт в одном ответе.
func (s *Store) LastSampleAt(ctx context.Context, ifaceID int64) (time.Time, error) {
	var ts sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT MAX(ps.sampled_at) FROM peer_state ps
		JOIN peers p ON p.id = ps.peer_id WHERE p.interface_id = ?`, ifaceID).Scan(&ts)
	if err != nil || !ts.Valid {
		return time.Time{}, err
	}
	return time.Unix(ts.Int64, 0), nil
}
