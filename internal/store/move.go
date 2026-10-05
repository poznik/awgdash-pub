package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// MoveOptions — как вести себя при переносе устройств (SPEC FR-3.9).
type MoveOptions struct {
	// RaiseLimit поднимает лимит устройств нового владельца, когда перенос его превышает.
	// Без него перенос сверх лимита отклоняется.
	RaiseLimit bool
}

// MovedDevice — одно перенесённое устройство. Was и Name различаются, когда имя было занято
// у нового владельца и получило суффикс.
type MovedDevice struct {
	ID          int64
	Was         string
	Name        string
	InterfaceID int64
}

// Renamed — переехало ли устройство под новым именем.
func (m MovedDevice) Renamed() bool { return m.Was != m.Name }

// MoveResult — итог переноса: для флеша в панели и для аудита.
type MoveResult struct {
	Moved    []MovedDevice
	Skipped  int      // уже принадлежали новому владельцу — не трогали
	NewLimit int      // 0 значит лимит не меняли
	Foreign  []string // имена устройств на серверах, не разрешённых новому владельцу
}

// Renamed — сколько устройств переехало с новым именем.
func (r MoveResult) Renamed() int {
	n := 0
	for _, m := range r.Moved {
		if m.Renamed() {
			n++
		}
	}
	return n
}

// MoveDevices передаёт устройства пользователю toUserID одной транзакцией (FR-3.9).
// Ключи, адрес и пир не трогаются: клиент переезда не замечает. Занятое имя получает суффикс
// с именем прежнего владельца. Устройства из корзины не переносятся.
func (s *Store) MoveDevices(ctx context.Context, ids []int64, toUserID int64, opts MoveOptions) (MoveResult, error) {
	var res MoveResult
	if len(ids) == 0 {
		return res, fmt.Errorf("переносить нечего")
	}
	now := time.Now().Unix()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return res, err
	}
	defer tx.Rollback()

	var to User
	var allowed string
	err = tx.QueryRowContext(ctx, `SELECT id, name, max_devices, allowed_interfaces FROM users WHERE id = ? AND deleted_at IS NULL`, toUserID).
		Scan(&to.ID, &to.Name, &to.MaxDevices, &allowed)
	if errors.Is(err, sql.ErrNoRows) {
		return res, fmt.Errorf("новый владелец не найден")
	}
	if err != nil {
		return res, err
	}
	to.AllowedInterfaces = parseIDs(allowed)

	type moving struct {
		id      int64
		name    string
		iface   int64
		owner   string
		ownerID int64
	}
	var list []moving
	for _, id := range ids {
		var m moving
		err := tx.QueryRowContext(ctx, `SELECT d.id, d.name, d.interface_id, d.user_id, u.name
			FROM devices d JOIN users u ON u.id = d.user_id
			WHERE d.id = ? AND d.deleted_at IS NULL`, id).Scan(&m.id, &m.name, &m.iface, &m.ownerID, &m.owner)
		if errors.Is(err, sql.ErrNoRows) {
			return res, fmt.Errorf("устройство %d не найдено или лежит в корзине", id)
		}
		if err != nil {
			return res, err
		}
		if m.ownerID == toUserID {
			res.Skipped++
			continue
		}
		list = append(list, m)
	}
	if len(list) == 0 {
		return res, fmt.Errorf("все устройства уже принадлежат «%s»", to.Name)
	}
	// Порядок переноса задаёт и порядок суффиксов, поэтому он должен быть устойчивым.
	sort.Slice(list, func(i, j int) bool { return list[i].id < list[j].id })

	var used int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM devices WHERE user_id = ? AND deleted_at IS NULL`, toUserID).Scan(&used); err != nil {
		return res, err
	}
	if total := used + len(list); total > to.MaxDevices {
		if !opts.RaiseLimit {
			return res, fmt.Errorf("у «%s» лимит %d устройств, а после переноса станет %d — поднимите лимит или перенесите меньше",
				to.Name, to.MaxDevices, total)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE users SET max_devices = ?, updated_at = ? WHERE id = ?`, total, now, toUserID); err != nil {
			return res, err
		}
		res.NewLimit = total
	}

	taken := map[string]bool{}
	rows, err := tx.QueryContext(ctx, `SELECT name_ci FROM devices WHERE user_id = ? AND deleted_at IS NULL`, toUserID)
	if err != nil {
		return res, err
	}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			rows.Close()
			return res, err
		}
		taken[n] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return res, err
	}

	for _, m := range list {
		name := freeDeviceName(m.name, m.owner, taken)
		taken[strings.ToLower(name)] = true
		res.Moved = append(res.Moved, MovedDevice{ID: m.id, Was: m.name, Name: name, InterfaceID: m.iface})
		if !to.Allows(m.iface) {
			res.Foreign = append(res.Foreign, name)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE devices SET user_id = ?, name = ?, name_ci = ?, updated_at = ? WHERE id = ?`,
			toUserID, name, strings.ToLower(name), now, m.id); err != nil {
			return res, friendlyConstraint(err)
		}
	}
	if err := tx.Commit(); err != nil {
		return res, err
	}
	return res, nil
}

// freeDeviceName возвращает имя, свободное у нового владельца: сначала как есть, потом с именем
// прежнего владельца («n1» → «n1 Nik»), потом с номером («n1 Nik 2»). Длина держится в 32 рунах.
func freeDeviceName(base, prevOwner string, taken map[string]bool) string {
	if !taken[strings.ToLower(base)] {
		return base
	}
	owner := deviceNamePart(prevOwner)
	for n := 1; n < 1000; n++ {
		var tail string
		switch {
		case owner == "":
			tail = " " + strconv.Itoa(n+1) // имя владельца ничего не дало: «n1 2», «n1 3», …
		case n == 1:
			tail = " " + owner // «n1 Nik»
		default:
			tail = " " + owner + " " + strconv.Itoa(n) // «n1 Nik 2», «n1 Nik 3», …
		}
		cand := fitDeviceName(base, tail)
		if !taken[strings.ToLower(cand)] {
			return cand
		}
	}
	// Тысяча занятых вариантов — свободного имени нет; уникальный индекс откатит перенос
	// с внятной ошибкой, выдумывать что-то ещё здесь незачем.
	return base
}

// deviceNamePart оставляет от имени человека то, что допустимо в имени устройства (FR-3.8).
func deviceNamePart(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_' || r == '.':
			b.WriteRune(r)
		case r == ' ' && b.Len() > 0:
			b.WriteRune(' ')
		}
	}
	return strings.TrimSpace(b.String())
}

// fitDeviceName склеивает основу с хвостом, укладываясь в 32 руны: сначала укорачивается основа,
// а если и хвост длиннее лимита — обрезается результат.
func fitDeviceName(base, tail string) string {
	const max = 32
	br, tr := []rune(base), []rune(tail)
	if len(br)+len(tr) > max {
		keep := max - len(tr)
		if keep < 1 {
			keep = 1
		}
		br = []rune(strings.TrimSpace(string(br[:keep])))
	}
	out := string(br) + tail
	if r := []rune(out); len(r) > max {
		out = strings.TrimSpace(string(r[:max]))
	}
	return out
}

// CountTrashedDevices — сколько устройств пользователя лежит в корзине. Они не переносятся
// (FR-3.9), поэтому панель о них предупреждает при объединении.
func (s *Store) CountTrashedDevices(ctx context.Context, userID int64) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM devices WHERE user_id = ? AND deleted_at IS NOT NULL`, userID).Scan(&n)
	return n, err
}
