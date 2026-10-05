package hub

import (
	"context"
	"fmt"

	"github.com/poznik/awgdash-pub/internal/store"
)

// MoveRequest — передать устройства другому владельцу (FR-3.9).
type MoveRequest struct {
	DeviceIDs  []int64
	ToUserID   int64
	RaiseLimit bool
	Actor      string
	IP         string
}

// MergeRequest — объединить пользователей: все живые устройства одного уезжают другому (FR-2.7).
type MergeRequest struct {
	FromUserID    int64
	ToUserID      int64
	RaiseLimit    bool
	DeleteEmptied bool // удалить опустевшего тем же действием
	Actor         string
	IP            string
}

// MergeResult — итог объединения. InTrash — сколько устройств осталось у прежнего владельца
// в корзине: они переезжают вместе с ним, а не к новому.
type MergeResult struct {
	store.MoveResult
	From    string
	To      string
	InTrash int
	Deleted bool
}

// MoveDevices переносит устройства и приводит их пиры к статусу нового владельца (FR-3.9).
// Запись в БД идёт первой, пиры догоняются следом — так же, как в остальных действиях панели:
// желаемое состояние живёт в базе, рантайм приводится к нему здесь и в reconcile.
func (h *Hub) MoveDevices(ctx context.Context, req MoveRequest) (store.MoveResult, error) {
	to, err := h.Store.UserByID(ctx, req.ToUserID)
	if err != nil {
		return store.MoveResult{}, fmt.Errorf("новый владелец не найден")
	}
	res, err := h.Store.MoveDevices(ctx, req.DeviceIDs, req.ToUserID, store.MoveOptions{RaiseLimit: req.RaiseLimit})
	if err != nil {
		return res, err
	}
	var applyErr error
	for _, m := range res.Moved {
		d, err := h.Store.DeviceByID(ctx, m.ID)
		if err != nil {
			if applyErr == nil {
				applyErr = err
			}
			continue
		}
		details := map[string]any{"name": d.Name, "to": to.Name, "to_user_id": to.ID}
		if m.Renamed() {
			details["was"] = m.Was
		}
		h.audit(ctx, req.Actor, "device.move", "device", d.ID, req.IP, details)

		iface, err := h.Interface(ctx, d.InterfaceID)
		if err != nil {
			if applyErr == nil {
				applyErr = err
			}
			continue
		}
		if err := h.applyDevice(ctx, iface, d); err != nil && applyErr == nil {
			applyErr = err
		}
	}
	return res, applyErr
}

// MergeUsers сводит двух людей в одного: устройства переезжают, опустевшего можно удалить тем же
// действием (FR-2.7). Нужно после импорта — там один человек приходит несколькими записями.
func (h *Hub) MergeUsers(ctx context.Context, req MergeRequest) (MergeResult, error) {
	var out MergeResult
	if req.FromUserID == req.ToUserID {
		return out, fmt.Errorf("выбран тот же самый пользователь")
	}
	from, err := h.Store.UserByID(ctx, req.FromUserID)
	if err != nil {
		return out, err
	}
	to, err := h.Store.UserByID(ctx, req.ToUserID)
	if err != nil {
		return out, fmt.Errorf("новый владелец не найден")
	}
	out.From, out.To = from.Name, to.Name

	devs, err := h.Store.DevicesByUser(ctx, req.FromUserID)
	if err != nil {
		return out, err
	}
	if len(devs) == 0 {
		return out, fmt.Errorf("у «%s» нет устройств — объединять нечего", from.Name)
	}
	ids := make([]int64, 0, len(devs))
	for _, d := range devs {
		ids = append(ids, d.ID)
	}
	res, moveErr := h.MoveDevices(ctx, MoveRequest{
		DeviceIDs: ids, ToUserID: req.ToUserID, RaiseLimit: req.RaiseLimit, Actor: req.Actor, IP: req.IP,
	})
	out.MoveResult = res
	if len(res.Moved) == 0 {
		return out, moveErr
	}
	out.InTrash, err = h.Store.CountTrashedDevices(ctx, req.FromUserID)
	if err != nil {
		return out, err
	}

	h.audit(ctx, req.Actor, "user.merge", "user", from.ID, req.IP,
		map[string]any{"from": from.Name, "to": to.Name, "to_user_id": to.ID, "devices": len(res.Moved), "renamed": res.Renamed()})
	h.event(ctx, "users_merged", "info", 0, 0,
		fmt.Sprintf("устройства «%s» (%d шт.) переданы «%s»", from.Name, len(res.Moved), to.Name))

	if req.DeleteEmptied {
		if err := h.DeleteUser(ctx, req.FromUserID, req.Actor, req.IP); err != nil {
			return out, err
		}
		out.Deleted = true
	}
	return out, moveErr
}
