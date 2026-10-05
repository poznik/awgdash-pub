//go:build linux

package awg

import (
	"errors"
	"io/fs"
	"os"
	"syscall"
)

// preserveOwner переносит владельца исходного файла на новый: конфиг интерфейса принадлежит root,
// а панель работает от awgdash (нужен CAP_CHOWN; без него — понятная ошибка).
func preserveOwner(info fs.FileInfo, dst string) error {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	if os.Geteuid() == int(st.Uid) {
		return nil // владелец и так наш
	}
	return os.Chown(dst, int(st.Uid), int(st.Gid))
}

// isNotSupported — «операция не поддерживается» (fsync каталога на некоторых ФС).
func isNotSupported(err error) bool {
	return errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOTSUP)
}
