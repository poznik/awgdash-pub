//go:build !linux

package awg

import "io/fs"

// preserveOwner на не-Linux ничего не делает: боевой сервер — Linux, остальное нужно только тестам.
func preserveOwner(fs.FileInfo, string) error { return nil }

// isNotSupported — вне Linux fsync каталога недоступен, поэтому его ошибка не считается фатальной.
func isNotSupported(error) bool { return true }
