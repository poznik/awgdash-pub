package awg

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Runner выполняет внешние команды; в тестах подменяется.
type Runner interface {
	Run(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error)
}

// ExecRunner — настоящий exec с таймаутом.
type ExecRunner struct{ Timeout time.Duration }

// Run запускает команду, stdin передаётся как есть (для PSK), stderr попадает в текст ошибки.
func (r ExecRunner) Run(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
	t := r.Timeout
	if t == 0 {
		t = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, t)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errb.String())
		if msg == "" {
			msg = err.Error()
		}
		return out.Bytes(), fmt.Errorf("%s %s: %s", name, strings.Join(args, " "), msg)
	}
	return out.Bytes(), nil
}

// Tool — обёртка над бинарником awg.
type Tool struct {
	Bin string
	R   Runner
}

// ShowDump возвращает разобранный `awg show <iface> dump`.
func (t Tool) ShowDump(ctx context.Context, iface string) (*InterfaceDump, []PeerDump, error) {
	out, err := t.R.Run(ctx, nil, t.Bin, "show", iface, "dump")
	if err != nil {
		return nil, nil, err
	}
	return ParseDump(string(out))
}

// Version возвращает строку `awg --version` (например "amneziawg-tools v3.0.20260805 - https://amnezia.org").
func (t Tool) Version(ctx context.Context) (string, error) {
	out, err := t.R.Run(ctx, nil, t.Bin, "--version")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// Interfaces возвращает список интерфейсов по `awg show interfaces`.
func (t Tool) Interfaces(ctx context.Context) ([]string, error) {
	out, err := t.R.Run(ctx, nil, t.Bin, "show", "interfaces")
	if err != nil {
		return nil, err
	}
	return strings.Fields(string(out)), nil
}

// UnitActive проверяет `systemctl is-active <unit>`; ошибка exec трактуется как "неактивен".
func UnitActive(ctx context.Context, r Runner, unit string) bool {
	out, _ := r.Run(ctx, nil, "systemctl", "is-active", unit)
	return strings.TrimSpace(string(out)) == "active"
}

// DockerPrefix — префикс записи о чужом менеджере, живущем в контейнере: `docker:<имя>`.
const DockerPrefix = "docker:"

// ManagerActive проверяет, работает ли сейчас чужой менеджер пиров. Запись без префикса —
// systemd-юнит, с префиксом `docker:` — контейнер: wg-easy и подобные панели юнита не имеют,
// а порт интерфейса забирают так же (FR-1.3).
func ManagerActive(ctx context.Context, r Runner, spec string) bool {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return false
	}
	if name := strings.TrimPrefix(spec, DockerPrefix); name != spec {
		if name == "" {
			return false
		}
		out, err := r.Run(ctx, nil, "docker", "inspect", "-f", "{{.State.Running}}", name)
		if err != nil {
			return false // контейнера нет вовсе — docker выходит с ошибкой
		}
		return strings.TrimSpace(string(out)) == "true"
	}
	return UnitActive(ctx, r, spec)
}
