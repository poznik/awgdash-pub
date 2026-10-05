// Package backup собирает и проверяет резервные копии панели: состояние, конфиги интерфейсов
// и переменные окружения в одном зашифрованном файле (SPEC §6.9).
//
// Формат: tar → zstd → age. Внутри архива manifest.json с контрольными суммами, копия БД,
// конфиги интерфейсов режима own и .env хаба. Файл целиком шифруется на публичный ключ
// получателя: внутри лежат приватные ключи сервера и клиентов, поэтому незашифрованных
// копий панель не делает вовсе.
package backup

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/klauspost/compress/zstd"
)

// Kind — вид копии. config восстанавливает панель, full сохраняет ещё и наблюдение.
type Kind string

const (
	KindConfig Kind = "config"
	KindFull   Kind = "full"
)

// Manifest — что внутри и откуда снято. Читается при восстановлении и печатается проверкой.
type Manifest struct {
	Kind        Kind      `json:"kind"`
	CreatedAt   time.Time `json:"created_at"`
	Version     string    `json:"awgdash_version"`
	Schema      string    `json:"schema"`
	AWGVersion  string    `json:"awg_version"`
	Server      Server    `json:"server"`
	Interfaces  []Iface   `json:"interfaces"`
	Files       []File    `json:"files"`
	AdminHost   string    `json:"admin_host,omitempty"`
	PortalHost  string    `json:"portal_host,omitempty"`
	AuthorizedK []string  `json:"authorized_keys,omitempty"` // публичные ключи, которые нужны для публикации
}

// Server — машина, с которой снят бэкап.
type Server struct {
	Slug        string `json:"slug"`
	Hostname    string `json:"hostname"`
	PublicIP    string `json:"public_ip"`
	EgressIface string `json:"egress_iface"`
	Kernel      string `json:"kernel"`
}

// Iface — интерфейс и его существенные параметры: при восстановлении по ним видно,
// что приехало то, что ожидалось.
type Iface struct {
	Name string `json:"name"`
	// Server — слаг сервера, на котором живёт интерфейс: в парке из нескольких узлов
	// без него непонятно, куда возвращать конфиг.
	Server      string `json:"server,omitempty"`
	ServerID    int64  `json:"server_id,omitempty"`
	ConfPath    string `json:"conf_path"`
	Subnet      string `json:"subnet"`
	ListenPort  int    `json:"listen_port"`
	MTU         int    `json:"mtu"`
	Mode        string `json:"mode"`
	Peers       int    `json:"peers"`
	Obfuscation int    `json:"obfuscation"`
}

// File — элемент архива с длиной и контрольной суммой.
type File struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// Entry — файл, который кладут в архив.
type Entry struct {
	Name string // путь внутри архива: db.sqlite, conf/awg-de.conf, env/awgdash.env
	Path string // откуда читать
	Mode int64
}

// ErrNoRecipient — бэкап без получателя невозможен: писать на диск незашифрованные
// приватные ключи панель не станет.
var ErrNoRecipient = fmt.Errorf("не задан публичный ключ age — шифровать копию нечем")

// Name собирает имя файла копии: вид, дата и время без секунд.
func Name(kind Kind, at time.Time) string {
	return fmt.Sprintf("awgdash-%s-%s.tar.zst.age", kind, at.Format("20060102-1504"))
}

// Create пишет зашифрованный архив в dst. Манифест дополняется контрольными суммами файлов
// прямо во время упаковки: считать их отдельным проходом значило бы читать всё дважды.
func Create(dst string, recipient string, m Manifest, entries []Entry) (int64, error) {
	if strings.TrimSpace(recipient) == "" {
		return 0, ErrNoRecipient
	}
	rcpt, err := age.ParseX25519Recipient(strings.TrimSpace(recipient))
	if err != nil {
		return 0, fmt.Errorf("публичный ключ age: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return 0, err
	}
	// Сначала считаем суммы: манифест кладётся в архив первым, а знать о содержимом
	// он должен всё.
	for i, e := range entries {
		sum, size, err := hashFile(e.Path)
		if err != nil {
			return 0, err
		}
		m.Files = append(m.Files, File{Name: e.Name, Size: size, SHA256: sum})
		entries[i] = e
	}
	sort.Slice(m.Files, func(a, b int) bool { return m.Files[a].Name < m.Files[b].Name })

	tmp := dst + ".part"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return 0, err
	}
	defer func() {
		out.Close()
		os.Remove(tmp) // на успешном пути файл уже переименован
	}()

	enc, err := age.Encrypt(out, rcpt)
	if err != nil {
		return 0, err
	}
	zw, err := zstd.NewWriter(enc, zstd.WithEncoderLevel(zstd.SpeedBetterCompression))
	if err != nil {
		return 0, err
	}
	tw := tar.NewWriter(zw)

	manifestJSON, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return 0, err
	}
	if err := writeTarBytes(tw, "manifest.json", manifestJSON, 0o600); err != nil {
		return 0, err
	}
	for _, e := range entries {
		if err := writeTarFile(tw, e); err != nil {
			return 0, err
		}
	}
	if err := tw.Close(); err != nil {
		return 0, err
	}
	if err := zw.Close(); err != nil {
		return 0, err
	}
	if err := enc.Close(); err != nil {
		return 0, err
	}
	if err := out.Sync(); err != nil {
		return 0, err
	}
	if err := out.Close(); err != nil {
		return 0, err
	}
	if err := os.Rename(tmp, dst); err != nil {
		return 0, err
	}
	st, err := os.Stat(dst)
	if err != nil {
		return 0, err
	}
	return st.Size(), nil
}

// Open расшифровывает архив и разворачивает его в каталог dir. Возвращает манифест.
// Пустой dir означает «только прочитать манифест и сверить суммы» — файлы не сохраняются.
func Open(src string, identities []age.Identity, dir string) (Manifest, error) {
	var m Manifest
	f, err := os.Open(src)
	if err != nil {
		return m, err
	}
	defer f.Close()
	dec, err := age.Decrypt(f, identities...)
	if err != nil {
		return m, fmt.Errorf("расшифровка %s: %w", filepath.Base(src), err)
	}
	zr, err := zstd.NewReader(dec)
	if err != nil {
		return m, err
	}
	defer zr.Close()
	tr := tar.NewReader(zr)

	sums := map[string]string{}
	sizes := map[string]int64{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return m, err
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		name := filepath.ToSlash(filepath.Clean(hdr.Name))
		// Архив свой, но проверка обязательна: путь с .. распаковался бы мимо каталога.
		if strings.HasPrefix(name, "..") || filepath.IsAbs(name) {
			return m, fmt.Errorf("подозрительное имя в архиве: %q", hdr.Name)
		}
		h := sha256.New()
		var dstFile *os.File
		if dir != "" && name != "manifest.json" {
			path := filepath.Join(dir, filepath.FromSlash(name))
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				return m, err
			}
			if dstFile, err = os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600); err != nil {
				return m, err
			}
		}
		var body []byte
		var w io.Writer = h
		if dstFile != nil {
			w = io.MultiWriter(h, dstFile)
		}
		if name == "manifest.json" {
			buf := &strings.Builder{}
			w = io.MultiWriter(h, buf)
			if _, err := io.Copy(w, tr); err != nil {
				return m, err
			}
			body = []byte(buf.String())
			if err := json.Unmarshal(body, &m); err != nil {
				return m, fmt.Errorf("манифест не разобран: %w", err)
			}
		} else {
			n, err := io.Copy(w, tr)
			if dstFile != nil {
				dstFile.Close()
			}
			if err != nil {
				return m, err
			}
			sizes[name] = n
		}
		sums[name] = hex.EncodeToString(h.Sum(nil))
	}
	if m.CreatedAt.IsZero() {
		return m, fmt.Errorf("в архиве нет манифеста — это не копия awgdash")
	}
	for _, want := range m.Files {
		got, ok := sums[want.Name]
		if !ok {
			return m, fmt.Errorf("в архиве нет файла %s, заявленного манифестом", want.Name)
		}
		if got != want.SHA256 {
			return m, fmt.Errorf("%s: контрольная сумма не сходится (архив повреждён)", want.Name)
		}
		if sizes[want.Name] != want.Size {
			return m, fmt.Errorf("%s: длина %d вместо %d", want.Name, sizes[want.Name], want.Size)
		}
	}
	return m, nil
}

// Identities читает приватные ключи age. Всё, что не похоже на строку ключа, пропускается:
// человек нередко хранит рядом публичный ключ и заметки, и падать из-за них нельзя.
// Путь "-" читает стандартный ввод.
func Identities(path string) ([]age.Identity, error) {
	var r io.Reader = os.Stdin
	if path != "-" {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		r = f
	}
	raw, err := io.ReadAll(io.LimitReader(r, 1<<20))
	if err != nil {
		return nil, err
	}
	var keys []string
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToUpper(line), "AGE-SECRET-KEY-1") {
			keys = append(keys, line)
		}
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("в %s нет строки AGE-SECRET-KEY-1…", source(path))
	}
	ids, err := age.ParseIdentities(strings.NewReader(strings.Join(keys, "\n")))
	if err != nil {
		return nil, fmt.Errorf("приватный ключ age: %w", err)
	}
	return ids, nil
}

func source(path string) string {
	if path == "-" {
		return "переданном ключе"
	}
	return path
}

// Keygen создаёт новую пару ключей: приватный отдаётся человеку один раз, публичный
// живёт в настройках панели.
func Keygen() (secret, public string, err error) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return "", "", err
	}
	return id.String(), id.Recipient().String(), nil
}

func writeTarBytes(tw *tar.Writer, name string, body []byte, mode int64) error {
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: mode, Size: int64(len(body)), ModTime: time.Now()}); err != nil {
		return err
	}
	_, err := tw.Write(body)
	return err
}

func writeTarFile(tw *tar.Writer, e Entry) error {
	f, err := os.Open(e.Path)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	mode := e.Mode
	if mode == 0 {
		mode = 0o600
	}
	if err := tw.WriteHeader(&tar.Header{Name: e.Name, Mode: mode, Size: st.Size(), ModTime: st.ModTime()}); err != nil {
		return err
	}
	_, err = io.Copy(tw, f)
	return err
}

func hashFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}
