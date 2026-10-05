# awgdash — сборка и доставка. Собирается локально, ставится по ssh.
#
# Куда ставить. Парк обновляется целиком: список ssh-алиасов лежит в .awgdash-hosts рядом с
# Makefile (по одному в строке, хаб — последним), он не попадает в репозиторий. Одна машина —
# `make deploy HOST=<ssh-алиас>`; файл .awgdash-host с единственным алиасом тоже понимается.
# Разъехавшиеся версии в парке стоят дорого: проверки идут на узле его же кодом, и узел от
# прошлой недели считает «пусто» и «0» разными состояниями, где хаб считает их одним.
HOSTS ?= $(shell cat .awgdash-hosts 2>/dev/null)
HOST ?= $(shell cat .awgdash-host 2>/dev/null)
TARGETS = $(if $(HOST),$(HOST),$(HOSTS))
VERSION := $(shell git describe --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/poznik/awgdash-pub/internal/version.Version=$(VERSION)

.PHONY: build test vet deploy versions doctor logs status clean

build:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o dist/awgdash ./cmd/awgdash
	@ls -la dist/awgdash

test:
	go test ./...

vet:
	gofmt -l cmd internal; go vet ./...

deploy: test build
	@test -n "$(TARGETS)" || { echo "не задан сервер: make deploy HOST=<ssh-алиас> или запишите алиасы парка в .awgdash-hosts"; exit 2; }
	@bad=""; for h in $(TARGETS); do echo "=== $$h"; if scp -q dist/awgdash $$h:/tmp/awgdash && scp -q deploy/awgdash.service $$h:/tmp/awgdash.service && ssh $$h 'sudo -n bash -s' < deploy/install.sh; then :; else bad="$$bad $$h"; fi; done; test -z "$$bad" || { echo; echo "!!! не обновились:$$bad"; }
	@$(MAKE) --no-print-directory versions

# versions — что на самом деле стоит в парке. Реестр панели показывает то же самое, но здесь
# видно машины, до которых панель не дотянулась.
versions:
	@test -n "$(TARGETS)" || { echo "не задан сервер: make versions HOST=<ssh-алиас> или .awgdash-hosts"; exit 2; }
	@echo; echo "версии парка:"; for h in $(TARGETS); do printf '  %-14s ' "$$h"; ssh -o ConnectTimeout=10 $$h 'sudo -n /opt/awgdash/awgdash version' 2>/dev/null | tail -1 || echo "нет связи"; done

doctor:
	@test -n "$(HOST)" || { echo "не задан сервер: make doctor HOST=<ssh-алиас> или запишите алиас в .awgdash-host"; exit 2; }
	ssh $(HOST) 'sudo -n bash -c "set -a; . /etc/awgdash/awgdash.env; /opt/awgdash/awgdash doctor"'

logs:
	@test -n "$(HOST)" || { echo "не задан сервер: make logs HOST=<ssh-алиас> или запишите алиас в .awgdash-host"; exit 2; }
	ssh $(HOST) 'sudo -n journalctl -u awgdash -n 50 --no-pager -o cat'

status:
	@test -n "$(HOST)" || { echo "не задан сервер: make status HOST=<ssh-алиас> или запишите алиас в .awgdash-host"; exit 2; }
	ssh $(HOST) 'sudo -n systemctl status awgdash --no-pager; curl -s http://127.0.0.1:10088/healthz'

clean:
	rm -rf dist
