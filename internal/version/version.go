// Package version хранит версию сборки (подставляется через -ldflags).
package version

// Version — git describe на момент сборки; "dev" для локальных запусков.
var Version = "dev"

// API — версия контракта узла (SPEC §9). Хаб отказывается работать с узлом другой мажорной версии.
const API = 1
