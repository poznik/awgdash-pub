-- Код страны сервера (ISO 3166-1 alpha-2) — из него панель рисует флаг рядом с названием.
-- Пусто значит «не задан»: тогда панель пробует угадать по слагу (de → DE, kz → KZ).
ALTER TABLE servers ADD COLUMN country TEXT NOT NULL DEFAULT '';
