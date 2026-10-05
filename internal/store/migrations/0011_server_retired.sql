-- Вывод сервера из парка (SPEC FR-10.6): машина потеряна или закрыта навсегда.
-- enabled = 0 значит «временно не опрашиваем», retired_at — «этой машины больше нет».
ALTER TABLE servers ADD COLUMN retired_at INTEGER;
