-- awgdash · имена в нижнем регистре отдельной колонкой (ТЗ §7.1, §6.2).
-- SQLite не знает регистра кириллицы, поэтому поиск и сортировка звали функцию соединения
-- ulower(): она считалась для каждой строки и мешала индексам. Колонку заполняет код.
ALTER TABLE users ADD COLUMN name_ci TEXT NOT NULL DEFAULT '';
ALTER TABLE devices ADD COLUMN name_ci TEXT NOT NULL DEFAULT '';
CREATE INDEX users_name_ci ON users(name_ci) WHERE deleted_at IS NULL;
CREATE INDEX devices_name_ci ON devices(user_id, name_ci) WHERE deleted_at IS NULL;
