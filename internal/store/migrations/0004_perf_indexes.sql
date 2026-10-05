-- awgdash · индекс под страницы со списками (ТЗ §7.1).
-- peers.device_id соединяет устройство с его пиром: без индекса каждый join шёл сканом.
-- Отдельный индекс по traffic_raw(peer_id, ts) не нужен: это и есть её первичный ключ.
CREATE INDEX peers_device ON peers(device_id) WHERE device_id IS NOT NULL;
