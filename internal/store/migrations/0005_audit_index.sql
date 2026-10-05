-- awgdash · карточка пользователя и устройства показывает их историю: без индекса это скан журнала.
CREATE INDEX audit_target ON audit_log(target_type, target_id, ts);
CREATE INDEX audit_ts ON audit_log(ts);
