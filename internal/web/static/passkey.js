// Вход по ключу: Windows Hello, Touch ID, Face ID. Браузер сам держит приватную часть,
// панель получает только подпись. Без JS этот путь невозможен в принципе — пароль остаётся.
(function () {
  'use strict';

  var b64u = {
    decode: function (s) {
      s = String(s).replace(/-/g, '+').replace(/_/g, '/');
      while (s.length % 4) s += '=';
      var raw = atob(s), buf = new Uint8Array(raw.length);
      for (var i = 0; i < raw.length; i++) buf[i] = raw.charCodeAt(i);
      return buf.buffer;
    },
    encode: function (buf) {
      var bytes = new Uint8Array(buf), s = '';
      for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
      return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    },
  };

  function supported() {
    return !!(window.PublicKeyCredential && navigator.credentials && navigator.credentials.create);
  }

  function say(el, text, bad) {
    if (!el) return;
    el.textContent = text || '';
    el.hidden = !text;
    el.className = bad ? 'note note--bad' : 'note';
  }

  async function post(url, body) {
    var opts = { method: 'POST', credentials: 'same-origin', headers: {} };
    var csrf = document.querySelector('meta[name="csrf"]');
    if (csrf) opts.headers['X-CSRF-Token'] = csrf.content;
    if (body !== undefined) {
      opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(body);
    }
    var res = await fetch(url, opts);
    var data = null;
    try { data = await res.json(); } catch (e) { /* пустой ответ — ниже разберёмся по статусу */ }
    if (!res.ok) throw new Error((data && data.error) || ('сервер ответил ' + res.status));
    return data;
  }

  // Опции приходят с полями в base64url — браузеру нужны ArrayBuffer.
  function toCreateOptions(pk) {
    pk.challenge = b64u.decode(pk.challenge);
    pk.user.id = b64u.decode(pk.user.id);
    (pk.excludeCredentials || []).forEach(function (c) { c.id = b64u.decode(c.id); });
    return pk;
  }

  function toGetOptions(pk) {
    pk.challenge = b64u.decode(pk.challenge);
    (pk.allowCredentials || []).forEach(function (c) { c.id = b64u.decode(c.id); });
    return pk;
  }

  function fromCredential(cred) {
    var out = {
      id: cred.id,
      rawId: b64u.encode(cred.rawId),
      type: cred.type,
      clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
    };
    var r = cred.response;
    if (r.attestationObject) {
      out.response = {
        attestationObject: b64u.encode(r.attestationObject),
        clientDataJSON: b64u.encode(r.clientDataJSON),
      };
      if (r.getTransports) out.response.transports = r.getTransports();
    } else {
      out.response = {
        authenticatorData: b64u.encode(r.authenticatorData),
        clientDataJSON: b64u.encode(r.clientDataJSON),
        signature: b64u.encode(r.signature),
        userHandle: r.userHandle ? b64u.encode(r.userHandle) : null,
      };
    }
    return out;
  }

  // Ошибки WebAuthn говорят кодами; переводим в то, что можно прочитать.
  function human(err) {
    if (!err) return 'не получилось';
    if (err.name === 'NotAllowedError') return 'отменено или истекло время ожидания';
    if (err.name === 'InvalidStateError') return 'на этом устройстве ключ уже заведён';
    if (err.name === 'SecurityError') return 'браузер не доверяет адресу панели — нужен https или localhost';
    return err.message || String(err);
  }

  async function register(button, note) {
    var name = (document.getElementById('passkey-name') || {}).value || '';
    button.disabled = true;
    say(note, 'подтвердите на устройстве…');
    try {
      var options = await post('/settings/passkeys/begin');
      var cred = await navigator.credentials.create({ publicKey: toCreateOptions(options.publicKey) });
      await post('/settings/passkeys/finish?name=' + encodeURIComponent(name.trim()), fromCredential(cred));
      location.href = '/settings?ok=' + encodeURIComponent('ключ добавлен');
    } catch (err) {
      say(note, human(err), true);
      button.disabled = false;
    }
  }

  async function login(button, note) {
    button.disabled = true;
    say(note, 'подтвердите на устройстве…');
    try {
      var options = await post('/login/passkey/begin');
      var cred = await navigator.credentials.get({ publicKey: toGetOptions(options.publicKey) });
      var next = new URLSearchParams(location.search).get('next') || '';
      var res = await post('/login/passkey/finish?next=' + encodeURIComponent(next), fromCredential(cred));
      location.href = (res && res.next) || '/';
    } catch (err) {
      say(note, human(err), true);
      button.disabled = false;
    }
  }

  document.addEventListener('DOMContentLoaded', function () {
    var loginBtn = document.getElementById('passkey-login');
    var regBtn = document.getElementById('passkey-register');
    var note = document.getElementById('passkey-note');
    // Кнопки скрыты по умолчанию: в браузере без поддержки они бы только путали.
    if (!supported()) {
      // Вход по ключу невозможен — раскрываем форму логина, чтобы человек не искал её сам.
      var pw = document.getElementById('pw-details');
      if (pw) pw.open = true;
      return;
    }
    if (loginBtn) {
      loginBtn.hidden = false;
      loginBtn.addEventListener('click', function () { login(loginBtn, note); });
    }
    if (regBtn) {
      regBtn.hidden = false;
      regBtn.addEventListener('click', function () { register(regBtn, note); });
    }
  });
})();
