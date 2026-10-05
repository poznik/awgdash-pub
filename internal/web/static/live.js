// awgdash · живые данные (ТЗ §7.1): раз в 5 с блок с data-live перезапрашивает свой фрагмент.
// Без этого файла страница остаётся рабочей — она уже отрисована сервером, просто не обновляется.
(function () {
  "use strict";
  var EVERY = 5000;
  var blocks = Array.prototype.slice.call(document.querySelectorAll("[data-live]"));
  if (!blocks.length) return;
  var pause = 0; // растёт при ошибках: молчащий сервер не нужно долбить каждые 5 с

  function busy(el) {
    // Пока внутри блока печатают или открыт раскрывающийся блок, подменять его содержимое нельзя.
    if (el.contains(document.activeElement) && document.activeElement !== document.body) return true;
    return !!el.querySelector("details[open]");
  }

  function refresh(el) {
    if (busy(el)) return Promise.resolve();
    return fetch(el.getAttribute("data-live"), { credentials: "same-origin", headers: { "X-Live": "1" } })
      .then(function (r) {
        if (!r.ok) throw new Error(r.status);
        return r.text();
      })
      .then(function (html) {
        if (!busy(el)) {
          el.innerHTML = html;
          // Внутри фрагмента могут быть графики: им нужно навесить подсказку заново.
          el.dispatchEvent(new CustomEvent('awgdash:live', { bubbles: true }));
        }
        pause = 0;
      })
      .catch(function () {
        pause = Math.min(pause ? pause * 2 : EVERY, 60000);
      });
  }

  function tick() {
    if (document.hidden) return; // вкладка в фоне — не тратим ни сеть, ни батарею
    blocks.forEach(refresh);
  }

  var timer = setInterval(function () {
    if (pause) { pause -= EVERY; return; }
    tick();
  }, EVERY);
  document.addEventListener("visibilitychange", function () {
    if (!document.hidden) tick();
  });
  window.addEventListener("pagehide", function () { clearInterval(timer); });
})();

// Копирование по кнопке (design.md: JS в панели — только живые статусы и «скопировать»).
(function () {
  "use strict";
  var toast = document.querySelector("[data-toast]");
  var timer;

  function show(text) {
    if (!toast) return;
    toast.textContent = text;
    toast.setAttribute("data-show", "true");
    clearTimeout(timer);
    timer = setTimeout(function () { toast.removeAttribute("data-show"); }, 2200);
  }

  // Запасной путь для случаев, когда буфер обмена недоступен (старый браузер, не-secure origin).
  function legacyCopy(text) {
    var area = document.createElement("textarea");
    area.value = text;
    area.setAttribute("readonly", "");
    area.style.position = "fixed";
    area.style.opacity = "0";
    document.body.appendChild(area);
    area.select();
    var ok = false;
    try { ok = document.execCommand("copy"); } catch (e) { ok = false; }
    document.body.removeChild(area);
    return ok;
  }

  document.addEventListener("click", function (e) {
    var btn = e.target.closest ? e.target.closest("[data-copy]") : null;
    if (!btn) return;
    var src = document.querySelector(btn.getAttribute("data-copy"));
    if (!src) return;
    var text = (src.textContent || "").trim();
    var done = btn.getAttribute("data-copied") || "скопировано";
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(function () { show(done); },
        function () { show(legacyCopy(text) ? done : "не вышло скопировать — выделите текст руками"); });
      return;
    }
    show(legacyCopy(text) ? done : "не вышло скопировать — выделите текст руками");
  });
})();

// Модалки: ссылка с data-modal открывает <dialog> с тем же содержимым, что и страница,
// на которую она ведёт. Без JS ссылка просто открывает эту страницу — форма доступна всегда.
(function () {
  'use strict';
  document.addEventListener('click', function (e) {
    var open = e.target.closest ? e.target.closest('[data-modal]') : null;
    if (open) {
      var dlg = document.getElementById(open.getAttribute('data-modal'));
      if (dlg && dlg.showModal) {
        e.preventDefault();
        dlg.showModal();
        // Курсор уходит туда, куда человек и так собирался писать: в имя устройства.
        var first = dlg.querySelector('[autofocus]') ||
          dlg.querySelector('input[type="text"], input[type="radio"], button');
        if (first) first.focus();
        return;
      }
    }
    var close = e.target.closest ? e.target.closest('[data-modal-close]') : null;
    if (close) {
      var box = close.closest('dialog');
      if (box) {
        e.preventDefault();
        box.close();
      }
    }
  });
  // Клик по затемнению закрывает: диалог занимает всю площадь, поэтому смотрим на координаты.
  // Считается только клик, начатый и законченный на затемнении: иначе выделение имени мышью,
  // отпущенное за краем формы, засчитывалось диалогу как «клик мимо» и закрывало его.
  document.addEventListener('DOMContentLoaded', function () {
    document.querySelectorAll('dialog.modal').forEach(function (dlg) {
      var onBackdrop = function (e) {
        if (e.target !== dlg) return false;
        var r = dlg.getBoundingClientRect();
        return e.clientX < r.left || e.clientX > r.right || e.clientY < r.top || e.clientY > r.bottom;
      };
      var started = false;
      dlg.addEventListener('mousedown', function (e) { started = onBackdrop(e); });
      dlg.addEventListener('click', function (e) {
        if (started && onBackdrop(e)) dlg.close();
        started = false;
      });
    });
  });
})();

// Кнопка, открывающая свёрнутый блок и подводящая к нему: без скрипта ссылка просто
// прокручивает к якорю, и блок раскрывается щелчком по заголовку.
document.addEventListener('click', function (e) {
  var link = e.target.closest('[data-open]');
  if (!link) return;
  var box = document.querySelector(link.getAttribute('data-open'));
  if (!box) return;
  e.preventDefault();
  if (box.tagName === 'DETAILS') box.open = true;
  box.scrollIntoView({ behavior: 'smooth', block: 'start' });
  var field = box.querySelector('input, select, textarea');
  if (field) setTimeout(function () { field.focus({ preventScroll: true }); }, 250);
});

// График по наведению: показывает время корзины и сколько в ней скачано и отдано.
// Точки приходят из разметки уже отформатированными — браузеру остаётся найти ближайшую.
(function () {
  function setup(fig) {
    var raw = fig.getAttribute('data-points');
    if (!raw || raw === 'null') return;
    var pts;
    try { pts = JSON.parse(raw); } catch (e) { return; }
    if (!pts.length) return;
    var plot = fig.querySelector('.chart__plot');
    var svg = fig.querySelector('svg');
    var tip = fig.querySelector('.chart__tip');
    var guide = fig.querySelector('.chart__guide');
    if (!plot || !svg || !tip) return;
    var width = svg.viewBox.baseVal.width || 1;

    function show(e) {
      var box = svg.getBoundingClientRect();
      if (!box.width) return;
      var x = ((e.clientX - box.left) / box.width) * width;
      var best = pts[0], dist = Math.abs(pts[0].x - x);
      for (var i = 1; i < pts.length; i++) {
        var d = Math.abs(pts[i].x - x);
        if (d < dist) { dist = d; best = pts[i]; }
      }
      tip.innerHTML = '<b>' + best.t + '</b> · ↓ ' + best.d + ' · ↑ ' + best.u;
      var left = (best.x / width) * box.width;
      tip.style.left = left + 'px';
      tip.style.top = '-2px';
      tip.hidden = false;
      if (guide) {
        guide.setAttribute('x1', best.x);
        guide.setAttribute('x2', best.x);
        guide.hidden = false;
      }
    }
    function hide() {
      tip.hidden = true;
      if (guide) guide.hidden = true;
    }
    plot.addEventListener('mousemove', show);
    plot.addEventListener('mouseleave', hide);
    plot.addEventListener('touchmove', function (e) {
      if (e.touches.length === 1) show(e.touches[0]);
    }, { passive: true });
    plot.addEventListener('touchend', hide);
  }
  function scan(root) { (root || document).querySelectorAll('[data-chart]').forEach(setup); }
  document.addEventListener('DOMContentLoaded', function () { scan(document); });
  // Живые фрагменты перерисовывают разметку — графики в них подхватываются заново.
  document.addEventListener('awgdash:live', function (e) { scan(e.target); });
})();

// Форма нового устройства: подсказки «что подставит панель» зависят от выбранного сервера и
// типа устройства. Без скрипта в полях стоят значения первого сервера и типа «телефон» —
// ровно того, что отмечено при открытии формы.
(function () {
  'use strict';
  function apply(form) {
    var box = form.matches && form.matches('[data-hints]') ? form : form.querySelector('[data-hints]');
    if (!box) return;
    // Где лежат значения: в форме создания — на переключателе сервера, в форме правки
    // устройства сервер не меняется, и они висят на самой форме.
    var iface = form.querySelector('input[name="interface_id"]:checked') ||
      form.querySelector('input[name="interface_id"]') || box;
    var preset = form.querySelector('input[name="preset"]:checked');
    var router = preset && preset.value === 'router';
    var put = function (name, attr) {
      var input = box.querySelector('[name="' + name + '"]');
      var value = iface.getAttribute(attr);
      if (input && value) input.placeholder = value;
    };
    put('dns', 'data-dns');
    put('mtu', 'data-mtu');
    put('keepalive', router ? 'data-ka-router' : 'data-ka');
    put('allowed_ips', router ? 'data-ip-router' : 'data-ip');
  }
  document.addEventListener('change', function (e) {
    var t = e.target;
    if (!t || (t.name !== 'interface_id' && t.name !== 'preset')) return;
    var form = t.closest ? t.closest('form') : null;
    if (form) apply(form);
  });
})();
