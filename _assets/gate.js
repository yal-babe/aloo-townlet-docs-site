(function () {
  'use strict';

  var MANIFEST_URL = '_enc/manifest.json';
  var BUILD_TAG = '';

  function isGatedUrl(target) {
    var clean = String(target).split('#')[0].split('?')[0];
    return /\.(md|json)$/i.test(clean) && clean.indexOf('_enc/') === -1;
  }
  var CHECK_TEXT = 'aloo-townlet-kb';
  var SESSION_KEY = 'kb-key';
  var REMEMBER_KEY = 'kb-remember';
  var REMEMBER_MS = 7 * 24 * 60 * 60 * 1000;

  var manifest = null;
  var key = null;

  function b64ToBytes(b64) {
    var bin = atob(b64);
    var bytes = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  }

  function bytesToB64(bytes) {
    var bin = '';
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin);
  }

  function decryptWith(candidate, packed) {
    return crypto.subtle
      .decrypt({ name: 'AES-GCM', iv: b64ToBytes(packed.iv) }, candidate, b64ToBytes(packed.ct))
      .then(function (buf) {
        return new TextDecoder().decode(buf);
      });
  }

  function deriveKey(password) {
    var enc = new TextEncoder();
    return crypto.subtle
      .importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey'])
      .then(function (baseKey) {
        return crypto.subtle.deriveKey(
          {
            name: 'PBKDF2',
            salt: b64ToBytes(manifest.salt),
            iterations: manifest.iterations,
            hash: 'SHA-256'
          },
          baseKey,
          { name: 'AES-GCM', length: 256 },
          true,
          ['decrypt']
        );
      });
  }

  function verifyKey(candidate) {
    return decryptWith(candidate, manifest.check).then(function (text) {
      if (text !== CHECK_TEXT) throw new Error('bad key');
      return candidate;
    });
  }

  function importRaw(raw) {
    return crypto.subtle.importKey('raw', b64ToBytes(raw), { name: 'AES-GCM' }, true, ['decrypt']);
  }

  function exportRaw(candidate) {
    return crypto.subtle.exportKey('raw', candidate).then(function (buf) {
      return bytesToB64(new Uint8Array(buf));
    });
  }

  function remember(candidate) {
    return exportRaw(candidate).then(function (raw) {
      localStorage.setItem(REMEMBER_KEY, JSON.stringify({ key: raw, exp: Date.now() + REMEMBER_MS }));
      sessionStorage.setItem(SESSION_KEY, raw);
    });
  }

  function forget() {
    localStorage.removeItem(REMEMBER_KEY);
    sessionStorage.removeItem(SESSION_KEY);
  }

  function restore() {
    var raw = sessionStorage.getItem(SESSION_KEY);
    if (raw) return importRaw(raw).then(verifyKey);
    var saved = localStorage.getItem(REMEMBER_KEY);
    if (!saved) return Promise.reject(new Error('locked'));
    try {
      var parsed = JSON.parse(saved);
      if (!parsed || parsed.exp < Date.now()) {
        localStorage.removeItem(REMEMBER_KEY);
        return Promise.reject(new Error('locked'));
      }
      return importRaw(parsed.key).then(verifyKey).then(function (candidate) {
        sessionStorage.setItem(SESSION_KEY, parsed.key);
        return candidate;
      });
    } catch (e) {
      localStorage.removeItem(REMEMBER_KEY);
      return Promise.reject(new Error('locked'));
    }
  }

  // ---- 拦截 docsify 的 XHR 请求并解密 ----

  function installXhrGate() {
    if (window.__kbXhrGated) return;
    window.__kbXhrGated = true;

    var NativeXHR = window.XMLHttpRequest;

    function GatedXHR() {
      var native = new NativeXHR();
      var listeners = {};
      var url = '';
      var plain = null;
      var aborted = false;
      var api = this;

      function isEncrypted() {
        var clean = url.split('#')[0].split('?')[0];
        return /\.(md|json)$/i.test(clean) && clean.indexOf('_enc/') === -1;
      }

      function emit(type, evt) {
        var event = evt || {};
        if (!evt) {
          event.type = type;
          event.target = api;
        }
        (listeners[type] || []).forEach(function (fn) {
          try {
            fn.call(api, event);
          } catch (e) {
            console.error(e);
          }
        });
      }

      native.addEventListener('load', function () {
        if (aborted) return;
        if (!isEncrypted() || native.status >= 400) {
          emit('load');
          return;
        }
        var packed;
        try {
          packed = JSON.parse(native.responseText);
        } catch (e) {
          emit('error');
          return;
        }
        decryptWith(key, packed).then(
          function (text) {
            if (aborted) return;
            plain = text;
            emit('load');
            emit('loadend');
          },
          function () {
            if (!aborted) emit('error');
          }
        );
      });

      native.addEventListener('error', function (e) {
        if (!aborted) emit('error', e);
      });

      native.addEventListener('progress', function (e) {
        if (!aborted) emit('progress', e);
      });

      native.addEventListener('loadend', function () {
        if (!isEncrypted()) emit('loadend');
      });

      this.open = function (method, target) {
        url = String(target);
        var finalTarget = target;
        if (BUILD_TAG && isGatedUrl(url)) {
          finalTarget = url + (url.indexOf('?') === -1 ? '?' : '&') + '_kb=' + encodeURIComponent(BUILD_TAG);
        }
        native.open(method, finalTarget);
      };
      this.send = function (body) {
        native.send(body);
      };
      this.setRequestHeader = function () {
        native.setRequestHeader.apply(native, arguments);
      };
      this.getResponseHeader = function (name) {
        return native.getResponseHeader(name);
      };
      this.getAllResponseHeaders = function () {
        return native.getAllResponseHeaders();
      };
      this.overrideMimeType = function () {
        native.overrideMimeType.apply(native, arguments);
      };
      this.abort = function () {
        aborted = true;
        native.abort();
      };
      this.addEventListener = function (type, fn) {
        (listeners[type] || (listeners[type] = [])).push(fn);
      };
      this.removeEventListener = function (type, fn) {
        var list = listeners[type];
        if (!list) return;
        var index = list.indexOf(fn);
        if (index >= 0) list.splice(index, 1);
      };

      Object.defineProperty(this, 'status', { get: function () { return native.status; } });
      Object.defineProperty(this, 'readyState', { get: function () { return native.readyState; } });
      Object.defineProperty(this, 'responseURL', { get: function () { return native.responseURL; } });
      Object.defineProperty(this, 'responseType', {
        get: function () { return native.responseType; },
        set: function (value) { native.responseType = value; }
      });
      Object.defineProperty(this, 'response', {
        get: function () { return plain !== null ? plain : native.response; }
      });
      Object.defineProperty(this, 'responseText', {
        get: function () { return plain !== null ? plain : native.responseText; }
      });
    }

    window.XMLHttpRequest = GatedXHR;
  }

  // ---- 站内 JSON 链接：解密后用新标签页打开 ----

  function siteRoot() {
    return location.origin + location.pathname.replace(/[^/]*$/, '');
  }

  function docDirUrl() {
    var path = location.hash.replace(/^#\/?/, '').split('?')[0];
    var dir = path.indexOf('/') >= 0 ? path.slice(0, path.lastIndexOf('/') + 1) : '';
    return siteRoot() + dir;
  }

  function openJsonLink(href, base) {
    var target;
    try {
      target = new URL(href, base);
    } catch (e) {
      return;
    }
    if (target.origin !== location.origin) return;
    fetch(target.href, { cache: 'no-store' })
      .then(function (response) {
        if (!response.ok) throw new Error('HTTP ' + response.status);
        return response.text();
      })
      .then(function (text) {
        var packed = JSON.parse(text);
        return decryptWith(key, packed);
      })
      .then(function (plainText) {
        var pretty = plainText;
        try {
          pretty = JSON.stringify(JSON.parse(plainText), null, 2);
        } catch (e) {
          /* 保持原文 */
        }
        var url = URL.createObjectURL(new Blob([pretty], { type: 'application/json;charset=utf-8' }));
        window.open(url, '_blank', 'noopener');
      })
      .catch(function () {
        alert('数据文件解密失败，请刷新页面后重试。');
      });
  }

  function installJsonLinks() {
    document.addEventListener(
      'click',
      function (event) {
        var node = event.target;
        while (node && node !== document && node.tagName !== 'A') node = node.parentNode;
        if (!node || node.tagName !== 'A') return;
        var href = node.getAttribute('href') || '';
        if (!/\.json(\?|#|$)/i.test(href)) return;
        event.preventDefault();
        event.stopPropagation();
        var base = node.closest && node.closest('.sidebar') ? siteRoot() : docDirUrl();
        openJsonLink(href, base);
      },
      true
    );
  }

  // ---- 解锁与 docsify 加载 ----

  function loadScript(src) {
    return new Promise(function (resolve, reject) {
      var script = document.createElement('script');
      script.src = src;
      script.onload = resolve;
      script.onerror = reject;
      document.body.appendChild(script);
    });
  }

  function loadDocsify() {
    // 插件必须先于 docsify 核心执行，才能注册到 $docsify.plugins
    return loadScript('_assets/plugins/search.min.js')
      .then(function () { return loadScript('_assets/plugins/copy-code.min.js'); })
      .then(function () { return loadScript('_assets/docsify.min.js'); });
  }

  function addLockButton() {
    var button = document.createElement('button');
    button.type = 'button';
    button.className = 'kb-lock-btn';
    button.textContent = '锁定';
    button.title = '清除本机保存的密钥';
    button.addEventListener('click', function () {
      forget();
      location.reload();
    });
    document.body.appendChild(button);
  }

  function unlock(candidate) {
    key = candidate;
    installXhrGate();
    installJsonLinks();
    document.body.classList.add('kb-unlocked');
    var lock = document.getElementById('kb-lock');
    if (lock && lock.parentNode) lock.parentNode.removeChild(lock);
    addLockButton();
    loadDocsify().catch(function () {
      document.getElementById('app').textContent = '站点资源加载失败，请刷新重试。';
    });
  }

  function showError(message) {
    var error = document.getElementById('kb-error');
    if (error) error.textContent = message;
  }

  function bindForm() {
    var form = document.getElementById('kb-unlock-form');
    var input = document.getElementById('kb-password');
    var button = document.getElementById('kb-unlock-btn');
    var rememberBox = document.getElementById('kb-remember');
    if (!form || !input || !button) return;

    input.focus();

    form.addEventListener('submit', function (event) {
      event.preventDefault();
      var password = input.value;
      if (!password) {
        showError('请输入访问口令。');
        return;
      }
      showError('');
      button.disabled = true;
      button.textContent = '解锁中…';
      deriveKey(password)
        .then(verifyKey)
        .then(function (candidate) {
          if (rememberBox && rememberBox.checked) return remember(candidate).then(function () { return candidate; });
          return exportRaw(candidate).then(function (raw) {
            sessionStorage.setItem(SESSION_KEY, raw);
            return candidate;
          });
        })
        .then(unlock)
        .catch(function () {
          button.disabled = false;
          button.textContent = '解锁';
          input.select();
          showError('口令不正确，请重试。');
        });
    });
  }

  function fatal(message) {
    var card = document.querySelector('.kb-lock-card');
    if (card) {
      card.innerHTML =
        '<h1>无法加载知识库</h1><p class="kb-error">' + message + '</p>' +
        '<p class="kb-lock-foot">请检查网络后刷新页面。</p>';
    }
  }

  function start() {
    if (!window.crypto || !crypto.subtle) {
      fatal('当前浏览器不支持加密访问，请使用最新版 Chrome、Safari 或 Edge。');
      return;
    }
    bindForm();
    fetch(MANIFEST_URL, { cache: 'no-store' })
      .then(function (response) {
        if (!response.ok) throw new Error('manifest ' + response.status);
        return response.json();
      })
      .then(function (data) {
        manifest = data;
        BUILD_TAG = String(data.salt || '').replace(/[^A-Za-z0-9]/g, '').slice(0, 16);
        return restore().then(unlock, function () {
          /* 无可用密钥，等待输入 */
        });
      })
      .catch(function () {
        fatal('未能读取加密清单，站点可能尚未完成部署。');
      });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', start);
  } else {
    start();
  }
})();
