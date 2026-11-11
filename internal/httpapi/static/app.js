/* Sanctum: upload progress. Optional: without this script the upload form
   still works as a normal form post, just without a progress bar. */
(function () {
  'use strict';
  var xhr = null;

  function fmt(n) {
    if (n >= 1073741824) return (n / 1073741824).toFixed(2) + ' GB';
    if (n >= 1048576) return (n / 1048576).toFixed(1) + ' MB';
    return Math.max(1, Math.round(n / 1024)) + ' KB';
  }
  function $(id) { return document.getElementById(id); }

  function reset(form, msg) {
    var p = $('prog');
    if (p) p.hidden = true;
    var b = form.querySelector('button[type=submit]');
    if (b) b.disabled = false;
    xhr = null;
    if (msg) { var e = $('progerr'); if (e) { e.textContent = msg; e.hidden = false; } }
  }

  document.addEventListener('click', function (ev) {
    if (ev.target && ev.target.id === 'progcancel' && xhr) { xhr.abort(); }
  });

  document.addEventListener('submit', function (ev) {
    var form = ev.target;
    if (!form || !form.hasAttribute || !form.hasAttribute('data-upload')) return;
    if (!window.XMLHttpRequest || !window.FormData) return; // fall back to a normal post
    var input = form.querySelector('input[type=file]');
    if (!input || !input.files || !input.files.length) return;
    ev.preventDefault();

    var bar = $('progbar'), txt = $('progtxt'), p = $('prog'), err = $('progerr');
    var total = input.files[0].size;
    if (err) err.hidden = true;
    bar.removeAttribute('value'); bar.max = 100; bar.value = 0;
    txt.textContent = 'Starting upload…';
    p.hidden = false;
    form.querySelector('button[type=submit]').disabled = true;

    xhr = new XMLHttpRequest();
    xhr.open('POST', form.getAttribute('action'));
    xhr.upload.onprogress = function (e) {
      if (!e.lengthComputable) return;
      var pct = Math.min(100, Math.round(e.loaded * 100 / e.total));
      bar.value = pct;
      txt.textContent = 'Uploading ' + pct + '%  (' + fmt(e.loaded) + ' of ' + fmt(e.total) + ')';
    };
    xhr.upload.onload = function () {
      bar.removeAttribute('value'); // indeterminate: the server is checking the file
      txt.textContent = 'Upload finished. Checking that the backup opens… this can take a minute.';
      var c = $('progcancel'); if (c) c.hidden = true;
    };
    xhr.onerror = function () { reset(form, 'The upload failed. Check your connection and try again.'); };
    xhr.onabort = function () { reset(form, 'Upload cancelled.'); };
    xhr.onload = function () {
      var type = xhr.getResponseHeader('Content-Type') || '';
      if (type.indexOf('text/html') === -1) {
        reset(form, (xhr.responseText || 'The upload was refused.').trim().slice(0, 300));
        return;
      }
      var doc = new DOMParser().parseFromString(xhr.responseText, 'text/html');
      document.title = doc.title;
      document.body.innerHTML = doc.body.innerHTML;
      window.scrollTo(0, 0);
      xhr = null;
    };
    xhr.send(new FormData(form));
  });
})();
