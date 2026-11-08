// Next Wednesday 10:00-11:30 America/Los_Angeles, shown in the visitor's own time zone.
(function () {
  var TZ = 'America/Los_Angeles', START_H = 10, LEN_MIN = 90, EARLY_MIN = 10;
  function parts(t) {
    var p = {};
    new Intl.DateTimeFormat('en-US', { timeZone: TZ, hourCycle: 'h23', year: 'numeric', month: 'numeric', day: 'numeric', hour: 'numeric', minute: 'numeric', weekday: 'short' })
      .formatToParts(new Date(t)).forEach(function (x) { p[x.type] = x.value; });
    return p;
  }
  function laToUtc(y, m, d, h, mi) {
    var guess = Date.UTC(y, m - 1, d, h, mi), p = parts(guess);
    return guess - (Date.UTC(+p.year, p.month - 1, +p.day, +p.hour, +p.minute) - guess);
  }
  try {
    var now = Date.now(), start, end;
    for (var i = -1; i < 8; i++) {
      var p = parts(now + i * 864e5);
      if (p.weekday !== 'Wed') continue;
      start = laToUtc(+p.year, +p.month, +p.day, START_H, 0);
      end = start + LEN_MIN * 6e4;
      if (end > now) break;
    }
    var when = document.getElementById('ws-when'), note = document.getElementById('ws-note');
    if (!when) return;
    if (now >= start - EARLY_MIN * 6e4 && now < end) {
      when.innerHTML = '<span class="live">Happening now</span>';
      note.textContent = 'Come in any time until ' + new Date(end).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' }) + '.';
    } else {
      var d = new Date(start);
      when.textContent = 'Next: ' + d.toLocaleDateString([], { weekday: 'long', month: 'long', day: 'numeric' }) + ', ' +
        d.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' }) + '\u2013' + new Date(end).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit', timeZoneName: 'short' });
      note.textContent = 'Shown in your time zone.';
    }
  } catch (e) { /* keep the plain-text time */ }
})();

// Join a Daily room inside the page. Daily's own knock screen still decides who gets in.
function joinRoom(url, stageId) {
  var stage = document.getElementById(stageId);
  if (!window.Daily || !stage) { window.location.href = url; return false; }
  if (stage.dataset.on) { stage.scrollIntoView({ behavior: 'smooth' }); return false; }
  stage.dataset.on = '1';
  var call = window.Daily.createFrame(stage, { showLeaveButton: true, showFullscreenButton: true, iframeStyle: { width: '100%', height: 'min(75vh, 46rem)', border: '0' } });
  call.on('left-meeting', function () { call.destroy(); stage.innerHTML = ''; delete stage.dataset.on; });
  call.join({ url: url });
  stage.scrollIntoView({ behavior: 'smooth' });
  return false;
}
