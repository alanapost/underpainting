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
    var when = document.getElementById('ws-when');
    if (!when) return;
    var t = function (x, o) { return new Date(x).toLocaleTimeString([], Object.assign({ hour: 'numeric', minute: '2-digit' }, o || {})); };
    if (now >= start - EARLY_MIN * 6e4 && now < end) {
      when.innerHTML = '<span class="live"><span class="dot" aria-hidden="true"></span>Happening now, until ' + t(end) + '</span>';
      var join = document.getElementById('ws-join'), plan = document.getElementById('ws-plan'), cal = document.getElementById('ws-cal');
      if (join) join.textContent = 'Join now';
      if (plan) plan.hidden = false;
      if (cal) cal.hidden = true;
      document.body.dataset.live = '1';
    } else {
      when.textContent = new Date(start).toLocaleDateString([], { weekday: 'long', month: 'long', day: 'numeric' }) + ', ' + t(start) + '\u2013' + t(end, { timeZoneName: 'short' });
    }
  } catch (e) { /* keep the plain-text time */ }
})();

// Join a Daily room inside the page. Daily's own knock screen still decides who gets in.
// Brand colours for Daily's call screen (from underpainting.club/brand/).
var CALL_THEME = {
  light: { colors: { accent: '#7c3f25', accentText: '#ffffff', background: '#f8f4ec', backgroundAccent: '#ece2d1', baseText: '#2a221d', border: '#e0d5c4', mainAreaBg: '#2a221d', mainAreaBgAccent: '#3a3029', mainAreaText: '#f2ece1', supportiveText: '#6b5b4d' } },
  dark: { colors: { accent: '#d08a5c', accentText: '#1e1915', background: '#27201b', backgroundAccent: '#2e251f', baseText: '#efe6da', border: '#3a3029', mainAreaBg: '#1e1915', mainAreaBgAccent: '#2e251f', mainAreaText: '#efe6da', supportiveText: '#bba996' } }
};
function joinRoom(url, stageId, quiet) {
  var stage = document.getElementById(stageId);
  if (!window.Daily || !stage) { window.location.href = url; return false; }
  if (stage.dataset.on) { stage.scrollIntoView({ behavior: 'smooth' }); return false; }
  stage.dataset.on = '1';
  var call = window.Daily.createFrame(stage, { showLeaveButton: true, showFullscreenButton: true, theme: CALL_THEME, iframeStyle: { width: '100%', height: 'min(75vh, 40rem)', border: '0' } });
  call.on('left-meeting', function () { call.destroy(); stage.innerHTML = ''; delete stage.dataset.on; });
  call.join({ url: url });
  if (!quiet) stage.scrollIntoView({ behavior: 'smooth' });
  return false;
}
