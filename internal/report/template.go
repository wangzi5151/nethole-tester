package report

// htmlTemplate is a single-file, offline report. It contains no external
// references (no CDN, no fonts, no analytics) and works from file://.
const htmlTemplate = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>NetHole-Tester Report</title>
<style>
  :root { --bg:#0f1115; --panel:#171a21; --line:#262b36; --fg:#e6e9ef; --mut:#8b93a7; }
  * { box-sizing: border-box; }
  body { margin:0; background:var(--bg); color:var(--fg); font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"PingFang SC","Microsoft YaHei",sans-serif; }
  .wrap { max-width:1080px; margin:0 auto; padding:28px 18px 60px; }
  h1 { font-size:22px; margin:0 0 4px; }
  h1 span { color:#3ddc84; }
  .sub { color:var(--mut); font-size:12px; margin-bottom:22px; }
  .cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:12px; margin-bottom:22px; }
  .card { background:var(--panel); border:1px solid var(--line); border-radius:12px; padding:14px 16px; }
  .card .v { font-size:22px; font-weight:700; }
  .card .l { color:var(--fg); font-size:12px; margin-top:2px; }
  .card .s { color:var(--mut); font-size:11px; margin-top:4px; }
  .panel { background:var(--panel); border:1px solid var(--line); border-radius:12px; padding:16px; margin-bottom:22px; }
  .legend { display:flex; gap:18px; flex-wrap:wrap; margin-bottom:10px; font-size:13px; }
  .legend label { cursor:pointer; user-select:none; }
  .dot { display:inline-block; width:10px; height:10px; border-radius:50%; margin-right:6px; vertical-align:middle; }
  canvas { width:100%; height:340px; display:block; }
  .tip { position:fixed; pointer-events:none; background:#000c; border:1px solid var(--line); border-radius:8px; padding:6px 9px; font-size:12px; display:none; white-space:nowrap; z-index:9; }
  table { width:100%; border-collapse:collapse; font-size:12.5px; }
  th,td { text-align:left; padding:7px 8px; border-bottom:1px solid var(--line); }
  th { color:var(--mut); font-weight:600; }
  .sev-critical { color:#ff5c5c; } .sev-warn { color:#ffb74d; } .sev-info { color:#4aa8ff; }
  ul.hints { margin:0; padding-left:20px; } ul.hints li { margin:6px 0; }
  .foot { color:var(--mut); font-size:12px; text-align:center; margin-top:30px; border-top:1px solid var(--line); padding-top:16px; }
  .pill { display:inline-block; background:#20242e; border:1px solid var(--line); border-radius:999px; padding:1px 9px; font-size:11px; color:var(--mut); }
</style>
</head>
<body>
<div class="wrap">
  <h1>Net<span>Hole</span>-Tester 网络质量报告</h1>
  <div class="sub">生成于 {{GENERATED}} · 纯本地生成，未上传任何数据 · generated locally, zero upload</div>
  {{SUMMARY}}

  <div class="panel">
    <div class="legend" id="legend"></div>
    <canvas id="chart"></canvas>
    <div style="color:var(--mut);font-size:11px;margin-top:8px">横轴：运行时间（秒） · 纵轴：延迟 RTT（毫秒） · 断开的线段代表该时刻丢包/超时 · X: elapsed seconds, Y: latency ms, gaps = loss/timeout</div>
  </div>

  <div class="panel">
    <h3 style="margin:0 0 10px">网洞事件 / Hole events</h3>
    <div id="events"></div>
  </div>

  <div class="panel">
    <h3 style="margin:0 0 10px">相关性线索 / Correlation clues <span class="pill">仅提示，非诊断</span></h3>
    <ul class="hints" id="hints"></ul>
  </div>

  <div class="foot">
    本文件为静态 HTML，可离线双击打开 · 由 NetHole-Tester 生成 · 无遥测 / no telemetry<br>
    NetHole-Tester · MIT License
  </div>
</div>
<div class="tip" id="tip"></div>
<script>
var DATA = {{DATA}};
(function(){
  function $(id){ return document.getElementById(id); }

  // Legend + toggles
  var hidden = {};
  var legend = $('legend');
  DATA.series.forEach(function(s, i){
    var l = document.createElement('label');
    var cb = document.createElement('input');
    cb.type = 'checkbox'; cb.checked = true; cb.style.marginRight = '6px';
    cb.onchange = function(){ hidden[i] = !cb.checked; draw(); };
    l.appendChild(cb);
    var dot = document.createElement('span'); dot.className = 'dot'; dot.style.background = s.color;
    l.appendChild(dot);
    var txt = document.createElement('span'); txt.textContent = s.name + ' (' + s.points.length + ')';
    l.appendChild(txt);
    legend.appendChild(l);
  });

  var canvas = $('chart'), ctx = canvas.getContext('2d');
  var tip = $('tip');
  var geom = { xmin:0, xmax:1, ymin:0, ymax:10 };

  function resize(){
    var dpr = window.devicePixelRatio || 1;
    var w = canvas.clientWidth, h = canvas.clientHeight;
    canvas.width = w * dpr; canvas.height = h * dpr;
    ctx.setTransform(dpr,0,0,dpr,0,0);
    draw();
  }

  function computeScale(){
    var xmax = 1, ymax = 10;
    DATA.series.forEach(function(s){
      s.points.forEach(function(p){
        if (p.t > xmax) xmax = p.t;
        if (p.y > ymax) ymax = p.y;
      });
    });
    geom.xmax = xmax;
    geom.ymax = Math.ceil(ymax * 1.15);
  }

  function mapX(t, w, pad){ return pad.l + (t - geom.xmin) / (geom.xmax - geom.xmin) * (w - pad.l - pad.r); }
  function mapY(y, h, pad){ return h - pad.b - (y - geom.ymin) / (geom.ymax - geom.ymin) * (h - pad.t - pad.b); }

  function draw(){
    var w = canvas.clientWidth, h = canvas.clientHeight;
    var pad = { l:48, r:14, t:14, b:28 };
    ctx.clearRect(0,0,w,h);
    ctx.font = '11px sans-serif';

    // grid + y labels
    ctx.strokeStyle = '#262b36'; ctx.fillStyle = '#8b93a7'; ctx.lineWidth = 1;
    for (var g=0; g<=4; g++){
      var yv = geom.ymax * g/4;
      var yy = mapY(yv, h, pad);
      ctx.beginPath(); ctx.moveTo(pad.l, yy); ctx.lineTo(w-pad.r, yy); ctx.stroke();
      ctx.fillText(Math.round(yv) + 'ms', 6, yy + 4);
    }
    // x labels
    for (var xg=0; xg<=4; xg++){
      var xv = geom.xmax * xg/4;
      var xx = mapX(xv, w, pad);
      ctx.strokeStyle = '#1d222b';
      ctx.beginPath(); ctx.moveTo(xx, pad.t); ctx.lineTo(xx, h-pad.b); ctx.stroke();
      ctx.fillStyle = '#8b93a7';
      ctx.fillText(formatDur(xv), xx - 12, h - 8);
    }

    // series
    DATA.series.forEach(function(s, i){
      if (hidden[i]) return;
      ctx.strokeStyle = s.color; ctx.lineWidth = 1.4; ctx.beginPath();
      var pen = false;
      s.points.forEach(function(p){
        if (p.y < 0){ pen = false; return; }
        var x = mapX(p.t, w, pad), y = mapY(p.y, h, pad);
        if (!pen){ ctx.moveTo(x,y); pen = true; } else { ctx.lineTo(x,y); }
      });
      ctx.stroke();
      // loss markers
      ctx.fillStyle = '#ff5c5c';
      s.points.forEach(function(p){
        if (p.y < 0){ ctx.fillRect(mapX(p.t,w,pad)-1, h-pad.b-3, 2, 3); }
      });
    });
  }

  function formatDur(s){
    if (s >= 3600) return Math.round(s/3600) + 'h';
    if (s >= 60) return Math.round(s/60) + 'm';
    return Math.round(s) + 's';
  }

  canvas.addEventListener('mousemove', function(ev){
    var rect = canvas.getBoundingClientRect();
    var mx = ev.clientX - rect.left;
    var pad = { l:48, r:14, t:14, b:28 };
    var t = (mx - pad.l) / (rect.width - pad.l - pad.r) * (geom.xmax - geom.xmin) + geom.xmin;
    var best = null, bestd = 1e18;
    DATA.series.forEach(function(s, i){
      if (hidden[i]) return;
      s.points.forEach(function(p){
        var d = Math.abs(p.t - t);
        if (d < bestd){ bestd = d; best = { s:s, p:p }; }
      });
    });
    if (best && bestd < geom.xmax * 0.02){
      var txt = best.s.name + '  t=' + formatDur(best.p.t) + '  ';
      txt += (best.p.y < 0 ? 'LOSS/TIMEOUT' : Math.round(best.p.y) + 'ms');
      tip.textContent = txt;
      tip.style.display = 'block';
      tip.style.left = (ev.clientX + 12) + 'px';
      tip.style.top = (ev.clientY + 12) + 'px';
    } else { tip.style.display = 'none'; }
  });
  canvas.addEventListener('mouseleave', function(){ tip.style.display = 'none'; });

  // events table
  var ev = $('events');
  if (!DATA.events || DATA.events.length === 0){
    ev.innerHTML = '<div style="color:var(--mut)">未捕获到达到阈值的网洞事件（no holes above threshold）</div>';
  } else {
    var html = '<table><tr><th>#</th><th>开始 Start</th><th>持续</th><th>类型</th><th>严重度</th><th>说明</th></tr>';
    DATA.events.forEach(function(e, i){
      html += '<tr><td>' + (i+1) + '</td><td>' + e.start + '</td><td>' + e.dur_s.toFixed(1) + 's</td><td>' + e.kind + '</td><td class="sev-' + e.sev + '">' + e.sev + '</td><td>' + escapeHtml(e.why) + '</td></tr>';
    });
    html += '</table>';
    ev.innerHTML = html;
  }

  var ul = $('hints');
  (DATA.hints || []).forEach(function(t){
    var li = document.createElement('li');
    li.textContent = t;
    ul.appendChild(li);
  });

  function escapeHtml(s){
    return String(s).replace(/[&<>"]/g, function(c){
      return ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'})[c];
    });
  }

  computeScale();
  window.addEventListener('resize', resize);
  resize();
})();
</script>
</body>
</html>
`
