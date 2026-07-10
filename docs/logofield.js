/* logofield.js — a 3D field of AI-company logos behind the page content.
   - continuous CURVED drift; every logo BREATHES through depth (grows + shrinks)
   - on the first interaction (scroll / click / key):
       1) the field RECEDES into the background (deep + faint), then
       2) each logo SPIRALS out to the left/right margin along a GOLDEN logarithmic
          spiral (radius shrinks by 1/φ each quarter-turn), rising back toward the
          front to float there in 3D, leaving the centre clear.
   Sits behind content (z-index:0), pointer-events:none, reduced-motion aware. */
(function () {
  var field = document.getElementById('logoField');
  if (!field) return;

  var LOGOS = [
    'openai','anthropic','google','gemini','meta','nvidia','perplexity','huggingface','cursor',
    'xai','grok','midjourney','runway','stability','suno','ollama','togetherai','cerebras',
    'inflection','replicate','langchain','copilot',
    'deepseek','qwen','kimi','baidu',
    'mistral','cohere'
  ];

  var PHI = 1.6180339887;
  var DEEP = -720;                        // background depth during recede
  var reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  var W = window.innerWidth, H = window.innerHeight;
  if (W <= 700) LOGOS = LOGOS.filter(function (_, i) { return i % 2 === 0; });
  function rand(a, b) { return a + Math.random() * (b - a); }
  function clamp(v, a, b) { return v < a ? a : v > b ? b : v; }
  function easeInOut(t) { return t * t * (3 - 2 * t); }

  var parts = LOGOS.map(function (name, i) {
    var el = document.createElement('img');
    el.className = 'logo-particle';
    el.src = 'assets/logos/' + name + '.svg';
    el.alt = ''; el.decoding = 'async';
    field.appendChild(el);
    return {
      el: el,
      x: rand(0, W), y: rand(0, H),
      speed: rand(24, 46), heading: rand(0, 6.2832),
      omega: (Math.random() < 0.5 ? -1 : 1) * rand(0.18, 0.6),
      baseZ: rand(-160, 60), zAmp: rand(240, 340), zSpd: rand(0.13, 0.28), ph: rand(0, 6.2832),
      sideFrac: (i % 2 === 0) ? rand(-0.01, 0.085) : rand(0.915, 1.01),   // even->left edge, odd->right
      fph: rand(0, 6.2832),
      z: 0
    };
  });

  function place(p) {
    p.el.style.transform = 'translate3d(' + p.x + 'px,' + p.y + 'px,' + p.z + 'px) translate(-50%,-50%)';
  }

  if (reduce) { parts.forEach(function (p) { p.x = p.sideFrac * W; p.z = p.baseZ; place(p); }); return; }

  // recede (fast, into the background) then migrate (slow, golden spiral to the margins)
  var recede = 0, recedeT = 0, migrate = 0, migrateT = 0, captured = false;
  function trigger() { recedeT = 1; setTimeout(function () { migrateT = 1; }, 520); }
  ['scroll', 'wheel', 'pointerdown', 'keydown', 'touchstart'].forEach(function (ev) {
    window.addEventListener(ev, trigger, { passive: true, once: true });
  });

  var t0 = 0, last = 0, running = false, pad = 100;
  function loop(t) {
    if (!running) return;
    if (!t0) { t0 = t; last = t; }
    var dt = Math.min(0.033, (t - last) / 1000); last = t;
    var elapsed = (t - t0) / 1000;
    recede  += (recedeT  - recede)  * Math.min(1, dt * 3.4);   // ~0.3s to the background
    migrate += (migrateT - migrate) * Math.min(1, dt * 0.5);   // ~2.5s golden drift to the margins
    field.style.opacity = clamp(1 - 0.72 * recede + 0.30 * migrate, 0.24, 1).toFixed(3);

    // freeze each logo's spiral start the moment the migration begins
    if (migrateT === 1 && !captured) {
      captured = true;
      for (var k = 0; k < parts.length; k++) {
        var q = parts[k];
        q.tx = q.sideFrac * W;
        q.ty = clamp(q.y, 0.06 * H, 0.94 * H);      // target on the margin, at its current height
        var dx = q.x - q.tx, dy = q.y - q.ty;
        q.R0 = Math.max(1, Math.hypot(dx, dy));
        q.th0 = Math.atan2(dy, dx);
        q.spin = (q.sideFrac < 0.5 ? 1 : -1) * Math.PI * 2 * 1.15;   // ~1.15 turns, out to its side
        q.qt = Math.abs(q.spin) / (Math.PI / 2);                     // quarter-turns (~4.6)
      }
    }

    for (var i = 0; i < parts.length; i++) {
      var p = parts[i];
      if (captured) {
        var e = easeInOut(migrate);
        var th = p.th0 + p.spin * e;
        var R = p.R0 * Math.pow(1 / PHI, p.qt * e) * (1 - e);        // golden logarithmic spiral, converging
        p.x = p.tx + Math.cos(th) * R + Math.sin(elapsed * 0.42 + p.fph) * 9 * migrate;   // gentle float
        p.y = p.ty + Math.sin(th) * R + Math.cos(elapsed * 0.34 + p.fph) * 15 * migrate;
      } else {
        p.heading += p.omega * dt;
        var sp = p.speed * (1 - 0.5 * recede);
        p.x += Math.cos(p.heading) * sp * dt;
        p.y += Math.sin(p.heading) * sp * dt;
        if (p.x < -pad) p.x += W + 2 * pad; else if (p.x > W + pad) p.x -= W + 2 * pad;
        if (p.y < -pad) p.y += H + 2 * pad; else if (p.y > H + pad) p.y -= H + 2 * pad;
      }
      // depth: recede into the background, then rise back to float (breathing throughout)
      var deepPull = recede * (1 - migrate * 0.72);
      var bz = p.baseZ + (DEEP - p.baseZ) * deepPull;
      var amp = p.zAmp * (0.5 + 0.5 * (1 - deepPull));
      p.z = bz + Math.sin(elapsed * p.zSpd + p.ph) * amp;
      place(p);
    }
    requestAnimationFrame(loop);
  }
  function start() { if (running) return; running = true; requestAnimationFrame(loop); }
  function stop() { running = false; }

  parts.forEach(function (p) { p.z = p.baseZ; place(p); });
  start();

  document.addEventListener('visibilitychange', function () {
    if (document.hidden) stop(); else { last = 0; t0 = 0; start(); }
  });
  window.addEventListener('resize', function () { W = window.innerWidth; H = window.innerHeight; });
})();
