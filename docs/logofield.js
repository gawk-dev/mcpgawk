/* logofield.js — a 3D field of AI-company logos behind the page content.
   Idle: continuous CURVED drift; every logo BREATHES through depth (grows/shrinks).
   On first interaction (scroll / click / key):
     1) recede FAST into the background (deep + faint), then
     2) migrate SLOWLY outward, each logo on its OWN golden logarithmic spiral
        (varied turns/direction, staggered timing — no uniform path), to float in
        the left/right margins in 3D. A few logos instead fly to the "Any MCP server"
        node in the How-it-works card and settle there, becoming faint — the logos
        ARE the MCP servers you scan.
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
  var DEEP = -720;
  var reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  var W = window.innerWidth, H = window.innerHeight;
  if (W <= 700) LOGOS = LOGOS.filter(function (_, i) { return i % 2 === 0; });
  function rand(a, b) { return a + Math.random() * (b - a); }
  function clamp(v, a, b) { return v < a ? a : v > b ? b : v; }
  function easeInOut(t) { return t * t * (3 - 2 * t); }

  var nodeEl = document.getElementById('howServer');   // "Any MCP server" node

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
      sideFrac: (i % 2 === 0) ? rand(-0.01, 0.085) : rand(0.915, 1.01),
      fph: rand(0, 6.2832),
      // per-logo, non-uniform migration:
      migOff: rand(0, 0.30),                                            // staggered start
      spin: (Math.random() < 0.5 ? 1 : -1) * rand(0.35, 0.85) * 2 * Math.PI, // soft arc, varied per logo
      toNode: false,                                                    // field logos all go to the margins now

      z: 0
    };
  });
  parts.forEach(function (p) { p.qt = Math.abs(p.spin) / (Math.PI / 2); });

  function place(p) {
    p.el.style.transform = 'translate3d(' + p.x + 'px,' + p.y + 'px,' + p.z + 'px) translate(-50%,-50%)';
  }

  if (reduce) { parts.forEach(function (p) { p.x = p.sideFrac * W; p.z = p.baseZ; place(p); }); return; }

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
    recede += (recedeT - recede) * Math.min(1, dt * 3.4);       // FAST into the background (kept)
    if (migrateT === 1) migrate = Math.min(1, migrate + dt / 7.0);  // LINEAR ~7s ramp out (no fast lurch)
    field.style.opacity = clamp(1 - 0.72 * recede + 0.30 * migrate, 0.24, 1).toFixed(3);

    if (migrateT === 1 && !captured) {   // freeze each margin logo's spiral start
      captured = true;
      for (var k = 0; k < parts.length; k++) {
        var q = parts[k];
        if (q.toNode) continue;
        q.tx = q.sideFrac * W; q.ty = clamp(q.y, 0.06 * H, 0.94 * H);
        var dx = q.x - q.tx, dy = q.y - q.ty;
        q.R0 = Math.max(1, Math.hypot(dx, dy)); q.th0 = Math.atan2(dy, dx);
      }
    }

    var nr = null;
    if (nodeEl) { var r = nodeEl.getBoundingClientRect(); if (r.width) nr = { cx: r.left + r.width / 2, cy: r.top + r.height / 2 }; }

    for (var i = 0; i < parts.length; i++) {
      var p = parts[i];
      if (!captured) {                    // idle: free curved drift
        p.heading += p.omega * dt;
        var sp = p.speed * (1 - 0.5 * recede);
        p.x += Math.cos(p.heading) * sp * dt;
        p.y += Math.sin(p.heading) * sp * dt;
        if (p.x < -pad) p.x += W + 2 * pad; else if (p.x > W + pad) p.x -= W + 2 * pad;
        if (p.y < -pad) p.y += H + 2 * pad; else if (p.y > H + pad) p.y -= H + 2 * pad;
        var dp0 = recede; var bz0 = p.baseZ + (DEEP - p.baseZ) * dp0;
        p.z = bz0 + Math.sin(elapsed * p.zSpd + p.ph) * p.zAmp * (0.5 + 0.5 * (1 - dp0));
        place(p); continue;
      }
      var me = easeInOut(clamp((migrate - p.migOff) / (1 - p.migOff + 0.001), 0, 1));   // per-logo progress
      if (p.toNode && nr) {               // settle faintly near the "Any MCP server" node
        var oa = elapsed * 0.55 + p.fph;
        var orb = 46 + 26 * Math.sin(elapsed * 0.3 + p.fph * 1.7);
        var txn = nr.cx + Math.cos(oa) * orb;
        var tyn = nr.cy - 6 + Math.sin(oa) * orb * 0.62;
        p.x += (txn - p.x) * Math.min(1, me * 3 * dt);
        p.y += (tyn - p.y) * Math.min(1, me * 3 * dt);
        p.el.style.opacity = (0.55 - 0.32 * me).toFixed(2);       // less opaque as it settles
        p.z = p.baseZ * 0.4 + Math.sin(elapsed * p.zSpd + p.ph) * p.zAmp * 0.5;
        place(p); continue;
      }
      // margin logos: own golden spiral, converging
      var th = p.th0 + p.spin * me;
      var R = p.R0 * Math.pow(1 / PHI, p.qt * me) * (1 - me);
      p.x = p.tx + Math.cos(th) * R + Math.sin(elapsed * 0.42 + p.fph) * 9 * migrate;
      p.y = p.ty + Math.sin(th) * R + Math.cos(elapsed * 0.34 + p.fph) * 15 * migrate;
      var deepPull = recede * (1 - migrate * 0.72);
      var bz = p.baseZ + (DEEP - p.baseZ) * deepPull;
      p.z = bz + Math.sin(elapsed * p.zSpd + p.ph) * p.zAmp * (0.5 + 0.5 * (1 - deepPull));
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
