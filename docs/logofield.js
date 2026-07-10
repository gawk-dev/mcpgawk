/* logofield.js — a 3D field of AI-company logos behind the page content.
   - continuous CURVED drift; every logo BREATHES through depth (grows + shrinks)
   - on the first interaction (scroll / click / key):
       1) the field FAINTS in the centre (fades), then
       2) SLOWLY migrates to the LEFT + RIGHT margins and floats there in 3D,
          still breathing, leaving the centre clear for reading.
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

  var reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  var W = window.innerWidth, H = window.innerHeight;
  if (W <= 700) LOGOS = LOGOS.filter(function (_, i) { return i % 2 === 0; });
  function rand(a, b) { return a + Math.random() * (b - a); }

  var parts = LOGOS.map(function (name, i) {
    var el = document.createElement('img');
    el.className = 'logo-particle';
    el.src = 'assets/logos/' + name + '.svg';
    el.alt = ''; el.decoding = 'async';
    field.appendChild(el);
    return {
      el: el,
      x: rand(0, W), y: rand(0, H),
      speed: rand(24, 46),
      heading: rand(0, 6.2832),
      omega: (Math.random() < 0.5 ? -1 : 1) * rand(0.18, 0.6),   // curved path
      baseZ: rand(-160, 60),
      zAmp: rand(240, 340),                                       // depth breathing (grow/shrink)
      zSpd: rand(0.13, 0.28),
      ph: rand(0, 6.2832),
      // edge it drifts out to: even -> far left, odd -> far right (kept to the true margins)
      sideFrac: (i % 2 === 0) ? rand(-0.01, 0.085) : rand(0.915, 1.01),
      z: 0
    };
  });

  function place(p) {
    p.el.style.transform = 'translate3d(' + p.x + 'px,' + p.y + 'px,' + p.z + 'px) translate(-50%,-50%)';
  }

  if (reduce) {   // no animation: rest split to the margins, static
    parts.forEach(function (p) { p.x = p.sideFrac * W; p.z = p.baseZ; place(p); });
    return;
  }

  // faint (fast) then migrate-to-sides (slow) — both begin on the first interaction
  var faint = 0, faintTarget = 0, migrate = 0, migrateTarget = 0;
  function trigger() { faintTarget = 1; migrateTarget = 1; }
  ['scroll', 'wheel', 'pointerdown', 'keydown', 'touchstart'].forEach(function (ev) {
    window.addEventListener(ev, trigger, { passive: true, once: true });
  });

  var t0 = 0, last = 0, running = false, pad = 100;
  function loop(t) {
    if (!running) return;
    if (!t0) { t0 = t; last = t; }
    var dt = Math.min(0.033, (t - last) / 1000); last = t;
    var elapsed = (t - t0) / 1000;
    faint   += (faintTarget   - faint)   * Math.min(1, dt * 3.5);   // ~0.3s  -> quick faint in the centre
    migrate += (migrateTarget - migrate) * Math.min(1, dt * 0.55);  // ~2.5s  -> slow drift to the margins
    // faint in the centre, then recover a little once floating on the sides
    field.style.opacity = Math.max(0.24, Math.min(1, 1 - 0.66 * faint + 0.12 * migrate)).toFixed(3);
    for (var i = 0; i < parts.length; i++) {
      var p = parts[i];
      p.heading += p.omega * dt;
      var freeSp = p.speed * (1 - 0.78 * migrate);                 // drift eases off as it settles on the side
      p.x += Math.cos(p.heading) * freeSp * (1 - 0.6 * migrate) * dt;   // horizontal wander fades near the edge
      p.y += Math.sin(p.heading) * freeSp * dt;                    // keep floating vertically
      // slow migrate: spring x toward the side margin as `migrate` grows
      p.x += (p.sideFrac * W - p.x) * Math.min(1, migrate * 2.6 * dt);
      if (p.x < -pad) p.x += W + 2 * pad; else if (p.x > W + pad) p.x -= W + 2 * pad;
      if (p.y < -pad) p.y += H + 2 * pad; else if (p.y > H + pad) p.y -= H + 2 * pad;
      // float in 3D: full depth breathing throughout (grow + shrink)
      p.z = p.baseZ + Math.sin(elapsed * p.zSpd + p.ph) * p.zAmp;
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
