/* logofield.js — a 3D field of AI-company logos behind the page content.
   - continuous CURVED drift (each logo follows a turning path, never a straight line)
   - every logo BREATHES through depth (grows + shrinks), not just some
   - once the user interacts (scroll / click / key), the whole field RECEDES to a
     small, calm feed in the back so it never competes with reading
   Sits behind content (z-index:0), pointer-events:none, reduced-motion aware. */
(function () {
  var field = document.getElementById('logoField');
  if (!field) return;

  // AI tech firms only (no IT-services / consumer-service companies), global where the AI world is.
  var LOGOS = [
    // US / West AI labs + AI infra + AI-native tools
    'openai','anthropic','google','gemini','meta','nvidia','perplexity','huggingface','cursor',
    'xai','grok','midjourney','runway','stability','suno','ollama','togetherai','cerebras',
    'inflection','replicate','langchain','copilot',
    // China AI
    'deepseek','qwen','kimi','baidu',
    // Europe / Canada AI
    'mistral','cohere'
  ];

  var PERSPECTIVE = 1000;                 // must match CSS perspective on #logoField
  var DEEP = -720;                        // receded depth (small in the back)
  var reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  var W = window.innerWidth, H = window.innerHeight;
  if (W <= 700) LOGOS = LOGOS.filter(function (_, i) { return i % 2 === 0; });   // fewer on phones
  function rand(a, b) { return a + Math.random() * (b - a); }

  var parts = LOGOS.map(function (name) {
    var el = document.createElement('img');
    el.className = 'logo-particle';
    el.src = 'assets/logos/' + name + '.svg';
    el.alt = ''; el.decoding = 'async';
    field.appendChild(el);
    return {
      el: el,
      x: rand(0, W), y: rand(0, H),
      speed: rand(24, 46),                                // px/s along heading
      heading: rand(0, 6.2832),
      omega: (Math.random() < 0.5 ? -1 : 1) * rand(0.18, 0.6), // rad/s turn rate -> CURVED path
      baseZ: rand(-160, 60),                              // rest depth (all near enough to visibly scale)
      zAmp: rand(240, 340),                               // depth breathing amplitude (uniform-ish -> ALL breathe)
      zSpd: rand(0.13, 0.28),
      ph: rand(0, 6.2832),
      z: 0
    };
  });

  function place(p) {
    p.el.style.transform = 'translate3d(' + p.x + 'px,' + p.y + 'px,' + p.z + 'px) translate(-50%,-50%)';
    // full opacity (set once in CSS); depth is conveyed by scale
  }

  if (reduce) { parts.forEach(function (p) { p.z = p.baseZ; place(p); }); return; }

  // recede: 0 = full presence, 1 = shrunk to a small back feed. Eases toward target on interaction.
  var recede = 0, recedeTarget = 0;
  function triggerRecede() { recedeTarget = 1; }
  ['scroll', 'wheel', 'pointerdown', 'keydown', 'touchstart'].forEach(function (ev) {
    window.addEventListener(ev, triggerRecede, { passive: true, once: true });
  });

  var t0 = 0, last = 0, running = false;
  function loop(t) {
    if (!running) return;
    if (!t0) { t0 = t; last = t; }
    var dt = Math.min(0.033, (t - last) / 1000); last = t;
    var elapsed = (t - t0) / 1000;
    recede += (recedeTarget - recede) * Math.min(1, dt * 3);   // ~0.35s ease
    // as the field recedes, fade it to a faint backdrop so the small logos don't
    // sit awkwardly over the content the reader is now looking at
    field.style.opacity = (1 - 0.9 * recede).toFixed(3);
    var pad = 100;
    for (var i = 0; i < parts.length; i++) {
      var p = parts[i];
      // curved drift: continuously turn the heading, then step along it
      p.heading += p.omega * dt;
      var sp = p.speed * (1 - 0.45 * recede);                  // calmer once receded
      p.x += Math.cos(p.heading) * sp * dt;
      p.y += Math.sin(p.heading) * sp * dt;
      if (p.x < -pad) p.x += W + 2 * pad; else if (p.x > W + pad) p.x -= W + 2 * pad;
      if (p.y < -pad) p.y += H + 2 * pad; else if (p.y > H + pad) p.y -= H + 2 * pad;
      // depth: every logo breathes; the whole field recedes deep (small) on interaction
      var bz = p.baseZ + (DEEP - p.baseZ) * recede;
      var amp = p.zAmp * (1 - 0.6 * recede);
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
