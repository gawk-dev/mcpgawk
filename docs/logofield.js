/* logofield.js — a 3D field of brand logos that fly in with entropy and settle.
   Same spirit as the Nativerse boids background, but perspective-3D with logos:
   each starts deep + scattered with random velocity, springs toward a rest target,
   grows as it nears the viewer, then settles into a gentle float.
   Sits behind the page content (z-index:0); pointer-events:none; reduced-motion aware. */
(function () {
  var field = document.getElementById('logoField');
  if (!field) return;

  // blended set: AI model-makers + MCP-ecosystem software. Files in assets/logos/.
  var LOGOS = [
    'openai','anthropic','google','gemini','meta','mistral','huggingface','nvidia',
    'perplexity','grok','cohere','cursor','github','notion','slack','linear',
    'stripe','cloudflare','figma','vercel','supabase','discord'
  ];

  var PERSPECTIVE = 1000;           // must match CSS perspective on #logoField
  var BASE = 54;                    // base logo size in px (scaled by depth)
  var reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  var W = window.innerWidth, H = window.innerHeight;
  function rand(a, b) { return a + Math.random() * (b - a); }

  // rest targets: bias to the margins so the readable centre column stays clear.
  function targetX(i) {
    var m = i % 5;
    if (m === 0) return rand(0.03, 0.16) * W;   // far left
    if (m === 1) return rand(0.84, 0.97) * W;   // far right
    if (m === 2) return rand(0.14, 0.30) * W;   // left-mid
    if (m === 3) return rand(0.70, 0.86) * W;   // right-mid
    return rand(0.34, 0.66) * W;                // occasional centre (kept faint by depth)
  }

  var parts = LOGOS.map(function (name, i) {
    var el = document.createElement('img');
    el.className = 'logo-particle';
    el.src = 'assets/logos/' + name + '.svg';
    el.alt = '';
    el.decoding = 'async';
    field.appendChild(el);
    var tz = rand(-220, 240);                   // rest depth (some near/big, some far/small)
    return {
      el: el,
      x: rand(0, W), y: rand(0, H), z: rand(-950, -420),   // start deep + scattered
      vx: rand(-190, 190), vy: rand(-150, 150), vz: rand(-40, 60), // turbulent kick
      tx: targetX(i), ty: rand(0.06, 0.94) * H, tz: tz,
      ph: rand(0, 6.28), amp: rand(6, 16), bob: rand(0.16, 0.34)
    };
  });

  function depthOpacity(z) {
    // nearer (higher z) => more visible; keep it a background layer
    var o = (z + 950) / 1250;               // ~0 at far, ~1 near
    return Math.max(0.05, Math.min(0.6, 0.05 + o * 0.55));
  }
  function place(p, wx, wy) {
    p.el.style.transform =
      'translate3d(' + (p.x + wx) + 'px,' + (p.y + wy) + 'px,' + p.z + 'px) translate(-50%,-50%)';
    p.el.style.opacity = depthOpacity(p.z);
  }

  if (reduce) {                              // no animation: settle statically at targets
    parts.forEach(function (p) { p.x = p.tx; p.y = p.ty; p.z = p.tz; place(p, 0, 0); });
    return;
  }

  var STIFF = 2.4, DAMP = 2.7, t0 = 0, last = 0;
  function step(axis, p, target, k) {
    var v = 'v' + axis;
    var a = (target - p[axis]) * k - p[v] * DAMP;
    p[v] += a * p._dt;
    p[axis] += p[v] * p._dt;
  }

  var running = false;
  function loop(t) {
    if (!running) return;
    if (!t0) { t0 = t; last = t; }
    var dt = Math.min(0.033, (t - last) / 1000); last = t;
    var elapsed = (t - t0) / 1000;
    var k = STIFF * Math.min(1, elapsed / 6);   // spring ramps in -> entropy first, then settles
    for (var i = 0; i < parts.length; i++) {
      var p = parts[i]; p._dt = dt;
      step('x', p, p.tx, k); step('y', p, p.ty, k); step('z', p, p.tz, k);
      // gentle perpetual bob so the settled field still breathes
      var wx = Math.sin(elapsed * p.bob + p.ph) * p.amp;
      var wy = Math.cos(elapsed * p.bob * 0.8 + p.ph) * p.amp;
      place(p, wx, wy);
    }
    requestAnimationFrame(loop);
  }
  function start() { if (running) return; running = true; requestAnimationFrame(loop); }
  function stop() { running = false; }

  parts.forEach(function (p) { place(p, 0, 0); });   // initial deep frame
  start();

  document.addEventListener('visibilitychange', function () {
    if (document.hidden) stop(); else { last = 0; start(); }   // pause offscreen
  });
  window.addEventListener('resize', function () {
    W = window.innerWidth; H = window.innerHeight;
    parts.forEach(function (p, i) { p.tx = targetX(i); p.ty = rand(0.06, 0.94) * H; });
  });
})();
