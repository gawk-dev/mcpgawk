/* logofield.js — a 3D field of brand logos behind the page content.
   Two motion variations, switchable with a query param (default 'a'):
     ?fx=a  ENTROPY → SETTLE : start deep + scattered with a turbulent kick,
            spring toward rest targets in the margins, grow with depth, then settle.
     ?fx=b  CONTINUOUS FLOW  : never settles — logos drift across and "breathe"
            through depth forever, a perpetually alive space.
   Sits behind content (z-index:0), pointer-events:none, reduced-motion aware. */
(function () {
  var field = document.getElementById('logoField');
  if (!field) return;

  // blended, globally-spread set (US / China / Korea+Japan / Europe / India / SEAsia / LatAm).
  var LOGOS = [
    // Western AI
    'openai','anthropic','google','gemini','meta','mistral','nvidia','huggingface','perplexity','grok','cursor','cohere',
    // China AI
    'deepseek','qwen','kimi','baidu',
    // Western software / MCP ecosystem
    'github','gitlab','notion','slack','linear','stripe','cloudflare','figma','vercel','supabase','discord','docker',
    // China consumer/software
    'tiktok','wechat','alibaba','xiaomi','huawei','weibo',
    // Korea / Japan
    'naver','line','kakaotalk','rakuten','sony',
    // SE Asia
    'grab','shopee',
    // Europe
    'spotify','sap','klarna',
    // India
    'paytm','zoho','infosys','swiggy',
    // LatAm
    'mercadolibre','nubank'
  ];

  var MODE = (new URLSearchParams(location.search).get('fx') === 'a') ? 'a' : 'b';   // default: continuous flow
  var PERSPECTIVE = 1000;                 // must match CSS perspective on #logoField
  var reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  var W = window.innerWidth, H = window.innerHeight;
  function rand(a, b) { return a + Math.random() * (b - a); }

  // rest targets (mode A): bias to the margins so the readable centre stays clear.
  function targetX(i) {
    var m = i % 5;
    if (m === 0) return rand(0.03, 0.15) * W;
    if (m === 1) return rand(0.85, 0.97) * W;
    if (m === 2) return rand(0.13, 0.29) * W;
    if (m === 3) return rand(0.71, 0.87) * W;
    return rand(0.34, 0.66) * W;
  }

  var parts = LOGOS.map(function (name, i) {
    var el = document.createElement('img');
    el.className = 'logo-particle';
    el.src = 'assets/logos/' + name + '.svg';
    el.alt = ''; el.decoding = 'async';
    field.appendChild(el);
    var p = {
      el: el, name: name,
      x: rand(0, W), y: rand(0, H), z: rand(-950, -420),
      vx: rand(-190, 190), vy: rand(-150, 150), vz: rand(-40, 60),
      tx: targetX(i), ty: rand(0.06, 0.94) * H, tz: rand(-220, 240),
      ph: rand(0, 6.28), amp: rand(6, 16), bob: rand(0.16, 0.34)
    };
    if (MODE === 'b') {                   // continuous-flow init: gentle constant drift + depth breathing
      p.x = rand(0, W); p.y = rand(0, H);
      p.vx = rand(-26, 26); p.vy = rand(-20, 20);
      p.baseZ = rand(-380, 120); p.zAmp = rand(140, 320); p.zSpd = rand(0.12, 0.3);
      p.z = p.baseZ;
    }
    return p;
  });

  function place(p, wx, wy) {
    p.el.style.transform =
      'translate3d(' + (p.x + wx) + 'px,' + (p.y + wy) + 'px,' + p.z + 'px) translate(-50%,-50%)';
    // full opacity — logos read at full strength (they sit behind the text either way)
  }

  if (reduce) {                           // no animation: settle statically
    parts.forEach(function (p, i) {
      p.x = (MODE === 'b') ? p.x : p.tx;
      p.y = (MODE === 'b') ? p.y : p.ty;
      p.z = (MODE === 'b') ? p.baseZ : p.tz;
      place(p, 0, 0);
    });
    return;
  }

  var STIFF = 2.4, DAMP = 2.7, t0 = 0, last = 0;
  function springAxis(p, axis, target, k) {
    var v = 'v' + axis;
    var a = (target - p[axis]) * k - p[v] * DAMP;
    p[v] += a * p._dt; p[axis] += p[v] * p._dt;
  }

  function stepA(p, elapsed, k) {         // entropy → settle
    p._dt = p._dt;
    springAxis(p, 'x', p.tx, k); springAxis(p, 'y', p.ty, k); springAxis(p, 'z', p.tz, k);
    var wx = Math.sin(elapsed * p.bob + p.ph) * p.amp;
    var wy = Math.cos(elapsed * p.bob * 0.8 + p.ph) * p.amp;
    place(p, wx, wy);
  }
  function stepB(p, elapsed) {            // continuous flow + depth breathing
    p.x += p.vx * p._dt; p.y += p.vy * p._dt;
    var pad = 90;                          // wrap around the edges (toroidal)
    if (p.x < -pad) p.x += W + 2 * pad; else if (p.x > W + pad) p.x -= W + 2 * pad;
    if (p.y < -pad) p.y += H + 2 * pad; else if (p.y > H + pad) p.y -= H + 2 * pad;
    p.z = p.baseZ + Math.sin(elapsed * p.zSpd + p.ph) * p.zAmp;
    place(p, 0, 0);
  }

  var running = false;
  function loop(t) {
    if (!running) return;
    if (!t0) { t0 = t; last = t; }
    var dt = Math.min(0.033, (t - last) / 1000); last = t;
    var elapsed = (t - t0) / 1000;
    var k = STIFF * Math.min(1, elapsed / 6);
    for (var i = 0; i < parts.length; i++) {
      var p = parts[i]; p._dt = dt;
      if (MODE === 'b') stepB(p, elapsed); else stepA(p, elapsed, k);
    }
    requestAnimationFrame(loop);
  }
  function start() { if (running) return; running = true; requestAnimationFrame(loop); }
  function stop() { running = false; }

  parts.forEach(function (p) { place(p, 0, 0); });
  start();

  document.addEventListener('visibilitychange', function () {
    if (document.hidden) stop(); else { last = 0; t0 = 0; start(); }
  });
  window.addEventListener('resize', function () {
    W = window.innerWidth; H = window.innerHeight;
    parts.forEach(function (p, i) { p.tx = targetX(i); p.ty = rand(0.06, 0.94) * H; });
  });
})();
