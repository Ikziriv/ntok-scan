// NTOK SCAN — Self-contained 3D WebGL + GLSL Telemetry Shader & Auth UX
// Zero external dependencies, works 100% offline/air-gapped & inside Tauri WebView2 (WebGL1 / GLSL ES 1.00).
(function () {
  // ---------- Auth UX helpers (password reveal + live register checks) ----------
  function bindAuthUx() {
    document.querySelectorAll("[data-pw-toggle]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var id = btn.getAttribute("data-pw-toggle");
        var inp = document.getElementById(id);
        if (!inp) return;
        var show = inp.type === "password";
        inp.type = show ? "text" : "password";
        btn.textContent = show ? "hide" : "show";
        btn.setAttribute("aria-pressed", show ? "true" : "false");
      });
    });

    var pw = document.getElementById("reg-password");
    var cf = document.getElementById("reg-confirm");
    var pLen = document.getElementById("pw-len");
    var pMatch = document.getElementById("pw-match");
    if (pw && cf && pLen && pMatch) {
      function sync() {
        var okLen = pw.value.length >= 8;
        var okMatch = cf.value.length > 0 && pw.value === cf.value;
        pLen.classList.toggle("ok", okLen);
        pMatch.classList.toggle("ok", okMatch);
      }
      pw.addEventListener("input", sync);
      cf.addEventListener("input", sync);
    }
  }

  // ---------- 3D WebGL Telemetry Topology + Custom GLSL Shaders ----------
  function initStage() {
    var canvas = document.getElementById("auth-canvas");
    if (!canvas) return;
    var gl = canvas.getContext("webgl", { alpha: false, antialias: true, powerPreference: "high-performance" })
          || canvas.getContext("experimental-webgl", { alpha: false, antialias: true });
    if (!gl) return;

    var reducedMotion = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    function compile(type, src) {
      var sh = gl.createShader(type);
      gl.shaderSource(sh, src);
      gl.compileShader(sh);
      if (!gl.getShaderParameter(sh, gl.COMPILE_STATUS)) {
        gl.deleteShader(sh);
        return null;
      }
      return sh;
    }

    function link(vsSrc, fsSrc) {
      var vs = compile(gl.VERTEX_SHADER, vsSrc);
      var fs = compile(gl.FRAGMENT_SHADER, fsSrc);
      if (!vs || !fs) return null;
      var prog = gl.createProgram();
      gl.attachShader(prog, vs);
      gl.attachShader(prog, fs);
      gl.linkProgram(prog);
      if (!gl.getProgramParameter(prog, gl.LINK_STATUS)) {
        gl.deleteProgram(prog);
        return null;
      }
      return prog;
    }

    // ---- Pass 1: Volumetric Obsidian Radar + FBM Cobalt Aurora Backdrop ----
    var bgProg = link(
      "attribute vec2 aPos; varying vec2 vUv; void main(){ vUv = aPos * 0.5 + 0.5; gl_Position = vec4(aPos, 0.0, 1.0); }",
      [
        "precision mediump float;",
        "varying vec2 vUv;",
        "uniform float uTime;",
        "uniform vec2 uRes;",
        "uniform vec2 uMouse;",
        "uniform float uFocus;",
        "float hash(vec2 p){ return fract(sin(dot(p, vec2(127.1, 311.7))) * 43758.5453123); }",
        "float noise(vec2 p){",
        "  vec2 i = floor(p), f = fract(p);",
        "  f = f * f * (3.0 - 2.0 * f);",
        "  return mix(mix(hash(i), hash(i + vec2(1.0, 0.0)), f.x),",
        "             mix(hash(i + vec2(0.0, 1.0)), hash(i + vec2(1.0, 1.0)), f.x), f.y);",
        "}",
        "float fbm(vec2 p){",
        "  float v = 0.0, a = 0.5;",
        "  mat2 m = mat2(0.8, 0.6, -0.6, 0.8);",
        "  for(int i = 0; i < 4; i++){ v += a * noise(p); p = m * p * 2.02; a *= 0.5; }",
        "  return v;",
        "}",
        "void main(){",
        "  vec2 uv = vUv;",
        "  vec2 p = (gl_FragCoord.xy - 0.5 * uRes) / min(uRes.x, uRes.y);",
        "  p -= uMouse * 0.06;",
        "  vec3 base = vec3(0.039, 0.067, 0.125);", // #0A1120 Obsidian Navy
        "  float n1 = fbm(p * 2.1 + vec2(uTime * 0.06, -uTime * 0.04));",
        "  float n2 = fbm(p * 3.4 - vec2(uTime * 0.04, uTime * 0.07) + n1 * 0.6);",
        "  vec3 cobalt = vec3(0.168, 0.384, 0.722);", // #2B62B8 Signal Cobalt
        "  vec3 sky    = vec3(0.271, 0.769, 0.925);", // #45C4EC Logo Sky Cyan
        "  float dist = length(p);",
        "  float halo = exp(-dist * dist * 2.2);",
        "  vec3 col = base + cobalt * (0.28 * n2 * halo + 0.10 * n1);",
        "  // Subtle telemetry coordinate grid",
        "  vec2 gp = abs(fract(p * 7.0) - 0.5);",
        "  float gridLine = smoothstep(0.475, 0.495, max(gp.x, gp.y));",
        "  col += sky * gridLine * 0.035 * (1.0 - smoothstep(0.2, 1.1, dist));",
        "  // Concentric radar rings + expanding pulse",
        "  float rings = smoothstep(0.008, 0.0, abs(fract(dist * 4.0) - 0.5) - 0.485);",
        "  float pulseR = fract(uTime * (0.16 + 0.08 * uFocus));",
        "  float pulse = exp(-abs(dist - pulseR * 0.95) * 38.0) * (1.0 - pulseR);",
        "  // Angular radar sweep beam",
        "  float ang = atan(p.y, p.x);",
        "  float sweepAng = mod(-uTime * (0.65 + 0.35 * uFocus), 6.2831853) - 3.1415926;",
        "  float dAng = mod(ang - sweepAng + 6.2831853, 6.2831853);",
        "  float beam = exp(-dAng * 4.5) * smoothstep(0.88, 0.05, dist);",
        "  col += sky * (rings * 0.06 + pulse * 0.24 + beam * 0.14);",
        "  // Vignette",
        "  col *= smoothstep(1.35, 0.28, dist);",
        "  gl_FragColor = vec4(col, 1.0);",
        "}"
      ].join("\n")
    );

    // ---- Pass 2: 3D Faceted Geodesic Shell (Fresnel + Horizontal Scan-Wave) ----
    var meshProg = link(
      [
        "attribute vec3 aPos;",
        "attribute vec3 aNorm;",
        "uniform mat4 uProj;",
        "uniform mat4 uView;",
        "uniform mat4 uModel;",
        "uniform float uTime;",
        "uniform float uFocus;",
        "varying vec3 vNormal;",
        "varying vec3 vWorldPos;",
        "varying float vWave;",
        "void main(){",
        "  float sweepY = sin(uTime * (0.9 + 0.45 * uFocus)) * 1.15;",
        "  float wave = exp(-abs(aPos.y - sweepY) * 6.5);",
        "  vec3 displaced = aPos + aNorm * (wave * 0.032);",
        "  vec4 world = uModel * vec4(displaced, 1.0);",
        "  vWorldPos = world.xyz;",
        "  vNormal = normalize((uModel * vec4(aNorm, 0.0)).xyz);",
        "  vWave = wave;",
        "  gl_Position = uProj * uView * world;",
        "}"
      ].join("\n"),
      [
        "precision mediump float;",
        "varying vec3 vNormal;",
        "varying vec3 vWorldPos;",
        "varying float vWave;",
        "uniform vec3 uCamPos;",
        "uniform float uWire;",
        "void main(){",
        "  vec3 V = normalize(uCamPos - vWorldPos);",
        "  vec3 N = normalize(vNormal);",
        "  float fresnel = pow(1.0 - abs(dot(N, V)), 2.5);",
        "  vec3 deep   = vec3(0.098, 0.192, 0.325);", // #193153 Deep Navy Facet
        "  vec3 cobalt = vec3(0.216, 0.475, 0.839);", // #3779D6
        "  vec3 sky    = vec3(0.271, 0.769, 0.925);", // #45C4EC
        "  if (uWire > 0.5) {",
        "    vec3 wcol = mix(cobalt * 0.85, sky * 1.25, clamp(vWave * 1.2 + fresnel * 0.45, 0.0, 1.0));",
        "    float alpha = 0.22 + vWave * 0.62 + fresnel * 0.28;",
        "    gl_FragColor = vec4(wcol, alpha);",
        "  } else {",
        "    vec3 scol = mix(deep, cobalt, fresnel * 0.85) + sky * (vWave * 0.48 + pow(fresnel, 2.0) * 0.55);",
        "    float alpha = 0.16 + fresnel * 0.36 + vWave * 0.18;",
        "    gl_FragColor = vec4(scol, alpha);",
        "  }",
        "}"
      ].join("\n")
    );

    // ---- Pass 3: 3D Port & Host Nodes (Glowing Point Sprites) ----
    var ptsProg = link(
      [
        "attribute vec3 aPos;",
        "attribute float aKind;", // 0 = neutral cobalt, 1 = open sky-cyan, 2 = filtered amber
        "attribute float aPhase;",
        "uniform mat4 uProj;",
        "uniform mat4 uView;",
        "uniform mat4 uModel;",
        "uniform float uTime;",
        "uniform float uDpr;",
        "uniform float uFocus;",
        "varying float vKind;",
        "varying float vPulse;",
        "void main(){",
        "  float sweepY = sin(uTime * (0.9 + 0.45 * uFocus)) * 1.15;",
        "  float hit = exp(-abs(aPos.y - sweepY) * 6.0);",
        "  float pulse = 0.65 + 0.35 * sin(uTime * 2.6 + aPhase) + hit * 0.85;",
        "  vec4 world = uModel * vec4(aPos * (1.0 + hit * 0.03), 1.0);",
        "  vec4 viewPos = uView * world;",
        "  gl_Position = uProj * viewPos;",
        "  float baseSize = aKind > 0.5 ? 10.5 : 5.5;",
        "  gl_PointSize = clamp((baseSize + hit * 5.0) * uDpr * (2.6 / max(-viewPos.z, 0.8)), 2.5, 22.0);",
        "  vKind = aKind;",
        "  vPulse = pulse;",
        "}"
      ].join("\n"),
      [
        "precision mediump float;",
        "varying float vKind;",
        "varying float vPulse;",
        "void main(){",
        "  vec2 c = gl_PointCoord - 0.5;",
        "  float r = length(c);",
        "  if (r > 0.5) discard;",
        "  float core = exp(-r * r * 26.0);",
        "  float glow = exp(-r * r * 7.0);",
        "  vec3 col = vKind > 1.5 ? vec3(0.92, 0.76, 0.35) :",
        "             vKind > 0.5 ? vec3(0.271, 0.769, 0.925) : vec3(0.24, 0.49, 0.86);",
        "  vec3 finalCol = mix(col, vec3(1.0), core * 0.65);",
        "  float alpha = clamp((glow * 0.85 + core) * min(vPulse, 1.4), 0.0, 1.0);",
        "  gl_FragColor = vec4(finalCol, alpha);",
        "}"
      ].join("\n")
    );

    if (!bgProg || !meshProg || !ptsProg) return;

    // ---- Build Subdivided Geodesic Icosahedron (2 subdivisions = 320 facets) ----
    function buildGeodesic(radius) {
      var t = (1.0 + Math.sqrt(5.0)) / 2.0;
      var v = [
        [-1, t, 0], [1, t, 0], [-1, -t, 0], [1, -t, 0],
        [0, -1, t], [0, 1, t], [0, -1, -t], [0, 1, -t],
        [t, 0, -1], [t, 0, 1], [-t, 0, -1], [-t, 0, 1]
      ].map(norm3);

      var faces = [
        [0,11,5],[0,5,1],[0,1,7],[0,7,10],[0,10,11],
        [1,5,9],[5,11,4],[11,10,2],[10,7,6],[7,1,8],
        [3,9,4],[3,4,2],[3,2,6],[3,6,8],[3,8,9],
        [4,9,5],[2,4,11],[6,2,10],[8,6,7],[9,8,1]
      ];

      function norm3(a) {
        var l = Math.hypot(a[0], a[1], a[2]) || 1;
        return [a[0] / l, a[1] / l, a[2] / l];
      }

      for (var s = 0; s < 2; s++) {
        var next = [];
        var midCache = {};
        function mid(i1, i2) {
          var key = i1 < i2 ? i1 + ":" + i2 : i2 + ":" + i1;
          if (midCache[key] !== undefined) return midCache[key];
          var a = v[i1], b = v[i2];
          var idx = v.length;
          v.push(norm3([(a[0] + b[0]) * 0.5, (a[1] + b[1]) * 0.5, (a[2] + b[2]) * 0.5]));
          midCache[key] = idx;
          return idx;
        }
        for (var i = 0; i < faces.length; i++) {
          var f = faces[i];
          var a = mid(f[0], f[1]), b = mid(f[1], f[2]), c = mid(f[2], f[0]);
          next.push([f[0], a, c], [f[1], b, a], [f[2], c, b], [a, b, c]);
        }
        faces = next;
      }

      var triPos = [], triNorm = [], wirePos = [], wireNorm = [];
      var edgeSeen = {};
      function addEdge(i1, i2) {
        var key = i1 < i2 ? i1 + ":" + i2 : i2 + ":" + i1;
        if (edgeSeen[key]) return;
        edgeSeen[key] = 1;
        var a = v[i1], b = v[i2];
        wirePos.push(a[0] * radius, a[1] * radius, a[2] * radius, b[0] * radius, b[1] * radius, b[2] * radius);
        wireNorm.push(a[0], a[1], a[2], b[0], b[1], b[2]);
      }

      for (var k = 0; k < faces.length; k++) {
        var fc = faces[k];
        var p0 = v[fc[0]], p1 = v[fc[1]], p2 = v[fc[2]];
        // Flat facet normal for crisp low-poly look matching faceted-N monogram
        var ux = p1[0] - p0[0], uy = p1[1] - p0[1], uz = p1[2] - p0[2];
        var vx = p2[0] - p0[0], vy = p2[1] - p0[1], vz = p2[2] - p0[2];
        var fn = norm3([uy * vz - uz * vy, uz * vx - ux * vz, ux * vy - uy * vx]);
        for (var j = 0; j < 3; j++) {
          var pt = v[fc[j]];
          triPos.push(pt[0] * radius, pt[1] * radius, pt[2] * radius);
          triNorm.push(fn[0], fn[1], fn[2]);
        }
        addEdge(fc[0], fc[1]);
        addEdge(fc[1], fc[2]);
        addEdge(fc[2], fc[0]);
      }

      // Outer orbital telemetry ring + port/host nodes
      var ptsPos = [], ptsKind = [], ptsPhase = [];
      for (var vi = 0; vi < v.length; vi++) {
        var pv = v[vi];
        var r = radius * 1.015;
        ptsPos.push(pv[0] * r, pv[1] * r, pv[2] * r);
        var h = Math.abs(Math.sin(vi * 12.9898) * 43758.5453) % 1;
        ptsKind.push(h > 0.80 ? 1.0 : h > 0.72 ? 2.0 : 0.0);
        ptsPhase.push(vi * 0.73);
      }
      // Subtle equatorial orbital scan ring
      var ringSegs = 72;
      var ringR = radius * 1.36;
      for (var ri = 0; ri < ringSegs; ri++) {
        var a0 = (ri / ringSegs) * Math.PI * 2;
        var a1 = ((ri + 1) / ringSegs) * Math.PI * 2;
        var tilt = 0.34;
        var x0 = Math.cos(a0) * ringR, z0 = Math.sin(a0) * ringR, y0 = Math.sin(a0) * ringR * tilt;
        var x1 = Math.cos(a1) * ringR, z1 = Math.sin(a1) * ringR, y1 = Math.sin(a1) * ringR * tilt;
        wirePos.push(x0, y0, z0, x1, y1, z1);
        wireNorm.push(0, 1, 0, 0, 1, 0);
        if (ri % 6 === 0) {
          ptsPos.push(x0, y0, z0);
          ptsKind.push(ri % 12 === 0 ? 1.0 : 0.0);
          ptsPhase.push(ri * 0.5);
        }
      }

      return {
        triPos: new Float32Array(triPos),
        triNorm: new Float32Array(triNorm),
        triCount: triPos.length / 3,
        wirePos: new Float32Array(wirePos),
        wireNorm: new Float32Array(wireNorm),
        wireCount: wirePos.length / 3,
        ptsPos: new Float32Array(ptsPos),
        ptsKind: new Float32Array(ptsKind),
        ptsPhase: new Float32Array(ptsPhase),
        ptsCount: ptsPos.length / 3
      };
    }

    var geo = buildGeodesic(1.06);

    function makeBuf(arr) {
      var b = gl.createBuffer();
      gl.bindBuffer(gl.ARRAY_BUFFER, b);
      gl.bufferData(gl.ARRAY_BUFFER, arr, gl.STATIC_DRAW);
      return b;
    }

    var quadBuf = makeBuf(new Float32Array([-1, -1, 1, -1, -1, 1, -1, 1, 1, -1, 1, 1]));
    var triPosBuf = makeBuf(geo.triPos);
    var triNormBuf = makeBuf(geo.triNorm);
    var wirePosBuf = makeBuf(geo.wirePos);
    var wireNormBuf = makeBuf(geo.wireNorm);
    var ptsPosBuf = makeBuf(geo.ptsPos);
    var ptsKindBuf = makeBuf(geo.ptsKind);
    var ptsPhaseBuf = makeBuf(geo.ptsPhase);

    // ---- Minimal 4x4 matrix helpers ----
    function perspective(fovRad, aspect, near, far) {
      var f = 1.0 / Math.tan(fovRad * 0.5);
      var nf = 1.0 / (near - far);
      return new Float32Array([
        f / aspect, 0, 0, 0,
        0, f, 0, 0,
        0, 0, (far + near) * nf, -1,
        0, 0, 2 * far * near * nf, 0
      ]);
    }
    function rotXY(rx, ry) {
      var cx = Math.cos(rx), sx = Math.sin(rx);
      var cy = Math.cos(ry), sy = Math.sin(ry);
      return new Float32Array([
        cy, sx * sy, -cx * sy, 0,
        0, cx, sx, 0,
        sy, -sx * cy, cx * cy, 0,
        0, 0, 0, 1
      ]);
    }
    function translate(x, y, z) {
      return new Float32Array([
        1, 0, 0, 0,
        0, 1, 0, 0,
        0, 0, 1, 0,
        x, y, z, 1
      ]);
    }

    // ---- Uniform & attribute locations ----
    var bgLoc = {
      aPos: gl.getAttribLocation(bgProg, "aPos"),
      uTime: gl.getUniformLocation(bgProg, "uTime"),
      uRes: gl.getUniformLocation(bgProg, "uRes"),
      uMouse: gl.getUniformLocation(bgProg, "uMouse"),
      uFocus: gl.getUniformLocation(bgProg, "uFocus")
    };
    var meshLoc = {
      aPos: gl.getAttribLocation(meshProg, "aPos"),
      aNorm: gl.getAttribLocation(meshProg, "aNorm"),
      uProj: gl.getUniformLocation(meshProg, "uProj"),
      uView: gl.getUniformLocation(meshProg, "uView"),
      uModel: gl.getUniformLocation(meshProg, "uModel"),
      uTime: gl.getUniformLocation(meshProg, "uTime"),
      uFocus: gl.getUniformLocation(meshProg, "uFocus"),
      uCamPos: gl.getUniformLocation(meshProg, "uCamPos"),
      uWire: gl.getUniformLocation(meshProg, "uWire")
    };
    var ptsLoc = {
      aPos: gl.getAttribLocation(ptsProg, "aPos"),
      aKind: gl.getAttribLocation(ptsProg, "aKind"),
      aPhase: gl.getAttribLocation(ptsProg, "aPhase"),
      uProj: gl.getUniformLocation(ptsProg, "uProj"),
      uView: gl.getUniformLocation(ptsProg, "uView"),
      uModel: gl.getUniformLocation(ptsProg, "uModel"),
      uTime: gl.getUniformLocation(ptsProg, "uTime"),
      uDpr: gl.getUniformLocation(ptsProg, "uDpr"),
      uFocus: gl.getUniformLocation(ptsProg, "uFocus")
    };

    var width = 1, height = 1, dpr = 1;
    function resize() {
      dpr = Math.min(window.devicePixelRatio || 1, 2);
      var rect = canvas.getBoundingClientRect();
      width = Math.max(1, Math.floor(rect.width * dpr));
      height = Math.max(1, Math.floor(rect.height * dpr));
      if (canvas.width !== width || canvas.height !== height) {
        canvas.width = width;
        canvas.height = height;
      }
      gl.viewport(0, 0, width, height);
    }

    var targetMx = 0, targetMy = 0, mx = 0, my = 0;
    var targetFocus = 0, focusVal = 0;

    window.addEventListener("pointermove", function (e) {
      targetMx = (e.clientX / Math.max(window.innerWidth, 1) - 0.5) * 2.0;
      targetMy = (e.clientY / Math.max(window.innerHeight, 1) - 0.5) * 2.0;
    }, { passive: true });

    document.querySelectorAll(".auth-card input").forEach(function (inp) {
      inp.addEventListener("focus", function () { targetFocus = 1.0; });
      inp.addEventListener("blur", function () { targetFocus = 0.0; });
    });

    if (window.ResizeObserver) {
      new ResizeObserver(resize).observe(canvas);
    } else {
      window.addEventListener("resize", resize);
    }
    resize();

    var start = performance.now();
    var rafId = 0;

    function draw(now) {
      var t = (now - start) * 0.001;
      mx += (targetMx - mx) * 0.05;
      my += (targetMy - my) * 0.05;
      focusVal += (targetFocus - focusVal) * 0.06;

      gl.clearColor(0.039, 0.067, 0.125, 1.0);
      gl.clear(gl.COLOR_BUFFER_BIT | gl.DEPTH_BUFFER_BIT);

      // 1. Shader backdrop
      gl.disable(gl.DEPTH_TEST);
      gl.disable(gl.BLEND);
      gl.useProgram(bgProg);
      gl.bindBuffer(gl.ARRAY_BUFFER, quadBuf);
      gl.enableVertexAttribArray(bgLoc.aPos);
      gl.vertexAttribPointer(bgLoc.aPos, 2, gl.FLOAT, false, 0, 0);
      gl.uniform1f(bgLoc.uTime, t);
      gl.uniform2f(bgLoc.uRes, width, height);
      gl.uniform2f(bgLoc.uMouse, mx, -my);
      gl.uniform1f(bgLoc.uFocus, focusVal);
      gl.drawArrays(gl.TRIANGLES, 0, 6);
      gl.disableVertexAttribArray(bgLoc.aPos);

      // Shared 3D transforms
      var aspect = width / Math.max(height, 1);
      var proj = perspective(0.72, aspect, 0.1, 20.0);
      var view = translate(0.0, 0.12, -3.55);
      var model = rotXY(0.28 + my * 0.22, t * 0.24 + mx * 0.35);

      // 2. Faceted 3D geodesic shell + wireframe lattice
      gl.enable(gl.BLEND);
      gl.blendFunc(gl.SRC_ALPHA, gl.ONE_MINUS_SRC_ALPHA);
      gl.enable(gl.DEPTH_TEST);
      gl.depthMask(false);

      gl.useProgram(meshProg);
      gl.uniformMatrix4fv(meshLoc.uProj, false, proj);
      gl.uniformMatrix4fv(meshLoc.uView, false, view);
      gl.uniformMatrix4fv(meshLoc.uModel, false, model);
      gl.uniform1f(meshLoc.uTime, t);
      gl.uniform1f(meshLoc.uFocus, focusVal);
      gl.uniform3f(meshLoc.uCamPos, 0.0, -0.12, 3.55);

      // Translucent Fresnel facets
      gl.uniform1f(meshLoc.uWire, 0.0);
      gl.bindBuffer(gl.ARRAY_BUFFER, triPosBuf);
      gl.enableVertexAttribArray(meshLoc.aPos);
      gl.vertexAttribPointer(meshLoc.aPos, 3, gl.FLOAT, false, 0, 0);
      gl.bindBuffer(gl.ARRAY_BUFFER, triNormBuf);
      gl.enableVertexAttribArray(meshLoc.aNorm);
      gl.vertexAttribPointer(meshLoc.aNorm, 3, gl.FLOAT, false, 0, 0);
      gl.drawArrays(gl.TRIANGLES, 0, geo.triCount);

      // Additive glowing wireframe + orbital scan ring
      gl.blendFunc(gl.SRC_ALPHA, gl.ONE);
      gl.uniform1f(meshLoc.uWire, 1.0);
      gl.bindBuffer(gl.ARRAY_BUFFER, wirePosBuf);
      gl.vertexAttribPointer(meshLoc.aPos, 3, gl.FLOAT, false, 0, 0);
      gl.bindBuffer(gl.ARRAY_BUFFER, wireNormBuf);
      gl.vertexAttribPointer(meshLoc.aNorm, 3, gl.FLOAT, false, 0, 0);
      gl.drawArrays(gl.LINES, 0, geo.wireCount);
      gl.disableVertexAttribArray(meshLoc.aPos);
      gl.disableVertexAttribArray(meshLoc.aNorm);

      // 3. Glowing port & host nodes
      gl.useProgram(ptsProg);
      gl.uniformMatrix4fv(ptsLoc.uProj, false, proj);
      gl.uniformMatrix4fv(ptsLoc.uView, false, view);
      gl.uniformMatrix4fv(ptsLoc.uModel, false, model);
      gl.uniform1f(ptsLoc.uTime, t);
      gl.uniform1f(ptsLoc.uDpr, dpr);
      gl.uniform1f(ptsLoc.uFocus, focusVal);

      gl.bindBuffer(gl.ARRAY_BUFFER, ptsPosBuf);
      gl.enableVertexAttribArray(ptsLoc.aPos);
      gl.vertexAttribPointer(ptsLoc.aPos, 3, gl.FLOAT, false, 0, 0);
      gl.bindBuffer(gl.ARRAY_BUFFER, ptsKindBuf);
      gl.enableVertexAttribArray(ptsLoc.aKind);
      gl.vertexAttribPointer(ptsLoc.aKind, 1, gl.FLOAT, false, 0, 0);
      gl.bindBuffer(gl.ARRAY_BUFFER, ptsPhaseBuf);
      gl.enableVertexAttribArray(ptsLoc.aPhase);
      gl.vertexAttribPointer(ptsLoc.aPhase, 1, gl.FLOAT, false, 0, 0);
      gl.drawArrays(gl.POINTS, 0, geo.ptsCount);
      gl.disableVertexAttribArray(ptsLoc.aPos);
      gl.disableVertexAttribArray(ptsLoc.aKind);
      gl.disableVertexAttribArray(ptsLoc.aPhase);

      gl.depthMask(true);
    }

    function loop(now) {
      draw(now);
      if (!reducedMotion && !document.hidden) {
        rafId = requestAnimationFrame(loop);
      }
    }

    document.addEventListener("visibilitychange", function () {
      if (document.hidden) {
        cancelAnimationFrame(rafId);
      } else if (!reducedMotion) {
        rafId = requestAnimationFrame(loop);
      }
    });

    rafId = requestAnimationFrame(loop);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", function () {
      bindAuthUx();
      initStage();
    });
  } else {
    bindAuthUx();
    initStage();
  }
})();
