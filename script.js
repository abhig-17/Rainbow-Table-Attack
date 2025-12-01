// IIFE to avoid global scope pollution
(async function () {
  // ===== Smooth scroll & active menu =====
  const links = [...document.querySelectorAll('.menu a')];
  links.forEach(a => a.addEventListener('click', e => {
    e.preventDefault();
    document.querySelector(a.getAttribute('href')).scrollIntoView({ behavior: 'smooth' });
  }));

  const obs = new IntersectionObserver(entries => {
    entries.forEach(e => {
      if (e.isIntersecting) {
        links.forEach(a => a.classList.remove('active'));
        const id = '#' + e.target.id;
        const hit = links.find(a => a.getAttribute('href') === id);
        if (hit) hit.classList.add('active');
      }
    });
  }, { rootMargin: '-40% 0px -55% 0px', threshold: 0 });

  ['home', 'theory', 'procedure', 'simulation', 'code', 'conclusion'].forEach(id => {
    const el = document.getElementById(id);
    if (el) obs.observe(el);
  });

  // ===== Crypto helpers =====
  async function sha1Hex(str) {
    const enc = new TextEncoder().encode(str);
    const buf = await crypto.subtle.digest('SHA-1', enc);
    return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
  }

  // Tiny reduction function: map hash to a word from a small dictionary by taking bytes mod N
  function reduceToWord(hashHex, dict) {
    const n = dict.length; let sum = 0;
    for (let i = 0; i < hashHex.length; i += 2) { sum += parseInt(hashHex.slice(i, i + 2), 16); }
    return dict[sum % n];
  }

  // ===== Demo rainbow table (8 entries) =====
  const DICT = [
    'helloworld', 'admin123', 'letmein', 'welcome', 'master', 'sunshine', 'dragon', 'monkey'
  ];

  let Table = []; // [{start, hash}]

  async function buildTable() {
    Table = [];
    for (const word of DICT) {
      const h = await sha1Hex(word);
      Table.push({ start: word, hash: h });
    }
    renderTable();
    const status = document.getElementById('build-status');
    if (status) { status.textContent = `✓ Rainbow table built with ${Table.length} precomputed hashes`; }
    const buildBtn = document.getElementById('build-btn');
    if (buildBtn) { buildBtn.textContent = `Table Ready (${Table.length} entries)`; }
  }

  function renderTable() {
    const tbody = document.querySelector('#rt-table tbody');
    if (!tbody) return;
    tbody.innerHTML = Table.map(r => `<tr><td><code>${r.start}</code></td><td><code>${r.hash}</code></td></tr>`).join('');
  }

  async function crackHash(target) {
    if (!target) return { found: false };
    const lower = target.toLowerCase();
    const direct = Table.find(r => r.hash === lower);
    if (direct) return { found: true, password: direct.start, method: 'Direct lookup' };
    const reduced = reduceToWord(lower, DICT);
    const h2 = await sha1Hex(reduced);
    const match = Table.find(r => r.hash === h2);
    if (match) return { found: true, password: match.start, method: '1-step reduction' };
    return { found: false };
  }

  // Set footer year
  const yearEl = document.getElementById('year');
  if (yearEl) yearEl.textContent = new Date().getFullYear();

  // Build table button
  const buildBtn = document.getElementById('build-btn');
  if (buildBtn) {
    buildBtn.addEventListener('click', async () => {
      const btn = document.getElementById('build-btn');
      btn.disabled = true; btn.textContent = 'Building…';
      await buildTable();
      btn.disabled = false; btn.classList.add('pill');
    });
  }

  // Sample buttons
  const sampleWrap = document.getElementById('sample-wrap');
  if (sampleWrap) {
    DICT.forEach(word => {
      const b = document.createElement('button');
      b.className = 'btn tag';
      b.textContent = word;
      b.addEventListener('click', async () => {
        const h = await sha1Hex(word);
        const input = document.getElementById('hash-input');
        if (input) input.value = h;
        const outEl = document.getElementById('crack-out');
        if (outEl) outEl.textContent = `Hash set from word "${word}".`;
      });
      sampleWrap.appendChild(b);
    });
  }

  // Crack button
  const crackBtn = document.getElementById('crack-btn');
  if (crackBtn) {
    crackBtn.addEventListener('click', async () => {
      const h = (document.getElementById('hash-input') || {}).value?.trim();
      const out = document.getElementById('crack-out');
      if (!out) return;
      if (!h) { out.textContent = 'Please enter or generate a hash first.'; out.style.color = 'var(--muted)'; return; }
      out.textContent = 'Working…'; out.style.color = 'var(--muted)';
      const res = await crackHash(h);
      if (res.found) { out.textContent = `Password: ${res.password} (${res.method})`; out.style.color = 'var(--success)'; }
      else { out.textContent = 'Not found in demo table.'; out.style.color = 'var(--danger)'; }
    });
  }

  // optional: build table on load for convenience (comment out if undesired)
  // await buildTable();

})();
