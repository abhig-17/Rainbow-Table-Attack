// =========================================================
// Rainbow Table Attack Simulation Script
// Cybersecurity Educational Suite
// =========================================================

(function () {
  'use strict';

  // Navigation Smooth Scroll & Active Menu Highlighting
  const links = Array.from(document.querySelectorAll('.menu a'));
  links.forEach(a => {
    a.addEventListener('click', e => {
      e.preventDefault();
      const target = document.querySelector(a.getAttribute('href'));
      if (target) {
        target.scrollIntoView({ behavior: 'smooth' });
      }
    });
  });

  const observer = new IntersectionObserver(entries => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        links.forEach(l => l.classList.remove('active'));
        const href = '#' + entry.target.id;
        const activeLink = links.find(l => l.getAttribute('href') === href);
        if (activeLink) activeLink.classList.add('active');
      }
    });
  }, { rootMargin: '-30% 0px -60% 0px', threshold: 0 });

  ['home', 'theory', 'procedure', 'simulation', 'code', 'defense'].forEach(id => {
    const el = document.getElementById(id);
    if (el) observer.observe(el);
  });

  // Footer Year
  const yearEl = document.getElementById('year');
  if (yearEl) yearEl.textContent = new Date().getFullYear();

  // Toast Notification System
  const toastEl = document.getElementById('toast');
  let toastTimer = null;
  function showToast(message) {
    if (!toastEl) return;
    toastEl.textContent = message;
    toastEl.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => {
      toastEl.classList.remove('show');
    }, 2500);
  }

  // ================= Cryptographic Operations =================
  async function sha1Hex(str) {
    const encoder = new TextEncoder();
    const data = encoder.encode(str);
    const hashBuffer = await crypto.subtle.digest('SHA-1', data);
    return Array.from(new Uint8Array(hashBuffer))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

  // Reduction Function: maps 40-char SHA-1 hex string to dictionary index
  function reduceToWord(hashHex, dict) {
    let sum = 0;
    for (let i = 0; i < hashHex.length; i += 2) {
      const byte = parseInt(hashHex.slice(i, i + 2), 16);
      if (!isNaN(byte)) sum += byte;
    }
    return dict[sum % dict.length];
  }

  // Sample Dictionary
  const DICT = [
    'helloworld',
    'admin123',
    'letmein',
    'welcome',
    'master',
    'sunshine',
    'dragon',
    'monkey'
  ];

  let Table = []; // Array of { start: string, hash: string }

  // ================= Build Table Operation =================
  const buildBtn = document.getElementById('build-btn');
  const buildStatus = document.getElementById('build-status');
  const entriesCounter = document.getElementById('entries-counter');

  async function buildTable() {
    Table = [];
    for (const word of DICT) {
      const h = await sha1Hex(word);
      Table.push({ start: word, hash: h });
    }
    renderTable(Table);

    if (buildStatus) {
      buildStatus.innerHTML = `<span style="color: var(--emerald);">✓ Rainbow table compiled with <strong>${Table.length} precomputed endpoints</strong>.</span>`;
    }
    if (entriesCounter) {
      entriesCounter.textContent = `${Table.length} Endpoints Precomputed`;
      entriesCounter.style.borderColor = 'var(--emerald)';
      entriesCounter.style.color = 'var(--emerald)';
    }
    if (buildBtn) {
      buildBtn.textContent = '✓ Table Ready in Memory';
      buildBtn.style.background = 'linear-gradient(135deg, #059669, #10b981)';
    }
    showToast(`Rainbow table initialized with ${Table.length} entries`);
  }

  if (buildBtn) {
    buildBtn.addEventListener('click', async () => {
      buildBtn.disabled = true;
      buildBtn.textContent = '⚡ Computing Hashes…';
      await buildTable();
      buildBtn.disabled = false;
    });
  }

  // ================= Render Table & Filter =================
  const tableBody = document.querySelector('#rt-table tbody');
  const tableFilterInput = document.getElementById('table-filter');

  function renderTable(data) {
    if (!tableBody) return;
    if (data.length === 0) {
      tableBody.innerHTML = `<tr><td colspan="3" style="text-align: center; color: var(--text-dim); padding: 24px;">No matching records found.</td></tr>`;
      return;
    }

    tableBody.innerHTML = data.map(row => `
      <tr>
        <td><code>${row.start}</code></td>
        <td><code>${row.hash}</code></td>
        <td style="text-align: right;">
          <button class="copy-btn copy-hash-btn" data-hash="${row.hash}" data-word="${row.start}">
            📋 Use Hash
          </button>
        </td>
      </tr>
    `).join('');

    // Attach row copy buttons
    document.querySelectorAll('.copy-hash-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const hash = btn.getAttribute('data-hash');
        const word = btn.getAttribute('data-word');
        const hashInput = document.getElementById('hash-input');
        if (hashInput) {
          hashInput.value = hash;
          hashInput.focus();
        }
        highlightSampleWord(word);
        showToast(`Loaded SHA-1 for "${word}"`);
      });
    });
  }

  if (tableFilterInput) {
    tableFilterInput.addEventListener('input', e => {
      const q = e.target.value.toLowerCase().trim();
      if (!Table.length) return;
      const filtered = Table.filter(r => r.start.toLowerCase().includes(q) || r.hash.toLowerCase().includes(q));
      renderTable(filtered);
    });
  }

  // ================= Sample Words Buttons =================
  const sampleWrap = document.getElementById('sample-wrap');
  function highlightSampleWord(selectedWord) {
    document.querySelectorAll('.btn-tag').forEach(tag => {
      if (tag.getAttribute('data-word') === selectedWord) {
        tag.classList.add('selected');
      } else {
        tag.classList.remove('selected');
      }
    });
  }

  if (sampleWrap) {
    DICT.forEach(word => {
      const btn = document.createElement('button');
      btn.className = 'btn-tag';
      btn.setAttribute('data-word', word);
      btn.innerHTML = `<span>🔑</span> ${word}`;
      btn.addEventListener('click', async () => {
        const hash = await sha1Hex(word);
        const hashInput = document.getElementById('hash-input');
        if (hashInput) {
          hashInput.value = hash;
          hashInput.focus();
        }
        highlightSampleWord(word);
        showToast(`Target hash set for: "${word}"`);
      });
      sampleWrap.appendChild(btn);
    });
  }

  // ================= Cracking Operation =================
  const crackBtn = document.getElementById('crack-btn');
  const hashInput = document.getElementById('hash-input');
  const resultCard = document.getElementById('result-card');
  const resultHeadline = document.getElementById('result-headline');
  const resultBadge = document.getElementById('result-badge');
  const resultMessage = document.getElementById('result-message');
  const resultMeta = document.getElementById('result-meta');
  const metaPassword = document.getElementById('meta-password');
  const metaMethod = document.getElementById('meta-method');
  const metaLatency = document.getElementById('meta-latency');

  async function crackHash(target) {
    if (!target) return { found: false, error: 'Empty input' };
    const lower = target.toLowerCase().trim();

    // 1. Direct Lookup in precomputed table
    const direct = Table.find(r => r.hash === lower);
    if (direct) {
      return { found: true, password: direct.start, method: 'Direct Endpoint Match' };
    }

    // 2. 1-Step Reduction check
    const candidate = reduceToWord(lower, DICT);
    const candidateHash = await sha1Hex(candidate);
    if (candidateHash === lower) {
      return { found: true, password: candidate, method: '1-Step Reduction Chain' };
    }

    return { found: false };
  }

  if (crackBtn) {
    crackBtn.addEventListener('click', async () => {
      const inputVal = (hashInput?.value || '').trim();

      if (!inputVal) {
        showToast('Please enter or select a hash first.');
        if (hashInput) hashInput.focus();
        return;
      }

      if (Table.length === 0) {
        showToast('Building table automatically...');
        await buildTable();
      }

      crackBtn.disabled = true;
      crackBtn.textContent = '⚡ Analyzing…';

      const startTime = performance.now();
      const res = await crackHash(inputVal);
      const elapsed = (performance.now() - startTime).toFixed(2);

      crackBtn.disabled = false;
      crackBtn.textContent = '🔍 Crack Hash';

      if (!resultCard) return;

      resultCard.classList.remove('success', 'danger');
      resultCard.classList.add('active');

      if (res.found) {
        resultCard.classList.add('success');
        resultHeadline.textContent = '🔓 Password Hash Reversed!';
        resultHeadline.style.color = '#34d399';
        resultBadge.textContent = 'Hash Compromised';
        resultBadge.style.color = '#34d399';
        resultBadge.style.borderColor = 'rgba(52, 211, 153, 0.4)';
        resultMessage.textContent = `The target SHA-1 hash was successfully resolved using precomputed lookup tables in ${elapsed} ms.`;
        
        resultMeta.style.display = 'grid';
        metaPassword.textContent = res.password;
        metaMethod.textContent = res.method;
        metaLatency.textContent = `${elapsed} ms`;

        highlightSampleWord(res.password);
        showToast(`Success! Recovered plaintext: "${res.password}"`);
      } else {
        resultCard.classList.add('danger');
        resultHeadline.textContent = '🔒 Hash Not Found in Table';
        resultHeadline.style.color = '#fb7185';
        resultBadge.textContent = 'Search Exhausted';
        resultBadge.style.color = '#fb7185';
        resultBadge.style.borderColor = 'rgba(251, 113, 133, 0.4)';
        resultMessage.textContent = `No matching endpoint or 1-step reduction chain found in the current demonstration dictionary (Search latency: ${elapsed} ms).`;
        resultMeta.style.display = 'none';
        showToast('Hash not found in current table.');
      }
    });
  }

  // ================= Code Copy Button =================
  const copyCodeBtn = document.getElementById('copy-code-btn');
  if (copyCodeBtn) {
    copyCodeBtn.addEventListener('click', () => {
      const codeSnippet = document.getElementById('code-snippet');
      if (codeSnippet) {
        navigator.clipboard.writeText(codeSnippet.innerText).then(() => {
          copyCodeBtn.textContent = '✓ Copied!';
          showToast('Python reference code copied to clipboard');
          setTimeout(() => {
            copyCodeBtn.textContent = '📋 Copy Code';
          }, 2000);
        });
      }
    });
  }

  // Automatically initialize table on page load for immediate demo readiness
  buildTable();

})();
