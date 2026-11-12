(() => {
  const $ = (selector) => document.querySelector(selector);
  const runButton = $('#run-button');
  const runLabel = $('#run-label');
  const resetButton = $('#reset-button');
  const exportButton = $('#export-button');
  const detailsToggle = $('#details-toggle');
  let latestReport = null;
  let toastTimer = null;

  const timingLabels = [
    ['keygen_mlkem_ms', 'ML-KEM key generation'],
    ['keygen_x25519_ms', 'X25519 key generation'],
    ['encaps_mlkem_ms', 'ML-KEM encapsulation'],
    ['encaps_x25519_keygen_ms', 'Ephemeral X25519 keygen'],
    ['encaps_x25519_dh_ms', 'Sender X25519 DH'],
    ['decaps_mlkem_ms', 'ML-KEM decapsulation'],
    ['decaps_x25519_dh_ms', 'Receiver X25519 DH'],
    ['encaps_combiner_ms', 'Sender SHA3-256'],
    ['decaps_combiner_ms', 'Receiver SHA3-256'],
  ];

  function notify(message) {
    const toast = $('#toast');
    toast.textContent = message;
    toast.classList.add('visible');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => toast.classList.remove('visible'), 2300);
  }

  function setHealth(ok, message) {
    const status = $('#runtime-status');
    status.replaceChildren();
    const dot = document.createElement('span');
    dot.className = `dot ${ok ? 'dot-green' : 'dot-amber'}`;
    status.append(dot, document.createTextNode(message));
  }

  async function checkHealth() {
    try {
      const response = await fetch('/api/health', {cache: 'no-store'});
      const data = await response.json();
      if (response.ok && data.ok) setHealth(true, data.openssl);
      else setHealth(false, 'OpenSSL setup needed');
    } catch (_) {
      setHealth(false, 'Backend unavailable');
    }
  }

  function appendList(parent, items) {
    const ul = document.createElement('ul');
    items.forEach((item) => {
      const li = document.createElement('li');
      li.textContent = item;
      ul.append(li);
    });
    parent.append(ul);
  }

  function renderSteps(steps) {
    document.querySelectorAll('.flow-card').forEach((card) => {
      card.classList.remove('is-complete', 'is-failed', 'is-running');
      const runtime = card.querySelector('.step-runtime');
      const detail = card.querySelector('.step-detail');
      runtime.textContent = 'Not part of this run yet';
      detail.replaceChildren();
      detail.style.display = '';
    });
    steps.forEach((step) => {
      const card = document.querySelector(`.flow-card[data-id="${step.id}"]`);
      if (!card) return;
      card.classList.add(step.status === 'failed' ? 'is-failed' : 'is-complete');
      card.querySelector('.step-runtime').textContent = `${Number(step.elapsed_ms).toFixed(3)} ms · ${step.status.toUpperCase()}`;
      const detail = card.querySelector('.step-detail');
      const expl = document.createElement('p');
      expl.textContent = step.explanation;
      detail.append(expl);
      appendList(detail, [`Input: ${step.inputs.join(', ')}`, `Output: ${step.outputs.join(', ')}`]);
    });
    applyDetailsVisibility();
  }

  function applyDetailsVisibility() {
    const grid = $('#flow-grid');
    grid.classList.toggle('show-details', detailsToggle.checked);
  }

  function renderTimings(timings) {
    const host = $('#timing-list');
    host.replaceChildren();
    const values = timingLabels
      .filter(([key]) => Number.isFinite(timings[key]))
      .map(([key, label]) => ({key, label, value: timings[key]}));
    const max = Math.max(...values.map((item) => item.value), 0.01);
    values.forEach(({label, value}) => {
      const item = document.createElement('div');
      item.className = 'timing-item';
      const name = document.createElement('div');
      name.className = 'timing-name';
      const text = document.createElement('span');
      text.textContent = label;
      const number = document.createElement('strong');
      number.textContent = `${Number(value).toFixed(3)} ms`;
      name.append(text, number);
      const track = document.createElement('div');
      track.className = 'timing-track';
      const fill = document.createElement('div');
      fill.className = 'timing-fill';
      fill.style.width = `${Math.max(1, (value / max) * 100)}%`;
      track.append(fill);
      item.append(name, track);
      host.append(item);
    });
    const total = document.createElement('div');
    total.className = 'timing-item';
    const name = document.createElement('div');
    name.className = 'timing-name';
    const label = document.createElement('span');
    label.textContent = 'Full round trip';
    const value = document.createElement('strong');
    value.textContent = `${Number(timings.total_roundtrip_ms).toFixed(3)} ms`;
    name.append(label, value);
    const track = document.createElement('div');
    track.className = 'timing-track';
    const fill = document.createElement('div');
    fill.className = 'timing-fill';
    fill.style.width = '100%';
    track.append(fill);
    total.append(name, track);
    host.append(total);
  }

  function renderResult(report) {
    latestReport = report;
    renderSteps(report.steps);
    renderTimings(report.timings_ms);
    $('#sender-fingerprint').textContent = report.fingerprints.sender_hybrid_secret_sha256_prefix;
    $('#receiver-fingerprint').textContent = report.fingerprints.receiver_hybrid_secret_sha256_prefix;
    $('#ciphertext-total').innerHTML = `${report.actual_lengths_bytes.xwing_ciphertext.toLocaleString()} <small>B</small>`;
    $('#pk-preview').textContent = report.public_previews.recipient_x25519_public_hex_prefix + '…';
    $('#c2-preview').textContent = report.public_previews.ephemeral_x25519_public_hex_prefix + '…';
    $('#ct-preview').textContent = report.public_previews.mlkem_ciphertext_hex_prefix + '… (1,088 bytes total)';

    const checks = report.checks;
    const verifyCard = document.querySelector('.flow-card[data-id="verify"]');
    if (verifyCard) {
      const rows = verifyCard.querySelectorAll('.flow-size strong');
      if (rows.length >= 2) {
        rows[0].textContent = checks.mlkem_component_match ? 'PASS' : 'FAIL';
        rows[1].textContent = (checks.x25519_component_match && checks.hybrid_shared_secret_match) ? 'PASS' : 'FAIL';
      }
    }
    const allPass = checks.mlkem_component_match && checks.x25519_component_match && checks.hybrid_shared_secret_match;
    const status = $('#result-status');
    status.textContent = allPass ? 'PASS' : 'FAIL';
    status.className = `pill ${allPass ? 'pill-mint' : 'pill-muted'}`;
    const banner = $('#agreement-banner');
    banner.className = `agreement-banner ${allPass ? 'pass' : 'fail'}`;
    banner.replaceChildren();
    const icon = document.createElement('span');
    icon.className = 'banner-symbol';
    icon.textContent = allPass ? '✓' : '×';
    const message = document.createElement('span');
    message.textContent = allPass
      ? 'All three checks passed: ML-KEM component, X25519 component, and final 32-byte hybrid secret.'
      : 'At least one component did not match. Review the run report.';
    banner.append(icon, message);
    exportButton.disabled = false;
    notify(allPass ? 'Real X-Wing round trip completed successfully.' : 'Round trip completed with a failed check.');
  }

  async function runHandshake() {
    runButton.disabled = true;
    resetButton.disabled = true;
    runLabel.textContent = 'Running real cryptographic operations…';
    document.body.classList.add('is-running');
    document.querySelectorAll('.flow-card').forEach((card) => {
      card.classList.remove('is-complete', 'is-failed');
      card.classList.add('is-running');
      const runtime = card.querySelector('.step-runtime');
      runtime.textContent = 'OpenSSL operation in progress…';
    });
    try {
      const response = await fetch('/api/run', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: '{}', cache: 'no-store'});
      const report = await response.json();
      if (!response.ok || !report.ok) throw new Error(report.error || `Backend error ${response.status}`);
      renderResult(report);
      setHealth(true, report.runtime.openssl);
    } catch (error) {
      document.querySelectorAll('.flow-card').forEach((card) => card.classList.remove('is-running'));
      notify(error.message || 'The handshake failed. Check the terminal for details.');
      $('#agreement-banner').className = 'agreement-banner fail';
      $('#agreement-banner').textContent = error.message || 'The handshake failed. Check OpenSSL 3.5+ availability.';
    } finally {
      runButton.disabled = false;
      resetButton.disabled = false;
      runLabel.textContent = 'Run actual handshake';
      document.body.classList.remove('is-running');
    }
  }

  function resetDashboard() {
    latestReport = null;
    document.querySelectorAll('.flow-card').forEach((card) => {
      card.classList.remove('is-complete', 'is-failed', 'is-running');
      card.querySelector('.step-runtime').textContent = 'Awaiting run';
      card.querySelector('.step-detail').replaceChildren();
    });
    $('#sender-fingerprint').textContent = '—';
    $('#receiver-fingerprint').textContent = '—';
    const verifyCard = document.querySelector('.flow-card[data-id="verify"]');
    if (verifyCard) verifyCard.querySelectorAll('.flow-size strong').forEach((node) => { node.textContent = '—'; });
    $('#result-status').textContent = 'NOT RUN';
    $('#result-status').className = 'pill pill-muted';
    $('#agreement-banner').className = 'agreement-banner';
    $('#agreement-banner').textContent = '○ Run the handshake to check shared-secret agreement.';
    $('#timing-list').innerHTML = '<div class="empty-state">Timing data will appear after an actual run.</div>';
    $('#pk-preview').textContent = 'Waiting for run';
    $('#c2-preview').textContent = 'Waiting for run';
    $('#ct-preview').textContent = 'Waiting for run';
    exportButton.disabled = true;
    notify('Dashboard trace reset.');
  }

  function exportReport() {
    if (!latestReport) return;
    const blob = new Blob([JSON.stringify(latestReport, null, 2)], {type: 'application/json'});
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `xwing-paper-baseline-${new Date().toISOString().replaceAll(':', '-')}.json`;
    document.body.append(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
    notify('Run report exported.');
  }

  document.querySelectorAll('[data-copy]').forEach((button) => {
    button.addEventListener('click', async () => {
      const value = document.getElementById(button.dataset.copy).textContent;
      try {
        await navigator.clipboard.writeText(value);
        notify('Copied to clipboard.');
      } catch (_) {
        notify('Clipboard access is unavailable in this browser context.');
      }
    });
  });

  runButton.addEventListener('click', runHandshake);
  resetButton.addEventListener('click', resetDashboard);
  exportButton.addEventListener('click', exportReport);
  detailsToggle.addEventListener('change', applyDetailsVisibility);
  const whyToggle = $('#why-toggle');
  if (whyToggle) {
    whyToggle.addEventListener('click', () => {
      const expanded = whyToggle.getAttribute('aria-expanded') === 'true';
      whyToggle.setAttribute('aria-expanded', String(!expanded));
      $('#why-more').hidden = expanded;
      whyToggle.textContent = expanded ? 'More context' : 'Less context';
    });
  }
  checkHealth();
  applyDetailsVisibility();
})();

