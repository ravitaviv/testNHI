'use strict';

// ======================================================================
// === Constants & catalogs ===
// ======================================================================

const STORAGE_KEY = 'nhivault.state.v1';

const INTEGRATION_CATALOG = [
  { key: 'aws', label: 'AWS' },
  { key: 'kubernetes', label: 'Kubernetes' },
  { key: 'github', label: 'GitHub' },
  { key: 'slack', label: 'Slack' },
  { key: 'salesforce', label: 'Salesforce' },
  { key: 'anthropic_api', label: 'Anthropic API' },
  { key: 'openai_api', label: 'OpenAI API' },
  { key: 'custom', label: 'Custom Integration' },
];

const TTL_OPTIONS = [
  { key: '15m', label: '15 minutes', minutes: 15 },
  { key: '1h', label: '1 hour', minutes: 60 },
  { key: '24h', label: '24 hours', minutes: 1440 },
  { key: '7d', label: '7 days', minutes: 10080 },
];

const AGENT_TYPES = [
  'Conversational AI',
  'CI/CD Automation',
  'Data Pipeline',
  'Revenue Automation',
  'Custom',
];

const AUDIT_TYPE_LABELS = {
  agent_created: 'Agent registered',
  credential_issued: 'Credential issued',
  credential_revoked: 'Credential revoked',
  credential_expired: 'Credential expired',
};

// ======================================================================
// === Utilities ===
// ======================================================================

function randomId(prefix) {
  const bytes = new Uint8Array(8);
  crypto.getRandomValues(bytes);
  const hex = [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
  return `${prefix}_${hex}`;
}

function generateMockSecret() {
  const bytes = new Uint8Array(24);
  crypto.getRandomValues(bytes);
  const hex = [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
  return `nhi_${hex}`;
}

function maskSecret(secret) {
  return `${secret.slice(0, 8)}••••••••${secret.slice(-4)}`;
}

function isoMinAgo(minutes) {
  return new Date(Date.now() - minutes * 60000).toISOString();
}

function isoMinFromNow(minutes) {
  return isoMinAgo(-minutes);
}

function formatRelative(iso) {
  const diffMs = new Date(iso).getTime() - Date.now();
  const diffMin = Math.round(diffMs / 60000);
  const future = diffMin > 0;
  const abs = Math.abs(diffMin);
  let value, unit;
  if (abs < 1) return 'just now';
  if (abs < 60) { value = abs; unit = 'minute'; }
  else if (abs < 1440) { value = Math.round(abs / 60); unit = 'hour'; }
  else if (abs < 43200) { value = Math.round(abs / 1440); unit = 'day'; }
  else { value = Math.round(abs / 43200); unit = 'month'; }
  const plural = value === 1 ? '' : 's';
  return future ? `in ${value} ${unit}${plural}` : `${value} ${unit}${plural} ago`;
}

function formatAbsolute(iso) {
  return new Date(iso).toLocaleString(undefined, {
    year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
  });
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function scopeLabel(key) {
  const item = INTEGRATION_CATALOG.find((i) => i.key === key);
  return item ? item.label : key;
}

function scopeLabels(keys) {
  return keys.map(scopeLabel).join(', ');
}

async function copyToClipboard(text, fallbackInputEl) {
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(text);
      return true;
    }
    throw new Error('Clipboard API unavailable');
  } catch (err) {
    try {
      fallbackInputEl.focus();
      fallbackInputEl.select();
      return document.execCommand('copy');
    } catch (err2) {
      return false;
    }
  }
}

// ======================================================================
// === State: load / save / seed / reset ===
// ======================================================================

let state = null;

function loadState() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return buildSeedState();
    const parsed = JSON.parse(raw);
    if (!parsed || parsed.version !== 1 || !Array.isArray(parsed.agents)) {
      return buildSeedState();
    }
    return parsed;
  } catch (err) {
    return buildSeedState();
  }
}

function saveState() {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
  } catch (err) {
    // localStorage unavailable (private mode, quota, etc.) — state stays in-memory for this session.
  }
}

function resetState() {
  state = buildSeedState();
  saveState();
}

function buildSeedState() {
  const agents = [];
  const credentials = [];
  const auditLog = [];

  function addAgent(name, type, owner, description, status, createdAgoMin) {
    const agent = {
      id: randomId('agent'),
      name,
      type,
      owner,
      description,
      status,
      createdAt: isoMinAgo(createdAgoMin),
      lastActivityAt: isoMinAgo(createdAgoMin),
    };
    agents.push(agent);
    auditLog.push({
      id: randomId('audit'),
      timestamp: agent.createdAt,
      type: 'agent_created',
      agentId: agent.id,
      credentialId: null,
      summary: `Registered agent — ${name} (${type})`,
      meta: {},
    });
    return agent;
  }

  function addCredential(agent, scopes, ttlKey, issuedAgoMin, revokedAgoMin) {
    const ttl = TTL_OPTIONS.find((t) => t.key === ttlKey);
    const issuedAt = isoMinAgo(issuedAgoMin);
    const expiresAt = isoMinAgo(issuedAgoMin - ttl.minutes);
    const cred = {
      id: randomId('cred'),
      agentId: agent.id,
      scopes,
      secretMasked: maskSecret(generateMockSecret()),
      createdAt: issuedAt,
      expiresAt,
      ttlLabel: ttl.label,
      status: revokedAgoMin != null ? 'revoked' : 'active',
      revokedAt: revokedAgoMin != null ? isoMinAgo(revokedAgoMin) : null,
    };
    credentials.push(cred);
    const scopesStr = scopeLabels(scopes);

    auditLog.push({
      id: randomId('audit'),
      timestamp: issuedAt,
      type: 'credential_issued',
      agentId: agent.id,
      credentialId: cred.id,
      summary: `Issued credential for ${agent.name} — scopes: ${scopesStr} (TTL ${ttl.label})`,
      meta: { scopes, ttlLabel: ttl.label },
    });

    if (revokedAgoMin != null) {
      auditLog.push({
        id: randomId('audit'),
        timestamp: cred.revokedAt,
        type: 'credential_revoked',
        agentId: agent.id,
        credentialId: cred.id,
        summary: `Revoked credential for ${agent.name} — scopes: ${scopesStr}`,
        meta: { scopes },
      });
    } else if (new Date(expiresAt).getTime() <= Date.now()) {
      auditLog.push({
        id: randomId('audit'),
        timestamp: expiresAt,
        type: 'credential_expired',
        agentId: agent.id,
        credentialId: cred.id,
        summary: `Credential for ${agent.name} expired — scopes: ${scopesStr} (TTL ${ttl.label})`,
        meta: { scopes },
      });
    }
    return cred;
  }

  const supportCopilot = addAgent(
    'Support Copilot', 'Conversational AI', 'Customer Support Engineering',
    'Answers tier-1 customer questions and looks up order and account details across support tools.',
    'active', 45 * 1440,
  );
  addCredential(supportCopilot, ['slack', 'salesforce'], '24h', 600, null);
  addCredential(supportCopilot, ['slack'], '7d', 20 * 1440, 15 * 1440);

  const deployBot = addAgent(
    'CI/CD Deploy Bot', 'CI/CD Automation', 'Platform Engineering',
    'Builds, tests, and deploys production releases across the application infrastructure.',
    'active', 90 * 1440,
  );
  addCredential(deployBot, ['github', 'aws', 'kubernetes'], '1h', 40, null);
  addCredential(deployBot, ['aws'], '1h', 2 * 1440, null);

  const dataPipeline = addAgent(
    'Data Pipeline Agent', 'Data Pipeline', 'Data Platform',
    'Runs scheduled ETL jobs that move data between the warehouse, storage, and analytics tools.',
    'active', 60 * 1440,
  );
  addCredential(dataPipeline, ['aws', 'custom'], '24h', 180, null);

  const salesAssistant = addAgent(
    'Sales Assistant Agent', 'Revenue Automation', 'Revenue Operations',
    'Drafts follow-up emails and updates CRM records after sales calls using an LLM API.',
    'suspended', 21 * 1440,
  );
  addCredential(salesAssistant, ['salesforce', 'anthropic_api'], '7d', 6 * 1440, 4 * 1440);

  return { version: 1, agents, credentials, auditLog };
}

function logNewlyExpiredCredentials() {
  let changed = false;
  for (const cred of state.credentials) {
    if (cred.status === 'revoked') continue;
    if (new Date(cred.expiresAt).getTime() > Date.now()) continue;
    const alreadyLogged = state.auditLog.some(
      (e) => e.type === 'credential_expired' && e.credentialId === cred.id,
    );
    if (alreadyLogged) continue;
    const agent = getAgent(cred.agentId);
    addAuditEntry({
      type: 'credential_expired',
      agentId: cred.agentId,
      credentialId: cred.id,
      timestamp: cred.expiresAt,
      summary: `Credential for ${agent ? agent.name : 'unknown agent'} expired — scopes: ${scopeLabels(cred.scopes)} (TTL ${cred.ttlLabel})`,
      meta: { scopes: cred.scopes },
    });
    changed = true;
  }
  if (changed) saveState();
}

// ======================================================================
// === Derived helpers ===
// ======================================================================

function getAgent(id) {
  return state.agents.find((a) => a.id === id);
}

function credentialEffectiveStatus(cred) {
  if (cred.status === 'revoked') return 'revoked';
  if (new Date(cred.expiresAt).getTime() <= Date.now()) return 'expired';
  return 'active';
}

// ======================================================================
// === Router ===
// ======================================================================

function parseRoute() {
  const hash = window.location.hash || '#/dashboard';
  const path = hash.replace(/^#/, '');
  const parts = path.split('/').filter(Boolean);
  if (parts.length === 0 || parts[0] === 'dashboard') return { name: 'dashboard' };
  if (parts[0] === 'agents' && parts[1]) return { name: 'agent', id: parts[1] };
  if (parts[0] === 'audit') return { name: 'audit' };
  return { name: 'notfound' };
}

function navigate(hash) {
  if (window.location.hash === hash) {
    render();
  } else {
    window.location.hash = hash;
  }
}

// ======================================================================
// === Render: dashboard / agent detail / audit log ===
// ======================================================================

const auditFilters = { agentId: '', type: '' };

function render() {
  logNewlyExpiredCredentials();
  const route = parseRoute();
  updateActiveNav(route.name);
  const app = document.getElementById('app');
  if (route.name === 'dashboard') app.innerHTML = renderDashboard();
  else if (route.name === 'agent') app.innerHTML = renderAgentDetail(route.id);
  else if (route.name === 'audit') app.innerHTML = renderAuditPage();
  else app.innerHTML = renderNotFound();
}

function updateActiveNav(routeName) {
  document.querySelectorAll('.nav-link').forEach((link) => {
    const linkRoute = link.getAttribute('data-route');
    const isActive = linkRoute === routeName || (routeName === 'agent' && linkRoute === 'dashboard');
    link.classList.toggle('active', isActive);
  });
}

function statusBadgeHtml(status) {
  const labels = { active: 'Active', suspended: 'Suspended', revoked: 'Revoked', expired: 'Expired' };
  return `<span class="badge badge-${status}">${labels[status] || status}</span>`;
}

function renderDashboard() {
  const activeCredCount = state.credentials.filter((c) => credentialEffectiveStatus(c) === 'active').length;
  const integrationsInUse = new Set(
    state.credentials
      .filter((c) => credentialEffectiveStatus(c) === 'active')
      .flatMap((c) => c.scopes),
  ).size;

  const agentsHtml = state.agents.length
    ? `<div class="agent-grid">${state.agents.map(agentCardHtml).join('')}</div>`
    : '<div class="empty-state">No agents registered yet. Add one to get started.</div>';

  return `
    <div class="page-header">
      <div>
        <h1 class="page-title">Agents</h1>
        <p class="page-subtitle">AI agents and machine workloads with vault-issued credentials.</p>
      </div>
      <button type="button" class="btn btn-primary" data-action="add-agent">Add Agent</button>
    </div>
    <div class="stat-strip">
      <div class="stat-tile"><div class="stat-value">${state.agents.length}</div><div class="stat-label">Registered Agents</div></div>
      <div class="stat-tile"><div class="stat-value">${activeCredCount}</div><div class="stat-label">Active Credentials</div></div>
      <div class="stat-tile"><div class="stat-value">${integrationsInUse}</div><div class="stat-label">Integrations in Use</div></div>
      <div class="stat-tile"><div class="stat-value">${state.auditLog.length}</div><div class="stat-label">Events Logged</div></div>
    </div>
    ${agentsHtml}
  `;
}

function agentCardHtml(agent) {
  const activeCount = state.credentials.filter(
    (c) => c.agentId === agent.id && credentialEffectiveStatus(c) === 'active',
  ).length;
  return `
    <a class="card" href="#/agents/${agent.id}">
      <div class="card-top">
        <div>
          <div class="card-name">${escapeHtml(agent.name)}</div>
          <div class="card-type">${escapeHtml(agent.type)}</div>
        </div>
        ${statusBadgeHtml(agent.status)}
      </div>
      <div class="card-desc">${escapeHtml(agent.description)}</div>
      <div class="card-meta">
        <span>${activeCount} active credential${activeCount === 1 ? '' : 's'}</span>
        <span>${formatRelative(agent.lastActivityAt)}</span>
      </div>
    </a>
  `;
}

function renderAgentDetail(agentId) {
  const agent = getAgent(agentId);
  if (!agent) return renderNotFound();

  const creds = state.credentials
    .filter((c) => c.agentId === agent.id)
    .sort((a, b) => {
      const ea = credentialEffectiveStatus(a) === 'active' ? 0 : 1;
      const eb = credentialEffectiveStatus(b) === 'active' ? 0 : 1;
      if (ea !== eb) return ea - eb;
      return new Date(b.createdAt) - new Date(a.createdAt);
    });

  const credsHtml = creds.length
    ? `<div class="cred-list">${creds.map(credentialRowHtml).join('')}</div>`
    : '<div class="empty-state">No credentials issued yet.</div>';

  const agentAudit = state.auditLog
    .filter((e) => e.agentId === agent.id)
    .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
    .slice(0, 5);
  const auditHtml = agentAudit.length
    ? `<div class="audit-list">${agentAudit.map(auditRowHtml).join('')}</div>`
    : '<div class="empty-state">No activity yet.</div>';

  return `
    <a href="#/dashboard" class="back-link">&larr; All agents</a>
    <div class="detail-header">
      <div class="detail-header-top">
        <div>
          <h1 class="detail-title">${escapeHtml(agent.name)}</h1>
          <div class="detail-type">${escapeHtml(agent.type)} &middot; ${escapeHtml(agent.owner)}</div>
        </div>
        ${statusBadgeHtml(agent.status)}
      </div>
      <p class="detail-desc">${escapeHtml(agent.description)}</p>
      <div class="detail-facts">
        <span><b>Created</b> ${formatRelative(agent.createdAt)}</span>
        <span><b>Last activity</b> ${formatRelative(agent.lastActivityAt)}</span>
      </div>
    </div>

    <div class="section">
      <div class="section-head">
        <div class="section-title">Credentials</div>
        <button type="button" class="btn btn-primary btn-small" data-action="issue-credential" data-agent-id="${agent.id}">Issue New Credential</button>
      </div>
      ${credsHtml}
    </div>

    <div class="section">
      <div class="section-head"><div class="section-title">Recent Activity</div></div>
      ${auditHtml}
    </div>
  `;
}

function credentialRowHtml(cred) {
  const eff = credentialEffectiveStatus(cred);
  const dateLine = eff === 'revoked'
    ? `Revoked ${formatRelative(cred.revokedAt)}`
    : eff === 'expired'
      ? `Expired ${formatRelative(cred.expiresAt)}`
      : `Expires ${formatRelative(cred.expiresAt)}`;

  return `
    <div class="cred-row">
      <div class="cred-row-top">
        <span class="cred-secret">${escapeHtml(cred.secretMasked)}</span>
        ${statusBadgeHtml(eff)}
      </div>
      <div class="chip-row">${cred.scopes.map((s) => `<span class="chip">${escapeHtml(scopeLabel(s))}</span>`).join('')}</div>
      <div class="cred-bottom">
        <span class="cred-dates">Issued ${formatRelative(cred.createdAt)} &middot; ${dateLine}</span>
        ${eff === 'active' ? `<button type="button" class="btn btn-danger btn-small" data-action="revoke" data-cred-id="${cred.id}">Revoke</button>` : ''}
      </div>
    </div>
  `;
}

function auditRowHtml(entry) {
  const agent = entry.agentId ? getAgent(entry.agentId) : null;
  const agentLink = agent ? ` &middot; <a href="#/agents/${agent.id}">${escapeHtml(agent.name)}</a>` : '';
  return `
    <div class="audit-row">
      <div class="audit-dot-col"><span class="dot dot-${entry.type}"></span></div>
      <div class="audit-body">
        <div class="audit-summary">${escapeHtml(entry.summary)}</div>
        <div class="audit-time">${formatAbsolute(entry.timestamp)} &middot; ${formatRelative(entry.timestamp)}${agentLink}</div>
      </div>
    </div>
  `;
}

function renderAuditPage() {
  const agentOptions = state.agents
    .map((a) => `<option value="${a.id}" ${auditFilters.agentId === a.id ? 'selected' : ''}>${escapeHtml(a.name)}</option>`)
    .join('');
  const typeOptions = Object.entries(AUDIT_TYPE_LABELS)
    .map(([k, l]) => `<option value="${k}" ${auditFilters.type === k ? 'selected' : ''}>${l}</option>`)
    .join('');

  let entries = [...state.auditLog].sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
  if (auditFilters.agentId) entries = entries.filter((e) => e.agentId === auditFilters.agentId);
  if (auditFilters.type) entries = entries.filter((e) => e.type === auditFilters.type);

  const listHtml = entries.length
    ? `<div class="audit-list">${entries.map(auditRowHtml).join('')}</div>`
    : '<div class="empty-state">No matching events.</div>';

  return `
    <div class="page-header">
      <div>
        <h1 class="page-title">Audit Log</h1>
        <p class="page-subtitle">Every agent registration, credential issuance, revocation, and expiry.</p>
      </div>
    </div>
    <div class="audit-filters" style="margin-bottom:16px;">
      <select class="select" id="auditAgentFilter">
        <option value="">All agents</option>
        ${agentOptions}
      </select>
      <select class="select" id="auditTypeFilter">
        <option value="">All event types</option>
        ${typeOptions}
      </select>
    </div>
    ${listHtml}
  `;
}

function renderNotFound() {
  return '<div class="empty-state">Not found. <a href="#/dashboard">Go to dashboard</a></div>';
}

// ======================================================================
// === Modals: add agent / issue credential / confirm ===
// ======================================================================

function onModalKeydown(e) {
  if (e.key === 'Escape') closeModal();
}

function openModal(bodyHtml, { dismissible = true } = {}) {
  document.removeEventListener('keydown', onModalKeydown);
  const root = document.getElementById('modalRoot');
  root.innerHTML = `<div class="modal-overlay" id="modalOverlay"><div class="modal" role="dialog" aria-modal="true">${bodyHtml}</div></div>`;
  if (dismissible) {
    document.getElementById('modalOverlay').addEventListener('click', (e) => {
      if (e.target.id === 'modalOverlay') closeModal();
    });
    document.addEventListener('keydown', onModalKeydown);
  }
}

function closeModal() {
  document.getElementById('modalRoot').innerHTML = '';
  document.removeEventListener('keydown', onModalKeydown);
}

function openAddAgentModal() {
  const typeOptions = AGENT_TYPES.map((t) => `<option value="${escapeHtml(t)}">${escapeHtml(t)}</option>`).join('');
  openModal(`
    <h2 class="modal-title">Add Agent</h2>
    <p class="modal-subtitle">Register a new AI agent or machine workload.</p>
    <form id="addAgentForm">
      <div class="field">
        <label for="agentName">Name</label>
        <input type="text" id="agentName" name="name" required maxlength="60" placeholder="e.g. Support Copilot">
      </div>
      <div class="field">
        <label for="agentType">Type</label>
        <select id="agentType" name="type" required>${typeOptions}</select>
      </div>
      <div class="field">
        <label for="agentOwner">Owner / Team</label>
        <input type="text" id="agentOwner" name="owner" required maxlength="60" placeholder="e.g. Platform Engineering">
      </div>
      <div class="field">
        <label for="agentDesc">Description</label>
        <textarea id="agentDesc" name="description" required maxlength="240" placeholder="What does this agent do?"></textarea>
      </div>
      <div class="modal-actions">
        <button type="button" class="btn btn-ghost" data-action="cancel-modal">Cancel</button>
        <button type="submit" class="btn btn-primary">Add Agent</button>
      </div>
    </form>
  `);

  document.getElementById('addAgentForm').addEventListener('submit', (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    const agent = createAgent({
      name: fd.get('name').trim(),
      type: fd.get('type'),
      owner: fd.get('owner').trim(),
      description: fd.get('description').trim(),
    });
    closeModal();
    showToast(`Registered ${agent.name}`);
    navigate(`#/agents/${agent.id}`);
  });
}

function openIssueCredentialModal(agentId) {
  const agent = getAgent(agentId);
  if (!agent) return;
  renderIssuePanel1(agent);
}

function renderIssuePanel1(agent) {
  const chipsHtml = INTEGRATION_CATALOG.map((item) => `
    <label class="chip-select" data-key="${item.key}">
      <input type="checkbox" name="scope" value="${item.key}">
      <span>${escapeHtml(item.label)}</span>
    </label>
  `).join('');

  const ttlHtml = TTL_OPTIONS.map((t, i) => `
    <label class="radio-chip" data-key="${t.key}">
      <input type="radio" name="ttl" value="${t.key}" ${i === 1 ? 'checked' : ''}>
      <span>${escapeHtml(t.label)}</span>
    </label>
  `).join('');

  openModal(`
    <h2 class="modal-title">Issue Credential</h2>
    <p class="modal-subtitle">For <b>${escapeHtml(agent.name)}</b> &mdash; choose scope and lifetime.</p>
    <div class="field">
      <label>Integration scope</label>
      <div class="chip-row">${chipsHtml}</div>
    </div>
    <div class="field">
      <label>Time to live</label>
      <div class="radio-row">${ttlHtml}</div>
    </div>
    <p class="modal-error" id="issueError" style="display:none;">Select at least one integration scope.</p>
    <div class="modal-actions">
      <button type="button" class="btn btn-ghost" data-action="cancel-modal">Cancel</button>
      <button type="button" class="btn btn-primary" id="generateCredBtn">Generate Credential</button>
    </div>
  `);

  const modalEl = document.getElementById('modalRoot');
  modalEl.querySelectorAll('.chip-select').forEach((label) => {
    const input = label.querySelector('input');
    input.addEventListener('change', () => label.classList.toggle('is-checked', input.checked));
  });
  modalEl.querySelectorAll('.radio-chip').forEach((label) => {
    const input = label.querySelector('input');
    if (input.checked) label.classList.add('is-checked');
    input.addEventListener('change', () => {
      modalEl.querySelectorAll('.radio-chip').forEach((l) => l.classList.remove('is-checked'));
      label.classList.add('is-checked');
    });
  });

  document.getElementById('generateCredBtn').addEventListener('click', () => {
    const scopes = [...modalEl.querySelectorAll('input[name="scope"]:checked')].map((i) => i.value);
    if (scopes.length === 0) {
      document.getElementById('issueError').style.display = 'block';
      return;
    }
    const ttlKey = modalEl.querySelector('input[name="ttl"]:checked').value;
    const { record, fullSecret } = issueCredential(agent.id, scopes, ttlKey);
    renderIssuePanel2(agent, record, fullSecret);
  });
}

function renderIssuePanel2(agent, cred, fullSecret) {
  openModal(`
    <h2 class="modal-title">Credential Issued</h2>
    <p class="modal-subtitle">For <b>${escapeHtml(agent.name)}</b> &mdash; scopes: ${escapeHtml(scopeLabels(cred.scopes))} &middot; TTL ${escapeHtml(cred.ttlLabel)}</p>
    <div class="warning-note">This secret is shown once and cannot be retrieved again. Copy it now.</div>
    <div class="secret-box">
      <input type="text" id="secretValue" readonly value="${escapeHtml(fullSecret)}">
      <button type="button" class="btn btn-ghost btn-small" id="copySecretBtn">Copy</button>
    </div>
    <div class="modal-actions">
      <button type="button" class="btn btn-primary" id="doneIssueBtn">Done</button>
    </div>
  `, { dismissible: false });

  const secretInput = document.getElementById('secretValue');
  secretInput.focus();
  secretInput.select();

  document.getElementById('copySecretBtn').addEventListener('click', async () => {
    const ok = await copyToClipboard(fullSecret, secretInput);
    const btn = document.getElementById('copySecretBtn');
    if (!btn) return;
    btn.textContent = ok ? 'Copied!' : 'Select & Ctrl+C';
    setTimeout(() => { if (document.getElementById('copySecretBtn')) btn.textContent = 'Copy'; }, 1800);
  });

  document.getElementById('doneIssueBtn').addEventListener('click', () => {
    closeModal();
    showToast('Credential issued');
    render();
  });
}

function openConfirmModal({ title, message, confirmLabel = 'Confirm', danger = false, onConfirm }) {
  openModal(`
    <h2 class="modal-title">${escapeHtml(title)}</h2>
    <p class="modal-subtitle">${escapeHtml(message)}</p>
    <div class="modal-actions">
      <button type="button" class="btn btn-ghost" data-action="cancel-modal">Cancel</button>
      <button type="button" class="btn ${danger ? 'btn-danger' : 'btn-primary'}" id="confirmActionBtn">${escapeHtml(confirmLabel)}</button>
    </div>
  `);
  document.getElementById('confirmActionBtn').addEventListener('click', () => {
    closeModal();
    onConfirm();
  });
}

// ======================================================================
// === Actions ===
// ======================================================================

function addAuditEntry({ type, agentId, credentialId, timestamp, summary, meta }) {
  state.auditLog.push({
    id: randomId('audit'),
    timestamp,
    type,
    agentId: agentId || null,
    credentialId: credentialId || null,
    summary,
    meta: meta || {},
  });
}

function createAgent({ name, type, owner, description }) {
  const now = new Date().toISOString();
  const agent = {
    id: randomId('agent'),
    name,
    type,
    owner,
    description,
    status: 'active',
    createdAt: now,
    lastActivityAt: now,
  };
  state.agents.push(agent);
  addAuditEntry({
    type: 'agent_created',
    agentId: agent.id,
    credentialId: null,
    timestamp: now,
    summary: `Registered agent — ${name} (${type})`,
    meta: {},
  });
  saveState();
  return agent;
}

function issueCredential(agentId, scopes, ttlKey) {
  const agent = getAgent(agentId);
  const ttl = TTL_OPTIONS.find((t) => t.key === ttlKey);
  const fullSecret = generateMockSecret();
  const now = new Date();
  const cred = {
    id: randomId('cred'),
    agentId,
    scopes,
    secretMasked: maskSecret(fullSecret),
    createdAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + ttl.minutes * 60000).toISOString(),
    ttlLabel: ttl.label,
    status: 'active',
    revokedAt: null,
  };
  state.credentials.push(cred);
  addAuditEntry({
    type: 'credential_issued',
    agentId,
    credentialId: cred.id,
    timestamp: cred.createdAt,
    summary: `Issued credential for ${agent.name} — scopes: ${scopeLabels(scopes)} (TTL ${ttl.label})`,
    meta: { scopes, ttlLabel: ttl.label },
  });
  agent.lastActivityAt = cred.createdAt;
  saveState();
  return { record: cred, fullSecret };
}

function revokeCredential(credId) {
  const cred = state.credentials.find((c) => c.id === credId);
  if (!cred || cred.status === 'revoked') return;
  const agent = getAgent(cred.agentId);
  cred.status = 'revoked';
  cred.revokedAt = new Date().toISOString();
  addAuditEntry({
    type: 'credential_revoked',
    agentId: cred.agentId,
    credentialId: cred.id,
    timestamp: cred.revokedAt,
    summary: `Revoked credential for ${agent ? agent.name : 'unknown agent'} — scopes: ${scopeLabels(cred.scopes)}`,
    meta: { scopes: cred.scopes },
  });
  if (agent) agent.lastActivityAt = cred.revokedAt;
  saveState();
}

// ======================================================================
// === Toast ===
// ======================================================================

function showToast(message) {
  const root = document.getElementById('toastRoot');
  const el = document.createElement('div');
  el.className = 'toast';
  el.textContent = message;
  root.appendChild(el);
  setTimeout(() => el.remove(), 2400);
}

// ======================================================================
// === Event wiring / init ===
// ======================================================================

function wireGlobalEvents() {
  window.addEventListener('hashchange', render);

  document.getElementById('resetDemoBtn').addEventListener('click', () => {
    openConfirmModal({
      title: 'Reset demo data?',
      message: 'This restores the original seed agents, credentials, and audit log. Anything you added will be lost.',
      confirmLabel: 'Reset',
      danger: true,
      onConfirm: () => {
        resetState();
        showToast('Demo data reset');
        navigate('#/dashboard');
      },
    });
  });

  document.addEventListener('click', (e) => {
    const addAgentBtn = e.target.closest('[data-action="add-agent"]');
    if (addAgentBtn) { openAddAgentModal(); return; }

    const issueBtn = e.target.closest('[data-action="issue-credential"]');
    if (issueBtn) { openIssueCredentialModal(issueBtn.getAttribute('data-agent-id')); return; }

    const cancelBtn = e.target.closest('[data-action="cancel-modal"]');
    if (cancelBtn) { closeModal(); return; }

    const revokeBtn = e.target.closest('[data-action="revoke"]');
    if (revokeBtn) {
      const credId = revokeBtn.getAttribute('data-cred-id');
      const cred = state.credentials.find((c) => c.id === credId);
      const agent = cred ? getAgent(cred.agentId) : null;
      openConfirmModal({
        title: 'Revoke credential?',
        message: `This immediately revokes the credential for ${agent ? agent.name : 'this agent'}. This cannot be undone.`,
        confirmLabel: 'Revoke',
        danger: true,
        onConfirm: () => {
          revokeCredential(credId);
          showToast('Credential revoked');
          render();
        },
      });
    }
  });

  document.addEventListener('change', (e) => {
    if (e.target.id === 'auditAgentFilter') {
      auditFilters.agentId = e.target.value;
      render();
    } else if (e.target.id === 'auditTypeFilter') {
      auditFilters.type = e.target.value;
      render();
    }
  });
}

function init() {
  try {
    state = loadState();
    logNewlyExpiredCredentials();
    wireGlobalEvents();
    render();
  } catch (err) {
    console.error('Fufu NHI Vault failed to initialize:', err);
    const app = document.getElementById('app');
    if (app) {
      app.innerHTML = `
        <div class="init-error">
          <h2>Something went wrong</h2>
          <p>The app couldn't start. Try clearing this site's local storage and reloading.</p>
        </div>`;
    }
  }
}

document.addEventListener('DOMContentLoaded', init);
