let securityData = null;

async function loadSecurityData() {
  if (securityData) return securityData;
  const res = await fetch('/api/security/overview');
  securityData = await res.json();
  return securityData;
}

// ─── Tab: Processes ──────────────────────────────────────────────

async function loadProcessesTab() {
  const data = await loadSecurityData();
  const el = document.getElementById('tab-processes-content');
  const d = data.processes;

  if (!d.available) {
    el.innerHTML = notAvailable(d.error);
    return;
  }

  const infraCount = d.processes.filter(p => p.isInfrastructure).length;
  const totalRssMB = Math.round(d.processes.reduce((s, p) => s + p.rss, 0) / 1024);

  el.innerHTML = `
    <div class="stats" style="margin-bottom:1rem">
      <div class="stat-card"><span class="stat-value">${d.processes.length}</span><span class="stat-label">Total Processes</span></div>
      <div class="stat-card stat-warn"><span class="stat-value">${infraCount}</span><span class="stat-label">Infrastructure</span></div>
      <div class="stat-card"><span class="stat-value">${totalRssMB} MB</span><span class="stat-label">Total RSS</span></div>
    </div>
    <div class="table-wrapper">
      <table>
        <thead><tr><th>PID</th><th>User</th><th>RSS (KB)</th><th>CPU%</th><th>Command</th><th>Type</th></tr></thead>
        <tbody>
          ${d.processes.map(p => `
            <tr class="${p.isInfrastructure ? 'row-update' : ''}">
              <td>${p.pid}</td>
              <td>${esc(p.user)}</td>
              <td>${p.rss.toLocaleString()}</td>
              <td>${p.cpu}</td>
              <td class="desc-col" title="${esc(p.command)}">${esc(p.command)}</td>
              <td>${p.isInfrastructure ? '<span class="badge badge-update">Infra</span>' : '<span class="badge badge-ok">App</span>'}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    </div>
  `;
}

// ─── Tab: Environment ────────────────────────────────────────────

async function loadEnvironmentTab() {
  const data = await loadSecurityData();
  const el = document.getElementById('tab-environment-content');
  const d = data.envLeakage;

  if (!d.available) {
    el.innerHTML = notAvailable(d.error);
    return;
  }

  const readable = d.results.filter(r => r.readable);

  el.innerHTML = `
    <div class="stats" style="margin-bottom:1rem">
      <div class="stat-card"><span class="stat-value">${d.results.length}</span><span class="stat-label">Processes Checked</span></div>
      <div class="stat-card stat-critical"><span class="stat-value">${readable.length}</span><span class="stat-label">Env Readable</span></div>
    </div>
    <div class="table-wrapper">
      <table>
        <thead><tr><th>PID</th><th>Command</th><th>Readable</th><th>Env Vars</th><th>Key Names (sample)</th></tr></thead>
        <tbody>
          ${d.results.filter(r => r.readable && r.envCount > 0).map(r => `
            <tr>
              <td>${r.pid}</td>
              <td class="desc-col" title="${esc(r.command)}">${esc(r.command)}</td>
              <td><span class="badge badge-security">Yes</span></td>
              <td>${r.envCount}</td>
              <td class="desc-col">${r.envKeys.slice(0, 8).map(k => esc(k)).join(', ')}${r.envKeys.length > 8 ? '...' : ''}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    </div>
  `;
}

// ─── Tab: Filesystem ─────────────────────────────────────────────

async function loadFilesystemTab() {
  const data = await loadSecurityData();
  const el = document.getElementById('tab-filesystem-content');
  const d = data.filesystem;

  const readableCount = d.results.filter(r => r.readable).length;

  el.innerHTML = `
    <div class="stats" style="margin-bottom:1rem">
      <div class="stat-card"><span class="stat-value">${d.results.length}</span><span class="stat-label">Paths Checked</span></div>
      <div class="stat-card stat-critical"><span class="stat-value">${readableCount}</span><span class="stat-label">Readable</span></div>
    </div>
    <div class="table-wrapper">
      <table>
        <thead><tr><th>Path</th><th>Type</th><th>Exists</th><th>Readable</th><th>Risk</th></tr></thead>
        <tbody>
          ${d.results.map(r => `
            <tr class="${r.readable ? 'row-security' : ''}">
              <td><code>${esc(r.path)}</code></td>
              <td>${r.type}</td>
              <td>${r.exists ? 'Yes' : 'No'}</td>
              <td>${r.readable ? '<span class="badge badge-security">Yes</span>' : '<span class="badge badge-ok">No</span>'}</td>
              <td>${esc(r.risk)}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    </div>
  `;
}

// ─── Tab: Resources ──────────────────────────────────────────────

async function loadResourcesTab() {
  const data = await loadSecurityData();
  const el = document.getElementById('tab-resources-content');
  const d = data.resources;

  el.innerHTML = `
    <div class="stats" style="margin-bottom:1rem">
      <div class="stat-card"><span class="stat-value">${(d.totalMemoryMB / 1024).toFixed(1)} GB</span><span class="stat-label">Total RAM</span></div>
      <div class="stat-card"><span class="stat-value">${(d.freeMemoryMB / 1024).toFixed(1)} GB</span><span class="stat-label">Free RAM</span></div>
      <div class="stat-card"><span class="stat-value">${d.cpuCount}</span><span class="stat-label">CPU Cores</span></div>
      <div class="stat-card ${d.cgroupEnforced ? 'stat-ok' : 'stat-critical'}">
        <span class="stat-value">${d.cgroupEnforced ? 'Yes' : 'No'}</span>
        <span class="stat-label">Cgroups Enforced</span>
      </div>
    </div>
    <div class="table-wrapper">
      <table>
        <thead><tr><th>Metric</th><th>Value</th></tr></thead>
        <tbody>
          <tr><td>CPU Model</td><td>${esc(d.cpuModel)}</td></tr>
          <tr><td>CPU Cores</td><td>${d.cpuCount}</td></tr>
          <tr><td>Total RAM</td><td>${d.totalMemoryMB.toLocaleString()} MB</td></tr>
          <tr><td>Free RAM</td><td>${d.freeMemoryMB.toLocaleString()} MB</td></tr>
          <tr><td>Cgroup Memory Limit</td><td>${d.cgroupMemoryLimitMB ? d.cgroupMemoryLimitMB.toLocaleString() + ' MB' : 'None'}</td></tr>
          <tr><td>Cgroup CPU Quota</td><td>${d.cgroupCpuQuota ? d.cgroupCpuQuota + ' cores' : 'None'}</td></tr>
          <tr><td>Cgroups Enforced</td><td>${d.cgroupEnforced ? '<span class="badge badge-ok">Yes</span>' : '<span class="badge badge-security">No</span>'}</td></tr>
        </tbody>
      </table>
    </div>
  `;
}

// ─── Tab: System ─────────────────────────────────────────────────

async function loadSystemTab() {
  const data = await loadSecurityData();
  const el = document.getElementById('tab-system-content');
  const d = data.system;

  const uptimeHrs = (d.uptime / 3600).toFixed(1);

  el.innerHTML = `
    <div class="table-wrapper">
      <table>
        <thead><tr><th>Property</th><th>Value</th></tr></thead>
        <tbody>
          <tr><td>Hostname</td><td>${esc(d.hostname)}</td></tr>
          <tr><td>Distribution</td><td>${d.distro ? esc(d.distro) : 'N/A'}</td></tr>
          <tr><td>Kernel</td><td>${esc(d.kernel)}</td></tr>
          <tr><td>Architecture</td><td>${esc(d.arch)}</td></tr>
          <tr><td>Node.js</td><td>${esc(d.nodeVersion)}</td></tr>
          <tr><td>Uptime</td><td>${uptimeHrs} hours</td></tr>
          <tr><td>dpkg Packages</td><td>${d.dpkgPackageCount !== null ? d.dpkgPackageCount : 'N/A'}</td></tr>
        </tbody>
      </table>
    </div>
  `;
}

// ─── Tab: Network ────────────────────────────────────────────────

async function loadNetworkTab() {
  const data = await loadSecurityData();
  const el = document.getElementById('tab-network-content');
  const d = data.network;

  if (!d.available) {
    el.innerHTML = notAvailable(d.error);
    return;
  }

  el.innerHTML = `
    <div class="stats" style="margin-bottom:1rem">
      <div class="stat-card"><span class="stat-value">${d.listeners.length}</span><span class="stat-label">Listening Ports</span></div>
      ${d.workspaceId ? `<div class="stat-card"><span class="stat-value" style="font-size:1rem">${esc(d.workspaceId)}</span><span class="stat-label">Workspace ID</span></div>` : ''}
    </div>
    <div class="table-wrapper">
      <table>
        <thead><tr><th>Address</th><th>Port</th><th>Process</th></tr></thead>
        <tbody>
          ${d.listeners.map(l => `
            <tr>
              <td><code>${esc(l.address)}</code></td>
              <td>${l.port}</td>
              <td>${esc(l.process) || '-'}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    </div>
  `;
}

// ─── Tab: User ───────────────────────────────────────────────────

async function loadUserTab() {
  const data = await loadSecurityData();
  const el = document.getElementById('tab-user-content');
  const d = data.user;

  el.innerHTML = `
    <div class="table-wrapper">
      <table>
        <thead><tr><th>Property</th><th>Value</th></tr></thead>
        <tbody>
          <tr><td>Username</td><td>${esc(d.username)}</td></tr>
          <tr><td>UID</td><td>${d.uid}</td></tr>
          <tr><td>GID</td><td>${d.gid}</td></tr>
          <tr><td>Home</td><td><code>${esc(d.homedir)}</code></td></tr>
          <tr><td>Shell</td><td>${esc(d.shell)}</td></tr>
          <tr><td>Groups</td><td>${d.groups.map(g => `${esc(g.name)} (${g.gid})`).join(', ') || 'N/A'}</td></tr>
        </tbody>
      </table>
    </div>
  `;
}

// ─── Tab: Env Vars ───────────────────────────────────────────────

async function loadEnvkeysTab() {
  const data = await loadSecurityData();
  const el = document.getElementById('tab-envkeys-content');
  const d = data.envKeys;

  el.innerHTML = `
    <div class="stats" style="margin-bottom:1rem">
      <div class="stat-card"><span class="stat-value">${d.count}</span><span class="stat-label">Environment Variables</span></div>
    </div>
    <div class="table-wrapper">
      <table>
        <thead><tr><th>#</th><th>Key Name</th></tr></thead>
        <tbody>
          ${d.keys.map((k, i) => `
            <tr>
              <td>${i + 1}</td>
              <td><code>${esc(k)}</code></td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    </div>
  `;
}

// ─── Tab: Kubernetes ─────────────────────────────────────────────

async function loadKubernetesTab() {
  const data = await loadSecurityData();
  const el = document.getElementById('tab-kubernetes-content');
  const d = data.kubernetes;

  const rows = [
    ['KUBERNETES_SERVICE_HOST', d.serviceHost || 'Not set'],
    ['KUBERNETES_SERVICE_PORT', d.servicePort || 'Not set'],
    ['Service Account Token', d.serviceAccountExists ? '<span class="badge badge-ok">Exists</span>' : '<span class="badge badge-update">Not found</span>'],
    ['Namespace', d.namespace || 'N/A'],
    ['API Reachable', d.apiReachable ? '<span class="badge badge-ok">Yes</span>' : '<span class="badge badge-update">No</span>'],
  ];

  if (d.apiResponse) {
    if (d.apiResponse.error) {
      rows.push(['API Response', esc(d.apiResponse.error)]);
    } else {
      rows.push(['API Status', `${d.apiResponse.status} ${esc(d.apiResponse.statusText || '')}`]);
      rows.push(['API Authorized', d.apiResponse.ok ? '<span class="badge badge-ok">Yes</span>' : '<span class="badge badge-security">No (Forbidden)</span>']);
    }
  }

  el.innerHTML = `
    <div class="table-wrapper">
      <table>
        <thead><tr><th>Property</th><th>Value</th></tr></thead>
        <tbody>
          ${rows.map(([k, v]) => `<tr><td>${esc(k)}</td><td>${v}</td></tr>`).join('')}
        </tbody>
      </table>
    </div>
  `;
}

// ─── Helpers ─────────────────────────────────────────────────────

function notAvailable(error) {
  return `<div class="loading">${esc(error || 'Not available on this platform')}</div>`;
}
