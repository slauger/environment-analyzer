function esc(s) {
  const el = document.createElement('span');
  el.textContent = s;
  return el.innerHTML;
}

// ─── Tab Navigation ──────────────────────────────────────────────

const tabLoaders = {
  packages: loadPackagesTab,
  processes: loadProcessesTab,
  environment: loadEnvironmentTab,
  filesystem: loadFilesystemTab,
  resources: loadResourcesTab,
  system: loadSystemTab,
  network: loadNetworkTab,
  user: loadUserTab,
  envkeys: loadEnvkeysTab,
  kubernetes: loadKubernetesTab,
  dns: loadDnsTab,
  capabilities: loadCapabilitiesTab,
  securitymodules: loadSecuritymodulesTab,
  systemusers: loadSystemusersTab,
  mounts: loadMountsTab,
  outbound: loadOutboundTab,
  internals: loadInternalsTab,
  nix: loadNixTab,
};

const loadedTabs = new Set();

function switchTab(tabName) {
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

  document.querySelector(`.tab-btn[data-tab="${tabName}"]`)?.classList.add('active');
  document.getElementById(`tab-${tabName}`)?.classList.add('active');

  if (!loadedTabs.has(tabName) && tabLoaders[tabName]) {
    loadedTabs.add(tabName);
    tabLoaders[tabName]();
  }
}

document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => switchTab(btn.dataset.tab));
  });

  // Load initial tab
  loadPackagesTab();
  loadedTabs.add('packages');
});
