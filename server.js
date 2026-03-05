const express = require('express');
const { exec } = require('child_process');
const { promisify } = require('util');
const path = require('path');
const execAsync = promisify(exec);
const { parseDpkg } = require('./lib/parser');
const { upsertPackages, getAllPackages, getStats, isEmpty } = require('./lib/db');
const { fetchAllRepos } = require('./lib/repo');
const security = require('./lib/security');

const app = express();
const PORT = process.env.PORT || 3000;

let scanning = false;

app.get('/healthz', (_req, res) => res.send('ok'));
app.use(express.static(path.join(__dirname, 'public')));

app.get('/api/packages', (req, res) => {
  const { search, filter, sortBy, sortDir } = req.query;
  const packages = getAllPackages({ search, filter, sortBy, sortDir });
  res.json(packages);
});

app.get('/api/stats', (_req, res) => {
  res.json({ ...getStats(), scanning });
});

app.post('/api/refresh', async (_req, res) => {
  if (scanning) {
    return res.status(409).json({ error: 'Scan already in progress' });
  }

  scanning = true;
  try {
    const stats = await refresh();
    res.json(stats);
  } catch (err) {
    res.status(500).json({ error: err.message });
  } finally {
    scanning = false;
  }
});

async function refresh() {
  const timestamp = new Date().toISOString();

  console.log('Reading installed packages...');
  const { stdout: dpkgOutput } = await execAsync('dpkg -l', {
    encoding: 'utf8',
    maxBuffer: 10 * 1024 * 1024,
  });
  const packages = parseDpkg(dpkgOutput);
  console.log(`Found ${packages.length} installed packages`);

  const { allUpdates, securityUpdates } = await fetchAllRepos(packages);

  upsertPackages(packages, allUpdates, securityUpdates, timestamp);

  return getStats();
}

// Security endpoints
app.get('/api/security/overview', async (_req, res) => res.json(await security.getOverview()));
app.get('/api/security/processes', (_req, res) => res.json(security.getProcessList()));
app.get('/api/security/env-leakage', (_req, res) => res.json(security.getEnvLeakage()));
app.get('/api/security/env-keys', (_req, res) => res.json(security.getOwnEnvKeys()));
app.get('/api/security/filesystem', (_req, res) => res.json(security.getFilesystemExposure()));
app.get('/api/security/resources', (_req, res) => res.json(security.getResourceInfo()));
app.get('/api/security/system', (_req, res) => res.json(security.getSystemInfo()));
app.get('/api/security/network', (_req, res) => res.json(security.getNetworkInfo()));
app.get('/api/security/user', (_req, res) => res.json(security.getUserContext()));
app.get('/api/security/kubernetes', async (_req, res) => res.json(await security.getKubernetesInfo()));
app.get('/api/security/dns', async (_req, res) => res.json(await security.getDnsInfo()));
app.get('/api/security/capabilities', (_req, res) => res.json(security.getCapabilities()));
app.get('/api/security/securitymodules', (_req, res) => res.json(security.getSecurityModules()));
app.get('/api/security/systemusers', (_req, res) => res.json(security.getSystemUsers()));
app.get('/api/security/mounts', (_req, res) => res.json(security.getMountInfo()));
app.get('/api/security/outbound', async (_req, res) => res.json(await security.getOutboundAccess()));
app.get('/api/security/nix', (_req, res) => res.json(security.getNixInfo()));

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Environment Analyzer running on http://0.0.0.0:${PORT}`);

  // Run initial scan in next tick so health checks respond immediately
  if (isEmpty()) {
    setImmediate(async () => {
      console.log('Database empty, running initial scan...');
      scanning = true;
      try {
        const stats = await refresh();
        console.log(`Done: ${stats.total} packages, ${stats.withUpdates} updates, ${stats.securityUpdates} security`);
      } catch (err) {
        console.warn('Initial scan failed:', err.message);
      } finally {
        scanning = false;
      }
    });
  }
});
