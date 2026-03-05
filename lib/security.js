const { execSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const INFRA_PATTERNS = [
  'node.*agent', 'code-server', 'watchdog', 'sshd',
  'supervisord', 'nix-daemon', 'dbus-daemon',
];

/**
 * 1. Process Visibility — ps aux
 */
function getProcessList() {
  try {
    const output = execSync('ps aux --no-headers', { encoding: 'utf8', timeout: 5000 });
    const processes = [];

    for (const line of output.split('\n')) {
      const m = line.match(
        /^(\S+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\d+)\s+(\d+)\s+\S+\s+\S+\s+\S+\s+\S+\s+(.+)$/
      );
      if (!m) continue;

      const cmd = m[7].trim();
      const isInfra = INFRA_PATTERNS.some(p => new RegExp(p, 'i').test(cmd));

      processes.push({
        user: m[1],
        pid: parseInt(m[2], 10),
        cpu: parseFloat(m[3]),
        mem: parseFloat(m[4]),
        vsz: parseInt(m[5], 10),
        rss: parseInt(m[6], 10),
        command: cmd,
        isInfrastructure: isInfra,
      });
    }

    return { available: true, processes };
  } catch {
    return { available: false, processes: [], error: 'ps not available' };
  }
}

/**
 * 2. Environment Variable Leakage — reads /proc/{pid}/environ
 * NEVER exposes values, only key names.
 */
function getEnvLeakage() {
  const results = [];

  try {
    const pids = fs.readdirSync('/proc').filter(f => /^\d+$/.test(f));

    for (const pid of pids) {
      const envPath = `/proc/${pid}/environ`;
      let cmdline = '';
      try {
        cmdline = fs.readFileSync(`/proc/${pid}/cmdline`, 'utf8').replace(/\0/g, ' ').trim();
      } catch {}

      try {
        const raw = fs.readFileSync(envPath, 'utf8');
        const vars = raw.split('\0').filter(Boolean);
        const keys = vars.map(v => v.split('=')[0]).filter(Boolean);

        results.push({
          pid: parseInt(pid, 10),
          command: cmdline.substring(0, 120),
          readable: true,
          envCount: keys.length,
          envKeys: keys,
        });
      } catch {
        results.push({
          pid: parseInt(pid, 10),
          command: cmdline.substring(0, 120),
          readable: false,
          envCount: 0,
          envKeys: [],
        });
      }
    }

    return { available: true, results };
  } catch {
    return { available: false, results: [], error: '/proc not available (not Linux?)' };
  }
}

/**
 * 3. Filesystem Exposure — check sensitive paths
 */
function getFilesystemExposure() {
  const checks = [
    { path: '/home', type: 'directory', risk: 'Home directories of all users' },
    { path: `${os.homedir()}/.ssh`, type: 'directory', risk: 'SSH keys and config' },
    { path: `${os.homedir()}/.gitconfig`, type: 'file', risk: 'Git configuration with identity' },
    { path: `${os.homedir()}/.env`, type: 'file', risk: 'Environment secrets' },
    { path: `${os.homedir()}/.codesphere-internal`, type: 'directory', risk: 'Platform internal config' },
    { path: '/nix/store', type: 'directory', risk: 'Nix package store' },
    { path: '/etc/passwd', type: 'file', risk: 'System users' },
    { path: '/etc/shadow', type: 'file', risk: 'Password hashes' },
    { path: '/proc/1/environ', type: 'file', risk: 'PID 1 environment variables' },
    { path: '/sys/fs/cgroup', type: 'directory', risk: 'Cgroup configuration' },
  ];

  const results = checks.map(check => {
    let exists = false;
    let readable = false;

    try {
      fs.accessSync(check.path, fs.constants.F_OK);
      exists = true;
      fs.accessSync(check.path, fs.constants.R_OK);
      readable = true;
    } catch {}

    return { ...check, exists, readable };
  });

  return { available: true, results };
}

/**
 * 4. Resource Info — RAM, CPU, cgroups
 */
function getResourceInfo() {
  const result = {
    available: true,
    totalMemoryMB: Math.round(os.totalmem() / 1024 / 1024),
    freeMemoryMB: Math.round(os.freemem() / 1024 / 1024),
    cpuCount: os.cpus().length,
    cpuModel: os.cpus()[0]?.model || 'unknown',
    cgroupEnforced: false,
    cgroupMemoryLimitMB: null,
    cgroupCpuQuota: null,
  };

  // Check cgroup v2 memory limit
  try {
    const memMax = fs.readFileSync('/sys/fs/cgroup/memory.max', 'utf8').trim();
    if (memMax !== 'max') {
      result.cgroupMemoryLimitMB = Math.round(parseInt(memMax, 10) / 1024 / 1024);
      result.cgroupEnforced = true;
    }
  } catch {
    // cgroup v1 fallback
    try {
      const memLimit = fs.readFileSync('/sys/fs/cgroup/memory/memory.limit_in_bytes', 'utf8').trim();
      const limitMB = Math.round(parseInt(memLimit, 10) / 1024 / 1024);
      if (limitMB < result.totalMemoryMB) {
        result.cgroupMemoryLimitMB = limitMB;
        result.cgroupEnforced = true;
      }
    } catch {}
  }

  // Check cgroup v2 CPU quota
  try {
    const cpuMax = fs.readFileSync('/sys/fs/cgroup/cpu.max', 'utf8').trim();
    const [quota, period] = cpuMax.split(' ');
    if (quota !== 'max') {
      result.cgroupCpuQuota = (parseInt(quota, 10) / parseInt(period, 10)).toFixed(2);
      result.cgroupEnforced = true;
    }
  } catch {}

  return result;
}

/**
 * 5. System Info — OS, kernel, base image
 */
function getSystemInfo() {
  const result = {
    available: true,
    hostname: os.hostname(),
    platform: os.platform(),
    arch: os.arch(),
    kernel: os.release(),
    nodeVersion: process.version,
    uptime: os.uptime(),
    distro: null,
    dpkgPackageCount: null,
  };

  // Read /etc/os-release for distro info
  try {
    const osRelease = fs.readFileSync('/etc/os-release', 'utf8');
    const prettyName = osRelease.match(/PRETTY_NAME="?([^"\n]+)"?/);
    if (prettyName) result.distro = prettyName[1];
  } catch {}

  // Count dpkg packages
  try {
    const output = execSync('dpkg -l 2>/dev/null | grep "^ii" | wc -l', {
      encoding: 'utf8',
      timeout: 5000,
    });
    result.dpkgPackageCount = parseInt(output.trim(), 10);
  } catch {}

  return result;
}

/**
 * 6. Network Info — listening ports
 */
function getNetworkInfo() {
  try {
    const output = execSync('ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null', {
      encoding: 'utf8',
      timeout: 5000,
    });

    const listeners = [];
    for (const line of output.split('\n').slice(1)) {
      const m = line.match(/LISTEN\s+\d+\s+\d+\s+(\S+):(\d+)\s/);
      if (!m) continue;

      let process = '';
      const pm = line.match(/users:\(\("([^"]+)"/);
      if (pm) process = pm[1];

      listeners.push({
        address: m[1],
        port: parseInt(m[2], 10),
        process,
      });
    }

    // Detect workspace ID from env
    const workspaceId = process.env.WORKSPACE_ID || null;
    const dnsPattern = workspaceId
      ? `ws-server-${workspaceId}-{service}.workspaces:{port}`
      : null;

    return { available: true, listeners, workspaceId, dnsPattern };
  } catch {
    return { available: false, listeners: [], error: 'ss/netstat not available' };
  }
}

/**
 * 7. User Context — UID, GID, groups
 */
function getUserContext() {
  const info = os.userInfo();
  const result = {
    available: true,
    username: info.username,
    uid: info.uid,
    gid: info.gid,
    homedir: info.homedir,
    shell: info.shell,
    groups: [],
  };

  try {
    const output = execSync('id', { encoding: 'utf8', timeout: 5000 });
    const groupsMatch = output.match(/groups=(.+)/);
    if (groupsMatch) {
      result.groups = groupsMatch[1].split(',').map(g => {
        const m = g.match(/(\d+)\(([^)]+)\)/);
        return m ? { gid: parseInt(m[1], 10), name: m[2] } : null;
      }).filter(Boolean);
    }
  } catch {}

  return result;
}

/**
 * 8. Own process environment variable keys (never values)
 */
function getOwnEnvKeys() {
  const keys = Object.keys(process.env).sort();
  return { available: true, keys, count: keys.length };
}

/**
 * 9. Kubernetes API probe
 * Checks if K8s service account and API are reachable.
 */
async function getKubernetesInfo() {
  const result = {
    available: false,
    serviceHost: process.env.KUBERNETES_SERVICE_HOST || null,
    servicePort: process.env.KUBERNETES_SERVICE_PORT || null,
    serviceAccountExists: false,
    apiReachable: false,
    namespace: null,
    apiResponse: null,
  };

  // Check service account token
  const tokenPath = '/var/run/secrets/kubernetes.io/serviceaccount/token';
  const nsPath = '/var/run/secrets/kubernetes.io/serviceaccount/namespace';
  const caPath = '/var/run/secrets/kubernetes.io/serviceaccount/ca.crt';

  try {
    fs.accessSync(tokenPath, fs.constants.R_OK);
    result.serviceAccountExists = true;
  } catch {}

  try {
    result.namespace = fs.readFileSync(nsPath, 'utf8').trim();
  } catch {}

  if (!result.serviceHost) {
    return result;
  }

  result.available = true;

  // Try to reach the K8s API
  try {
    const token = fs.readFileSync(tokenPath, 'utf8').trim();
    const baseUrl = `https://${result.serviceHost}:${result.servicePort}`;

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);

    const res = await fetch(`${baseUrl}/api/v1/namespaces/${result.namespace || 'default'}/pods`, {
      headers: { Authorization: `Bearer ${token}` },
      signal: controller.signal,
      // Skip TLS verification for in-cluster (Node 22 doesn't have a clean way, but the request itself tells us a lot)
    }).catch(e => ({ ok: false, status: 0, statusText: e.message }));

    clearTimeout(timeout);

    result.apiReachable = true;
    result.apiResponse = {
      status: res.status,
      statusText: res.statusText,
      ok: res.ok,
    };
  } catch (err) {
    result.apiResponse = { error: err.message };
  }

  return result;
}

/**
 * Combined overview — all data in one call
 */
async function getOverview() {
  const k8s = await getKubernetesInfo();
  return {
    processes: getProcessList(),
    envLeakage: getEnvLeakage(),
    envKeys: getOwnEnvKeys(),
    filesystem: getFilesystemExposure(),
    resources: getResourceInfo(),
    system: getSystemInfo(),
    network: getNetworkInfo(),
    user: getUserContext(),
    kubernetes: k8s,
  };
}

module.exports = {
  getProcessList,
  getEnvLeakage,
  getOwnEnvKeys,
  getFilesystemExposure,
  getResourceInfo,
  getSystemInfo,
  getNetworkInfo,
  getUserContext,
  getKubernetesInfo,
  getOverview,
};
