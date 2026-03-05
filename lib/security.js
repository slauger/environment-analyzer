const { execSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const dns = require('dns');
const net = require('net');

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
 * 10. DNS Configuration — resolv.conf + DNS probes
 */
async function getDnsInfo() {
  const result = {
    available: true,
    nameservers: [],
    searchDomains: [],
    options: [],
    probes: [],
  };

  // Parse /etc/resolv.conf
  try {
    const content = fs.readFileSync('/etc/resolv.conf', 'utf8');
    for (const line of content.split('\n')) {
      const trimmed = line.trim();
      if (trimmed.startsWith('nameserver ')) {
        result.nameservers.push(trimmed.split(/\s+/)[1]);
      } else if (trimmed.startsWith('search ')) {
        result.searchDomains = trimmed.split(/\s+/).slice(1);
      } else if (trimmed.startsWith('options ')) {
        result.options = trimmed.split(/\s+/).slice(1);
      }
    }
  } catch {
    result.available = false;
  }

  // DNS probes
  const targets = [
    'kubernetes.default.svc.cluster.local',
    'google.com',
  ];

  const workspaceId = process.env.WORKSPACE_ID;
  if (workspaceId) {
    targets.splice(1, 0, `ws-server-${workspaceId}-app.workspaces`);
  }

  for (const host of targets) {
    try {
      const addresses = await new Promise((resolve, reject) => {
        dns.resolve4(host, (err, addrs) => err ? reject(err) : resolve(addrs));
      });
      result.probes.push({ host, resolved: true, addresses });
    } catch (err) {
      result.probes.push({ host, resolved: false, error: err.code || err.message });
    }
  }

  return result;
}

/**
 * 11. Linux Capabilities — decode CapEff/CapPrm/CapBnd from /proc/1/status
 */
const CAP_NAMES = [
  'CAP_CHOWN', 'CAP_DAC_OVERRIDE', 'CAP_DAC_READ_SEARCH', 'CAP_FOWNER',
  'CAP_FSETID', 'CAP_KILL', 'CAP_SETGID', 'CAP_SETUID',
  'CAP_SETPCAP', 'CAP_LINUX_IMMUTABLE', 'CAP_NET_BIND_SERVICE', 'CAP_NET_BROADCAST',
  'CAP_NET_ADMIN', 'CAP_NET_RAW', 'CAP_IPC_LOCK', 'CAP_IPC_OWNER',
  'CAP_SYS_MODULE', 'CAP_SYS_RAWIO', 'CAP_SYS_CHROOT', 'CAP_SYS_PTRACE',
  'CAP_SYS_PACCT', 'CAP_SYS_ADMIN', 'CAP_SYS_BOOT', 'CAP_SYS_NICE',
  'CAP_SYS_RESOURCE', 'CAP_SYS_TIME', 'CAP_SYS_TTY_CONFIG', 'CAP_MKNOD',
  'CAP_LEASE', 'CAP_AUDIT_WRITE', 'CAP_AUDIT_CONTROL', 'CAP_SETFCAP',
  'CAP_MAC_OVERRIDE', 'CAP_MAC_ADMIN', 'CAP_SYSLOG', 'CAP_WAKE_ALARM',
  'CAP_BLOCK_SUSPEND', 'CAP_AUDIT_READ', 'CAP_PERFMON', 'CAP_BPF',
  'CAP_CHECKPOINT_RESTORE',
];

function decodeCapHex(hex) {
  const val = BigInt('0x' + hex);
  const caps = [];
  for (let i = 0; i < CAP_NAMES.length; i++) {
    if (val & (1n << BigInt(i))) {
      caps.push(CAP_NAMES[i]);
    }
  }
  return caps;
}

function getCapabilities() {
  const result = {
    available: false,
    effective: { hex: null, caps: [] },
    permitted: { hex: null, caps: [] },
    bounding: { hex: null, caps: [] },
  };

  try {
    const status = fs.readFileSync('/proc/1/status', 'utf8');

    for (const line of status.split('\n')) {
      const [key, val] = line.split(':').map(s => s.trim());
      if (!val) continue;

      if (key === 'CapEff') {
        result.effective = { hex: val, caps: decodeCapHex(val) };
        result.available = true;
      } else if (key === 'CapPrm') {
        result.permitted = { hex: val, caps: decodeCapHex(val) };
      } else if (key === 'CapBnd') {
        result.bounding = { hex: val, caps: decodeCapHex(val) };
      }
    }
  } catch {}

  return result;
}

/**
 * 12. Security Modules — AppArmor, Seccomp, LSM
 */
function getSecurityModules() {
  const result = {
    available: false,
    apparmor: null,
    seccomp: null,
    lsm: null,
  };

  // AppArmor profile
  try {
    result.apparmor = fs.readFileSync('/proc/1/attr/current', 'utf8').trim();
    result.available = true;
  } catch {}

  // Seccomp status
  try {
    const status = fs.readFileSync('/proc/self/status', 'utf8');
    const match = status.match(/^Seccomp:\s*(\d+)/m);
    if (match) {
      const mode = parseInt(match[1], 10);
      const modes = { 0: 'disabled', 1: 'strict', 2: 'filter' };
      result.seccomp = { mode, label: modes[mode] || 'unknown' };
      result.available = true;
    }
  } catch {}

  // Active LSMs
  try {
    result.lsm = fs.readFileSync('/sys/kernel/security/lsm', 'utf8').trim().split(',');
    result.available = true;
  } catch {}

  return result;
}

/**
 * 13. System Users — parse /etc/passwd
 */
function getSystemUsers() {
  const result = { available: false, users: [] };

  try {
    const content = fs.readFileSync('/etc/passwd', 'utf8');
    for (const line of content.split('\n')) {
      if (!line.trim()) continue;
      const parts = line.split(':');
      if (parts.length < 7) continue;

      result.users.push({
        username: parts[0],
        uid: parseInt(parts[2], 10),
        gid: parseInt(parts[3], 10),
        gecos: parts[4],
        home: parts[5],
        shell: parts[6],
        isHuman: parseInt(parts[2], 10) >= 1000,
      });
    }
    result.available = true;
  } catch {}

  return result;
}

/**
 * 14. Mount Info — parse /proc/mounts
 */
function getMountInfo() {
  const result = { available: false, mounts: [] };

  try {
    const content = fs.readFileSync('/proc/mounts', 'utf8');
    for (const line of content.split('\n')) {
      if (!line.trim()) continue;
      const parts = line.split(/\s+/);
      if (parts.length < 4) continue;

      result.mounts.push({
        device: parts[0],
        mountpoint: parts[1],
        type: parts[2],
        options: parts[3],
      });
    }
    result.available = true;
  } catch {}

  return result;
}

/**
 * 15. Outbound Access — TCP connect probes + HTTP fetch
 */
async function getOutboundAccess() {
  const targets = [
    { host: '1.1.1.1', port: 53, label: 'DNS (1.1.1.1:53)' },
    { host: '1.1.1.1', port: 443, label: 'HTTPS (1.1.1.1:443)' },
    { host: 'registry.npmjs.org', port: 443, label: 'npm Registry' },
    { host: 'cache.nixos.org', port: 443, label: 'Nix Cache' },
  ];

  const probes = [];

  for (const target of targets) {
    const result = await new Promise(resolve => {
      const sock = new net.Socket();
      const start = Date.now();

      sock.setTimeout(3000);
      sock.connect(target.port, target.host, () => {
        const ms = Date.now() - start;
        sock.destroy();
        resolve({ ...target, reachable: true, latencyMs: ms });
      });
      sock.on('error', (err) => {
        sock.destroy();
        resolve({ ...target, reachable: false, error: err.code || err.message });
      });
      sock.on('timeout', () => {
        sock.destroy();
        resolve({ ...target, reachable: false, error: 'TIMEOUT' });
      });
    });
    probes.push(result);
  }

  // HTTP fetch to get external IP
  let externalIp = null;
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);
    const res = await fetch('https://httpbin.org/ip', { signal: controller.signal });
    clearTimeout(timeout);
    if (res.ok) {
      const body = await res.json();
      externalIp = body.origin || null;
    }
  } catch {}

  return { available: true, probes, externalIp };
}

/**
 * 16. Codesphere Internals — list internal directories
 */
function getCodesphereInternals() {
  const result = { available: false, paths: [] };

  const dirsToScan = [
    '/etc/codesphere/shared-internal',
    path.join(os.homedir(), '.codesphere-internal'),
  ];

  for (const dir of dirsToScan) {
    try {
      fs.accessSync(dir, fs.constants.R_OK);
      const entries = listDirRecursive(dir, 0, 2);
      result.paths.push({ base: dir, entries });
      result.available = true;
    } catch {
      result.paths.push({ base: dir, entries: null, error: 'Not accessible' });
    }
  }

  return result;
}

function listDirRecursive(dirPath, depth, maxDepth) {
  if (depth >= maxDepth) return [];
  const entries = [];

  try {
    const items = fs.readdirSync(dirPath, { withFileTypes: true });
    for (const item of items) {
      const fullPath = path.join(dirPath, item.name);
      const entry = {
        name: item.name,
        path: fullPath,
        isDirectory: item.isDirectory(),
        size: null,
        children: [],
      };

      if (!item.isDirectory()) {
        try {
          entry.size = fs.statSync(fullPath).size;
        } catch {}
      } else {
        entry.children = listDirRecursive(fullPath, depth + 1, maxDepth);
      }

      entries.push(entry);
    }
  } catch {}

  return entries;
}

/**
 * 17. Nix Info — version, channels, store, packages
 */
function getNixInfo() {
  const result = {
    available: false,
    version: null,
    channels: [],
    installedPackages: [],
    storeSize: null,
    storePathCount: null,
  };

  // Nix version
  try {
    result.version = execSync('nix-env --version 2>/dev/null', { encoding: 'utf8', timeout: 5000 }).trim();
    result.available = true;
  } catch {}

  // Channels
  try {
    const output = execSync('nix-channel --list 2>/dev/null', { encoding: 'utf8', timeout: 5000 });
    for (const line of output.split('\n').filter(Boolean)) {
      const parts = line.split(/\s+/);
      result.channels.push({ name: parts[0], url: parts[1] || '' });
    }
  } catch {}

  // Installed packages
  try {
    const output = execSync('nix-env -q 2>/dev/null', { encoding: 'utf8', timeout: 10000 });
    result.installedPackages = output.split('\n').filter(Boolean);
  } catch {}

  // Store size
  try {
    const output = execSync('du -sh /nix/store 2>/dev/null', { encoding: 'utf8', timeout: 15000 });
    result.storeSize = output.split(/\s+/)[0];
  } catch {}

  // Store path count
  try {
    const output = execSync('ls /nix/store 2>/dev/null | wc -l', { encoding: 'utf8', timeout: 10000 });
    result.storePathCount = parseInt(output.trim(), 10);
  } catch {}

  return result;
}

/**
 * Combined overview — all data in one call
 */
async function getOverview() {
  const [k8s, dnsInfo, outbound] = await Promise.all([
    getKubernetesInfo(),
    getDnsInfo(),
    getOutboundAccess(),
  ]);
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
    dns: dnsInfo,
    capabilities: getCapabilities(),
    securityModules: getSecurityModules(),
    systemUsers: getSystemUsers(),
    mounts: getMountInfo(),
    outbound,
    internals: getCodesphereInternals(),
    nix: getNixInfo(),
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
  getDnsInfo,
  getCapabilities,
  getSecurityModules,
  getSystemUsers,
  getMountInfo,
  getOutboundAccess,
  getCodesphereInternals,
  getNixInfo,
  getOverview,
};
