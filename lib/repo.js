const { parsePackagesFile, compareVersions, gunzip } = require('./parser');

const MIRROR = 'http://archive.ubuntu.com/ubuntu';
const RELEASE = 'noble';
const COMPONENTS = ['main', 'universe', 'restricted', 'multiverse'];
const ARCH = 'amd64';

const REPOS = {
  security: `${MIRROR}/dists/${RELEASE}-security`,
  updates: `${MIRROR}/dists/${RELEASE}-updates`,
};

/**
 * Download and parse a single Packages.gz file.
 */
async function fetchPackagesFile(baseUrl, component) {
  const url = `${baseUrl}/${component}/binary-${ARCH}/Packages.gz`;
  const res = await fetch(url);
  if (!res.ok) {
    console.warn(`Failed to fetch ${url}: ${res.status}`);
    return new Map();
  }
  const buffer = Buffer.from(await res.arrayBuffer());
  const text = gunzip(buffer);
  return parsePackagesFile(text);
}

/**
 * Fetch all Packages files from a repo (all components) and merge them.
 */
async function fetchRepo(baseUrl) {
  const merged = new Map();

  const results = await Promise.all(
    COMPONENTS.map(comp => fetchPackagesFile(baseUrl, comp))
  );

  for (const packages of results) {
    for (const [name, info] of packages) {
      const existing = merged.get(name);
      if (!existing || compareVersions(info.version, existing.version) > 0) {
        merged.set(name, info);
      }
    }
  }

  return merged;
}

/**
 * Fetch both noble-updates and noble-security repos.
 * Returns:
 *   - allUpdates: Map of packages with newer versions in any repo
 *   - securityUpdates: Map of packages with newer versions in security repo
 */
async function fetchAllRepos(installedPackages) {
  console.log('Fetching noble-security packages...');
  const securityRepo = await fetchRepo(REPOS.security);

  console.log('Fetching noble-updates packages...');
  const updatesRepo = await fetchRepo(REPOS.updates);

  // Merge all repo data (updates takes precedence for version)
  const allRepo = new Map();
  for (const [name, info] of securityRepo) allRepo.set(name, info);
  for (const [name, info] of updatesRepo) {
    const existing = allRepo.get(name);
    if (!existing || compareVersions(info.version, existing.version) > 0) {
      allRepo.set(name, info);
    }
  }

  // Compare installed vs repo versions
  const allUpdates = new Map();
  const securityUpdates = new Map();

  for (const pkg of installedPackages) {
    const repoInfo = allRepo.get(pkg.name);
    if (repoInfo && compareVersions(repoInfo.version, pkg.version) > 0) {
      allUpdates.set(pkg.name, repoInfo);
    }

    const secInfo = securityRepo.get(pkg.name);
    if (secInfo && compareVersions(secInfo.version, pkg.version) > 0) {
      securityUpdates.set(pkg.name, secInfo);
    }
  }

  console.log(`Found ${allUpdates.size} updates, ${securityUpdates.size} security updates`);
  return { allUpdates, securityUpdates };
}

module.exports = { fetchAllRepos };
