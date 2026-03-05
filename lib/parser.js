const zlib = require('zlib');

/**
 * Parse dpkg -l output into structured package objects.
 * Only returns packages with status "ii" (installed).
 */
function parseDpkg(output) {
  const lines = output.split('\n');
  const packages = [];

  for (const line of lines) {
    const match = line.match(
      /^ii\s+(\S+?)(?::(\S+))?\s+(\S+)\s+(\S+)\s+(.+)$/
    );
    if (match) {
      packages.push({
        name: match[1],
        architecture: match[2] || match[4],
        version: match[3],
        description: match[5].trim(),
      });
    }
  }

  return packages;
}

/**
 * Parse a Debian Packages file (uncompressed text) into a Map of
 * packageName -> { version, section, priority, description }.
 * If a package appears multiple times, keeps the highest version.
 */
function parsePackagesFile(text) {
  const packages = new Map();
  const blocks = text.split('\n\n');

  for (const block of blocks) {
    if (!block.trim()) continue;

    const fields = {};
    for (const line of block.split('\n')) {
      const m = line.match(/^(\S+?):\s+(.*)$/);
      if (m) {
        fields[m[1]] = m[2];
      }
    }

    if (!fields.Package || !fields.Version) continue;

    const name = fields.Package;
    const existing = packages.get(name);

    if (!existing || compareVersions(fields.Version, existing.version) > 0) {
      packages.set(name, {
        version: fields.Version,
        section: fields.Section || null,
        priority: fields.Priority || null,
        description: fields.Description || null,
      });
    }
  }

  return packages;
}

/**
 * Simple Debian version comparison.
 * Compares epoch, upstream version, and debian revision.
 */
function compareVersions(a, b) {
  if (a === b) return 0;

  const parseVer = (v) => {
    let epoch = 0;
    let rest = v;
    const epochMatch = v.match(/^(\d+):(.*)/);
    if (epochMatch) {
      epoch = parseInt(epochMatch[1], 10);
      rest = epochMatch[2];
    }
    return { epoch, rest };
  };

  const va = parseVer(a);
  const vb = parseVer(b);

  if (va.epoch !== vb.epoch) return va.epoch - vb.epoch;

  // Simple lexicographic comparison of version string parts
  // This handles most cases correctly for Ubuntu versions
  const partsA = va.rest.split(/[\.\-\+~]/);
  const partsB = vb.rest.split(/[\.\-\+~]/);
  const len = Math.max(partsA.length, partsB.length);

  for (let i = 0; i < len; i++) {
    const pa = partsA[i] || '0';
    const pb = partsB[i] || '0';
    const na = parseInt(pa, 10);
    const nb = parseInt(pb, 10);

    if (!isNaN(na) && !isNaN(nb)) {
      if (na !== nb) return na - nb;
    } else {
      if (pa < pb) return -1;
      if (pa > pb) return 1;
    }
  }

  return 0;
}

/**
 * Decompress gzipped buffer.
 */
function gunzip(buffer) {
  return zlib.gunzipSync(buffer).toString('utf8');
}

module.exports = { parseDpkg, parsePackagesFile, compareVersions, gunzip };
