const Database = require('better-sqlite3');
const path = require('path');

const DB_PATH = path.join(__dirname, '..', 'packages.db');

let db;

function getDb() {
  if (!db) {
    db = new Database(DB_PATH);
    db.pragma('journal_mode = WAL');
    db.exec(`
      CREATE TABLE IF NOT EXISTS packages (
        name TEXT PRIMARY KEY,
        version TEXT NOT NULL,
        architecture TEXT,
        description TEXT,
        update_version TEXT,
        is_security INTEGER DEFAULT 0,
        scanned_at TEXT NOT NULL
      )
    `);
    db.exec(`
      CREATE TABLE IF NOT EXISTS scan_meta (
        key TEXT PRIMARY KEY,
        value TEXT
      )
    `);
  }
  return db;
}

function upsertPackages(packages, repoUpdates, securityUpdates, timestamp) {
  const d = getDb();
  const insert = d.prepare(`
    INSERT OR REPLACE INTO packages
      (name, version, architecture, description, update_version, is_security, scanned_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `);

  const tx = d.transaction(() => {
    d.exec('DELETE FROM packages');
    for (const pkg of packages) {
      const repoInfo = repoUpdates.get(pkg.name);
      const secInfo = securityUpdates.get(pkg.name);

      // Package has an update if repo version is newer than installed
      const updateVersion = repoInfo ? repoInfo.version : null;
      const isSecurity = secInfo ? 1 : 0;

      insert.run(
        pkg.name,
        pkg.version,
        pkg.architecture,
        pkg.description,
        updateVersion,
        isSecurity,
        timestamp,
      );
    }
    d.prepare('INSERT OR REPLACE INTO scan_meta (key, value) VALUES (?, ?)')
      .run('last_scan', timestamp);
  });

  tx();
}

function getAllPackages({ search, filter, sortBy, sortDir } = {}) {
  const d = getDb();
  let sql = 'SELECT * FROM packages WHERE 1=1';
  const params = [];

  if (search) {
    sql += ' AND (name LIKE ? OR description LIKE ?)';
    params.push(`%${search}%`, `%${search}%`);
  }
  if (filter === 'security') {
    sql += ' AND is_security = 1';
  } else if (filter === 'updates') {
    sql += ' AND update_version IS NOT NULL';
  } else if (filter === 'current') {
    sql += ' AND update_version IS NULL';
  }

  const allowedCols = ['name', 'version', 'architecture', 'update_version', 'is_security'];
  const col = allowedCols.includes(sortBy) ? sortBy : 'name';
  const dir = sortDir === 'desc' ? 'DESC' : 'ASC';
  sql += ` ORDER BY ${col} ${dir}`;

  return d.prepare(sql).all(...params);
}

function getStats() {
  const d = getDb();
  const total = d.prepare('SELECT COUNT(*) as count FROM packages').get().count;
  const withUpdates = d.prepare('SELECT COUNT(*) as count FROM packages WHERE update_version IS NOT NULL').get().count;
  const securityUpdates = d.prepare('SELECT COUNT(*) as count FROM packages WHERE is_security = 1').get().count;
  const lastScan = d.prepare('SELECT value FROM scan_meta WHERE key = ?').get('last_scan');
  return {
    total,
    withUpdates,
    securityUpdates,
    upToDate: total - withUpdates,
    lastScan: lastScan?.value || null,
  };
}

function isEmpty() {
  const d = getDb();
  return d.prepare('SELECT COUNT(*) as count FROM packages').get().count === 0;
}

module.exports = { getDb, upsertPackages, getAllPackages, getStats, isEmpty };
