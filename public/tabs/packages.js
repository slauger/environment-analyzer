let currentSort = { by: 'name', dir: 'asc' };
let debounceTimer;

async function loadPackagesTab() {
  fetchPackageStats();
  fetchPackages();
}

async function fetchPackageStats() {
  const res = await fetch('/api/stats');
  const stats = await res.json();

  document.getElementById('pkg-stat-total').textContent = stats.total;
  document.getElementById('pkg-stat-security').textContent = stats.securityUpdates;
  document.getElementById('pkg-stat-updates').textContent = stats.withUpdates - stats.securityUpdates;
  document.getElementById('pkg-stat-current').textContent = stats.upToDate;

  const scanInfo = document.getElementById('pkg-last-scan');
  if (stats.scanning) {
    scanInfo.textContent = 'Scanning...';
  } else if (stats.lastScan) {
    scanInfo.textContent = `Last scan: ${new Date(stats.lastScan).toLocaleString()}`;
  }
}

async function fetchPackages() {
  const search = document.getElementById('pkg-search').value;
  const filter = document.getElementById('pkg-filter').value;

  const params = new URLSearchParams({
    sortBy: currentSort.by,
    sortDir: currentSort.dir,
  });
  if (search) params.set('search', search);
  if (filter) params.set('filter', filter);

  const res = await fetch(`/api/packages?${params}`);
  const packages = await res.json();
  renderPackageTable(packages);
}

function renderPackageTable(packages) {
  const tbody = document.getElementById('pkg-body');

  if (packages.length === 0) {
    tbody.innerHTML = '<tr><td colspan="6" class="loading">No packages found</td></tr>';
    return;
  }

  tbody.innerHTML = packages.map(pkg => {
    let rowClass = '';
    let statusBadge = '';

    if (pkg.is_security) {
      rowClass = 'row-security';
      statusBadge = '<span class="badge badge-security">Security</span>';
    } else if (pkg.update_version) {
      rowClass = 'row-update';
      statusBadge = '<span class="badge badge-update">Update</span>';
    } else {
      statusBadge = '<span class="badge badge-ok">Current</span>';
    }

    return `
      <tr class="${rowClass}">
        <td><a href="https://packages.ubuntu.com/noble/${encodeURIComponent(pkg.name)}" target="_blank" rel="noopener" class="pkg-link">${esc(pkg.name)}</a></td>
        <td class="version-col">${esc(pkg.version)}</td>
        <td class="version-col">${pkg.update_version ? esc(pkg.update_version) : '-'}</td>
        <td>${statusBadge}</td>
        <td>${esc(pkg.architecture || '')}</td>
        <td class="desc-col" title="${esc(pkg.description || '')}">${esc(pkg.description || '')}</td>
      </tr>
    `;
  }).join('');
}

async function doPackageRefresh() {
  const btn = document.getElementById('pkg-refresh-btn');
  btn.disabled = true;
  btn.textContent = 'Scanning...';

  try {
    await fetch('/api/refresh', { method: 'POST' });
    await Promise.all([fetchPackageStats(), fetchPackages()]);
  } catch (err) {
    console.error('Refresh failed:', err);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Refresh';
  }
}

// Init package tab events
document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('#tab-packages th.sortable').forEach(th => {
    th.addEventListener('click', () => {
      const col = th.dataset.sort;
      if (currentSort.by === col) {
        currentSort.dir = currentSort.dir === 'asc' ? 'desc' : 'asc';
      } else {
        currentSort.by = col;
        currentSort.dir = 'asc';
      }
      document.querySelectorAll('#tab-packages th.sortable').forEach(h => {
        h.classList.remove('active', 'asc', 'desc');
      });
      th.classList.add('active', currentSort.dir);
      fetchPackages();
    });
  });

  document.getElementById('pkg-search').addEventListener('input', () => {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(fetchPackages, 300);
  });

  document.getElementById('pkg-filter').addEventListener('change', fetchPackages);
  document.getElementById('pkg-refresh-btn').addEventListener('click', doPackageRefresh);
});
