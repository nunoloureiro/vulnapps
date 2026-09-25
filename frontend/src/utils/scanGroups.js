export const scanGroupOptions = {
  scanner: 'Scanner',
  scanner_version: 'Scanner version',
  configuration: 'App + scanner version + labels',
  app: 'App',
  label: 'Label',
};

export function groupScans(scans, labelsMap, groupBy) {
  if (!groupBy) return [{ key: '', name: '', scans }];
  const grouped = new Map();
  for (const scan of scans) {
    const scanner = scan.scanner_name || 'Unknown scanner';
    const version = scan.scanner_version || null;
    const scannerVersion = `${scanner} · ${version ? `v${version}` : 'Version unknown'}`;
    const app = `${scan.app_name}${scan.app_version ? ` v${scan.app_version}` : ''}`;
    const labels = [...new Set((labelsMap[scan.id] || []).map(label => label.name))].sort();
    let entries;
    if (groupBy === 'label') {
      entries = labels.length ? labels.map(name => ({ key: JSON.stringify(name), name })) : [{ key: 'unlabeled', name: 'No labels' }];
    } else if (groupBy === 'app') {
      entries = [{ key: String(scan.app_id), name: app }];
    } else if (groupBy === 'scanner_version') {
      entries = [{ key: JSON.stringify([scanner, version]), name: scannerVersion }];
    } else if (groupBy === 'configuration') {
      entries = [{ key: JSON.stringify([scan.app_id, scanner, version, labels]), name: scannerVersion, detail: `${app} · ${labels.length ? labels.join(' · ') : 'No labels'}` }];
    } else {
      entries = [{ key: scanner, name: scanner }];
    }
    for (const entry of entries) {
      if (!grouped.has(entry.key)) grouped.set(entry.key, { ...entry, scans: [] });
      grouped.get(entry.key).scans.push(scan);
    }
  }
  return [...grouped.values()].sort((a, b) => a.name.localeCompare(b.name) || (a.detail || '').localeCompare(b.detail || ''));
}
