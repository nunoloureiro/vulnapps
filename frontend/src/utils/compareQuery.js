// Query string for the Compare page: `?title=<name>&scans=<ids>`. The title
// always comes first; the scans list is kept exactly as written (commas and
// empty slots such as "1,2,,3" stay readable rather than becoming %2C).
export function compareQuery(title, scans) {
  const parts = [];
  const t = String(title || '').trim();
  if (t) parts.push('title=' + encodeURIComponent(t));
  const s = String(scans || '').split(',').map(x => encodeURIComponent(x.trim())).join(',');
  if (s.replace(/,/g, '')) parts.push('scans=' + s);
  return parts.length ? '?' + parts.join('&') : '';
}
