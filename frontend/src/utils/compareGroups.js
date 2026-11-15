// Visual groups on the Compare page. An empty slot in ?scans= (two commas in
// a row, e.g. "1592,1594,,1466") marks a break: a light vertical line is drawn
// after the scan just before it. Returns the Set of scan ids followed by a
// break. Leading/trailing empties and repeated empties make one break or none.
export function groupBreaksAfter(scansParam) {
  const breaks = new Set();
  let last = null;
  let pending = false;
  for (const raw of String(scansParam || '').split(',')) {
    const token = raw.trim();
    if (token === '') {
      if (last !== null) pending = true;
      continue;
    }
    if (!/^\d+$/.test(token)) continue;
    if (pending && last !== null) breaks.add(last);
    pending = false;
    last = Number(token);
  }
  return breaks;
}
