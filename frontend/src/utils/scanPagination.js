export const scanSortKeys = ['date', 'scanner', 'app', 'tp', 'fp', 'pending', 'fn', 'weighted_found', 'cost_per_point'];
export const scanPageSizes = [25, 50, 100, 200];

export function scanPagination(params) {
  const page = Number(params.get('page') || 1);
  const pageSize = Number(params.get('page_size') || 50);
  return {
    page: Number.isSafeInteger(page) && page > 0 ? page : 1,
    pageSize: scanPageSizes.includes(pageSize) ? pageSize : 50,
    sort: scanSortKeys.includes(params.get('sort')) ? params.get('sort') : 'date',
    direction: params.get('direction') === 'asc' ? 'asc' : 'desc',
  };
}

export function changeScanParams(params, changes) {
  const next = new URLSearchParams(params);
  if (Object.keys(changes).some(key => key !== 'page')) next.delete('page');
  for (const [key, value] of Object.entries(changes)) {
    next.delete(key);
    for (const item of Array.isArray(value) ? value : [value]) {
      if (item !== '' && item !== null && item !== undefined) next.append(key, String(item));
    }
  }
  return next;
}
