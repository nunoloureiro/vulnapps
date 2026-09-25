export function searchableFilterOptions(options, query, allLabel) {
  const search = query.trim().toLocaleLowerCase();
  if (!search) return [{ value: '', label: allLabel }, ...options];
  return options.filter((option) => String(option.label).toLocaleLowerCase().includes(search));
}
