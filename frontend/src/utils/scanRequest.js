export const initialScanRequest = { key: null, id: 0, status: 'loading', data: null, error: '' };

export function scanRequestReducer(state, action) {
  if (action.type === 'start') {
    return { ...state, key: action.key, id: action.id, status: 'loading', error: '' };
  }
  if (action.id !== state.id || action.key !== state.key) return state;
  if (action.type === 'success') {
    return { ...state, status: 'success', data: action.data, error: '' };
  }
  if (action.type === 'failure') {
    return { ...state, status: 'error', data: null, error: action.error };
  }
  return state;
}

export function scanResultForKey(state, key) {
  if (state.key !== key || state.status === 'loading') return { loading: true, data: null, error: '' };
  return { loading: false, data: state.data, error: state.error };
}
