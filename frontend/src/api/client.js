const API_BASE = '/api';

let onUnauthorized = null;

function getToken() {
  return localStorage.getItem('token');
}

function setToken(token) {
  if (token) localStorage.setItem('token', token);
  else localStorage.removeItem('token');
}

async function request(method, path, body = null, options = {}) {
  const headers = {};
  const token = getToken();
  if (token) headers['Authorization'] = `Bearer ${token}`;

  const fetchOptions = { method, headers };

  if (body && !(body instanceof FormData)) {
    headers['Content-Type'] = 'application/json';
    fetchOptions.body = JSON.stringify(body);
  } else if (body) {
    fetchOptions.body = body;
  }

  const response = await fetch(`${API_BASE}${path}`, fetchOptions);

  if (response.status === 401) {
    if (!options.noRedirect) {
      setToken(null);
      onUnauthorized?.();
    }
    throw new Error('Unauthorized');
  }

  if (!response.ok) {
    const data = await response.json().catch(() => ({}));
    throw new Error(data.detail || `Request failed: ${response.status}`);
  }

  if (response.status === 204) return {};
  return response.json();
}

async function download(path, fallbackFilename = 'download') {
  const headers = {};
  const token = getToken();
  if (token) headers['Authorization'] = `Bearer ${token}`;
  const response = await fetch(`${API_BASE}${path}`, { method: 'GET', headers });
  if (response.status === 401) {
    setToken(null);
    onUnauthorized?.();
    throw new Error('Unauthorized');
  }
  if (!response.ok) {
    throw new Error(`Download failed: ${response.status}`);
  }
  // Try to extract filename from Content-Disposition; fall back to provided name.
  let filename = fallbackFilename;
  const cd = response.headers.get('Content-Disposition');
  if (cd) {
    const m = /filename\*?=(?:UTF-8'')?"?([^";]+)/i.exec(cd);
    if (m) filename = decodeURIComponent(m[1]);
  }
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export const api = {
  get: (path, options) => request('GET', path, null, options),
  post: (path, body, options) => request('POST', path, body, options),
  put: (path, body, options) => request('PUT', path, body, options),
  del: (path, options) => request('DELETE', path, null, options),
  download,
  getToken,
  setToken,
  setOnUnauthorized: (cb) => { onUnauthorized = cb; },
};
