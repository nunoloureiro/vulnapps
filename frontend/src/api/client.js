const API_BASE = '/api';

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
      window.location.href = '/login';
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

export const api = {
  get: (path, options) => request('GET', path, null, options),
  post: (path, body, options) => request('POST', path, body, options),
  put: (path, body, options) => request('PUT', path, body, options),
  del: (path, options) => request('DELETE', path, null, options),
  getToken,
  setToken,
};
