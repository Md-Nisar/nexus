import http from 'k6/http';
import { config } from '../config/environment.js';

/**
 * Thin wrappers over k6/http that resolve paths against BASE_URL and tag every request with a
 * stable `name`, so metrics group per endpoint rather than per full URL. Pass
 * `{ tags: { name: '/api/v1/things/{id}' } }` for paths that contain ids.
 */

export function get(path, params = {}) {
  return http.get(`${config.baseUrl}${path}`, withName(path, params));
}

export function postJson(path, body, params = {}) {
  const named = withName(path, params);
  return http.post(`${config.baseUrl}${path}`, JSON.stringify(body), {
    ...named,
    headers: { 'Content-Type': 'application/json', ...named.headers },
  });
}

function withName(path, params) {
  return { ...params, tags: { name: path, ...params.tags } };
}
