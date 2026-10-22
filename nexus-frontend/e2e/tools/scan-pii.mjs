#!/usr/bin/env node
/**
 * Fails when any scanned file contains a persona email address or its blind index (US-019 T-027,
 * RC-63(h)), in raw, URL-encoded (`%40`), JSON-escaped (`\u0040`) or HTML-entity form, or a
 * generated `e2e-<timestamp>@example.com` registrant address. Zip archives (Playwright traces)
 * and every base64 zip embedded in the HTML report are opened and scanned too.
 *
 * Screenshots cannot be text-scanned (the shell header shows the signed-in address), so any
 * PNG/JPEG file in the scanned set fails the scan: CI runs with `screenshot: 'off'`.
 *
 * Usage: node scan-pii.mjs --hmac-key-from <application-dev.yml> <file-or-dir>...
 *        node scan-pii.mjs --hmac-key <key> <file-or-dir>...
 */
import { createHmac } from 'node:crypto';
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { inflateRawSync } from 'node:zlib';

/** Same normalisation as EmailBlindIndexService: trim, NFC, lower-case. */
export function blindIndex(email, key) {
  const normalised = email.trim().normalize('NFC').toLowerCase();
  return createHmac('sha256', key).update(normalised, 'utf8').digest('hex');
}

export function hmacKeyFromYaml(text) {
  const match = /^\s*hmac-key:\s*(\S+)\s*$/m.exec(text);
  if (!match) throw new Error('hmac-key not found');
  return match[1];
}

/** Entries of a zip archive (stored or deflated), read from the central directory. */
export function zipEntries(buffer) {
  const eocd = buffer.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
  if (eocd < 0) return [];
  const count = buffer.readUInt16LE(eocd + 10);
  let offset = buffer.readUInt32LE(eocd + 16);
  const entries = [];
  for (let i = 0; i < count; i += 1) {
    const method = buffer.readUInt16LE(offset + 10);
    const size = buffer.readUInt32LE(offset + 20);
    const nameLength = buffer.readUInt16LE(offset + 28);
    const extraLength = buffer.readUInt16LE(offset + 30);
    const commentLength = buffer.readUInt16LE(offset + 32);
    const local = buffer.readUInt32LE(offset + 42);
    const name = buffer.toString('utf8', offset + 46, offset + 46 + nameLength);
    const start = local + 30 + buffer.readUInt16LE(local + 26) + buffer.readUInt16LE(local + 28);
    const raw = buffer.subarray(start, start + size);
    entries.push({ name, data: method === 8 ? inflateRawSync(raw) : raw });
    offset += 46 + nameLength + extraLength + commentLength;
  }
  return entries;
}

function* contents(label, buffer) {
  yield { label, text: buffer.toString('latin1') };
  if (buffer.subarray(0, 2).toString('latin1') === 'PK') {
    for (const entry of zipEntries(buffer)) yield* contents(`${label}!${entry.name}`, entry.data);
  }
  const embedded = buffer
    .toString('latin1')
    .matchAll(/data:application\/zip;base64,([A-Za-z0-9+/=]+)/g);
  let index = 0;
  for (const match of embedded) {
    yield* contents(`${label}!report${index}`, Buffer.from(match[1], 'base64'));
    index += 1;
  }
}

function* files(path) {
  if (statSync(path).isDirectory()) {
    for (const name of readdirSync(path)) yield* files(join(path, name));
  } else {
    yield path;
  }
}

const IMAGE = /\.(png|jpe?g)$/i;

/**
 * `onHit({ label, kind, before, after })` is optional and receives the text around a plain-value
 * match (the match itself is never passed on) so a failing CI run says where the address is.
 */
export function scan(paths, needles, onHit) {
  const hits = [];
  for (const path of paths) {
    for (const file of files(path)) {
      if (IMAGE.test(file)) hits.push(`screenshot found in ${file}`);
      for (const { label, text } of contents(file, readFileSync(file))) {
        const lower = text.toLowerCase();
        for (const { kind, value, pattern } of needles) {
          if (value ? lower.includes(value) : pattern.test(text)) {
            hits.push(`${kind} found in ${label}`);
            const at = value ? lower.indexOf(value) : -1;
            if (onHit && at >= 0) {
              onHit({
                label,
                kind,
                before: text.slice(Math.max(0, at - 80), at),
                after: text.slice(at + value.length, at + value.length + 20),
              });
            }
          }
        }
      }
    }
  }
  return hits;
}

/** The `@` as it appears raw, URL-encoded (also double-encoded), JSON-escaped or as an entity. */
const AT_FORMS = ['@', '%40', '%2540', '\\u0040', '&#64;', '&#x40;', '&commat;'];

/** Registrants created by the registration spec: `e2e-<Date.now()>@example.com`. */
const REGISTRANT = {
  kind: 'generated registrant address',
  pattern: new RegExp(`e2e-\\d+(?:${AT_FORMS.map(escapeRegExp).join('|')})example\\.com`, 'i'),
};

function escapeRegExp(text) {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

export function needlesFor(emails, key) {
  return [
    ...emails.flatMap((email) => {
      const [local, domain] = email.toLowerCase().split('@');
      return [
        ...AT_FORMS.map((at) => ({ kind: 'email address', value: `${local}${at}${domain}` })),
        { kind: 'email blind index', value: blindIndex(email, key) },
      ];
    }),
    REGISTRANT,
  ];
}

async function main(argv) {
  const [keyFlag, keySource, ...paths] = argv;
  if (!['--hmac-key', '--hmac-key-from'].includes(keyFlag) || !keySource || paths.length === 0) {
    console.error('Usage: scan-pii.mjs --hmac-key <key> | --hmac-key-from <yml> <path>...');
    return 2;
  }
  const key =
    keyFlag === '--hmac-key' ? keySource : hmacKeyFromYaml(readFileSync(keySource, 'utf8'));
  const { PERSONAS } = await import('../fixtures/personas.ts');
  const existing = paths.filter((path) => existsSync(path));
  const missing = paths.filter((path) => !existsSync(path));
  if (missing.length > 0) {
    console.error(`Nothing to scan at: ${missing.join(', ')}`);
    return 2;
  }
  const emails = Object.values(PERSONAS).map((persona) => persona.email);
  const hits = scan(existing, needlesFor(emails, key), ({ label, before, after }) =>
    console.error(`  near ${label}: ${JSON.stringify(before)} <match> ${JSON.stringify(after)}`),
  );
  if (hits.length > 0) {
    for (const hit of new Set(hits)) console.error(hit);
    return 1;
  }
  console.log(`No persona email or blind index in ${existing.length} scanned path(s).`);
  return 0;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  process.exitCode = await main(process.argv.slice(2));
}
