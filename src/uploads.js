import { existsSync, mkdirSync, writeFileSync, readFileSync, unlinkSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const UPLOAD_DIR = join(__dirname, '..', 'public', 'uploads');
if (!existsSync(UPLOAD_DIR)) mkdirSync(UPLOAD_DIR, { recursive: true });

const AUDIO_EXT = { 'audio/mpeg': '.mp3', 'audio/mp3': '.mp3', 'audio/wav': '.wav', 'audio/x-wav': '.wav', 'audio/ogg': '.ogg', 'audio/mp4': '.m4a', 'audio/aac': '.aac', 'audio/webm': '.webm' };
const IMAGE_EXT = { 'image/png': '.png', 'image/webp': '.webp', 'image/gif': '.gif', 'image/jpeg': '.jpg' };

const META_FILE = join(UPLOAD_DIR, 'meta.json');
let meta = { music: null, crash: null, plane: null };
try { if (existsSync(META_FILE)) meta = { ...meta, ...JSON.parse(readFileSync(META_FILE, 'utf8')) }; } catch {}

function saveMeta() {
  try { writeFileSync(META_FILE, JSON.stringify(meta)); } catch (e) { console.error('meta save failed', e.message); }
}

function removeOld(kind) {
  const cur = meta[kind];
  if (cur && cur.file) {
    const p = join(UPLOAD_DIR, cur.file);
    try { if (existsSync(p)) unlinkSync(p); } catch {}
  }
}

function readBody(req, maxBytes) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', c => {
      size += c.length;
      if (size > maxBytes) { reject(new Error('File too large')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

// ADDED: current state for fresh WebSocket connections
export function getUploadInfo() {
  return {
    audio: {
      music: meta.music ? { url: `/uploads/${meta.music.file}`, name: meta.music.name } : null,
      crash: meta.crash ? { url: `/uploads/${meta.crash.file}`, name: meta.crash.name } : null,
    },
    plane: meta.plane ? { url: `/uploads/${meta.plane.file}`, name: meta.plane.name } : null,
  };
}

export function registerUploads(app, wss, isAdmin, broadcast) {
  app.get('/api/audio/info', (req, res) => {
    res.json({
      music: meta.music ? { url: `/uploads/${meta.music.file}`, name: meta.music.name } : null,
      crash: meta.crash ? { url: `/uploads/${meta.crash.file}`, name: meta.crash.name } : null,
    });
  });

  app.get('/api/plane/info', (req, res) => {
    res.json(meta.plane ? { url: `/uploads/${meta.plane.file}`, name: meta.plane.name } : null);
  });

  async function handleAudioUpload(req, res, kind) {
    const password = decodeURIComponent(String(req.headers['x-admin-password'] || ''));
    if (!isAdmin(password)) return res.status(401).json({ error: 'unauthorized' });
    const type = String(req.headers['content-type'] || '').split(';')[0].trim();
    const ext = AUDIO_EXT[type];
    if (!ext) return res.status(400).json({ error: 'Unsupported audio type' });
    let buf;
    try { buf = await readBody(req, 15 * 1024 * 1024); }
    catch (e) { return res.status(413).json({ error: 'File too large (max 15 MB)' }); }
    if (!buf.length) return res.status(400).json({ error: 'Empty file' });
    const rawName = decodeURIComponent(String(req.headers['x-file-name'] || 'audio' + ext));
    const file = `${kind}_${Date.now()}${ext}`;
    removeOld(kind);
    writeFileSync(join(UPLOAD_DIR, file), buf);
    meta[kind] = { file, name: rawName, uploadedAt: Date.now() };
    saveMeta();
    broadcast({ type: 'audioInfo', data: {
      music: meta.music ? { url: `/uploads/${meta.music.file}`, name: meta.music.name } : null,
      crash: meta.crash ? { url: `/uploads/${meta.crash.file}`, name: meta.crash.name } : null,
    }});
    res.json({ ok: true, name: rawName });
  }

  app.post('/api/admin/audio/music', (req, res) => handleAudioUpload(req, res, 'music'));
  app.post('/api/admin/audio/crash', (req, res) => handleAudioUpload(req, res, 'crash'));

  app.delete('/api/admin/audio/:kind', (req, res) => {
    const password = decodeURIComponent(String(req.headers['x-admin-password'] || ''));
    if (!isAdmin(password)) return res.status(401).json({ error: 'unauthorized' });
    const kind = req.params.kind;
    if (!['music', 'crash'].includes(kind)) return res.status(400).json({ error: 'bad kind' });
    removeOld(kind);
    meta[kind] = null;
    saveMeta();
    broadcast({ type: 'audioInfo', data: {
      music: meta.music ? { url: `/uploads/${meta.music.file}`, name: meta.music.name } : null,
      crash: meta.crash ? { url: `/uploads/${meta.crash.file}`, name: meta.crash.name } : null,
    }});
    res.json({ ok: true });
  });

  app.post('/api/admin/plane', async (req, res) => {
    const password = decodeURIComponent(String(req.headers['x-admin-password'] || ''));
    if (!isAdmin(password)) return res.status(401).json({ error: 'unauthorized' });
    const type = String(req.headers['content-type'] || '').split(';')[0].trim();
    const ext = IMAGE_EXT[type];
    if (!ext) return res.status(400).json({ error: 'Unsupported image type' });
    let buf;
    try { buf = await readBody(req, 2 * 1024 * 1024); }
    catch (e) { return res.status(413).json({ error: 'Image too large (max 2 MB)' }); }
    if (!buf.length) return res.status(400).json({ error: 'Empty file' });
    const rawName = decodeURIComponent(String(req.headers['x-file-name'] || 'plane' + ext));
    const file = `plane_${Date.now()}${ext}`;
    removeOld('plane');
    writeFileSync(join(UPLOAD_DIR, file), buf);
    meta.plane = { file, name: rawName, uploadedAt: Date.now() };
    saveMeta();
    broadcast({ type: 'planeInfo', data: { url: `/uploads/${meta.plane.file}`, name: meta.plane.name } });
    res.json({ ok: true, name: rawName });
  });

  app.delete('/api/admin/plane', (req, res) => {
    const password = decodeURIComponent(String(req.headers['x-admin-password'] || ''));
    if (!isAdmin(password)) return res.status(401).json({ error: 'unauthorized' });
    removeOld('plane');
    meta.plane = null;
    saveMeta();
    broadcast({ type: 'planeInfo', data: null });
    res.json({ ok: true });
  });
}