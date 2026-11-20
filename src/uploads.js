import { existsSync, mkdirSync, writeFileSync, readFileSync, unlinkSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const UPLOAD_DIR = join(__dirname, '..', 'public', 'uploads');
if (!existsSync(UPLOAD_DIR)) mkdirSync(UPLOAD_DIR, { recursive: true });

const AUDIO_EXT = { 'audio/mpeg': '.mp3', 'audio/mp3': '.mp3', 'audio/wav': '.wav', 'audio/x-wav': '.wav', 'audio/ogg': '.ogg', 'audio/mp4': '.m4a', 'audio/aac': '.aac', 'audio/webm': '.webm' };
const IMAGE_EXT = { 'image/png': '.png', 'image/webp': '.webp', 'image/gif': '.gif', 'image/jpeg': '.jpg' };

const META_FILE = join(UPLOAD_DIR, 'meta.json');

// NEW: Array-based library structure with migration support for old single-file format
let meta = { music: [], crash: [], plane: [] };
try { 
  if (existsSync(META_FILE)) {
    const oldMeta = JSON.parse(readFileSync(META_FILE, 'utf8'));
    
    // Migrate old format if it exists
    if (oldMeta.music && typeof oldMeta.music === 'object' && !Array.isArray(oldMeta.music)) {
      meta.music = [{ ...oldMeta.music, id: 'music_' + Date.now(), isActive: true }];
    } else if (Array.isArray(oldMeta.music)) { meta.music = oldMeta.music; }
    
    if (oldMeta.crash && typeof oldMeta.crash === 'object' && !Array.isArray(oldMeta.crash)) {
      meta.crash = [{ ...oldMeta.crash, id: 'crash_' + Date.now(), isActive: true }];
    } else if (Array.isArray(oldMeta.crash)) { meta.crash = oldMeta.crash; }
    
    if (oldMeta.plane && typeof oldMeta.plane === 'object' && !Array.isArray(oldMeta.plane)) {
      meta.plane = [{ ...oldMeta.plane, id: 'plane_' + Date.now(), isActive: true }];
    } else if (Array.isArray(oldMeta.plane)) { meta.plane = oldMeta.plane; }
  }
} catch {}

function saveMeta() {
  try { writeFileSync(META_FILE, JSON.stringify(meta)); } catch (e) { console.error('meta save failed', e.message); }
}

function getActive(kind) {
  return meta[kind].find(item => item.isActive) || null;
}

function deactivateCurrent(kind) {
  meta[kind].forEach(item => { item.isActive = false; });
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

export function getUploadInfo() {
  const activeMusic = getActive('music');
  const activeCrash = getActive('crash');
  const activePlane = getActive('plane');
  return {
    audio: {
      music: activeMusic ? { url: `/uploads/${activeMusic.file}`, name: activeMusic.name } : null,
      crash: activeCrash ? { url: `/uploads/${activeCrash.file}`, name: activeCrash.name } : null,
    },
    plane: activePlane ? { url: `/uploads/${activePlane.file}`, name: activePlane.name } : null,
  };
}

export function registerUploads(app, wss, isAdmin, broadcast) {
  app.get('/api/audio/info', (req, res) => {
    const activeMusic = getActive('music');
    const activeCrash = getActive('crash');
    res.json({
      music: activeMusic ? { url: `/uploads/${activeMusic.file}`, name: activeMusic.name } : null,
      crash: activeCrash ? { url: `/uploads/${activeCrash.file}`, name: activeCrash.name } : null,
    });
  });

  app.get('/api/plane/info', (req, res) => {
    const activePlane = getActive('plane');
    res.json(activePlane ? { url: `/uploads/${activePlane.file}`, name: activePlane.name } : null);
  });

  // --- NEW: Media Library Endpoints ---

  // Get library for a specific kind
  app.get('/api/admin/media/:kind', (req, res) => {
    const password = decodeURIComponent(String(req.headers['x-admin-password'] || ''));
    if (!isAdmin(password)) return res.status(401).json({ error: 'unauthorized' });
    const kind = req.params.kind;
    if (!['music', 'crash', 'plane'].includes(kind)) return res.status(400).json({ error: 'bad kind' });
    res.json({ items: meta[kind] });
  });

  // Set a specific file as active
  app.post('/api/admin/media/:kind/:id/activate', (req, res) => {
    const password = decodeURIComponent(String(req.headers['x-admin-password'] || ''));
    if (!isAdmin(password)) return res.status(401).json({ error: 'unauthorized' });
    const kind = req.params.kind;
    const id = req.params.id;
    if (!['music', 'crash', 'plane'].includes(kind)) return res.status(400).json({ error: 'bad kind' });
    
    const item = meta[kind].find(i => i.id === id);
    if (!item) return res.status(404).json({ error: 'not found' });

    deactivateCurrent(kind);
    item.isActive = true;
    saveMeta();

    if (kind === 'plane') {
      broadcast({ type: 'planeInfo', data: { url: `/uploads/${item.file}`, name: item.name } });
    } else {
      broadcast({ type: 'audioInfo', data: {
        music: getActive('music') ? { url: `/uploads/${getActive('music').file}`, name: getActive('music').name } : null,
        crash: getActive('crash') ? { url: `/uploads/${getActive('crash').file}`, name: getActive('crash').name } : null,
      }});
    }
    res.json({ ok: true });
  });

  // Permanently delete a file
  app.delete('/api/admin/media/:kind/:id', (req, res) => {
    const password = decodeURIComponent(String(req.headers['x-admin-password'] || ''));
    if (!isAdmin(password)) return res.status(401).json({ error: 'unauthorized' });
    const kind = req.params.kind;
    const id = req.params.id;
    if (!['music', 'crash', 'plane'].includes(kind)) return res.status(400).json({ error: 'bad kind' });
    
    const idx = meta[kind].findIndex(i => i.id === id);
    if (idx === -1) return res.status(404).json({ error: 'not found' });

    const item = meta[kind][idx];
    const wasActive = item.isActive;
    
    const p = join(UPLOAD_DIR, item.file);
    try { if (existsSync(p)) unlinkSync(p); } catch {}

    meta[kind].splice(idx, 1);
    saveMeta();

    if (wasActive) {
      if (kind === 'plane') {
        broadcast({ type: 'planeInfo', data: null });
      } else {
        broadcast({ type: 'audioInfo', data: {
          music: getActive('music') ? { url: `/uploads/${getActive('music').file}`, name: getActive('music').name } : null,
          crash: getActive('crash') ? { url: `/uploads/${getActive('crash').file}`, name: getActive('crash').name } : null,
        }});
      }
    }
    res.json({ ok: true });
  });

  // --- Upload Handlers ---

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
    const id = `${kind}_${Date.now()}`;
    const file = `${id}${ext}`;
    
    deactivateCurrent(kind); // Don't delete, just deactivate
    writeFileSync(join(UPLOAD_DIR, file), buf);
    
    meta[kind].push({ id, file, name: rawName, uploadedAt: Date.now(), isActive: true });
    saveMeta();
    
    broadcast({ type: 'audioInfo', data: {
      music: getActive('music') ? { url: `/uploads/${getActive('music').file}`, name: getActive('music').name } : null,
      crash: getActive('crash') ? { url: `/uploads/${getActive('crash').file}`, name: getActive('crash').name } : null,
    }});
    res.json({ ok: true, name: rawName });
  }

  app.post('/api/admin/audio/music', (req, res) => handleAudioUpload(req, res, 'music'));
  app.post('/api/admin/audio/crash', (req, res) => handleAudioUpload(req, res, 'crash'));

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
    const id = `plane_${Date.now()}`;
    const file = `${id}${ext}`;
    
    deactivateCurrent('plane'); // Don't delete, just deactivate
    writeFileSync(join(UPLOAD_DIR, file), buf);
    
    meta.plane.push({ id, file, name: rawName, uploadedAt: Date.now(), isActive: true });
    saveMeta();
    
    broadcast({ type: 'planeInfo', data: { url: `/uploads/${meta.plane.find(i => i.isActive).file}`, name: rawName } });
    res.json({ ok: true, name: rawName });
  });
}