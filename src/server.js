const http = require('http');
const path = require('path');
const fs = require('fs');
const url = require('url');
const crypto = require('crypto');

loadEnvFile();

const PORT = process.env.PORT ? Number(process.env.PORT) : 3000;
const CLIENT_ID = process.env.SPOTIFY_CLIENT_ID || '';
const CLIENT_SECRET = process.env.SPOTIFY_CLIENT_SECRET || '';
const REDIRECT_URI = process.env.SPOTIFY_REDIRECT_URI || `http://localhost:${PORT}/callback`;
const SCOPES = (process.env.SPOTIFY_SCOPES || 'user-read-email user-read-private user-read-playback-state user-read-currently-playing user-top-read playlist-read-private')
  .split(/\s+/)
  .filter(Boolean);
const SESSION_SECRET = process.env.SESSION_SECRET || 'session-secret';

const sessionStore = new Map();
const cookieName = 'spotify_session';

const server = http.createServer(async (req, res) => {
  const parsedUrl = new url.URL(req.url, `http://${req.headers.host}`);
  const { pathname } = parsedUrl;

  if (pathname === '/login') {
    return handleLogin(req, res);
  }

  if (pathname === '/callback') {
    return handleCallback(req, res, parsedUrl.searchParams);
  }

  if (pathname === '/logout') {
    return handleLogout(req, res);
  }

  if (pathname.startsWith('/api/')) {
    return handleApiRoute(req, res, pathname);
  }

  return serveStatic(req, res, pathname);
});

function loadEnvFile() {
  const envPath = path.join(process.cwd(), '.env');
  if (!fs.existsSync(envPath)) {
    return;
  }

  const content = fs.readFileSync(envPath, 'utf-8');
  content
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith('#'))
    .forEach((line) => {
      const [key, ...rest] = line.split('=');
      const value = rest.join('=').trim();
      if (!process.env[key]) {
        process.env[key] = value;
      }
    });
}

function parseCookies(req) {
  const header = req.headers.cookie;
  if (!header) return {};
  return header.split(';').reduce((acc, part) => {
    const [key, value] = part.trim().split('=');
    acc[key] = decodeURIComponent(value);
    return acc;
  }, {});
}

function signSessionId(sessionId) {
  return crypto.createHmac('sha256', SESSION_SECRET).update(sessionId).digest('hex');
}

function validateSessionCookie(cookieValue) {
  if (!cookieValue) return null;
  const [sessionId, signature] = cookieValue.split('.');
  if (!sessionId || !signature) return null;
  const expected = signSessionId(sessionId);
  return expected === signature ? sessionId : null;
}

function setSessionCookie(res, sessionId) {
  const signature = signSessionId(sessionId);
  const serialized = `${cookieName}=${sessionId}.${signature}; HttpOnly; Path=/; SameSite=Lax`;
  res.setHeader('Set-Cookie', serialized);
}

function getOrCreateSession(req, res) {
  const cookies = parseCookies(req);
  let sessionId = validateSessionCookie(cookies[cookieName]);

  if (sessionId && sessionStore.has(sessionId)) {
    return sessionStore.get(sessionId);
  }

  sessionId = crypto.randomBytes(24).toString('hex');
  const session = { id: sessionId, tokens: null, state: null };
  sessionStore.set(sessionId, session);
  setSessionCookie(res, sessionId);
  return session;
}

function handleLogin(req, res) {
  if (!CLIENT_ID || !CLIENT_SECRET) {
    return sendJson(res, 500, { error: 'Spotify Client ID/Secret sind nicht konfiguriert.' });
  }

  const session = getOrCreateSession(req, res);
  const state = crypto.randomBytes(16).toString('hex');
  session.state = state;

  const authorizeUrl = new url.URL('https://accounts.spotify.com/authorize');
  authorizeUrl.searchParams.set('client_id', CLIENT_ID);
  authorizeUrl.searchParams.set('response_type', 'code');
  authorizeUrl.searchParams.set('redirect_uri', REDIRECT_URI);
  authorizeUrl.searchParams.set('scope', SCOPES.join(' '));
  authorizeUrl.searchParams.set('state', state);

  redirect(res, authorizeUrl.toString());
}

async function handleCallback(req, res, searchParams) {
  const session = getOrCreateSession(req, res);
  const code = searchParams.get('code');
  const state = searchParams.get('state');

  if (!code || !state || state !== session.state) {
    return sendJson(res, 400, { error: 'Invalid OAuth state or missing code' });
  }

  try {
    const tokenData = await exchangeCodeForTokens(code);
    session.tokens = formatTokenData(tokenData);
    session.state = null;
    redirect(res, '/');
  } catch (error) {
    console.error('Callback error', error);
    sendJson(res, 500, { error: 'Failed to complete Spotify authentication' });
  }
}

function handleLogout(req, res) {
  const cookies = parseCookies(req);
  const sessionId = validateSessionCookie(cookies[cookieName]);
  if (sessionId) {
    sessionStore.delete(sessionId);
  }
  res.setHeader('Set-Cookie', `${cookieName}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax`);
  redirect(res, '/');
}

async function handleApiRoute(req, res, pathname) {
  const session = getOrCreateSession(req, res);
  if (!session.tokens) {
    return sendJson(res, 401, { error: 'User is not authenticated with Spotify.' });
  }

  try {
    switch (pathname) {
      case '/api/me':
        return sendJson(res, 200, await getProfile(session));
      case '/api/currently-playing':
        return await handleCurrentlyPlaying(res, session);
      case '/api/top-tracks':
        return sendJson(res, 200, await getTopTracks(session));
      case '/api/top-artists':
        return sendJson(res, 200, await getTopArtists(session));
      case '/api/playlists':
        return sendJson(res, 200, await getPlaylists(session));
      default:
        return sendJson(res, 404, { error: 'Endpoint not found' });
    }
  } catch (error) {
    console.error('API error', error);
    sendJson(res, 500, { error: 'Unexpected error occurred while contacting Spotify.' });
  }
}

async function handleCurrentlyPlaying(res, session) {
  const response = await spotifyRequest(session, 'https://api.spotify.com/v1/me/player/currently-playing');
  if (response.status === 204) {
    return sendJson(res, 200, { isPlaying: false });
  }

  const payload = await response.json();
  if (!payload || !payload.item) {
    return sendJson(res, 200, { isPlaying: false });
  }

  const item = payload.item;
  const artists = (item.artists || []).map((artist) => artist.name).join(', ');
  const image = item.album?.images?.[0]?.url || null;
  const progressMs = payload.progress_ms || 0;
  const durationMs = item.duration_ms || 0;

  return sendJson(res, 200, {
    isPlaying: payload.is_playing,
    title: item.name,
    artists,
    album: item.album?.name || '',
    image,
    progressMs,
    durationMs,
  });
}

async function getProfile(session) {
  const response = await spotifyRequest(session, 'https://api.spotify.com/v1/me');
  const data = await response.json();
  return {
    displayName: data.display_name,
    email: data.email,
    images: data.images || [],
  };
}

async function getTopTracks(session) {
  const response = await spotifyRequest(
    session,
    'https://api.spotify.com/v1/me/top/tracks?limit=10&time_range=short_term'
  );
  const data = await response.json();
  return (data.items || []).map((track) => ({
    name: track.name,
    artists: (track.artists || []).map((artist) => artist.name).join(', '),
    album: track.album?.name || '',
    image: track.album?.images?.[0]?.url || null,
    url: track.external_urls?.spotify || null,
  }));
}

async function getTopArtists(session) {
  const response = await spotifyRequest(
    session,
    'https://api.spotify.com/v1/me/top/artists?limit=10&time_range=short_term'
  );
  const data = await response.json();
  return (data.items || []).map((artist) => ({
    name: artist.name,
    genres: artist.genres || [],
    image: artist.images?.[0]?.url || null,
    url: artist.external_urls?.spotify || null,
  }));
}

async function getPlaylists(session) {
  const response = await spotifyRequest(session, 'https://api.spotify.com/v1/me/playlists?limit=20');
  const data = await response.json();
  return (data.items || []).map((playlist) => ({
    name: playlist.name,
    trackCount: playlist.tracks?.total || 0,
    image: playlist.images?.[0]?.url || null,
    url: playlist.external_urls?.spotify || null,
    owner: playlist.owner?.display_name || '',
  }));
}

async function spotifyRequest(session, endpoint) {
  await ensureAccessToken(session);
  let response = await fetch(endpoint, {
    headers: { Authorization: `Bearer ${session.tokens.accessToken}` },
  });

  if (response.status === 401 || response.status === 403) {
    const refreshed = await refreshAccessToken(session);
    if (!refreshed) {
      throw new Error('Unable to refresh access token');
    }
    response = await fetch(endpoint, {
      headers: { Authorization: `Bearer ${session.tokens.accessToken}` },
    });
  }

  return response;
}

async function ensureAccessToken(session) {
  if (!session.tokens) {
    throw new Error('Missing access token');
  }

  if (Date.now() >= session.tokens.expiresAt - 60000) {
    await refreshAccessToken(session);
  }
}

async function refreshAccessToken(session) {
  if (!session.tokens || !session.tokens.refreshToken) {
    return false;
  }

  const tokenUrl = 'https://accounts.spotify.com/api/token';
  const body = new url.URLSearchParams({
    grant_type: 'refresh_token',
    refresh_token: session.tokens.refreshToken,
  });

  const response = await fetch(tokenUrl, {
    method: 'POST',
    headers: {
      Authorization: 'Basic ' + Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64'),
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body,
  });

  if (!response.ok) {
    throw new Error('Failed to refresh access token');
  }

  const data = await response.json();
  const updated = formatTokenData({
    access_token: data.access_token,
    refresh_token: data.refresh_token || session.tokens.refreshToken,
    expires_in: data.expires_in,
  });
  session.tokens = updated;
  return true;
}

async function exchangeCodeForTokens(code) {
  const tokenUrl = 'https://accounts.spotify.com/api/token';
  const body = new url.URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: REDIRECT_URI,
  });

  const response = await fetch(tokenUrl, {
    method: 'POST',
    headers: {
      Authorization: 'Basic ' + Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64'),
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body,
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Token exchange failed: ${response.status} ${errorText}`);
  }

  return response.json();
}

function formatTokenData(data) {
  const expiresAt = Date.now() + (data.expires_in || 3600) * 1000;
  return {
    accessToken: data.access_token,
    refreshToken: data.refresh_token,
    expiresAt,
  };
}

function serveStatic(req, res, pathname) {
  let filePath = path.join(process.cwd(), 'public', pathname === '/' ? 'index.html' : pathname);
  if (filePath.endsWith('/')) {
    filePath = path.join(filePath, 'index.html');
  }

  if (!filePath.startsWith(path.join(process.cwd(), 'public'))) {
    return sendJson(res, 403, { error: 'Forbidden' });
  }

  fs.readFile(filePath, (err, data) => {
    if (err) {
      return sendJson(res, 404, { error: 'Not found' });
    }

    const ext = path.extname(filePath).toLowerCase();
    const contentType = getContentType(ext);
    res.writeHead(200, { 'Content-Type': contentType });
    res.end(data);
  });
}

function getContentType(ext) {
  switch (ext) {
    case '.html':
      return 'text/html; charset=utf-8';
    case '.css':
      return 'text/css';
    case '.js':
      return 'application/javascript';
    case '.json':
      return 'application/json';
    case '.png':
      return 'image/png';
    case '.jpg':
    case '.jpeg':
      return 'image/jpeg';
    default:
      return 'text/plain';
  }
}

function redirect(res, location) {
  res.writeHead(302, { Location: location });
  res.end();
}

function sendJson(res, statusCode, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json',
  });
  res.end(body);
}

server.listen(PORT, () => {
  console.log(`Server listening on http://localhost:${PORT}`);
});
