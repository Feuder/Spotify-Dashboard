# Spotify Dashboard

Ein einfaches Fullstack-Beispiel, das nach dem Spotify-Login dein Profil, aktuell laufenden Track, Top-Tracks/-Artists und Playlists abruft. Das Backend nutzt nur Node.js-Bordmittel (kein Express) und stellt REST-Endpunkte bereit, die von einer kleinen statischen Frontend-Seite konsumiert werden.

## Vorbereitung
1. Lege in deinem [Spotify Developer Dashboard](https://developer.spotify.com) eine App an.
2. Trage eine Redirect-URI ein, z. B. `http://localhost:3000/callback`.
3. Kopiere die Datei `.env.example` zu `.env` und befülle sie mit deiner Client-ID, deinem Client-Secret sowie einem eigenen `SESSION_SECRET`.

## Starten
```bash
npm install   # entfällt, es werden keine externen Pakete genutzt
npm start
```
Die Anwendung läuft anschließend unter `http://localhost:3000`.

## Endpunkte
- `GET /login` startet den OAuth-Flow und leitet zu Spotify weiter.
- `GET /callback` tauscht den Code gegen Token und legt sie in einer einfachen In-Memory-Session ab.
- `GET /api/me` liefert Profilinformationen.
- `GET /api/currently-playing` liefert den aktuell laufenden Track oder einen leeren Zustand.
- `GET /api/top-tracks`, `GET /api/top-artists`, `GET /api/playlists` liefern die Daten für das Dashboard.

## Hinweise
- Die Tokens werden in einem In-Memory-Store gehalten. Für Produktion sollte ein persistentes Backend (z. B. Datenbank oder Redis) genutzt werden.
- Das Frontend zeigt verständliche Fehler-/Leermeldungen, falls kein Login vorliegt oder Spotify keine Daten liefert.
- Für produktive Umgebungen sollte HTTPS verwendet werden und das Session-Cookie entsprechend konfiguriert werden.
