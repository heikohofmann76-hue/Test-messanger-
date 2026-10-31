# Krypto-Messenger (MVP)

Ein Ende-zu-Ende-verschlüsselter Messenger als Web-App (PWA) mit WhatsApp-ähnlichen Funktionen.
Läuft im Browser auf PC, Android und iPhone und lässt sich wie eine App installieren.

## Starten

Voraussetzung: [Node.js](https://nodejs.org) ab Version 18.

```bash
cd messenger
npm install
npm start
```

Dann im Browser **http://localhost:3000** öffnen. Zum Ausprobieren ein zweites Fenster im
privaten Modus öffnen (eigener Schlüsselspeicher) und dort ein zweites Konto anlegen.

Andere Geräte im WLAN erreichen die App über `http://<IP-deines-PCs>:3000`.
Mikrofon (Sprachnachrichten) und „App installieren“ funktionieren auf Handys nur über **HTTPS**,
z. B. hinter einem Reverse-Proxy wie Caddy oder über einen Hoster (Render, Fly.io, eigener Server).

## Funktionen

- Einzelchats und Gruppen
- Text, Emojis, Fotos, Dateien (bis 25 MB), Sprachnachrichten
- Antworten auf Nachrichten, Löschen für mich / für alle, Kopieren
- Häkchen: 🕓 wird gesendet · ✓ gesendet · ✓✓ zugestellt · blaue ✓✓ gelesen
- „schreibt…“-Anzeige, online / zuletzt online
- Status (Stories) für 24 Stunden, Text auf Farbe oder Foto
- Ungelesen-Zähler, Suche, Browser-Benachrichtigungen
- Hell- und Dunkelmodus, Handy- und Desktop-Layout
- Offline-Zustellung: der Server hält verschlüsselte Nachrichten, bis der Empfänger online ist
- Sicherheitsnummer zum Prüfen der Verschlüsselung, Warnung bei Schlüsselwechsel

## Verschlüsselung

Die App nutzt ein Signal-artiges Protokoll (`public/signal.js`), umgesetzt mit WebCrypto:

- **Identität:** Jedes Gerät erzeugt beim ersten Start einen Identitätsschlüssel (ECDH P-256) und
  einen Signaturschlüssel (ECDSA). Die privaten Schlüssel sind nicht exportierbar und liegen nur in
  der IndexedDB des Browsers.
- **Sitzungsaufbau (X3DH):** Jeder Nutzer legt beim Server einen signierten Prekey und einen Vorrat
  Einmal-Prekeys ab. Wer eine Sitzung startet, holt sich ein Prekey-Bundle und leitet daraus einen
  gemeinsamen Startschlüssel ab, ohne dass die Gegenseite online sein muss.
- **Double Ratchet:** Bei jedem Sprecherwechsel ein neuer DH-Schlüssel, für jede Nachricht ein neuer
  Schlüssel (AES-256-GCM). Alte Schlüssel werden verworfen. Das bringt **Forward Secrecy** (ein
  geknackter Schlüssel gibt keine alten Nachrichten preis) und **Post-Compromise Security** (nach
  einem Leck wird die Sitzung von selbst wieder sicher). Nachrichten außer der Reihe funktionieren.
- **Gruppen:** die Nachricht wird für jedes Mitglied einzeln über dessen Sitzung verschlüsselt.
- Der Server sieht nur, wer wem wann wie viel schickt. Keinen Inhalt, keine Medien, keinen Status.

Unterschied zum echten Signal-Protokoll: P-256 statt Curve25519 (in allen Browsern ohne Bibliothek
verfügbar) und AES-GCM statt AES-CBC+HMAC. Die Krypto-Logik ist mit einer Testreihe abgedeckt
(beide Richtungen, vertauschte Reihenfolge, abgelehnte Wiederholung, erkannte Manipulation).

**Ehrliche Grenzen des MVP:** kein Multi-Device, keine Anrufe und kein verschlüsseltes Backup. Wer die
Browserdaten löscht, verliert das Konto auf dem Gerät. Nächste sinnvolle Schritte: Multi-Device und
ein Matrix-Gateway nach außen.

## Anbindung an WhatsApp, iMessage und andere Messenger

| Ziel | Weg | Status |
|---|---|---|
| WhatsApp | EU-DMA „Drittanbieter-Chats“ (Vertrag mit Meta, Signal-kompatible Verschlüsselung) | offiziell, nur EU, Antrag nötig |
| iPhone | RCS (seit iOS 26.5 Ende-zu-Ende-verschlüsselt mit MLS), über RCS-Business-Anbieter | offiziell, kostenpflichtig |
| iMessage direkt | keine offene Schnittstelle | nicht offiziell möglich |
| Telegram, Signal, Discord, Slack u. a. | Matrix-Protokoll + Bridges | technisch möglich |
| WhatsApp/iMessage per Bridge | mautrix-whatsapp, BlueBubbles | inoffiziell, verstößt gegen Nutzungsbedingungen, Sperrrisiko, Bridge sieht Klartext |

Empfehlung: als Nächstes ein Matrix-Gateway einbauen (für die offenen Messenger) und parallel den
DMA-Zugang bei Meta beantragen, sobald es ein Unternehmen hinter der App gibt.

## Aufbau

```
server.js          Relay-Server (HTTP + WebSocket), speichert in data.json
public/index.html  Oberfläche
public/style.css   Design (hell/dunkel, mobil)
public/app.js      Client: Krypto, Speicher, Chat-Logik
public/sw.js       Service Worker (installierbar)
```
