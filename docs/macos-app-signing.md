Perfekt — so startest du auf einem deutschen macOS, um in deinem Apple-Developer-Account eine zweite Developer-ID-Signatur zu erstellen.

Auf dem Mac (CSR erzeugen)

Öffne Schlüsselbundverwaltung.
In der Menüleiste: Schlüsselbundverwaltung → Zertifikatsassistent → Zertifikat von einer Zertifizierungsstelle anfordern…
Trage deine Apple-Developer-E-Mail und einen Namen ein.
Wähle „Auf Festplatte sichern“ (nicht direkt an CA senden).
Speichere die Datei als developer-id-second.csr.
Im Apple Developer Account (zweites Zertifikat erstellen)

Gehe zu developer.apple.com → Certificates, Identifiers & Profiles.
Öffne Certificates und klicke auf +.
Wähle Developer ID Application.
Lade die eben erstellte developer-id-second.csr hoch.
Lade das neue Zertifikat (.cer) herunter.
Zurück auf dem Mac (installieren & prüfen)

Doppelklicke die .cer-Datei, damit sie in der Schlüsselbundverwaltung importiert wird.
In Anmeldung → Meine Zertifikate prüfen:
Neues Developer ID Application: ... ist sichtbar.
Darunter ist ein Privater Schlüssel vorhanden (wichtig).
Identitäten anzeigen:
security find-identity -v -p codesigning
Für GitHub Actions exportieren

In Schlüsselbundverwaltung: Rechtsklick auf das neue Zertifikat (+ Schlüssel) → Exportieren…
Format: Persönliche Informationen austauschen (.p12).
Danach Base64 erzeugen:
base64 -i developer-id-signing-2.p12 | tr -d '\n' > developer-id-signing-2.p12.b64
Neue Secrets setzen (z. B. MACOS_CERTIFICATE_P12_BASE64_2, MACOS_CERTIFICATE_PASSWORD_2, MACOS_SIGNING_IDENTITY_2).
Wichtig

Der Wert für MACOS_SIGNING_IDENTITY muss exakt einer Zeile aus security find-identity entsprechen.
Falls Apple das Zertifikatslimit erreicht meldet: altes, ungenutztes Developer-ID-Zertifikat widerrufen und neu erstellen.