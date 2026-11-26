# Report Partner

Pagina protetta da password con i dati del Custom Report del portale partner, **senza commissioni**.
Si aggiorna da sola ogni ora circa con GitHub Actions.

## Cosa è pubblico e cosa no

| Pubblico | Privato |
|---|---|
| Questo codice | Email e password del portale (GitHub Secrets) |
| `docs/data.enc.json`, cifrato (AES-256-GCM, chiave da PBKDF2 con 600.000 iterazioni) | La password della pagina (GitHub Secrets) |
| | I dati in chiaro (solo chi ha la password della pagina) |

Le commissioni, il saldo e i ricavi vengono tolti **prima** della cifratura: non arrivano mai su GitHub.
Colonne tenute: data, Serial ID, paese, sub-affiliato, registrazioni, FTD, FTD idonei, importi FTD e depositi, click, impression, rimborsi/chargeback.

## Configurazione (una volta sola)

1. **Settings → Secrets and variables → Actions → New repository secret**, crea:
   - `ETORO_EMAIL`: email di accesso al portale
   - `ETORO_PASSWORD`: password del portale
   - `REPORT_PASSWORD`: password della pagina per i sub-affiliati (lunga: 4-5 parole a caso)
2. **Settings → Pages**: Source "Deploy from a branch", branch `main`, cartella `/docs`.
3. **Actions → Aggiorna report → Run workflow** per il primo avvio (scarica 12 mesi di storico).

Indirizzo della pagina: `https://<utente>.github.io/report-partner/`

## Cambiare la password della pagina

Aggiorna il secret `REPORT_PASSWORD` e lancia **Run workflow**: i dati vengono riscaricati e cifrati con la nuova password.
