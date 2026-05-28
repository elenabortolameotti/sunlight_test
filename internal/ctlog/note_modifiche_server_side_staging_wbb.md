# Server-Side Staging per WBB Threshold Entries

Questa nota riassume le modifiche introdotte per supportare il nuovo meccanismo di **server-side staging** delle entry WBB con soglia maggiore di 1.

L’obiettivo della modifica è permettere a più entità di inviare firme separate per lo stesso contenuto WBB. Il server raccoglie queste submission in una staging area e pubblica la entry nel log solo quando il numero di firmatari distinti raggiunge la soglia richiesta.

I test di riferimento che risultano passanti sono:

```bash
go test ./internal/ctlog/... -v -count=1 -run TestStagingMechanism
go test ./internal/ctlog/... -v -count=1 -run "TestWBB|TestStaging"
```

---

## 1. Modifiche in `internal/ctlog/ctlog.go`

### 1.1 Aggiunta della staging area nella struct `Log`

Alla struct `Log` è stata aggiunta una nuova mappa per tenere traccia delle submission parziali in attesa del raggiungimento della soglia.

```go
stagingMu sync.Mutex
staging   map[[32]byte]*StagingEntry
```

La mappa usa come chiave un hash SHA-256 del contenuto WBB completo.

```go
contentHash := SHA256(wbbData)
```

Questo permette di associare tutte le submission relative alla stessa entry WBB alla stessa staging entry.

Il mutex `stagingMu` protegge la mappa da accessi concorrenti, poiché `/submit` può essere chiamato da più richieste HTTP contemporaneamente.

---

### 1.2 Aggiunta del tipo `StagingEntry`

È stato introdotto il tipo `StagingEntry`, che rappresenta lo stato server-side di una entry WBB non ancora pubblicata oppure già pubblicata ma ancora capace di ricevere late arrivals.

```go
type StagingEntry struct {
    WBBData       string
    Phase         Phase
    Role          Role
    EntryType     EntryType
    Threshold     int
    Content       string

    Submissions   map[string]*StagingSubmission

    RunningBLSAggregate []byte

    FirstSubmissionAt int64
    LastSubmissionAt  int64

    IsPublished   bool
    LeafIndex     int64
}
```

I campi principali sono:

- `WBBData`: conserva la stringa WBB originale.
- `Phase`, `Role`, `EntryType`, `Threshold`, `Content`: conservano la versione parsata della entry.
- `Submissions`: mappa `entityID -> submission`; serve anche a impedire che la stessa entità venga contata due volte.
- `RunningBLSAggregate`: campo predisposto per il supporto BLS server-side.
- `FirstSubmissionAt`: timestamp della prima submission ricevuta.
- `LastSubmissionAt`: timestamp dell’ultima submission ricevuta.
- `IsPublished`: indica se la soglia è stata raggiunta e la entry è già stata pubblicata nel log.
- `LeafIndex`: indice della leaf pubblicata quando `IsPublished == true`.

---

### 1.3 Aggiunta del tipo `StagingSubmission`

È stato introdotto il tipo `StagingSubmission`, che rappresenta il contributo di una singola entità.

```go
type StagingSubmission struct {
    EntityID      string
    Timestamp     int64
    Signature     []byte
    BLSSignature  []byte
}
```

I campi principali sono:

- `EntityID`: identificativo dell’entità firmataria, per esempio `TT-1` o `RT-2`.
- `Timestamp`: timestamp della submission.
- `Signature`: firma Ed25519 della singola submission.
- `BLSSignature`: campo predisposto per il caso BLS.

---

### 1.4 Inizializzazione dello staging in `LoadLog`

Nel costruttore del log, dentro `LoadLog`, la staging area viene inizializzata così:

```go
staging: make(map[[32]byte]*StagingEntry),
```

Questo evita panic dovuti a scritture su una mappa nil e prepara il log a ricevere submission parziali.

---

## 2. Modifiche in `internal/ctlog/http.go`

Le modifiche principali in `http.go` riguardano:

1. il calcolo del content hash;
2. l’aggiunta delle funzioni core di staging;
3. la finalizzazione delle entry quando la soglia è raggiunta;
4. la gestione dei late arrivals;
5. i nuovi formati di response;
6. la modifica del flow di `submitEntry`.

---

## 2.1 `computeContentHash`

È stata aggiunta la funzione:

```go
func computeContentHash(wbbData string) [32]byte {
    return sha256.Sum256([]byte(wbbData))
}
```

Questa funzione genera la chiave della staging area.

Due submission con la stessa stringa WBB completa producono lo stesso hash e finiscono nella stessa staging entry.

Due submission con contenuto diverso producono hash diversi e vengono gestite separatamente.

Questo è importante per il test di conflict resolution: due risultati diversi non devono contaminarsi a vicenda.

---

## 2.2 `stageSubmission`

È stata aggiunta la funzione:

```go
func (l *Log) stageSubmission(contentHash [32]byte, signedEntry SignedEntry, wbbEntry WBBEntry) (currentCount int, isNew bool, err error)
```

Questa funzione aggiunge una submission singola allo staging.

La logica è:

1. verifica la submission singola tramite `verifySingleWBBEntry`;
2. cerca una staging entry già esistente per quel `contentHash`;
3. se non esiste, crea una nuova `StagingEntry`;
4. rifiuta la submission se la entry è già pubblicata;
5. rifiuta la submission se lo stesso signer ha già contribuito;
6. aggiunge la submission alla mappa `Submissions`;
7. aggiorna i timestamp;
8. restituisce il numero attuale di signer distinti.

Il controllo di sicurezza più importante è quello contro i duplicati:

```go
if _, exists := staged.Submissions[signedEntry.EntityID]; exists {
    return len(staged.Submissions), false, fmtErrorf("duplicate signer: %s", signedEntry.EntityID)
}
```

Senza questo controllo, una singola entità potrebbe inviare più volte la stessa firma e raggiungere artificialmente una soglia che dovrebbe richiedere più entità distinte.

---

## 2.3 `checkThreshold`

È stata aggiunta la funzione:

```go
func (l *Log) checkThreshold(contentHash [32]byte) (count int, thresholdMet bool, err error)
```

Questa funzione controlla se una staging entry ha raggiunto la soglia richiesta.

La logica è:

1. recupera la staging entry tramite `contentHash`;
2. conta le submission distinte presenti in `Submissions`;
3. confronta il numero con `staged.Threshold`.

Esempio:

```text
TT-1                  -> count = 1, thresholdMet = false
TT-1 + TT-2           -> count = 2, thresholdMet = false
TT-1 + TT-2 + TT-3    -> count = 3, thresholdMet = true
```

La funzione non modifica lo stato: serve solo a leggere la situazione corrente.

---

## 2.4 `stagedSigners`

È stata aggiunta una helper per ottenere i firmatari ordinati:

```go
func stagedSigners(staged *StagingEntry) []string
```

La funzione raccoglie le chiavi della mappa `Submissions` e le ordina con `sort.Strings`.

Questo è utile perché le mappe Go non hanno ordine deterministico. Ordinare i signer rende stabili:

- le response HTTP;
- le entry finali;
- i test.

---

## 2.5 `finalizeEntry`

È stata aggiunta la funzione:

```go
func (l *Log) finalizeEntry(contentHash [32]byte, ctx context.Context) (leafIndex int64, err error)
```

Questa funzione viene chiamata quando `checkThreshold` indica che la soglia è stata raggiunta.

La logica è:

1. recupera la staging entry;
2. controlla che non sia già pubblicata;
3. controlla difensivamente che la soglia sia davvero raggiunta;
4. costruisce una `SignedEntry` finale;
5. serializza la entry;
6. la pubblica nel log usando `addLeafToPool`;
7. marca la staging entry come pubblicata;
8. salva il `LeafIndex`.

Nel caso Ed25519, la entry finale contiene:

```go
SigAlgorithm: "ed25519"
EntityIDs:    []string{...}
Signatures:   [][]byte{...}
```

Nel caso BLS, la funzione è predisposta per usare:

```go
SigAlgorithm:       "bls"
AggregateSignature: staged.RunningBLSAggregate
```

La funzione rilascia il lock prima di chiamare `addLeafToPool`, così non blocca inutilmente altre submission mentre il log sequenzia la leaf.

---

## 2.6 `appendToPublishedEntry`

È stata aggiunta la funzione:

```go
func (l *Log) appendToPublishedEntry(contentHash [32]byte, signedEntry SignedEntry, entityID string) (leafIndex int64, totalSigners int, err error)
```

Questa funzione gestisce i late arrivals.

Un late arrival è una firma valida che arriva dopo che la soglia è già stata raggiunta e la entry è già stata pubblicata.

Esempio:

```text
TT-1 -> pending
TT-2 -> pending
TT-3 -> published
TT-4 -> appended
```

La funzione:

1. recupera la staging entry;
2. verifica che sia già pubblicata;
3. controlla che `entityID` coincida con `signedEntry.EntityID`;
4. controlla che i dati firmati siano gli stessi della entry già pubblicata;
5. rifiuta signer duplicati;
6. verifica comunque la firma singola con `verifySingleWBBEntry`;
7. aggiunge il nuovo signer alla mappa `Submissions`;
8. ritorna il `LeafIndex` originale e il numero totale di signer.

La funzione non pubblica una nuova leaf nel log. Il late arrival viene associato alla entry già pubblicata.

---

## 2.7 Nuove response per lo staging

Sono stati aggiunti tre formati di response.

### Pending response

Usata quando la soglia non è ancora raggiunta.

```go
type stagingPendingResponse struct {
    Status          string   `json:"status"`
    ContentHash     string   `json:"content_hash"`
    CurrentSigners  int      `json:"current_signers"`
    RequiredSigners int      `json:"required_signers"`
    Signers         []string `json:"signers"`
    Message         string   `json:"message"`
}
```

Esempio:

```json
{
  "status": "pending",
  "content_hash": "...",
  "current_signers": 1,
  "required_signers": 3,
  "signers": ["TT-1"],
  "message": "need 2 more signature(s)"
}
```

### Published response

Usata quando la soglia viene raggiunta e la entry viene pubblicata.

```go
type stagingPublishedResponse struct {
    Status          string   `json:"status"`
    ContentHash     string   `json:"content_hash"`
    LeafIndex       int64    `json:"leaf_index"`
    CurrentSigners  int      `json:"current_signers"`
    RequiredSigners int      `json:"required_signers"`
    Signers         []string `json:"signers"`
    Message         string   `json:"message"`

    Algorithm          string   `json:"algorithm,omitempty"`
    Signatures         [][]byte `json:"signatures,omitempty"`
    AggregateSignature []byte   `json:"aggregate_signature,omitempty"`
}
```

Nel caso Ed25519, la response contiene anche:

```json
"algorithm": "ed25519",
"signatures": [...]
```

Questo è stato necessario per far passare il test `Ed25519_Staging`.

### Appended response

Usata quando arriva una firma valida dopo la pubblicazione.

```go
type stagingAppendedResponse struct {
    Status       string   `json:"status"`
    ContentHash  string   `json:"content_hash"`
    LeafIndex    int64    `json:"leaf_index"`
    TotalSigners int      `json:"total_signers"`
    Signers      []string `json:"signers"`
    Message      string   `json:"message"`
}
```

Esempio:

```json
{
  "status": "appended",
  "content_hash": "...",
  "leaf_index": 0,
  "total_signers": 4,
  "signers": ["TT-1", "TT-2", "TT-3", "TT-4"],
  "message": "signature appended to already published entry"
}
```

---

## 2.8 Modifica del flow di `submitEntry`

La funzione `submitEntry` è stata modificata per supportare tre comportamenti.

### Caso 1: threshold uguale a 1

Le entry con soglia 1 vengono ancora gestite come prima.

Il server:

1. verifica la firma singola con `verifySingleWBBEntry`;
2. continua nel normale flow di pubblicazione immediata;
3. inserisce la entry nel log con `addLeafToPool`;
4. ritorna `200 OK`.

Questo è il caso usato da entry come:

```text
ER election_pub_key
BB ballot_digest
BB encrypted_ballot
```

### Caso 2: threshold maggiore di 1 con entry aggregata già completa

Per mantenere compatibilità con i test WBB già esistenti, il server riconosce anche il formato:

```go
EntityIDs
AggregateSignature
```

In questo caso:

1. chiama `verifyAggregateWBBEntry`;
2. verifica che la firma aggregata soddisfi i requisiti;
3. pubblica immediatamente la entry nel log;
4. ritorna `200 OK`.

Questo permette ai test WBB esistenti di continuare a funzionare senza essere riscritti.

### Caso 3: threshold maggiore di 1 con submission singola

Questo è il nuovo flow server-side staging.

Quando arriva una submission con:

```go
EntityID
Signature
```

il server:

1. calcola `contentHash`;
2. controlla se la entry è già pubblicata;
3. se è già pubblicata, chiama `appendToPublishedEntry`;
4. altrimenti chiama `stageSubmission`;
5. chiama `checkThreshold`;
6. se la soglia non è raggiunta, ritorna `202 Accepted` con status `pending`;
7. se la soglia è raggiunta, chiama `finalizeEntry`;
8. ritorna `200 OK` con status `published`.

In forma sintetica:

```text
TT-1 -> 202 pending
TT-2 -> 202 pending
TT-3 -> 200 published
TT-4 -> 200 appended
```

---

## 3. Comportamento finale ottenuto

### Entry con soglia 1

```text
ER-1 firma una entry ER threshold 1
-> verifica singola
-> pubblicazione immediata
-> 200 OK
```

### Entry con soglia maggiore di 1 tramite staging

```text
TT-1 firma
-> 202 pending

TT-2 firma
-> 202 pending

TT-3 firma
-> soglia raggiunta
-> entry pubblicata
-> 200 published
```

### Late arrival

```text
TT-4 firma dopo la pubblicazione
-> firma verificata
-> aggiunta allo stato staging
-> nessuna nuova leaf
-> 200 appended
```

### Duplicate signer

```text
TT-1 firma una seconda volta per lo stesso contentHash
-> rejected
-> duplicate signer
```

### Contenuti diversi

```text
result_A e result_B producono content hash diversi
-> staging separate
-> nessuna contaminazione tra contenuti
```

---

## 4. Test verificati

Sono stati verificati i test richiesti dalla guida.

### Tutti i test staging

```bash
go test ./internal/ctlog/... -v -count=1 -run TestStagingMechanism
```

Risultato:

```text
PASS
```

Questo include:

- `Basic_Staging_-_Single_Entity`
- `Basic_Staging_-_Multiple_Entities`
- `Threshold_Detection`
- `Late_Arrivals_After_Threshold`
- `Conflict_Resolution_-_Different_Content`
- `Duplicate_Signer_Prevention`
- `Ed25519_Staging`
- `BLS_Staging`
- `Staging_State_Persistence`

### WBB test vecchi e nuovi

```bash
go test ./internal/ctlog/... -v -count=1 -run "TestWBB|TestStaging"
```

Risultato:

```text
PASS
```

Questo conferma che:

- i nuovi test staging passano;
- i vecchi test WBB continuano a passare;
- la policy WBB è ancora rispettata;
- i test negativi su ruoli, fasi, entry type e soglie continuano a funzionare.

---

## 5. Riassunto finale

Le modifiche hanno introdotto un nuovo meccanismo di server-side staging per le entry WBB con soglia maggiore di 1.

Il server ora può:

1. ricevere submission singole;
2. verificare ogni firma;
3. impedire signer duplicati;
4. accumulare firme per contenuto;
5. pubblicare solo quando la soglia viene raggiunta;
6. gestire firme arrivate dopo la pubblicazione;
7. mantenere compatibilità con le entry aggregate già complete.

Il risultato è una WBB più coerente con un modello threshold multi-entità, in cui la soglia può essere raggiunta progressivamente tramite submission indipendenti.
