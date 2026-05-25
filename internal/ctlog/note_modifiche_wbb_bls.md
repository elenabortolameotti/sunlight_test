# Note tecniche sulle modifiche WBB / BLS aggregate signatures

Questa nota riassume le modifiche introdotte per trasformare il flusso in un flusso coerente con una Web Bulletin Board (WBB), mantenendo la firma singola per le entry a soglia 1 e introducendo firme BLS aggregate per le entry a soglia maggiore di 1.

## Obiettivo generale

Il comportamento finale implementato è:

- per entry con `threshold == 1`: la richiesta usa una singola identità (`entity_id`) e una singola firma Ed25519 (`signature`);
- per entry con `threshold > 1`: la richiesta usa una lista esplicita di firmatari (`entity_ids`) e una firma BLS aggregata (`aggregate_signature`);
- la policy WBB viene applicata a ogni entry prima dell’inserimento nel log;
- la lista dei firmatari aggregati viene restituita nella response, così è visibile quali entità hanno firmato.

---

## `internal/ctlog/wbb_policy.go`

Questo file contiene la logica di policy WBB.

È stato usato per validare il formato logico delle entry WBB:

```text
phase,role,entry_type,threshold,content
```

La policy controlla che:

- la fase sia corretta (`setup`, `voting`, `tallying`);
- il ruolo sia corretto (`RT`, `ER`, `BB`, `TT`);
- l’entry type sia ammesso per quella coppia fase/ruolo;
- la soglia dichiarata sia coerente con l’entry type.

Esempi di regole supportate:

- `RT` può scrivere `acc_pub_key` in fase `setup` con soglia 2;
- `ER` può scrivere `election_pub_key`, `pseudonymous_id_count`, `voter_id_merkle_root` in fase `setup` con soglia 1;
- `BB` può scrivere entry di voting come `ballot_digest`, `ballot_metadata`, `cast_intended_proof` con soglia 1;
- `BB` può scrivere `encrypted_ballot` in fase `tallying` con soglia 1;
- `TT` può scrivere `mixed_ballots`, `re_encryption_proof`, `tally_result`, `tally_proof` in fase `tallying` con soglia 3.

---

## `internal/ctlog/http.go`

Questo è il file principale modificato per integrare la policy WBB e la verifica delle firme.

### 1. Estensione di `SignedEntry`

La struct `SignedEntry` è stata estesa per supportare sia il caso a firma singola sia il caso aggregato.

Prima supportava solo:

```go
Data      []byte
EntityID  string
Timestamp int64
Signature []byte
```

Ora supporta anche:

```go
EntityIDs          []string
AggregateSignature []byte
```

Il significato è:

- `EntityID` + `Signature`: firma singola Ed25519, usata per entry con threshold 1;
- `EntityIDs` + `AggregateSignature`: firma BLS aggregata, usata per entry con threshold maggiore di 1.

I campi singoli e aggregati sono lasciati opzionali tramite `omitempty`, così la stessa struct può rappresentare entrambi i formati.

### 2. Riorganizzazione di `submitEntry`

La funzione `submitEntry` è stata riorganizzata.

Prima il server richiedeva sempre `entity_id` e `signature`, verificando sempre una firma Ed25519 prima ancora di interpretare la entry WBB. Questo non era compatibile con le entry aggregate, perché una entry RT/TT aggregata non ha un singolo `entity_id`, ma una lista `entity_ids`.

Il nuovo flusso è:

1. decodifica del JSON;
2. controllo dei campi comuni (`data`, `timestamp`);
3. controllo del timestamp anti-replay;
4. parsing della entry WBB con `ParseWBBEntry`;
5. applicazione della policy con `CheckWBBWritePolicy`;
6. scelta del ramo di verifica:
   - se `threshold == 1`, verifica singola Ed25519;
   - se `threshold > 1`, verifica BLS aggregata;
7. inserimento della entry nel log;
8. risposta JSON con `entity_id` oppure `entity_ids`.

### 3. Verifica singola Ed25519

È stata introdotta/isolata una funzione logica equivalente a `verifySingleWBBEntry`.

Questa funzione controlla:

- che `entity_id` sia presente;
- che `signature` sia presente;
- che il ruolo derivato da `entity_id` coincida con il ruolo dichiarato nella entry WBB;
- che la public key Ed25519 dell’entità esista;
- che la firma Ed25519 sia valida.

Questo ramo è usato per entry a soglia 1, ad esempio `ER` e `BB`.

### 4. Verifica BLS aggregata

È stata introdotta una funzione logica equivalente a `verifyAggregateWBBEntry`.

Questa funzione controlla:

- che `entity_ids` sia presente;
- che `aggregate_signature` sia presente;
- che il numero di firmatari sia almeno uguale alla soglia richiesta;
- che i firmatari siano distinti;
- che ogni firmatario abbia il ruolo corretto;
- che ogni firmatario abbia una public key BLS registrata;
- che la firma BLS aggregata verifichi rispetto alle public key dei firmatari.

In questo modo `RT-1` da solo non può soddisfare una soglia 2 e `TT-1, TT-2` non possono soddisfare una soglia 3.

### 5. Messaggio firmato per BLS aggregata

Per la firma BLS aggregata è stata usata una funzione di costruzione del messaggio firmato, equivalente a:

```go
aggregateSignedMessage(data, timestamp, entityIDs)
```

Il messaggio include:

```text
data || timestamp || entity_ids
```

Questo è importante perché la lista dei firmatari viene vincolata crittograficamente alla firma aggregata. Quindi non è possibile prendere una firma aggregata valida e cambiare successivamente la lista dei firmatari nella richiesta.

### 6. Response JSON

La response è stata aggiornata per supportare entrambi i casi:

- per entry singole ritorna `entity_id`;
- per entry aggregate ritorna `entity_ids`.

Esempio entry singola:

```json
{
  "leaf_index": 0,
  "timestamp": 1779184674852,
  "data_hash": "...",
  "entity_id": "ER-1"
}
```

Esempio entry aggregata:

```json
{
  "leaf_index": 0,
  "timestamp": 1779184674799,
  "data_hash": "...",
  "entity_ids": ["RT-1", "RT-2"]
}
```

---

## `internal/ctlog/ctlog.go`

Questo file è stato modificato per rendere disponibili al log anche le public key BLS delle entità.

### 1. Modifica di `Config`

Alla struct `Config` è stato aggiunto un campo per le public key BLS:

```go
EntityBLSKeys map[string][]byte
```

Questo campo è separato da:

```go
EntityKeys map[string]ed25519.PublicKey
```

La separazione è importante perché:

- `EntityKeys` contiene le chiavi pubbliche Ed25519 per le firme singole;
- `EntityBLSKeys` contiene le chiavi pubbliche BLS serializzate per la verifica aggregata.

### 2. Modifica di `Log`

Alla struct `Log` è stato aggiunto un campo interno:

```go
entityBLSKeys map[string][]byte
```

Questo consente a `http.go` di verificare le firme BLS aggregate durante il submit.

### 3. Modifica di `LoadLog`

In `LoadLog`, oltre a inizializzare `entityKeys`, viene inizializzato anche `entityBLSKeys`.

Se `config.EntityBLSKeys` è presente, viene usato quello; altrimenti viene inizializzata una mappa vuota.

Questo evita che il server abbia chiavi private BLS: nel log sono presenti solo public key usate per verificare.

---

## `internal/ctlog/wbb_policy_e2e_test.go`

Questo è il file di test principale per la WBB.

### 1. Generazione di firme Ed25519 reali

I test inizialmente usavano firme placeholder.

La funzione `generateTestEntityKeys` è stata modificata per salvare anche le private key Ed25519:

```go
testEntityPrivateKeys map[string]ed25519.PrivateKey
```

La helper `createWBBEntry` ora firma davvero il messaggio atteso da `SignedEntry.Verify`.

Questo ha permesso di superare la fase in cui le richieste fallivano prima ancora di arrivare alla policy.

### 2. Generazione di signer BLS per i test

Nei test sono stati aggiunti:

```go
testEntityBLSSigners map[string]*my_crypto.BLSSigner
testEntityBLSKeys    map[string][]byte
```

La distinzione è:

- `testEntityBLSSigners` resta solo nei test e serve a produrre firme BLS;
- `testEntityBLSKeys` contiene le public key BLS e viene passata alla config del server.

Questo mantiene separato il materiale privato dal materiale pubblico.

### 3. Configurazione del log nei test

Alla config del test è stato aggiunto:

```go
EntityBLSKeys: testEntityBLSKeys
```

Così il server può verificare le firme BLS aggregate prodotte dai test.

### 4. Helper per entry aggregate

È stata aggiunta una helper equivalente a `createAggregateWBBEntry`.

Questa helper:

1. costruisce il messaggio BLS da firmare;
2. fa firmare lo stesso messaggio a più signer BLS;
3. aggrega le firme;
4. restituisce una `SignedEntry` con:
   - `Data`;
   - `Timestamp`;
   - `EntityIDs`;
   - `AggregateSignature`.

Questa helper viene usata per RT e TT.

### 5. Test RT

Il test valido `RT_can_write_acc_pub_key_with_threshold_2` è stato modificato per usare una firma BLS aggregata con:

```text
RT-1, RT-2
```

La response mostra la lista dei firmatari:

```json
"entity_ids": ["RT-1", "RT-2"]
```

### 6. Test ER

I test ER restano a firma singola Ed25519:

- `ER_can_write_election_pub_key`;
- `ER_can_write_pseudonymous_id_count`;
- `ER_can_write_voter_id_merkle_root`.

Le response contengono:

```json
"entity_id": "ER-1"
```

### 7. Test BB

I test BB restano a firma singola Ed25519:

- `BB_can_write_ballot_digest`;
- `BB_can_write_ballot_metadata`;
- `BB_can_write_cast_intended_proof`;
- `BB_can_write_encrypted_ballot`.

Le response contengono:

```json
"entity_id": "BB-1"
```

### 8. Test TT

I test TT validi sono stati modificati per usare firma BLS aggregata con:

```text
TT-1, TT-2, TT-3
```

I test coperti sono:

- `TT_can_write_mixed_ballots_with_threshold_3`;
- `TT_can_write_re_encryption_proof`;
- `TT_can_write_tally_result`;
- `TT_can_write_tally_proof`.

Le response contengono:

```json
"entity_ids": ["TT-1", "TT-2", "TT-3"]
```

### 9. Test negativi aggiuntivi

Sono stati aggiunti test negativi per rafforzare la verifica aggregata:

- RT aggregata con un solo firmatario;
- TT aggregata con due soli firmatari;
- RT aggregata con firmatario duplicato;
- RT aggregata con un firmatario di ruolo sbagliato.

Questi test verificano che la soglia non sia solo dichiarata nella stringa WBB, ma venga effettivamente applicata ai firmatari della richiesta aggregata.

---

## `internal/ctlog/e2e_test.go`

Questo file contiene anche test legacy non specifici WBB.

### 1. `MemoryBackend`

Il backend in memoria usato nei test è stato reso sicuro rispetto ad accessi concorrenti.

È stato sostituito il placeholder:

```go
mu bytes.Buffer
```

con:

```go
mu sync.Mutex
```

Poi i metodi che accedono alla mappa interna sono stati protetti con lock.

In particolare:

- `Upload`;
- `Fetch`;
- `Discard`.

### 2. `MemoryLockBackend`

Anche il lock backend in memoria è stato reso più robusto aggiungendo un mutex.

Questo ha risolto il problema:

```text
fatal error: concurrent map writes
```

che compariva durante i test.

### 3. Test legacy ancora da riallineare

Il test legacy `TestE2ESignedEntrySubmission` non è ancora stato riallineato.

Attualmente può fallire perché il nuovo `/submit` richiede che `Data` sia una entry WBB valida nel formato:

```text
phase,role,entry_type,threshold,content
```

mentre il test legacy usa dati generici non-WBB.

Questa parte è da sistemare separatamente, senza toccare la logica WBB/BLS già funzionante.

---

## `internal/durable/path.go`

Per poter eseguire i test su Windows è stata fatta una modifica locale legata a:

```go
syscall.O_DIRECTORY
```

Su Windows questa costante non è disponibile, quindi per far compilare il progetto in ambiente Windows è stata rimossa o sostituita (con 0) nei punti problematici.

Questa modifica è pratica per lo sviluppo locale su Windows, ma andrebbe valutata separatamente se il codice deve restare portabile tra Windows e Unix.

---

## Stato finale dei test WBB

I test WBB principali passano.

Sono stati verificati separatamente:

```bash
go test ./internal/ctlog/... -v -count=1 -run TestWBBPolicyAllEntities/Setup_Phase
```

Risultato:

- RT passa con `entity_ids:["RT-1","RT-2"]`;
- ER passa con `entity_id:"ER-1"`.

```bash
go test ./internal/ctlog/... -v -count=1 -run TestWBBPolicyAllEntities/Voting_Phase
```

Risultato:

- BB passa per tutte le entry di voting previste.

```bash
go test ./internal/ctlog/... -v -count=1 -run TestWBBPolicyAllEntities/Tallying_Phase
```

Risultato:

- BB passa per `encrypted_ballot`;
- TT passa con `entity_ids:["TT-1","TT-2","TT-3"]` per tutte le entry previste.

Il comportamento finale è quindi coerente con la policy WBB:

- ruoli e fasi sono controllati;
- le soglie dichiarate sono controllate;
- le firme singole sono usate solo per threshold 1;
- le firme BLS aggregate sono usate per threshold maggiore di 1;
- la lista dei firmatari aggregati è visibile nella risposta.
