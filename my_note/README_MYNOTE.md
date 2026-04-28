Idea del protocollo:

log crea checkpoint
↓
log firma checkpoint con firma standard note
↓
witness riceve nota già firmata dal log
↓
witness fa note.Open (con libreria standard) per verificare la firma del log
↓
witness firma il solo testo del checkpoint (msg)
↓
aggiungi riga witness-agg alla nota
↓
chi verifica usa OpenMixedNote di my_note


Quindi:
- witness usa note per verificare e my_note per firmare (addSignatureAfterVerify)
- client usa my_note per verificare (OpenMixedNote)