
## Descrizione
Breve introduzione alla macchina:
- **Difficoltà:** Media
- **Categoria:** Web Exploitation
- **Piattaforma:** THM

## Riepilogo dei Passi
1. Ricognizione iniziale
2. Identificazione di un servizio vulnerabile
3. Sfruttamento
4. Escalation dei privilegi
5. Conclusione

## Dettagli Tecnici

### Passo 1: Ricognizione
```bash\
nmap -sC -sV -oN ./nmap/initial-scan.txt 10.10.10.X\
```
