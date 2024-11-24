{\rtf1\ansi\ansicpg1252\cocoartf2818
\cocoatextscaling0\cocoaplatform0{\fonttbl\f0\fswiss\fcharset0 Helvetica;}
{\colortbl;\red255\green255\blue255;}
{\*\expandedcolortbl;;}
\paperw11900\paperh16840\margl1440\margr1440\vieww11520\viewh8400\viewkind0
\pard\tx720\tx1440\tx2160\tx2880\tx3600\tx4320\tx5040\tx5760\tx6480\tx7200\tx7920\tx8640\pardirnatural\partightenfactor0

\f0\fs24 \cf0 # Writeup: Machine XYZ\
\
![Status](https://img.shields.io/badge/Status-Completed-brightgreen)\
\
## Descrizione\
Breve introduzione alla macchina:\
- **Difficolt\'e0:** Media\
- **Categoria:** Web Exploitation\
- **Piattaforma:** Hack The Box (HTB)\
\
## Riepilogo dei Passi\
1. Ricognizione iniziale.\
2. Identificazione di un servizio vulnerabile.\
3. Sfruttamento.\
4. Escalation dei privilegi.\
5. Conclusione.\
\
## Dettagli Tecnici\
\
### Passo 1: Ricognizione\
```bash\
nmap -sC -sV -oN ./nmap/initial-scan.txt 10.10.10.X\
}