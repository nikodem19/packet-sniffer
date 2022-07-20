###IPK - projekt 1
### Autor
* **Nikodém Babirád (xbabix01)** 

## Zadanie
Implementace severu, který bude komunikovat protokolem HTTP a bude zajišťovat překlad doménových jmen. Pro překlad jmen bude server používat lokální resolver stanice na které běží - užijte přímo API, které poskytuje OS (například getnameinfo, getaddrinfo pro C/C++). 
# Knihovny potrebné na preklad
socketserver, socket, re, sys, signal
# Základné operace
###GET
vo formáte:
GET /resolve?name=apple.com&type=A HTTP/1.1
###POST
vo formáte:
POST /dns-query HTTP/1.1
# IMPLEMENTACE
Server som implementoval pomocou knihovne socketserver, pomocou ktorej som spojaznil základnú komunikáciu. Následne som využil knihovne re, socket a signal na spravnu funkcionalitu serveru a spravny format jeho vstupov. Neplatné vstupy sú ošetrené pomocou error codov.
### RETURN CODE
200 OK - uspesna komunikace,
404 NOT FOUND - neuspesna komunikace, nedostupne
400 BAD REQUEST - neplatny vstup
405 BAD METHOD - neplatna metoda
