# TP ARP Spoofing sur Docker

Ce dépôt fournit un environnement Docker complet pour démontrer une attaque de type ARP spoofing / man-in-the-middle entre une victime et un serveur HTTP. Trois conteneurs partagent le même réseau L2 :

- `server` : expose un service HTTP (Flask) qui journalise toutes les requêtes reçues.
- `victim` : envoie périodiquement des requêtes POST JSON vers le serveur.
- `attacker` : empoisonne les tables ARP de la victime et du serveur, intercepte le trafic HTTP et le relaie en affichant les requêtes/réponses capturées.

## Prérequis

- Docker et Docker Compose v2.
- Accès root au démon Docker (l'attaquant a besoin des capacités `NET_ADMIN` / `NET_RAW`).

## Lancer la simulation

```bash
docker-compose up --build
```

## Vérifier que l'attaque fonctionne

Affichez les journaux de l'attaquant pour voir les paquets interceptés :

```bash
docker-compose logs -f attacker
```

Vous pouvez également consulter les journaux de la victime ou du serveur :

```bash
docker-compose logs victim
docker-compose logs server
```

## Arrêter et nettoyer

```bash
docker-compose down
```
