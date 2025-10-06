# Solutions du TP ARP Spoofing

## Exercice 1 : Compréhension du Docker Compose

1. **Réponse** : L'attaquant a besoin des capacités `NET_ADMIN` et `NET_RAW` car il doit :
   - `NET_ADMIN` : Modifier les tables ARP du système et configurer les interfaces réseau
   - `NET_RAW` : Créer et envoyer des paquets réseau bruts (paquets ARP falsifiés) avec Scapy

2. **Réponse** : Les adresses IP fixes sont utilisées pour :
   - Simplifier la configuration et éviter les problèmes de découverte
   - Permettre à l'attaquant de connaître précisément les adresses IP de ses cibles
   - Faciliter la compréhension du TP pour les étudiants
   - Éviter que DHCP ne change les adresses pendant la démo

## Exercice 2 : Analyse du comportement normal

1. **Réponse** : Dans les logs de la victime, on observe un pattern régulier de messages :
   - Un message indiquant le début du générateur de trafic
   - Des messages périodiques (toutes les 4 secondes) montrant les requêtes POST envoyées
   - Un message initial indiquant l'adresse MAC du serveur détectée
   - Les logs montrent des statuts HTTP 200 et les réponses du serveur

2. **Réponse** : Le serveur traite les requêtes de la victime en :
   - Affichant un message initial avec l'adresse MAC de la victime
   - Journalisant chaque requête reçue avec l'IP source, le user-agent et le corps
   - Si l'adresse MAC change pour une même IP, il affiche une alerte
   - Retournant une réponse JSON avec un statut "ok" et un écho du message reçu

## Exercice 3 : Code à compléter - L'attaquant

### 3.1 : Résolution d'adresse MAC

**Réponse** : La fonction `resolve_mac()` est essentielle car :
- Elle permet à l'attaquant de découvrir les adresses MAC réelles de la victime et du serveur
- Ces adresses MAC sont nécessaires pour construire les paquets ARP falsifiés
- Sans connaître les vraies MACs, l'attaquant ne pourrait pas cibler correctement ses paquets
- La fonction utilise `srp()` pour envoyer une requête ARP et capturer la réponse

**Code complété** :
```python
packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_ip)
answered, _ = srp(packet, timeout=2, retry=3, iface=iface, verbose=0)
for _, response in answered:
    mac = response[Ether].src
```

### 3.2 : Interception et transfert des paquets

**Réponse** : L'attaquant détermine la direction en vérifiant :
- Les adresses IP source et destination dans le paquet
- Si `IP.src == VICTIM_IP et IP.dst == SERVER_IP` → "victim->server"
- Si `IP.src == SERVER_IP et IP.dst == VICTIM_IP` → "server->victim"
- Il modifie l'en-tête Ethernet pour que le paquet atteigne la prochaine machine sur le réseau local

**Code complété** :
```python
if packet[IP].src == VICTIM_IP and packet[IP].dst == SERVER_IP:
    direction = "victim->server"
    dst_mac = server_mac
elif packet[IP].src == SERVER_IP and packet[IP].dst == VICTIM_IP:
    direction = "server->victim"
    dst_mac = victim_mac

new_packet = Ether(src=attacker_mac, dst=dst_mac) / packet[IP]
```

## Exercice 4 : Analyse de l'attaque

1. **Réponse** : Dans les logs de l'attaquant, on observe :
   - Les messages de résolution d'adresses MAC initiales
   - Le démarrage de la boucle d'empoisonnement ARP
   - Le démarrage du sniffer de paquets
   - Des messages "captured HTTP victim->server" montrant l'interception des requêtes POST
   - Des messages "captured HTTP server->victim" montrant l'interception des réponses
   - Le contenu des requêtes et réponses est visible en clair

2. **Réponse** : La victime continue de fonctionner normalement car l'attaquant :
   - Active l'IP forwarding pour relayer les paquets
   - Modifie les en-têtes Ethernet pour que les paquets atteignent leurs destinations
   - Maintient les deux directions de communication (victime→serveur et serveur→victime)
   - Ne modifie pas le contenu des paquets, il les relaie simplement

3. **Réponse** : Au niveau des adresses MAC dans les logs de la victime :
   - Initialement, la victime détecte l'adresse MAC réelle du serveur
   - Après l'attaque, la victime voit l'adresse MAC de l'attaquant à la place de celle du serveur
   - Un message d'alerte s'affiche : "ARP cache serveur modifié: [ancienne_MAC] -> [nouvelle_MAC]"
   - Cela prouve que la table ARP de la victime a été empoisonnée

4. **Réponse** : Oui, l'attaquant peut lire le contenu des requêtes car :
   - Les logs montrent clairement le contenu JSON des requêtes POST
   - Les réponses HTTP avec leur contenu sont également visibles
   - L'attaquant voit les données en clair car la communication n'est pas chiffrée (HTTP)
   - Cela démontre le danger du MITM : interception de données sensibles

## Exercice 5 : Analyse du code de l'attaquant

1. **Réponse** : Dans la fonction `poison_arp()`, les deux paquets ARP envoyés sont :
   - `frame_to_victim` : Paquet ARP falsifié disant à la victime que l'IP du serveur correspond à la MAC de l'attaquant
   - `frame_to_server` : Paquet ARP falsifié disant au serveur que l'IP de la victime correspond à la MAC de l'attaquant
   - Les deux paquets sont de type ARP reply (op=2) pour mettre à jour les caches ARP

2. **Réponse** : L'attaquant doit maintenir l'empoisonnement en boucle car :
   - Les tables ARP ont une durée de vie limitée (timeout)
   - Les entrées ARP peuvent être rafraîchies par des requêtes légitimes
   - Si l'empoisonnement s'arrête, les caches se reconstitueront normalement
   - La boucle assure une interception continue du trafic

3. **Réponse** : Si vous commentez les lignes `sendp()` dans la boucle `poison_arp()` :
   - L'attaque ne fonctionne plus. Les paquets ARP falsifiés ne sont pas envoyés, donc les caches ARP ne sont pas corrompus.
   - Sans l'envoi régulier des paquets d'empoisonnement, les tables ARP restent légitimes. L'attaquant ne peut plus intercepter le trafic. Les logs de la victime ne montreront aucun changement d'adresse MAC.

---