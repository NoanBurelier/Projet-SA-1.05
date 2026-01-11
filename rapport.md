# Analyse du dump réseau
## Attaque SYN sur le serveur HTTP
- Nombre total de paquets SYN suspects : **2000**
- Seconde la plus chargée : **15:34:06** avec **2000** paquets SYN.
- Source principale : `190-0-175-100.gba.solunet.com.ar` → Destination : `184.107.43.74` (HTTP).
- Ce volume de SYN dans un temps très court est caractéristique d'une attaque de type **SYN flood**.

### Répartition des SYN par seconde
| Seconde | Nombre de SYN |
|---------|---------------|
| 15:34:06 | 2000 |

## Trafic HTTPS très volumineux
- Nombre total de paquets HTTPS : **2853**
- Volume total estimé en HTTPS : **157068 octets**
- Ce trafic correspond à de nombreuses connexions HTTPS qui peuvent saturer le lien réseau.

### Principaux couples IP en HTTPS
| IP source | IP destination | Nombre de paquets |
|-----------|----------------|-------------------|
| BP-Linux8 | www.aggloroanne.fr | 1022 |
| BP-Linux8 | mauves.univ-st-etienne.fr | 751 |
| BP-Linux8 | par10s38-in-f3.1e100.net | 255 |
| BP-Linux8 | par21s23-in-f3.1e100.net | 200 |
| BP-Linux8 | par21s17-in-f1.1e100.net | 176 |

## Graphiques d'illustration
- Graphique 1 : évolution du nombre de SYN par seconde.
- Graphique 2 : top 5 couples IP source/destination en HTTPS.
- Graphique 3 : top 5 IP source (volume global).
- Graphique 4 : top 5 IP destination.
- Graphique 5 : top 5 ports de destination.
- Graphique 6 : top 5 protocoles/ports de destination.
- Graphique 7 : trafic total (tous paquets) par seconde.
