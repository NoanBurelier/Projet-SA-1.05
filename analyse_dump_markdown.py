import csv                     # Module standard pour lire/écrire des fichiers CSV [web:15]
from collections import Counter  # Outil pratique pour compter les occurrences d’éléments [web:21]
import markdown                # Bibliothèque pour convertir du texte Markdown en HTML [web:22]


CSV_FILE = "dump.csv"          # Nom du fichier CSV contenant le dump réseau
MD_FILE = "rapport.md"         # Nom du fichier de sortie au format Markdown
HTML_FILE = "rapport.html"     # Nom du fichier de sortie au format HTML


def charger_lignes():
    """Charge toutes les lignes du CSV dans une liste de dictionnaires."""
    lignes = []                                    # Liste qui contiendra chaque ligne sous forme de dict
    with open(CSV_FILE, encoding="utf-8") as f:    # Ouverture du fichier CSV en lecture UTF-8
        reader = csv.DictReader(f, delimiter=";")  # Lit le CSV et mappe chaque ligne dans un dict (clé = nom de colonne) [web:15]
        for row in reader:                         # Parcourt chaque ligne du CSV
            lignes.append(row)                     # Ajoute la ligne dans la liste
    return lignes                                  # Retourne la liste de toutes les lignes


def analyser(lignes):
    """Analyse l’attaque SYN et le trafic HTTPS dans le dump."""

    # 1) Détection d’un SYN flood HTTP depuis 190-0-175-100.gba.solunet.com.ar vers 184.107.43.74
    syn_lignes = [
        row for row in lignes
        if "S" in row["flags"]       # On garde uniquement les paquets avec le flag SYN
        and row["ip_src"] == "190-0-175-100.gba.solunet.com.ar"  # IP source spécifique
        and row["ip_dst"] == "184.107.43.74"                     # IP destination spécifique
    ]

    total_syn = len(syn_lignes)      # Nombre total de paquets SYN suspects

    compteur_par_seconde = Counter() # Counter pour compter le nombre de SYN par seconde [web:21]
    for row in syn_lignes:
        time = row["time"]           # Exemple : "15:34:06.683573"
        seconde = time[:8]           # On garde "HH:MM:SS" pour regrouper par seconde
        compteur_par_seconde[seconde] += 1  # Incrémente le compteur pour cette seconde

    # Si on a au moins un SYN, on récupère la seconde la plus chargée
    if compteur_par_seconde:
        seconde_max, nb_max = compteur_par_seconde.most_common(1)[0]  # (seconde, nb SYN max)
    else:
        seconde_max, nb_max = None, 0  # Aucun SYN trouvé

    # 2) Analyse du trafic HTTPS volumineux
    https_lignes = [
        row for row in lignes
        if row["port_dst"] == "https"   # On sélectionne les paquets dont le port destination est "https"
    ]

    total_https = len(https_lignes)     # Nombre total de paquets HTTPS

    # Somme des longueurs de paquets HTTPS (en octets), en filtrant les valeurs non numériques
    total_bytes_https = sum(
        int(row["length"]) for row in https_lignes if str(row["length"]).isdigit()
    )

    # Compteur des couples (ip_src, ip_dst) en HTTPS
    compteur_https_pair = Counter()
    for row in https_lignes:
        pair = (row["ip_src"], row["ip_dst"])  # Tuple (IP source, IP destination)
        compteur_https_pair[pair] += 1         # Incrémente le nombre de paquets pour ce couple

    top_https_pairs = compteur_https_pair.most_common(5)  # Top 5 des couples IP les plus actifs en HTTPS

    # On retourne toutes les stats nécessaires aux fonctions suivantes
    return (total_syn, seconde_max, nb_max, compteur_par_seconde,
            total_https, total_bytes_https, top_https_pairs)


def generer_markdown(total_syn, seconde_max, nb_max, compteur_par_seconde,
                     total_https, total_bytes_https, top_https_pairs):
    """Génère le rapport Markdown à partir des statistiques calculées."""
    lignes_md = []  # Liste de lignes de texte Markdown

    # Titre principal
    lignes_md.append("# Analyse du dump réseau\n")

    # ---- Partie 1 : attaque SYN HTTP ----
    lignes_md.append("## Attaque SYN sur le serveur HTTP\n")
    lignes_md.append(f"- Nombre total de paquets SYN suspects : **{total_syn}**\n")
    if seconde_max is not None:  # On n’écrit la seconde max que si elle existe
        lignes_md.append(
            f"- Seconde la plus chargée : **{seconde_max}** avec **{nb_max}** paquets SYN.\n"
        )
    lignes_md.append(
        "- Source principale : `190-0-175-100.gba.solunet.com.ar` → Destination : `184.107.43.74` (HTTP).\n"
    )
    lignes_md.append(
        "- Ce volume de SYN dans un temps très court est caractéristique d'une attaque de type **SYN flood**.\n"
    )

    # Tableau récapitulatif du nombre de SYN par seconde
    lignes_md.append("\n### Répartition des SYN par seconde\n")
    lignes_md.append("| Seconde | Nombre de SYN |\n")
    lignes_md.append("|---------|---------------|\n")
    for seconde, nb in sorted(compteur_par_seconde.items()):  # Tri par ordre chronologique
        lignes_md.append(f"| {seconde} | {nb} |\n")

    # ---- Partie 2 : trafic HTTPS volumineux ----
    lignes_md.append("\n## Trafic HTTPS très volumineux\n")
    lignes_md.append(f"- Nombre total de paquets HTTPS : **{total_https}**\n")
    lignes_md.append(f"- Volume total estimé en HTTPS : **{total_bytes_https} octets**\n")
    lignes_md.append(
        "- Ce trafic correspond à de nombreuses connexions HTTPS qui peuvent saturer le lien réseau.\n"
    )

    # Tableau des principaux couples IP HTTPS
    lignes_md.append("\n### Principaux couples IP en HTTPS\n")
    lignes_md.append("| IP source | IP destination | Nombre de paquets |\n")
    lignes_md.append("|-----------|----------------|-------------------|\n")
    for (ip_src, ip_dst), nb in top_https_pairs:
        lignes_md.append(f"| {ip_src} | {ip_dst} | {nb} |\n")

    # Section descriptive des graphiques qui seront dans la version HTML
    lignes_md.append("\n## Graphiques d'illustration\n")
    lignes_md.append(
        "- Graphique 1 : évolution du nombre de SYN par seconde.\n"
    )
    lignes_md.append(
        "- Graphique 2 : top 5 couples IP source/destination en HTTPS.\n"
    )

    return "".join(lignes_md)  # On concatène la liste en une seule chaîne Markdown


def stats_globales(lignes):
    """Calcule des statistiques globales (IP, ports, proto) et les exporte en CSV."""
    # Conversion sûre de la longueur en int (0 si invalide)
    for row in lignes:
        try:
            row["length"] = int(row["length"])
        except ValueError:
            row["length"] = 0

    from collections import Counter  # Import local (déjà importé en haut)

    # Initialisation des compteurs pour paquets et octets
    packets_ip_src = Counter()
    bytes_ip_src = Counter()
    packets_ip_dst = Counter()
    bytes_ip_dst = Counter()
    packets_port_src = Counter()
    bytes_port_src = Counter()
    packets_port_dst = Counter()
    bytes_port_dst = Counter()
    packets_proto = Counter()
    bytes_proto = Counter()

    # Parcours de toutes les lignes pour alimenter les compteurs
    for row in lignes:
        ip_src = row["ip_src"]
        ip_dst = row["ip_dst"]
        port_src = row["port_src"]
        port_dst = row["port_dst"]
        length = row["length"]

        # Comptage par IP source
        packets_ip_src[ip_src] += 1
        bytes_ip_src[ip_src] += length

        # Comptage par IP destination
        packets_ip_dst[ip_dst] += 1
        bytes_ip_dst[ip_dst] += length

        # Comptage par port source
        packets_port_src[port_src] += 1
        bytes_port_src[port_src] += length

        # Comptage par port destination
        packets_port_dst[port_dst] += 1
        bytes_port_dst[port_dst] += length

        # Comptage par "proto" basé ici sur le port destination
        packets_proto[port_dst] += 1
        bytes_proto[port_dst] += length

    # Fonction interne pour écrire un CSV de stats génériques
    def ecrire_stats_csv(nom_fichier, key_name, packets_counter, bytes_counter):
        with open(nom_fichier, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f, delimiter=";")               # Writer CSV avec séparateur ';' [web:18]
            w.writerow([key_name, "packets", "bytes_total"])  # En-tête du fichier de stats
            for key, nb_packets in sorted(
                packets_counter.items(),
                key=lambda x: (x[1], bytes_counter[x[0]]),  # Tri par nb de paquets puis par octets
                reverse=True
            ):
                w.writerow([key, nb_packets, bytes_counter[key]])  # Une ligne par IP/port/proto

    # Génération des différents fichiers de stats
    ecrire_stats_csv("stats_ip_src.csv", "ip_src", packets_ip_src, bytes_ip_src)
    ecrire_stats_csv("stats_ip_dst.csv", "ip_dst", packets_ip_dst, bytes_ip_dst)
    ecrire_stats_csv("stats_port_src.csv", "port_src", packets_port_src, bytes_port_src)
    ecrire_stats_csv("stats_port_dst.csv", "port_dst", packets_port_dst, bytes_port_dst)
    ecrire_stats_csv("stats_proto.csv", "proto", packets_proto, bytes_proto)


def generer_html(md_text, compteur_par_seconde, top_https_pairs):
    """Génère la page HTML complète avec texte et graphiques Chart.js."""
    # Conversion du Markdown en HTML pour la partie texte du rapport
    body_html = markdown.markdown(md_text)  # Transforme le texte Markdown en HTML [web:22]

    # Données pour le graphique SYN (labels = secondes, data = nombre de SYN)
    labels_syn = [sec for sec, _ in sorted(compteur_par_seconde.items())]
    data_syn = [nb for _, nb in sorted(compteur_par_seconde.items())]

    # Données pour le graphique HTTPS (labels = 'ip_src → ip_dst', data = nombre de paquets)
    labels_https = [f"{src} → {dst}" for (src, dst), _ in top_https_pairs]
    data_https = [nb for _, nb in top_https_pairs]

    # Page HTML avec inclusion de Chart.js et deux graphiques (SYN & HTTPS)
    html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="utf-8">
    <title>Rapport d'analyse du dump réseau</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>  <!-- Import de Chart.js depuis un CDN -->
</head>
<body>
{body_html}

<h2>Graphique 1 : SYN par seconde</h2>
<canvas id="synChart" width="600" height="300"></canvas>  <!-- Canvas pour le graphique SYN -->

<h2>Graphique 2 : Top 5 couples HTTPS</h2>
<canvas id="httpsChart" width="600" height="300"></canvas>  <!-- Canvas pour le graphique HTTPS -->

<script>
const synLabels = {labels_syn};  // Labels pour l'axe X (secondes)
const synData = {data_syn};      // Nombre de SYN par seconde

// Création du graphique des SYN (barres verticales)
const ctxSyn = document.getElementById('synChart').getContext('2d');
new Chart(ctxSyn, {{
    type: 'bar',
    data: {{
        labels: synLabels,
        datasets: [{{
            label: 'Nombre de SYN',
            data: synData,
            backgroundColor: 'rgba(255, 99, 132, 0.5)',
            borderColor: 'rgba(255, 99, 132, 1)',
            borderWidth: 1
        }}]
    }},
    options: {{
        scales: {{
            y: {{
                beginAtZero: true  // L'axe Y commence à 0
            }}
        }}
    }}
}});

const httpsLabels = {labels_https};  // Labels pour chaque couple IP
const httpsData = {data_https};      // Nombre de paquets HTTPS par couple

// Création du graphique HTTPS (barres horizontales)
const ctxHttps = document.getElementById('httpsChart').getContext('2d');
new Chart(ctxHttps, {{
    type: 'bar',
    data: {{
        labels: httpsLabels,
        datasets: [{{
            label: 'Paquets HTTPS',
            data: httpsData,
            backgroundColor: 'rgba(54, 162, 235, 0.5)',
            borderColor: 'rgba(54, 162, 235, 1)',
            borderWidth: 1
        }}]
    }},
    options: {{
        indexAxis: 'y',  // Inversion des axes pour des barres horizontales
        scales: {{
            x: {{
                beginAtZero: true
            }}
        }}
    }}
}});
</script>

</body>
</html>
"""
    return html  # Retourne la chaîne HTML complète


def main():
    """Point d'entrée principal du script."""
    print("Début du script analyse_dump_markdown.py")

    lignes = charger_lignes()  # Lecture du CSV en mémoire

    # Analyse des SYN et du trafic HTTPS
    (total_syn, seconde_max, nb_max, compteur_par_seconde,
     total_https, total_bytes_https, top_https_pairs) = analyser(lignes)

    # Génération du texte Markdown du rapport
    md_text = generer_markdown(
        total_syn, seconde_max, nb_max, compteur_par_seconde,
        total_https, total_bytes_https, top_https_pairs
    )

    # Écriture du rapport Markdown sur disque
    with open(MD_FILE, "w", encoding="utf-8") as f:
        f.write(md_text)

    # Génération de la page HTML avec graphiques
    html = generer_html(md_text, compteur_par_seconde, top_https_pairs)
    with open(HTML_FILE, "w", encoding="utf-8") as f:
        f.write(html)

    # Génération des fichiers CSV de statistiques globales
    stats_globales(lignes)

    print(f"Rapport Markdown : {MD_FILE}")
    print(f"Page HTML       : {HTML_FILE}")
    print("Stats générées.")


# Exécution du script si lancé directement
if __name__ == "__main__":
    main()





