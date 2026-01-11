import csv                      # Module standard pour lire/écrire des fichiers CSV
from collections import Counter # Outil pratique pour compter les occurrences
import markdown                 # Bibliothèque pour convertir du Markdown en HTML


CSV_FILE = "dump.csv"           # Fichier CSV issu de ton tcpdump
MD_FILE = "rapport.md"          # Fichier texte Markdown généré
HTML_FILE = "rapport.html"      # Page HTML avec texte + graphiques


def charger_lignes():
    """Charge toutes les lignes du CSV dans une liste de dictionnaires."""
    lignes = []
    # Ouverture du CSV en lecture, encodage UTF-8, séparateur ';'
    with open(CSV_FILE, encoding="utf-8") as f:
        reader = csv.DictReader(f, delimiter=";")
        # Chaque row est un dict {nom_colonne: valeur}
        for row in reader:
            lignes.append(row)
    return lignes


def analyser(lignes):
    """
    Calcule toutes les stats nécessaires :
    - attaque SYN,
    - trafic HTTPS,
    - top IP / ports,
    - top "protocoles",
    - trafic global par seconde.
    """

    # 1) SYN flood HTTP 190-0-175-100.gba.solunet.com.ar -> 184.107.43.74
    syn_lignes = [
        row for row in lignes
        if "S" in row["flags"]                         # paquet avec flag SYN
        and row["ip_src"] == "190-0-175-100.gba.solunet.com.ar"
        and row["ip_dst"] == "184.107.43.74"
    ]

    total_syn = len(syn_lignes)                        # nombre total de SYN suspects

    # Nombre de SYN par seconde (sur le temps HH:MM:SS)
    compteur_par_seconde = Counter()
    for row in syn_lignes:
        time = row["time"]                             # exemple "15:34:06.683573"
        seconde = time[:8]                             # on garde "15:34:06"
        compteur_par_seconde[seconde] += 1

    # Seconde la plus chargée en SYN
    if compteur_par_seconde:
        seconde_max, nb_max = compteur_par_seconde.most_common(1)[0]
    else:
        seconde_max, nb_max = None, 0

    # 2) Trafic HTTPS volumineux (tous les paquets avec port_dst == "https")
    https_lignes = [
        row for row in lignes
        if row["port_dst"] == "https"
    ]

    total_https = len(https_lignes)                    # nombre de paquets HTTPS

    # Volume total HTTPS en octets (on ignore les valeurs non numériques)
    total_bytes_https = sum(
        int(row["length"]) for row in https_lignes if str(row["length"]).isdigit()
    )

    # Comptage des couples (ip_src, ip_dst) en HTTPS
    compteur_https_pair = Counter()
    for row in https_lignes:
        pair = (row["ip_src"], row["ip_dst"])
        compteur_https_pair[pair] += 1
    top_https_pairs = compteur_https_pair.most_common(5)   # top 5 couples HTTPS

    # 3) Stats génériques pour graphes “top X” (toutes IP/ports sur l’ensemble du dump)
    ip_src_counter = Counter(row["ip_src"] for row in lignes)
    ip_dst_counter = Counter(row["ip_dst"] for row in lignes)
    port_dst_counter = Counter(row["port_dst"] for row in lignes)

    top_ip_src = ip_src_counter.most_common(5)         # IP qui émettent le plus
    top_ip_dst = ip_dst_counter.most_common(5)         # IP qui reçoivent le plus
    top_port_dst = port_dst_counter.most_common(5)     # ports de destination les plus utilisés

    # 4) Top "protocoles" (ici assimilés au port de destination)
    proto_counter = Counter(row["port_dst"] for row in lignes)
    top_proto = proto_counter.most_common(5)

    # 5) Trafic global par seconde (tous les paquets, pas seulement SYN/HTTPS)
    trafic_par_seconde = Counter()
    for row in lignes:
        time = row["time"]
        seconde = time[:8]
        trafic_par_seconde[seconde] += 1

    # On renvoie toutes les stats, qui serviront au Markdown + HTML
    return (total_syn, seconde_max, nb_max, compteur_par_seconde,
            total_https, total_bytes_https, top_https_pairs,
            top_ip_src, top_ip_dst, top_port_dst,
            top_proto, trafic_par_seconde)


def generer_markdown(total_syn, seconde_max, nb_max, compteur_par_seconde,
                     total_https, total_bytes_https, top_https_pairs,
                     top_ip_src, top_ip_dst, top_port_dst,
                     top_proto, trafic_par_seconde):
    """Construit le texte du rapport au format Markdown."""
    lignes_md = []

    lignes_md.append("# Analyse du dump réseau\n")

    # Partie 1 : SYN flood
    lignes_md.append("## Attaque SYN sur le serveur HTTP\n")
    lignes_md.append(f"- Nombre total de paquets SYN suspects : **{total_syn}**\n")
    if seconde_max is not None:
        lignes_md.append(
            f"- Seconde la plus chargée : **{seconde_max}** avec **{nb_max}** paquets SYN.\n"
        )
    lignes_md.append(
        "- Source principale : `190-0-175-100.gba.solunet.com.ar` → Destination : `184.107.43.74` (HTTP).\n"
    )
    lignes_md.append(
        "- Ce volume de SYN dans un temps très court est caractéristique d'une attaque de type **SYN flood**.\n"
    )

    # Tableau : nombre de SYN par seconde
    lignes_md.append("\n### Répartition des SYN par seconde\n")
    lignes_md.append("| Seconde | Nombre de SYN |\n")
    lignes_md.append("|---------|---------------|\n")
    for seconde, nb in sorted(compteur_par_seconde.items()):
        lignes_md.append(f"| {seconde} | {nb} |\n")

    # Partie 2 : HTTPS
    lignes_md.append("\n## Trafic HTTPS très volumineux\n")
    lignes_md.append(f"- Nombre total de paquets HTTPS : **{total_https}**\n")
    lignes_md.append(f"- Volume total estimé en HTTPS : **{total_bytes_https} octets**\n")
    lignes_md.append(
        "- Ce trafic correspond à de nombreuses connexions HTTPS qui peuvent saturer le lien réseau.\n"
    )

    # Tableau : couples IP en HTTPS
    lignes_md.append("\n### Principaux couples IP en HTTPS\n")
    lignes_md.append("| IP source | IP destination | Nombre de paquets |\n")
    lignes_md.append("|-----------|----------------|-------------------|\n")
    for (ip_src, ip_dst), nb in top_https_pairs:
        lignes_md.append(f"| {ip_src} | {ip_dst} | {nb} |\n")

    # Résumé des graphiques (texte dans le rapport)
    lignes_md.append("\n## Graphiques d'illustration\n")
    lignes_md.append("- Graphique 1 : évolution du nombre de SYN par seconde.\n")
    lignes_md.append("- Graphique 2 : top 5 couples IP source/destination en HTTPS.\n")
    lignes_md.append("- Graphique 3 : top 5 IP source (volume global).\n")
    lignes_md.append("- Graphique 4 : top 5 IP destination.\n")
    lignes_md.append("- Graphique 5 : top 5 ports de destination.\n")
    lignes_md.append("- Graphique 6 : top 5 protocoles/ports de destination.\n")
    lignes_md.append("- Graphique 7 : trafic total (tous paquets) par seconde.\n")

    # On renvoie une seule grosse chaîne Markdown
    return "".join(lignes_md)


def stats_globales(lignes):
    """Calcule des statistiques globales (IP, ports, proto) et les exporte en plusieurs CSV."""
    # Normalisation de length en int (0 si invalide)
    for row in lignes:
        try:
            row["length"] = int(row["length"])
        except ValueError:
            row["length"] = 0

    from collections import Counter

    # Compteurs de paquets et d'octets
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

    # Alimentation des compteurs
    for row in lignes:
        ip_src = row["ip_src"]
        ip_dst = row["ip_dst"]
        port_src = row["port_src"]
        port_dst = row["port_dst"]
        length = row["length"]

        packets_ip_src[ip_src] += 1
        bytes_ip_src[ip_src] += length

        packets_ip_dst[ip_dst] += 1
        bytes_ip_dst[ip_dst] += length

        packets_port_src[port_src] += 1
        bytes_port_src[port_src] += length

        packets_port_dst[port_dst] += 1
        bytes_port_dst[port_dst] += length

        packets_proto[port_dst] += 1
        bytes_proto[port_dst] += length

    # Fonction générique pour écrire un fichier de stats (IP / port / proto)
    def ecrire_stats_csv(nom_fichier, key_name, packets_counter, bytes_counter):
        with open(nom_fichier, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f, delimiter=";")
            w.writerow([key_name, "packets", "bytes_total"])
            # tri décroissant sur nombre de paquets puis sur volume
            for key, nb_packets in sorted(
                packets_counter.items(),
                key=lambda x: (x[1], bytes_counter[x[0]]),
                reverse=True
            ):
                w.writerow([key, nb_packets, bytes_counter[key]])

    # Écriture des différents fichiers de stats
    ecrire_stats_csv("stats_ip_src.csv", "ip_src", packets_ip_src, bytes_ip_src)
    ecrire_stats_csv("stats_ip_dst.csv", "ip_dst", packets_ip_dst, bytes_ip_dst)
    ecrire_stats_csv("stats_port_src.csv", "port_src", packets_port_src, bytes_port_src)
    ecrire_stats_csv("stats_port_dst.csv", "port_dst", packets_port_dst, bytes_port_dst)
    ecrire_stats_csv("stats_proto.csv", "proto", packets_proto, bytes_proto)


def generer_html(md_text, compteur_par_seconde, top_https_pairs,
                 top_ip_src, top_ip_dst, top_port_dst,
                 top_proto, trafic_par_seconde):
    """
    Génère la page HTML complète :
    - corps du rapport (Markdown -> HTML),
    - 7 graphiques Chart.js basés sur les stats calculées.
    """
    # Conversion du Markdown en HTML (pour le texte du rapport)
    body_html = markdown.markdown(md_text)

    # Données pour le graphique SYN
    labels_syn = [sec for sec, _ in sorted(compteur_par_seconde.items())]
    data_syn = [nb for _, nb in sorted(compteur_par_seconde.items())]

    # Données pour les couples HTTPS
    labels_https = [f"{src} → {dst}" for (src, dst), _ in top_https_pairs]
    data_https = [nb for _, nb in top_https_pairs]

    # Données top IP / ports
    labels_ip_src = [ip for ip, _ in top_ip_src]
    data_ip_src = [nb for _, nb in top_ip_src]

    labels_ip_dst = [ip for ip, _ in top_ip_dst]
    data_ip_dst = [nb for _, nb in top_ip_dst]

    labels_port_dst = [port for port, _ in top_port_dst]
    data_port_dst = [nb for _, nb in top_port_dst]

    # Données top protocoles
    labels_proto = [proto for proto, _ in top_proto]
    data_proto = [nb for _, nb in top_proto]

    # Trafic global par seconde
    labels_trafic = [sec for sec, _ in sorted(trafic_par_seconde.items())]
    data_trafic = [nb for _, nb in sorted(trafic_par_seconde.items())]

    # Page HTML avec intégration de Chart.js et du code JS des 7 graphiques
    html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="utf-8">
    <title>Rapport d'analyse du dump réseau</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
{body_html}

<h2>Graphique 1 : SYN par seconde</h2>
<canvas id="synChart" width="600" height="300"></canvas>

<h2>Graphique 2 : Top 5 couples HTTPS</h2>
<canvas id="httpsChart" width="600" height="300"></canvas>

<h2>Graphique 3 : Top 5 IP source</h2>
<canvas id="ipSrcChart" width="600" height="300"></canvas>

<h2>Graphique 4 : Top 5 IP destination</h2>
<canvas id="ipDstChart" width="600" height="300"></canvas>

<h2>Graphique 5 : Top 5 ports destination</h2>
<canvas id="portDstChart" width="600" height="300"></canvas>

<h2>Graphique 6 : Top 5 protocoles / ports de destination</h2>
<canvas id="protoChart" width="600" height="300"></canvas>

<h2>Graphique 7 : Trafic global par seconde</h2>
<canvas id="traficChart" width="600" height="300"></canvas>

<script>
// SYN
const synLabels = {labels_syn};
const synData = {data_syn};
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
            y: {{ beginAtZero: true }}
        }}
    }}
}});

// HTTPS pairs
const httpsLabels = {labels_https};
const httpsData = {data_https};
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
        indexAxis: 'y',
        scales: {{
            x: {{ beginAtZero: true }}
        }}
    }}
}});

// Top IP source
const ipSrcLabels = {labels_ip_src};
const ipSrcData = {data_ip_src};
const ctxIpSrc = document.getElementById('ipSrcChart').getContext('2d');
new Chart(ctxIpSrc, {{
    type: 'bar',
    data: {{
        labels: ipSrcLabels,
        datasets: [{{
            label: 'Paquets émis',
            data: ipSrcData,
            backgroundColor: 'rgba(75, 192, 192, 0.5)',
            borderColor: 'rgba(75, 192, 192, 1)',
            borderWidth: 1
        }}]
    }},
    options: {{
        indexAxis: 'y',
        scales: {{
            x: {{ beginAtZero: true }}
        }}
    }}
}});

// Top IP destination
const ipDstLabels = {labels_ip_dst};
const ipDstData = {data_ip_dst};
const ctxIpDst = document.getElementById('ipDstChart').getContext('2d');
new Chart(ctxIpDst, {{
    type: 'bar',
    data: {{
        labels: ipDstLabels,
        datasets: [{{
            label: 'Paquets reçus',
            data: ipDstData,
            backgroundColor: 'rgba(255, 206, 86, 0.5)',
            borderColor: 'rgba(255, 206, 86, 1)',
            borderWidth: 1
        }}]
    }},
    options: {{
        indexAxis: 'y',
        scales: {{
            x: {{ beginAtZero: true }}
        }}
    }}
}});

// Top ports destination
const portDstLabels = {labels_port_dst};
const portDstData = {data_port_dst};
const ctxPortDst = document.getElementById('portDstChart').getContext('2d');
new Chart(ctxPortDst, {{
    type: 'bar',
    data: {{
        labels: portDstLabels,
        datasets: [{{
            label: 'Paquets vers le port',
            data: portDstData,
            backgroundColor: 'rgba(153, 102, 255, 0.5)',
            borderColor: 'rgba(153, 102, 255, 1)',
            borderWidth: 1
        }}]
    }},
    options: {{
        scales: {{
            y: {{ beginAtZero: true }}
        }}
    }}
}});

// Top protocoles / ports
const protoLabels = {labels_proto};
const protoData = {data_proto};
const ctxProto = document.getElementById('protoChart').getContext('2d');
new Chart(ctxProto, {{
    type: 'bar',
    data: {{
        labels: protoLabels,
        datasets: [{{
            label: 'Paquets par port/proto',
            data: protoData,
            backgroundColor: 'rgba(255, 159, 64, 0.5)',
            borderColor: 'rgba(255, 159, 64, 1)',
            borderWidth: 1
        }}]
    }},
    options: {{
        scales: {{
            y: {{ beginAtZero: true }}
        }}
    }}
}});

// Trafic global par seconde
const traficLabels = {labels_trafic};
const traficData = {data_trafic};
const ctxTrafic = document.getElementById('traficChart').getContext('2d');
new Chart(ctxTrafic, {{
    type: 'line',
    data: {{
        labels: traficLabels,
        datasets: [{{
            label: 'Paquets totaux par seconde',
            data: traficData,
            fill: false,
            borderColor: 'rgba(0, 0, 0, 0.8)',
            tension: 0.1
        }}]
    }},
    options: {{
        scales: {{
            y: {{ beginAtZero: true }}
        }}
    }}
}});
</script>

</body>
</html>
"""
    return html


def main():
    """Point d'entrée du script : enchaîne chargement, analyse, rapports et stats CSV."""
    print("Début du script analyse_dump_markdown.py")

    # Lecture du CSV
    lignes = charger_lignes()

    # Calcul de toutes les statistiques
    (total_syn, seconde_max, nb_max, compteur_par_seconde,
     total_https, total_bytes_https, top_https_pairs,
     top_ip_src, top_ip_dst, top_port_dst,
     top_proto, trafic_par_seconde) = analyser(lignes)

    # Génération du rapport Markdown
    md_text = generer_markdown(
        total_syn, seconde_max, nb_max, compteur_par_seconde,
        total_https, total_bytes_https, top_https_pairs,
        top_ip_src, top_ip_dst, top_port_dst,
        top_proto, trafic_par_seconde
    )

    # Écriture du Markdown sur disque
    with open(MD_FILE, "w", encoding="utf-8") as f:
        f.write(md_text)

    # Génération de la page HTML avec graphiques
    html = generer_html(
        md_text, compteur_par_seconde, top_https_pairs,
        top_ip_src, top_ip_dst, top_port_dst,
        top_proto, trafic_par_seconde
    )
    with open(HTML_FILE, "w", encoding="utf-8") as f:
        f.write(html)

    # Export des stats globales en CSV pour Excel/Calc
    stats_globales(lignes)

    print(f"Rapport Markdown : {MD_FILE}")
    print(f"Page HTML       : {HTML_FILE}")
    print("Stats générées.")


if __name__ == "__main__":
    main()








