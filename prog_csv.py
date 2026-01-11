import re   # Module pour utiliser les expressions régulières en Python [web:32]
import csv  # Module standard pour lire/écrire des fichiers CSV [web:39]


# Motif pour les lignes tcpdump
pattern = re.compile(
    r'^(?P<time>\d{2}:\d{2}:\d{2}\.\d+)\s+IP\s+'
    r'(?P<src>[^ ]+)\s+>\s+(?P<dst>[^:]+):\s+Flags\s+\[(?P<flags>[^\]]+)\],.*length\s+(?P<length>\d+)'
)
# On compile une expression régulière pour analyser une ligne tcpdump typique [web:34]
# - ^                         : début de ligne
# - (?P<time>...)             : groupe nommé "time" pour l'heure au format HH:MM:SS.xxxxxx
# - \s+IP\s+                  : espaces + le mot "IP" + espaces
# - (?P<src>[^ ]+)            : groupe "src" = source (IP/host.port) jusqu'au prochain espace
# - \s+>\s+                   : séparateur " > " entre src et dst
# - (?P<dst>[^:]+):           : groupe "dst" = destination (IP/host.port) jusqu'à deux-points
# - \s+Flags\s+\[(?P<flags>[^\]]+)\] : extrait le contenu entre [ ] après "Flags"
# - .*length\s+(?P<length>\d+): cherche "length" puis capture la taille (nombre entier)
# Les groupes nommés permettent d'accéder aux valeurs avec m.group("time"), etc. [web:29]


def split_host_port(s: str):
    """Sépare un 'host.port' en ('host', 'port'). Si pas de point, renvoie (s, '')."""
    parts = s.rsplit('.', 1)          # Coupe la chaîne en 2 à partir de la fin, sur le dernier '.' [web:32]
    if len(parts) == 2:               # Si on a bien une partie host et une partie port
        host, port = parts
    else:                             # Sinon, il n'y a pas de port (ex: juste une IP ou un hostname)
        host, port = s, ''
    return host, port                 # Retourne l'hôte et le port séparés


def main():
    """Lit un fichier texte tcpdump et génère un CSV structuré."""
    input_file = "DumpFile.txt"   # Fichier texte en entrée (sortie brute de tcpdump)
    output_file = "dump.csv"      # Fichier CSV en sortie, exploitable dans Calc/Excel

    # Ouverture des fichiers en même temps :
    # - f_in  pour la lecture du dump texte
    # - f_out pour l'écriture du CSV
    with open(input_file, encoding="utf-8") as f_in, \
         open(output_file, "w", newline="", encoding="utf-8") as f_out:

        # Noms des colonnes dans le CSV
        fieldnames = ["time", "ip_src", "port_src", "ip_dst", "port_dst", "flags", "length"]

        # Création d'un DictWriter qui écrit des lignes à partir de dictionnaires [web:33]
        writer = csv.DictWriter(f_out, fieldnames=fieldnames, delimiter=";")
        writer.writeheader()  # Écrit la première ligne d'en-tête dans le CSV

        # Parcours de chaque ligne du fichier tcp

