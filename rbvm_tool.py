import json
import psycopg2
from tkinter import *
from tkinter import filedialog
import matplotlib.pyplot as plt
import pandas as pd
from contextlib import ExitStack
import math
from datetime import datetime

conn = psycopg2.connect(database="postgres",
    host="localhost",
    user="postgres",
    password="Alibabar",
    port="5432")

cur = conn.cursor()

#Delete schema
# cur.execute("""
#     DROP SCHEMA IF EXISTS jaka CASCADE;
# """)

# Création du schéma VM et de la table VM.info avec contraintes d'unicité sur D, C et I
cur.execute("""
      CREATE SCHEMA IF NOT EXISTS jaka;
      CREATE TABLE IF NOT EXISTS jaka.vm(
        name VARCHAR PRIMARY KEY,
        A FLOAT,
        C FLOAT,
        I FLOAT
        );
""")

#Création de la table micro dans le schéma jaka avec les infos parsées dans le fichier JSON
cur.execute("""
    CREATE TABLE IF NOT EXISTS jaka.micro(
        bs_id VARCHAR,
        cve_id VARCHAR,
        bom_ref VARCHAR,
        composant_ref VARCHAR,
        severity VARCHAR,
        score_cvss FLOAT,
        attack_vector VARCHAR,
        attack_complexity VARCHAR,
        privileges_required VARCHAR,
        user_interaction VARCHAR,
        scope VARCHAR,
        impact_confidentiality VARCHAR,
        impact_integrity VARCHAR,
        impact_availability VARCHAR,
        exp_score FLOAT,
        env_score FLOAT,
        KEV VARCHAR,
        C_heritage FLOAT,
        I_heritage FLOAT,
        a_heritage FLOAT,
        PRIMARY KEY (bs_id, cve_id)
    );
""")

cur.execute("""
    CREATE TABLE IF NOT EXISTS jaka.jointure(
        num SERIAL PRIMARY KEY,
        bs_id VARCHAR,
        vm_id VARCHAR,
        cve_id VARCHAR,
        FOREIGN KEY (bs_id, cve_id) REFERENCES jaka.micro(bs_id, cve_id), 
        FOREIGN KEY (vm_id) REFERENCES jaka.vm(name)
    );
""")

# Mettre à jour les valeurs D, C, I dans micro en fonction de la VM associée
#à updater = done
def update_micro_heritage():
    cur.execute("""
        UPDATE jaka.micro m
        SET 
            C_heritage = (
                SELECT MAX(vm.C)
                FROM jaka.jointure j
                JOIN jaka.vm vm ON j.vm_id = vm.name
                WHERE j.bs_id = m.bs_id
            ),
            I_heritage = (
                SELECT MAX(vm.I)
                FROM jaka.jointure j
                JOIN jaka.vm vm ON j.vm_id = vm.name
                WHERE j.bs_id = m.bs_id
            ),
            a_heritage = (
                SELECT MAX(vm.A)
                FROM jaka.jointure j
                JOIN jaka.vm vm ON j.vm_id = vm.name
                WHERE j.bs_id = m.bs_id
            );
    """)


##### VARIABLES GLOBALES #####

attack_vector = None
attack_complexity = None
privileges_required = None
user_interaction = None
scope = None
confidentiality = None
integrity = None
availability = None
authentification = None
exp_score = None
env_score = None
kev = None

# Dictionnaire permettant de stocker les microservices ainsi que leurs valeurs P1, P2, P3, P4, P5,
dicoListePx = {}

##### CLASSES ET LISTES #####

#Classe permettant de définir les CVE
class CVE:
    def __init__(self, id, composant_ref, description, severity, score_CVSS, attack_vector, attack_complexity, privileges_required, user_interaction, scope, confidentiality, integrity, availability, exp_score, env_score, kev):
        self.id = id
        self.composant_ref = composant_ref
        self.description = description
        self.severity = severity
        self.score_CVSS = score_CVSS
        self.attack_vector = attack_vector
        self.attack_complexity = attack_complexity
        self.privileges_required = privileges_required
        self.user_interaction = user_interaction
        self.scope = scope
        self.confidentiality = confidentiality
        self.integrity = integrity
        self.availability = availability
        self.exp_score = exp_score
        self.env_score = env_score
        self.kev = kev
    
    def __repr__(self):
        return(f"ID: {self.id} \nBom-ref: {self.composant_ref} \nDescription: {self.description} \nSeverity: {self.severity} \nScore CVSS: {self.score_CVSS} \nAV: {self.attack_vector} \nAC: {self.attack_complexity} \nPR: {self.privileges_required} \nUI: {self.user_interaction} \nS: {self.scope} \nC: {self.confidentiality} \nI: {self.integrity} \nA: {self.availability} \nScore Exp: {self.exp_score} \nScore Env: {self.env_score} \nKeV: {self.kev}\n\n")

class CVE_others:
    def __init__(self, id, composant_ref, description, severity):
        self.id = id
        self.composant_ref = composant_ref
        self.description = description
        self.severity = severity
    
    def __repr__(self):
        return(f"ID: {self.id} \nBom-ref: {self.composant_ref} \nDescription: {self.description} \nSeverity: {self.severity}\n\n")

##### FONCTIONS #####

# Fonction permettant de parser les variables environnementales à partir du "vector" du VDR (CVSS3.0)
def var_environnementales_CVSSv3(svector):
    attack_vector = svector[12]
    attack_complexity = svector[17]
    privileges_required = svector[22]
    user_interaction = svector[27]
    scope = svector[31]
    confidentiality = svector[35]
    integrity = svector[39]
    availability = svector[43]
    return (attack_vector, attack_complexity, privileges_required, user_interaction, scope, confidentiality, integrity, availability)

# Fonction permettant de parser les variables environnementales à partir du "vector" du VDR (CVSS2.0)
def var_environnementales_CVSSv2(svector):
    attack_vector = svector[4]
    attack_complexity = svector[9]
    authentification = svector[14]
    confidentiality = svector[18]
    integrity = svector[22]
    availability = svector[26]
    return (attack_vector, attack_complexity, authentification, confidentiality, integrity, availability)

# Fonction permettant de parser les variables environnementales à partir du "vector" du VDR (CVSS non spécifié)
def var_environnementales_other(svector):
    attack_vector = "None"
    attack_complexity = "None"
    privileges_required = "None"
    user_interaction = "None"
    scope = "None"
    confidentiality = "None"
    integrity = "None"
    availability = "None"
    return (attack_vector, attack_complexity, privileges_required, user_interaction, scope, confidentiality, integrity, availability)

# Fonction permettant de calculer le score d'exploitabilité
def calcul_score_exploitabilité(attack_vector, attack_complexity, privileges_required, user_interaction):

    exp_score = (8.22 * attack_vector * attack_complexity * privileges_required * user_interaction) / 3.9 * 4
    return round(exp_score, 1)

# Fonction de decomposition analytique du VDR
def parsing(vdr_data, kev_data) :
    p1 = []
    p2 = []
    p3 = []
    p4 = []
    p5 = []
    list_vulnerabilities = []  # Initialize here
    if 'vulnerabilities' in vdr_data:
        list_vulnerabilities = []
        for vulnerability in vdr_data['vulnerabilities']:
            id = vulnerability.get('id')
            if "GHSA" in id:
                continue
            score_CVSS = vulnerability.get('ratings')[0].get('score')
            if score_CVSS is None:
                continue
            composant_ref = vulnerability.get('bom-ref')
            description = vulnerability.get('description')
            severity = vulnerability.get('ratings')[0].get('severity')
            vector = vulnerability.get('ratings')[0].get('vector')
            svector = str(vector)
            method = vulnerability.get('ratings')[0].get('method')
            if "CVSSv2" in method:
                continue
            # if "CVSSv4" in method:
            #     continue
            if "CVSSv3" in method:
                attack_vector, attack_complexity, privileges_required, user_interaction, scope, confidentiality, integrity, availability = var_environnementales_CVSSv3(svector)
            # elif "CVSSv2" in method:
            #     attack_vector, attack_complexity, authentification, confidentiality, integrity, availability = var_environnementales_CVSSv2(svector)
            elif "other" in method:
                attack_vector, attack_complexity, privileges_required, user_interaction, scope, confidentiality, integrity, availability = var_environnementales_other(svector)
                vuln_other = CVE_others(
                    id=id,
                    composant_ref=composant_ref,
                    description=description,
                    severity=severity)
                cur.execute("""INSERT INTO jaka.micro(bs_id, cve_id, bom_ref, composant_ref, severity) 
                            VALUES (%s, %s, %s, %s, %s) 
                            ON CONFLICT (bs_id, cve_id) DO NOTHING;
                            """, (bs_id, vuln_other.id, serialNumber, vuln_other.composant_ref, vuln_other.severity))
                continue


            #Initialisation du score d"xploitabilité
            exp_score = None
            #variables attack vector
            AV_network = 0.85
            AV_adjacent = 0.62
            AV_local = 0.55
            AV_physical = 0.2
            #variables attack complexity
            AC_low = 0.77
            AC_high = 0.44
            #variables privileges_required
            PR_none = 0.85
            PR_low = 0.62
            PR_high = 0.27
            #variables user interaction
            UI_none = 0.85
            UI_required = 0.62
            #variables confidencialité, intégrité, disponibilité
            CIA_none = 0
            CIA_low = 0.22
            CIA_high = 0.56
            #Définition de la valeur de l'attack vector
            if "N" in attack_vector:attack_vector = AV_network
            elif "A" in attack_vector:attack_vector = AV_adjacent
            elif "L" in attack_vector:attack_vector = AV_local
            elif "P" in attack_vector:attack_vector = AV_physical
            else: attack_vector = None
            #Définition de la valeur de l'attack complexity
            if "L" in attack_complexity:attack_complexity = AC_low
            elif "H" in attack_complexity:attack_complexity = AC_high
            else: attack_complexity = None
            #Définition de la valeur des privileges required
            if "N" in privileges_required:privileges_required = PR_none
            elif "L" in privileges_required:privileges_required = PR_low
            elif "H" in privileges_required:privileges_required = PR_high
            else: privileges_required = None
            #Définition de la valeur du user interaction
            if "N" in user_interaction:user_interaction = UI_none
            elif "R" in user_interaction:user_interaction = UI_required
            else: user_interaction = None
            #Définition de la valeur confidencialité, intégrité, disponibilité
            if "N" in confidentiality:confidentiality_num = CIA_none
            elif "L" in confidentiality:confidentiality_num = CIA_low
            elif "H" in confidentiality:confidentiality_num = CIA_high
            if "N" in integrity:integrity_num = CIA_none
            elif "L" in integrity:integrity_num = CIA_low
            elif "H" in integrity:integrity_num = CIA_high
            if "N" in availability:availability_num = CIA_none
            elif "L" in availability:availability_num = CIA_low
            elif "H" in availability:availability_num = CIA_high

            # Calcul du score d'exploitabilité et assignation dans la variable exp_score
            exp_score = calcul_score_exploitabilité(attack_vector, attack_complexity, privileges_required, user_interaction)

            # Calcul du score environnemental et assignation dans la variable env_score
            env_score = calcul_score_environnemental(1.5, 0.5, 0.5, availability_num, integrity_num, confidentiality_num, scope, attack_vector, attack_complexity, privileges_required, user_interaction)

            # Déterminer si la CVE est une KEV
            if id in kev_data : kev = "YES"
            else: kev = "NO"

            if "YES" in kev:
                p1.append(exp_score)
            else:
                definitionPx(p2, p3, p4, p5, env_score, exp_score)

            # Création d'une classe pour la CVE
            vuln = CVE(
                id=id,
                composant_ref=composant_ref,
                description=description,
                severity=severity,
                score_CVSS=score_CVSS,
                attack_vector=attack_vector,
                attack_complexity=attack_complexity,
                privileges_required=privileges_required,
                user_interaction=user_interaction,
                scope=scope,
                confidentiality=confidentiality,
                integrity=integrity,
                availability=availability,
                exp_score=exp_score,
                env_score=env_score,
                kev=kev
            )

            list_vulnerabilities.append(vuln)
    
    # Insert vulnerabilities for the current vdr_data
    for vuln in list_vulnerabilities:
        cur.execute("""
            INSERT INTO jaka.micro(
                bs_id, cve_id, bom_ref, composant_ref, severity, score_cvss, attack_vector, attack_complexity, privileges_required, user_interaction, scope, impact_confidentiality, impact_integrity, impact_availability, exp_score, KEV
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (bs_id, cve_id) DO NOTHING;
        """, (bs_id, vuln.id, serialNumber, vuln.composant_ref, vuln.severity, vuln.score_CVSS, vuln.attack_vector, vuln.attack_complexity, vuln.privileges_required, vuln.user_interaction, vuln.scope, vuln.confidentiality, vuln.integrity, vuln.availability, vuln.exp_score, vuln.kev
        ))

# Fonction permettant de calculer le score environnemental
def calcul_score_environnemental(disponibiliteVM, integriteVM, confidentialiteVM, availability, integrity, confidentiality, scope, attack_vector, attack_complexity, privileges_required, user_interaction):
    try:
        disponibiliteVM = float(disponibiliteVM)
        integriteVM = float(integriteVM)
        confidentialiteVM = float(confidentialiteVM)
        availability = float(availability)
        integrity = float(integrity)
        confidentiality = float(confidentiality)
        attack_vector = float(attack_vector)
        attack_complexity = float(attack_complexity)
        privileges_required = float(privileges_required)
        user_interaction = float(user_interaction)
    except ValueError as e:
        print(f"Erreur de conversion: {e}")
        return None  # ou une valeur par défaut

    # Définition de la valeur scope
    if "U" in scope:
        modified_impact = 6.42 * min(1 - (1 - disponibiliteVM * availability) * (1 - integriteVM * integrity) * (1 - confidentialiteVM * confidentiality), 0.915)
    elif "C" in scope:
        modified_impact = 7.52 * (min(1 - (1 - disponibiliteVM * availability) * (1 - integriteVM * integrity) * (1 - confidentialiteVM * confidentiality), 0.915) - 0.029) - 3.25 * (((min(1 - (1 - disponibiliteVM * availability) * (1 - integriteVM * integrity) * (1 - confidentialiteVM * confidentiality), 0.915)) * 0.9731 - 0.02) ** 13)
    
    modified_exploitability = 8.22 * attack_vector * attack_complexity * privileges_required * user_interaction

    if "U" in scope:
        env_score = round(min(modified_impact + modified_exploitability, 10), 2)
    elif "C" in scope:
        env_score = round(min(1.08 * (modified_impact + modified_exploitability), 10), 2)
    
    return env_score


def option_5_calcul_scores():
    # Dictionnaire pour stocker les scores par bs_id et cve_id
    scores_dict = {}

    # Récupération des données
    cur.execute("""
        SELECT 
            bs_id,
            cve_id,
            C_heritage, 
            I_heritage, 
            a_heritage, 
            impact_confidentiality, 
            impact_integrity, 
            impact_availability, 
            scope, 
            attack_vector, 
            attack_complexity, 
            privileges_required, 
            user_interaction 
        FROM 
            jaka.micro
        ORDER BY 
            bs_id, cve_id;
    """)
    rows = cur.fetchall()

    if len(rows) == 0:
        print("Aucune donnée à traiter.")
        return

    # Traitement de chaque ligne
    for row in rows:
        (bs_id, cve_id, C_heritage, I_heritage, a_heritage, 
         impact_confidentiality, impact_integrity, impact_availability, 
         scope, attack_vector, attack_complexity, 
         privileges_required, user_interaction) = row
        
        # Conversion des valeurs textuelles en numériques
        impact_availability_num = convert_cia_to_numeric(impact_availability)
        impact_integrity_num = convert_cia_to_numeric(impact_integrity)
        impact_confidentiality_num = convert_cia_to_numeric(impact_confidentiality)

        try:
            # Calcul du score environnemental
            env_score = calcul_score_environnemental(
                a_heritage, I_heritage, C_heritage, 
                impact_availability_num, impact_integrity_num, impact_confidentiality_num, 
                scope, attack_vector, attack_complexity, 
                privileges_required, user_interaction
            )

            # Stockage des scores
            if bs_id not in scores_dict:
                scores_dict[bs_id] = {}
            
            scores_dict[bs_id][cve_id] = env_score

        except Exception as e:
            print(f"Erreur lors du calcul pour {bs_id}, {cve_id}: {e}")

    # Mise à jour de la base de données
    for bs_id, cve_scores in scores_dict.items():
        for cve_id, env_score in cve_scores.items():
            cur.execute("""
                UPDATE jaka.micro
                SET env_score = %s
                WHERE bs_id = %s AND cve_id = %s;
            """, (env_score, bs_id, cve_id))

# Fonctions de conversion des valeurs d'impact CIA en valeurs numériques
def convert_cia_to_numeric(value):
    #Convertit les valeurs d'impact CIA en valeurs numériques
    if value == 'N': return 0  # None
    elif value == 'L': return 0.22  # Low
    elif value == 'H': return 0.56  # High
    return 0

# Liaison du bs_id 'cpn-mab-échanges' à la VM 'Server' dans la table jointure
def link(bs_id, vm_id):
#rajouter un WHERE pour null pour éviter les doublons | créer une fonction indé qui permet la demande de prendre la valeur max des CIA requirements des vm
# dès lors qu'un micro service a pls vm associées = done 
    cur.execute(f"""
    UPDATE jaka.jointure 
    SET vm_id = '{vm_id}'
    WHERE bs_id = '{bs_id}' AND vm_id IS NULL
;
""")

# Fonction permettant d'ouvrir le fivhier KEV pour lecture
def open_kev():
    file_path = filedialog.askopenfilename(filetypes=[("JSON files", "*.json")])
    if file_path:
        with open(file_path, 'r') as file:
            kev = json.load(file)
        return kev
    return None

# Fonction permettant de trier dans le Px associé les scores d'exploitabilité si NON KEV
def definitionPx(p2, p3, p4, p5, scoreEnv, scoreExp):
    if 9.0 <= scoreEnv <= 10:
        p2.append(scoreExp)
    elif 7.0 <= scoreEnv <= 8.9:
        p3.append(scoreExp)
    elif 4.0 <= scoreEnv <= 6.9:
        p4.append(scoreExp)
    elif 0.1 <= scoreEnv <= 3.9:
        p5.append(scoreExp)
    else: pass
    
    return (p2, p3, p4, p5)

# Fonction permettant de crer les boites a moustache des Microservices
def boite(boite_path):
    cur.execute("SELECT DISTINCT bs_id FROM jaka.micro;")
    bs = cur.fetchall()
    liste_dia = ["confidentiality", "integrity", "availability"]
    for i in range (len(liste_dia)):
        for b in bs:
            b = b[0]
            cur.execute("""
                SELECT cve_id 
                FROM jaka.micro 
                WHERE bs_id = %s AND kev = 'YES';
            """, (b,))

            kev = cur.fetchall()
            kev_data = {row[0] for row in kev}

            cur.execute(f"""
                SELECT cve_id, exp_score, env_score 
                FROM jaka.micro 
                WHERE bs_id = %s AND impact_{liste_dia[i]} != 'N';
            """, (b,))
            #faire une triple boucle for en ajoutant dans un WHERE où confidentialité != N , intégrité != N et disponibilité != N
            data = cur.fetchall()

            p1 = []
            p2 = []
            p3 = []
            p4 = []
            p5 = []

            for id, exp_score, env_score in data:
                if id in kev_data:
                    p1.append(exp_score)
                else:
                    p2, p3, p4, p5 = definitionPx(p2, p3, p4, p5, env_score, exp_score)

            data = [p5, p4, p3, p2, p1]
            impact_key = f"{b}-{liste_dia[i]}"
            dicoListePx[impact_key] = data


            positions = [1, 2, 3, 4, 5]
            labels = ["P5", "P4", "P3", "P2", "P1"]
            data_filtree = [d if isinstance(d, list) and len(d) > 0 else [] for d in data]

            # Obtenir la date de creation de la boite pour affichage dans le nom du fichier cree
            now = datetime.now()
            date = now.strftime("%d.%m.%Y")

            # Charger l'image de fond
            im = plt.imread("fond.png")

            # Créer une figure et un axe avec la taille spécifiée
            fig, ax = plt.subplots(figsize=(10, 5))

            # Ajouter l'image de fond à l'axe
            ax.imshow(im, extent=[0, 4, 0.5, 5.5], aspect='auto', alpha=0.5, zorder=0)

            # Ajouter le boxplot sur le même axe
            ax.boxplot(data_filtree, vert=False, positions=positions, patch_artist=False, showfliers=False, zorder=1)
            box = ax.boxplot(data_filtree, vert=False, positions=positions, patch_artist=False, showfliers=False, zorder=1)

            # Ajouter quadrillage sur l'axe des abscisses
            ax.grid(axis='x', linestyle='--', linewidth=0.5, color='gray', alpha=0.7)

            # Mettre la mediane en rouge
            for median in box['medians'] :
                median.set_color('red')
                median.set_linewidth(3)

            # Supprimer les bordures droite et haute pour une meilleur visibilite
            ax.spines['right'].set_visible(False)
            ax.spines['top'].set_visible(False)

            # Ajouter les étiquettes, titre et limites
            ax.set_title(f'{b} ({liste_dia[i]})')
            ax.set_ylabel("Sévérité")
            ax.set_xlabel("Score d'exploitabilité")
            ax.set_xlim(0, 4)
            ax.set_ylim(0.5, 5.5)  # Ajusté pour correspondre à l'image de fond
            ax.set_yticks(positions)
            ax.set_yticklabels(labels)
            # Sauvegarder la figure
            plt.savefig(f'{boite_path}\\{b}-{liste_dia[i]} {date}.png', format='png', dpi=300)

def boite_vm(vm_id, folder_path):
    liste_dia = ["confidentiality", "integrity", "availability"]
    cur.execute("""
        SELECT j.bs_id
        FROM jaka.jointure j
        WHERE j.vm_id = %s;
    """, (vm_id,))

    rows = cur.fetchall()
    p1t = {'confidentiality': [], 'integrity': [], 'availability': []}
    p2t = {'confidentiality': [], 'integrity': [], 'availability': []}
    p3t = {'confidentiality': [], 'integrity': [], 'availability': []}
    p4t = {'confidentiality': [], 'integrity': [], 'availability': []}
    p5t = {'confidentiality': [], 'integrity': [], 'availability': []}

    for row in rows:
        bs_id = row[0]
        
        for impact in liste_dia:
            impact_key = f"{bs_id}-{impact}"
            if impact_key in dicoListePx:
                p5t[impact].extend(dicoListePx[impact_key][0])
                p4t[impact].extend(dicoListePx[impact_key][1])  
                p3t[impact].extend(dicoListePx[impact_key][2])  
                p2t[impact].extend(dicoListePx[impact_key][3])  
                p1t[impact].extend(dicoListePx[impact_key][4])
    data = {}

    for impact in liste_dia:
        p1, p2, p3, p4, p5 = [], [], [], [], []
        p5.extend(p5t[impact])
        p4.extend(p4t[impact])
        p3.extend(p3t[impact])
        p2.extend(p2t[impact])
        p1.extend(p1t[impact])
        
        data[impact] = [p5, p4, p3, p2, p1]

    for impact in liste_dia:
        positions = [1, 2, 3, 4, 5]
        labels = ["P5", "P4", "P3", "P2", "P1"]
        data_filtree = [d if len(d) > 0 else [] for d in data[impact]]

        now = datetime.now()
        date = now.strftime("%d.%m.%Y")
        im = plt.imread("fond.png")
        fig, ax = plt.subplots(figsize=(10, 5))
        ax.imshow(im, extent=[0, 4, 0.5, 5.5], aspect='auto', alpha=0.5, zorder=0)

        ax.boxplot(data_filtree, vert=False, positions=positions, patch_artist=False, showfliers=False, zorder=1)
        box = ax.boxplot(data_filtree, vert=False, positions=positions, patch_artist=False, showfliers=False, zorder=1)

        ax.grid(axis='x', linestyle='--', linewidth=0.5, color='gray', alpha=0.7)

        for median in box['medians']:
            median.set_color('red')
            median.set_linewidth(3)

        ax.spines['right'].set_visible(False)
        ax.spines['top'].set_visible(False)
        ax.set_title(f'{vm_id} - {impact.capitalize()}')
        ax.set_ylabel("Sévérité")
        ax.set_xlabel("Score d'exploitabilité")
        ax.set_xlim(0, 4.1)
        ax.set_ylim(0.5, 5.5)
        ax.set_yticks(positions)
        ax.set_yticklabels(labels)
        name = f"{vm_id}-{impact}-{date}"
        plt.savefig(f'{folder_path}\\{name}.png', format='png', dpi=300)
        plt.close(fig)

    # Afficher le graphique
    #plt.show()

def open_files():
    file_paths = filedialog.askopenfilenames(filetypes=[("JSON files", "*.json")])
    data_list = []
    for file_path in file_paths:
        with open(file_path, 'r', encoding="utf-8") as file:
            data = json.load(file)
            data_list.append(data)
    return data_list

if __name__ == "__main__":
    root = Tk()
    root.withdraw()  # Cache la fenêtre principale
    while True:
        print("Choisir une étape:\n")
        print("1. Sélectionner un Vulnerability Disclosure Report (VDR) et le fichier Known Exploited Vulnerabilities Catalog (KEV)")
        #import de masse VDR + import unique du catalogue KEV -> done
        print(" Lier un bien support (BS) [microservice] à une valeur métier (VM)")
        print(" Mettre à jour la surface d'attaque d'un bien support (BS) [microservice]")
        #passe en backend (clés primaires clés étrangères dans 'jointure') -> done
        print("------------------------------------")
        print("2. Affecter les valeurs DIC à un bien support (BS) [microservice] en fonction de la valeur métier (VM)")
        print("3. Calculer le score environnemental de chaque bien support (BS) [microservice]")
        print("------------------------------------")
        print("4. Afficher le traitement statistique descriptif des risques concernant les bien supports (BS) [microservice]")
        print("5. Afficher les boîtes à moustache VM")
        #en masse
        #valeur métier (même que option6)
        #harmoniser CIA pas DIC
        #créer des vues pour voir les micro et vm qui ne sont pas liés dans 'jointure' et les afficher
        print("6. Quitter")

        option = input("Etape: ")
        if option == "5":
            if not dicoListePx:
                print("Please run option 4 first to populate data.")
                continue
            folder_path = filedialog.askdirectory()
            if not folder_path:
                print("No folder selected.")
                continue
            cur.execute("SELECT DISTINCT vm_id FROM jaka.jointure;")
            v = cur.fetchall()
            for vid in v:
                vid = vid[0]
                boite_vm(vid, folder_path)
            
        if option == "1":
            vdr_data_list = open_files()
            kev_data = open_kev()
            if not vdr_data_list:
                print("No .json files selected or files are empty.")
                exit()

            # Liste pour stocker les CVE parsées

            for vdr_data in vdr_data_list:
                # Accès aux données du VDR.json et parsing des variables
                bs_id = vdr_data.get('metadata', {}).get('component', {}).get('name')
                serialNumber = vdr_data.get('serialNumber')
                #ajouter le bs_id dans jointure
                cur.execute(f"""
                    INSERT INTO jaka.jointure (bs_id)
                    VALUES ('{bs_id}');
                """)

                parsing(vdr_data, kev_data)

            # Création de la VM 'Server' dans la table VM
            # cur.execute("""
            #     INSERT INTO jaka.vm (name, A, C, I)
            #     VALUES ('Server', 1, 0, 1),
            #         ('Client', 3, 1, 0),
            #         ('Network', 1, 1, 4),
            #         ('Test', 1, 1.5, 1.5);
            # """)

            #Drop les views
            # cur.execute("""
            #     DROP VIEW IF EXISTS jaka.impact_confidentiality CASCADE;
            #     DROP VIEW IF EXISTS jaka.impact_integrity CASCADE;
            #     DROP VIEW IF EXISTS jaka.impact_availability CASCADE;
            # """)

            cur.execute("""
                CREATE OR REPLACE VIEW jaka.impact_confidentiality AS
                SELECT * FROM jaka.micro
                WHERE impact_confidentiality != 'N';
            """)

            cur.execute("""
                CREATE OR REPLACE VIEW jaka.impact_integrity AS
                SELECT * FROM jaka.micro
                WHERE impact_integrity != 'N';
            """)

            cur.execute("""
                CREATE OR REPLACE VIEW jaka.impact_availability AS
                SELECT * FROM jaka.micro
                WHERE impact_availability != 'N';
            """)

            conn.commit()

        

            #changer bom_ref en composant_ref = done
            #arrondir aux décimales 10^-1 les valeur de exp_score = done
            #quand un microservice est lié à pls VM, prendre la valeur max des CIA requirements des VM (si C vaut 3 dans la vm network et 2 dans la vm client, alors C vaut 3 pour le microservice)
            # |
            # |
            # -->done

        elif option == "2":
            update_micro_heritage()
            print("Valeurs D, C, I mises à jour dans micro en fonction de la VM associée.")
            conn.commit()

        elif option == "3":
            print("Assurez-vous que les valeurs D, C, I dans la table micro sont à jour en fonction de la valeur métier associée")
            
            option_5_calcul_scores()
            
            print("Scores environnementaux mis à jour.")
            conn.commit()
            
        elif option == "4":
            print("Affichage boîte à moustache")      
            #dans boite et boite_vm, j'ai besoin de générer pour chaque bien support 3 fichiers de boîte à moustache, chacune qui s'assure que impact_availability != N; impact_confidentiality != N et impact_integrity != N      
            boite_path = filedialog.askdirectory()
            if not boite_path:
                print("No folder selected.")
                continue
            boite(boite_path)

        elif option == "6":
            exit()
            cur.close()
            conn.close()