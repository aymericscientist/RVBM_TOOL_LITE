import json  # Module pour lire, écrire et manipuler des données au format JSON.
from tkinter import *  # Module pour créer des interfaces graphiques (fenêtres, boutons, etc.).
from tkinter import filedialog  # Module pour ouvrir des boîtes de dialogue de sélection de fichiers ou de dossiers.
import matplotlib.pyplot as plt  # Bibliothèque pour générer des graphiques et visualiser des données.
import pandas as pd  # Bibliothèque pour manipuler et analyser des données sous forme de tableaux (DataFrames).
from contextlib import ExitStack  # Module pour gérer plusieurs contextes de manière sécurisée (fichiers, connexions, etc.).
import math  # Module intégré pour des opérations mathématiques (fonctions trigonométriques, logarithmes, etc.).
from datetime import datetime  # Module pour manipuler des dates et heures.
import openpyxl  # Bibliothèque pour lire, écrire et manipuler des fichiers Excel au format `.xlsx`.
import os  # Module pour interagir avec le système de fichiers et les chemins.
from pysqlcipher3 import dbapi2 as sqlite3  # Module pour chiffrer et déchiffrer des bases de données SQLite avec SQLCipher.

conn = sqlite3.connect("rbvm.db")
# Demander à l'utilisateur de saisir la clé PRAGMA pour SQLCipher
key = input("Entrez la clé pour SQLCipher: ")
# Appliquer la clé PRAGMA chiffrée à la connexion SQLite
conn.execute(f"PRAGMA key = '{key}';")
conn.execute("PRAGMA foreign_keys = ON;")
cur = conn.cursor()

# Création de la table valeurs_metiers avec contraintes d'unicité sur les propriétés C (confidentialité), I (intégrité) et A (disponibilité)
cur.execute("""
      CREATE TABLE IF NOT EXISTS valeurs_metiers(
        name TEXT PRIMARY KEY,
        C REAL,
        I REAL,
        A REAL      
      );
""")

# Création de la table biens_supports avec les informations en provenance du fichier VDR
cur.execute("""
    CREATE TABLE IF NOT EXISTS biens_supports(
        bs_id TEXT NOT NULL, 
        cve_id TEXT,
        bom_ref TEXT,
        composant_ref TEXT,
        severity TEXT,
        score_cvss REAL,
        attack_vector REAL,
        attack_complexity REAL,
        privileges_required REAL,
        user_interaction REAL,
        scope TEXT,
        impact_confidentiality TEXT,
        impact_integrity TEXT,
        impact_availability TEXT,
        exp_score REAL,
        env_score REAL,
        KEV TEXT,
        C_heritage REAL,
        I_heritage REAL,
        A_heritage REAL,
        PRIMARY KEY (bs_id, cve_id)
    );
""")

cur.execute("""
    CREATE TABLE IF NOT EXISTS jointure(
    num    INTEGER PRIMARY KEY AUTOINCREMENT,
    bs_id  TEXT NOT NULL,
    vm_id  TEXT,
    FOREIGN KEY (vm_id) REFERENCES valeurs_metiers(name)
);
""")

# Mettre à jour les valeurs C (confidentialité), I (intégrité) et A (disponibilité) dans biens_supports en fonction de la valeur métier associée
def update_micro_heritage():
    cur.execute("""
        UPDATE biens_supports
        SET 
            C_heritage = (
                SELECT MAX(vm.C)
                FROM jointure j
                JOIN valeurs_metiers vm ON j.vm_id = vm.name
                WHERE j.bs_id = biens_supports.bs_id
            ),
            I_heritage = (
                SELECT MAX(vm.I)
                FROM jointure j
                JOIN valeurs_metiers vm ON j.vm_id = vm.name
                WHERE j.bs_id = biens_supports.bs_id
            ),
            A_heritage = (
                SELECT MAX(vm.A)
                FROM jointure j
                JOIN valeurs_metiers vm ON j.vm_id = vm.name
                WHERE j.bs_id = biens_supports.bs_id
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
folder_BS_VERT = None
folder_BS_ORANGE = None
folder_BS_ROUGE = None
folder_VM_VERT = None
folder_VM_ORANGE = None
folder_VM_ROUGE = None
folder_VM_META = None

# Dictionnaire permettant de stocker les biens supports ainsi que leurs valeurs P1, P2, P3, P4, P5,
dicoListePx = {}

dicoC = {'p5':[], 'p4':[], 'p3':[], 'p2':[], 'p1':[]}
dicoI = {'p5':[], 'p4':[], 'p3':[], 'p2':[], 'p1':[]}
dicoA = {'p5':[], 'p4':[], 'p3':[], 'p2':[], 'p1':[]}

dicoGlobal = {"confidentiality": dicoC, "integrity": dicoI, "availability": dicoA}

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

# Fonction permettant de trier le nombre de CVE en vert, orange et rouge en fonction de chaque P(x)
def triAffichageVOR(p1, p2, p3, p4, p5, p1Vert, p1Orange, p1Rouge, p2Vert, p2Orange, p2Rouge, p3Vert, p3Orange, p4Vert, p4Orange, p5Vert):
    for score in p1:
        if 0 <= score <= 0.4:
            p1Vert += 1
        elif 0.5 <= score <= 1.4:
            p1Orange += 1
        else:
            p1Rouge += 1
    
    for score in p2:
        if 0 <= score <= 0.4:
            p2Vert += 1
        elif 0.5 <= score <= 2.4:
            p2Orange += 1
        else:
            p2Rouge += 1
    
    for score in p3:
        if 0 <= score <= 1.4:
            p3Vert += 1
        else:
            p3Orange += 1

    for score in p4:
        if 0 <= score <= 2.4:
            p4Vert += 1
        else:
            p4Orange += 1

    for score in p5:
        p5Vert += 1
    
    return (p1Vert, p1Orange, p1Rouge, p2Vert, p2Orange, p2Rouge, p3Vert, p3Orange, p4Vert, p4Orange, p5Vert)


# Fonction de decomposition analytique du VDR
def parsing(vdr_data, kev_data) :
    p1 = []
    p2 = []
    p3 = []
    p4 = []
    p5 = []
    list_vulnerabilities = []
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
            if "CVSSv3" in method:
                attack_vector, attack_complexity, privileges_required, user_interaction, scope, confidentiality, integrity, availability = var_environnementales_CVSSv3(svector)
            elif "other" in method:
                attack_vector, attack_complexity, privileges_required, user_interaction, scope, confidentiality, integrity, availability = var_environnementales_other(svector)
                vuln_other = CVE_others(
                    id=id,
                    composant_ref=composant_ref,
                    description=description,
                    severity=severity)
                cur.execute("""INSERT INTO biens_supports(bs_id, cve_id, bom_ref, composant_ref, severity) 
                            VALUES (?, ?, ?, ?, ?) 
                            ON CONFLICT (bs_id, cve_id) DO NOTHING;
                            """, (bs_id, vuln_other.id, serialNumber, vuln_other.composant_ref, vuln_other.severity))
                continue


            # Initialisation du score d'exploitabilité
            exp_score = None
            
            # variables attack vector
            AV_network = 0.85
            AV_adjacent = 0.62
            AV_local = 0.55
            AV_physical = 0.2
            
            # variables attack complexity
            AC_low = 0.77
            AC_high = 0.44
            
            # variables privileges_required
            PR_none = 0.85
            PR_low = 0.62
            PR_high = 0.27
            
            # variables user interaction
            UI_none = 0.85
            UI_required = 0.62
            
            # variables confidencialité, intégrité, disponibilité
            CIA_none = 0
            CIA_low = 0.22
            CIA_high = 0.56
            
            # Définition de la valeur de l'attack vector
            if "N" in attack_vector:attack_vector = AV_network
            elif "A" in attack_vector:attack_vector = AV_adjacent
            elif "L" in attack_vector:attack_vector = AV_local
            elif "P" in attack_vector:attack_vector = AV_physical
            else: attack_vector = None
            
            # Définition de la valeur de l'attack complexity
            if "L" in attack_complexity:attack_complexity = AC_low
            elif "H" in attack_complexity:attack_complexity = AC_high
            else: attack_complexity = None
            
            # Définition de la valeur des privileges required
            if "N" in privileges_required:privileges_required = PR_none
            elif "L" in privileges_required:privileges_required = PR_low
            elif "H" in privileges_required:privileges_required = PR_high
            else: privileges_required = None
           
           # Définition de la valeur du user interaction
            if "N" in user_interaction:user_interaction = UI_none
            elif "R" in user_interaction:user_interaction = UI_required
            else: user_interaction = None
           
           # Définition de la valeur confidencialité, intégrité, disponibilité
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
    
    for vuln in list_vulnerabilities:
        cur.execute("""
            INSERT INTO biens_supports(
                bs_id, cve_id, bom_ref, composant_ref, severity, score_cvss, attack_vector, attack_complexity, privileges_required, user_interaction, scope, impact_confidentiality, impact_integrity, impact_availability, exp_score, KEV
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            A_heritage, 
            impact_confidentiality, 
            impact_integrity, 
            impact_availability, 
            scope, 
            attack_vector, 
            attack_complexity, 
            privileges_required, 
            user_interaction 
        FROM 
            biens_supports
        ORDER BY 
            bs_id, cve_id;
    """)
    rows = cur.fetchall()

    if len(rows) == 0:
        print("Aucune donnée à traiter.")
        return

    # Traitement de chaque ligne
    for row in rows:
        (bs_id, cve_id, C_heritage, I_heritage, A_heritage, 
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
                A_heritage, I_heritage, C_heritage, 
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
                UPDATE biens_supports
                SET env_score = ?
                WHERE bs_id = ? AND cve_id = ?;
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
    cur.execute(f"""
    UPDATE jointure 
    SET vm_id = '{vm_id}'
    WHERE bs_id = '{bs_id}' AND vm_id IS NULL
;
""")

# Fonction permettant d'ouvrir le fivhier KEV pour lecture
def open_kev():
    file_path = filedialog.askopenfilename(filetypes=[("JSON files", "*.json")])
    if (file_path):
        with open(file_path, 'r') as file:
            kev = json.load(file)
        return kev
    return None

# Fonction permettant de trier dans le Px associé les scores d'exploitabilité si NON KEV
def definitionPx(p2, p3, p4, p5, scoreEnv, scoreExp):
    if 9.0 <= scoreEnv <= 10.0:
        p2.append(scoreExp)
    elif 7.0 <= scoreEnv <= 8.9:
        p3.append(scoreExp)
    elif 4.0 <= scoreEnv <= 6.9:
        p4.append(scoreExp)
    elif 0.1 <= scoreEnv <= 3.9:
        p5.append(scoreExp)
    else: pass
    
    return (p2, p3, p4, p5)

# Fonction permettant de créer les boites à moustache des Microservices
def boite(boite_path):
    cur.execute("SELECT DISTINCT bs_id FROM biens_supports;")
    bs = cur.fetchall()
    liste_dia = ["confidentiality", "integrity", "availability"]
    p1Vert = 0
    p1Orange = 0
    p1Rouge = 0
    p2Vert = 0
    p2Orange = 0
    p2Rouge = 0
    p3Vert = 0
    p3Orange = 0
    p4Vert = 0
    p4Orange = 0
    p5Vert = 0
    for i in range (len(liste_dia)):
        for b in bs:
            p1Vert = 0
            p1Orange = 0
            p1Rouge = 0
            p2Vert = 0
            p2Orange = 0
            p2Rouge = 0
            p3Vert = 0
            p3Orange = 0
            p4Vert = 0
            p4Orange = 0
            p5Vert = 0
            b = b[0]
            cur.execute("""
                SELECT cve_id 
                FROM biens_supports 
                WHERE bs_id = ? AND kev = 'YES';
            """, (b,))

            kev = cur.fetchall()
            kev_data = {row[0] for row in kev}

            cur.execute(f"""
                SELECT cve_id, exp_score, env_score 
                FROM biens_supports 
                WHERE bs_id = ? AND impact_{liste_dia[i]} != 'N';
            """, (b,))
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

            p1Vert, p1Orange, p1Rouge, p2Vert, p2Orange, p2Rouge, p3Vert, p3Orange, p4Vert, p4Orange, p5Vert = triAffichageVOR(p1, p2, p3, p4, p5, p1Vert, p1Orange, p1Rouge, p2Vert, p2Orange, p2Rouge, p3Vert, p3Orange, p4Vert, p4Orange, p5Vert)

            data = [p5, p4, p3, p2, p1]
            impact_key = f"{b}-{liste_dia[i]}"
            dicoListePx[impact_key] = data


            positions = [1, 2, 3, 4, 5]
            labels = ["P5", "P4", "P3", "P2", "P1"]
            data_filtree = [d if isinstance(d, list) and len(d) > 0 else [] for d in data]

            nbVertOrangeRouge = [
                [(f"{p5Vert}", "green")],
                [(f"{p4Vert}", "green"), (f"{p4Orange}", "orange")],
                [(f"{p3Vert}", "green"), (f"{p3Orange}", "orange")],
                [(f"{p2Vert}", "green"), (f"{p2Orange}", "orange"), (f"{p2Rouge}", "red")],
                [(f"{p1Vert}", "green"), (f"{p1Orange}", "orange"), (f"{p1Rouge}", "red")],
            ]

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

            ax.spines['right'].set_visible(False)
            ax.spines['top'].set_visible(False)

            # Ajouter les étiquettes, titre et limites
            ax.set_title(f'{b} ({liste_dia[i]})')
            ax.set_ylabel("Sévérité", labelpad=55)
            ax.set_xlabel("Score d'exploitabilité")
            ax.set_xlim(0, 4)
            ax.set_ylim(0.5, 5.5)  # Ajusté pour correspondre à l'image de fond
            ax.set_yticks(positions)
            ax.set_yticklabels(labels)

            for pos, nbVertOrangeRouge in zip(positions, nbVertOrangeRouge):
                y_pos = pos
                x_pos = -0.43
                for text, color in nbVertOrangeRouge:
                    ax.text(x_pos, y_pos, text, ha='right', va='center', fontsize=11, color=color)
                    x_pos += 0.1

            # Ajuster dynamiquement le labelpad après redimensionnement
            def update_labelpad(event):
                """Ajuster dynamiquement le labelpad du label y."""
                fig_width, _ = fig.get_size_inches()
                ax.set_ylabel("Sévérité", labelpad=fig_width * 5)  # Ajuste en fonction de la largeur

            # Connecter l'événement de redimensionnement
            fig.canvas.mpl_connect("resize_event", update_labelpad)

            # Sauvegarder la figure
            plt.savefig(f'{boite_path}\\{b}-{liste_dia[i]} {date}.png', format='png', dpi=300)
            if (p1Vert or p2Vert or p3Vert or p4Vert or p5Vert != 0) and (p1Orange == 0 and p1Rouge == 0 and p2Orange == 0 and p2Rouge == 0 and p3Orange == 0 and p4Orange == 0):
                plt.savefig(f'{folder_BS_VERT}\\{b}-{liste_dia[i]} {date}.png', format='png', dpi=300)
            if (p1Orange or p2Orange or p3Orange or p3Orange != 0) and (p1Rouge == 0 and p2Rouge == 0):
                plt.savefig(f'{folder_BS_ORANGE}\\{b}-{liste_dia[i]} {date}.png', format='png', dpi=300)
            if p1Rouge or p2Rouge != 0:
                plt.savefig(f'{folder_BS_ROUGE}\\{b}-{liste_dia[i]} {date}.png', format='png', dpi=300)

def boite_vm(vm_id, folder_path):
    liste_dia = ["confidentiality", "integrity", "availability"]
    cur.execute("""
        SELECT j.bs_id
        FROM jointure j
        WHERE j.vm_id = ?;
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
        p1 = data[impact][4]
        p2 = data[impact][3]
        p3 = data[impact][2]
        p4 = data[impact][1]
        p5 = data[impact][0]

        if impact == "confidentiality":
            dicoC["p5"].extend(p5)
            dicoC["p4"].extend(p4)
            dicoC["p3"].extend(p3)
            dicoC["p2"].extend(p2)
            dicoC["p1"].extend(p1)
        elif impact == "integrity":
            dicoI["p5"].extend(p5)
            dicoI["p4"].extend(p4)
            dicoI["p3"].extend(p3)
            dicoI["p2"].extend(p2)
            dicoI["p1"].extend(p1)
        elif impact == "availability":
            dicoA["p5"].extend(p5)
            dicoA["p4"].extend(p4)
            dicoA["p3"].extend(p3)
            dicoA["p2"].extend(p2)
            dicoA["p1"].extend(p1)

        p1Vert = 0
        p1Orange = 0
        p1Rouge = 0
        p2Vert = 0
        p2Orange = 0
        p2Rouge = 0
        p3Vert = 0
        p3Orange = 0
        p4Vert = 0
        p4Orange = 0
        p5Vert = 0

        p1Vert, p1Orange, p1Rouge, p2Vert, p2Orange, p2Rouge, p3Vert, p3Orange, p4Vert, p4Orange, p5Vert = triAffichageVOR(p1, p2, p3, p4, p5, p1Vert, p1Orange, p1Rouge, p2Vert, p2Orange, p2Rouge, p3Vert, p3Orange, p4Vert, p4Orange, p5Vert)

        positions = [1, 2, 3, 4, 5]
        labels = ["P5", "P4", "P3", "P2", "P1"]
        data_filtree = [d if len(d) > 0 else [] for d in data[impact]]

        nbVertOrangeRouge = [
            [(f"{p5Vert}", "green")],
            [(f"{p4Vert}", "green"), (f"{p4Orange}", "orange")],
            [(f"{p3Vert}", "green"), (f"{p3Orange}", "orange")],
            [(f"{p2Vert}", "green"), (f"{p2Orange}", "orange"), (f"{p2Rouge}", "red")],
            [(f"{p1Vert}", "green"), (f"{p1Orange}", "orange"), (f"{p1Rouge}", "red")],
        ]

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
        ax.set_ylabel("Sévérité", labelpad=55)
        ax.set_xlabel("Score d'exploitabilité")
        ax.set_xlim(0, 4.1)
        ax.set_ylim(0.5, 5.5)
        ax.set_yticks(positions)
        ax.set_yticklabels(labels)
        name = f"{vm_id}-{impact}-{date}"

        for pos, nbVertOrangeRouge in zip(positions, nbVertOrangeRouge):
            y_pos = pos
            x_pos = -0.43
            for text, color in nbVertOrangeRouge:
                ax.text(x_pos, y_pos, text, ha='right', va='center', fontsize=11, color=color)
                x_pos += 0.1

        # Ajuster dynamiquement le labelpad après redimensionnement
        def update_labelpad(event):
            """Ajuster dynamiquement le labelpad du label y."""
            fig_width, _ = fig.get_size_inches()
            ax.set_ylabel("Sévérité", labelpad=fig_width * 5)  # Ajuste en fonction de la largeur

        # Connecter l'événement de redimensionnement
        fig.canvas.mpl_connect("resize_event", update_labelpad)
        plt.savefig(f'{folder_path}\\{name}.png', format='png', dpi=300)
        if (p1Vert or p2Vert or p3Vert or p4Vert or p5Vert != 0) and (p1Orange == 0 and p1Rouge == 0 and p2Orange == 0 and p2Rouge == 0 and p3Orange == 0 and p4Orange == 0):
            plt.savefig(f'{folder_VM_VERT}\\{name}.png', format='png', dpi=300)
        if (p1Orange or p2Orange or p3Orange or p3Orange != 0) and (p1Rouge == 0 and p2Rouge == 0):
            plt.savefig(f'{folder_VM_ORANGE}\\{name}.png', format='png', dpi=300)
        if p1Rouge or p2Rouge != 0:
            plt.savefig(f'{folder_VM_ROUGE}\\{name}.png', format='png', dpi=300)
        plt.close(fig)
        
def boite_vm_globale(folder_path):
    liste_dia = ["confidentiality", "integrity", "availability"]

    for impact in liste_dia:
        p1 = dicoGlobal[impact]['p1']
        p2 = dicoGlobal[impact]['p2']
        p3 = dicoGlobal[impact]['p3']
        p4 = dicoGlobal[impact]['p4']
        p5 = dicoGlobal[impact]['p5']

        p1Vert = 0
        p1Orange = 0
        p1Rouge = 0
        p2Vert = 0
        p2Orange = 0
        p2Rouge = 0
        p3Vert = 0
        p3Orange = 0
        p4Vert = 0
        p4Orange = 0
        p5Vert = 0

        p1Vert, p1Orange, p1Rouge, p2Vert, p2Orange, p2Rouge, p3Vert, p3Orange, p4Vert, p4Orange, p5Vert = triAffichageVOR(p1, p2, p3, p4, p5, p1Vert, p1Orange, p1Rouge, p2Vert, p2Orange, p2Rouge, p3Vert, p3Orange, p4Vert, p4Orange, p5Vert)

        data = [p5, p4, p3, p2, p1]

        positions = [1, 2, 3, 4, 5]
        labels = ["P5", "P4", "P3", "P2", "P1"]
        data_filtree = [d if len(d) > 0 else [] for d in data]
        nbVertOrangeRouge = [
            [(f"{p5Vert}", "green")],
            [(f"{p4Vert}", "green"), (f"{p4Orange}", "orange")],
            [(f"{p3Vert}", "green"), (f"{p3Orange}", "orange")],
            [(f"{p2Vert}", "green"), (f"{p2Orange}", "orange"), (f"{p2Rouge}", "red")],
            [(f"{p1Vert}", "green"), (f"{p1Orange}", "orange"), (f"{p1Rouge}", "red")],
        ]

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
        ax.set_title(f'Meta representation VM - {impact.capitalize()}')
        ax.set_ylabel("Sévérité", labelpad=55)
        ax.set_xlabel("Score d'exploitabilité")
        ax.set_xlim(0, 4.1)
        ax.set_ylim(0.5, 5.5)
        ax.set_yticks(positions)
        ax.set_yticklabels(labels)
        name = f"Meta representation VM-{impact}-{date}"

        for pos, nbVertOrangeRouge in zip(positions, nbVertOrangeRouge):
            y_pos = pos
            x_pos = -0.43
            for text, color in nbVertOrangeRouge:
                ax.text(x_pos, y_pos, text, ha='right', va='center', fontsize=11, color=color)
                x_pos += 0.1

        # Ajuster dynamiquement le labelpad après redimensionnement
        def update_labelpad(event):
            """Ajuster dynamiquement le labelpad du label y."""
            fig_width, _ = fig.get_size_inches()
            ax.set_ylabel("Sévérité", labelpad=fig_width * 5)  # Ajuste en fonction de la largeur

        # Connecter l'événement de redimensionnement
        fig.canvas.mpl_connect("resize_event", update_labelpad)
        plt.savefig(f'{folder_VM_META}\\{name}.png', format='png', dpi=300)
        plt.close(fig)

def open_files():
    file_paths = filedialog.askopenfilenames(filetypes=[("JSON files", "*.json")])
    data_list = []
    for file_path in file_paths:
        with open(file_path, 'r', encoding="utf-8") as file:
            data = json.load(file)
            data_list.append(data)
    return data_list

def parse_excel():
    file_path = filedialog.askopenfilename(filetypes=[("Excel files", "*.xlsx")])
    if not file_path:
        print("No .xlsx file selected.")
        return

    excel = openpyxl.load_workbook(file_path)
    feuille = excel.active
    results = {}

    # Prcourir toutes les colonnes à partir de la colonne B avec col = B et row = 2 (B2)
    for col in feuille.iter_cols(min_col=2, min_row=2, values_only=False):
        col_index = col[0].column # Récupère l'index de la colonne actuelle (par ex 2 pour la colonne B).
        col_name = feuille.cell(row=1, column=col_index).value  # Récupère le nom de la colonne
        print(col_name)
        for cell in col:
            if cell.value and str(cell.value).lower() == 'oui':
                row_index = cell.row
                row_name = feuille[f"A{row_index}"].value  # Récupère la valeur de la colonne A pour cette ligne
                if col_name not in results:
                    results[col_name] = []
                if row_name not in results[col_name]:
                    results[col_name].append(row_name)

    print(results)
    cur.execute("DROP TABLE IF EXISTS jointure;")
    cur.execute("""
    CREATE TABLE IF NOT EXISTS jointure(
    num    INTEGER PRIMARY KEY AUTOINCREMENT,
    bs_id  TEXT NOT NULL,
    vm_id  TEXT,
    FOREIGN KEY (vm_id) REFERENCES valeurs_metiers(name));
                """)
    for vm_id, bs_ids in results.items():
        for bs_id in bs_ids:
            cur.execute("""
                INSERT INTO jointure (bs_id, vm_id)
                VALUES (?, ?);
            """, (bs_id, vm_id))
    

    conn.commit()
    return results

def convert_level(value):
    if not value:
        return 0
    if "E" in value:
        return 1.5
    elif "M" in value:
        return 1
    elif "L" in value:
        return 0.5
    return 0

def parse_vm():
    root = Tk()
    root.withdraw()
    file_path = filedialog.askopenfilename(filetypes=[("Excel files","*.xlsx")])
    if not file_path:
        print("No Excel file selected.")
        return

    wb = openpyxl.load_workbook(file_path)
    sheet = wb.active
    results = {}
    for row in range(3, sheet.max_row + 1):
        valeur_meiter = sheet.cell(row=row, column=8).value
        if not valeur_meiter:
            continue
        D = convert_level(str(sheet.cell(row=row, column=10).value)) # colonne J
        I = convert_level(str(sheet.cell(row=row, column=13).value)) # colonne M
        C  = convert_level(str(sheet.cell(row=row, column=15).value)) # colonne O

        results[valeur_meiter] = (D, I, C)
    
    for valeur_meiter, (D, I, C) in results.items():
        cur.execute("""
            INSERT INTO valeurs_metiers (name, A, C, I)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(name) DO UPDATE SET A=excluded.A, C=excluded.C, I=excluded.I;
        """, (valeur_meiter, D, C, I))
    conn.commit()

if __name__ == "__main__":
    root = Tk()
    root.withdraw()
    while True:
        print("Choisir une étape:\n")
        print("1. Sélectionner un ou plusieurs Vulnerability Disclosure Report (VDR) et le fichier Known Exploited Vulnerabilities Catalog (KEV)")
        print("------------------------------------")
        print("2. Lier un bien support (BS) [microservice] à une valeur métier (VM)")
        print(" Mettre à jour la surface d'attaque d'un bien support (BS) [microservice]")
        print("Affecter les valeurs DIC à un bien support (BS) [microservice] en fonction de la valeur métier (VM)")
        print("Calculer le score environnemental de chaque bien support (BS) [microservice]")
        print("------------------------------------")
        print("3. Générer le traitement statistique descriptif des risques concernant les bien supports (BS) [microservice]")
        print("4. Générer les boîtes à moustache VM")
        print("5. Quitter")

        option = input("Etape: ")
        if option == "4":
            if not dicoListePx:
                print("Please run option 2 first to populate data.")
                continue
            folder_path = filedialog.askdirectory()
            if not folder_path:
                print("No folder selected.")
                continue
            subfolder_VERT = os.path.join(folder_path, "03_VERT")
            subfolder_ORANGE = os.path.join(folder_path, "02_ORANGE")
            subfolder_ROUGE = os.path.join(folder_path, "01_ROUGE")
            subfolder_VM_META = os.path.join(folder_path, "04_Meta_représentation_des_VM")
            folder_VM_VERT = subfolder_VERT
            folder_VM_ORANGE = subfolder_ORANGE
            folder_VM_ROUGE = subfolder_ROUGE
            folder_VM_META = subfolder_VM_META
            if not os.path.exists(subfolder_VERT):
                os.makedirs(subfolder_VERT, exist_ok=True)
            if not os.path.exists(subfolder_ORANGE):
                os.makedirs(subfolder_ORANGE, exist_ok=True)
            if not os.path.exists(subfolder_ROUGE):
                os.makedirs(subfolder_ROUGE, exist_ok=True)
            if not os.path.exists(subfolder_VM_META):
                os.makedirs(subfolder_VM_META, exist_ok=True)
            cur.execute("SELECT DISTINCT vm_id FROM jointure;")
            v = cur.fetchall()
            for vid in v:
                vid = vid[0]
                boite_vm(vid, folder_path)
            boite_vm_globale(folder_path)
            
        if option == "1":
            vdr_data_list = open_files()
            kev_data = open_kev()
            if not vdr_data_list:
                print("No .json files selected or files are empty.")
                exit()

            for vdr_data in vdr_data_list:
                # Accès aux données du VDR.json et parsing des variables
                bs_id = vdr_data.get('metadata', {}).get('component', {}).get('name')
                serialNumber = vdr_data.get('serialNumber')
                parsing(vdr_data, kev_data)

            cur.execute("DROP VIEW IF EXISTS impact_confidentiality;")
            cur.execute("DROP VIEW IF EXISTS impact_integrity;")
            cur.execute("DROP VIEW IF EXISTS impact_availability;")

            cur.execute("""
                CREATE VIEW impact_confidentiality AS
                SELECT * FROM biens_supports
                WHERE impact_confidentiality != 'N';
            """)

            cur.execute("""
                CREATE VIEW impact_integrity AS
                SELECT * FROM biens_supports
                WHERE impact_integrity != 'N';
            """)

            cur.execute("""
                CREATE VIEW impact_availability AS
                SELECT * FROM biens_supports
                WHERE impact_availability != 'N';
            """)

            conn.commit()

        elif option == "2":
            print("Sélectionner le fichier excel contenant la liste des valeurs métiers (VM)")
            parse_vm()
            print("Sélectionner le fichier excel contenant la liste des biens supports (BS) associés à une valeur métier (VM)")
            parse_excel()

            update_micro_heritage()
            print("Valeurs D, C, I mises à jour dans biens_supports en fonction de la VM associée.")            
            option_5_calcul_scores()
            print("Scores environnementaux mis à jour.")
            conn.commit()
            
        elif option == "3":
            print("Affichage boîte à moustache")      
            boite_path = filedialog.askdirectory()
            if not boite_path:
                print("No folder selected.")
                continue
            subfolder_VERT = os.path.join(boite_path, "03_VERT")
            subfolder_ORANGE = os.path.join(boite_path, "02_ORANGE")
            subfolder_ROUGE = os.path.join(boite_path, "01_ROUGE")
            folder_BS_VERT = subfolder_VERT
            folder_BS_ORANGE = subfolder_ORANGE
            folder_BS_ROUGE = subfolder_ROUGE
            if not os.path.exists(subfolder_VERT):
                os.makedirs(subfolder_VERT, exist_ok=True)
            if not os.path.exists(subfolder_ORANGE):
                os.makedirs(subfolder_ORANGE, exist_ok=True)
            if not os.path.exists(subfolder_ROUGE):
                os.makedirs(subfolder_ROUGE, exist_ok=True)
            boite(boite_path)

        elif option == "5":
            cur.close()
            conn.close()
            exit()