# -*- coding: utf-8 -*-

## ==== IMPORTS  ==== ##

# Imports standards
import sys
import os
import re
import json
import math
import time
import secrets
import string
import sqlite3
import requests
from datetime import datetime
from contextlib import ExitStack

# Imports pour la gestion des fichiers et des données
import openpyxl  # Manipulation des fichiers Excel
import pandas as pd  # Manipulation et analyse de données sous forme de DataFrames
from tabulate import tabulate  # Formatage des tableaux pour l'affichage CLI

# Imports pour l'affichage graphique
import matplotlib.pyplot as plt  # Génération de graphiques

# Imports PyQt5 pour l'interface utilisateur
from PyQt5.QtWidgets import (
    QApplication,
    QMainWindow,
    QLabel,
    QLineEdit,
    QPushButton,
    QFileDialog,
    QVBoxLayout,
    QWidget,
    QGroupBox,
    QHBoxLayout,
    QProgressBar,
    QRadioButton,
    QMessageBox,
    QInputDialog,
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer

# Imports Tkinter pour les boîtes de dialogue de fichiers
from tkinter import Tk, filedialog

## ==== PARTIE N°1 Définition de l'IHM ==== ##

class RBVMTool(QMainWindow):
    def __init__(self):
        super().__init__()

        self.passphrase = self.get_secure_passphrase()
        global passphrase
        passphrase = self.passphrase
        print("\nPassphrase saisie avec succès")

        self.setWindowTitle("Risk Based Vulnerability Management (RBVM) Tool")
        self.setGeometry(200, 100, 700, 800)
        self.vdr_data_list = []  # Stocker les VDR sélectionnés
        self.kev_data = {}  # Stocker les données KEV
        self.initUI()

# Famille de fonction pour la passphrase
    def get_secure_passphrase(self):
        """Demande une passphrase avec option de génération automatique"""
        while True:
            passphrase, ok = self.ask_for_passphrase()

            if not ok:
                print("\nOpération annulée")
                sys.exit()

            if self.is_passphrase_valid(passphrase):
                print("\nPassphrase saisie avec succès")
                return passphrase
            else:
                QMessageBox.warning(
                    None,
                    "Passphrase invalide",
                    "Votre passphrase ne respecte pas les exigences !\n\n"
                    "Elle doit contenir au moins :\n"
                    "- 8 caractères\n"
                    "- 1 majuscule\n"
                    "- 1 chiffre\n"
                    "- 1 caractère spécial",
                )
    def ask_for_passphrase(self):
        """Boîte de dialogue améliorée avec option de génération automatique"""
        dialog = QMessageBox()
        dialog.setWindowTitle("Chiffrement BDD obligatoire")
        dialog.setText(
            "Veuillez saisir une passphrase forte ou en générer une automatiquement."
        )

        passphrase_input = QLineEdit()
        passphrase_input.setEchoMode(QLineEdit.Password)

        generate_button = QPushButton("Générer une passphrase forte")
        copy_button = QPushButton("Copier")

        layout = QVBoxLayout()
        layout.addWidget(passphrase_input)
        layout.addWidget(generate_button)
        layout.addWidget(copy_button)

        container = QWidget()
        container.setLayout(layout)
        dialog.layout().addWidget(container)

        generate_button.clicked.connect(
            lambda: self.generate_and_set_passphrase(passphrase_input)
        )
        copy_button.clicked.connect(
            lambda: self.copy_to_clipboard(passphrase_input.text())
        )

        ok_button = dialog.addButton("OK", QMessageBox.AcceptRole)
        cancel_button = dialog.addButton("Annuler", QMessageBox.RejectRole)

        dialog.exec_()

        if dialog.clickedButton() == ok_button:
            return passphrase_input.text(), True
        else:
            return "", False
    def generate_and_set_passphrase(self, input_field):
        """Génère une passphrase forte et l'affiche"""
        new_passphrase = self.generate_secure_passphrase()
        input_field.setText(new_passphrase)
    def copy_to_clipboard(self, text):
        """Copie la passphrase générée dans le presse-papier"""
        clipboard = QApplication.clipboard()
        clipboard.setText(text)
        QMessageBox.information(
            None, "Copié !", "Passphrase copiée dans le presse-papier."
        )
    def generate_secure_passphrase(self, length=20):
        """Génère une passphrase forte respectant les exigences minimales."""
        if length < 8:
            raise ValueError(
                "La longueur minimale de la passphrase doit être de 8 caractères."
            )

        while True:
            # Assurer la présence d'au moins un caractère de chaque catégorie requise
            upper = secrets.choice(string.ascii_uppercase)
            digit = secrets.choice(string.digits)
            special = secrets.choice("@$!%*?&")

            # Remplir le reste avec des caractères aléatoires
            characters = string.ascii_letters + string.digits + "@$!%*?&"
            remaining = "".join(secrets.choice(characters) for _ in range(length - 3))

            # Mélanger aléatoirement pour éviter un modèle fixe
            passphrase = list(upper + digit + special + remaining)
            secrets.SystemRandom().shuffle(passphrase)
            passphrase = "".join(passphrase)

            # Vérifier que la passphrase respecte les exigences
            if self.is_passphrase_valid(passphrase):
                return passphrase
    def is_passphrase_valid(self, passphrase):
        """Vérifie que la passphrase respecte les exigences"""
        return bool(
            re.match(
                r"^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$", passphrase
            )
        )

# Procédure 1 - Famille de fonctions 
    def convert_level(self, value):
        if not value:
            return 0
        if "E" in value:
            return 1.5
        elif "M" in value:
            return 1
        elif "L" in value:
            return 0.5
        return 0

    def parse_vm(self):
        root = Tk()
        root.withdraw()
        file_path = filedialog.askopenfilename(filetypes=[("Excel files", "*.xlsx")])
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

            D = self.convert_level(str(sheet.cell(row=row, column=10).value))  # colonne J
            I = self.convert_level(str(sheet.cell(row=row, column=13).value))  # colonne M
            C = self.convert_level(str(sheet.cell(row=row, column=15).value))  # colonne O

            results[valeur_meiter] = (D, I, C)

        for valeur_meiter, (D, I, C) in results.items():
            cur.execute(
                """
                INSERT INTO valeurs_metiers (name, A, C, I)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(name) DO UPDATE SET A=excluded.A, C=excluded.C, I=excluded.I;
            """,
                (valeur_meiter, D, C, I),
            )
        conn.commit() # Récupération des valeurs DIC|CVSS 3.1 pour chaque valeur métier        

# Procédure 2 - Famille de fonctions
    def parse_excel():
        file_path = filedialog.askopenfilename(filetypes=[("Excel files", "*.xlsx")])
        if not file_path:
            print("No .xlsx file selected.")
            return

        excel = openpyxl.load_workbook(file_path)
        feuille = excel.active
        results = {}

        # Parcourir toutes les colonnes à partir de la colonne B avec col = B et row = 2 (B2)
        for col in feuille.iter_cols(min_col=2, min_row=2, values_only=False):
            col_index = col[
                0
            ].column  # Récupère l'index de la colonne actuelle (par ex 2 pour la colonne B).
            col_name = feuille.cell(
                row=1, column=col_index
            ).value  # Récupère le nom de la colonne
            print(col_name)
            for cell in col:
                if cell.value and str(cell.value).lower() == "oui":
                    row_index = cell.row
                    row_name = feuille[
                        f"A{row_index}"
                    ].value  # Récupère la valeur de la colonne A pour cette ligne
                    if col_name not in results:
                        results[col_name] = []
                    if row_name not in results[col_name]:
                        results[col_name].append(row_name)

        print(results)
        cur.execute("DROP TABLE IF EXISTS jointure;")
        cur.execute(
            """
        CREATE TABLE IF NOT EXISTS jointure(
        num    INTEGER PRIMARY KEY AUTOINCREMENT,
        bs_id  TEXT NOT NULL,
        vm_id  TEXT,
        FOREIGN KEY (vm_id) REFERENCES valeurs_metiers(name));
                    """
        )
        for vm_id, bs_ids in results.items():
            for bs_id in bs_ids:
                cur.execute(
                    """
                    INSERT INTO jointure (bs_id, vm_id)
                    VALUES (?, ?);
                """,
                    (bs_id, vm_id),
                )

        conn.commit()
        return results    
    def update_micro_heritage():
        cur.execute(
            """
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
        conn.commit()
         # Mettre à jour les valeurs C (confidentialité), I (intégrité) et A (disponibilité) dans biens_supports en fonction de la valeur métier associée
    def option_5_calcul_scores():
        # Dictionnaire pour stocker les scores par bs_id et cve_id
        scores_dict = {}

        # Récupération des données
        cur.execute(
            """
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
        """
        )
        rows = cur.fetchall()

        if len(rows) == 0:
            print("Aucune donnée à traiter.")
            return

        # Traitement de chaque ligne
        for row in rows:
            (
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
                user_interaction,
            ) = row

            # Conversion des valeurs textuelles en numériques
            impact_availability_num = convert_cia_to_numeric(impact_availability)
            impact_integrity_num = convert_cia_to_numeric(impact_integrity)
            impact_confidentiality_num = convert_cia_to_numeric(impact_confidentiality)

            try:
                # Calcul du score environnemental
                env_score = calcul_score_environnemental(
                    A_heritage,
                    I_heritage,
                    C_heritage,
                    impact_availability_num,
                    impact_integrity_num,
                    impact_confidentiality_num,
                    scope,
                    attack_vector,
                    attack_complexity,
                    privileges_required,
                    user_interaction,
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
                cur.execute(
                    """
                    UPDATE biens_supports
                    SET env_score = ?
                    WHERE bs_id = ? AND cve_id = ?;
                """,
                    (env_score, bs_id, cve_id),
                )
        conn.commit()

# Procédure 3 - passe directement à la procédure n04

# Procédure 4 -  Famille de fonctions concernant la récupération et le traitement VDR + KEV
    def browse_vdr(self):
        """Ouvre une boîte de dialogue pour sélectionner des fichiers VDR et les charge."""
        try:
            file_paths, _ = QFileDialog.getOpenFileNames(
                self,
                "Sélectionner un ou plusieurs VDR",
                "",
                "JSON Files (*.json);;All Files (*)",
            )

            if not file_paths:
                return  # Aucune sélection, on ne fait rien

            self.vdr_data_list = []  # Réinitialiser la liste

            for file_path in file_paths:
                with open(file_path, "r", encoding="utf-8") as file:
                    data = json.load(file)
                    self.vdr_data_list.append(data)

            # Met à jour le champ texte avec les fichiers sélectionnés
            self.vdr_input.setText(", ".join(file_paths))

        except Exception as e:
            QMessageBox.critical(self, "Erreur", f"Erreur lors du chargement des fichiers VDR : {e}")
    def browse_kev(self):
        #"""Ouvre une boîte de dialogue pour sélectionner un fichier KEV local ou le télécharger."""
        self.automatic_download.setChecked(False)
        self.local_file_option.setChecked(True)
        QApplication.processEvents()
        if self.automatic_download.isChecked():
            self.download_kev()  # Téléchargement automatique
        elif self.local_file_option.isChecked():
            file_path, _ = QFileDialog.getOpenFileName(
                self,
                "Sélectionner le fichier KEV",
                "",
                "JSON Files (*.json);;CSV Files (*.csv);;All Files (*)",
            )

            if file_path:
                self.kev_input.setText(file_path)  # Mise à jour de l'interface
                self.load_kev_data(file_path)  # Charger les données KEV depuis le fichier sélectionné
        else:
            QMessageBox.warning(self, "Avertissement", "Veuillez sélectionner une méthode pour récupérer le fichier KEV.") # Fonction nominale pour le KEV
    def browse_kev_manual(self):    
        self.local_file_option.click() # 🔹 Simule un clic sur "Sélectionner un fichier local" pour forcer l'activation
        QApplication.processEvents() # 🔹 Forcer la mise à jour de l'UI pour s'assurer que le changement est pris en compte
        file_path, _ = QFileDialog.getOpenFileName( # 🔹 Ouvre la boîte de dialogue pour sélectionner un fichier
            self,
            "Sélectionner le fichier KEV",
            "",
            "JSON Files (*.json);;CSV Files (*.csv);;All Files (*)",
        )

        if file_path:
            self.kev_input.setText(file_path)  # Met à jour le champ texte
            self.load_kev_data(file_path)  # Fonction permettant de mettre à jour l'UI dès que l'utilisateur veut téléverser manuellement le KEV Catalog
    def download_kev(self):
        """Télécharge automatiquement le fichier KEV depuis CISA et le charge."""
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        file_path = "known_exploited_vulnerabilities.json"

        try:
            response = requests.get(url, stream=True)
            response.raise_for_status()  # Vérifie les erreurs HTTP

            with open(file_path, "wb") as file:
                for chunk in response.iter_content(1024):
                    file.write(chunk)

            self.kev_input.setText(file_path)  # Mise à jour de l'interface
            self.load_kev_data(file_path)  # Charger les données KEV après le téléchargement
            QMessageBox.information(self, "Succès", "Le fichier KEV a été téléchargé et chargé avec succès.")

        except requests.RequestException as e:
            QMessageBox.critical(self, "Erreur", f"Échec du téléchargement : {e}")
    def load_kev_data(self, file_path):
        """Charge les données KEV depuis un fichier JSON."""
        try:
            with open(file_path, "r", encoding="utf-8") as file:
                self.kev_data = json.load(file)
            print("✅ Données KEV chargées avec succès !")
        except Exception as e:
            QMessageBox.critical(self, "Erreur", f"Erreur lors du chargement du fichier KEV : {e}")
    def master_function_charger_VDR(self):
        #"""Charge les fichiers VDR, les analyse et met à jour la base de données."""
        try:
            self.browse_vdr()  # Étape 1 : Sélection des fichiers VDR

            if not self.vdr_data_list:
                QMessageBox.warning(self, "Avertissement", "Aucun fichier VDR sélectionné.")
                return  # Arrêt si aucun fichier n'est chargé

            # Vérifier la méthode choisie pour le KEV
            if self.automatic_download.isChecked():
                self.download_kev()  # Télécharge le KEV
                return  # Attendre avant de continuer
            elif self.local_file_option.isChecked():
                kev_file_path = self.kev_input.text().strip()
                if kev_file_path:
                    self.load_kev_data(kev_file_path)  # Charger le fichier KEV sélectionné
                else:
                    QMessageBox.warning(self, "Avertissement", "Aucun fichier KEV sélectionné.")
                    return  # Arrêt si aucun fichier KEV n'est fourni
            else:
                QMessageBox.warning(self, "Avertissement", "Veuillez sélectionner une méthode pour obtenir le fichier KEV.")
                return

            if not self.kev_data:
                QMessageBox.warning(self, "Avertissement", "Le fichier KEV n'a pas pu être chargé.")
                return  # Arrêt si aucun KEV n'est chargé

            # Traitement des fichiers VDR
            for vdr_data in self.vdr_data_list:
                bs_id = vdr_data.get("metadata", {}).get("component", {}).get("name")
                serialNumber = vdr_data.get("serialNumber")

                if not bs_id or not serialNumber:
                    print("⚠ VDR invalide, absence de `bs_id` ou `serialNumber`.")
                    continue  # Ignore ce fichier VDR

                self.parsing(vdr_data, self.kev_data)

            # Mise à jour des vues SQL
            self.update_sql_views()

        except Exception as e:
            QMessageBox.critical(self, "Erreur", f"Une erreur s'est produite : {e}")
    def parsing(self, vdr_data, kev_data):
        """Analyse les fichiers VDR et met à jour la base de données."""
        try:
            list_vulnerabilities = vdr_data.get("vulnerabilities", [])

            for vulnerability in list_vulnerabilities:
                cve_id = vulnerability.get("id")
                if not cve_id or "GHSA" in cve_id:
                    continue

                # Récupération des valeurs essentielles
                score_CVSS = vulnerability.get("ratings", [{}])[0].get("score")
                severity = vulnerability.get("ratings", [{}])[0].get("severity")
                method = vulnerability.get("ratings", [{}])[0].get("method")

                if not score_CVSS or "CVSSv2" in method:
                    continue

                # Vérification si c'est une CVE connue exploitée (KEV)
                kev = "YES" if cve_id in kev_data else "NO"

                # Ajout dans la base de données
                cur.execute(
                    """
                    INSERT INTO biens_supports(
                        bs_id, cve_id, severity, score_cvss, KEV
                    )
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT (bs_id, cve_id) DO NOTHING;
                    """,
                    (vdr_data.get("metadata", {}).get("component", {}).get("name"), cve_id, severity, score_CVSS, kev),
                )

            conn.commit()

        except Exception as e:
            print(f"Erreur dans `parsing()`: {e}")
    def update_sql_views(self):
        """Mise à jour des vues SQL pour les impacts (Confidentialité, Intégrité, Disponibilité)."""
        try:
            cur.execute("DROP VIEW IF EXISTS impact_confidentiality;")
            cur.execute("DROP VIEW IF EXISTS impact_integrity;")
            cur.execute("DROP VIEW IF EXISTS impact_availability;")

            cur.execute(
                """
                CREATE VIEW impact_confidentiality AS
                SELECT * FROM biens_supports
                WHERE impact_confidentiality != 'N';
                """
            )

            cur.execute(
                """
                CREATE VIEW impact_integrity AS
                SELECT * FROM biens_supports
                WHERE impact_integrity != 'N';
                """
            )

            cur.execute(
                """
                CREATE VIEW impact_availability AS
                SELECT * FROM biens_supports
                WHERE impact_availability != 'N';
                """
            )

            conn.commit()
            print("✅ Vues SQL mises à jour.")

        except Exception as e:
            print(f"Erreur lors de la mise à jour des vues SQL : {e}")

# Procédure 5 - Famille de fonctions concernant la génération des représentations des risques
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
        for i in range(len(liste_dia)):
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
                cur.execute(
                    """
                    SELECT cve_id 
                    FROM biens_supports 
                    WHERE bs_id = ? AND kev = 'YES';
                """,
                    (b,),
                )

                kev = cur.fetchall()
                kev_data = {row[0] for row in kev}

                cur.execute(
                    f"""
                    SELECT cve_id, exp_score, env_score 
                    FROM biens_supports 
                    WHERE bs_id = ? AND impact_{liste_dia[i]} != 'N';
                """,
                    (b,),
                )
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

                (
                    p1Vert,
                    p1Orange,
                    p1Rouge,
                    p2Vert,
                    p2Orange,
                    p2Rouge,
                    p3Vert,
                    p3Orange,
                    p4Vert,
                    p4Orange,
                    p5Vert,
                ) = triAffichageVOR(
                    p1,
                    p2,
                    p3,
                    p4,
                    p5,
                    p1Vert,
                    p1Orange,
                    p1Rouge,
                    p2Vert,
                    p2Orange,
                    p2Rouge,
                    p3Vert,
                    p3Orange,
                    p4Vert,
                    p4Orange,
                    p5Vert,
                )

                data = [p5, p4, p3, p2, p1]
                impact_key = f"{b}-{liste_dia[i]}"
                dicoListePx[impact_key] = data

                positions = [1, 2, 3, 4, 5]
                labels = ["P5", "P4", "P3", "P2", "P1"]
                data_filtree = [
                    d if isinstance(d, list) and len(d) > 0 else [] for d in data
                ]

                nbVertOrangeRouge = [
                    [(f"{p5Vert}", "green")],
                    [(f"{p4Vert}", "green"), (f"{p4Orange}", "orange")],
                    [(f"{p3Vert}", "green"), (f"{p3Orange}", "orange")],
                    [
                        (f"{p2Vert}", "green"),
                        (f"{p2Orange}", "orange"),
                        (f"{p2Rouge}", "red"),
                    ],
                    [
                        (f"{p1Vert}", "green"),
                        (f"{p1Orange}", "orange"),
                        (f"{p1Rouge}", "red"),
                    ],
                ]

                now = datetime.now()
                date = now.strftime("%d.%m.%Y")

                # Charger l'image de fond
                im = plt.imread("fond.png")

                # Créer une figure et un axe avec la taille spécifiée
                fig, ax = plt.subplots(figsize=(10, 5))

                # Ajouter l'image de fond à l'axe
                ax.imshow(im, extent=[0, 4, 0.5, 5.5], aspect="auto", alpha=0.5, zorder=0)

                # Ajouter le boxplot sur le même axe
                ax.boxplot(
                    data_filtree,
                    vert=False,
                    positions=positions,
                    patch_artist=False,
                    showfliers=False,
                    zorder=1,
                )
                box = ax.boxplot(
                    data_filtree,
                    vert=False,
                    positions=positions,
                    patch_artist=False,
                    showfliers=False,
                    zorder=1,
                )

                # Ajouter quadrillage sur l'axe des abscisses
                ax.grid(axis="x", linestyle="--", linewidth=0.5, color="gray", alpha=0.7)

                # Mettre la mediane en rouge
                for median in box["medians"]:
                    median.set_color("red")
                    median.set_linewidth(3)

                ax.spines["right"].set_visible(False)
                ax.spines["top"].set_visible(False)

                # Ajouter les étiquettes, titre et limites
                ax.set_title(f"{b} ({liste_dia[i]})")
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
                        ax.text(
                            x_pos,
                            y_pos,
                            text,
                            ha="right",
                            va="center",
                            fontsize=11,
                            color=color,
                        )
                        x_pos += 0.1

                # Ajuster dynamiquement le labelpad après redimensionnement
                def update_labelpad(event):
                    """Ajuster dynamiquement le labelpad du label y."""
                    fig_width, _ = fig.get_size_inches()
                    ax.set_ylabel(
                        "Sévérité", labelpad=fig_width * 5
                    )  # Ajuste en fonction de la largeur

                # Connecter l'événement de redimensionnement
                fig.canvas.mpl_connect("resize_event", update_labelpad)

                # Sauvegarder la figure
                plt.savefig(
                    f"{boite_path}\\{b}-{liste_dia[i]} {date}.png", format="png", dpi=300
                )
                if (p1Vert or p2Vert or p3Vert or p4Vert or p5Vert != 0) and (
                    p1Orange == 0
                    and p1Rouge == 0
                    and p2Orange == 0
                    and p2Rouge == 0
                    and p3Orange == 0
                    and p4Orange == 0
                ):
                    plt.savefig(
                        f"{folder_BS_VERT}\\{b}-{liste_dia[i]} {date}.png",
                        format="png",
                        dpi=300,
                    )
                if (p1Orange or p2Orange or p3Orange or p3Orange != 0) and (
                    p1Rouge == 0 and p2Rouge == 0
                ):
                    plt.savefig(
                        f"{folder_BS_ORANGE}\\{b}-{liste_dia[i]} {date}.png",
                        format="png",
                        dpi=300,
                    )
                if p1Rouge or p2Rouge != 0:
                    plt.savefig(
                        f"{folder_BS_ROUGE}\\{b}-{liste_dia[i]} {date}.png",
                        format="png",
                        dpi=300,
                    ) # Fonction permettant de créer les boites à moustache des biens supports
    def boite_vm(vm_id, folder_path):
        liste_dia = ["confidentiality", "integrity", "availability"]
        cur.execute(
            """
            SELECT j.bs_id
            FROM jointure j
            WHERE j.vm_id = ?;
        """,
            (vm_id,),
        )

        rows = cur.fetchall()
        p1t = {"confidentiality": [], "integrity": [], "availability": []}
        p2t = {"confidentiality": [], "integrity": [], "availability": []}
        p3t = {"confidentiality": [], "integrity": [], "availability": []}
        p4t = {"confidentiality": [], "integrity": [], "availability": []}
        p5t = {"confidentiality": [], "integrity": [], "availability": []}

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

            (
                p1Vert,
                p1Orange,
                p1Rouge,
                p2Vert,
                p2Orange,
                p2Rouge,
                p3Vert,
                p3Orange,
                p4Vert,
                p4Orange,
                p5Vert,
            ) = triAffichageVOR(
                p1,
                p2,
                p3,
                p4,
                p5,
                p1Vert,
                p1Orange,
                p1Rouge,
                p2Vert,
                p2Orange,
                p2Rouge,
                p3Vert,
                p3Orange,
                p4Vert,
                p4Orange,
                p5Vert,
            )

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
            ax.imshow(im, extent=[0, 4, 0.5, 5.5], aspect="auto", alpha=0.5, zorder=0)

            ax.boxplot(
                data_filtree,
                vert=False,
                positions=positions,
                patch_artist=False,
                showfliers=False,
                zorder=1,
            )
            box = ax.boxplot(
                data_filtree,
                vert=False,
                positions=positions,
                patch_artist=False,
                showfliers=False,
                zorder=1,
            )

            ax.grid(axis="x", linestyle="--", linewidth=0.5, color="gray", alpha=0.7)

            for median in box["medians"]:
                median.set_color("red")
                median.set_linewidth(3)

            ax.spines["right"].set_visible(False)
            ax.spines["top"].set_visible(False)
            ax.set_title(f"{vm_id} - {impact.capitalize()}")
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
                    ax.text(
                        x_pos,
                        y_pos,
                        text,
                        ha="right",
                        va="center",
                        fontsize=11,
                        color=color,
                    )
                    x_pos += 0.1

            # Ajuster dynamiquement le labelpad après redimensionnement
            def update_labelpad(event):
                """Ajuster dynamiquement le labelpad du label y."""
                fig_width, _ = fig.get_size_inches()
                ax.set_ylabel(
                    "Sévérité", labelpad=fig_width * 5
                )  # Ajuste en fonction de la largeur

            # Connecter l'événement de redimensionnement
            fig.canvas.mpl_connect("resize_event", update_labelpad)
            plt.savefig(f"{folder_path}\\{name}.png", format="png", dpi=300)
            if (p1Vert or p2Vert or p3Vert or p4Vert or p5Vert != 0) and (
                p1Orange == 0
                and p1Rouge == 0
                and p2Orange == 0
                and p2Rouge == 0
                and p3Orange == 0
                and p4Orange == 0
            ):
                plt.savefig(f"{folder_VM_VERT}\\{name}.png", format="png", dpi=300)
            if (p1Orange or p2Orange or p3Orange or p3Orange != 0) and (
                p1Rouge == 0 and p2Rouge == 0
            ):
                plt.savefig(f"{folder_VM_ORANGE}\\{name}.png", format="png", dpi=300)
            if p1Rouge or p2Rouge != 0:
                plt.savefig(f"{folder_VM_ROUGE}\\{name}.png", format="png", dpi=300)
            plt.close(fig) # Fonction permettant de créer les boites à moustache des valeurs métiers
    def boite_vm_globale(folder_path):
        liste_dia = ["confidentiality", "integrity", "availability"]

        for impact in liste_dia:
            p1 = dicoGlobal[impact]["p1"]
            p2 = dicoGlobal[impact]["p2"]
            p3 = dicoGlobal[impact]["p3"]
            p4 = dicoGlobal[impact]["p4"]
            p5 = dicoGlobal[impact]["p5"]

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

            (
                p1Vert,
                p1Orange,
                p1Rouge,
                p2Vert,
                p2Orange,
                p2Rouge,
                p3Vert,
                p3Orange,
                p4Vert,
                p4Orange,
                p5Vert,
            ) = triAffichageVOR(
                p1,
                p2,
                p3,
                p4,
                p5,
                p1Vert,
                p1Orange,
                p1Rouge,
                p2Vert,
                p2Orange,
                p2Rouge,
                p3Vert,
                p3Orange,
                p4Vert,
                p4Orange,
                p5Vert,
            )

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
            ax.imshow(im, extent=[0, 4, 0.5, 5.5], aspect="auto", alpha=0.5, zorder=0)

            ax.boxplot(
                data_filtree,
                vert=False,
                positions=positions,
                patch_artist=False,
                showfliers=False,
                zorder=1,
            )
            box = ax.boxplot(
                data_filtree,
                vert=False,
                positions=positions,
                patch_artist=False,
                showfliers=False,
                zorder=1,
            )

            ax.grid(axis="x", linestyle="--", linewidth=0.5, color="gray", alpha=0.7)

            for median in box["medians"]:
                median.set_color("red")
                median.set_linewidth(3)

            ax.spines["right"].set_visible(False)
            ax.spines["top"].set_visible(False)
            ax.set_title(f"Meta representation VM - {impact.capitalize()}")
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
                    ax.text(
                        x_pos,
                        y_pos,
                        text,
                        ha="right",
                        va="center",
                        fontsize=11,
                        color=color,
                    )
                    x_pos += 0.1

            # Ajuster dynamiquement le labelpad après redimensionnement
            def update_labelpad(event):
                """Ajuster dynamiquement le labelpad du label y."""
                fig_width, _ = fig.get_size_inches()
                ax.set_ylabel(
                    "Sévérité", labelpad=fig_width * 5
                )  # Ajuste en fonction de la largeur

            # Connecter l'événement de redimensionnement
            fig.canvas.mpl_connect("resize_event", update_labelpad)
            plt.savefig(f"{folder_VM_META}\\{name}.png", format="png", dpi=300)
            plt.close(fig) # Fonction permettant de créer les boites à moustache méta des valeurs métiers
    def start_conversion_MOE(self):
        print("Affichage boîte à moustache")
        boite_path = filedialog.askdirectory()
        if not boite_path:
            print("No folder selected.")
            return
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
        self.boite(boite_path)
    def start_conversion_MOA(self):
        if not dicoListePx:
            print("Données manquantes")
            return
        folder_path = filedialog.askdirectory()
        if not folder_path:
            print("No folder selected.")
            return
        subfolder_VERT = os.path.join(folder_path, "03_VERT")
        subfolder_ORANGE = os.path.join(folder_path, "02_ORANGE")
        subfolder_ROUGE = os.path.join(folder_path, "01_ROUGE")
        subfolder_VM_META = os.path.join(
            folder_path, "04_Meta_représentation_des_VM")
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
            self.boite_vm(vid, folder_path)
        self.boite_vm_globale(folder_path)

# Famille de fonctions concernant l'IHM
    def initUI(self):
        """Initialise l'interface utilisateur"""
        central_widget = QWidget()
        main_layout = QVBoxLayout()

        # Titre principal
        title = QLabel("Risk Based Vulnerability Management (RBVM) Tool", self)
        title.setStyleSheet("font-size: 20px; font-weight: bold; color: #444;")

        # 1ère étape - Intégrer les besoins de sécurité et sûreté des valeurs métiers
        security_group = QGroupBox(
            "1ère étape : Charger (excel) les valeurs métiers ainsi que leurs besoins de sécurité et sûreté [template_prerequis DIC.xlsx]"
        )
        security_layout = QHBoxLayout()
        self.security_input = QLineEdit(self)
        security_browse = QPushButton("Téléverser", self)
        security_browse.clicked.connect(self.browse_security)
        security_layout.addWidget(self.security_input)
        security_layout.addWidget(security_browse)
        security_group.setLayout(security_layout)

        # 2ème étape - Intégrer la matrice Bien Support - Valeur Métier
        matrix_group = QGroupBox(
            "2ème étape : Charger la matrice (excel) associant les biens supports aux valeurs métiers [template_matrice_vm_bs.xlsx]"
        )
        matrix_layout = QHBoxLayout()
        self.matrix_input = QLineEdit(self)
        matrix_browse = QPushButton("Téléverser", self)
        matrix_browse.clicked.connect(self.browse_matrix)
        matrix_layout.addWidget(self.matrix_input)
        matrix_layout.addWidget(matrix_browse)
        matrix_group.setLayout(matrix_layout)

        # 3ème étape - Charger le fichier KEV Catalog
        kev_group = QGroupBox(
            "3ème étape : Charger le fichier Known Exploited Vulnerabilities (KEV) Catalog du Cybersecurity & Infrastructure Security Agency (CISA)"
        )
        kev_layout = QVBoxLayout()

        self.automatic_download = QRadioButton(
            "Télécharger automatiquement depuis CISA [par défaut]", self
        )
        self.local_file_option = QRadioButton(
            "Sélectionner un fichier local (JSON/CSV)", self
        )
        self.automatic_download.setChecked(
            True
        )  # Option par défaut : Télécharger automatiquement depuis CISA

        kev_file_layout = QHBoxLayout()
        self.kev_input = QLineEdit(self)
        kev_browse = QPushButton("Téléverser", self)
        kev_browse.clicked.connect(self.browse_kev_manual)
        kev_file_layout.addWidget(self.kev_input)
        kev_file_layout.addWidget(kev_browse)

        kev_layout.addWidget(self.automatic_download)
        kev_layout.addWidget(self.local_file_option)
        kev_layout.addLayout(kev_file_layout)
        kev_group.setLayout(kev_layout)

        # 4ème étape - Charger VDR
        vdr_group = QGroupBox(
            "4ème étape : Charger tous les Vulnerability Disclosure Report (VDR) concernant l'exhaustivité des biens supports"
        )
        vdr_layout = QHBoxLayout()
        self.vdr_input = QLineEdit(self)
        vdr_browse = QPushButton("Téléverser", self)
        vdr_browse.clicked.connect(self.master_function_charger_VDR)
        vdr_layout.addWidget(self.vdr_input)
        vdr_layout.addWidget(vdr_browse)
        vdr_group.setLayout(vdr_layout)

        # Ajouter un layout horizontal pour les boutons
        buttons_layout = QHBoxLayout()

        # Bouton génération représentation des risques concernant les biens supports (RSSI)
        self.convert_button_MOE = QPushButton(
            "Générer les représentations concernant les risques liés aux biens supports (MOE)",
            self,
        )
        self.convert_button_MOE.setStyleSheet(
            "background-color: #28a745; color: white; font-size: 12px; padding: 8px;"
        )
        self.convert_button_MOE.clicked.connect(self.start_conversion_MOE)

        # Bouton génération représentation des risques concernant les valeurs métiers (CSN)
        self.convert_button_MOA = QPushButton(
            "Générer les représentations concernant les risques liés aux valeurs métiers (MOA)",
            self,
        )
        self.convert_button_MOA.setStyleSheet(
            "background-color: #28a745; color: white; font-size: 12px; padding: 8px;"
        )
        self.convert_button_MOA.clicked.connect(self.start_conversion_MOA)
        
        # Ajouter les boutons au layout horizontal
        buttons_layout.addWidget(self.convert_button_MOE)
        buttons_layout.addWidget(self.convert_button_MOA)

        # Ajout au layout principal
        main_layout.addWidget(title)
        main_layout.addWidget(security_group)  # Charger besoins de sécurité et sûreté
        main_layout.addWidget(matrix_group)  # Charger association VM & BS
        main_layout.addWidget(kev_group)  # Charger KEV
        main_layout.addWidget(vdr_group)  # Sélectionner les VDR
        main_layout.addLayout(buttons_layout)

        # Appliquer le layout principal à la fenêtre
        central_widget.setLayout(main_layout)
        self.setCentralWidget(central_widget)

        # Appliquer le style CSS
        self.setStyleSheet(
            """
            QMainWindow {
                background-color: #f4f4f4;
            }
            QLabel {
                font-size: 14px;
                color: #333;
            }
            QPushButton {
                background-color: #0078D7;
                color: white;
                font-size: 14px;
                padding: 6px;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #005BB5;
            }
            QLineEdit {
                border: 1px solid #ccc;
                padding: 5px;
                border-radius: 5px;
                background-color: white;
            }
            QProgressBar {
                border: 1px solid #bbb;
                padding: 3px;
                border-radius: 5px;
                background-color: #fff;
                text-align: center;
            }
        """
        )
    def browse_kev(self):
        """Ouvre une boîte de dialogue pour sélectionner un fichier KEV local (JSON/CSV)"""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Sélectionner un fichier KEV",
            "",
            "JSON/CSV Files (*.json *.csv);;All Files (*)",
        )
        if file_path:
            self.kev_input.setText(file_path)  # Intégrer le KEV Catalog
    def browse_matrix(self):
        """Ouvre une boîte de dialogue pour sélectionner un fichier Excel contenant la matrice BS-VM"""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Sélectionner un fichier Excel",
            "",
            "Excel Files (*.xlsx *.xls);;All Files (*)",
        )
        if file_path:
            self.matrix_input.setText(
                file_path
            )  # Intégrer la matrice valeur métier - bien support
    def browse_security(self):
        """Ouvre une boîte de dialogue pour sélectionner un fichier Excel contenant les besoins de sécurité"""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Sélectionner un fichier Excel",
            "",
            "Excel Files (*.xlsx *.xls);;All Files (*)",
        )
        if file_path:
            self.security_input.setText(
                file_path
            )  # Intégrer les besoins de sécurité et sûreté des valeurs métiers

if __name__ == "__main__":
    import sys

    app = QApplication(sys.argv)
    fenetre = RBVMTool()
    fenetre.show()

    ## ==== prérequis BDD du programme ==== ##
    conn = sqlite3.connect("rbvm.db")  # Connexion à la base de données SQLite chiffrée avec SQLCipher
    conn.execute(f'PRAGMA passphrase = "{fenetre.passphrase}";')  # Appliquer la clé PRAGMA chiffrée à la connexion SQLite
    conn.execute("PRAGMA foreign_passphrase = ON;")  # Appliquer la clé PRAGMA chiffrée à la connexion SQLite
    cur = conn.cursor()  # Création du curseur
    sys.exit(app.exec_())  #  Lancement de l'application



# Création des tables
cur.execute(
    """
      CREATE TABLE IF NOT EXISTS valeurs_metiers(
        name TEXT PRIMARY KEY,
        C REAL,
        I REAL,
        A REAL      
      );
"""
)  # Création de la table valeurs_metiers avec contraintes d'unicité sur les propriétés C (confidentialité), I (intégrité) et A (disponibilité)
cur.execute(
    """
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
"""
)  # Création de la table biens_supports
cur.execute(
    """
    CREATE TABLE IF NOT EXISTS jointure(
    num    INTEGER PRIMARY KEY AUTOINCREMENT,
    bs_id  TEXT NOT NULL,
    vm_id  TEXT,
    FOREIGN KEY (vm_id) REFERENCES valeurs_metiers(name)
);
"""
)  # Création de la table jointure permettant d'associer toute valeur métier à tout bien support (n;n)

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
dicoC = {"p5": [], "p4": [], "p3": [], "p2": [], "p1": []}
dicoI = {"p5": [], "p4": [], "p3": [], "p2": [], "p1": []}
dicoA = {"p5": [], "p4": [], "p3": [], "p2": [], "p1": []}
dicoGlobal = {"confidentiality": dicoC, "integrity": dicoI, "availability": dicoA}

##### CLASSES  #####
class CVE:
    def __init__(
        self,
        id,
        composant_ref,
        description,
        severity,
        score_CVSS,
        attack_vector,
        attack_complexity,
        privileges_required,
        user_interaction,
        scope,
        confidentiality,
        integrity,
        availability,
        exp_score,
        env_score,
        kev,
    ):
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
        return f"ID: {self.id} \nBom-ref: {self.composant_ref} \nDescription: {self.description} \nSeverity: {self.severity} \nScore CVSS: {self.score_CVSS} \nAV: {self.attack_vector} \nAC: {self.attack_complexity} \nPR: {self.privileges_required} \nUI: {self.user_interaction} \nS: {self.scope} \nC: {self.confidentiality} \nI: {self.integrity} \nA: {self.availability} \nScore Exp: {self.exp_score} \nScore Env: {self.env_score} \nKeV: {self.kev}\n\n"  # Classe permettant de définir les CVE
class CVE_others:
    def __init__(self, id, composant_ref, description, severity):
        self.id = id
        self.composant_ref = composant_ref
        self.description = description
        self.severity = severity

    def __repr__(self):
        return f"ID: {self.id} \nBom-ref: {self.composant_ref} \nDescription: {self.description} \nSeverity: {self.severity}\n\n"


##### FONCTIONS #####


# Famille de fonctions pour parser les variables environnementales à partir du VDR (CVSS X)
def var_environnementales_CVSSv3(svector):
    attack_vector = svector[12]
    attack_complexity = svector[17]
    privileges_required = svector[22]
    user_interaction = svector[27]
    scope = svector[31]
    confidentiality = svector[35]
    integrity = svector[39]
    availability = svector[43]
    return (
        attack_vector,
        attack_complexity,
        privileges_required,
        user_interaction,
        scope,
        confidentiality,
        integrity,
        availability,
    )  # Fonction permettant de parser les variables environnementales à partir du "vector" du VDR (CVSS3.0)
def var_environnementales_CVSSv2(svector):
    attack_vector = svector[4]
    attack_complexity = svector[9]
    authentification = svector[14]
    confidentiality = svector[18]
    integrity = svector[22]
    availability = svector[26]
    return (
        attack_vector,
        attack_complexity,
        authentification,
        confidentiality,
        integrity,
        availability,
    )  # Fonction permettant de parser les variables environnementales à partir du "vector" du VDR (CVSS2.0)
def var_environnementales_other(svector):
    attack_vector = "None"
    attack_complexity = "None"
    privileges_required = "None"
    user_interaction = "None"
    scope = "None"
    confidentiality = "None"
    integrity = "None"
    availability = "None"
    return (
        attack_vector,
        attack_complexity,
        privileges_required,
        user_interaction,
        scope,
        confidentiality,
        integrity,
        availability,
    )  # Fonction permettant de parser les variables environnementales à partir du "vector" du VDR (CVSS non spécifié)
def calcul_score_exploitabilité(
    attack_vector, attack_complexity, privileges_required, user_interaction
):

    exp_score = (
        (
            8.22
            * attack_vector
            * attack_complexity
            * privileges_required
            * user_interaction
        )
        / 3.9
        * 4
    )
    return round(
        exp_score, 1
    )  # Fonction permettant de calculer le score d'exploitabilité CVSS 3.1
def triAffichageVOR(
    p1,
    p2,
    p3,
    p4,
    p5,
    p1Vert,
    p1Orange,
    p1Rouge,
    p2Vert,
    p2Orange,
    p2Rouge,
    p3Vert,
    p3Orange,
    p4Vert,
    p4Orange,
    p5Vert,
):
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

    return (
        p1Vert,
        p1Orange,
        p1Rouge,
        p2Vert,
        p2Orange,
        p2Rouge,
        p3Vert,
        p3Orange,
        p4Vert,
        p4Orange,
        p5Vert,
    )  # Fonction permettant de trier le nombre de CVE en vert, orange et rouge (VOR) en fonction de chaque P(x)
def calcul_score_environnemental(
    disponibiliteVM,
    integriteVM,
    confidentialiteVM,
    availability,
    integrity,
    confidentiality,
    scope,
    attack_vector,
    attack_complexity,
    privileges_required,
    user_interaction,
):
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
        modified_impact = 6.42 * min(
            1
            - (1 - disponibiliteVM * availability)
            * (1 - integriteVM * integrity)
            * (1 - confidentialiteVM * confidentiality),
            0.915,
        )
    elif "C" in scope:
        modified_impact = 7.52 * (
            min(
                1
                - (1 - disponibiliteVM * availability)
                * (1 - integriteVM * integrity)
                * (1 - confidentialiteVM * confidentiality),
                0.915,
            )
            - 0.029
        ) - 3.25 * (
            (
                (
                    min(
                        1
                        - (1 - disponibiliteVM * availability)
                        * (1 - integriteVM * integrity)
                        * (1 - confidentialiteVM * confidentiality),
                        0.915,
                    )
                )
                * 0.9731
                - 0.02
            )
            ** 13
        )

    modified_exploitability = (
        8.22
        * attack_vector
        * attack_complexity
        * privileges_required
        * user_interaction
    )

    if "U" in scope:
        env_score = round(min(modified_impact + modified_exploitability, 10), 2)
    elif "C" in scope:
        env_score = round(
            min(1.08 * (modified_impact + modified_exploitability), 10), 2
        )

    return (
        env_score  # Fonction permettant de calculer le score environnemental CVSS 3.1
    )
def option_5_calcul_scores():
    # Dictionnaire pour stocker les scores par bs_id et cve_id
    scores_dict = {}

    # Récupération des données
    cur.execute(
        """
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
    """
    )
    rows = cur.fetchall()

    if len(rows) == 0:
        print("Aucune donnée à traiter.")
        return

    # Traitement de chaque ligne
    for row in rows:
        (
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
            user_interaction,
        ) = row

        # Conversion des valeurs textuelles en numériques
        impact_availability_num = convert_cia_to_numeric(impact_availability)
        impact_integrity_num = convert_cia_to_numeric(impact_integrity)
        impact_confidentiality_num = convert_cia_to_numeric(impact_confidentiality)

        try:
            # Calcul du score environnemental
            env_score = calcul_score_environnemental(
                A_heritage,
                I_heritage,
                C_heritage,
                impact_availability_num,
                impact_integrity_num,
                impact_confidentiality_num,
                scope,
                attack_vector,
                attack_complexity,
                privileges_required,
                user_interaction,
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
            cur.execute(
                """
                UPDATE biens_supports
                SET env_score = ?
                WHERE bs_id = ? AND cve_id = ?;
            """,
                (env_score, bs_id, cve_id),
            )
def convert_cia_to_numeric(value):
    # Convertit les valeurs d'impact CIA en valeurs numériques
    if value == "N":
        return 0  # None
    elif value == "L":
        return 0.22  # Low
    elif value == "H":
        return 0.56  # High
    return 0  # Fonctions de conversion des valeurs d'impact CIA en valeurs numériques



def definitionPx(p2, p3, p4, p5, scoreEnv, scoreExp):
    if 9.0 <= scoreEnv <= 10.0:
        p2.append(scoreExp)
    elif 7.0 <= scoreEnv <= 8.9:
        p3.append(scoreExp)
    elif 4.0 <= scoreEnv <= 6.9:
        p4.append(scoreExp)
    elif 0.1 <= scoreEnv <= 3.9:
        p5.append(scoreExp)
    else:
        pass

    return (
        p2,
        p3,
        p4,
        p5,
    )  # Fonction permettant de trier dans la P(x) associée aux scores d'exploitabilité si NON KEV



if __name__ == "__main__":
    root = Tk()
    root.withdraw()
