# RBVM Tool

> A tool for Risk Based Vulnerability Management

## Table des matières

- [Description](#description)
- [Fonctionnalités](#fonctionnalités)
- [Installation](#installation)
- [Utilisation](#utilisation)
- [Structure du Code](#structure-du-code)
- [Contribuer](#contribuer)
- [Licence](#licence)

## Description

RBVM Tool est une application Python conçue pour gérer et analyser les vulnérabilités d’un système en s’appuyant sur une approche basée sur le risque. L’outil intègre plusieurs étapes allant de l’importation des besoins de sécurité des valeurs métiers à la génération de représentations graphiques (boxplots) pour visualiser les risques.

## Fonctionnalités

- **Chargement des valeurs métiers et besoins de sécurité**  
  Importation des données issues de fichiers Excel (ex. : `template_prerequis DIC.xlsx`) pour définir les exigences en termes de disponibilité, intégrité et confidentialité.

- **Gestion du KEV Catalog**  
  Téléchargement automatique depuis le site du CISA ou chargement manuel d’un fichier KEV (Known Exploited Vulnerabilities) au format JSON ou CSV.

- **Traitement des Vulnerability Disclosure Reports (VDR)**  
  Extraction des vulnérabilités (CVE) et des métriques CVSS à partir de fichiers JSON.

- **Association via une matrice BS-VM**  
  Chargement d’un fichier Excel associant les biens supports aux valeurs métiers, permettant de mettre à jour la base de données avec les valeurs héritées en matière de sécurité.

- **Calcul des scores CVSS**  
  Conversion des métriques du vecteur CVSS en scores d’exploitabilité et environnementaux, via des formules adaptées.

- **Génération de représentations graphiques**  
  Création de boxplots classant les scores d’exploitabilité par catégories (P1 à P5) en fonction des impacts sur la disponibilité, la confidentialité et l’intégrité. Les graphiques sont enregistrés dans des répertoires organisés (ex. : `01_ROUGE`, `02_ORANGE`, `03_VERT`).

- **Interface graphique conviviale**  
  Interface développée avec PyQt5 (et Tkinter pour certaines boîtes de dialogue) permettant de charger les fichiers, de lancer les traitements et de visualiser les résultats.

- **Base de données SQLite chiffrée**  
  Stockage sécurisé des données dans une base SQLite, protégée par une passphrase saisie ou générée lors du démarrage de l’application.

## Installation

1. **Cloner le dépôt** ou télécharger le fichier `rbvm_tool.py`.

2. **Installer les dépendances**  
   Créez un fichier `requirements.txt` contenant :
   ```
   numpy
   openpyxl
   pandas
   tabulate
   matplotlib
   requests
   PyQt5
   ```
   Puis exécutez la commande suivante :
   ```bash
   pip install -r requirements.txt
   ```

## Utilisation

1. **Lancer l’application**  
   Exécutez la commande :
   ```bash
   python rbvm_tool.py
   ```

2. **Saisie de la passphrase**  
   À l’ouverture, une fenêtre vous invite à saisir ou générer une passphrase forte. Celle-ci est utilisée pour chiffrer la base de données SQLite.

3. **Chargement des fichiers**  
   - **Valeurs métiers et besoins de sécurité :** Sélectionnez le fichier Excel correspondant (ex. : `template_prerequis DIC.xlsx`).  
   - **KEV Catalog :** Choisissez de télécharger automatiquement depuis CISA ou de sélectionner un fichier local (JSON/CSV).  
   - **VDR :** Chargez un ou plusieurs fichiers JSON contenant les Vulnerability Disclosure Reports.  
   - **Matrice BS-VM :** Importez le fichier Excel associant les biens supports aux valeurs métiers (ex. : `template_matrice_vm_bs.xlsx`).

4. **Génération des représentations graphiques**  
   Utilisez l’interface pour générer :
   - Les représentations des risques liés aux biens supports (MOE).  
   - Les représentations des risques liés aux valeurs métiers (MOA).

5. **Consulter les résultats**  
   Les boxplots générées sont sauvegardées dans des répertoires organisés (ex. : `01_ROUGE`, `02_ORANGE`, `03_VERT`, etc.) selon les critères de classification.

## Structure du Code

- **rbvm_tool.py**  
  Ce fichier contient l’ensemble des fonctionnalités de l’application, incluant :
  - L’interface graphique (PyQt5 et Tkinter).  
  - Les fonctions de chargement et de traitement des données issues des fichiers Excel et JSON.  
  - La gestion de la base de données SQLite chiffrée.  
  - La génération des boxplots pour la visualisation des risques.

## Contribuer

Les contributions sont les bienvenues !  
Si vous souhaitez améliorer l’outil ou corriger des bugs, merci de soumettre une pull request ou d’ouvrir une issue sur le dépôt GitHub.

## Licence

Ce projet est distribué sous licence [MIT](LICENSE).

