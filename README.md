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

RBVM Tool est une application Python conçue pour apprécier (identifier, analyser et évaluer) les risques brutes d'un ou de plusieurs systèmes sociotechniques à l'échelle en s'appuyant sur une approche basée sur les vulnérabilités (RBVM). A ce jour l'outil permet seulement de traiter les vulnérabilités publiques connues (CVE), la prochaine version permettra d'intégrer également les faiblesses (CWE) relevant des différents audits.

L’outil intègre plusieurs étapes allant de l’importation des besoins de sécurité et de sûreté des valeurs métiers à la génération de représentations graphiques (boxplots) pour visualiser les risques brutes. Cet outil permet de couvrir tout ou partie les référentiels suivants :
- EBIOS-RM ;
- ISO/CEI 27005:2022 ;
- ISO/CEI 31000:2018 ;
- ISO/TS 22317:2021 ;
- ISO/IEC 27034-1:2011 ;
- TOGAF ;
- Score CVSS 3.1 ;
- catalogue KEV du CISA ;
- Software Component Verification Standard (SCVS) V1.0 OWASP

## Fonctionnalités

- **Chargement des valeurs métiers et de leurs besoins de sécurité et de sûreté**  
  Importation des données issues de fichiers Excel (ex. : `template_prerequis DIC.xlsx`) pour définir les exigences en termes de disponibilité, intégrité et confidentialité. Attention dans le `template_prerequis DIC.xlsx` il faut compléter au minimum la colonne G (fonctionnalité), la colonne H (besoin de disponibilité), la colonne K (besoin d'intégrité) et la colonne M (besoin de confidentialité). De plus, vous devrez veiller à bien respecter la validation de données intégrées dans le template afin d'éviter les erreurs.

- **Gestion du KEV Catalog**  
  Téléchargement automatique depuis le site du CISA ou chargement manuel d’un fichier KEV (Known Exploited Vulnerabilities) au format JSON ou CSV.

- **Traitement des Vulnerability Disclosure Reports (VDR)**  
  Extraction des vulnérabilités publiques connues (CVE) et de leurs métriques CVSS à partir de fichiers JSON.

- **Association via une matrice Bien support - Valeur métier**  
  Chargement d’un fichier Excel associant les biens supports aux valeurs métiers, permettant de mettre à jour la base de données avec les valeurs héritées en matière de sécurité et de sûreté.

- **Calcul des scores CVSS**  
  Conversion des métriques du vecteur CVSS en scores d’exploitabilité et environnementaux, via des formules adaptées. Dans le cadre de la présente version de cet outil, nous traitons uniquement les scores V3. Dans une prochaine version, nous intégrerons également les scores V4.

- **Génération de représentations graphiques**  
  Création de boxplots classant les scores d’exploitabilité par catégories (P1 à P5) en fonction des impacts sur la disponibilité, la confidentialité et l’intégrité. Les graphiques sont enregistrés dans des répertoires organisés (ex. : `01_ROUGE`, `02_ORANGE`, `03_VERT`).

  Attention dans les spécifications CVSSv3 le score d'exploitabilité a pour valeur maximale 3,9. Nous recalculons les scores pouvoir avoir une valeur maximale de 4.

- **Interface graphique conviviale**  
  Interface développée avec PyQt5 (et Tkinter pour certaines boîtes de dialogue) permettant de charger les fichiers, de lancer les traitements et de visualiser les résultats.

- **Base de données SQLite chiffrée**  
  Stockage sécurisé des données dans une base SQLite, protégée par une passphrase saisie ou générée lors du démarrage de l’application.

  Attention la BDD n'est pas encore chiffrée à date, nous essayons de trouver l'intégration optimale pour que ce soit le plus simple pour l'utilisateur final

## Installation

1. **Cloner le dépôt** ou télécharger le fichier `rbvm_tool.py`.

2. **Télécharger les dépendances**  
   Télécharger le fichier [`requirements.txt`](https://github.com/aymericscientist/RVBM_TOOL_LITE/blob/59de4013511d0f4d5e4c73a223157e453ce89a08/requirements.txt) 

3. **Installer les dépendances**  
   Puis exécutez la commande suivante :
   ```
   pip install -r requirements.txt
   ```

## Utilisation

Veuillez la [procédure idoine](https://github.com/aymericscientist/RVBM_TOOL_LITE/blob/59de4013511d0f4d5e4c73a223157e453ce89a08/procedure_emploi.md)

## Structure du Code

- **rbvm_tool.py**  
  Ce fichier contient l’ensemble des fonctionnalités de l’application, incluant :
  - L’interface graphique (PyQt5 et Tkinter) ;
  - Les fonctions de chargement et de traitement des données issues des fichiers Excel et JSON ;
  - La gestion de la base de données SQLite ;
  - La génération des boxplots pour la visualisation des risques.

## Contribuer

Les contributions sont les bienvenues !  
Si vous souhaitez améliorer l’outil ou corriger des bugs, merci de soumettre une pull request ou d’ouvrir une issue sur le dépôt GitHub.

## Licence

Ce projet est distribué sous licence Apache-2.0 license.

