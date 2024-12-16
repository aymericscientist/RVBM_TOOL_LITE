# README

---

## English Section

### Overview

This project focuses on the analysis, management, and visualization of vulnerabilities in microservices and their associated virtual machines (VMs). The application connects to a PostgreSQL database to handle and process data, integrates with Known Exploited Vulnerabilities (KEV) Catalog, and computes both exploitability and environmental scores for vulnerabilities. It also generates detailed statistical visualizations like box plots to help assess risk levels.

---

### Features

1. **Database Setup**:
   - Schema `jaka` with tables `micro`, `vm`, and `jointure`.
   - `micro` stores vulnerability data.
   - `vm` contains metadata on virtual machines.
   - `jointure` links microservices with VMs.

2. **Data Parsing**:
   - Processes VDR (Vulnerability Disclosure Report) and KEV JSON files.
   - Parses CVSS vectors (v2 and v3).

3. **Score Calculation**:
   - Computes exploitability scores based on CVSS metrics.
   - Calculates environmental scores reflecting the maximum CIA (Confidentiality, Integrity, Availability) values when microservices are associated with multiple VMs.

4. **Visualization**:
   - Generates box plots for microservices and VMs with severity categories (P1 to P5).

5. **Statistical Descriptive Analysis**:
   - Enables risk assessment of vulnerabilities.

6. **Dynamic Updating**:
   - Updates `micro` table with CIA values inherited from associated VMs.

---

### Prerequisites

- Python (3.7+)
- PostgreSQL (with `psycopg2` connector)
- Required Python packages:
  - `json`
  - `requests`
  - `psycopg2`
  - `tkinter`
  - `matplotlib`
  - `pandas`

---

### Installation

1. Clone this repository:
   ```bash
   git clone <repository_url>
   cd <repository_name>
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Set up your PostgreSQL database:
   - Create a database named `postgres`.
   - Update connection credentials in the script if necessary.

---

### Usage

1. Run the script:
   ```bash
   python <script_name>.py
   ```

2. Use the interactive menu to:
   - Import VDR and KEV JSON files.
   - Update vulnerability inheritance.
   - Calculate environmental scores.
   - Generate box plots.

3. Outputs:
   - Updated database tables.
   - Box plots saved as PNG files in the specified directory.

---

### Key Functions

- **Parsing and Processing:**
  - Parses VDR JSON files for vulnerabilities.
  - Calculates scores based on CVSS vectors.

- **Data Updates:**
  - Updates the `micro` table with scores and inheritance data.

- **Visualization:**
  - Generates box plots highlighting severity levels.

---

## French Section

### Aperçu

Ce projet porte sur l'analyse, la gestion et la visualisation des vulnérabilités dans les microservices et les machines virtuelles (VM) associées. L'application se connecte à une base de données PostgreSQL pour traiter et gérer les données, s'intègre au catalogue des vulnérabilités exploitées connues (KEV) et calcule les scores d'exploitabilité et environnementaux. Elle génère également des visualisations statistiques détaillées telles que des boîtes à moustaches pour évaluer les niveaux de risque.

---

### Fonctionnalités

1. **Configuration de la base de données**:
   - Schéma `jaka` avec les tables `micro`, `vm` et `jointure`.
   - `micro` stocke les données de vulnérabilité.
   - `vm` contient les métadonnées sur les machines virtuelles.
   - `jointure` relie les microservices aux VM.

2. **Analyse des données**:
   - Traite les fichiers JSON VDR et KEV.
   - Parse les vecteurs CVSS (v2 et v3).

3. **Calcul des scores**:
   - Calcule les scores d'exploitabilité basés sur les métriques CVSS.
   - Détermine les scores environnementaux tenant compte des valeurs maximales de CIA (Confidentialité, Intégrité, Disponibilité).

4. **Visualisation**:
   - Génère des boîtes à moustaches pour les microservices et les VM avec des catégories de sévérité (P1 à P5).

5. **Analyse descriptive statistique**:
   - Permet d'évaluer les risques liés aux vulnérabilités.

6. **Mise à jour dynamique**:
   - Met à jour la table `micro` avec les valeurs CIA héritées des VM associées.

---

### Prérequis

- Python (3.7+)
- PostgreSQL (avec connecteur `psycopg2`)
- Bibliothèques Python nécessaires:
  - `json`
  - `requests`
  - `psycopg2`
  - `tkinter`
  - `matplotlib`
  - `pandas`

---

### Installation

1. Clonez ce dépôt :
   ```bash
   git clone <repository_url>
   cd <repository_name>
   ```
2. Installez les dépendances :
   ```bash
   pip install -r requirements.txt
   ```
3. Configurez votre base de données PostgreSQL :
   - Créez une base de données nommée `postgres`.
   - Mettez à jour les informations d'identification de connexion dans le script si nécessaire.

---

### Utilisation

1. Lancez le script :
   ```bash
   python <script_name>.py
   ```

2. Utilisez le menu interactif pour :
   - Importer des fichiers JSON VDR et KEV.
   - Mettre à jour l'héritage des vulnérabilités.
   - Calculer les scores environnementaux.
   - Générer des boîtes à moustaches.

3. Résultats :
   - Tables de base de données mises à jour.
   - Boîtes à moustaches sauvegardées au format PNG dans le répertoire spécifié.

---

### Fonctions Clés

- **Analyse et Traitement:**
  - Analyse les fichiers JSON VDR pour les vulnérabilités.
  - Calcule les scores basés sur les vecteurs CVSS.

- **Mises à jour des données:**
  - Met à jour la table `micro` avec les scores et les données d'héritage.

- **Visualisation:**
  - Génère des boîtes à moustaches mettant en évidence les niveaux de sévérité.

