### Aperçu

Ce projet porte sur l'analyse, la gestion et la visualisation des vulnérabilités dans les actifs et les valeurs métiers associées. L'application se connecte à une base de données pour traiter et gérer les données, s'intègre au catalogue des vulnérabilités exploitées connues (KEV) et calcule les scores d'exploitabilité et environnementaux. Elle génère également des visualisations statistiques descriptives détaillées telles que des boîtes à moustaches pour évaluer les niveaux de risque.

---

### Fonctionnalités

1. **Configuration de la base de données**:
   - Schéma `jaka` avec les tables `micro`, `vm` et `jointure`.
   - `micro` stocke les données de vulnérabilité.
   - `vm` contient les métadonnées sur les valeurs métiers.
   - `jointure` relie les microservices aux valeurs métiers.

2. **Analyse des données**:
   - Traite les fichiers JSON VDR et KEV.
   - Parse les vecteurs CVSS (v2 et v3).

3. **Calcul des scores**:
   - Calcule les scores d'exploitabilité basés sur les métriques CVSS.
   - Détermine les scores environnementaux tenant compte des valeurs maximales de CIA (Confidentialité, Intégrité, Disponibilité).

4. **Visualisation**:
   - Génère des boîtes à moustaches pour les microservices et les valeurs métiers avec des catégories de sévérité (P1 à P5).

5. **Analyse descriptive statistique**:
   - Permet d'évaluer les risques liés aux vulnérabilités.

6. **Mise à jour dynamique**:
   - Met à jour la table `micro` avec les valeurs CIA héritées des valeurs métiers associées.

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

