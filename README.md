# Gestion des risques relatif aux biens supports (BS) et aux valeurs métiers (VM)

Ce script Python permet d'analyser et de traiter des données issues de rapports de divulgation de vulnérabilités (VDR) ainsi que des catalogues de vulnérabilités exploitées (KEV). Il offre également des outils d'analyse statistique pour évaluer les risques des biens supports (BS) et des valeurs métiers (VM).

---

## Fonctionnalités principales

1. **Importation des données VDR et KEV :**
   - Importez et parsez des fichiers JSON pour extraire des données liées aux vulnérabilités.
   - Mettez à jour les bases de données SQLite en fonction des données importées.

2. **Liaison BS et VM :**
   - Associez des biens supports (BS) à des valeurs métiers (VM) en utilisant des fichiers Excel.
   - Générez automatiquement les mises à jour de surface d'attaque pour les BS.

3. **Calculs des scores de vulnérabilité :**
   - Calculez les scores d'exploitabilité (exp_score) et environnementaux (env_score) basés sur les vecteurs CVSS.

4. **Analyse statistique :**
   - Générez des boîtes à moustache (boxplots) pour visualiser les scores de vulnérabilité selon leur sévérité (P1 à P5).

5. **Base de données SQLite intégrée :**
   - Gérez les données dans une base locale SQLite avec des tables optimisées (`biens_supports`, `valeurs_metiers`, et `jointure`).

---

## Prérequis

### Modules Python nécessaires :
- **json** : Manipulation des fichiers JSON.
- **sqlite3** : Base de données intégrée.
- **tkinter** : Interface graphique pour la sélection des fichiers.
- **matplotlib** : Visualisation graphique.
- **pandas** : Analyse des données tabulaires.
- **openpyxl** : Manipulation des fichiers Excel (.xlsx).

Installez les bibliothèques manquantes avec la commande :
```bash
pip install matplotlib pandas openpyxl
```

---

## Structure du script

### Tables principales

1. **`valeurs_metiers` :**
   - Contient les valeurs métiers avec leurs niveaux de confidentialité (C), d'intégrité (I) et de disponibilité (A).

2. **`biens_supports` :**
   - Stocke les données sur les biens supports (BS), y compris les scores CVSS, les vecteurs d'attaque et les scores calculés.

3. **`jointure` :**
   - Lie les biens supports (BS) aux valeurs métiers (VM).

---

## Utilisation

1. **Exécution du script :**
   Lancez le script dans votre environnement Python :
   ```bash
   python rbvm.py
   ```

2. **Interface utilisateur :**
   Une interface simple s'ouvre dans la console avec les options suivantes :
   - **1 :** Importer les fichiers VDR et KEV.
   - **2 :** Associer les BS aux VM et mettre à jour les surfaces d'attaque.
   - **3 :** Générer les analyses statistiques descriptives.
   - **4 :** Créer des boîtes à moustache pour visualiser les risques.
   - **5 :** Quitter l'application.

3. **Sélection des fichiers :**
   - L'interface graphique Tkinter permet de choisir les fichiers JSON et Excel nécessaires.

---

## Visualisation des données

Les boîtes à moustache générées se trouvent dans des sous-dossiers organisés par niveaux de risque :
- `03_VERT/` : Faible risque.
- `02_ORANGE/` : Risque modéré.
- `01_ROUGE/` : Haut risque.

---

## Exemple d'extension

Vous pouvez adapter ou étendre le script pour ajouter d'autres visualisations ou méthodes de traitement des vulnérabilités.

---

## Contact

Pour toute question ou amélioration, n'hésitez pas à contacter l'auteur.
