![image](https://github.com/user-attachments/assets/cbc34224-77b2-49a4-855c-5e5b179a3595)

## 1ère étape [MOA] : Charger (Excel) les valeurs métiers ainsi que leurs besoins de sécurité et sûreté 

Cette étape consiste à compléter le document Excel [`template_prerequis DIC.xlsx`](https://github.com/aymericscientist/RVBM_TOOL_LITE/blob/746138f0ecdd2cb29c8f330502c0c334994b5dff/template_prerequis%20DIC.xlsx) permettant de répondre aux exigences suivantes :

- **EBIOS-RM** [Méthode EBIOS Risk Manager](https://cyber.gouv.fr/la-methode-ebios-risk-manager)  
  - Atelier n°1 - 5/ Comment procéder ?  
    - B) Délimiter le périmètre métier et technique  
    - C) Identifier les événements redoutés (définition des événements redoutés centraux concernant les valeurs métiers)

- **ISO/TS 22317:2021**  
  *Sécurité et résilience — Systèmes de management de la continuité d'activité — Lignes directrices pour le bilan d'impact sur l'activité*  
  [Lien vers la norme](https://www.iso.org/fr/standard/79000.html)  
  ⚠️ Pour être pleinement conforme, il faut veiller à opérer le BIA également sur le(s) service(s) organique(s) concerné(s)

- **TOGAF** [Lien vers TOGAF](https://www.opengroup.org/togaf)

- **Score CVSS 3.1** [Spécification officielle](https://www.first.org/cvss/v3-1/specification-document)

📌 Le document Excel doit être, de manière préférentielle, **continuellement accessible** aux équipes **SSI** ainsi qu’aux équipes **fonctionnelles** (MOA, AMOA et urbanistes), afin d’assurer la fraîcheur des données et de rester au plus proche du réel dans les résultats produits par le RVBM Tool.

![image](https://github.com/user-attachments/assets/11182a00-747e-44f6-aad7-415e968c6f2f)

---

## 2ème étape [MOE] : Charger le fichier *Known Exploited Vulnerabilities (KEV) Catalog* du **CISA**

Dans le cadre de la matrice finale, on intègre la combinatoire :

- Les **valeurs qualitatives** du tableau 14 de la [spécification CVSS 3.1](https://www.first.org/cvss/v3-1/specification-document) ;
- La **présence ou non de vulnérabilités (CVE)** issues du **[catalogue KEV](https://www.cisa.gov/resources-tools/resources/kev-catalog)** du **CISA**

📡 Vous pouvez importer le fichier :
- Automatiquement (si accès Internet)
- Manuellement (téléchargement préalable, pour un usage **hors ligne** sur des systèmes sensibles) **[catalogue KEV](https://www.cisa.gov/resources-tools/resources/kev-catalog)**

🎯 Cela permet de répondre à l’exigence suivante :

- **EBIOS-RM**  
  [Atelier n°5 - 5/ Comment procéder ? - B) Décider de la stratégie de traitement du risque](https://cyber.gouv.fr/la-methode-ebios-risk-manager)

---

## 3ème étape [MOE] : Charger tous les VDR concernant l’exhaustivité des biens supports

### a) Générez les **SBOM** du périmètre concerné (cf https://owasp-scvs.gitbook.io/scvs/v2-software-bill-of-materials) 
### b) Ingerer les SBOM dans **Dependency Track**  (cf https://dependencytrack.org/)
### c) Générer les **VDR** à partir de Dependency Track  
> ⚠️ Vérifiez que le **nom du composant parent** est bien **identique au nom du micro-service ou du conteneur désiré**
### c) Selectionner les **VDR** générés dans l'outil RBVM tool à l'étape 3

Les VDR permettent d’avoir (seulement) la connaissance des **vulnérabilités publiques connues (CVE)** sur votre périmètre technique.

---

## 4ème étape [MOE] : Charger la matrice (Excel) associant les biens supports aux valeurs métiers [`template_matrice_vm_bs.xlsx`](https://github.com/aymericscientist/RVBM_TOOL_LITE/blob/746138f0ecdd2cb29c8f330502c0c334994b5dff/template_prerequis%20DIC.xlsx)

Cette matrice permet d’associer un ou plusieurs **biens supports** (micro-service, conteneur, etc.) à une **valeur métier** précise.

🎯 Elle permet de répondre aux exigences suivantes :

- **EBIOS-RM**  
  [Atelier n°1 - 5/ Comment procéder ?](https://cyber.gouv.fr/la-methode-ebios-risk-manager)  
  - B) Délimiter le périmètre métier et technique  
  - C) Identifier les événements redoutés (définition des événements redoutés locaux concernant les biens supports)
"""
