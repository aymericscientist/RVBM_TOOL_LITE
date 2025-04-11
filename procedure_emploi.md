![image](https://github.com/user-attachments/assets/cbc34224-77b2-49a4-855c-5e5b179a3595)

## 1ère étape [MOA] : Charger (Excel) les valeurs métiers ainsi que leurs besoins de sécurité et sûreté 

Cette étape consiste à compléter le document Excel [`template_prerequis DIC.xlsx`](https://github.com/aymericscientist/RVBM_TOOL_LITE/blob/746138f0ecdd2cb29c8f330502c0c334994b5dff/template_prerequis%20DIC.xlsx) permettant de répondre aux exigences suivantes :

- **EBIOS-RM** [Méthode EBIOS Risk Manager](https://cyber.gouv.fr/la-methode-ebios-risk-manager)  
  - Atelier n°1 - 5/ Comment procéder ?  
    - B) Délimiter le périmètre métier et technique ;  
    - C) Identifier les événements redoutés (définition des événements redoutés centraux concernant les valeurs métiers).

- **ISO/TS 22317:2021** ⚠️ Pour être pleinement conforme, il faut veiller à opérer le BIA également sur le(s) service(s) organique(s) concerné(s)
  *Sécurité et résilience — Systèmes de management de la continuité d'activité — Lignes directrices pour le bilan d'impact sur l'activité* [Lien vers la norme](https://www.iso.org/fr/standard/79000.html)  

- **ISO/IEC 27034-1:2011** [Lien vers la norme](https://www.iso.org/standard/44378.html) *Information technology — Security techniques — Application security* notamment la partie §7.3.2, §7.3.3, §7.3.6.

- **TOGAF** [Lien vers TOGAF](https://www.opengroup.org/togaf)

- **Score CVSS 3.1** [Spécification officielle](https://www.first.org/cvss/v3-1/specification-document)

📌 Le document Excel doit être, de manière préférentielle, **continuellement accessible** aux équipes **SSI** ainsi qu’aux équipes **fonctionnelles** (MOA, AMOA et urbanistes), afin d’assurer la fraîcheur des données et de rester au plus proche du réel dans les résultats produits par le RVBM Tool.

![image](https://github.com/user-attachments/assets/11182a00-747e-44f6-aad7-415e968c6f2f)

> ⚠️ La colonne G doit **obligatoirement** être complétée, que ce soit conformément à TOGAF ou selon la dénomination de la valeur métier à votre discrétion
> ⚠️ La colonne H doit **obligatoirement** être complétée. Vous devez **obligatoirement** respecter l'échelle qualitative imposée par le [Table 12: Security Requirements](https://www.first.org/cvss/v3-1/specification-document)
> ⚠️ La colonne K doit **obligatoirement** être complétée. Vous devez **obligatoirement** respecter l'échelle qualitative imposée par le [Table 12: Security Requirements](https://www.first.org/cvss/v3-1/specification-document)
> ⚠️ La colonne M doit **obligatoirement** être complétée. Vous devez **obligatoirement** respecter l'échelle qualitative imposée par le [Table 12: Security Requirements](https://www.first.org/cvss/v3-1/specification-document)
---

## 2ème étape [MOE] : Charger le fichier *Known Exploited Vulnerabilities (KEV) Catalog* du **CISA**

Dans le cadre de la matrice finale, on intègre la combinatoire :

- Les **valeurs qualitatives** du tableau 14 de la [spécification CVSS 3.1](https://www.first.org/cvss/v3-1/specification-document) ;
- La **présence ou non de vulnérabilités (CVE)** issues du **[catalogue KEV](https://www.cisa.gov/resources-tools/resources/kev-catalog)** du **CISA**

📡 Vous pouvez importer le fichier :
- Automatiquement (si accès Internet) ;
- Manuellement (téléchargement préalable, pour un usage **hors ligne** sur des systèmes sensibles) **[catalogue KEV](https://www.cisa.gov/resources-tools/resources/kev-catalog)**.

🎯 Cela permet de répondre à l’exigence suivante :

- **EBIOS-RM** [Atelier n°5 - 5/ Comment procéder ? - B) Décider de la stratégie de traitement du risque](https://cyber.gouv.fr/la-methode-ebios-risk-manager)

---

## 3ème étape [MOE] : Charger chaque VDR concernant l’exhaustivité des biens supports

### a) Générez les **SBOM** du périmètre concerné (cf https://owasp-scvs.gitbook.io/scvs/v2-software-bill-of-materials) 
### b) Ingerer les SBOM dans **Dependency Track**  (cf https://dependencytrack.org/)
### c) Générer les **VDR** à partir de Dependency Track  
> ⚠️ Vérifiez que le **nom du composant parent** est bien **identique au nom du micro-service ou du conteneur désiré**.
### d) Selectionner les **VDR** dans l'outil RBVM tool à l'étape 3
> ⚠️ Les VDR permettent d’avoir (seulement) la connaissance des **vulnérabilités publiques connues (CVE)** sur votre périmètre technique.

---

## 4ème étape [MOE] : Charger la matrice (Excel) associant les biens supports aux valeurs métiers

Cette étape consiste à compléter le document Excel  [`template_matrice_vm_bs.xlsx`](https://github.com/aymericscientist/RVBM_TOOL_LITE/blob/e9179bf87252389e101b9cb91b3de3984cd5166d/template_matrice_vm_bs.xlsx) afin d’associer un ou plusieurs **biens supports** (micro-service, conteneur, etc.) à une **valeur métier** précise.
> ⚠️ Vérifiez que toutes les dénominations de **valeurs métiers** et de **biens supports** soient homogènes et uniques. Le fichier excel doit notamment strictement reprendre le nom des valeurs métiers figurant dans l'étape n°1 et le nom des biens supports figurant à l'étape n°3. Toute incohérence sera affichée et vous ne pourrez pas aller au-delà le temps que ces prérequis ne sont pas correctement honorés.

🎯 Elle permet de répondre aux exigences suivantes :

- **EBIOS-RM** [Atelier n°1 - 5/ Comment procéder ?](https://cyber.gouv.fr/la-methode-ebios-risk-manager)  
  - B) Délimiter le périmètre métier et technique ;  
  - C) Identifier les événements redoutés (définition des événements redoutés locaux concernant les biens supports).

---

## 5ème étape [MOE] : Générer les représentations concernant les risques liés aux biens supports (MOE)

Cette étape consiste à opérer un traitement statistique descriptif atomique à destination des équipes projets. L'équipe projet va bénéficier de trois représentations : (1) concernant la disponibilité, (2) concernant l'intégrité et, (3) concernant la confidentialité. Cette représentation modélise la vue brute des risques concernant (1) ou (2) ou (3). Cet outil ne permet pas de proposer un plan de traitement des risques, ce sera l'objet d'un [futur projet](https://github.com/aymericscientist/CAB_automation_tool_with_SBOM).

- **EBIOS-RM** [Atelier n°5 - 5/ Comment procéder ?](https://cyber.gouv.fr/la-methode-ebios-risk-manager)
    - A) Réaliser une synthèse des scénarios de risque ;
    - B) Décider de la stratégie de traitement du risque ;
    - E) Mettre en place le cadre de suivi des risques ;
    - F) Mettre en place des mécanismes de surveillance.

---

## 6ème étape [MOA] : Générer les représentations concernant les risques liés aux valeurs métiers (MOA)

Cette étape consiste à opérer un traitement statistique descriptif fédérant tous les biens supports liés à une valeur métier à destination des équipes projets. L'équipe projet va bénéficier de trois représentations : (1) concernant la disponibilité, (2) concernant l'intégrité et, (3) concernant la confidentialité. Cette représentation modélise la vue brute des risques concernant (1) ou (2) ou (3). Cet outil ne permet pas de proposer un plan de traitement des risques, ce sera l'objet d'un [futur projet](https://github.com/aymericscientist/CAB_automation_tool_with_SBOM).

- **EBIOS-RM** [Atelier n°5 - 5/ Comment procéder ?](https://cyber.gouv.fr/la-methode-ebios-risk-manager)
    - A) Réaliser une synthèse des scénarios de risque ;
    - B) Décider de la stratégie de traitement du risque ;
    - E) Mettre en place le cadre de suivi des risques ;
    - F) Mettre en place des mécanismes de surveillance.
