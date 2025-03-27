![image](https://github.com/user-attachments/assets/cbc34224-77b2-49a4-855c-5e5b179a3595)

1ère étape [MOA] : Charger (excel) les valeurs métiers ainsi que leurs besoins de sécurité et sûreté [template_prerequis DIC.xslx]

  Cette étape consiste à compléter le document excel https://github.com/aymericscientist/RVBM_TOOL_LITE/blob/746138f0ecdd2cb29c8f330502c0c334994b5dff/template_prerequis%20DIC.xlsx permettant de répondre aux exigences suivantes :
    EBIOS-RM https://cyber.gouv.fr/la-methode-ebios-risk-manager 
      Atelier n°1 - 5/ Comment procéder ? - B) délimiter le périmètre métier et technique
      Atelier n°1 - 5/ Comment procéder ? - C) Identifier les événements redoutés 
    ISO/TS 22317:2021 Sécurité et résilience — Systèmes de management de la continuité d'activité — Lignes directrices pour le bilan d'impact sur l'activité https://www.iso.org/fr/standard/79000.html (attention pour que ce soit pleinement conforme, il faut veiller à opérer le BIA également sur le(s) service(s) organique(s) concerné(s))
    TOFAF https://www.opengroup.org/togaf 
    Score CVSS 3.1 https://www.first.org/cvss/v3-1/specification-document
Le document excel doit être, de manière préférentielle, continuellement accessible aux équipes SSI ainsi qu'aux équipes fonctionnelles (MOA, AMOA et urbanistes), cela permet d'assurer la fraîcheur des données et ainsi permettre d'être au plus proche du réel concernant les résultats du RBVM Tool

2ème étape [MOE] : Charger le fichier Known Exploited Vulnerabilities (KEV) Catalog du CISA

  Dans le cadre de la matrice finale, nous intégrons la combinaison des valeurs qualitatives du tableau 14 de https://www.first.org/cvss/v3-1/specification-document ainsi que de la présence ou non de vulnérabilités (CVE) présentes au sein du catalogue KEV du CISA. Cela représente la stratégie de traitement des risques. Vous avez la possibilité de l'importer automatiquement si vous avez un accès à Internet ou vous pouvez télécharger le fichier puis l'importer manuellement à cette étape. Cela permet un mode hors ligne concernant les systèmes les plus sensibles.

3ème étape [MOE] : Charger tous les VDR concernant l'exhaustivité des biens supports



4ème étape [MOE] : Charger la matrice (excel) associant les biens supports aux valeurs métiers template_matrice_vm_bs.xslx]
