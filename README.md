# Git secret recovery scanner

Ces scripts recherchent des secrets dans les objets d'un dépôt Git local,
y compris dans l'historique, le reflog et les objets non atteignables.

## Utilisation

Depuis le dossier `git-scanner` :

```text
python simple_recover.py <chemin/vers/dépot>
```

La version optimisée s'utilise de la même façon :

```text
python recover_updated.py <chemin/vers/depot>
```

La sortie est un rapport JSON écrit sur la sortie standard. Les secrets sont
affichés volontairement en clair dans le champ `secret`.

## Types détectés

Les types actuellement pris en compte sont :

- clés d'accès AWS (`AKIA...`) ;
- clés secrètes AWS associées à `aws_secret_access_key` ;
- tokens GitHub ;
- webhooks Slack ;
- clés API OpenAI commençant par `sk-` ;
- clés live Stripe ;
- clés API Google ;
- en-têtes de clés privées ;
- tokens JWT ;
- secrets associés à `jwt_secret` ;
- valeurs affectées à `password`, `passwd` ou `pwd`.

Cette liste n'est pas exhaustive. La détection repose sur des formats et des
noms de champs connus ; un secret d'un autre type, une variante de format ou
une valeur transformée peut ne pas être détecté. À l'inverse, certains motifs
peuvent produire des faux positifs et doivent être confirmés manuellement.

## Codes de sortie

- `0` : aucun secret trouvé
- `1` : au moins un secret trouvé
- `2` : erreur de commande ou dépôt invalide

## Résultat

Les résultats sont regroupés par type de secret et fingerprint. Lorsqu'un même
secret existe à plusieurs endroits, le résultat principal conserve le statut
le plus accessible : `history`, puis `reflog`, puis `unreachable`. Les autres
emplacements sont disponibles dans `also_in_locations`.
