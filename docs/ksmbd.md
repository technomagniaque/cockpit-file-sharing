# Onglet ksmbd (branche `feat/ksmbd`)

Gestion du serveur SMB3 du noyau (ksmbd + ksmbd-tools) : configuration par
paramètres, simulateur d'empilement des permissions, conversion Samba → ksmbd.

Code : `file-sharing/src/tabs/ksmbd/`

| Fichier | Rôle |
|---|---|
| `ksmbd-params.ts` | catalogue des paramètres (portée, type, défaut, catégorie) + lecture des valeurs comme ksmbd-tools |
| `ini.ts` | lecture / écriture smb.conf / ksmbd.conf |
| `permission-stack.ts` | modèle de l'empilement : connexion, identité, création, couches d'accès |
| `samba-to-ksmbd.ts` | conversion avec rapport ligne par ligne |
| `ksmbd-manager.ts` | accès serveur (ksmbd.conf, Samba, comptes, sondes RDMA / noyau / ZFS) |
| `ui/*.vue` | onglet, éditeur de paramètres, simulateur, conversion |
| `ksmbd.test.ts` | tests vitest des modules purs |

## Comment ksmbd empile les permissions

Vérifié dans le code de ksmbd-tools (`tree_conn.c`, `share.c`, `config_parser.c`)
et du noyau (`smb2pdu.c`, `smb_common.c`, `vfs.c`, `fs/namei.c`).

### 1. Connexion au partage (ksmbd.mountd)

1. Mauvais mot de passe + `map to guest = never` → refus.
2. Mode de départ : `read only` s'il est défini, sinon le premier défini parmi `writable`, `writeable`, `write ok` (dans cet ordre). Chaque clé est héritée **séparément** de [global] : `writable = no` en [global] l'emporte sur `writeable = yes` dans le partage. Sans aucune de ces clés : lecture seule.
3. Invité : `restrict anonymous` = 1 ou 2 (toute autre valeur vaut 0) sans `guest ok` → refus ; `guest ok = yes` → accepté comme invité **sans consulter les listes**.
4. Le compte doit exister dans `ksmbdpwd.db` (`ksmbd.adduser`).
5. `invalid users` → refus.
6. `read list` → lecture seule, et **`valid users` n'est pas consulté**.
7. `write list` → écriture, et **`valid users` n'est pas consulté**.
8. `valid users` → refus si non membre.

**`hosts allow`, `hosts deny` et `admin users` n'ont aucun effet** : ksmbd-tools les range dans
`KSMBD_SHARE_CONF_IS_BROKEN` (`include/management/share.h`) et ne les lit jamais, ni dans un partage
ni dans [global]. Toute restriction par adresse doit passer par le pare-feu ou par
`interfaces` + `bind interfaces only`.

`@groupe` est développé au chargement de la config (groupe primaire + membres secondaires), en ne gardant que les comptes présents dans la base ksmbd : un `valid users = @groupe` sans membre ksmbd refuse tout le monde. `+groupe` / `&groupe` (Samba) ne sont pas reconnus.

### 2. Identité des opérations (noyau)

`fsuid` = utilisateur ou `force user` ; `fsgid` = groupe primaire, `force group`, ou groupe primaire du `force user`. **Les groupes secondaires de l'utilisateur connecté restent actifs** même avec `force user`. Le compte `force user` doit seulement exister comme compte Unix.

### 3. Création d'un fichier ou dossier (noyau)

1. Mode demandé : mode POSIX du client Linux (extensions SMB 3.1.1) ou tous les bits.
2. `& create mask` (`directory mask`) puis `| force create mode` (`force directory mode`).
3. Dossier : `vfs_mkdir` masque avec `S_IRWXUGO|S_ISVTX` → un setgid venu de `directory mask` / `force directory mode` est perdu.
4. Si le parent **n'a pas d'ACL POSIX par défaut** (toujours vrai en `acltype=off`), l'**umask des workers ksmbd** est appliqué : 0022 sur les noyaux récents (kworker sur `init_fs`), à vérifier avec `grep Umask /proc/$(pgrep -x kthreadd)/status` (l'onglet le lit). L'écriture groupe disparaît alors, même avec `force create mode = 0060`. Avec une ACL par défaut, c'est elle qui décide.
5. Dossier parent setgid → groupe du parent, et setgid propagé aux sous-dossiers.
6. `inherit owner = yes` → UID du parent seulement (via `i_uid_write`, persistance non garantie).
7. ACL : descripteur envoyé par le client, sinon héritage NT (`acl_xattr`), sinon, sur un FS avec ACL POSIX et sans ACL par défaut, `ksmbd_vfs_set_init_posix_acl` pose `user::`, `user:<uid>`, `group::`, `group:<gid>`, `mask::rwx`, `other::` (+ la même en ACL par défaut pour un dossier). Le masque rwx est recopié dans les bits groupe du mode : `stat` affiche g=rwx avec « + » alors que le groupe propriétaire garde ses droits réels.

### 4. Chaque accès

Connexion en lecture seule → toute écriture refusée ; puis DACL NT (`security.NTACL`, avec `acl_xattr`) **et** droits POSIX : les deux doivent accorder l'accès.

## Pièges du parseur ksmbd-tools

- Clés insensibles à la casse mais **espaces significatifs** (`readonly` ≠ `read only`), pas d'alias Samba (`create mode`, `public`, `browsable`… ignorés).
- **La première occurrence d'une clé gagne** (Samba : la dernière) ; une valeur vide n'enregistre pas la clé.
- **Une valeur s'arrête au premier `;` ou `#`** : `veto files = /.DS_Store/#recycle/` est lu `/.DS_Store/`.
- Pas de continuation de ligne `\` ; une ligne sans `=`, ou un paramètre avant toute section, fait rejeter le fichier.
- Booléens par préfixe de `yes`, `true`, `1`, `enable` ; `on` vaut **faux**.
- `server signing` / `smb3 encryption` : `enabled`, `auto`, `mandatory`, sinon **disabled** (`required`, `yes`… → disabled sans message). Dans un partage, `smb3 encryption = disabled` signifie seulement « non exigé ».
- `map to guest = bad password` est désactivé dans le code.
- `max connections` en [global] plafonne **tout le serveur** (défaut 256) et n'est pas propagé ; dans un partage, défaut 128.
- `interfaces` attend des **noms** de netdev, pas des adresses.
- **`ksmbd.control --reload` ne relit que les partages** : un changement de [global] (RDMA, multicanal, interfaces, signature, protocole, durable handles…) exige `systemctl restart ksmbd` (= `ksmbd.control --shutdown` puis `ksmbd.mountd`). L'onglet le détecte et propose le redémarrage.

## Conversion Samba → ksmbd

Lit `smb.conf` et le registre (`net conf list`, utilisé par cockpit-file-sharing), puis :

- normalise clés et valeurs (signature / chiffrement : `yes`, `auto`, `desired`… → `auto` ; `required`, `force`… → `mandatory`) ;
- signale chaque paramètre abandonné (security ADS, passdb, shadow_copy2, recycle, full_audit, catia, inherit permissions, %U, valeurs contenant `;` ou `#`…) ;
- **abandonne `hosts allow`, `hosts deny` et `admin users` avec un avertissement bloquant** (la restriction d'accès disparaît) ;
- avertit quand `read list` / `write list` contiennent des entrées absentes de `valid users` (elles y échapperaient) et, par défaut, les retire ; signale les entrées présentes dans les deux listes ;
- retire les entrées entre guillemets contenant un espace (`"@Domain Users"`), non exprimables ;
- recopie `max connections` de [global] dans chaque partage ;
- ne garde que les noms d'interface dans `interfaces` (sinon pas de `bind interfaces only`) ;
- signale l'absence de `follow symlinks` (Samba suit les liens par défaut, ksmbd non) ;
- n'active Kerberos que pour `kerberos method` avec keytab ;
- ignore [homes] / [printers] ; convertit `fruit:time machine` ;
- ajoute RDMA (`server multi channel support`, `smbd max io size`, `interfaces`, `bind interfaces only`), `durable handles`, `smb2 leases`, tailles d'E/S, signature, chiffrement, dialecte minimal ;
- produit la liste des commandes à exécuter (comptes `ksmbd.adduser`, `force user` comme simple compte Unix, arrêt de Samba, vérifs RDMA, port 5445 pour iWARP, `systemctl restart ksmbd`).

Le résultat est chargé dans l'éditeur ; l'écriture crée `ksmbd.conf.bak-<date>`, lance
`ksmbd.control --reload` pour les partages et signale si un redémarrage complet est nécessaire.

## Tests

```bash
cd file-sharing && yarn vitest run src/tabs/ksmbd
```
