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
2. Mode de départ : `read only` s'il est présent (même hérité de [global]), sinon `writable` / `writeable` / `write ok` ; défaut lecture seule.
3. `hosts allow` : **comparaison exacte de chaînes** (pas de CIDR, pas de préfixe `192.168.1.`, pas de nom). Si la liste existe et que l'IP n'y est pas → refus ; si elle y est, `hosts deny` n'est pas consulté.
4. `hosts deny` (seulement sans `hosts allow`).
5. Invité : `restrict anonymous ≥ 1` sans `guest ok` → refus ; `guest ok = yes` → accepté comme invité **sans consulter les listes**.
6. Le compte doit exister dans `ksmbdpwd.db` (`ksmbd.adduser`).
7. `admin users` → accepté immédiatement, **avant `invalid users`** (Samba fait l'inverse). Ne donne aucun privilège root.
8. `invalid users` → refus.
9. `read list` → lecture seule, et **`valid users` n'est pas consulté**.
10. `write list` → écriture, et **`valid users` n'est pas consulté**.
11. `valid users` → refus si non membre.

`@groupe` est développé au chargement de la config (groupe primaire + membres secondaires), en ne gardant que les comptes présents dans la base ksmbd : un `valid users = @groupe` sans membre ksmbd refuse tout le monde. `+groupe` / `&groupe` (Samba) ne sont pas reconnus.

### 2. Identité des opérations (noyau)

`fsuid` = utilisateur ou `force user` ; `fsgid` = groupe primaire, `force group`, ou groupe primaire du `force user`. **Les groupes secondaires de l'utilisateur connecté restent actifs** même avec `force user`.

### 3. Création d'un fichier ou dossier (noyau)

1. Mode demandé : mode POSIX du client Linux (extensions SMB 3.1.1) ou tous les bits.
2. `& create mask` (`directory mask`) puis `| force create mode` (`force directory mode`).
3. VFS : si le parent **n'a pas d'ACL POSIX par défaut** (toujours vrai en `acltype=off`), **l'umask 0022 des workers ksmbd est appliqué** → l'écriture groupe disparaît, même avec `force create mode = 0060`. Avec une ACL par défaut, c'est elle qui décide.
4. Dossier parent setgid → groupe du parent (et setgid propagé aux sous-dossiers).
5. `inherit owner = yes` → UID du parent seulement.
6. ACL : descripteur envoyé par le client, sinon héritage NT (`acl_xattr`), sinon ACL POSIX de base dérivée du mode (+ ACL par défaut pour un dossier) quand le FS gère les ACL POSIX.

### 4. Chaque accès

Connexion en lecture seule → toute écriture refusée ; puis DACL NT (`security.NTACL`, avec `acl_xattr`) **et** droits POSIX : les deux doivent accorder l'accès.

## Pièges du parseur ksmbd-tools

- Clés insensibles à la casse mais **espaces significatifs**, pas d'alias Samba (`create mode`, `public`, `browsable`… ignorés).
- **La première occurrence d'une clé gagne** (Samba : la dernière).
- Booléens par préfixe de `yes`, `true`, `1`, `enable` ; `on` vaut **faux**.
- `server signing` / `smb3 encryption` : `enabled`, `auto`, `mandatory`, sinon **disabled** (`required`, `yes`… → disabled sans message).
- `map to guest = bad password` est désactivé dans le code.

## Conversion Samba → ksmbd

Lit `smb.conf` et le registre (`net conf list`, utilisé par cockpit-file-sharing) ;
normalise clés et valeurs ; signale chaque paramètre abandonné (security ADS, passdb,
shadow_copy2, recycle, full_audit, catia, inherit permissions, %U…) ; ignore
[homes] / [printers] ; garde les IP exactes de `hosts allow/deny` en signalant les plages
perdues ; convertit `fruit:time machine` ; ajoute RDMA (`server multi channel support`,
`smbd max io size`, `interfaces`, `bind interfaces only`), `durable handles`,
`smb2 leases`, tailles d'E/S, signature, chiffrement, dialecte minimal ; produit la
liste des commandes à exécuter (comptes `ksmbd.adduser`, arrêt de Samba, vérifs RDMA,
port 5445 pour iWARP).

Le résultat est chargé dans l'éditeur ; l'écriture crée `ksmbd.conf.bak-<date>` puis
lance `ksmbd.control --reload`.

## Tests

```bash
cd file-sharing && yarn vitest run src/tabs/ksmbd
```
