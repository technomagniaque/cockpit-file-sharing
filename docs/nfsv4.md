# NFSv3 + NFSv4.1, NFS sur RDMA et cohabitation avec ksmbd

Code : `file-sharing/src/tabs/nfs/nfsv4.ts` (analyse et édition de nfs.conf, module pur),
`file-sharing/src/tabs/nfs/nfsv4-manager.ts` (accès serveur), `file-sharing/src/tabs/nfs/ui/NFSv4Panel.vue`
(volet de l'onglet NFS), `file-sharing/src/common/dual-protocol.ts` (constats SMB + NFS),
`file-sharing/src/tabs/ksmbd/smb-dialects.ts` (dialectes SMB).

Références noyau : arbre Linux 7.4-rc consulté localement, comparé à **v6.12** (base d'UEK8) sur les
points cités ; aucune différence de comportement trouvée sauf mention. Les clés et défauts de
`nfs.conf(5)` et `exports(5)` sont cités de mémoire (le dépôt nfs-utils n'était pas accessible).

## Cible : NFSv3 + NFSv4.1 sur tous les exports

Les versions NFS sont **globales au serveur** : `fs/nfsd/nfssvc.c` `nfsd_vers()` tient un tableau par
espace de noms réseau, et aucun drapeau d'export (`NFSEXP_*`) ne restreint une version. Tout client
autorisé sur un export peut donc le monter en v3 comme en v4.1. On restreint par la liste des clients
de chaque export, par le pare-feu, ou avec `sec=krb5*` (contrôlé pour toutes les versions par
`check_nfsd_access`, donc valable aussi en v3 avec rpc.gssd / gss-proxy).

### Interrupteurs par version

Le volet NFS a une case par version (v3, 4.0, 4.1, 4.2), écrite dans `[nfsd]` : `vers3`, `vers4.0`,
`vers4.1`, `vers4.2`, et `vers4` qui suit (y si au moins une mineure). Vérifié dans le noyau :

- les versions mineures sont **indépendantes** (`nfsd_minorversion`) : 4.2 sans 4.1 est accepté ;
- couper toutes les mineures coupe v4 (`nfsd_adjust_nfsd_versions4`) ;
- **tout couper réactive tout** (`__write_versions` → `nfsd_reset_versions`) : l'interface le refuse ;
- les versions ne changent pas pendant que nfsd tourne (`-EBUSY`) : `systemctl restart nfs-server` ;
- `/proc/fs/nfsd/versions` n'affiche jamais `+4.0` : 4.0 est implicite dans `+4` sauf `-4.0`
  (`nfsd_print_version_support`).

Préréglages (raccourcis qui positionnent ces cases) :

| Préréglage | Versions | Autres réglages |
|---|---|---|
| **Recommandé : NFSv3 + NFSv4.1** | v3, 4.1 (4.2 au choix), 4.0 coupé | `udp=n`, ports v3 fixes (ci-dessous) |
| NFSv4.1 seulement | 4.1 (4.2 au choix) | `udp=n` |

Garde-fous affichés : v3 coupé (clients ESXi NFS 3, appliances, sauvegardes), 4.1 coupé, 4.2 sans 4.1,
RDMA indépendant des versions.

**Note honnête sur les performances** : couper des versions réduit la surface d'attaque et les
négociations, mais le débit dépend surtout du groupe « Performances » : threads nfsd (valeur réelle lue
dans `/proc/fs/nfsd/threads` ; rpc.nfsd(8) indique 8 par défaut), RDMA, `rsize` / `wsize` côté client
(1 Mio maximum chez knfsd, `RPCSVC_MAXPAYLOAD`), `nconnect`, `sync` + SLOG plutôt que `async`, et le
coût de `krb5i` / `krb5p`.

### Ports et services NFSv3

| Service | Clé nfs.conf | Port fixé par le préréglage |
|---|---|---|
| rpcbind | — | 111 tcp / udp |
| nfsd | — | 2049 tcp |
| mountd | `[mountd] port` | 20048 |
| statd | `[statd] port`, `outgoing-port` | 662, 2020 |
| lockd (NLM) | `[lockd] port`, `udp-port` | 32803, 32769 |

`rpcbind.socket`, `nfs-mountd` et `rpc-statd` doivent être actifs ; la sonde le vérifie.
**rpc.mountd doit tourner même en NFSv4 seul** (upcalls `nfsd.export` / `auth.unix.ip` du noyau) :
seul son port réseau est alors inutile à ouvrir.

### Datasets ZFS enfants

`fs/nfsd/vfs.c` `nfsd_cross_mnt` traverse un point de montage pour un client v4, ou si l'export parent a
`crossmnt`, ou si l'enfant a `nohide` ; l'enfant doit être connu de mountd (export explicite ou
synthétisé par `crossmnt`). Côté client, seul un client Linux suit ce changement de système de
fichiers en v3 ; ESXi, macOS et Windows ne le font pas. Le volet liste donc les datasets enfants de
chaque export ZFS (`zfs list -r`) et **propose une ligne d'export par dataset non exporté**, avec les
mêmes options et un `fsid` unique. Chaque dataset se monte alors séparément en v3.

### ACL en NFSv3

Les clients v3 lisent et écrivent les ACL POSIX telles quelles (programme NFSACL 100227,
`fs/nfsd/nfs3acl.c`, 1024 entrées max. `NFS_ACL_MAX_ENTRIES`), tandis que les clients v4.1 voient leur
traduction en ACL NFSv4. Une ACL posée en v4 qui n'est pas représentable en POSIX est refusée ; vue
depuis v3, l'ACL est toujours exacte.

### Identités

`nfs4_disable_idmapping` vaut Y par défaut (vérifié en 6.12 et 7.4) : avec `sec=sys`, v4.1 transmet des
UID / GID numériques, **comme v3** : les deux versions voient les mêmes propriétaires. Avec `N`, v4.1
passe par `utilisateur@domaine` (idmapd) et v3 reste numérique : un compte absent apparaît `nobody` en
v4.1 mais avec son numéro en v3. Le volet le signale.

## nfs.conf.d et include

`/etc/nfs.conf.d/*.conf` est lu après `nfs.conf` et l'emporte. Le volet affiche le nfs.conf
**effectif**, signale chaque clé surchargée et la directive `include`. Les modifications du plugin vont
dans `/etc/nfs.conf` (copie `.bak-<date>`, refusée si la copie échoue) : retirez une clé surchargée
dans nfs.conf.d pour qu'elle prenne effet.

La clé `[gssd] use-gss-proxy` a été retirée du volet : elle concerne rpc.gssd (client). Côté serveur,
Kerberos passe par `gssproxy.service` et `/etc/gssproxy/24-nfs-server.conf`.

## NFS sur RDMA

- **Serveur** : `[nfsd] rdma=y`, `rdma-port=20049` (bouton dans le volet). Le transport « rdma »
  (`net/sunrpc/xprtrdma/svc_rdma_transport.c`) exige `CONFIG_SUNRPC_XPRT_RDMA` et le module `rpcrdma`.
  Sonde : `/proc/fs/nfsd/portlist` (ligne `rdma 20049`), module chargé, `rdma link show`, type de nœud
  (`/sys/class/infiniband/*/node_type` : RNIC = iWARP, CA = InfiniBand / RoCE). À chaud :
  `echo 'rdma 20049' > /proc/fs/nfsd/portlist`.
- RDMA sert **toutes** les versions actives (v3, 4.0, 4.1, 4.2) ; mountd, statd et lockd restent en
  TCP / UDP.
- **QL41112 en NPAR** : la partition passée à la VM doit avoir la personnalité RDMA, pilote `qedr`.
- **Pare-feu** : iWARP utilise l'espace de ports TCP → `20049/tcp` ; RoCEv2 → `4791/udp` (traité par
  la carte ; utile surtout pour un pare-feu réseau). RoCE exige un réseau sans perte (PFC / ECN).
- **Client** : `mount -t nfs -o vers=4.1,proto=rdma,port=20049 serveur:/chemin /mnt` ; en v3
  `-o vers=3,proto=rdma,port=20049`. Le port 20049 est déjà le défaut avec `proto=rdma`
  (`fs/nfs/fs_context.c` `NFS_RDMA_PORT`). `nconnect` **reste accepté** avec RDMA (`fs/nfs/nfs4client.c`,
  identique en 6.12) ; `READ_PLUS` est désactivé sur RDMA (`fs/nfs/client.c`).
- **Cohabitation avec ksmbd SMB Direct** : ksmbd écoute en RDMA sur 445 (IB / RoCE) et 5445 (iWARP)
  (`fs/smb/server/transport_rdma.c`) : aucun conflit avec 20049, mêmes interfaces RDMA possibles.

## Options d'export contrôlées

| Option | Constat |
|---|---|
| `fsid` absent | sur ZFS l'identifiant peut changer après import du pool (« stale file handle ») : `fsid=<uuid>` |
| `sec=sys` + `*` ou sous-réseau large | AUTH_SYS fait confiance à l'UID annoncé : restreindre l'hôte ou `krb5p` |
| `no_root_squash`, `async` | dangereux ; `async` encore plus en v3 (COMMIT) |
| datasets enfants | à exporter explicitement (v3) ; `crossmnt` en complément pour v4 |
| `no_acl` | **sans effet sur knfsd** : `NFSEXP_NOACL` n'est jamais lu dans `fs/nfsd` |
| `pnfs` | layouts bloc / SCSI, pas pour ZFS |
| `security_label`, `xprtsec=` | reconnus (NFSv4.2, RPC-with-TLS) |

`/etc/exports.d/zfs.exports` (propriété `sharenfs`) est signalé : ces exports échappent au plugin.

## ACL : ce que voient les clients NFSv4

OpenZFS upstream sous Linux ne gère pas `acltype=nfsv4` (seulement FreeBSD et le fork TrueNAS).
Avec `acltype=posixacl`, knfsd présente l'ACL POSIX sous forme d'ACL NFSv4 (`nfsd4_get_nfs4_acl`) ;
une ACL posée par `nfs4_setfacl` doit se traduire en POSIX, sinon EINVAL (`nfs4_acl_nfsv4_to_posix`).

## SMB (ksmbd) et NFS sur le même dataset

Constats vérifiés dans le code noyau, affichés dans l'onglet ksmbd (section « Cohabitation NFS ») et
dans le volet NFS pour chaque export qui recoupe un partage (chemins comparés **après résolution**
`readlink -f`).

| Sujet | Comportement | Recommandation |
|---|---|---|
| Oplocks et baux SMB | Internes à ksmbd (`oplock.c`) ; aucun `vfs_setlease` : une écriture NFS ne rappelle jamais le cache d'un client SMB | `oplocks = no` sur le partage (bloque oplocks **et** baux pour ce partage, `smb2_open` teste `KSMBD_SHARE_FLAG_OPLOCKS`) — v3 comme v4 |
| Délégations NFSv4 | ksmbd ouvre en `O_NONBLOCK` (`smb2_open`) : `__break_lease` lance le rappel puis renvoie `-EWOULDBLOCK` **sans attendre**. En 6.12 le client reçoit `STATUS_UNEXPECTED_IO_ERROR` (7.4 : `STATUS_FILE_NOT_AVAILABLE`). Toute ouverture SMB en écriture d'un fichier délégué en lecture, toute ouverture d'un fichier délégué en écriture. `lease-break-time` ne s'applique pas (`nfsd_break_deleg_cb` met `fl_break_time = 0`) | **`fs.leases-enable=0` d'office sur un serveur double protocole** |
| Suppression SMB d'un fichier délégué | delete-on-close → `__ksmbd_inode_close` → `ksmbd_vfs_unlink` → `vfs_unlink(…, NULL)` → `-EWOULDBLOCK` consigné seulement en debug ; la fermeture répond succès : **le fichier revient** | idem (critique) |
| Renommage / attributs SMB | `ksmbd_vfs_rename` et `notify_change` sans `delegated_inode` → `-EAGAIN` → `STATUS_FILE_LOCK_CONFLICT` (`smb2_set_info`), sans nouvel essai automatique connu côté Windows | idem |
| `fs.leases-enable=0` | Testé seulement dans `generic_add_lease` : refuse les **nouveaux** baux (délégations nfsd lecture / écriture, layouts pNFS, `F_SETLEASE`). Global à l'hôte (tous les conteneurs). Aucun réglage nfsd dédié | `/etc/sysctl.d/99-nfs-ksmbd.conf` : `fs.leases-enable = 0`, `sysctl -p …`, **puis `systemctl restart nfs-server`** (les délégations déjà accordées restent). Proposé par le plugin, jamais écrit sans confirmation |
| Verrous de plage | ksmbd pose des verrous POSIX (`smb2_lock` → `vfs_lock_file`), comme NLM en v3 (`fs/lockd/svclock.c`). Un verrou **même partagé** posé par NFS ou un processus local bloque toute écriture SMB sur la plage (`check_lock_range` : échec immédiat `STATUS_FILE_LOCK_CONFLICT`, un `pr_err` par E/S refusée, qui peut inonder dmesg). Les E/S NFS ignorent les verrous. La période de grâce NLM / nfsd n'est pas respectée par ksmbd | — |
| Modes de partage | Internes à ksmbd et à nfsd ; aucune exclusion croisée | Éviter l'édition simultanée d'un même fichier |
| `acl_xattr` | DACL vérifiée par ksmbd seulement | Retirer `acl_xattr`, effacer `security.NTACL` |
| Poignées durables | Accordées selon la demande du client, **indépendamment** de `oplocks = no` ; une poignée orpheline garde le fichier ouvert au moins 60 s | Signalé si `durable handles = yes` |
| Caches d'attributs | Ni le cache d'attributs NFS (`actimeo`, cohérence fermeture → ouverture) ni le cache de métadonnées Windows (~10 s) ne sont couverts par `oplocks = no`. Change attribute NFSv4 sur ZFS = ctime (granularité grossière possible en 6.12, non vérifié) | Information |
| `streams_xattr`, `user.DOSATTRIB` | Invisibles en v3 et v4.1 (xattrs seulement en 4.2) | — |
| `force user` / `force group` | Propriétaires divergents | `all_squash,anonuid=…,anongid=…` ou ACL par défaut |
| Création de fichiers | umask des workers ksmbd vs umask des clients | ACL POSIX par défaut + setgid |
| Time Machine | Exige baux et poignées durables | Partage SMB seul |

Le bouton « Appliquer les réglages double protocole recommandés » de l'onglet ksmbd modifie la
configuration affichée, sans l'enregistrer : `oplocks = no` ; `acl_xattr` retiré (ou signalé s'il vient
de `[global]`) ; `time machine = no` (y compris hérité de `[global]`) ; et affiche les commandes
`fs.leases-enable=0` à exécuter soi-même.

## Dialectes SMB (ksmbd)

Une case par dialecte dans l'onglet ksmbd, ramenée à la plage contiguë `server min protocol` …
`server max protocol` (seule possibilité de ksmbd). Dialectes négociables (`smb_common.c` `smb2_protos`) :
`SMB2_10`, `SMB3_00`, `SMB3_02`, `SMB3_11`. `SMB2_22` n'est pas un dialecte (joker de négociation SMB1) ;
SMB1 n'existe pas. Couper un dialecte au milieu de la plage est refusé, ou l'interface propose de couper
aussi tout ce qui est plus ancien ou plus récent, avec la liste des clients perdus. Multicanal et
SMB Direct exigent SMB3_00+, AES-GCM et la pré-authentification SMB3_11. Changement global :
redémarrage complet de ksmbd.
