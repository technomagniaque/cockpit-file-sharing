# NFSv4.1 et cohabitation avec ksmbd

Code : `file-sharing/src/tabs/nfs/nfsv4.ts` (analyse et édition de nfs.conf, module pur),
`file-sharing/src/tabs/nfs/nfsv4-manager.ts` (accès serveur), `file-sharing/src/tabs/nfs/ui/NFSv4Panel.vue`
(volet de l'onglet NFS), `file-sharing/src/common/dual-protocol.ts` (constats SMB + NFS).

Références noyau : arbre Linux 7.4-rc consulté localement. Les clés et défauts de `nfs.conf(5)`
et `exports(5)` sont cités de mémoire (le dépôt nfs-utils n'était pas accessible pour vérification).

## Serveur NFSv4.1 seul

Dans l'onglet NFS, volet « NFSv4.1 » :

- versions de `/etc/nfs.conf` comparées à celles réellement servies (`/proc/fs/nfsd/versions`) ;
- préréglage « NFSv4.1 seulement » : `vers3=n`, `vers4.0=n`, `vers4.1=y`, `vers4.2` au choix, `udp=n` ;
- champs `threads`, `grace-time`, `lease-time`, `rdma` / `rdma-port` (NFS sur RDMA, utile avec une carte
  iWARP / RoCE), `[mountd] manage-gids`, `[gssd] use-gss-proxy` ;
- l'écriture garde les commentaires du fichier et crée `nfs.conf.bak-<date>`.

Les versions ne changent qu'au démarrage de nfsd : `systemctl restart nfs-server`.

**Pare-feu** : en NFSv4.1 seul, uniquement `2049/tcp` (`firewall-cmd --add-service=nfs`).
rpcbind (111) et mountd (20048) ne servent qu'à NFSv3. Ajoutez `20049/tcp` si NFS/RDMA est actif.

## Identités (idmapping)

- `nfs4_disable_idmapping` vaut Y par défaut : avec `sec=sys`, knfsd envoie des UID / GID **numériques**
  (`fs/nfsd/nfs4idmap.c`, `encode_name_from_id`). Serveur et clients doivent partager les mêmes UID / GID.
- Avec Kerberos (`sec=krb5`, `krb5i`, `krb5p`) ou l'idmapping actif, les noms circulent sous la forme
  `utilisateur@domaine` : `Domain` de `/etc/idmapd.conf` doit être identique partout, sinon les fichiers
  appartiennent à `nobody`.

## Options d'export contrôlées

| Option | Constat |
|---|---|
| `fsid` absent | sur ZFS l'identifiant peut changer après import du pool, ce qui provoque des « stale file handle » : mettre `fsid=<uuid>` |
| `sec=sys` + `*` ou sous-réseau large | AUTH_SYS fait confiance à l'UID annoncé : restreindre l'hôte ou passer à `krb5p` |
| `no_root_squash`, `async` | dangereux (root distant, pertes silencieuses) |
| sans `crossmnt` | les datasets ZFS enfants apparaissent vides |
| `no_acl` | **sans effet sur knfsd** : `NFSEXP_NOACL` n'est jamais lu dans `fs/nfsd` |
| `pnfs` | layouts bloc / SCSI, pas pour ZFS |
| `security_label`, `xprtsec=` | reconnus (NFSv4.2, RPC-with-TLS) |

Le volet signale aussi `/etc/exports.d/zfs.exports` : les datasets avec la propriété `sharenfs`
génèrent des exports que le plugin ne gère pas.

## ACL : ce que voient les clients NFSv4

OpenZFS upstream sous Linux ne gère pas `acltype=nfsv4` (seulement FreeBSD et le fork TrueNAS).
Avec `acltype=posixacl`, knfsd présente l'ACL POSIX sous forme d'ACL NFSv4 (`nfs4_getfacl`,
`fs/nfsd/nfs4acl.c` `nfsd4_get_nfs4_acl`). Une ACL NFSv4 posée par un client (`nfs4_setfacl`) doit
pouvoir se traduire en ACL POSIX, sinon le serveur répond EINVAL (`nfs4_acl_nfsv4_to_posix`).

## SMB (ksmbd) et NFSv4.1 sur le même dataset

Constats vérifiés dans le code noyau, affichés dans l'onglet ksmbd (section « Cohabitation NFS »)
et dans le volet NFSv4.1 pour chaque export qui recoupe un partage.

| Sujet | Comportement | Recommandation |
|---|---|---|
| Oplocks et baux SMB | Gérés en interne par ksmbd (`fs/smb/server/oplock.c`). `fs/smb/server` n'appelle jamais `vfs_setlease` ni `kernel_setlease` : une écriture NFS ne rappelle jamais le cache d'un client SMB, qui peut lire des données périmées ou écraser des modifications | `oplocks = no` sur le partage. Cela bloque oplocks **et** baux pour ce partage (`smb2pdu.c` `smb2_open` teste `KSMBD_SHARE_FLAG_OPLOCKS` et n'appelle alors pas `smb_grant_oplock`). `smb2 leases` peut rester actif pour les autres partages |
| Délégations NFSv4 | Ce sont des baux noyau (`fs/nfsd/nfs4state.c`, `kernel_setlease`). ksmbd ouvre par `dentry_open` → `do_dentry_open` → `break_lease` (`fs/open.c`) : une ouverture SMB rappelle la délégation et attend le client NFS. Suppression ou renommage SMB : `vfs_unlink` / `vfs_rename` sans `delegated_inode` → `try_break_deleg` non bloquant → `-EWOULDBLOCK` temporaire | Rien à faire en général. Si des ouvertures SMB se figent : `sysctl fs.leases-enable=0` (désactive tous les baux du système ; aucun réglage dédié dans nfsd) |
| Verrous de plage | ksmbd pose des verrous POSIX noyau (`smb2pdu.c` `smb2_lock` → `vfs_lock_file`), en conflit avec les verrous NFS. Les E/S SMB respectent tout verrou POSIX (`vfs.c` `check_lock_range`), les E/S NFS ignorent les verrous | — |
| Modes de partage (deny write) | Internes à ksmbd (`smb_common.c` `ksmbd_smb_check_shared_mode`) ; les « deny » NFSv4 sont internes à nfsd (`st_deny_bmap`). Aucune exclusion croisée | Éviter l'édition simultanée d'un même fichier par les deux protocoles |
| `acl_xattr` | La DACL `security.NTACL` n'est vérifiée que par ksmbd (`smbacl.c` `smb_check_perm_dacl`). NFS n'obéit qu'au mode et à l'ACL POSIX | Retirer `acl_xattr` et effacer les `security.NTACL` existants (cockpit-zfs → Permissions → « Effacer les ACL NT ») |
| `streams_xattr`, `user.DOSATTRIB` | Xattrs `user.`, invisibles en NFSv4.1 (seul NFSv4.2 transporte les xattrs, RFC 8276). Une copie faite côté NFS les perd | — |
| `force user` / `force group` | En SMB, tout est créé sous ce compte ; en NFS, sous l'UID du client | `all_squash,anonuid=<uid>,anongid=<gid>` côté NFS, ou ACL par défaut |
| Création de fichiers | En SMB : masques puis umask des workers ksmbd. En NFS : umask du client. Sans ACL par défaut, les droits diffèrent | ACL POSIX par défaut + setgid sur la racine du partage |
| Time Machine | Exige baux et poignées durables, donc incompatible avec `oplocks = no` | Garder la cible Time Machine sur un partage SMB seul |

Samba proposait `kernel oplocks` et `kernel share modes` (baux et verrous noyau) pour une
cohabitation partielle ; ksmbd n'a **aucun équivalent**. Le convertisseur Samba → ksmbd ajoute ces
constats au rapport quand un partage a le même chemin qu'un export NFS, et bloque si
`oplocks = no` manque.

Le bouton « Appliquer les réglages double protocole recommandés » de l'onglet ksmbd modifie la
configuration affichée, sans l'enregistrer :

- `oplocks = no` ;
- `acl_xattr` retiré de `vfs objects`, ou signalé s'il vient de `[global]`, puisqu'une valeur vide est ignorée par ksmbd-tools ;
- `time machine = no`.
