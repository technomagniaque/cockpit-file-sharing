<script setup lang="ts">
/**
 * Simulateur de l'empilement des permissions ksmbd : connexion au partage,
 * identité effective, mode / propriétaire / ACL des objets créés, et couches
 * vérifiées à chaque accès.
 */
import { computed, reactive, ref, watch } from "vue";
import type { IniDocument } from "../ini";
import { getValue, findSection } from "../ini";
import { evaluateTreeConnect, effectiveIdentity, computeCreate, accessLayers, effectiveShare, type UserDb, type StackStep } from "../permission-stack";
import type { KsmbdManager, PathProbe } from "../ksmbd-manager";

const props = defineProps<{ doc: IniDocument; db: UserDb; manager: KsmbdManager; workerUmask?: number | null }>();

const shares = computed(() => props.doc.sections.filter((s) => s.name.toLowerCase() !== "global" && s.name.toLowerCase() !== "ipc$").map((s) => s.name));
const ctx = reactive({ share: "", account: "", peerAddr: "192.168.0.10", guestSession: false, badPassword: false });
const create = reactive({ kind: "file" as "file" | "dir", posixMode: "", posixAclFs: true, parentHasDefaultAcl: false, parentHasInheritableNtAcl: false, parentSetgid: false, parentOwner: "", parentGroup: "", clientSendsSecurityDescriptor: false, umask: "" });
watch(() => props.workerUmask, (u) => { if (u !== null && u !== undefined) create.umask = u.toString(8).padStart(4, "0"); }, { immediate: true });
const pathProbe = ref<PathProbe | null>(null);
const probing = ref(false);

watch(shares, (s) => { if (!ctx.share && s.length) ctx.share = s[0]!; }, { immediate: true });
watch(() => props.db, (db) => { if (!ctx.account) ctx.account = db.ksmbdUsers[0] ?? ""; }, { immediate: true });

async function probeSharePath() {
  const path = getValue(findSection(props.doc, ctx.share), "path");
  if (!path) return;
  probing.value = true;
  try {
    const p = await props.manager.probePath(path);
    pathProbe.value = p;
    if (p.exists) {
      create.posixAclFs = p.posixAclFs;
      create.parentHasDefaultAcl = p.hasDefaultAcl;
      create.parentHasInheritableNtAcl = p.hasNtAcl;
      create.parentSetgid = p.setgid;
      create.parentOwner = p.owner;
      create.parentGroup = p.group;
    }
  } finally {
    probing.value = false;
  }
}
watch(() => ctx.share, () => { pathProbe.value = null; probeSharePath(); }, { immediate: true });

const connect = computed(() => (ctx.share ? evaluateTreeConnect(props.doc, ctx.share, ctx, props.db) : null));
const identity = computed(() => (ctx.share && ctx.account ? effectiveIdentity(props.doc, ctx.share, connect.value?.guest ? connect.value.effectiveAccount ?? ctx.account : ctx.account, props.db) : null));
const created = computed(() =>
  ctx.share && ctx.account
    ? computeCreate(props.doc, ctx.share, ctx.account, props.db, {
        ...create,
        posixMode: create.posixMode ? parseInt(create.posixMode, 8) : undefined,
        umask: parseInt(create.umask || "0022", 8) || 0,
      })
    : null
);
const layers = computed(() => (ctx.share ? accessLayers(props.doc, ctx.share) : []));
const eff = computed(() => (ctx.share ? effectiveShare(props.doc, ctx.share) : {}));
const overridden = computed(() => Object.entries(eff.value).filter(([, v]) => v.origin !== "default" && v.value));

const effectClass = (s: StackStep) =>
  ({ deny: "text-danger", ro: "text-warning", rw: "text-success", bind: "text-success", pass: "text-muted", info: "", ignored: "text-muted line-through" })[s.effect];
const effectLabel = (s: StackStep) =>
  ({ deny: "REFUS", ro: "lecture seule", rw: "écriture", bind: "accepté", pass: "suite", info: "", ignored: "ignoré" })[s.effect];
const statusLabel = (s?: string) => ({ deny: "Refusé", ro: "Lecture seule", rw: "Lecture-écriture" })[s ?? "deny"];
const oct = (n: number) => n.toString(8).padStart(4, "0");
const sym = (m: number) =>
  [0o400, 0o200, 0o100, 0o40, 0o20, 0o10, 0o4, 0o2, 0o1].map((b, i) => (m & b ? "rwx"[i % 3] : "-")).join("") +
  (m & 0o2000 ? " +setgid" : "");
</script>

<template>
  <div class="space-y-4 text-sm">
    <div class="grid grid-cols-1 md:grid-cols-5 gap-3">
      <div>
        <label class="text-label block">Partage</label>
        <select v-model="ctx.share" class="input-textlike w-full">
          <option v-for="s in shares" :key="s" :value="s">{{ s }}</option>
        </select>
      </div>
      <div>
        <label class="text-label block">Compte</label>
        <input v-model="ctx.account" list="ksmbd-accounts" class="input-textlike w-full" />
        <datalist id="ksmbd-accounts">
          <option v-for="u in db.ksmbdUsers" :key="u" :value="u" />
        </datalist>
      </div>
      <div>
        <label class="text-label block">IP du client</label>
        <input v-model="ctx.peerAddr" class="input-textlike w-full font-mono" />
      </div>
      <label class="flex items-center gap-2 mt-5"><input type="checkbox" v-model="ctx.guestSession" /> session invité</label>
      <label class="flex items-center gap-2 mt-5"><input type="checkbox" v-model="ctx.badPassword" /> mauvais mot de passe</label>
    </div>

    <div v-if="connect" class="rounded-lg border border-default p-3">
      <div class="text-header">
        1. Connexion au partage :
        <span :class="connect.status === 'deny' ? 'text-danger' : connect.status === 'ro' ? 'text-warning' : 'text-success'">{{ statusLabel(connect.status) }}</span>
        <span v-if="connect.guest" class="text-xs text-muted ml-2">(invité : {{ connect.effectiveAccount }})</span>
      </div>
      <table class="w-full mt-2">
        <tbody>
          <tr v-for="(s, i) in connect.steps" :key="i" class="border-t border-default align-top">
            <td class="py-1 pr-2 w-6 text-muted">{{ i + 1 }}</td>
            <td class="pr-2 w-48">{{ s.label }}</td>
            <td class="pr-2 font-mono text-xs w-64 break-all">{{ s.param ? `${s.param} = ${s.value ?? ''}` : '' }}</td>
            <td class="pr-2" :class="effectClass(s)">{{ effectLabel(s) }}</td>
            <td class="text-muted">{{ s.detail }}</td>
          </tr>
        </tbody>
      </table>
      <ul v-if="connect.warnings.length" class="mt-2 list-disc pl-5 text-warning">
        <li v-for="w in connect.warnings" :key="w">{{ w }}</li>
      </ul>
      <p class="text-xs text-muted mt-2">
        Ordre réel de ksmbd-tools : mot de passe → invité → compte ksmbd → invalid users → read list → write list → valid users.
        hosts allow, hosts deny et admin users sont ignorés par ksmbd-tools actuel (KSMBD_SHARE_CONF_IS_BROKEN).
        Les @groupes sont développés au chargement de la configuration : après un changement de groupe Unix, exécutez « ksmbd.control --reload ».
      </p>
    </div>

    <div v-if="identity && connect?.status !== 'deny'" class="rounded-lg border border-default p-3">
      <div class="text-header">2. Identité des opérations : {{ identity.uid }}:{{ identity.gid }}</div>
      <div v-for="(s, i) in identity.steps" :key="i" class="flex gap-2">
        <span class="w-48">{{ s.label }}</span><span class="text-muted">{{ s.detail }}</span>
      </div>
    </div>

    <div class="rounded-lg border border-default p-3">
      <div class="text-header">3. Contrôle à chaque accès</div>
      <div v-for="(s, i) in layers" :key="i" class="flex gap-2 mt-1">
        <span class="w-56">{{ s.label }}</span><span class="text-muted">{{ s.detail }}</span>
      </div>
    </div>

    <div class="rounded-lg border border-default p-3 space-y-2">
      <div class="text-header">4. Création d'un fichier ou dossier</div>
      <div class="text-xs text-muted">
        <template v-if="probing">Lecture du dossier du partage…</template>
        <template v-else-if="pathProbe?.exists">
          Racine du partage : {{ pathProbe.owner }}:{{ pathProbe.group }} {{ pathProbe.mode }}, {{ pathProbe.fstype }}
          <template v-if="pathProbe.acltype"> (acltype={{ pathProbe.acltype }})</template>,
          ACL par défaut : {{ pathProbe.hasDefaultAcl ? "oui" : "non" }}, ACL NT : {{ pathProbe.hasNtAcl ? "oui" : "non" }}.
          Les cases ci-dessous sont préremplies, modifiez-les pour simuler un sous-dossier.
        </template>
        <template v-else-if="pathProbe">Chemin introuvable sur le serveur.</template>
      </div>
      <div class="grid grid-cols-2 md:grid-cols-4 gap-2">
        <select v-model="create.kind" class="input-textlike">
          <option value="file">Fichier</option>
          <option value="dir">Dossier</option>
        </select>
        <input v-model="create.posixMode" class="input-textlike font-mono" placeholder="mode client POSIX (vide = Windows/macOS)" />
        <input v-model="create.umask" class="input-textlike font-mono" :title="workerUmask != null ? 'umask lu sur le serveur (kthreadd)' : 'umask non lu : 0022 sur les noyaux récents'" placeholder="umask (0022)" />
        <span></span>
        <label class="flex items-center gap-1"><input type="checkbox" v-model="create.posixAclFs" /> FS avec ACL POSIX</label>
        <label class="flex items-center gap-1"><input type="checkbox" v-model="create.parentHasDefaultAcl" /> parent : ACL par défaut</label>
        <label class="flex items-center gap-1"><input type="checkbox" v-model="create.parentSetgid" /> parent : setgid</label>
        <label class="flex items-center gap-1"><input type="checkbox" v-model="create.parentHasInheritableNtAcl" /> parent : ACL NT héritable</label>
        <label class="flex items-center gap-1 md:col-span-2"><input type="checkbox" v-model="create.clientSendsSecurityDescriptor" /> le client envoie un descripteur de sécurité</label>
      </div>
      <template v-if="created">
        <div class="font-mono">
          Résultat : {{ oct(created.statMode) }} ({{ sym(created.statMode) }}{{ created.effective ? '+' : '' }}) — {{ created.owner }}:{{ created.group }}
        </div>
        <div v-if="created.effective" class="text-xs text-muted">
          Mode vu par stat : bits groupe = masque de l'ACL. Droits effectifs : {{ created.effective }}.
        </div>
        <div class="text-xs font-mono">ACL : {{ created.acl }}</div>
        <div v-for="(s, i) in created.steps" :key="i" class="flex gap-2">
          <span class="w-48">{{ s.label }}</span>
          <span class="font-mono text-xs w-56 break-all">{{ s.param ? `${s.param} = ${s.value}` : '' }}</span>
          <span class="text-muted">{{ s.detail }}</span>
        </div>
        <ul v-if="created.warnings.length" class="list-disc pl-5 text-warning">
          <li v-for="w in created.warnings" :key="w">{{ w }}</li>
        </ul>
      </template>
    </div>

    <details class="rounded-lg border border-default p-3">
      <summary class="cursor-pointer text-label">Paramètres effectifs du partage (hors défauts)</summary>
      <div v-for="[k, v] in overridden" :key="k" class="font-mono text-xs">
        {{ k }} = {{ v.value }} <span class="text-muted">({{ v.origin === 'global' ? 'hérité de [global]' : 'partage' }})</span>
      </div>
    </details>
  </div>
</template>
