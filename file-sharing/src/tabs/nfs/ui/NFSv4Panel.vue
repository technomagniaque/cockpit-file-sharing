<script setup lang="ts">
/**
 * Volet NFSv3 + NFSv4.1 : interrupteurs de version, nfs.conf, performances,
 * RDMA, idmapping, contrôle des exports (datasets enfants pour v3) et
 * cohabitation avec les partages ksmbd.
 */
import { computed, onMounted, ref, watch } from "vue";
import { CardContainer, pushNotification, Notification } from "@45drives/houston-common-ui";
import type { NFSExport } from "@/tabs/nfs/data-types";
import {
  NFS_CONF_FIELDS, getNfsConf, setNfsConf, applyV41OnlyPreset, applyV3V41Preset, applyRdma, configuredVersions, parseProcVersions,
  analyzeServer, analyzeExportV41, analyzeExportV3, nfsConfBool, setVersions, versionGuards, currentVersions, effectiveNfsConf,
  clientMountCommands, NFS_VERSION_INFO, NFS_PERF_KEYS, NFS_CLIENT_PERF_TIPS,
  type Finding, type NfsConfField, type NfsVersionKey,
} from "@/tabs/nfs/nfsv4";
import { LEASES_SYSCTL } from "@/common/dual-protocol";
import type { UserDb } from "@/tabs/ksmbd/permission-stack";
import { NFSv4Manager, type NfsServerSnapshot } from "@/tabs/nfs/nfsv4-manager";
import { KsmbdManager } from "@/tabs/ksmbd/ksmbd-manager";
import { parseIni, findSection, getValue, type IniDocument } from "@/tabs/ksmbd/ini";
import { analyzeDualProtocol, overlappingExports, type DualFinding } from "@/common/dual-protocol";

const props = defineProps<{ nfsExports: NFSExport[] }>();

const manager = new NFSv4Manager();
const ksmbd = new KsmbdManager();
const snap = ref<NfsServerSnapshot | null>(null);
const confText = ref("");
const savedConf = ref("");
const raw = ref(false);
const busy = ref(false);
const keepV42 = ref(true);
const ksmbdDoc = ref<IniDocument | null>(null);
const workerUmask = ref<string | undefined>(undefined);
const ksmbdDb = ref<UserDb | undefined>(undefined);
const rootDefaultAcl = ref<Record<string, boolean>>({});
const versionError = ref("");

async function load(force = true) {
  busy.value = true;
  try {
    snap.value = await manager.snapshot(props.nfsExports.map((e) => e.path));
    // ne pas écraser une modification non enregistrée lors d'un rechargement automatique
    if (force || confText.value === savedConf.value) confText.value = snap.value.nfsConf;
    savedConf.value = snap.value.nfsConf;
    try {
      const text = await ksmbd.readConf();
      ksmbdDoc.value = text.trim() ? parseIni(text, "ksmbd") : null;
      if (ksmbdDoc.value) {
        const p = await ksmbd.probe();
        workerUmask.value = p.workerUmask !== null ? p.workerUmask.toString(8).padStart(4, "0") : undefined;
        ksmbdDb.value = await ksmbd.userDb();
        const acl: Record<string, boolean> = {};
        for (const s of ksmbdDoc.value.sections) {
          const path = getValue(s, "path");
          if (path) acl[path] = (await ksmbd.probePath(path)).hasDefaultAcl;
        }
        rootDefaultAcl.value = acl;
      }
    } catch {
      ksmbdDoc.value = null;
    }
  } catch (e: any) {
    pushNotification(new Notification("Lecture NFS impossible", e?.message ?? String(e), "error"));
  } finally {
    busy.value = false;
  }
}
onMounted(() => load(true));
watch(() => props.nfsExports.map((e) => e.path).join("\n"), () => load(false));

const modified = computed(() => confText.value !== savedConf.value);
const effConf = computed(() => effectiveNfsConf({ nfsConf: confText.value, nfsConfD: snap.value?.nfsConfD }));
const conf = computed(() => configuredVersions(effConf.value));
const toggles = computed(() => currentVersions(effConf.value));
const guards = computed<Finding[]>(() => versionGuards(toggles.value, { nfsConf: effConf.value }));
const rdmaOn = computed(() => nfsConfBool(getNfsConf(effConf.value, "nfsd", "rdma")));
const perfFields = computed(() => NFS_CONF_FIELDS.filter((f) => NFS_PERF_KEYS.some((k) => k.section === f.section && k.key === f.key)));
const otherFields = computed(() => NFS_CONF_FIELDS.filter((f) => !NFS_PERF_KEYS.some((k) => k.section === f.section && k.key === f.key) && !/^vers/.test(f.key)));

function toggleVersion(k: NfsVersionKey, on: boolean) {
  const next = { ...toggles.value, [k]: on };
  const r = setVersions(confText.value, next);
  versionError.value = r.ok ? "" : r.error ?? "";
  if (r.ok) confText.value = r.text;
}
const live = computed(() => (snap.value?.procVersions ? parseProcVersions(snap.value.procVersions) : null));

function fieldValue(f: NfsConfField) {
  const v = getNfsConf(confText.value, f.section, f.key);
  if (v === undefined) return "";
  // normalise yes / 1 / true… pour le menu y / n
  return f.type === "bool" ? (nfsConfBool(v) ? "y" : "n") : v;
}
function setField(f: NfsConfField, v: string) {
  confText.value = setNfsConf(confText.value, f.section, f.key, v === "" ? undefined : v);
}
function preset(kind: "v3v41" | "v41") {
  confText.value = kind === "v3v41"
    ? applyV3V41Preset(confText.value, keepV42.value, { fixPorts: true })
    : applyV41OnlyPreset(confText.value, keepV42.value);
  versionError.value = "";
}
function toggleRdma(on: boolean) {
  confText.value = applyRdma(confText.value, on);
}
async function save() {
  busy.value = true;
  try {
    const backup = await manager.writeNfsConf(confText.value);
    savedConf.value = confText.value;
    const ov = (snap.value?.nfsConfD ?? []).length ? "\nAttention : /etc/nfs.conf.d peut surcharger ces réglages." : "";
    pushNotification(new Notification("nfs.conf enregistré", `Copie : ${backup}\nRedémarrage requis : systemctl restart nfs-server${ov}`, "success", 10000));
    await load(true);
  } catch (e: any) {
    pushNotification(new Notification("Écriture impossible", e?.message ?? String(e), "error"));
  } finally {
    busy.value = false;
  }
}

const serverFindings = computed<Finding[]>(() =>
  snap.value ? analyzeServer({ ...snap.value, nfsConf: confText.value }, props.nfsExports) : []
);
const exportedPaths = computed(() => props.nfsExports.map((e) => snap.value?.resolved[e.path] ?? e.path));
const exportFindings = computed(() =>
  props.nfsExports.map((e) => {
    const isZfs = (snap.value?.fstypes[e.path] ?? "zfs") === "zfs";
    const v3 = conf.value.v3 && isZfs ? analyzeExportV3(e, snap.value?.zfsChildren[e.path] ?? [], exportedPaths.value) : { findings: [], suggestedLines: [] };
    return {
      export: e,
      findings: [...analyzeExportV41(e, isZfs), ...v3.findings],
      suggestedLines: v3.suggestedLines,
      mounts: clientMountCommands(snap.value?.hostname ?? "serveur", e.path, rdmaOn.value),
      dual: dualFor(e),
    };
  })
);
const resolve = (p: string) => snap.value?.resolved[p] ?? p;

function dualFor(e: NFSExport): { share: string; relation: string; findings: DualFinding[] }[] {
  const doc = ksmbdDoc.value;
  if (!doc) return [];
  const out: { share: string; relation: string; findings: DualFinding[] }[] = [];
  for (const s of doc.sections) {
    if (s.name.toLowerCase() === "global" || s.name.toLowerCase() === "ipc$") continue;
    const path = getValue(findSection(doc, s.name), "path") ?? "";
    for (const o of overlappingExports(path, [e], resolve)) {
      out.push({
        share: s.name,
        relation: o.relation,
        findings: analyzeDualProtocol({
          doc, share: s.name, nfsExport: e, workerUmask: workerUmask.value, db: ksmbdDb.value,
          rootHasDefaultAcl: rootDefaultAcl.value[path], leasesEnable: snap.value?.leasesEnable,
          nfsV3: conf.value.v3, nfsV4: conf.value.v40 || conf.value.v41 || conf.value.v42, resolve,
        }),
      });
    }
  }
  return out;
}

const levelClass = (l: string) => ({ danger: "text-danger", warning: "text-warning", info: "text-muted" })[l] ?? "";
const levelLabel = (l: string) => ({ danger: "critique", warning: "attention", info: "info" })[l] ?? l;
const yes = (b: boolean | undefined) => (b === undefined ? "?" : b ? "oui" : "non");
</script>

<template>
  <CardContainer>
    <template #header>NFSv3 + NFSv4.1 — versions, performances, RDMA et cohabitation SMB</template>
    <div class="space-y-4 text-sm">
      <div class="grid grid-cols-2 md:grid-cols-5 gap-2">
        <div class="text-label">Version</div><div class="text-label">nfs.conf</div><div class="text-label">Servie (noyau)</div><div></div><div></div>
        <template v-for="row in ([['NFSv3', 'v3'], ['NFSv4.0', 'v40'], ['NFSv4.1', 'v41'], ['NFSv4.2', 'v42']] as const)" :key="row[1]">
          <div>{{ row[0] }}</div>
          <div>{{ yes(conf[row[1]]) }}</div>
          <div :class="live && live[row[1]] !== conf[row[1]] ? 'text-warning' : ''">{{ live ? yes(live[row[1]]) : "nfsd arrêté" }}</div>
          <div></div><div></div>
        </template>
      </div>
      <div class="text-xs text-muted">
        Domaine idmapd : {{ snap?.idmapdDomain ?? "(non défini)" }} — domaine DNS : {{ snap?.dnsDomain ?? "?" }} —
        nfs4_disable_idmapping : {{ snap?.disableIdmapping === undefined ? "?" : snap.disableIdmapping ? "Y (UID numériques avec sec=sys)" : "N" }}
      </div>

      <div class="rounded-lg border border-default p-3">
        <div class="text-label">Versions servies (nfs.conf effectif)</div>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-2 mt-2">
          <label v-for="v in NFS_VERSION_INFO" :key="v.key" class="flex items-start gap-2">
            <input type="checkbox" class="mt-1" :checked="toggles[v.key]" @change="toggleVersion(v.key, ($event.target as HTMLInputElement).checked)" />
            <span>
              <span class="font-medium">{{ v.label }}</span>
              <span class="text-xs text-muted"> — {{ v.brings }}</span>
              <span class="block text-xs text-muted">Clients concernés : {{ v.clients }}</span>
            </span>
          </label>
        </div>
        <div v-if="versionError" class="text-danger mt-1">{{ versionError }}</div>
        <div v-for="(g, i) in guards" :key="i" class="mt-1 text-xs">
          <span :class="levelClass(g.level)">[{{ levelLabel(g.level) }}] {{ g.title }}</span>
          <span class="text-muted"> — {{ g.detail }}</span>
        </div>
        <div class="button-group-row flex-wrap items-center mt-2">
          <button class="btn btn-primary" @click="preset('v3v41')">Recommandé : NFSv3 + NFSv4.1 (ports v3 fixes)</button>
          <button class="btn btn-secondary" @click="preset('v41')">NFSv4.1 seulement</button>
          <label class="flex items-center gap-1"><input type="checkbox" v-model="keepV42" /> garder NFSv4.2</label>
        </div>
        <p class="text-xs text-muted mt-1">Les versions sont globales (aucun réglage par export) et ne changent qu'au redémarrage de nfsd : systemctl restart nfs-server.</p>
      </div>

      <div class="rounded-lg border border-default p-3">
        <div class="text-label">Performances</div>
        <p class="text-xs text-muted">Couper des versions réduit la surface d'attaque et les négociations, mais le débit dépend surtout de ces réglages, de RDMA, de sync / async et de la sécurité (krb5i / krb5p chiffrent et signent chaque requête).</p>
        <div class="grid grid-cols-1 lg:grid-cols-3 gap-3 mt-2">
          <div v-for="f in perfFields" :key="f.section + f.key">
            <label class="block"><span class="font-mono">[{{ f.section }}] {{ f.key }}</span></label>
            <select v-if="f.type === 'bool'" class="input-textlike w-full" :value="fieldValue(f)" @change="f.key === 'rdma' && ($event.target as HTMLSelectElement).value !== '' ? toggleRdma(($event.target as HTMLSelectElement).value === 'y') : setField(f, ($event.target as HTMLSelectElement).value)">
              <option value="">défaut ({{ f.default }})</option>
              <option value="y">y</option>
              <option value="n">n</option>
            </select>
            <input v-else class="input-textlike w-full font-mono" :value="fieldValue(f)" :placeholder="f.key === 'threads' && snap?.liveThreads !== undefined ? `actuel : ${snap.liveThreads}` : `défaut : ${f.default}`" @change="setField(f, ($event.target as HTMLInputElement).value.trim())" />
            <div class="text-xs text-muted">{{ f.help }}</div>
          </div>
        </div>
        <ul class="list-disc pl-5 text-xs text-muted mt-2">
          <li v-for="t in NFS_CLIENT_PERF_TIPS" :key="t">{{ t }}</li>
        </ul>
      </div>

      <div class="rounded-lg border border-default p-3">
        <div class="text-label">NFS sur RDMA</div>
        <div class="text-xs text-muted">
          rdma={{ rdmaOn ? "y" : "n" }} — module rpcrdma : {{ snap?.rpcrdmaLoaded ? "chargé" : "non chargé" }} — CONFIG_SUNRPC_XPRT_RDMA={{ snap?.xprtRdmaConfig ?? "?" }} —
          écoute : {{ snap?.portlist ? snap.portlist.split("\n").join(", ") : "nfsd arrêté" }} —
          liens : {{ (snap?.rdmaLinks ?? []).map((l) => `${l.dev}/${l.port} ${l.state}${l.netdev ? " (" + l.netdev + ")" : ""}${snap?.rdmaNodeTypes?.[l.dev] === "iwarp" ? " iWARP" : snap?.rdmaNodeTypes?.[l.dev] === "ib-roce" ? " RoCE/IB" : ""}`).join(", ") || "aucun" }}
        </div>
        <div class="button-group-row mt-2">
          <button class="btn btn-secondary" @click="toggleRdma(!rdmaOn)">{{ rdmaOn ? "Désactiver" : "Activer" }} NFS/RDMA (port 20049)</button>
        </div>
        <p class="text-xs text-muted mt-1">RDMA sert NFSv3 et NFSv4.x ; mountd, statd et lockd restent en TCP / UDP. ksmbd SMB Direct écoute sur 445 en InfiniBand / RoCE et sur 5445 en iWARP : pas de conflit.</p>
      </div>

      <div v-if="snap && snap.leasesEnable !== false && ksmbdDoc" class="rounded-lg border border-default p-3 text-warning">
        Délégations NFSv4 actives (fs.leases-enable=1) alors que ksmbd tourne : ouvertures SMB en échec et suppressions SMB perdues sur les fichiers délégués. À appliquer hors plugin, après confirmation :
        <pre class="font-mono text-xs mt-1">{{ LEASES_SYSCTL.commands.join("\n") }}</pre>
      </div>

      <div class="button-group-row flex-wrap items-center">
        <button class="btn btn-secondary" @click="raw = !raw">{{ raw ? "Champs" : "Texte brut" }}</button>
        <button class="btn btn-primary" :disabled="busy || !modified" @click="save">Enregistrer nfs.conf</button>
        <button class="btn btn-secondary" :disabled="busy || !modified" @click="confText = savedConf">Annuler</button>
        <button class="btn btn-secondary" :disabled="busy" @click="load(true)">Relire</button>
      </div>
      <p v-if="modified" class="text-xs text-warning">Modifié, non enregistré. Après enregistrement : systemctl restart nfs-server (les versions ne changent qu'au démarrage de nfsd).</p>

      <textarea v-if="raw" v-model="confText" rows="20" class="input-textlike w-full font-mono text-xs"></textarea>
      <div v-else class="grid grid-cols-1 lg:grid-cols-2 gap-3">
        <div v-for="f in otherFields" :key="f.section + f.key">
          <label class="block"><span class="font-mono">[{{ f.section }}] {{ f.key }}</span> — {{ f.label }}</label>
          <select v-if="f.type === 'bool'" class="input-textlike w-full" :value="fieldValue(f)" @change="setField(f, ($event.target as HTMLSelectElement).value)">
            <option value="">défaut ({{ f.default }})</option>
            <option value="y">y</option>
            <option value="n">n</option>
          </select>
          <input v-else class="input-textlike w-full font-mono" :value="fieldValue(f)" :placeholder="`défaut : ${f.default}`" @change="setField(f, ($event.target as HTMLInputElement).value.trim())" />
          <div class="text-xs text-muted">{{ f.help }}</div>
        </div>
      </div>

      <div>
        <div class="text-header">Serveur</div>
        <div v-for="(f, i) in serverFindings" :key="i" class="mt-1">
          <span :class="levelClass(f.level)" class="font-medium">[{{ levelLabel(f.level) }}] {{ f.title }}</span>
          <div class="text-muted">{{ f.detail }}</div>
          <div v-if="f.fix" class="font-mono text-xs">{{ f.fix }}</div>
          <div v-if="f.ref" class="text-xs text-muted">Réf. : {{ f.ref }}</div>
        </div>
      </div>

      <div v-for="ef in exportFindings" :key="ef.export.path" class="rounded-lg border border-default p-3">
        <div class="text-header font-mono">{{ ef.export.path }}</div>
        <div v-if="!ef.findings.length" class="text-success">Options correctes pour NFSv4.1.</div>
        <div v-for="(f, i) in ef.findings" :key="i" class="mt-1">
          <span :class="levelClass(f.level)">[{{ levelLabel(f.level) }}] {{ f.title }}</span>
          <span class="text-muted"> — {{ f.detail }}</span>
          <span v-if="f.fix" class="font-mono text-xs"> → {{ f.fix }}</span>
        </div>
        <div v-if="ef.suggestedLines.length" class="mt-2">
          <div class="text-label">Exports à ajouter pour les datasets enfants (NFSv3)</div>
          <pre class="font-mono text-xs rounded border border-default p-2 overflow-auto">{{ ef.suggestedLines.join("\n") }}</pre>
        </div>
        <details class="mt-2 text-xs">
          <summary class="cursor-pointer text-muted">Montage côté client</summary>
          <pre class="font-mono">{{ ef.mounts.join("\n") }}</pre>
        </details>
        <div v-for="d in ef.dual" :key="d.share" class="mt-3 border-t border-default pt-2">
          <div class="text-label">
            Cohabitation avec le partage ksmbd [{{ d.share }}]
            ({{ d.relation === "same" ? "même chemin" : d.relation === "nfs-parent" ? "partage dans l'export" : "export dans le partage" }})
          </div>
          <div v-for="f in d.findings" :key="f.id" class="mt-1">
            <span :class="levelClass(f.level)">[{{ levelLabel(f.level) }}] {{ f.title }}</span>
            <div class="text-muted">{{ f.detail }}</div>
            <div v-if="f.fix" class="text-xs">→ {{ f.fix }}</div>
            <div v-if="f.ref" class="text-xs text-muted">Réf. : {{ f.ref }}</div>
          </div>
          <div class="text-xs text-muted mt-1">Les réglages recommandés s'appliquent depuis l'onglet ksmbd (section « Cohabitation NFS »).</div>
        </div>
      </div>
    </div>
  </CardContainer>
</template>
