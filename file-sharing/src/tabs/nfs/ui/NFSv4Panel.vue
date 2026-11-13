<script setup lang="ts">
/**
 * Volet NFSv4.1 : versions servies, nfs.conf, idmapping, contrôle des
 * exports pour NFSv4.1 et cohabitation avec les partages ksmbd.
 */
import { computed, onMounted, ref, watch } from "vue";
import { CardContainer, pushNotification, Notification } from "@45drives/houston-common-ui";
import type { NFSExport } from "@/tabs/nfs/data-types";
import {
  NFS_CONF_FIELDS, getNfsConf, setNfsConf, applyV41OnlyPreset, configuredVersions, parseProcVersions,
  analyzeServer, analyzeExportV41, type Finding, type NfsConfField,
} from "@/tabs/nfs/nfsv4";
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

async function load() {
  busy.value = true;
  try {
    snap.value = await manager.snapshot(props.nfsExports.map((e) => e.path));
    confText.value = snap.value.nfsConf;
    savedConf.value = snap.value.nfsConf;
    try {
      const text = await ksmbd.readConf();
      ksmbdDoc.value = text.trim() ? parseIni(text, "ksmbd") : null;
      if (ksmbdDoc.value) {
        const p = await ksmbd.probe();
        workerUmask.value = p.workerUmask !== null ? p.workerUmask.toString(8).padStart(4, "0") : undefined;
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
onMounted(load);
watch(() => props.nfsExports.map((e) => e.path).join("\n"), load);

const modified = computed(() => confText.value !== savedConf.value);
const conf = computed(() => configuredVersions(confText.value));
const live = computed(() => (snap.value?.procVersions ? parseProcVersions(snap.value.procVersions) : null));

function fieldValue(f: NfsConfField) {
  return getNfsConf(confText.value, f.section, f.key) ?? "";
}
function setField(f: NfsConfField, v: string) {
  confText.value = setNfsConf(confText.value, f.section, f.key, v === "" ? undefined : v);
}
function preset() {
  confText.value = applyV41OnlyPreset(confText.value, keepV42.value);
}
async function save() {
  busy.value = true;
  try {
    const backup = await manager.writeNfsConf(confText.value);
    savedConf.value = confText.value;
    pushNotification(new Notification("nfs.conf enregistré", `Copie : ${backup}\nRedémarrage requis : systemctl restart nfs-server`, "success", 10000));
    await load();
  } catch (e: any) {
    pushNotification(new Notification("Écriture impossible", e?.message ?? String(e), "error"));
  } finally {
    busy.value = false;
  }
}

const serverFindings = computed<Finding[]>(() =>
  snap.value ? analyzeServer({ ...snap.value, nfsConf: confText.value }, props.nfsExports) : []
);
const exportFindings = computed(() =>
  props.nfsExports.map((e) => ({
    export: e,
    findings: analyzeExportV41(e, (snap.value?.fstypes[e.path] ?? "zfs") === "zfs"),
    dual: dualFor(e),
  }))
);

function dualFor(e: NFSExport): { share: string; relation: string; findings: DualFinding[] }[] {
  const doc = ksmbdDoc.value;
  if (!doc) return [];
  const out: { share: string; relation: string; findings: DualFinding[] }[] = [];
  for (const s of doc.sections) {
    if (s.name.toLowerCase() === "global" || s.name.toLowerCase() === "ipc$") continue;
    const path = getValue(findSection(doc, s.name), "path") ?? "";
    for (const o of overlappingExports(path, [e])) {
      out.push({ share: s.name, relation: o.relation, findings: analyzeDualProtocol({ doc, share: s.name, nfsExport: e, workerUmask: workerUmask.value }) });
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
    <template #header>NFSv4.1 — serveur, idmapping et cohabitation SMB</template>
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

      <div class="button-group-row flex-wrap items-center">
        <button class="btn btn-secondary" @click="preset">Préréglage « NFSv4.1 seulement »</button>
        <label class="flex items-center gap-1"><input type="checkbox" v-model="keepV42" /> garder NFSv4.2</label>
        <button class="btn btn-secondary" @click="raw = !raw">{{ raw ? "Champs" : "Texte brut" }}</button>
        <button class="btn btn-primary" :disabled="busy || !modified" @click="save">Enregistrer nfs.conf</button>
        <button class="btn btn-secondary" :disabled="busy || !modified" @click="confText = savedConf">Annuler</button>
        <button class="btn btn-secondary" :disabled="busy" @click="load">Relire</button>
      </div>
      <p v-if="modified" class="text-xs text-warning">Modifié, non enregistré. Après enregistrement : systemctl restart nfs-server (les versions ne changent qu'au démarrage de nfsd).</p>

      <textarea v-if="raw" v-model="confText" rows="20" class="input-textlike w-full font-mono text-xs"></textarea>
      <div v-else class="grid grid-cols-1 lg:grid-cols-2 gap-3">
        <div v-for="f in NFS_CONF_FIELDS" :key="f.section + f.key">
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
