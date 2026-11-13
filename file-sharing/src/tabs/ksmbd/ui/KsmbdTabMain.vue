<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { CenteredCardColumn, CardContainer, pushNotification, Notification } from "@45drives/houston-common-ui";
import SystemdServiceCard from "@/common/ui/SystemdServiceCard.vue";
import { useUserSettings } from "@/common/user-settings";
import KsmbdParamEditor from "./KsmbdParamEditor.vue";
import KsmbdPermissionSimulator from "./KsmbdPermissionSimulator.vue";
import SambaConversion from "./SambaConversion.vue";
import { KsmbdManager, type KsmbdProbe } from "../ksmbd-manager";
import { parseIni, serializeIni, findSection, type IniDocument } from "../ini";
import type { UserDb } from "../permission-stack";
import { NFSv4Manager } from "@/tabs/nfs/nfsv4-manager";
import type { NFSExport } from "@/tabs/nfs/data-types";
import { analyzeDualProtocol, applyDualProtocolRecommendations, overlappingExports } from "@/common/dual-protocol";
import { getValue } from "../ini";

const userSettings = useUserSettings();
const manager = new KsmbdManager();
const nfsManager = new NFSv4Manager();
const nfsExports = ref<NFSExport[]>([]);
const nfsExportErrors = ref<string[]>([]);
const rootDefaultAcl = ref<Record<string, boolean>>({});

const doc = ref<IniDocument>({ flavor: "ksmbd", sections: [{ name: "global", entries: [], flavor: "ksmbd" }] });
const savedText = ref("");
const rawText = ref("");
const rawMode = ref(false);
const probe = ref<KsmbdProbe | null>(null);
const db = ref<UserDb>({ ksmbdUsers: [], unixUsers: {}, groups: {} });
const selectedShare = ref("");
const newShareName = ref("");
const busy = ref(false);
const view = ref<"config" | "simulator" | "convert">("config");
const needsRestart = ref(false);
const parseIssues = ref<{ errors: NonNullable<IniDocument["errors"]>; truncated: NonNullable<IniDocument["truncated"]> }>({ errors: [], truncated: [] });

const header = ["ksmbd.conf géré par cockpit-file-sharing — voir ksmbd.conf(5)"];
const currentText = computed(() => serializeIni(doc.value, header));
const modified = computed(() => (rawMode.value ? rawText.value : currentText.value) !== savedText.value);
const global = computed(() => findSection(doc.value, "global")!);
const shares = computed(() => doc.value.sections.filter((s) => s.name.toLowerCase() !== "global"));
const share = computed(() => (selectedShare.value ? findSection(doc.value, selectedShare.value) : undefined));
const netdevs = computed(() => (probe.value?.netdevs ?? []).map((n) => n.name));

function loadText(text: string, markSaved = false) {
  // lecture façon ksmbd-tools : première occurrence, troncature au « ; » / « # », pas de continuation
  const parsed = parseIni(text, "ksmbd");
  parseIssues.value = { errors: parsed.errors ?? [], truncated: parsed.truncated ?? [] };
  if (!findSection(parsed, "global")) parsed.sections.unshift({ name: "global", entries: [], flavor: "ksmbd" });
  doc.value = parsed;
  rawText.value = serializeIni(parsed, header);
  if (markSaved) savedText.value = rawText.value;
  if (!share.value) selectedShare.value = shares.value[0]?.name ?? "";
}

async function reload() {
  busy.value = true;
  try {
    const [text, p, users] = await Promise.all([manager.readConf(), manager.probe(), manager.userDb()]);
    probe.value = p;
    db.value = users;
    loadText(text, true);
    loadNfs();
  } catch (e: any) {
    pushNotification(new Notification("Lecture impossible", e?.message ?? String(e), "error"));
  } finally {
    busy.value = false;
  }
}
onMounted(reload);

async function loadNfs() {
  try {
    const r = await nfsManager.allExports(userSettings.value.nfs.confPath);
    nfsExports.value = r.exports;
    nfsExportErrors.value = r.errors;
    for (const sh of shares.value) {
      const path = getValue(sh, "path");
      if (path && overlappingExports(path, r.exports).length) {
        const pp = await manager.probePath(path);
        rootDefaultAcl.value = { ...rootDefaultAcl.value, [sh.name]: pp.hasDefaultAcl };
      }
    }
  } catch {
    nfsExports.value = [];
  }
}

const umaskStr = computed(() => (probe.value?.workerUmask != null ? probe.value.workerUmask.toString(8).padStart(4, "0") : undefined));
const dualForShare = computed(() => {
  if (!share.value) return [];
  const path = getValue(share.value, "path") ?? "";
  return overlappingExports(path, nfsExports.value).map((o) => ({
    export: o.export,
    relation: o.relation,
    findings: analyzeDualProtocol({ doc: doc.value, share: share.value!.name, nfsExport: o.export, db: db.value, rootHasDefaultAcl: rootDefaultAcl.value[share.value!.name], workerUmask: umaskStr.value }),
  }));
});
function applyDual() {
  if (!share.value) return;
  const changes = applyDualProtocolRecommendations(doc.value, share.value.name);
  doc.value = { ...doc.value };
  pushNotification(new Notification("Réglages double protocole", changes.length ? changes.join("\n") + "\nNon enregistré : vérifiez puis enregistrez." : "Déjà appliqués.", "info", 8000));
}
const levelClass = (l: string) => ({ danger: "text-danger", warning: "text-warning", info: "text-muted" })[l] ?? "";

function toggleRaw() {
  if (rawMode.value) loadText(rawText.value);
  else rawText.value = currentText.value;
  rawMode.value = !rawMode.value;
}

async function save() {
  const text = rawMode.value ? rawText.value : currentText.value;
  busy.value = true;
  try {
    const r = await manager.writeConf(text);
    savedText.value = text;
    loadText(text, true);
    if (r.needsRestart) needsRestart.value = true;
    pushNotification(new Notification("ksmbd.conf enregistré",
      `Copie : ${r.backup}\n` + (r.needsRestart
        ? "[global] a changé : ksmbd.control --reload ne relit que les partages. Redémarrage complet nécessaire (systemctl restart ksmbd)."
        : (r.reload.out || r.reload.err)).trim(),
      r.needsRestart || r.reload.code !== 0 ? "warning" : "success", 10000));
  } catch (e: any) {
    pushNotification(new Notification("Écriture impossible", e?.message ?? String(e), "error"));
  } finally {
    busy.value = false;
  }
}

async function restartKsmbd() {
  busy.value = true;
  try {
    const r = await manager.restart();
    if (r.code === 0) {
      needsRestart.value = false;
      pushNotification(new Notification("ksmbd redémarré", "Les paramètres [global] sont appliqués.", "success", 6000));
    } else {
      pushNotification(new Notification("Redémarrage impossible", r.err || r.out, "error"));
    }
  } finally {
    busy.value = false;
  }
}

function addShare() {
  const name = newShareName.value.trim();
  if (!name || findSection(doc.value, name)) return;
  doc.value.sections.push({ name, flavor: "ksmbd", entries: [{ key: "path", value: "" }, { key: "read only", value: "no" }] });
  selectedShare.value = name;
  newShareName.value = "";
}
function removeShare(name: string) {
  doc.value.sections = doc.value.sections.filter((s) => s.name !== name);
  selectedShare.value = shares.value[0]?.name ?? "";
}
function fromConversion(text: string) {
  rawMode.value = false;
  loadText(text);
  view.value = "config";
  pushNotification(new Notification("Configuration convertie chargée", "Vérifiez puis enregistrez.", "info", 6000));
}

const envIssues = computed(() => {
  const p = probe.value;
  if (!p) return [];
  const out: string[] = [];
  if (p.smbServerBuilt === "n") out.push(`Le noyau ${p.kernel} n'a pas CONFIG_SMB_SERVER : ksmbd indisponible.`);
  if (!p.moduleAvailable && p.smbServerBuilt !== "y") out.push("Module ksmbd introuvable (modinfo ksmbd). Sur Oracle Linux, il peut être dans kernel-uek-modules-extra.");
  if (!p.toolsInstalled) out.push("ksmbd-tools absent (ksmbd.mountd introuvable).");
  if (p.sambaRunning) out.push("Samba est actif : arrêtez smb/smbd avant de démarrer ksmbd (port 445).");
  if (p.smbdirectBuilt === "n") out.push("CONFIG_SMB_SERVER_SMBDIRECT absent : pas de RDMA possible avec ce noyau.");
  if (!p.timeMachineCapable) out.push(`Time Machine via ksmbd exige Linux 7.3 ou plus (actuel : ${p.kernel}).`);
  return out;
});
</script>

<template>
  <CenteredCardColumn>
    <CardContainer>
      <template #header>ksmbd — serveur SMB3 du noyau</template>
      <div v-if="probe" class="grid grid-cols-2 md:grid-cols-4 gap-2 text-sm">
        <div><span class="text-muted">Noyau</span> <span class="font-mono">{{ probe.kernel }}</span></div>
        <div><span class="text-muted">Module</span> {{ probe.moduleLoaded ? "chargé" : probe.moduleAvailable ? "disponible" : "absent" }}</div>
        <div><span class="text-muted">SMB Direct</span> CONFIG={{ probe.smbdirectBuilt }}, {{ probe.rdmaLinks.length }} lien(s) RDMA</div>
        <div><span class="text-muted">ksmbd-tools</span> {{ probe.toolsInstalled ? probe.toolsVersion || "installé" : "absent" }}</div>
        <div class="col-span-2"><span class="text-muted">OpenZFS</span> <span class="font-mono">{{ probe.zfsVersion || "—" }}</span></div>
        <div><span class="text-muted">ksmbd.mountd</span> {{ probe.mountdRunning ? "actif" : "arrêté" }}</div>
        <div><span class="text-muted">Samba</span> {{ probe.sambaRunning ? "actif" : "arrêté" }}</div>
        <div><span class="text-muted">umask des workers</span> <span class="font-mono">{{ probe.workerUmask != null ? probe.workerUmask.toString(8).padStart(4, "0") : "?" }}</span></div>
      </div>
      <ul v-if="envIssues.length" class="mt-2 list-disc pl-5 text-sm text-warning">
        <li v-for="i in envIssues" :key="i">{{ i }}</li>
      </ul>
      <div class="button-group-row mt-3">
        <button v-for="v in ([['config', 'Configuration'], ['simulator', 'Empilement des permissions'], ['convert', 'Conversion Samba → ksmbd']] as const)" :key="v[0]"
          class="btn" :class="view === v[0] ? 'btn-primary' : 'btn-secondary'" @click="view = v[0]">{{ v[1] }}</button>
        <button class="btn btn-secondary" :disabled="busy" @click="reload">Relire</button>
      </div>
    </CardContainer>

    <template v-if="view === 'config'">
      <CardContainer>
        <template #header>
          Configuration {{ manager.confPath }}<span v-if="modified"> *</span>
        </template>
        <div v-if="needsRestart" class="mb-3 rounded-lg border border-default p-3 text-sm text-warning">
          [global] a été modifié : ksmbd ne l'applique qu'au démarrage (ksmbd.control --reload ne relit que les partages).
          Le redémarrage coupe les connexions SMB en cours (ksmbd.control --shutdown puis ksmbd.mountd).
          <button class="btn btn-secondary ml-2" :disabled="busy" @click="restartKsmbd">systemctl restart ksmbd</button>
        </div>
        <div v-if="parseIssues.errors.length || parseIssues.truncated.length" class="mb-3 rounded-lg border border-default p-3 text-sm">
          <div v-for="e in parseIssues.errors" :key="'e' + e.line" class="text-danger">
            Ligne {{ e.line }} : <span class="font-mono">{{ e.text }}</span> — {{ e.reason }}
          </div>
          <div v-for="t in parseIssues.truncated" :key="t.section + t.key" class="text-warning">
            [{{ t.section }}] <span class="font-mono">{{ t.key }} = {{ t.raw }}</span> est lu « {{ t.value }} » par ksmbd-tools (coupé au « ; » ou « # »)
          </div>
        </div>
        <div class="button-group-row mb-3">
          <button class="btn btn-primary" :disabled="busy || !modified" @click="save">Enregistrer et recharger</button>
          <button class="btn btn-secondary" :disabled="busy || !modified" @click="loadText(savedText, true)">Annuler</button>
          <button class="btn btn-secondary" @click="toggleRaw">{{ rawMode ? "Éditeur par paramètres" : "Texte brut" }}</button>
        </div>
        <textarea v-if="rawMode" v-model="rawText" rows="28" class="input-textlike w-full font-mono text-xs"></textarea>
        <template v-else>
          <div class="text-header mb-2">[global]</div>
          <KsmbdParamEditor :section="global" scope="global" :netdevs="netdevs" />
          <div class="text-xs text-muted mt-2">
            Les paramètres de partage placés dans [global] (create mask, vfs objects…) servent de défaut à tous les partages :
            éditez-les en texte brut.
          </div>
        </template>
      </CardContainer>

      <CardContainer v-if="!rawMode">
        <template #header>Partages</template>
        <div class="flex flex-row flex-wrap gap-2 items-center mb-3">
          <button v-for="s in shares" :key="s.name" class="btn text-sm" :class="selectedShare === s.name ? 'btn-primary' : 'btn-secondary'" @click="selectedShare = s.name">
            {{ s.name }}
          </button>
          <input v-model="newShareName" class="input-textlike w-40" placeholder="nouveau partage" @keyup.enter="addShare" />
          <button class="btn btn-secondary" @click="addShare">Ajouter</button>
        </div>
        <template v-if="share">
          <div class="flex justify-between items-center mb-2">
            <div class="text-header">[{{ share.name }}]</div>
            <button class="btn btn-danger text-xs" @click="removeShare(share.name)">Supprimer ce partage</button>
          </div>
          <KsmbdParamEditor :key="share.name" :section="share" scope="share" :inherited="global" />
          <div v-if="dualForShare.length" class="mt-4 rounded-lg border border-default p-3 text-sm">
            <div class="flex justify-between items-center">
              <div class="text-header">Cohabitation NFS</div>
              <button class="btn btn-secondary text-xs" @click="applyDual">Appliquer les réglages double protocole recommandés</button>
            </div>
            <div v-for="d in dualForShare" :key="d.export.path" class="mt-2">
              <div class="text-label">
                Export NFS <span class="font-mono">{{ d.export.path }}</span>
                ({{ d.relation === "same" ? "même chemin" : d.relation === "nfs-parent" ? "l'export contient ce partage" : "ce partage contient l'export" }})
              </div>
              <div v-for="f in d.findings" :key="f.id" class="mt-1">
                <span :class="levelClass(f.level)" class="font-medium">{{ f.title }}</span>
                <div class="text-muted">{{ f.detail }}</div>
                <div v-if="f.fix" class="text-xs">→ {{ f.fix }}</div>
                <div v-if="f.ref" class="text-xs text-muted">Réf. : {{ f.ref }}</div>
              </div>
            </div>
          </div>
          <div v-if="nfsExportErrors.length" class="mt-2 text-xs text-warning">
            Exports NFS illisibles ignorés : {{ nfsExportErrors.join(" ; ") }}
          </div>
        </template>
        <div v-else class="text-muted text-sm">Aucun partage.</div>
      </CardContainer>
    </template>

    <CardContainer v-else-if="view === 'simulator'">
      <template #header>Empilement des permissions (configuration affichée, enregistrée ou non)</template>
      <KsmbdPermissionSimulator :doc="doc" :db="db" :manager="manager" :workerUmask="probe?.workerUmask" />
    </CardContainer>

    <CardContainer v-else>
      <template #header>Conversion Samba → ksmbd</template>
      <SambaConversion :manager="manager" :smbConfPath="userSettings.samba.confPath" :probe="probe" :nfsExports="nfsExports" @apply="fromConversion" />
    </CardContainer>

    <SystemdServiceCard name="Service ksmbd" serviceName="ksmbd.service" warnIfStopped />
  </CenteredCardColumn>
</template>
