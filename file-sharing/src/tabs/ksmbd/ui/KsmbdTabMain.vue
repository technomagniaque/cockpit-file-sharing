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

const userSettings = useUserSettings();
const manager = new KsmbdManager();

const doc = ref<IniDocument>({ sections: [{ name: "global", entries: [] }] });
const savedText = ref("");
const rawText = ref("");
const rawMode = ref(false);
const probe = ref<KsmbdProbe | null>(null);
const db = ref<UserDb>({ ksmbdUsers: [], unixUsers: {}, groups: {} });
const selectedShare = ref("");
const newShareName = ref("");
const busy = ref(false);
const view = ref<"config" | "simulator" | "convert">("config");

const header = ["ksmbd.conf géré par cockpit-file-sharing — voir ksmbd.conf(5)"];
const currentText = computed(() => serializeIni(doc.value, header));
const modified = computed(() => (rawMode.value ? rawText.value : currentText.value) !== savedText.value);
const global = computed(() => findSection(doc.value, "global")!);
const shares = computed(() => doc.value.sections.filter((s) => s.name.toLowerCase() !== "global"));
const share = computed(() => (selectedShare.value ? findSection(doc.value, selectedShare.value) : undefined));
const netdevs = computed(() => (probe.value?.netdevs ?? []).map((n) => n.name));

function loadText(text: string, markSaved = false) {
  // ksmbd-tools retient la première occurrence d'une clé
  const parsed = parseIni(text, "first");
  if (!findSection(parsed, "global")) parsed.sections.unshift({ name: "global", entries: [] });
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
  } catch (e: any) {
    pushNotification(new Notification("Lecture impossible", e?.message ?? String(e), "error"));
  } finally {
    busy.value = false;
  }
}
onMounted(reload);

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
    pushNotification(new Notification("ksmbd.conf enregistré",
      `Copie : ${r.backup}\n${r.reload.out || r.reload.err}`.trim(), r.reload.code === 0 ? "success" : "warning", 8000));
  } catch (e: any) {
    pushNotification(new Notification("Écriture impossible", e?.message ?? String(e), "error"));
  } finally {
    busy.value = false;
  }
}

function addShare() {
  const name = newShareName.value.trim();
  if (!name || findSection(doc.value, name)) return;
  doc.value.sections.push({ name, entries: [{ key: "path", value: "" }, { key: "read only", value: "no" }] });
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
        </template>
        <div v-else class="text-muted text-sm">Aucun partage.</div>
      </CardContainer>
    </template>

    <CardContainer v-else-if="view === 'simulator'">
      <template #header>Empilement des permissions (configuration affichée, enregistrée ou non)</template>
      <KsmbdPermissionSimulator :doc="doc" :db="db" :manager="manager" />
    </CardContainer>

    <CardContainer v-else>
      <template #header>Conversion Samba → ksmbd</template>
      <SambaConversion :manager="manager" :smbConfPath="userSettings.samba.confPath" :probe="probe" @apply="fromConversion" />
    </CardContainer>

    <SystemdServiceCard name="Service ksmbd" serviceName="ksmbd.service" warnIfStopped />
  </CenteredCardColumn>
</template>
