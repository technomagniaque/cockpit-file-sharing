<script setup lang="ts">
/**
 * Conversion Samba → ksmbd : lit smb.conf + registre, applique les options
 * propres à ksmbd (RDMA, multicanal, interfaces, tailles, sécurité), affiche
 * le rapport et l'aperçu, puis écrit ksmbd.conf (avec sauvegarde).
 */
import { computed, reactive, ref } from "vue";
import { convertSambaToKsmbd, mergeSambaSources, defaultConversionOptions, type ConversionResult, type ReportAction } from "../samba-to-ksmbd";
import type { KsmbdManager, KsmbdProbe } from "../ksmbd-manager";

const props = defineProps<{ manager: KsmbdManager; smbConfPath: string; probe: KsmbdProbe | null }>();
const emit = defineEmits<{ (e: "apply", text: string): void }>();

const opts = reactive(defaultConversionOptions());
const result = ref<ConversionResult | null>(null);
const sources = ref<{ smbConf: string; registry: string } | null>(null);
const loading = ref(false);
const error = ref("");
const actionFilter = ref<ReportAction | "all" | "problems">("problems");
const pasted = ref("");
const usePasted = ref(false);

const rdmaNetdevs = computed(() => (props.probe?.rdmaLinks ?? []).map((l) => l.netdev).filter(Boolean));
const allNetdevs = computed(() => (props.probe?.netdevs ?? []).map((n) => n.name));

function toggle(list: string[], v: string) {
  const i = list.indexOf(v);
  if (i >= 0) list.splice(i, 1); else list.push(v);
}

async function analyse() {
  loading.value = true;
  error.value = "";
  try {
    if (usePasted.value) {
      sources.value = { smbConf: pasted.value, registry: "" };
    } else {
      const s = await props.manager.readSamba(props.smbConfPath);
      sources.value = { smbConf: s.smbConf, registry: s.registry };
    }
    const doc = mergeSambaSources(sources.value.smbConf, sources.value.registry);
    if (!doc.sections.length) throw new Error("Aucune configuration Samba trouvée");
    result.value = convertSambaToKsmbd(doc, opts);
  } catch (e: any) {
    error.value = e?.message ?? String(e);
  } finally {
    loading.value = false;
  }
}

const problems: ReportAction[] = ["dropped", "warning", "converted", "skipped-section", "added"];
const filteredReport = computed(() => {
  const r = result.value?.report ?? [];
  if (actionFilter.value === "all") return r;
  if (actionFilter.value === "problems") return r.filter((l) => problems.includes(l.action));
  return r.filter((l) => l.action === actionFilter.value);
});
const counts = computed(() => {
  const c: Record<string, number> = {};
  for (const l of result.value?.report ?? []) c[l.action] = (c[l.action] ?? 0) + 1;
  return c;
});
const actionLabels: Record<ReportAction, string> = {
  kept: "conservé", renamed: "renommé", converted: "converti", dropped: "abandonné",
  added: "ajouté", warning: "attention", "skipped-section": "section ignorée",
};
const actionClass: Record<ReportAction, string> = {
  kept: "text-muted", renamed: "text-muted", converted: "text-warning", dropped: "text-danger",
  added: "text-success", warning: "text-warning", "skipped-section": "text-danger",
};

function downloadPreview() {
  if (!result.value) return;
  const blob = new Blob([result.value.text], { type: "text/plain" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "ksmbd.conf";
  a.click();
  URL.revokeObjectURL(a.href);
}
</script>

<template>
  <div class="space-y-4 text-sm">
    <div class="flex flex-row flex-wrap gap-4 items-center">
      <label class="flex items-center gap-2"><input type="radio" :value="false" v-model="usePasted" /> Lire <span class="font-mono">{{ smbConfPath }}</span> + registre (net conf list)</label>
      <label class="flex items-center gap-2"><input type="radio" :value="true" v-model="usePasted" /> Coller un smb.conf</label>
    </div>
    <textarea v-if="usePasted" v-model="pasted" rows="8" class="input-textlike w-full font-mono text-xs" placeholder="[global]&#10;  workgroup = …"></textarea>

    <!-- RDMA / multicanal -->
    <div class="rounded-lg border border-default p-3 space-y-2">
      <div class="text-label">RDMA (SMB Direct) et multicanal</div>
      <div v-if="probe" class="text-xs text-muted">
        Noyau {{ probe.kernel }} : CONFIG_SMB_SERVER_SMBDIRECT={{ probe.smbdirectBuilt }} —
        <template v-if="probe.rdmaLinks.length">liens RDMA : {{ probe.rdmaLinks.map((l) => `${l.dev}/${l.port} ${l.state}${l.netdev ? ' (' + l.netdev + ')' : ''}`).join(", ") }}</template>
        <template v-else>aucun lien RDMA détecté (rdma link show)</template>
      </div>
      <div class="flex flex-row flex-wrap gap-4">
        <label class="flex items-center gap-2"><input type="checkbox" v-model="opts.rdma.enable" /> Activer SMB Direct</label>
        <label class="flex items-center gap-2"><input type="checkbox" v-model="opts.multichannel" /> Multicanal</label>
        <label class="flex items-center gap-2">smbd max io size <input v-model="opts.rdma.maxIoSize" class="input-textlike w-24 font-mono" /></label>
      </div>
      <div v-if="opts.rdma.enable">
        <div class="text-xs text-muted">Interfaces RDMA à écouter (partitions NPAR avec personnalité RDMA, passées à la VM) :</div>
        <div class="flex flex-wrap gap-3 mt-1">
          <label v-for="n in (rdmaNetdevs.length ? rdmaNetdevs : allNetdevs)" :key="'r' + n" class="flex items-center gap-1">
            <input type="checkbox" :checked="opts.rdma.interfaces.includes(n)" @change="toggle(opts.rdma.interfaces, n)" />
            <span class="font-mono">{{ n }}</span>
          </label>
        </div>
      </div>
      <div>
        <div class="text-xs text-muted">Interfaces TCP supplémentaires (vide = toutes) :</div>
        <div class="flex flex-wrap gap-3 mt-1">
          <label v-for="n in allNetdevs" :key="'t' + n" class="flex items-center gap-1">
            <input type="checkbox" :checked="opts.extraInterfaces.includes(n)" @change="toggle(opts.extraInterfaces, n)" />
            <span class="font-mono">{{ n }}</span>
          </label>
        </div>
      </div>
    </div>

    <!-- autres options -->
    <div class="rounded-lg border border-default p-3 grid grid-cols-1 md:grid-cols-3 gap-3">
      <label class="flex items-center gap-2"><input type="checkbox" v-model="opts.durableHandles" /> durable handles</label>
      <label class="flex items-center gap-2"><input type="checkbox" v-model="opts.leases" /> smb2 leases</label>
      <label class="flex items-center gap-2"><input type="checkbox" v-model="opts.timeMachine" /> convertir fruit:time machine</label>
      <label class="flex items-center gap-2"><input type="checkbox" v-model="opts.keepWindowsAcls" /> garder les ACL Windows (acl_xattr)</label>
      <label class="flex items-center gap-2" title="Sinon, toute liste d'hôtes contenant une plage est retirée entièrement">
        <input type="checkbox" v-model="opts.hostsExactOnly" /> hosts allow/deny : garder les IP exactes
      </label>
      <span></span>
      <label>Signature
        <select v-model="opts.signing" class="input-textlike w-full">
          <option value="keep">reprendre Samba</option><option value="auto">auto</option><option value="mandatory">mandatory</option><option value="disabled">disabled</option>
        </select>
      </label>
      <label>Chiffrement SMB3
        <select v-model="opts.encryption" class="input-textlike w-full">
          <option value="keep">reprendre Samba</option><option value="auto">auto</option><option value="mandatory">mandatory</option><option value="disabled">disabled</option>
        </select>
      </label>
      <label>Protocole minimal
        <select v-model="opts.minProtocol" class="input-textlike w-full">
          <option value="keep">reprendre Samba</option><option>SMB2_10</option><option>SMB3_00</option><option>SMB3_02</option><option>SMB3_11</option>
        </select>
      </label>
      <label>smb2 max read <input v-model="opts.smb2MaxRead" class="input-textlike w-full font-mono" placeholder="4MB (défaut)" /></label>
      <label>smb2 max write <input v-model="opts.smb2MaxWrite" class="input-textlike w-full font-mono" placeholder="4MB (défaut)" /></label>
      <label>smb2 max trans <input v-model="opts.smb2MaxTrans" class="input-textlike w-full font-mono" placeholder="1MB (défaut)" /></label>
      <label>smb2 max credits <input v-model="opts.smb2MaxCredits" class="input-textlike w-full font-mono" placeholder="8192 (défaut)" /></label>
      <label>max ip connections <input v-model="opts.maxIpConnections" class="input-textlike w-full font-mono" placeholder="32 (défaut)" /></label>
      <label>Partages exclus <input :value="opts.excludeShares.join(' ')" @change="opts.excludeShares = ($event.target as HTMLInputElement).value.split(/[\s,]+/).filter(Boolean)" class="input-textlike w-full" /></label>
    </div>

    <div class="button-group-row">
      <button class="btn btn-primary" :disabled="loading" @click="analyse">{{ loading ? "Analyse…" : "Analyser et convertir" }}</button>
    </div>
    <div v-if="error" class="text-danger">{{ error }}</div>

    <template v-if="result">
      <div class="flex flex-row flex-wrap gap-2 items-center">
        <span class="text-label">Rapport</span>
        <button v-for="f in (['problems', 'all', 'dropped', 'warning', 'converted', 'added', 'skipped-section', 'kept'] as const)" :key="f"
          class="btn text-xs py-0.5 px-2" :class="actionFilter === f ? 'btn-primary' : 'btn-secondary'" @click="actionFilter = f">
          {{ f === 'problems' ? 'à revoir' : f === 'all' ? 'tout' : actionLabels[f] }}
          <template v-if="f !== 'problems' && f !== 'all'"> ({{ counts[f] ?? 0 }})</template>
        </button>
      </div>
      <table class="w-full text-xs">
        <thead><tr class="text-left text-muted"><th>Section</th><th>Samba</th><th>ksmbd</th><th>Action</th><th>Note</th></tr></thead>
        <tbody>
          <tr v-for="(l, i) in filteredReport" :key="i" class="border-t border-default align-top">
            <td class="py-0.5 pr-2 font-mono">[{{ l.section }}]</td>
            <td class="pr-2 font-mono break-all">{{ l.key ? `${l.key}${l.from !== undefined ? ' = ' + l.from : ''}` : '' }}</td>
            <td class="pr-2 font-mono break-all">{{ l.to ?? '' }}</td>
            <td class="pr-2" :class="actionClass[l.action]">{{ actionLabels[l.action] }}</td>
            <td class="text-muted">{{ l.note }}</td>
          </tr>
        </tbody>
      </table>

      <div class="grid grid-cols-1 lg:grid-cols-2 gap-3">
        <div>
          <div class="text-label">ksmbd.conf proposé</div>
          <pre class="rounded-lg border border-default p-2 font-mono text-xs overflow-auto max-h-96">{{ result.text }}</pre>
        </div>
        <div>
          <div class="text-label">Étapes à faire sur le serveur</div>
          <pre class="rounded-lg border border-default p-2 font-mono text-xs overflow-auto max-h-96">{{ result.followUp.join("\n") }}</pre>
        </div>
      </div>
      <div class="button-group-row">
        <button class="btn btn-primary" @click="emit('apply', result.text)">Charger dans l'éditeur ksmbd</button>
        <button class="btn btn-secondary" @click="downloadPreview">Télécharger</button>
      </div>
      <p class="text-xs text-muted">
        « Charger dans l'éditeur » remplace la configuration affichée sans l'écrire ; vérifiez puis utilisez « Enregistrer »
        (une copie <span class="font-mono">ksmbd.conf.bak-…</span> est créée). Samba et ksmbd ne peuvent pas écouter tous deux sur le port 445.
      </p>
    </template>
  </div>
</template>
