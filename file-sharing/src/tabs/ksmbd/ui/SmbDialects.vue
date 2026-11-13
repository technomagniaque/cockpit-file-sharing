<script setup lang="ts">
/**
 * Interrupteurs par dialecte SMB, ramenés à la plage contiguë min–max que
 * ksmbd sait gérer, et groupe « Performances ».
 */
import { computed, ref } from "vue";
import { findSection, getValue, setValue, deleteValue, type IniDocument } from "../ini";
import { findParamExact, defaultFor, type KsmbdParam } from "../ksmbd-params";
import { SMB_DIALECTS, SMB_PERF_KEYS, readRange, enabledDialects, toggleDialect, writeRange, rangeWarnings, type SmbDialect, type ToggleResult } from "../smb-dialects";

const props = defineProps<{ doc: IniDocument }>();
const emit = defineEmits<{ (e: "changed"): void }>();

const range = computed(() => readRange(props.doc));
const enabled = computed(() => enabledDialects(range.value));
const warnings = computed(() => rangeWarnings(props.doc, range.value));
const last = ref<ToggleResult | null>(null);
const pending = ref<{ d: SmbDialect; result: ToggleResult } | null>(null);

function toggle(d: SmbDialect, on: boolean) {
  pending.value = null;
  const r = toggleDialect(range.value, d, on);
  if (!r.ok && !on && r.message.includes("milieu")) {
    // proposer les deux façons de garder une plage contiguë
    pending.value = { d, result: r };
    last.value = r;
    return;
  }
  apply(r);
}
function trim(side: "low" | "high") {
  if (!pending.value) return;
  apply(toggleDialect(range.value, pending.value.d, false, side));
  pending.value = null;
}
function apply(r: ToggleResult) {
  last.value = r;
  if (r.ok) {
    writeRange(props.doc, r.range);
    emit("changed");
  }
}

const g = computed(() => findSection(props.doc, "global"));
const perfParams = computed(() => SMB_PERF_KEYS.map((k) => findParamExact(k)).filter((p): p is KsmbdParam => !!p));
function val(p: KsmbdParam) {
  return getValue(g.value, p.key) ?? "";
}
function set(p: KsmbdParam, v: string) {
  if (!g.value) return;
  if (v === "") deleteValue(g.value, p.key);
  else setValue(g.value, p.key, v);
  emit("changed");
}
</script>

<template>
  <div class="space-y-3 text-sm">
    <div class="rounded-lg border border-default p-3">
      <div class="text-label">
        Dialectes SMB — plage active :
        <template v-if="range.empty"><span class="text-danger">vide (aucun client accepté)</span></template>
        <template v-else>{{ range.min }} → {{ range.max }}</template>
      </div>
      <p class="text-xs text-muted">
        ksmbd n'a que « server min protocol » et « server max protocol » : seule une plage contiguë est possible.
        SMB1 n'existe pas dans ksmbd ; « SMB2_22 » n'est pas un dialecte (joker de négociation). Changement global : redémarrage complet de ksmbd.
      </p>
      <div class="grid grid-cols-1 md:grid-cols-2 gap-2 mt-2">
        <label v-for="d in SMB_DIALECTS" :key="d.id" class="flex items-start gap-2">
          <input type="checkbox" class="mt-1" :checked="enabled.includes(d.id)" @change="toggle(d.id, ($event.target as HTMLInputElement).checked)" />
          <span>
            <span class="font-mono">{{ d.id }}</span> <span class="font-medium">{{ d.label }}</span>
            <span class="block text-xs text-muted">{{ d.brings }}</span>
            <span class="block text-xs text-muted">Clients : {{ d.clients }}</span>
          </span>
        </label>
      </div>
      <div v-if="pending" class="mt-2 rounded border border-default p-2">
        <div class="text-warning">{{ pending.result.message }}</div>
        <div class="button-group-row mt-1">
          <button class="btn btn-secondary text-xs" @click="trim('low')">Couper {{ pending.d }} et tout ce qui est plus ancien</button>
          <button class="btn btn-secondary text-xs" @click="trim('high')">Couper {{ pending.d }} et tout ce qui est plus récent</button>
          <button class="btn btn-secondary text-xs" @click="pending = null">Annuler</button>
        </div>
      </div>
      <div v-else-if="last" class="mt-2" :class="last.ok ? 'text-muted' : 'text-danger'">
        {{ last.message }}
        <ul v-if="last.lostClients.length" class="list-disc pl-5 text-xs text-warning">
          <li v-for="c in last.lostClients" :key="c">Ne pourront plus se connecter — {{ c }}</li>
        </ul>
      </div>
      <ul v-if="range.notes?.length" class="list-disc pl-5 text-xs mt-2" :class="range.empty ? 'text-danger' : 'text-warning'">
        <li v-for="n in range.notes" :key="n">{{ n }}</li>
      </ul>
      <ul v-if="warnings.length" class="list-disc pl-5 text-xs text-warning mt-2">
        <li v-for="w in warnings" :key="w">{{ w }}</li>
      </ul>
    </div>

    <div class="rounded-lg border border-default p-3">
      <div class="text-label">Performances</div>
      <p class="text-xs text-muted">
        Couper des dialectes réduit la surface d'attaque et la négociation, mais le débit dépend surtout de ces réglages :
        multicanal et SMB Direct (RDMA), tailles d'E/S, signature et chiffrement (coût CPU, AES-GCM en SMB3_11 bien plus rapide qu'AES-CCM).
      </p>
      <div class="grid grid-cols-1 lg:grid-cols-2 gap-3 mt-2">
        <div v-for="p in perfParams" :key="p.key">
          <label class="block font-mono">{{ p.key }}</label>
          <select v-if="p.type === 'bool' || p.type === 'opt' || p.type === 'enum'" class="input-textlike w-full" :value="val(p)" @change="set(p, ($event.target as HTMLSelectElement).value)">
            <option value="">défaut ({{ defaultFor(p, "global") }})</option>
            <option v-for="o in (p.type === 'bool' ? ['yes', 'no'] : p.values ?? [])" :key="o" :value="o">{{ o }}</option>
          </select>
          <input v-else class="input-textlike w-full font-mono" :value="val(p)" :placeholder="`défaut : ${defaultFor(p, 'global')}`" @change="set(p, ($event.target as HTMLInputElement).value.trim())" />
          <div class="text-xs text-muted">{{ p.description }}</div>
        </div>
      </div>
    </div>
  </div>
</template>
