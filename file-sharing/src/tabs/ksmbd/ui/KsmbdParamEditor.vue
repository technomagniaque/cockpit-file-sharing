<script setup lang="ts">
/**
 * Édite les paramètres ksmbd d'une section (global ou partage), regroupés par
 * catégorie. Une valeur vide retire la clé (valeur par défaut de ksmbd-tools).
 */
import { computed, ref } from "vue";
import { categoryLabels, paramsFor, findParam, ksmbdBool, ksmbdOpt, type KsmbdParam, type KsmbdCategory } from "../ksmbd-params";
import { getValue, setValue, deleteValue, type IniSection } from "../ini";

const props = defineProps<{
  section: IniSection;
  scope: "global" | "share";
  /** valeurs héritées de [global] (pour les partages) */
  inherited?: IniSection;
  netdevs?: string[];
}>();
const emit = defineEmits<{ (e: "changed"): void }>();

const filter = ref("");
const showUndocumented = ref(true);

const groups = computed(() => {
  const params = paramsFor(props.scope).filter(
    (p) =>
      (showUndocumented.value || p.documented !== false) &&
      (!filter.value || (p.key + p.description).toLowerCase().includes(filter.value.toLowerCase()))
  );
  const out: { cat: KsmbdCategory; label: string; params: KsmbdParam[] }[] = [];
  for (const p of params) {
    let g = out.find((x) => x.cat === p.category);
    if (!g) out.push((g = { cat: p.category, label: categoryLabels[p.category], params: [] }));
    g.params.push(p);
  }
  return out;
});

const unknownKeys = computed(() => props.section.entries.filter((e) => !findParam(e.key)));

function val(p: KsmbdParam): string {
  return getValue(props.section, p.key) ?? "";
}
function inheritedVal(p: KsmbdParam): string | undefined {
  if (props.scope !== "share" || p.scope !== "share") return undefined;
  return getValue(props.inherited, p.key);
}
function set(p: KsmbdParam, v: string) {
  if (v === "" || v === undefined) deleteValue(props.section, p.key);
  else setValue(props.section, p.key, v);
  emit("changed");
}
function placeholder(p: KsmbdParam) {
  const inh = inheritedVal(p);
  return inh !== undefined ? `${inh} (hérité de [global])` : p.default ? `${p.default} (défaut)` : "(non défini)";
}
/** Avertit quand ksmbd-tools lirait la valeur autrement que prévu. */
function valueWarning(p: KsmbdParam): string | undefined {
  const v = val(p).trim();
  if (!v) return undefined;
  if (p.type === "bool" && !/^(yes|no|true|false|1|0|enable|disable)$/i.test(v))
    return `ksmbd lira « ${v} » comme ${ksmbdBool(v) ? "vrai" : "faux"}`;
  if (p.type === "opt" && ksmbdOpt(v) !== v.toLowerCase()) return `ksmbd lira « ${v} » comme ${ksmbdOpt(v)}`;
  if (p.type === "octal" && !/^0?[0-7]{3,4}$/.test(v)) return "mode octal attendu (ex. 0775)";
  if (p.type === "size" && !/^\d+\s*[kmgtpe]?b?$/i.test(v)) return "taille attendue (ex. 8MB)";
  if (p.key === "hosts allow" || p.key === "hosts deny") {
    const bad = v.split(/[\s,]+/).filter((h) => h && !/^\d{1,3}(\.\d{1,3}){3}$/.test(h) && !h.includes(":"));
    if (bad.length) return `comparaison exacte d'IP seulement : ${bad.join(", ")} ne correspondra jamais`;
  }
  return undefined;
}
function toggleListValue(p: KsmbdParam, item: string) {
  const items = val(p).split(/[\s,]+/).filter(Boolean);
  const i = items.indexOf(item);
  if (i >= 0) items.splice(i, 1); else items.push(item);
  set(p, items.join(" "));
}
</script>

<template>
  <div class="space-y-3">
    <div class="flex flex-row flex-wrap gap-3 items-center">
      <input v-model="filter" class="input-textlike w-64" placeholder="Filtrer les paramètres…" />
      <label class="text-sm text-muted flex items-center gap-1">
        <input type="checkbox" v-model="showUndocumented" />
        afficher les clés non documentées (admin users, hosts allow/deny)
      </label>
    </div>

    <details v-for="g in groups" :key="g.cat" class="rounded-lg border border-default px-3 py-2" :open="g.cat === 'access' || g.cat === 'rdma'">
      <summary class="cursor-pointer text-label">{{ g.label }}</summary>
      <div class="mt-2 grid grid-cols-1 lg:grid-cols-2 gap-x-6 gap-y-3">
        <div v-for="p in g.params" :key="p.key">
          <label class="block text-sm">
            <span class="font-mono">{{ p.key }}</span>
            <span v-if="p.documented === false" class="ml-1 text-xs text-warning">non documenté</span>
          </label>
          <select v-if="p.type === 'bool'" class="input-textlike w-full" :value="val(p)" @change="set(p, ($event.target as HTMLSelectElement).value)">
            <option value="">{{ placeholder(p) }}</option>
            <option value="yes">yes</option>
            <option value="no">no</option>
          </select>
          <select v-else-if="p.type === 'enum' || p.type === 'opt'" class="input-textlike w-full" :value="val(p)" @change="set(p, ($event.target as HTMLSelectElement).value)">
            <option value="">{{ placeholder(p) }}</option>
            <option v-for="o in p.values" :key="o" :value="o">{{ o }}</option>
          </select>
          <div v-else-if="p.key === 'vfs objects'" class="flex gap-3 text-sm">
            <label v-for="o in p.values" :key="o" class="flex items-center gap-1">
              <input type="checkbox" :checked="val(p).split(/[\s,]+/).includes(o)" @change="toggleListValue(p, o)" />
              <span class="font-mono">{{ o }}</span>
            </label>
          </div>
          <div v-else-if="p.key === 'interfaces' && netdevs?.length" class="flex flex-wrap gap-2 text-sm">
            <label v-for="n in netdevs" :key="n" class="flex items-center gap-1">
              <input type="checkbox" :checked="val(p).split(/[\s,]+/).includes(n)" @change="toggleListValue(p, n)" />
              <span class="font-mono">{{ n }}</span>
            </label>
          </div>
          <input v-else class="input-textlike w-full" :class="{ 'font-mono': ['octal', 'size', 'list', 'int'].includes(p.type) }"
            :value="val(p)" :placeholder="placeholder(p)" @change="set(p, ($event.target as HTMLInputElement).value.trim())" />
          <div class="text-xs text-muted mt-0.5">{{ p.description }}</div>
          <div v-if="p.warning" class="text-xs text-muted">{{ p.warning }}</div>
          <div v-if="valueWarning(p)" class="text-xs text-danger">{{ valueWarning(p) }}</div>
        </div>
      </div>
    </details>

    <div v-if="unknownKeys.length" class="rounded-lg border border-default px-3 py-2 text-sm">
      <div class="text-label">Clés inconnues de ksmbd-tools (ignorées par ksmbd)</div>
      <div v-for="e in unknownKeys" :key="e.key" class="flex justify-between font-mono">
        <span>{{ e.key }} = {{ e.value }}</span>
        <button class="text-danger text-xs" @click="deleteValue(section, e.key); emit('changed')">retirer</button>
      </div>
    </div>
  </div>
</template>
