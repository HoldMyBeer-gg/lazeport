<script setup>
import { computed } from 'vue'

const props = defineProps({
  /** Row labels (clients) */
  rows: { type: Array, default: () => [] },
  /** Optional formatter for row label display (e.g. i18n for __unassigned__) */
  rowLabelFormatter: { type: Function, default: null },
  /** Column labels (severities) */
  columns: { type: Array, default: () => [] },
  /** 2D data: rows × columns; each cell = { value, color? } or just a number */
  data: { type: Array, default: () => [] },
  /** Column header colors (optional) */
  columnColors: { type: Array, default: () => [] },
  /** When true, cells with value 0 are dimmed (filtered view) */
  filterActive: { type: Boolean, default: false },
})

const emit = defineEmits(['cell-click'])

function displayRowLabel(row) {
  return props.rowLabelFormatter ? props.rowLabelFormatter(row) : row
}

/** Severity weight for heat: Critical hottest, then High, Med, Low. */
function severityWeight(colLabel) {
  if (!colLabel) return 1
  const s = String(colLabel).toLowerCase()
  if (s === 'critical') return 4
  if (s === 'high') return 3
  if (s === 'med' || s === 'medium') return 2
  if (s === 'low') return 1
  return 1
}

const cells = computed(() => {
  const rows = props.data || []
  const cols = props.columns || []
  // Compute weighted value per cell and find max for normalization
  let maxWeighted = 0
  const weighted = rows.map((row, ri) =>
    row.map((cell, ci) => {
      const val = typeof cell === 'object' ? cell.value : cell
      const count = Number(val) || 0
      const weight = severityWeight(cols[ci])
      const w = count * weight
      if (w > maxWeighted) maxWeighted = w
      return { value: val, weighted: w }
    })
  )
  const maxVal = maxWeighted > 0 ? maxWeighted : 1
  return weighted.map((row) =>
    row.map(({ value, weighted: w }) => ({
      value,
      bg: cellBgFromWeighted(w, maxVal),
    }))
  )
})

/** Fire gradient: blue → cyan → green → yellow → orange → red. No grey (avoids RGB lerp through desaturated middle). */
const FIRE_STOPS = [
  { t: 0, r: 30, g: 100, b: 220 },
  { t: 0.2, r: 30, g: 200, b: 220 },
  { t: 0.4, r: 80, g: 220, b: 80 },
  { t: 0.6, r: 255, g: 220, b: 50 },
  { t: 0.8, r: 255, g: 120, b: 40 },
  { t: 1, r: 220, g: 40, b: 40 },
]

function fireColor(t) {
  t = Math.max(0, Math.min(1, t))
  if (t <= 0) return `rgb(${FIRE_STOPS[0].r},${FIRE_STOPS[0].g},${FIRE_STOPS[0].b})`
  if (t >= 1) return `rgb(${FIRE_STOPS[5].r},${FIRE_STOPS[5].g},${FIRE_STOPS[5].b})`
  const lerp = (a, b, s) => Math.round(a + (b - a) * s)
  for (let i = 0; i < FIRE_STOPS.length - 1; i++) {
    const a = FIRE_STOPS[i]
    const b = FIRE_STOPS[i + 1]
    if (t >= a.t && t <= b.t) {
      const s = (t - a.t) / (b.t - a.t)
      return `rgb(${lerp(a.r, b.r, s)},${lerp(a.g, b.g, s)},${lerp(a.b, b.b, s)})`
    }
  }
  return `rgb(${FIRE_STOPS[5].r},${FIRE_STOPS[5].g},${FIRE_STOPS[5].b})`
}

function cellBgFromWeighted(weightedValue, maxVal) {
  if (weightedValue === 0 || weightedValue == null) return 'transparent'
  const t = Math.min(1, Math.max(0, Number(weightedValue) / maxVal))
  return fireColor(t)
}
</script>

<template>
  <div class="heatmap-wrapper">
    <div
      class="heatmap-grid"
      :style="{
        gridTemplateColumns: `100px repeat(${columns.length}, 1fr)`,
        gridTemplateRows: `auto repeat(${rows.length}, 1fr)`,
      }"
    >
      <!-- Header: empty corner + column labels -->
      <div class="hm-corner"></div>
      <div
        v-for="(col, ci) in columns"
        :key="'ch-' + ci"
        class="hm-col-header"
        :style="{ color: columnColors[ci] || 'var(--text-muted)' }"
      >
        {{ col }}
      </div>

      <!-- Data rows -->
      <template v-for="(row, ri) in rows" :key="'r-' + ri">
        <div class="hm-row-label">{{ displayRowLabel(row) }}</div>
        <div
          v-for="(cell, ci) in cells[ri]"
          :key="'c-' + ri + '-' + ci"
          class="hm-cell"
          :style="{ background: cell.bg }"
          @click="emit('cell-click', { row: rows[ri], col: columns[ci], value: cell.value })"
        >
          {{ cell.value || '' }}
        </div>
      </template>
    </div>

    <!-- Micro legend: blue (fewer) → yellow → red (more) -->
    <div class="hm-legend">
      <span class="hm-legend-label">Fewer</span>
      <div class="hm-legend-bar">
        <div class="hm-legend-swatch" v-for="n in 5" :key="n"
          :style="{ background: fireColor((n - 1) / 4) }"
        ></div>
      </div>
      <span class="hm-legend-label">More open findings</span>
    </div>
  </div>
</template>

<style scoped>
.heatmap-wrapper {
  width: 100%;
  overflow-x: auto;
}

.heatmap-grid {
  display: grid;
  gap: 2px;
  min-width: 100%;
}

.hm-corner {
  /* empty top-left */
}

.hm-col-header {
  font-size: 11px;
  font-weight: 600;
  text-transform: capitalize;
  text-align: center;
  padding: 6px 4px;
}

.hm-row-label {
  font-size: 12px;
  font-weight: 500;
  color: var(--text-secondary);
  display: flex;
  align-items: center;
  padding-right: 8px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.hm-cell {
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 12px;
  font-weight: 600;
  color: var(--text-primary);
  border-radius: 4px;
  min-height: 32px;
  cursor: pointer;
  transition: background 0.15s, filter 0.15s;
}

.hm-cell:hover {
  filter: brightness(1.2);
}

.hm-cell-dimmed {
  opacity: 0.4;
}

/* Micro legend */
.hm-legend {
  display: flex;
  align-items: center;
  gap: 6px;
  margin-top: 10px;
  justify-content: flex-end;
}

.hm-legend-label {
  font-size: 10px;
  color: var(--text-faint);
  letter-spacing: 0.02em;
}

.hm-legend-bar {
  display: flex;
  gap: 2px;
}

.hm-legend-swatch {
  width: 14px;
  height: 8px;
  border-radius: 2px;
}
</style>
