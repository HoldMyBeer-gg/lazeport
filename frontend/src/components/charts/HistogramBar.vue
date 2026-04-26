<script setup>
import { ref, onMounted, onUnmounted, watch, nextTick } from 'vue'
import * as echarts from 'echarts/core'
import { BarChart } from 'echarts/charts'
import { GridComponent, TooltipComponent } from 'echarts/components'
import { CanvasRenderer } from 'echarts/renderers'

echarts.use([BarChart, GridComponent, TooltipComponent, CanvasRenderer])

const props = defineProps({
  xData: { type: Array, default: () => [] },
  yData: { type: Array, default: () => [] },
  barColor: { type: String, default: '#0d9488' },
  barColors: { type: Array, default: () => [] },
})
const emit = defineEmits(['drill'])

const chartRef = ref(null)
let chart = null

function getThemeColors() {
  const s = getComputedStyle(document.documentElement)
  return {
    text: s.getPropertyValue('--text-muted').trim() || '#ddebff',
    textPrimary: s.getPropertyValue('--text-primary').trim() || '#e2e8f0',
    border: s.getPropertyValue('--border').trim() || '#1e293b',
    bg: s.getPropertyValue('--bg-card').trim() || '#111827',
  }
}

function buildOption() {
  const c = getThemeColors()
  const colors = props.barColors.length ? props.barColors : props.yData.map(() => props.barColor)
  const total = props.yData.reduce((s, v) => s + v, 0) || 1
  return {
    tooltip: {
      trigger: 'axis',
      axisPointer: { type: 'shadow' },
      backgroundColor: c.bg,
      borderColor: c.border,
      padding: [10, 14],
      extraCssText: 'border-radius:8px; box-shadow:0 8px 24px rgba(0,0,0,.35);',
      textStyle: { color: c.text, fontSize: 12 },
      formatter(params) {
        if (!params || !params.length) return ''
        const p = params[0]
        const pct = ((p.value / total) * 100).toFixed(0)
        return `<div style="min-width:120px">
          <div style="font-weight:600;color:${c.textPrimary};margin-bottom:4px;font-size:13px">${p.axisValue}</div>
          <div style="display:flex;align-items:center;gap:6px;padding:2px 0">
            <span style="width:8px;height:8px;border-radius:2px;background:${p.color};flex-shrink:0"></span>
            <span style="flex:1">Open findings</span>
            <span style="font-weight:600;color:${c.textPrimary}">${p.value}</span>
          </div>
          <div style="font-size:11px;opacity:.6;margin-top:2px">${pct}% of all open findings</div>
        </div>`
      },
    },
    grid: { left: 36, right: 12, top: 10, bottom: 24, containLabel: false },
    xAxis: {
      type: 'category',
      data: props.xData,
      axisLine: { show: false },
      axisTick: { show: false },
      axisLabel: { color: c.text, fontSize: 12 },
    },
    yAxis: {
      type: 'value',
      splitLine: { lineStyle: { color: c.border, type: 'dashed' } },
      axisLabel: { color: c.text, fontSize: 12 },
      axisLine: { show: false },
      axisTick: { show: false },
    },
    series: [{
      type: 'bar',
      data: props.yData.map((val, i) => ({
        value: val,
        itemStyle: { color: colors[i] || props.barColor, borderRadius: [3, 3, 0, 0] },
      })),
      barWidth: '60%',
      emphasis: {
        itemStyle: { shadowBlur: 8, shadowColor: 'rgba(0,0,0,.3)' },
      },
    }],
  }
}

function init() {
  if (!chartRef.value) return
  chart = echarts.init(chartRef.value)
  chart.setOption(buildOption())
  chart.on('click', (params) => {
    emit('drill', { bucket: params.name, count: params.value })
  })
}

function resize() {
  chart?.resize()
}

watch(() => [props.xData, props.yData, props.barColors], () => {
  if (chart) chart.setOption(buildOption(), true)
}, { deep: true })

onMounted(() => {
  nextTick(init)
  window.addEventListener('resize', resize)
})

onUnmounted(() => {
  window.removeEventListener('resize', resize)
  chart?.dispose()
})
</script>

<template>
  <div ref="chartRef" style="width:100%;height:100%;cursor:pointer"></div>
</template>
