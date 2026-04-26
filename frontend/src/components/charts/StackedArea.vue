<script setup>
import { ref, onMounted, onUnmounted, watch, nextTick } from 'vue'
import * as echarts from 'echarts/core'
import { LineChart } from 'echarts/charts'
import { GridComponent, TooltipComponent, LegendComponent } from 'echarts/components'
import { CanvasRenderer } from 'echarts/renderers'

echarts.use([LineChart, GridComponent, TooltipComponent, LegendComponent, CanvasRenderer])

const props = defineProps({
  xData: { type: Array, default: () => [] },
  series: { type: Array, default: () => [] },
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
  return {
    tooltip: {
      trigger: 'axis',
      backgroundColor: c.bg,
      borderColor: c.border,
      padding: [10, 14],
      extraCssText: 'border-radius:8px; box-shadow:0 8px 24px rgba(0,0,0,.35);',
      textStyle: { color: c.text, fontSize: 12 },
      formatter(params) {
        if (!params || !params.length) return ''
        const week = params[0].axisValue
        let total = 0
        const rows = params
          .filter(p => p.value > 0)
          .sort((a, b) => b.value - a.value)
          .map(p => {
            total += p.value
            return `<div style="display:flex;align-items:center;gap:6px;padding:2px 0">
              <span style="width:8px;height:8px;border-radius:50%;background:${p.color};flex-shrink:0"></span>
              <span style="flex:1">${p.seriesName}</span>
              <span style="font-weight:600;color:${c.textPrimary}">${p.value}</span>
            </div>`
          })
          .join('')
        return `<div style="min-width:140px">
          <div style="font-weight:600;color:${c.textPrimary};margin-bottom:6px;font-size:13px">${week}</div>
          ${rows}
          <div style="border-top:1px solid ${c.border};margin-top:6px;padding-top:6px;display:flex;justify-content:space-between">
            <span>Total open</span>
            <span style="font-weight:700;color:${c.textPrimary}">${total}</span>
          </div>
          <div style="margin-top:6px;font-size:10px;opacity:.5;text-align:center">Click to filter by severity</div>
        </div>`
      },
    },
    legend: { show: false },
    grid: { left: 36, right: 12, top: 10, bottom: 24, containLabel: false },
    xAxis: {
      type: 'category',
      data: props.xData,
      boundaryGap: false,
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
    series: props.series.map((s) => ({
      name: s.name,
      type: 'line',
      stack: 'total',
      areaStyle: { opacity: 0.45 },
      smooth: true,
      symbol: 'none',
      emphasis: {
        focus: 'series',
        itemStyle: { borderWidth: 2, borderColor: '#fff' },
      },
      lineStyle: { width: 1.5, color: s.color },
      itemStyle: { color: s.color },
      data: s.data,
      triggerLineEvent: true,
    })),
  }
}

function init() {
  if (!chartRef.value) return
  chart = echarts.init(chartRef.value)
  chart.setOption(buildOption())
  chart.on('click', (params) => {
    if (params.seriesName) {
      emit('drill', { severity: params.seriesName, week: params.name })
    }
  })
  chart.getZr().setCursorStyle('pointer')
}

function resize() {
  chart?.resize()
}

watch(() => [props.xData, props.series], () => {
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
