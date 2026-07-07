<template>
  <div class="topo-wrap">
    <h2 class="page-title">🌐 企业网络拓扑可视化 <small>6节点 · 5安全区 · DMZ + 内网 + 管理区</small></h2>

    <n-grid :cols="8" :x-gap="16" :y-gap="16" responsive="screen">
      <n-grid-item :span="5">
        <n-card :bordered="false" class="section-card" content-style="padding:0">
          <div ref="topoCanvas" class="canvas-container">
            <canvas ref="canvasEl"></canvas>
            <div class="topo-legend">
              <div><span class="legend-dot" style="background:#e74c3c"></span> 外部威胁区</div>
              <div><span class="legend-dot" style="background:#f39c12"></span> DMZ隔离区</div>
              <div><span class="legend-dot" style="background:#3b9eff"></span> 内网核心区</div>
              <div><span class="legend-dot" style="background:#2ecc71"></span> 内网高安全区</div>
              <div><span class="legend-dot" style="background:#9b59b6"></span> 安全管理区</div>
            </div>
            <div ref="tooltip" class="topo-tooltip" v-show="tooltipVisible" :style="tooltipStyle" v-html="tooltipContent"></div>
          </div>
        </n-card>
      </n-grid-item>

      <n-grid-item :span="3">
        <!-- Network Summary -->
        <n-card title="网络摘要" size="small" :bordered="false" class="mb-3 section-card">
          <div class="summary-row"><span>总节点</span><strong>{{ summary.total_nodes }}</strong></div>
          <div class="summary-row"><span>运行中</span><n-tag type="success" size="tiny">{{ summary.running }}</n-tag></div>
          <div class="summary-row"><span>已攻陷</span><n-tag type="error" size="tiny">{{ summary.compromised }}</n-tag></div>
          <div class="summary-row"><span>已隔离</span><n-tag type="warning" size="tiny">{{ summary.isolated }}</n-tag></div>
          <n-divider />
          <div class="summary-row"><span>安全区</span><strong>{{ summary.zones }}</strong></div>
          <div class="summary-row"><span>路由规则</span><strong>{{ summary.routes }}</strong></div>
        </n-card>

        <!-- Security Posture -->
        <n-card title="安全态势" size="small" :bordered="false" class="mb-3 section-card">
          <div class="posture-box">
            <div class="posture-level" :style="{ color: postureColor }">{{ posture }}</div>
            <div class="text-muted">当前风险等级</div>
          </div>
        </n-card>

        <!-- Node Detail -->
        <n-card title="节点详情" size="small" :bordered="false" class="section-card">
          <n-empty v-if="!selectedNode" description="点击画布中的节点查看详情" />
          <div v-else>
            <h4 class="node-name">{{ selectedNode.name }}</h4>
            <div class="node-info"><strong>IP:</strong> <code>{{ selectedNode.ip }}</code></div>
            <div class="node-info"><strong>主机名:</strong> {{ selectedNode.hostname }}</div>
            <div class="node-info"><strong>OS:</strong> {{ selectedNode.os }}</div>
            <div class="node-info"><strong>类型:</strong> {{ selectedNode.type }}</div>
            <div class="node-info"><strong>角色:</strong> {{ selectedNode.role }}</div>
            <div class="node-info"><strong>安全区:</strong> <n-tag size="tiny">{{ selectedNode.zone }}</n-tag></div>
            <div class="node-info"><strong>状态:</strong>
              <n-tag :type="selectedNode.status === 'compromised' ? 'error' : (selectedNode.status === 'isolated' ? 'warning' : 'success')" size="tiny">{{ selectedNode.status }}</n-tag>
            </div>
            <n-space class="mt-2">
              <n-tag v-if="selectedNode.is_threat_source" type="error" size="tiny">威胁源</n-tag>
              <n-tag v-if="selectedNode.is_initial_victim" type="warning" size="tiny">初始受害者</n-tag>
              <n-tag v-if="selectedNode.is_patient_zero" type="warning" size="tiny">跳板机</n-tag>
              <n-tag v-if="selectedNode.is_domain_controller" type="info" size="tiny">域控制器</n-tag>
              <n-tag v-if="selectedNode.is_soc" type="success" size="tiny">SOC节点</n-tag>
            </n-space>
          </div>
        </n-card>
      </n-grid-item>
    </n-grid>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted, nextTick } from 'vue'
import { getNetworkTopology, getAllStatus } from '@/api/scenario'
import { useAppStore } from '@/stores/app'

const appStore = useAppStore()
const topoCanvas = ref<HTMLDivElement>()
const canvasEl = ref<HTMLCanvasElement>()
const tooltip = ref<HTMLDivElement>()
const tooltipVisible = ref(false)
const tooltipContent = ref('')
const tooltipStyle = ref({ left: '0px', top: '0px' })
const selectedNode = ref<any>(null)
const summary = ref({ total_nodes: 0, running: 0, compromised: 0, isolated: 0, zones: 0, routes: 0 })
const posture = ref('LOW')
const postureColor = ref('#2ecc71')

// Canvas drawing state
let ctx: CanvasRenderingContext2D | null = null
let W = 0, H = 0
let nodesData: any[] = []
let zonesData: Record<string, any> = {}
let routesData: any[] = []
let nodePositions: Record<string, { x: number; y: number; node: any }> = {}
let hoveredNode: string | null = null
let animFrame = 0
const particles: { x: number; y: number; tx: number; ty: number; speed: number; progress: number; color: string }[] = []

const zoneLayout: Record<string, { cx: number; cy: number; r: number }> = {
  external: { cx: 0.82, cy: 0.22, r: 0.11 },
  dmz: { cx: 0.55, cy: 0.22, r: 0.13 },
  internal: { cx: 0.25, cy: 0.55, r: 0.16 },
  secure_internal: { cx: 0.50, cy: 0.72, r: 0.13 },
  management: { cx: 0.75, cy: 0.78, r: 0.12 },
}

const zoneColors: Record<string, string> = {
  external: '#e74c3c',
  dmz: '#f39c12',
  internal: '#3b9eff',
  secure_internal: '#2ecc71',
  management: '#9b59b6',
}

function resize() {
  if (!topoCanvas.value || !canvasEl.value) return
  W = topoCanvas.value.clientWidth
  H = topoCanvas.value.clientHeight
  canvasEl.value.width = W
  canvasEl.value.height = H
  draw()
}

function draw() {
  if (!ctx || !canvasEl.value) return
  ctx.clearRect(0, 0, W, H)

  // Zone backgrounds
  for (const [zId, zl] of Object.entries(zoneLayout)) {
    const zx = zl.cx * W, zy = zl.cy * H, zr = zl.r * Math.min(W, H)
    ctx.beginPath()
    ctx.arc(zx, zy, zr, 0, Math.PI * 2)
    ctx.fillStyle = zoneColors[zId] + '0a'
    ctx.fill()
    ctx.strokeStyle = zoneColors[zId] + '33'
    ctx.lineWidth = 1.5
    ctx.setLineDash([6, 4])
    ctx.stroke()
    ctx.setLineDash([])

    const zName = (zonesData[zId] || {}).name || zId
    ctx.fillStyle = zoneColors[zId]
    ctx.font = 'bold 10px system-ui'
    ctx.textAlign = 'center'
    ctx.fillText(zName, zx, zy - zr - 6)
  }

  // Routes
  if (routesData) {
    routesData.forEach(route => {
      if (!route.allowed) return
      const fromZone = zoneLayout[(nodesData.find(n => n.id === route.from) || {}).zone || '']
      if (!fromZone) return
      const targets = route.to === 'all' ? nodesData.filter(n => n.id !== route.from) : nodesData.filter(n => n.id === route.to)
      targets.forEach(tn => {
        const toZone = zoneLayout[tn.zone]
        if (!toZone) return
        ctx!.beginPath()
        ctx!.moveTo(fromZone.cx * W, fromZone.cy * H)
        ctx!.lineTo(toZone.cx * W, toZone.cy * H)
        ctx!.strokeStyle = 'rgba(136,153,176,.12)'
        ctx!.lineWidth = 1
        ctx!.stroke()
      })
    })
  }

  // Particles
  particles.forEach(p => {
    ctx!.beginPath()
    ctx!.arc(p.x, p.y, 2, 0, Math.PI * 2)
    ctx!.fillStyle = p.color
    ctx!.fill()
  })

  // Nodes
  if (nodesData.length) {
    const zoneCounts: Record<string, number> = {}
    nodesData.forEach(n => { zoneCounts[n.zone] = (zoneCounts[n.zone] || 0) + 1 })
    const zoneIdx: Record<string, number> = {}
    nodePositions = {}

    nodesData.forEach(n => {
      const zl = zoneLayout[n.zone] || { cx: 0.5, cy: 0.5, r: 0.2 }
      const idx = zoneIdx[n.zone] || 0; zoneIdx[n.zone] = idx + 1
      const count = zoneCounts[n.zone] || 1
      const angle = (idx / count) * Math.PI * 2 - Math.PI / 2
      const rr = zl.r * Math.min(W, H) * 0.5
      const nx = zl.cx * W + Math.cos(angle) * rr
      const ny = zl.cy * H + Math.sin(angle) * rr
      nodePositions[n.id] = { x: nx, y: ny, node: n }

      // Glow for compromised
      if (n.status === 'compromised') {
        const grad = ctx!.createRadialGradient(nx, ny, 10, nx, ny, 26)
        grad.addColorStop(0, 'rgba(231,76,60,.4)')
        grad.addColorStop(1, 'rgba(231,76,60,0)')
        ctx!.beginPath(); ctx!.arc(nx, ny, 26, 0, Math.PI * 2); ctx!.fillStyle = grad; ctx!.fill()
      }

      const color = n.status === 'compromised' ? '#e74c3c' : zoneColors[n.zone]
      const r = (hoveredNode === n.id || selectedNode.value?.id === n.id) ? 22 : 18
      ctx!.beginPath(); ctx!.arc(nx, ny, r, 0, Math.PI * 2)
      ctx!.fillStyle = color
      ctx!.fill()
      ctx!.strokeStyle = n.status === 'compromised' ? '#ff4444' : (hoveredNode === n.id ? '#fff' : 'rgba(255,255,255,.2)')
      ctx!.lineWidth = n.status === 'compromised' ? 2.5 : (hoveredNode === n.id ? 2 : 1)
      ctx!.stroke()

      // Icon
      ctx!.fillStyle = '#fff'
      ctx!.font = (r > 20 ? '15px' : '13px') + ' system-ui'
      ctx!.textAlign = 'center'; ctx!.textBaseline = 'middle'
      const icon = n.is_soc ? '🛡' : (n.is_threat_source ? '💀' : (n.is_domain_controller ? '🏛' : (n.is_patient_zero ? '🎯' : '🖥')))
      ctx!.fillText(icon, nx, ny)

      // Label
      ctx!.fillStyle = '#8899b0'
      ctx!.font = '9px system-ui'
      ctx!.fillText(n.name || '', nx, ny + r + 12)
    })
  }
}

function updateParticles() {
  if (particles.length < 20 && nodesData.length && Math.random() < 0.3) {
    const validRoutes = (routesData || []).filter(r => r.allowed)
    if (validRoutes.length) {
      const route = validRoutes[Math.floor(Math.random() * validRoutes.length)]
      const fromNode = nodesData.find(n => n.id === route.from)
      if (fromNode) {
        const targets = route.to === 'all' ? nodesData.filter(n => n.id !== route.from) : nodesData.filter(n => n.id === route.to)
        if (targets.length) {
          const tn = targets[Math.floor(Math.random() * targets.length)]
          const fromZone = zoneLayout[fromNode.zone], toZone = zoneLayout[tn.zone]
          if (fromZone && toZone) {
            particles.push({
              x: fromZone.cx * W, y: fromZone.cy * H,
              tx: toZone.cx * W, ty: toZone.cy * H,
              speed: 0.003 + Math.random() * 0.006,
              progress: 0,
              color: zoneColors[fromNode.zone] + '88',
            })
          }
        }
      }
    }
  }
  for (let i = particles.length - 1; i >= 0; i--) {
    const p = particles[i]
    p.progress += p.speed
    p.x = p.x + (p.tx - p.x) * p.speed * 3
    p.y = p.y + (p.ty - p.y) * p.speed * 3
    if (p.progress >= 1) particles.splice(i, 1)
  }
}

function onMouseMove(e: MouseEvent) {
  if (!canvasEl.value) return
  const rect = canvasEl.value.getBoundingClientRect()
  const mx = e.clientX - rect.left, my = e.clientY - rect.top
  let found: string | null = null
  for (const [id, np] of Object.entries(nodePositions)) {
    const dx = mx - np.x, dy = my - np.y
    if (Math.sqrt(dx * dx + dy * dy) < 22) { found = id; break }
  }
  if (found !== hoveredNode) { hoveredNode = found; draw() }

  if (found && nodePositions[found]) {
    const n = nodePositions[found].node
    tooltipContent.value = `<strong>${n.name}</strong><br>IP: <code>${n.ip}</code><br>Role: ${n.role}<br>Zone: ${n.zone}<br>Status: <span style="color:${n.status === 'compromised' ? '#e74c3c' : '#2ecc71'}">${n.status}</span>`
    tooltipVisible.value = true
    tooltipStyle.value = {
      left: (mx + 16) + 'px',
      top: (my - 10) + 'px',
    }
  } else {
    tooltipVisible.value = false
  }
}

function onClick(e: MouseEvent) {
  if (!canvasEl.value) return
  const rect = canvasEl.value.getBoundingClientRect()
  const mx = e.clientX - rect.left, my = e.clientY - rect.top
  for (const [id, np] of Object.entries(nodePositions)) {
    const dx = mx - np.x, dy = my - np.y
    if (Math.sqrt(dx * dx + dy * dy) < 22) {
      selectedNode.value = np.node
      draw()
      return
    }
  }
}

async function loadData() {
  try {
    const res = await getNetworkTopology()
    if (res.data?.ok) {
      nodesData = res.data.data?.nodes || []
      zonesData = res.data.data?.zones || {}
      routesData = res.data.data?.routes || []
      const sum = res.data.data?.summary || {}
      summary.value = {
        total_nodes: sum.total_nodes || nodesData.length,
        running: sum.running || 0,
        compromised: sum.compromised || 0,
        isolated: sum.isolated || 0,
        zones: Object.keys(zonesData).length,
        routes: routesData.length,
      }
      draw()
    }
  } catch {}
  try {
    const statusRes = await getAllStatus()
    if (statusRes.data?.ok) {
      const net = statusRes.data.network || {}
      const risk = net.overall_risk || 'low'
      posture.value = risk.toUpperCase()
      const rc = risk === 'critical' ? '#e74c3c' : (risk === 'high' ? '#f59e0b' : (risk === 'medium' ? '#00a3c4' : '#2ecc71'))
      postureColor.value = rc
    }
  } catch {}
}

function animate() {
  updateParticles()
  if (nodesData.length) draw()
  animFrame = requestAnimationFrame(animate)
}

onMounted(async () => {
  await nextTick()
  ctx = canvasEl.value?.getContext('2d') || null
  // @ts-ignore
  window.addEventListener('resize', resize)
  canvasEl.value?.addEventListener('mousemove', onMouseMove)
  canvasEl.value?.addEventListener('click', onClick)
  canvasEl.value?.addEventListener('mouseleave', () => { hoveredNode = null; draw() })
  await loadData()
  resize()
  animate()
  setInterval(loadData, 8000)
})

onUnmounted(() => {
  cancelAnimationFrame(animFrame)
  // @ts-ignore
  window.removeEventListener('resize', resize)
})
</script>

<style scoped>
.topo-wrap { max-width: 1200px; margin: 0 auto; }
.page-title { font-size: 20px; margin-bottom: 16px; }
.page-title small { font-size: 13px; color: #6b7280; font-weight: 400; }
.mb-3 { margin-bottom: 16px; }
.mt-2 { margin-top: 10px; }
.section-card { border-radius: 14px; }
.canvas-container { position: relative; width: 100%; height: 540px; overflow: hidden; cursor: grab; background: #fafbfd; border-radius: 14px; }
.canvas-container:active { cursor: grabbing; }
.canvas-container canvas { display: block; }
.topo-legend { position: absolute; top: 12px; right: 12px; background: #fff; border: 1px solid #e5e7eb; border-radius: 8px; padding: 10px 14px; font-size: 11px; z-index: 5; box-shadow: 0 4px 12px rgba(0,0,0,.06); }
.topo-legend div { margin: 3px 0; }
.legend-dot { display: inline-block; width: 10px; height: 10px; border-radius: 2px; margin-right: 6px; }
.topo-tooltip { position: absolute; background: #fff; border: 1px solid #d0d6e0; border-radius: 8px; padding: 10px 14px; font-size: 12px; pointer-events: none; z-index: 10; max-width: 300px; box-shadow: 0 8px 24px rgba(0,0,0,.1); }
.summary-row { display: flex; justify-content: space-between; align-items: center; padding: 4px 0; font-size: 13px; }
.posture-box { text-align: center; padding: 16px 0; }
.posture-level { font-size: 48px; font-weight: 800; line-height: 1; }
.text-muted { color: #6b7280; font-size: 12px; }
.node-name { margin: 0 0 8px 0; }
.node-info { margin: 4px 0; font-size: 13px; }
</style>
