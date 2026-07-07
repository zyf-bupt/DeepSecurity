import { createRouter, createWebHistory } from 'vue-router'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    {
      path: '/',
      name: 'home',
      component: () => import('@/views/HomeView.vue'),
    },
    {
      path: '/dashboard',
      name: 'dashboard',
      component: () => import('@/views/DashboardView.vue'),
    },
    {
      path: '/scenario',
      name: 'scenario',
      component: () => import('@/views/ScenarioView.vue'),
    },
    {
      path: '/scenario/network',
      name: 'network-topology',
      component: () => import('@/views/NetworkTopologyView.vue'),
    },
    {
      path: '/detection',
      name: 'detection',
      component: () => import('@/views/DetectionView.vue'),
    },
    {
      path: '/attribution',
      name: 'attribution',
      component: () => import('@/views/AttributionView.vue'),
    },
    {
      path: '/attack',
      name: 'attack',
      component: () => import('@/views/AttackChainView.vue'),
    },
    {
      path: '/traceback',
      name: 'traceback',
      component: () => import('@/views/TracebackView.vue'),
    },
    {
      path: '/logs',
      name: 'logs',
      component: () => import('@/views/LogsView.vue'),
    },
    {
      path: '/logs/:id',
      name: 'log-detail',
      component: () => import('@/views/LogDetailView.vue'),
    },
    {
      path: '/logs/logontracer',
      name: 'logontracer',
      component: () => import('@/views/LogontracerView.vue'),
    },
    {
      path: '/behavior',
      name: 'behavior',
      component: () => import('@/views/BehaviorView.vue'),
    },
    {
      path: '/traffic',
      name: 'traffic',
      component: () => import('@/views/TrafficView.vue'),
    },
    {
      path: '/traffic/:id',
      name: 'traffic-detail',
      component: () => import('@/views/TrafficDetailView.vue'),
    },
  ],
})

export default router
