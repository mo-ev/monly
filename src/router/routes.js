
const homeRoutes = [
  {
    path: '/',
    component: () => import('layouts/HomeLayout.vue'),
    children: [
      { path: '', component: () => import('pages/Welcome.vue') }
    ]
  },
  {
    path: '/',
    component: () => import('layouts/MonitorLayout.vue'),
    children: [
      { path: 'devices', component: () => import('pages/DeviceList.vue') },
      { path: 'apps', component: () => import('pages/AppList.vue') },
      { path: 'configuration', component: () => import('pages/Configuration.vue') },
      { path: 'monitor/:scanId', component: () => import('pages/Monitor.vue') }
    ]
  },
  {
    path: '/',
    component: () => import('layouts/AnalyticLayout.vue'),
    children: [
      { path: 'scans', component: () => import('pages/ScanList.vue') },
      { path: 'scan/:id', component: () => import('pages/Scan.vue') }
    ]
  }
]

// Always leave this as last one
if (process.env.MODE !== 'ssr') {
  homeRoutes.push({
    path: '*',
    component: () => import('pages/Error404.vue')
  })
}

export default homeRoutes
