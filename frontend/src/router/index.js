import { createRouter, createWebHistory } from 'vue-router'
import Login from '../views/Login.vue'
import AcceptInvite from '../views/AcceptInvite.vue'
import DashboardLayout from '../views/DashboardLayout.vue'
import NotFound from '../views/NotFound.vue'
import { getSessionUser } from '../services/api'

// Child views are lazy-loaded; DashboardLayout must be eager so Vue Router
// can preserve it across child navigations without remounting the shell.
const Teams = () => import('../views/Teams.vue')
const Applications = () => import('../views/Applications.vue')
const GenerateRedirect = () => import('../views/GenerateRedirect.vue')
const Templates = () => import('../views/Templates.vue')
const Connectors = () => import('../views/Connectors.vue')
const ReportReader = () => import('../views/ReportReader.vue')
const ReportFindings = () => import('../views/ReportFindings.vue')
const Settings = () => import('../views/Settings.vue')
const Reports = () => import('../views/Reports.vue')
const OrganizationManagement = () => import('../views/OrganizationManagement.vue')
const Trends = () => import('../views/Trends.vue')

const routes = [
  { path: '/', redirect: '/login' },
  { path: '/login', component: Login },
  { path: '/invite', component: AcceptInvite },
  // Reader view: outside DashboardLayout for a clean, chromeless reading experience
  { path: '/dashboard/reports/:id/read', component: ReportReader, props: true },
  {
    path: '/dashboard',
    component: DashboardLayout,
    children: [
      { path: '', redirect: '/dashboard/generate' },
      { path: 'generate', component: GenerateRedirect },
      { path: 'settings', component: Settings },
      { path: 'profile', redirect: '/dashboard/settings' },
      { path: 'clients', component: Teams },
      { path: 'clients', redirect: '/dashboard/clients' },
      { path: 'applications', component: Applications },
      { path: 'templates', component: Templates },
      { path: 'reports', component: Reports, name: 'Reports' },
      { path: 'reports/:id/findings', component: ReportFindings, props: true },
      { path: 'connectors', component: Connectors },
      { path: 'trends', component: Trends },
      { path: 'organization', component: OrganizationManagement },
    ],
  },
  { path: '/:pathMatch(.*)*', name: 'NotFound', component: NotFound },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

router.beforeEach(async (to) => {
  if (to.path === '/login' || to.path === '/invite') {
    const user = await getSessionUser()
    if (user) return '/dashboard'
    return true
  }
  if (to.path.startsWith('/dashboard')) {
    const user = await getSessionUser()
    if (!user) return '/login'
  }
  return true
})

export default router
