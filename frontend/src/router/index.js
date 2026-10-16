import { createRouter, createWebHistory } from 'vue-router'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', component: () => import('@/views/HomeView.vue') },
    { path: '/login', component: () => import('@/views/LoginView.vue') },
    { path: '/register', component: () => import('@/views/RegisterView.vue') },
    { path: '/profile/:id', component: () => import('@/views/ProfileView.vue') },
    { path: '/project/:id', component: () => import('@/views/ProjectView.vue') },

    {
      path: '/admin',
      component: () => import('@/views/AdminView.vue'),
      beforeEnter: (to, from, next) => {
        const user = JSON.parse(localStorage.getItem('devfolio_user') || 'null')
        if (user && user.role === 'ADMIN') {
          next()
        } else {
          next('/login')
        }
      }
    }
  ]
})

export default router
