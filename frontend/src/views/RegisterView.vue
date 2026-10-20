<script setup>
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import api from '@/services/api'

const email = ref('')
const password = ref('')
const error = ref('')
const router = useRouter()
const auth = useAuthStore()

function isValidPassword(pwd) {
  if (!pwd || pwd.length < 8) return false
  const hasLetter = /[a-zA-Z]/.test(pwd)
  const hasDigit = /[0-9]/.test(pwd)
  const hasSpecial = /[^a-zA-Z0-9]/.test(pwd)
  return hasLetter && hasDigit && hasSpecial
}

async function register() {
  try {
    error.value = ''
    if (!isValidPassword(password.value)) {
      error.value = 'Le mot de passe doit contenir au moins 8 caractères, dont au moins une lettre, un chiffre et un caractère spécial.'
      return
    }
    const { data } = await api.post('/auth/register', {
      email: email.value,
      password: password.value
    })
    auth.setToken(data.token, data.user)
    router.push('/')
  } catch (e) {
    error.value = e.response?.data?.error || 'Erreur lors de l\'inscription'
  }
}
</script>

<template>
  <div class="row justify-content-center">
    <div class="col-md-6">
      <div class="card">
        <div class="card-body">
          <h2 class="card-title text-center mb-4">Inscription</h2>
          <div v-if="error" class="alert alert-danger">{{ error }}</div>
          <form @submit.prevent="register">
            <div class="mb-3">
              <label class="form-label">Email</label>
              <input v-model="email" type="email" class="form-control" required>
            </div>
            <div class="mb-3">
              <label class="form-label">Mot de passe</label>
              <input v-model="password" type="password" class="form-control" minlength="8" required>
              <div class="form-text">8 caractères minimum, avec au moins une lettre, un chiffre et un caractère spécial.</div>
            </div>
            <button type="submit" class="btn btn-success w-100">S'inscrire</button>
          </form>
          <p class="text-center mt-3">
            Déjà un compte ? <router-link to="/login">Se connecter</router-link>
          </p>
        </div>
      </div>
    </div>
  </div>
</template>
