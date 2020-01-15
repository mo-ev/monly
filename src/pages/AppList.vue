<template>
  <q-page>
    <div v-if="!error">
      <q-item-label class="text-h2">Apps</q-item-label>
      <q-input class="q-mb-md" dark v-model="searchText" text="Search ...">
        <template v-slot:prepend>
          <q-icon name="search" />
        </template>
      </q-input>
      <q-list dark bordered separator v-if="validApps && validApps.length > 0">
        <q-item clickable v-on:click="selectApp(index)" v-ripple v-for="(app, index) in validApps" v-bind:key="index" :active="app.identifier === selectedApp.identifier" active-class="selected">
          <q-item-section avatar>
            <q-avatar rounded>
              <icon :icon="app.largeIcon" class="icon" style="height: 27px; width: 27px"></icon>
            </q-avatar>
          </q-item-section>
          <q-item-section>
            <q-item-label>{{ app.identifier }}</q-item-label>
            <q-item-label caption>{{ app.name }}</q-item-label>
          </q-item-section>
        </q-item>
      </q-list>
      <q-spinner-dots
        v-else-if="isLoading"
        color="primary"
        size="2em"
      />
      <q-item-label v-else>No apps found.</q-item-label>
    </div>
    <div v-else>
      <q-banner inline-actions rounded class="bg-negative text-white">
        {{error}}

        <template v-slot:action>
          <q-btn flat label="Retry" @click="loadApps" />
        </template>
      </q-banner>
    </div>
  </q-page>
</template>

<script>
import Icon from '../components/Icon'

export default {
  name: 'AppList',
  components: {
    Icon
  },
  mounted () {
    this.isLoading = true
    this.loadApps()
    this.isLoading = false
  },
  data () {
    return {
      apps: [],
      error: null,
      isLoading: false,
      searchText: ''
    }
  },
  computed: {
    selectedApp: {
      get () {
        return { name: this.$store.state.monly.appName, identifier: this.$store.state.monly.appId }
      },
      set (index) {
        const app = this.validApps[index]
        this.$store.commit('monly/updateApp', app)
      }
    },
    validApps: {
      get () {
        return this.apps.filter(app => app.identifier.toLowerCase().includes(this.searchText))
      }
    }
  },
  methods: {
    async loadApps () {
      const deviceId = this.$store.state.monly.deviceId
      await this.$axios.get('http://localhost:3000/api/device/' + deviceId + '/apps')
        .then((response) => {
          this.apps = response.data
        })
        .catch((error) => {
          this.error = error
        })
    },
    selectApp (index) {
      this.selectedApp = index
      this.$router.push({ 'path': 'configuration' })
    }
  }
}
</script>
