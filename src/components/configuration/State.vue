<template>
  <div class="q-pb-sm">
    <q-chip dense v-if="this.$store.state.monly.deviceId" color="accent" text-color="white" icon="smartphone">
      {{this.$store.state.monly.deviceId}}
    </q-chip>
    <q-chip dense v-else color="negative" text-color="white" icon="smartphone">
      No device selected
    </q-chip>
    <q-chip dense v-if="this.$store.state.monly.appId" color="accent" text-color="white" icon="stop">
      {{this.$store.state.monly.appId}}
    </q-chip>
    <q-chip dense v-else color="negative" text-color="white" icon="stop">
      No app selected
    </q-chip>
    <q-chip dense v-if="this.$store.state.monly.session" color="accent" text-color="white" icon="stop">
      {{this.$store.state.monly.session}}
    </q-chip>
    <q-chip dense v-else color="negative" text-color="white" icon="stop">
      No session active
    </q-chip>
    <q-chip dense v-if="this.$store.state.monly.session" color="red" text-color="white" icon="clear" clickable @click="onReset">
      Reset
    </q-chip>
  </div>
</template>

<script>

export default {
  name: 'State',
  mounted () {
  },
  methods: {
    onReset () {
      this.resetState()

      this.$store.commit('monly/updateDevice', null)
      this.$store.commit('monly/updateApp', null)
      this.$store.commit('monly/updateSession', null)

      this.$router.push({ 'path': '/' })
    },
    async getState () {
      await this.$axios.get('http://127.0.0.1:3000/api/state/')
        .then((response) => {
          this.$store.commit('monly/updateSession', response.data.session)
        })
        .catch((error) => {
          this.error = error
        })
    },
    async resetState () {
      await this.$axios.get('http://127.0.0.1:3000/api/state/reset/' + this.$store.state.monly.deviceId)
        .then((response) => {
        })
        .catch((error) => {
          this.error = error
        })
    }
  },
  watch: {
    $route (to, from) {
      setTimeout(this.getState, 1000)
    }
  },
  data () {
    return {
      error: null
    }
  }
}
</script>

<style scoped>

</style>
