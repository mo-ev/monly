<template>
  <q-page>
    <div v-if="!error">
      <q-item-label class="text-h2 q-mb-md">Devices</q-item-label>
      <q-list dark bordered separator v-if="devices && devices.length > 0">
        <q-item clickable v-on:click="selectDevice(index)" v-ripple v-for="(device, index) in devices" v-bind:key="index" :active="device.id === selectedDevice.id" active-class="selected">
          <q-item-section avatar>
            <q-avatar rounded>
              <icon :icon="device.icon"  class="icon" style="height: 16px; width: 16px"></icon>
            </q-avatar>
          </q-item-section>
          <q-item-section>
            <q-item-label>{{ device.id }}</q-item-label>
            <q-item-label caption>{{ device.name }}</q-item-label>
          </q-item-section>
        </q-item>
      </q-list>
      <q-spinner-dots
        v-else-if="isLoading"
        color="primary"
        size="2em"
      />
      <q-item-label v-else>No connected devices found.</q-item-label>
    </div>
    <div v-else>
      <q-banner inline-actions rounded class="bg-negative text-white">
        {{error}}

        <template v-slot:action>
          <q-btn flat label="Retry" @click="loadDevices" />
        </template>
      </q-banner>
    </div>
  </q-page>
</template>

<script>
import Icon from '../components/Icon'

export default {
  name: 'DeviceList',
  components: {
    Icon
  },
  mounted () {
    this.isLoading = true
    this.loadDevices()
    this.isLoading = false
  },
  data () {
    return {
      devices: null,
      error: null,
      isLoading: false
    }
  },
  computed: {
    fridaVersion: {
      get () {
        return this.$store.state.monly.fridaVersion
      },
      set (val) {
        this.$store.commit('monly/updateVersion', val)
      }
    },
    selectedDevice: {
      get () {
        return { name: this.$store.state.monly.deviceName, id: this.$store.state.monly.deviceId }
      },
      set (index) {
        const device = this.devices[index]
        this.$store.commit('monly/updateDevice', device)
      }
    }
  },
  methods: {
    async loadDevices () {
      await this.$axios.get('http://127.0.0.1:3000/api/devices')
        .then((response) => {
          this.devices = response.data.list
          this.fridaVersion = response.data.version
        })
        .catch(() => {
          console.log('error')
        })
    },
    selectDevice (index) {
      this.selectedDevice = index
      // TODO: navigate to apps view
      this.$router.push({ 'path': 'apps' })
    }
  }
}
</script>
