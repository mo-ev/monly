<template>
  <q-page>
    <q-card>
          <q-tabs
            v-model="type"
            dense
            class="bg-accent text-white"
            active-color="white"
            indicator-color="white"
            align="justify"
            narrow-indicator
            dark
          >
            <q-tab name="info" label="App Information" />
            <q-tab name="settings" label="Scan Settings" />
          </q-tabs>

          <q-separator />

          <q-tab-panels class="bg-blue-grey-8 text-white" v-model="type" animated>
            <q-tab-panel name="info">
              <app-information />
            </q-tab-panel>
            <q-tab-panel name="settings">
              <scan-settings />
            </q-tab-panel>
          </q-tab-panels>
        </q-card>
  </q-page>
</template>

<script>
import AppInformation from '../components/configuration/AppInformation'
import ScanSettings from '../components/configuration/ScanSettings'

export default {
  name: 'Configuration',
  components: { ScanSettings, AppInformation },
  data () {
    return {
      type: 'info'
    }
  }
}
</script>

<style scoped>

</style>
