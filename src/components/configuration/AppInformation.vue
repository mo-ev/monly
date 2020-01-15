<template>
  <div v-if="!error">
    <q-splitter
      :value=10
      :limits="[10,10]"
    >

      <template v-slot:before>
        <q-tabs
          v-model="info"
          vertical
          class="text-white"
        >
          <q-tab name="general" icon="info" label="General" />
          <q-tab name="strings" icon="text_fields" label="Strings" />
          <q-tab name="modules" icon="view_module" label="Modules" />
          <q-tab name="classes" icon="all_out" label="Classes" />
          <q-tab name="storage" icon="storage" label="Storage" />
          <q-tab name="binary" icon="memory" label="Binary" />
          <q-tab name="logs" icon="attach_file" label="Logs" />
        </q-tabs>
      </template>

      <template v-slot:after>
        <q-tab-panels
          v-model="info"
          animated
          transition-prev="jump-up"
          transition-next="jump-up"
          class="bg-transparent"
        >
          <q-tab-panel name="general">
            <general v-if="item.general" :item="item.general" />
            <loading v-else />
          </q-tab-panel>

          <q-tab-panel name="strings">
            <message message="This function is not yet available in the current release version." />
          </q-tab-panel>

          <q-tab-panel name="modules">
            <modules v-if="item.modules" :items="item.modules" />
            <loading v-else />
          </q-tab-panel>

          <q-tab-panel name="classes">
            <classes v-if="item.classes" :items="item.classes" />
            <loading v-else />
          </q-tab-panel>

          <q-tab-panel name="storage">
            <storage v-if="item.storage" :item="item.storage" />
            <loading v-else />
          </q-tab-panel>

          <q-tab-panel name="binary">
            <message message="This function is not yet available in the current release version." />
            <div class="column text-center">
              <q-btn color="accent" icon="lock_open" label="Decrypt App Binary" />
            </div>
          </q-tab-panel>

          <q-tab-panel name="logs">
            <message message="This function is not yet available in the current release version." />
          </q-tab-panel>
        </q-tab-panels>
      </template>

    </q-splitter>
  </div>
  <div v-else>
    <q-banner inline-actions rounded class="bg-negative text-white">
      {{error}}

      <template v-slot:action>
        <q-btn flat label="Retry" @click="getAppInfo" />
      </template>
    </q-banner>
  </div>
</template>

<script>
import General from '../../components/configuration/General'
import Loading from '../../components/utils/Loading'
import Modules from '../../components/configuration/Modules'
import Classes from '../../components/configuration/Classes'
import Storage from '../../components/configuration/Storage'
import Message from './Message'

export default {
  name: 'AppInformation',
  components: { Storage, Classes, Modules, Loading, General, Message },
  mounted () {
    this.getAppInfo()
  },
  methods: {
    async getAppInfo () {
      await this.$axios.get('http://127.0.0.1:3000/api/device/' + this.deviceId + '/' + this.appId + '/info')
        .then((response) => {
          this.item.general = response.data.general
          this.item.strings = response.data.strings
          this.item.modules = response.data.modules
          this.item.classes = response.data.classes
          this.item.storage = response.data.storage
          this.item.logs = response.data.logs
        })
        .catch((error) => {
          this.error = error
        })
    }
  },
  data () {
    return {
      deviceId: this.$store.state.monly.deviceId,
      appId: this.$store.state.monly.appId,
      error: null,
      info: 'general',
      item: {
        general: null,
        strings: null,
        modules: null,
        classes: null,
        storage: null,
        logs: null
      }
    }
  }
}
</script>

<style scoped>

</style>
