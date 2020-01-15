<template>
  <div v-if="item" class="column">
    <q-card>
      <q-tabs
        v-model="tab"
        dense
        class="bg-accent text-white"
        active-color="white"
        indicator-color="white"
        align="justify"
        narrow-indicator
      >
        <q-tab name="keychain" label="Keychain" />
        <q-tab name="cookies" label="Cookies" />
        <q-tab name="userdefaults" label="User Defaults" />
      </q-tabs>

      <q-separator />

      <q-tab-panels class="bg-blue-grey-4" v-model="tab" animated>
        <q-tab-panel name="keychain">
          <keychain v-if="item.keychain" :items="item.keychain" />
        </q-tab-panel>

        <q-tab-panel name="cookies">
          <cookies v-if="item.cookies" :items="item.cookies" />
        </q-tab-panel>

        <q-tab-panel name="userdefaults">
          <user-defaults v-if="item.userDefaults" :items="item.userDefaults" />
        </q-tab-panel>
      </q-tab-panels>
    </q-card>
  </div>
</template>

<script>
import Keychain from './storage/Keychain'
import Cookies from './storage/Cookies'
import UserDefaults from './storage/UserDefaults'
export default {
  name: 'storage',
  components: { UserDefaults, Cookies, Keychain },
  props: {
    item: {
      keychain: Object,
      cookies: Object,
      userDefaults: Object
    }
  },
  data () {
    return {
      tab: 'keychain'
    }
  }
}
</script>

<style scoped>

</style>
