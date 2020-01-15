<template>
  <q-layout view="hHh lpR fFf">
    <q-header elevated>
      <q-toolbar>
        <q-btn dense flat round icon="menu" @click="left = !left" />

        <q-toolbar-title>
          <q-avatar>
            <img src="statics/app-logo-128x128.png">
          </q-avatar>
          Monly
        </q-toolbar-title>

        <div v-if="fridaVersion">Frida v.{{fridaVersion}}</div>
      </q-toolbar>

      <q-toolbar inset>
        <q-breadcrumbs active-color="white" style="font-size: 16px">
          <q-breadcrumbs-el label="Home" icon="home" to="/" />
          <q-breadcrumbs-el label="Devices" icon="devices" to="/devices" :disable="true" />
          <q-breadcrumbs-el label="Apps" icon="apps" to="/apps" :disable="true" />
          <q-breadcrumbs-el label="Configuration" icon="search" to="/configuration" :disable="true" />
          <q-breadcrumbs-el label="Monitor" icon="remove_red_eye" to="/monitor" :disable="true" />
        </q-breadcrumbs>
      </q-toolbar>
    </q-header>

    <q-drawer v-model="left" side="left" overlay bordered>
      <q-list>
        <q-item-label header>Essential Links</q-item-label>
        <q-item clickable tag="a" target="_blank" href="https://monly.dev">
          <q-item-section avatar>
            <q-icon name="school" />
          </q-item-section>
          <q-item-section>
            <q-item-label>Docs</q-item-label>
            <q-item-label caption>monly.dev</q-item-label>
          </q-item-section>
        </q-item>
        <q-item clickable tag="a" target="_blank" href="https://github.com/monly">
          <q-item-section avatar>
            <q-icon name="code" />
          </q-item-section>
          <q-item-section>
            <q-item-label>Github</q-item-label>
            <q-item-label caption>github.com/monly</q-item-label>
          </q-item-section>
        </q-item>
      </q-list>
    </q-drawer>

    <q-page-container class="bg-grey-10 text-white">
      <div class="q-pa-md">
        <state />
        <router-view />
      </div>
    </q-page-container>
  </q-layout>
</template>

<script>
import State from '../components/configuration/State'

export default {
  name: 'MonitorLayout',
  components: { State },
  data () {
    return {
      left: false
    }
  },
  computed: {
    fridaVersion () {
      return this.$store.state.monly.fridaVersion
    }
  }
}
</script>
