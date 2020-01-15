<template>
  <div class="column q-pa-md">
    <div class="q-gutter-sm">
      <q-toggle color="green" :label="options.args.label" v-model="selectedOptions" val="args" />
      <q-toggle color="green" :label="options.returnValue.label" v-model="selectedOptions" val="returnValue" />
      <q-toggle color="green" :label="options.backtrace.label" v-model="selectedOptions" val="backtrace" />
    </div>
    <div class="row q-gutter-md">
      <q-card class="card-hook" v-for="item in this.hooks" :key="item.name">
      <q-table
        class="q-mb-md"
        dense
        :title="item.name"
        :data="item.values"
        :columns="columns"
        :loading="isLoading"
        row-key="hook"
        selection="multiple"
        :selected.sync="selectedHooks"
        dark
        hide-bottom
      >
      </q-table>
    </q-card>
    </div>
    <q-btn v-if="selectedHooks.length > 0" color="accent" icon="select_all" label="Start Scan" @click="startScanSelected" />
  </div>
</template>

<script>
import json from '../../assets/configuration'

export default {
  name: 'ScanSettings',
  data () {
    return {
      deviceId: this.$store.state.monly.deviceId,
      appId: this.$store.state.monly.appId,
      hooks: json.hooks,
      isLoading: false,
      columns: [
        {
          name: 'Hook',
          label: 'Hook',
          align: 'left',
          field: 'hook'
        }
      ],
      options: {
        args: {
          label: 'Argument/s'
        },
        returnValue: {
          label: 'Return Value'
        },
        backtrace: {
          label: 'Backtrace'
        }
      },
      selectedHooks: [],
      selectedOptions: []
    }
  },
  methods: {
    async startScanSelected () {
      console.log('monitor app selected')
      await this.$axios.post('http://127.0.0.1:3000/api/monitor/' + this.deviceId + '/' + this.appId, { 'hooks': this.selectedHooks, 'options': this.selectedOptions })
        .then((response) => {
          console.log(response.data.result.scan)
          this.$router.push({ 'path': `monitor/${response.data.result.scan.id}` })
        })
        .catch((error) => {
          console.log(error)
        })
    }
  }
}
</script>

<style scoped>

  .card-hook {
    background: unset;
    box-shadow: unset;
  }

</style>
