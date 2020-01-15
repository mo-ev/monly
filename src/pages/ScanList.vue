<template>
  <q-page class="bg-grey-10 text-white">
    <div class="q-pa-md column">
      <q-table
        title="Scans"
        :data="data"
        :columns="columns"
        :loading="isLoading"
        row-key="id"
        selection="single"
        :selected.sync="selected"
        :pagination.sync="pagination"
        :filter="filter"
        dark
      >
        <template v-slot:top-right="props">
          <q-input dark borderless dense debounce="300" v-model="filter" placeholder="Search">
            <template v-slot:append>
              <q-icon name="search" />
            </template>
          </q-input>
          <q-btn
            flat round dense
            :icon="props.inFullscreen ? 'fullscreen_exit' : 'fullscreen'"
            @click="props.toggleFullscreen"
            class="q-ml-md"
          />
        </template>
      </q-table>
      <q-btn class="q-mt-md"  v-if="selected.length > 0" color="accent" icon="select_all" label="Analyse Selected Scan" :to="{ path: `/scan/${selected[0].id }`}" />
    </div>
  </q-page>
</template>

<script>
import { formatDate } from './utils/style'

export default {
  name: 'ScanList',
  mounted () {
    this.isLoading = true
    this.loadScans('deviceId', 'appId')
    this.isLoading = false
  },
  data () {
    return {
      isLoading: false,
      filter: '',
      pagination: {
        // sortBy: 'name',
        // page: 1,
        rowsPerPage: 30,
        descending: true
        // rowsNumber: xx if getting data from a server
      },
      selected: [],
      columns: [
        {
          name: 'id',
          required: true,
          label: 'Scan ID',
          align: 'left',
          field: 'id'
        },
        {
          name: 'createdAt',
          required: true,
          label: 'Created At',
          align: 'left',
          field: 'createdAt',
          format: val => `${formatDate(val, 'YY-MM-DD HH:mm:ss')}`,
          sortable: true
        },
        {
          name: 'app',
          required: true,
          label: 'App',
          align: 'left',
          field: 'app',
          sortable: true
        },
        {
          name: 'device',
          required: true,
          label: 'Device',
          align: 'left',
          field: 'device',
          sortable: true
        }
      ],
      data: []
    }
  },
  methods: {
    async loadScans (deviceId, appId) {
      await this.$axios.get('http://localhost:3000/api/scans')
        .then((response) => {
          this.data = response.data.scans
        })
        .catch(() => {
          console.log('error')
        })
    }
  }
}
</script>

<style scoped>

</style>
