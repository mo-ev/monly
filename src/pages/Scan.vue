<template>
  <q-page class="bg-grey-10 text-white">
    <div class="q-pa-md column">
      <q-table
        title="Scan"
        dense
        :data="data"
        :columns="columns"
        :loading="isLoading"
        row-key="name"
        :visible-columns="visibleColumns"
        :pagination.sync="pagination"
        :filter="filter"
        dark
      >
        <template v-slot:top="props">
          <q-select
            v-model="visibleColumns"
            multiple
            borderless
            dense
            options-dense
            :display-value="$q.lang.table.columns"
            emit-value
            dark
            map-options
            :options="columns"
            option-value="name"
            style="min-width: 150px"
          />
          <q-space />
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
          <q-btn flat round dense size="12px" icon="refresh" @click="loadScan" />
        </template>
      </q-table>
    </div>
  </q-page>
</template>

<script>
import { formatDate } from './utils/style'

export default {
  name: 'Scan',
  mounted () {
    this.isLoading = true
    this.loadScan()
    this.isLoading = false
  },
  data () {
    return {
      isLoading: false,
      filter: '',
      pagination: {
        // sortBy: 'name',
        // descending: false,
        // page: 1,
        rowsPerPage: 30
        // rowsNumber: xx if getting data from a server
      },
      visibleColumns: ['id', 'createdAt', 'data'],
      columns: [
        {
          name: 'id',
          label: 'ID',
          align: 'left',
          field: 'id'
        },
        {
          name: 'scanId',
          label: 'Scan ID',
          align: 'left',
          field: 'scanId'
        },
        {
          name: 'createdAt',
          label: 'Created At',
          align: 'left',
          field: 'createdAt',
          format: val => `${formatDate(val, 'YY-MM-DD HH:mm:ss:SSS')}`,
          sortable: true
        },
        {
          name: 'data',
          label: 'Data',
          align: 'left',
          field: 'data',
          format: (val) => `${JSON.stringify(val.payload.method)}`
        }
      ],
      data: []
    }
  },
  methods: {
    async loadScan () {
      const scanId = this.$route.params.id
      await this.$axios.get('http://localhost:3000/api/scans/' + scanId)
        .then((response) => {
          this.data = response.data.scanItems
        })
        .catch(() => {
          console.log('error')
        })
    }
  }
}
</script>
