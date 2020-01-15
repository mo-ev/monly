<template>
  <q-page class="bg-grey-10 text-white">
    <div class="q-pa-md column">
      <q-toggle v-model="visible" label="Observed Hooks" class="q-mb-md" />
      <div v-show="visible">
        <q-table class="q-ma-md"
                 title="Observed Items"
                 dense
                 :data="items"
                 :columns="columnsItems"
                 :loading="isLoading"
                 row-key="name"
                 :visible-columns="visibleColumnsItems"
                 :pagination.sync="paginationItems"
                 dark
        />
      </div>
      <q-table class="q-ma-md"
        title="Scan"
        dense
        :data="data"
        :columns="columns"
        :loading="isLoading"
        row-key="id"
        :visible-columns="visibleColumns"
        :pagination.sync="pagination"
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
          <q-btn borderless flat size="12px" icon="refresh" @click="refresh" />
        </template>
      </q-table>
    </div>
  </q-page>
</template>

<script>
import { formatDate } from './utils/style'

export default {
  name: 'Monitor',
  mounted () {
    this.observedItems()

    this.refresh()
    this.polling = window.setInterval(() => {
      this.refresh()
    }, 5000)
  },
  created () {},
  beforeDestroy () {
    window.clearInterval(this.polling)
  },
  data () {
    return {
      polling: null,
      visible: false,
      isLoading: false,
      items: null,
      paginationItems: {
        rowsPerPage: 25
      },
      columnsItems: [
        {
          name: 'address',
          label: 'Address',
          align: 'left',
          field: 'address'
        },
        {
          name: 'name',
          label: 'Name',
          align: 'left',
          field: 'name'
        }
      ],
      visibleColumnsItems: ['address', 'name'],
      data: [],
      pagination: {
        sortBy: 'createdAt',
        descending: true,
        rowsPerPage: 100
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
      ]
    }
  },
  methods: {
    async refresh () {
      const scanId = this.$route.params.scanId
      await this.$axios.get('http://localhost:3000/api/scans/' + scanId)
        .then((response) => {
          this.data = response.data.scanItems
        })
        .catch(() => {
          console.log('error')
        })
    },
    async observedItems () {
      await this.$axios.get('http://localhost:3000/api/monitor/observed')
        .then((response) => {
          let tmpItems = []
          response.data.result.forEach(hook => {
            hook.forEach(item => {
              tmpItems.push(item)
            })
          })
          this.items = tmpItems
        })
        .catch(() => {
          console.log('error')
        })
    }
  }
}
</script>
