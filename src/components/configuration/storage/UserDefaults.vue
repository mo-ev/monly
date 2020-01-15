<template>
  <div v-if="items" class="column">
    {{items}}
    <q-table
      class="q-mb-md"
      dense
      :data="items"
      :columns="columns"
      row-key="name"
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
  </div>
</template>

<script>
export default {
  name: 'UserDefaults',
  props: {
    items: Array
  },
  data () {
    return {
      pagination: {
        rowsPerPage: 25
      },
      filter: '',
      columns: [
        {
          name: 'version',
          required: true,
          label: 'Version',
          align: 'left',
          field: 'version'
        },
        {
          name: 'name',
          required: true,
          label: 'Name',
          align: 'left',
          field: 'name'
        },
        {
          name: 'value',
          required: true,
          label: 'Value',
          align: 'left',
          field: 'value'
        },
        {
          name: 'domain',
          required: true,
          label: 'Domain',
          align: 'left',
          field: 'domain'
        },
        {
          name: 'path',
          required: true,
          label: 'Path',
          align: 'left',
          field: 'path'
        },
        {
          name: 'isSecure',
          required: true,
          label: 'Secure',
          align: 'left',
          field: 'isSecure'
        }
      ]
    }
  }
}
</script>
