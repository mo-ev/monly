<template>
  <div v-if="items" class="column">
    <q-table
      class="q-mb-md"
      dense
      :data="items"
      :columns="columns"
      row-key="name"
      :visible-columns="visibleColumns"
      :pagination.sync="pagination"
      :filter="filter"
      dark
    >
      <template v-slot:top-left="props">
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
      </template>
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
  name: 'Keychain',
  props: {
    items: Array
  },
  data () {
    return {
      pagination: {
        // sortBy: 'name',
        // descending: false,
        // page: 1,
        rowsPerPage: 25
        // rowsNumber: xx if getting data from a server
      },
      filter: '',
      visibleColumns: ['clazz', 'creation'],
      columns: [
        {
          name: 'clazz',
          label: 'Clazz',
          align: 'left',
          field: 'clazz'
        },
        {
          name: 'creation',
          label: 'Creation',
          align: 'left',
          field: 'creation'
        },
        {
          name: 'modification',
          label: 'Modification',
          align: 'left',
          field: 'modification'
        },
        {
          name: 'description',
          label: 'Description',
          align: 'left',
          field: 'description'
        },
        {
          name: 'comment',
          label: 'Comment',
          align: 'left',
          field: 'comment'
        },
        {
          name: 'creator',
          label: 'Creator',
          align: 'left',
          field: 'creator'
        },
        {
          name: 'type',
          label: 'Type',
          align: 'left',
          field: 'type'
        },
        {
          name: 'scriptCode',
          label: 'Script Code',
          align: 'left',
          field: 'scriptCode'
        },
        {
          name: 'alias',
          label: 'Alias',
          align: 'left',
          field: 'alias'
        },
        {
          name: 'protected',
          label: 'Protected',
          align: 'left',
          field: 'protected'
        },
        {
          name: 'accessControl',
          label: 'Access Control',
          align: 'left',
          field: 'accessControl'
        },
        {
          name: 'accessibleAttribute',
          label: 'Accessible Attribute',
          align: 'left',
          field: 'accessibleAttribute'
        },
        {
          name: 'entitlementGroup',
          label: 'Entitlement Group',
          align: 'left',
          field: 'entitlementGroup'
        },
        {
          name: 'data',
          label: 'Data',
          align: 'left',
          field: 'data'
        },
        {
          name: 'generic',
          label: 'Generic',
          align: 'left',
          field: 'generic'
        },
        {
          name: 'service',
          label: 'Service',
          align: 'left',
          field: 'service'
        },
        {
          name: 'account',
          label: 'Account',
          align: 'left',
          field: 'account'
        },
        {
          name: 'label',
          label: 'Label',
          align: 'left',
          field: 'label'
        },
        {
          name: 'invisble',
          label: 'Invisble',
          align: 'left',
          field: 'invisble'
        },
        {
          name: 'negative',
          label: 'Negative',
          align: 'left',
          field: 'negative'
        },
        {
          name: 'customIcon',
          label: 'Custom Icon',
          align: 'left',
          field: 'customIcon'
        }
      ]
    }
  }
}
</script>

<style scoped>

</style>
