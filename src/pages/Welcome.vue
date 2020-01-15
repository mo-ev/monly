<template>
  <q-page class="q-pa-md row items-start q-gutter-md flex-center bg-grey-10 text-white">
    <q-btn color="primary" icon="dns" label="Analysis" :to="{ path: '/scans' }" />
    <q-btn color="secondary" icon-right="category" label="Monitoring" :to="{ path: '/devices' }" />
  </q-page>
</template>

<script>
export default {
  name: 'Welcome'
}
</script>

<style scoped>

</style>
