<template>
  <q-banner inline-actions rounded class="q-mb-sm bg-negative text-white">
    {{message}}
  </q-banner>
</template>

<script>
export default {
  name: 'message',
  props: {
    message: String
  },
  mounted () {
  }
}
</script>

<style scoped>

</style>
