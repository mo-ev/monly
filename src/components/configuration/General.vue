<template>
  <div v-if="item" class="column">
    <div class="text-h6">Name</div>
    {{item.name}}
    <div class="text-h6">Identifier</div>
    {{item.bundleIdentifier}}
    <div class="text-h6">Bundle</div>
    {{item.bundle}}
    <div class="text-h6">Binary</div>
    {{item.binary}}
    <div class="text-h6">Data</div>
    {{item.data}}
    <div class="text-h6">Version</div>
    {{item.version}}
  </div>
</template>

<script>
export default {
  name: 'general',
  props: {
    item: Object
  }
}
</script>

<style scoped>

</style>
