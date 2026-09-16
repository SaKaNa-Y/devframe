<script setup lang="ts">
// Fallback for hosts that don't apply the /chat redirect from vercel.json (e.g. local dev).
const DISCORD_INVITE_URL = 'https://discord.com/invite/bnH3KPzfpr'

definePageMeta({
  layout: false,
})

useRobotsRule('noindex, nofollow')

onMounted(() => {
  window.location.replace(DISCORD_INVITE_URL)
})
</script>

<template>
  <div />
</template>
