<template>
  <IpRelationshipGraph expanded canvas-only />
</template>

<script>
import IpRelationshipGraph from "../../components/IpRelationshipGraph.vue";

export default {
  name: "NodeMapDashboardView",
  components: { IpRelationshipGraph },
};
</script>
