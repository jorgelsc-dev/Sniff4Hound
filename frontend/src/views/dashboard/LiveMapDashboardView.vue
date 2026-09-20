<template>
  <MapPanel
    canvas-only
    immersive
    :show-panel-header="false"
    :show-intro="false"
    show-projection-switch
    default-projection="flat"
  />
</template>

<script>
import MapPanel from "../../components/MapPanel.vue";

export default {
  name: "LiveMapDashboardView",
  components: { MapPanel },
};
</script>
