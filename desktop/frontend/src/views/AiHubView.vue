<template>
  <div>
    <ViewHeader
      overline="IA"
      title="Inteligencia local"
      description="Choose a focused view instead of one crowded page - each one opens on its own, full width."
      :show-refresh="false"
    />

    <v-row density="compact">
      <v-col v-for="item in pages" :key="item.to" cols="12" sm="6" lg="4">
        <router-link :to="item.to" class="ai-hub-card-link">
          <v-card variant="tonal" class="pa-5 ai-hub-card" rounded="lg" hover>
            <div class="ai-hub-card__icon" :class="`text-${item.color}`">
              <v-icon :icon="item.icon" size="26" />
            </div>
            <div class="text-subtitle-1 font-weight-bold mt-3">{{ item.title }}</div>
            <div class="text-body-2 text-medium-emphasis mt-1">{{ item.description }}</div>
          </v-card>
        </router-link>
      </v-col>
    </v-row>
  </div>
</template>

<script>
import ViewHeader from "../components/ui/ViewHeader.vue";

export default {
  name: "AiHubView",
  components: {
    ViewHeader,
  },
  data() {
    return {
      pages: [
        {
          to: "/ai/overview",
          title: "Resumen",
          description: "LOF anomaly gallery, packet review and engine tuning.",
          icon: "mdi-clipboard-pulse-outline",
          color: "primary",
        },
        {
          to: "/ai/neural-network",
          title: "RNN Red Neuronal",
          description: "Live, animated view of the neural network's real weights and activations.",
          icon: "mdi-hub-outline",
          color: "secondary",
        },
      ],
    };
  },
};
</script>

<style scoped>
.ai-hub-card-link {
  display: block;
  height: 100%;
  text-decoration: none;
  color: inherit;
}

.ai-hub-card {
  height: 100%;
  transition: transform 0.16s ease, border-color 0.16s ease;
}

.ai-hub-card:hover {
  transform: translateY(-2px);
}

.ai-hub-card__icon {
  width: 46px;
  height: 46px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  border-radius: 12px;
  background: rgba(255, 255, 255, 0.06);
}
</style>
