<template>
  <v-navigation-drawer v-model="localOpen" temporary class="d-md-none mobile-drawer">
    <v-list nav density="compact">
      <template v-for="item in navItems" :key="item.to || item.label">
        <v-list-group v-if="item.children" :value="item.label">
          <template #activator="{ props: groupProps }">
            <v-list-item v-bind="groupProps" :prepend-icon="item.icon" :title="item.label" />
          </template>
          <v-list-item
            v-for="child in item.children"
            :key="child.to"
            :to="child.to"
            :prepend-icon="child.icon"
            :title="child.label"
            @click="closeDrawer"
          />
        </v-list-group>
        <v-list-item v-else :to="item.to" @click="closeDrawer">
          <template #prepend>
            <v-icon :icon="item.icon" />
          </template>
          <v-list-item-title>{{ item.label }}</v-list-item-title>
        </v-list-item>
      </template>
    </v-list>
  </v-navigation-drawer>
</template>

<script>
export default {
  name: "AppSidebar",
  props: {
    open: {
      type: Boolean,
      default: false,
    },
    navItems: {
      type: Array,
      default: () => [],
    },
  },
  emits: ["update:open"],
  computed: {
    localOpen: {
      get() {
        return this.open;
      },
      set(value) {
        this.$emit("update:open", value);
      },
    },
  },
  methods: {
    closeDrawer() {
      this.$emit("update:open", false);
    },
  },
};
</script>

<style scoped>
.mobile-drawer {
  border-right: 1px solid rgba(102, 212, 255, 0.18);
  background: linear-gradient(180deg, rgba(8, 13, 21, 0.98), rgba(6, 10, 16, 0.98));
  backdrop-filter: blur(18px) saturate(120%);
}

.mobile-drawer :deep(.v-list) {
  padding-top: 16px;
}

.mobile-drawer :deep(.v-list-item) {
  margin: 4px 12px;
  border-radius: 12px;
}

.mobile-drawer :deep(.v-list-item--active) {
  background: rgba(52, 230, 255, 0.12);
}
</style>
