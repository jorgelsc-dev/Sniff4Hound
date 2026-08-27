<template>
  <v-menu
    v-model="open"
    location="bottom end"
    :close-on-content-click="false"
    max-width="420"
  >
    <template #activator="{ props: menuProps }">
      <v-btn
        icon
        variant="text"
        size="small"
        class="chat-trigger"
        aria-label="Operator chat"
        v-bind="menuProps"
      >
        <v-badge
          :model-value="unread > 0"
          :content="unread > 99 ? '99+' : unread"
          color="info"
          floating
          offset-x="2"
          offset-y="2"
        >
          <v-icon icon="mdi-forum-outline" size="22" />
        </v-badge>
        <v-tooltip activator="parent" location="bottom">Operator chat</v-tooltip>
      </v-btn>
    </template>

    <v-card class="chat-menu" rounded="lg">
      <div class="chat-menu-header">
        <span class="text-subtitle-2">Operator chat</span>
        <span class="text-caption text-medium-emphasis">
          Shared with the <code>sniff4hound&gt;</code> terminal
        </span>
      </div>

      <div ref="log" class="chat-log">
        <div v-if="loading && !messages.length" class="chat-empty text-medium-emphasis">Loading…</div>
        <div v-else-if="!messages.length" class="chat-empty text-medium-emphasis">
          No messages yet. Anything typed here shows up in the terminal, and plain text typed at the
          <code>sniff4hound&gt;</code> prompt shows up here.
        </div>
        <div
          v-for="message in messages"
          :key="message.id"
          class="chat-row"
          :class="{ 'chat-row--self': message.author === 'dashboard' }"
        >
          <div class="chat-bubble">
            <div class="chat-meta">
              <span class="chat-author">{{ message.author }}</span>
              <span class="chat-time">{{ formatTimestamp(message.created_at) }}</span>
            </div>
            <div class="chat-content">{{ message.content }}</div>
          </div>
        </div>
      </div>

      <v-alert v-if="error" type="error" variant="tonal" density="compact" class="mx-3 mb-2">
        {{ error }}
      </v-alert>

      <div class="chat-compose">
        <v-text-field
          v-model.trim="draft"
          placeholder="Message the terminal…"
          density="compact"
          variant="outlined"
          hide-details
          maxlength="2000"
          :disabled="sending"
          @keyup.enter="send"
        />
        <v-btn
          icon
          size="small"
          variant="tonal"
          color="primary"
          :loading="sending"
          :disabled="!draft"
          aria-label="Send message"
          @click="send"
        >
          <v-icon icon="mdi-send" />
        </v-btn>
      </div>
    </v-card>
  </v-menu>
</template>

<script>
import store from "../../state/appStore";
import { formatTimestamp } from "../../utils/traffic";

export default {
  name: "OperatorChat",
  data() {
    return {
      store,
      open: false,
      messages: [],
      draft: "",
      sending: false,
      loading: false,
      error: "",
      unread: 0,
    };
  },
  computed: {
    // Same gate initRuntime() uses: the security code lives in tab memory and
    // is not there yet on first paint, so calling the API from mounted()
    // produced a 401 in the console on every load.
    canLoad() {
      return !this.store.authRequired || this.store.authStatus === "authenticated";
    },
  },
  watch: {
    open(value) {
      if (!value) return;
      this.unread = 0;
      this.load();
    },
    canLoad(ready) {
      if (ready) this.load();
    },
    // The websocket pushes every chat message into the store; mirroring off
    // that counter is what keeps this in sync without a second poll loop.
    "store.chatRevision"() {
      if (this.open) {
        this.load();
      } else {
        this.unread += 1;
      }
    },
  },
  mounted() {
    this.load();
  },
  methods: {
    formatTimestamp,
    load() {
      if (!this.canLoad) return;
      this.loading = true;
      this.store
        .listChatMessages()
        .then((rows) => {
          // The API returns newest-first; the log reads oldest-first.
          this.messages = Array.isArray(rows) ? [...rows].reverse() : [];
          this.$nextTick(this.scrollToEnd);
        })
        .catch((err) => {
          this.error = (err && err.message) || "Failed to load the chat";
        })
        .finally(() => {
          this.loading = false;
        });
    },
    send() {
      const content = String(this.draft || "").trim();
      if (!content || this.sending || !this.canLoad) return;
      this.sending = true;
      this.error = "";
      this.store
        .postChatMessage(content)
        .then(() => {
          this.draft = "";
          this.load();
        })
        .catch((err) => {
          this.error = (err && err.message) || "Failed to send";
        })
        .finally(() => {
          this.sending = false;
        });
    },
    scrollToEnd() {
      const log = this.$refs.log;
      if (log) log.scrollTop = log.scrollHeight;
    },
  },
};
</script>

<style scoped>
.chat-menu {
  width: 420px;
  max-width: 92vw;
  background: linear-gradient(180deg, rgba(7, 14, 24, 0.98), rgba(4, 10, 18, 0.98));
  border: 1px solid rgba(var(--brand-sky-rgb), 0.2);
}

.chat-menu-header {
  display: flex;
  flex-direction: column;
  gap: 2px;
  padding: 12px 16px 8px;
  border-bottom: 1px solid rgba(var(--brand-sky-rgb), 0.14);
}

.chat-log {
  max-height: 320px;
  overflow-y: auto;
  padding: 10px 12px;
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.chat-empty {
  padding: 18px 6px;
  font-size: 0.8rem;
  line-height: 1.5;
}

.chat-row {
  display: flex;
  justify-content: flex-start;
}

/* Messages posted from this dashboard sit on the right, the terminal's on the
   left, so a two-party conversation is readable at a glance. */
.chat-row--self {
  justify-content: flex-end;
}

.chat-bubble {
  max-width: 82%;
  padding: 6px 10px;
  border-radius: 10px;
  background: rgba(var(--brand-sky-rgb), 0.1);
  border: 1px solid rgba(var(--brand-sky-rgb), 0.16);
}

.chat-row--self .chat-bubble {
  background: rgba(var(--brand-cyan-rgb), 0.12);
  border-color: rgba(var(--brand-cyan-rgb), 0.28);
}

.chat-meta {
  display: flex;
  gap: 8px;
  align-items: baseline;
  font-size: 0.65rem;
  color: rgba(255, 255, 255, 0.5);
}

.chat-author {
  text-transform: uppercase;
  letter-spacing: 0.06em;
}

.chat-content {
  font-size: 0.85rem;
  line-height: 1.4;
  white-space: pre-wrap;
  word-break: break-word;
}

.chat-compose {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 10px 12px 12px;
  border-top: 1px solid rgba(var(--brand-sky-rgb), 0.14);
}
</style>
