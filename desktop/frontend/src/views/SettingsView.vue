<template>
  <div class="settings-view">
    <ConfigGraphNav v-model="activeTab" :states="graphStates" :refreshing="statusRefreshing" @refresh="refreshGraph">
    <v-window :model-value="activeTab" :touch="false">
      <v-window-item value="runtime">
        <div class="settings-engine-list">
          <div v-for="engine in ['sniffer', 'honeypot']" :key="engine" class="settings-engine">
            <div>
              <h3>{{ engine === 'sniffer' ? 'Sniffer' : 'Honeypot' }}</h3>
              <span>{{ runtime[engine]?.running ? 'En ejecución' : 'Detenido' }}</span>
            </div>
            <v-switch
              :model-value="Boolean(runtime[engine]?.running)"
              :aria-label="'Activar ' + engine"
              :loading="enginePending === engine"
              :disabled="Boolean(enginePending) || store.state.wsStatus !== 'online'"
              color="success"
              hide-details
              inset
              @update:model-value="toggleEngine(engine, $event)"
            />
          </div>
        </div>
        <v-alert v-if="engineError" type="error" variant="tonal" class="mt-4">{{ engineError }}</v-alert>
      </v-window-item>

      <v-window-item value="capture">
        <DataPanel
          title="Interfaces de captura"
          subtitle="Selecciona una o varias interfaces de escucha. Déjalo vacío para capturar en todas las interfaces visibles."
          variant="tonal"
          :count="selectedSnifferInterfaces.length || snifferInterfaceOptions.length"
          count-label="interfaces"
          class="mb-4 interface-card"
        >
          <template #header-actions>
            <v-chip
              size="small"
              :color="snifferBlocked ? 'error' : 'info'"
              variant="outlined"
              :prepend-icon="snifferBlocked ? 'mdi-alert-circle-outline' : 'mdi-lan-check'"
            >
              {{ selectedInterfacesLabel }}
            </v-chip>
          </template>

          <v-row density="compact" class="mt-2">
            <v-col cols="12" md="8">
              <v-select
                :model-value="selectedSnifferInterfaces"
                :items="snifferInterfaceOptions"
                label="Interfaces"
                item-title="label"
                item-value="value"
                variant="outlined"
                density="comfortable"
                hide-details="auto"
                multiple
                chips
                clearable
                closable-chips
                :loading="interfaceSubmitting"
                :disabled="!snifferInterfaceOptions.length"
                :error-messages="interfaceError ? [interfaceError] : []"
                @update:model-value="updateSnifferInterfaces"
              />
            </v-col>
            <v-col cols="12" md="4">
              <div class="interface-status">
                {{ snifferInterfaceStatus }}
              </div>
              <div class="text-caption text-medium-emphasis mt-2">
                {{ snifferInterfaceHint }}
              </div>
            </v-col>
          </v-row>
        </DataPanel>

      </v-window-item>
      <v-window-item value="scope">
        <DataPanel
          title="Alcance de detección"
          subtitle="Silencia detecciones para el tráfico que permanece completamente dentro de los ámbitos elegidos. Los paquetes excluidos siguen visibles en captura, pero no se clasifican, etiquetan por reglas, pasan por monitores ni se envían a detectores de anomalías."
          variant="tonal"
          class="mb-4 scope-card"
        >
          <template #header-actions>
            <v-chip
              size="small"
              :color="detectionScopes.length ? 'warning' : 'success'"
              variant="tonal"
              :prepend-icon="detectionScopes.length ? 'mdi-filter-off-outline' : 'mdi-filter-check-outline'"
            >
              {{ detectionScopes.length ? `${detectionScopes.length} silenciados` : "Detectando todo" }}
            </v-chip>
          </template>

          <v-row density="compact" class="mt-1" align="start">
            <v-col cols="12" md="7">
              <div class="d-flex flex-wrap ga-2">
                <v-checkbox
                  v-for="scope in detectionScopeOptions"
                  :key="scope.value"
                  :model-value="detectionScopes.includes(scope.value)"
                  :label="scope.label"
                  :disabled="detectionScopesSubmitting"
                  color="warning"
                  density="comfortable"
                  hide-details
                  class="scope-check"
                  @update:model-value="toggleDetectionScope(scope.value, $event)"
                />
              </div>
              <div class="text-caption text-medium-emphasis mt-2">
                Ambos extremos deben quedar dentro de un ámbito excluido. El tráfico desde un host
                privado hacia una dirección pública sigue capturándose y analizándose.
              </div>
            </v-col>
            <v-col cols="12" md="5">
              <div class="interface-status">{{ detectionScopeStatus }}</div>
              <div class="text-caption text-medium-emphasis mt-2">
                Deja todas las casillas vacías para detectar en todo el tráfico.
              </div>
            </v-col>
          </v-row>

          <v-alert v-if="detectionScopesError" type="error" variant="tonal" density="comfortable" class="mt-3">
            {{ detectionScopesError }}
          </v-alert>
        </DataPanel>

      </v-window-item>
      <v-window-item value="location">
        <DataPanel
          title="Ubicación del sensor"
          subtitle="Dónde está físicamente esta máquina. Las direcciones privadas y loopback no tienen geolocalización propia, así que el mapa Radar las ubica en este punto. Las direcciones públicas conservan su propia ubicación, resuelta desde bloques de registro."
          variant="tonal"
          class="mb-4 location-card"
        >
          <template #header-actions>
            <v-chip
              size="small"
              :color="locationConfigured ? 'success' : 'secondary'"
              variant="tonal"
              :prepend-icon="locationConfigured ? 'mdi-map-marker-check' : 'mdi-map-marker-off'"
            >
              {{ locationConfigured ? locationSummary : "Sin configurar" }}
            </v-chip>
          </template>

          <div class="text-caption text-medium-emphasis mb-2">
            Haz clic en el mapa para colocar el marcador, o escribe las coordenadas.
          </div>

          <LocationPicker
            :lat="locationDraft.lat"
            :lon="locationDraft.lon"
            :label="locationDraft.label"
            @update:lat="locationDraft.lat = $event"
            @update:lon="locationDraft.lon = $event"
            @update:label="locationDraft.label = $event"
          />

          <div class="d-flex flex-wrap justify-end ga-2 mt-3">
            <v-btn
              size="small"
              variant="text"
              color="secondary"
              :disabled="locationSubmitting || !locationConfigured"
              @click="clearLocation"
            >
              Borrar
            </v-btn>
            <v-btn
              size="small"
              variant="flat"
              color="primary"
              :loading="locationSubmitting"
              :disabled="!locationDirty || !locationDraftValid"
              @click="saveLocation"
            >
              Guardar ubicación
            </v-btn>
          </div>

          <v-alert v-if="locationError" type="error" variant="tonal" density="comfortable" class="mt-3">
            {{ locationError }}
          </v-alert>
        </DataPanel>

      </v-window-item>
      <v-window-item value="storage">
        <!-- Database file stats -->
        <DataPanel
          title="Base de datos"
          subtitle="Tamaño y estado del archivo SQLite. Compactar libera las páginas acumuladas entre podas sin eliminar ningún dato."
          variant="tonal"
          class="mb-4 storage-card"
        >
          <template #header-actions>
            <v-chip
              size="small"
              :color="storageStats ? 'primary' : 'secondary'"
              variant="tonal"
              prepend-icon="mdi-database"
            >
              {{ storageStats ? formatDbBytes(storageStats.live_bytes) + ' datos vivos' : 'Cargando…' }}
            </v-chip>
          </template>

          <v-row density="compact" align="start" class="mt-1">
            <v-col cols="12" md="8">
              <div v-if="storageStats" class="storage-detail">
                <div class="storage-path mono text-caption text-medium-emphasis mb-3">
                  {{ storageStats.path }}
                </div>

                <div class="text-caption text-medium-emphasis mb-1">
                  Uso del archivo
                </div>
                <v-progress-linear
                  :model-value="storageStats.file_bytes ? Math.round((storageStats.live_bytes / storageStats.file_bytes) * 100) : 0"
                  color="primary"
                  bg-color="rgba(255,255,255,0.08)"
                  rounded
                  height="10"
                  class="mb-2"
                />
                <div class="d-flex flex-wrap ga-2 justify-space-between text-caption text-medium-emphasis mb-3">
                  <span>{{ formatDbBytes(storageStats.live_bytes) }} datos</span>
                  <span>{{ formatDbBytes(storageStats.free_bytes) }} libres</span>
                  <span>{{ formatDbBytes(storageStats.file_bytes) }} total</span>
                </div>

                <v-alert
                  v-if="storageStats && !storageStats.incremental_reclaim"
                  type="warning"
                  variant="tonal"
                  density="comfortable"
                  class="mb-3"
                  prepend-icon="mdi-database-alert"
                >
                  Este archivo no tiene <code>auto_vacuum=INCREMENTAL</code>. Las podas periódicas no reducen el tamaño en disco. Compactar lo migra y activa la recuperación automática.
                </v-alert>

                <div class="d-flex flex-wrap ga-2">
                  <v-btn
                    size="small"
                    variant="tonal"
                    color="primary"
                    prepend-icon="mdi-database-arrow-down"
                    :loading="compacting"
                    :disabled="compacting"
                    @click="openCompact"
                  >
                    Compactar
                  </v-btn>
                  <v-btn
                    size="small"
                    variant="text"
                    prepend-icon="mdi-refresh"
                    :loading="storageLoading"
                    @click="loadStorageStats"
                  >
                    Actualizar
                  </v-btn>
                </div>

                <v-alert v-if="compactResult" type="success" variant="tonal" density="comfortable" class="mt-3">
                  {{ compactResult }}
                </v-alert>
                <v-alert v-if="storageError" type="error" variant="tonal" density="comfortable" class="mt-3">
                  {{ storageError }}
                </v-alert>
              </div>
              <div v-else-if="storageLoading" class="text-caption text-medium-emphasis">Cargando estadísticas…</div>
              <div v-else class="text-caption text-medium-emphasis">Sin datos de almacenamiento.</div>
            </v-col>
            <v-col cols="12" md="4">
              <div class="storage-stat-grid">
                <template v-if="storageStats">
                  <div class="storage-stat-item">
                    <div class="text-caption text-medium-emphasis">Tamaño de página</div>
                    <div class="text-body-2 font-weight-medium">{{ storageStats.page_size }} B</div>
                  </div>
                  <div class="storage-stat-item">
                    <div class="text-caption text-medium-emphasis">Páginas totales</div>
                    <div class="text-body-2 font-weight-medium">{{ (storageStats.page_count || 0).toLocaleString() }}</div>
                  </div>
                  <div class="storage-stat-item">
                    <div class="text-caption text-medium-emphasis">Páginas libres</div>
                    <div class="text-body-2 font-weight-medium">{{ (storageStats.freelist_count || 0).toLocaleString() }}</div>
                  </div>
                  <div class="storage-stat-item">
                    <div class="text-caption text-medium-emphasis">Recuperación incremental</div>
                    <div class="text-body-2 font-weight-medium">
                      <v-chip size="x-small" :color="storageStats.incremental_reclaim ? 'success' : 'warning'" variant="tonal">
                        {{ storageStats.incremental_reclaim ? 'Activa' : 'Inactiva' }}
                      </v-chip>
                    </div>
                  </div>
                </template>
              </div>
            </v-col>
          </v-row>
        </DataPanel>

        <!-- Compact confirmation dialog -->
        <v-dialog v-model="compactDialog" max-width="460">
          <v-card class="pa-4">
            <div class="text-h6 mb-3">¿Compactar la base de datos?</div>
            <div class="text-caption text-medium-emphasis mb-3">
              Reescribe el archivo SQLite recuperando todas las páginas libres y activa la recuperación automática incremental. La captura se pausa brevemente durante la reescritura. No elimina ningún dato.
            </div>
            <div class="d-flex flex-wrap justify-end ga-2">
              <v-btn variant="text" @click="compactDialog = false">Cancelar</v-btn>
              <v-btn color="primary" variant="flat" :loading="compacting" @click="confirmCompact">
                Compactar
              </v-btn>
            </div>
          </v-card>
        </v-dialog>

        <!-- Retention policy -->
        <DataPanel
          title="Política de retención"
          subtitle="Editable. Se guarda en la base y se aplica en el siguiente barrido, sin reiniciar. Sin valor propio, cada campo usa su variable de entorno SNIFF4HOUND_*."
          variant="tonal"
          class="mb-4 retention-card"
        >
          <template #header-actions>
            <v-chip
              v-if="retentionConfig"
              size="small"
              color="info"
              variant="tonal"
              prepend-icon="mdi-clock-outline"
            >
              {{ retentionConfig.retention_days }}d general · {{ retentionConfig.retention_alert_days }}d alertas
            </v-chip>
          </template>

          <v-row v-if="retentionConfig && retentionDraft" density="compact" class="mt-2">
            <v-col cols="12" class="pb-1">
              <div class="text-caption font-weight-medium text-medium-emphasis mb-2 text-uppercase" style="letter-spacing:.06em">Política temporal (primaria)</div>
            </v-col>
            <v-col cols="12" sm="6" md="4">
              <v-text-field
                v-model.number="retentionDraft.retention_days"
                label="Ventana general"
                type="number"
                min="0"
                max="3650"
                suffix="días"
                variant="outlined"
                density="compact"
                :disabled="retentionSaving"
                :hint="retentionFieldHint('retention_days', 'SNIFF4HOUND_RETENTION_DAYS')"
                persistent-hint
              />
            </v-col>
            <v-col cols="12" sm="6" md="4">
              <v-text-field
                v-model.number="retentionDraft.retention_alert_days"
                label="Alertas high/critical"
                type="number"
                min="0"
                max="3650"
                suffix="días"
                variant="outlined"
                density="compact"
                :disabled="retentionSaving"
                :hint="retentionFieldHint('retention_alert_days', 'SNIFF4HOUND_RETENTION_ALERT_DAYS')"
                persistent-hint
              />
            </v-col>
            <v-col cols="12" sm="6" md="4">
              <v-text-field
                v-model.number="retentionDraft.retention_interval_seconds"
                label="Intervalo de barrido"
                type="number"
                min="5"
                max="86400"
                suffix="s"
                variant="outlined"
                density="compact"
                :disabled="retentionSaving"
                :hint="retentionFieldHint('retention_interval_seconds', 'SNIFF4HOUND_RETENTION_INTERVAL_SECONDS')"
                persistent-hint
              />
            </v-col>

            <v-col cols="12" class="pb-1 mt-3">
              <div class="text-caption font-weight-medium text-medium-emphasis mb-2 text-uppercase" style="letter-spacing:.06em">Topes de filas (freno ante picos)</div>
            </v-col>
            <v-col cols="12" sm="6" md="4">
              <v-text-field
                v-model.number="retentionDraft.retention_max_packets"
                label="Base de paquetes"
                type="number"
                min="1000"
                step="1000"
                variant="outlined"
                density="compact"
                :disabled="retentionSaving"
                :hint="retentionFieldHint('retention_max_packets', 'SNIFF4HOUND_RETENTION_MAX_PACKETS')"
                persistent-hint
              />
            </v-col>
            <v-col cols="12">
              <v-table density="compact" class="retention-table rounded-lg">
                <thead>
                  <tr>
                    <th>Tabla</th>
                    <th>Límite de filas</th>
                    <th>Origen</th>
                    <th class="text-right">Acción</th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="table in retentionTables" :key="table">
                    <td class="mono">{{ table }}</td>
                    <td class="retention-table__input">
                      <v-text-field
                        v-model.number="retentionDraft.table_limits[table]"
                        type="number"
                        min="100"
                        max="5000000"
                        variant="underlined"
                        density="compact"
                        hide-details
                        :disabled="retentionSaving"
                        aria-label="Límite de filas"
                      />
                    </td>
                    <td class="text-caption text-medium-emphasis">{{ retentionTableOrigin(table) }}</td>
                    <td class="text-right">
                      <v-btn
                        v-if="retentionOverridden(`limit_${table}`)"
                        size="x-small"
                        variant="text"
                        :disabled="retentionSaving"
                        @click="clearRetentionOverride({ table })"
                      >Restablecer</v-btn>
                    </td>
                  </tr>
                </tbody>
              </v-table>
            </v-col>
            <v-col cols="12">
              <v-alert v-if="retentionError" type="error" variant="tonal" density="comfortable" class="mb-3">{{ retentionError }}</v-alert>
              <v-alert v-if="retentionSaved" type="success" variant="tonal" density="comfortable" class="mb-3">Política guardada. Se aplica en el siguiente barrido.</v-alert>
              <div class="d-flex flex-wrap justify-end ga-2">
                <v-btn variant="text" :disabled="retentionSaving || !retentionOverriddenAny" @click="clearRetentionOverride({})">Restablecer todo</v-btn>
                <v-btn color="primary" variant="tonal" :loading="retentionSaving" :disabled="retentionSaving || !retentionDirty" @click="saveRetentionConfig">Guardar política</v-btn>
              </div>
            </v-col>
          </v-row>
          <div v-else-if="retentionLoading" class="text-caption text-medium-emphasis">Cargando política…</div>
          <div v-else class="text-caption text-medium-emphasis">Sin datos de retención.</div>
        </DataPanel>

        <!-- Purge -->
        <DataPanel
          title="Datos almacenados"
          subtitle="Elimina lo que captura y el honeypot han escrito. Definiciones de monitores, listeners, listas de acceso y configuración nunca se tocan."
          variant="tonal"
          class="mb-4 purge-card"
        >
          <v-row density="compact" align="center">
            <v-col cols="12" md="8">
              <div class="text-body-2">
                <strong>Historial de detección</strong> elimina paquetes, etiquetas y payloads almacenados.
                <strong>Todo</strong> también borra flows, dominios, paths y sesiones, y luego compacta el archivo en disco.
              </div>
            </v-col>
            <v-col cols="12" md="4" class="d-flex justify-md-end ga-2 flex-wrap">
              <v-btn
                size="small"
                variant="tonal"
                color="warning"
                :disabled="purging"
                @click="openPurge('all')"
              >
                Historial de detección
              </v-btn>
              <v-btn
                size="small"
                variant="tonal"
                color="error"
                :disabled="purging"
                @click="openPurge('everything')"
              >
                Todo
              </v-btn>
            </v-col>
          </v-row>

          <v-alert v-if="purgeResult" type="success" variant="tonal" density="comfortable" class="mt-3">
            {{ purgeResult }}
          </v-alert>
          <v-alert v-if="purgeError" type="error" variant="tonal" density="comfortable" class="mt-3">
            {{ purgeError }}
          </v-alert>
        </DataPanel>

        <v-dialog v-model="purgeDialog" max-width="460">
          <v-card class="pa-4">
            <div class="text-h6 mb-3">
              {{ purgeScope === "everything" ? "¿Eliminar todos los datos de captura?" : "¿Limpiar el historial de detección?" }}
            </div>
            <div class="text-caption text-medium-emphasis mb-3">
              <template v-if="purgeScope === 'everything'">
                Elimina todos los paquetes, etiquetas, payloads, flows, dominios, paths y sesiones, y luego compacta el archivo. Monitores, listeners, listas de acceso y configuración sobreviven. No se puede deshacer.
              </template>
              <template v-else>
                Elimina paquetes, etiquetas y payloads almacenados. Flows, dominios, paths y sesiones se conservan. No se puede deshacer.
              </template>
            </div>
            <div class="d-flex flex-wrap justify-end ga-2">
              <v-btn variant="text" @click="purgeDialog = false">Cancelar</v-btn>
              <v-btn color="error" variant="flat" :loading="purging" @click="confirmPurge">
                {{ purgeScope === "everything" ? "Eliminar todo" : "Limpiar historial" }}
              </v-btn>
            </div>
          </v-card>
        </v-dialog>

      </v-window-item>

      <v-window-item value="honeypot">
        <DataPanel
          title="Listeners"
          subtitle="Habilita o deshabilita listeners individuales. Un listener creado no puede editarse ni eliminarse, solo encenderse o apagarse, para conservar el registro de lo que estuvo expuesto."
          variant="tonal"
          :count="listeners.length"
          count-label="listeners"
          :error="listenersError"
          class="mb-4 listeners-card"
        >
          <template #header-actions>
            <v-btn size="small" color="primary" variant="outlined" prepend-icon="mdi-plus" @click="openNewListenerDialog">
              Nuevo listener
            </v-btn>
          </template>

          <v-text-field
            v-model.trim="listenerSearch"
            label="Buscar listeners"
            placeholder="protocolo, puerto, etiqueta, origen..."
            prepend-inner-icon="mdi-magnify"
            clearable
            variant="outlined"
            density="comfortable"
            class="mb-3"
            hide-details
          />

          <v-data-table
            :headers="listenerHeaders"
            :items="listeners"
            :search="listenerSearch"
            :custom-filter="filterListenerRows"
            density="comfortable"
            items-per-page="10"
            no-data-text="Todavía no hay listeners."
            class="listeners-table"
          >
            <template v-slot:[`item.endpoint`]="{ item }">
              <span class="mono">{{ String(item.proto || "").toUpperCase() }}/{{ item.port }}</span>
            </template>
            <template v-slot:[`item.label`]="{ item }">
              {{ item.label || "-" }}
            </template>
            <template v-slot:[`item.source`]="{ item }">
              <v-chip size="x-small" :color="item.source === 'builtin' ? 'secondary' : 'info'" variant="tonal">
                {{ sourceLabel(item.source) }}
              </v-chip>
            </template>
            <template v-slot:[`item.running`]="{ item }">
              <v-chip
                size="x-small"
                :color="item.running ? 'success' : 'secondary'"
                variant="tonal"
                :prepend-icon="item.running ? 'mdi-check-circle-outline' : 'mdi-close-circle-outline'"
              >
                {{ item.running ? "En ejecución" : "Detenido" }}
              </v-chip>
            </template>
            <template v-slot:[`item.enabled`]="{ item }">
              <v-switch
                :model-value="item.enabled"
                :loading="listenerTogglePending === item.id"
                :disabled="Boolean(listenerTogglePending)"
                density="compact"
                hide-details
                color="success"
                @update:model-value="(value) => toggleListener(item, value)"
              />
            </template>
          </v-data-table>
        </DataPanel>

        <v-dialog v-model="newListenerDialog" max-width="420">
          <v-card class="pa-4">
            <div class="text-h6 mb-3">Nuevo listener</div>
            <div class="text-caption text-medium-emphasis mb-3">
              Podrás habilitarlo o deshabilitarlo más tarde, pero no editarlo ni eliminarlo.
              Revisa el protocolo y el puerto antes de crearlo.
            </div>
            <v-select
              v-model="newListener.proto"
              :items="['tcp', 'udp']"
              label="Protocolo"
              variant="outlined"
              density="comfortable"
            />
            <v-text-field
              v-model.number="newListener.port"
              label="Puerto"
              type="number"
              variant="outlined"
              density="comfortable"
              :min="1"
              :max="65535"
            />
            <v-text-field
              v-model.trim="newListener.label"
              label="Etiqueta (opcional)"
              variant="outlined"
              density="comfortable"
            />
            <v-alert v-if="newListenerError" type="error" variant="tonal" density="comfortable" class="mb-3">
              {{ newListenerError }}
            </v-alert>
            <div class="d-flex flex-wrap justify-end ga-2">
              <v-btn variant="text" @click="newListenerDialog = false">Cancelar</v-btn>
              <v-btn color="primary" variant="flat" :loading="newListenerSubmitting" @click="createListener">
                Crear
              </v-btn>
            </div>
          </v-card>
        </v-dialog>
      </v-window-item>

      <v-window-item value="detection">
        <v-alert v-if="error" type="error" variant="tonal" class="mb-4">
          {{ error }}
        </v-alert>
        <v-alert v-if="configError" type="error" variant="tonal" class="mb-4">
          {{ configError }}
        </v-alert>

        <v-card variant="tonal" class="pa-4 mb-4 filter-card">
          <div class="d-flex align-start justify-space-between flex-wrap ga-3">
            <div>
              <div class="text-subtitle-2 font-weight-medium">Guardar solo tráfico detectado</div>
              <div class="text-caption text-medium-emphasis mt-1">
                Controla si se ejecuta el catálogo de reglas de monitores. Cuando está activo
                (recomendado), los paquetes se evalúan contra tus monitores: las coincidencias se
                guardan como alertas y el resto solo se cuenta en vivo, sin escribirse en SQLite.
                Al desactivarlo no se guarda toda la captura: se omite el catálogo de reglas, así
                que solo los detectores de anomalías pueden disparar almacenamiento.
              </div>
            </div>
            <v-switch
              :model-value="filterEnabled"
              :loading="configSubmitting"
              color="primary"
              hide-details
              inset
              @update:model-value="toggleFilter"
            />
          </div>
          <v-row density="compact" class="mt-3">
            <v-col cols="12" md="6">
              <v-select
                :model-value="monitorMinSeverity"
                :items="monitorSeverityOptions"
                item-title="label"
                item-value="value"
                label="Severidad mínima de monitores"
                variant="outlined"
                density="comfortable"
                hide-details="auto"
                :loading="configSubmitting"
                @update:model-value="updateMonitorMinSeverity"
              />
            </v-col>
            <v-col cols="12" md="6">
              <v-switch
                :model-value="suppressGeneratedInfo"
                label="Silenciar señales generadas info/baja"
                :loading="configSubmitting"
                color="warning"
                hide-details="auto"
                inset
                @update:model-value="toggleGeneratedInfoFilter"
              />
            </v-col>
          </v-row>
        </v-card>

        <div class="d-flex justify-end mb-3">
          <v-btn color="primary" prepend-icon="mdi-plus" @click="openCreateDialog">
            Nuevo monitor
          </v-btn>
        </div>

        <EntityTablePanel
          title="Monitores de detección"
          subtitle="Los monitores integrados pueden habilitarse o deshabilitarse, pero no editarse ni eliminarse. Los personalizados sí pueden editarse o eliminarse. Su tráfico en vivo y gráficas están en la página Monitores."
          :rows="monitors"
          :columns="columns"
          :loading="loading"
          :error="error"
          :last-updated="lastUpdated"
          search-enabled
          search-label="Buscar monitores"
          search-placeholder="Nombre, etiqueta, descripción..."
          :page-size="25"
          empty-text="Todavía no hay monitores definidos"
          @refresh="load"
        >
          <template #cell-mode="{ value }">
            <v-chip size="x-small" :color="modeColor(value)" variant="tonal">
              {{ modeLabel(value) }}
            </v-chip>
          </template>
          <template #cell-severity="{ item }">
            <v-chip size="x-small" :color="severityColor(item.action && item.action.severity)" variant="tonal">
              {{ (item.action && item.action.severity) || "info" }}
            </v-chip>
          </template>
          <template #cell-match_summary="{ item }">
            <span class="match-summary">{{ matchSummary(item) }}</span>
          </template>
          <template #cell-source="{ item }">
            <v-chip size="x-small" :color="item.source === 'builtin' ? 'secondary' : 'success'" variant="tonal">
              {{ item.source === "builtin" ? "Integrado" : "Personalizado" }}
            </v-chip>
          </template>
          <template #cell-enabled="{ item }">
            <v-switch
              :model-value="item.enabled"
              :disabled="isBusy(item.id)"
              color="primary"
              density="compact"
              hide-details
              inset
              @update:model-value="(value) => toggleEnabled(item, value)"
            />
          </template>
          <template #cell-actions="{ item }">
            <div class="row-actions">
              <v-btn
                size="small"
                variant="tonal"
                color="secondary"
                prepend-icon="mdi-file-document-outline"
                @click="openRuleDetail(item)"
              >
                Ver
              </v-btn>
              <v-btn
                v-if="item.source !== 'builtin'"
                size="small"
                variant="tonal"
                color="primary"
                prepend-icon="mdi-pencil"
                :disabled="isBusy(item.id)"
                @click="openEditDialog(item)"
              >
                Editar
              </v-btn>
              <v-btn
                v-if="item.source !== 'builtin'"
                size="small"
                variant="tonal"
                color="error"
                prepend-icon="mdi-delete"
                :loading="isBusy(item.id)"
                @click="removeMonitor(item)"
              >
                Eliminar
              </v-btn>
            </div>
          </template>
        </EntityTablePanel>

        <RuleDetailDialog v-model="ruleDetailOpen" :monitor="ruleDetailMonitor" />

        <v-dialog v-model="dialogOpen" max-width="980">
          <v-card rounded="xl" class="pa-2 monitor-dialog-card">
            <v-card-title class="text-h6">
              {{ editingId ? "Editar monitor" : "Nuevo monitor" }}
            </v-card-title>
            <v-card-text class="monitor-dialog-body">
              <v-alert v-if="formError" type="error" variant="tonal" density="comfortable" class="mb-4">
                {{ formError }}
              </v-alert>

              <v-row density="compact">
                <v-col cols="12" md="8">
                  <v-text-field v-model.trim="form.name" label="Nombre" variant="outlined" density="comfortable" />
                </v-col>
                <v-col cols="12" md="4">
                  <v-text-field
                    v-model.number="form.priority"
                    type="number"
                    label="Prioridad"
                    hint="Los valores bajos se ejecutan primero"
                    persistent-hint
                    variant="outlined"
                    density="comfortable"
                  />
                </v-col>
                <v-col cols="12">
                  <v-text-field
                    v-model.trim="form.description"
                    label="Descripción"
                    variant="outlined"
                    density="comfortable"
                  />
                </v-col>
                <v-col cols="12" sm="6">
                  <v-select
                    v-model="form.severity"
                    :items="severityOptions"
                    label="Severidad"
                    variant="outlined"
                    density="comfortable"
                  />
                </v-col>
                <v-col cols="12" sm="6">
                  <v-text-field
                    v-model.trim="form.tag"
                    label="Etiqueta"
                    hint="Etiqueta breve asociada a los paquetes guardados"
                    persistent-hint
                    variant="outlined"
                    density="comfortable"
                  />
                </v-col>
              </v-row>

              <v-btn-toggle v-model="form.mode" mandatory color="primary" class="mode-toggle my-4">
                <v-btn value="rule">Constructor</v-btn>
                <v-btn value="regex">Regex</v-btn>
                <v-btn value="stateful">Con estado</v-btn>
              </v-btn-toggle>

              <v-expansion-panels v-model="monitorBuilderPanels" multiple variant="accordion" class="monitor-builder">
                <v-expansion-panel value="include">
                  <v-expansion-panel-title>Incluir</v-expansion-panel-title>
                  <v-expansion-panel-text>
                    <v-row density="compact">
                      <v-col cols="12" sm="6">
                        <v-select
                          v-model="form.protocols"
                          :items="protocolOptions"
                          label="Protocolos"
                          multiple
                          chips
                          closable-chips
                          clearable
                          variant="outlined"
                          density="comfortable"
                        />
                      </v-col>
                      <v-col cols="12" sm="6">
                        <v-combobox
                          v-model="form.ports"
                          label="Puertos"
                          multiple
                          chips
                          closable-chips
                          clearable
                          variant="outlined"
                          density="comfortable"
                        />
                      </v-col>
                      <v-col cols="12" sm="6">
                        <v-combobox
                          v-model="form.srcPorts"
                          label="Puertos origen"
                          multiple
                          chips
                          closable-chips
                          clearable
                          variant="outlined"
                          density="comfortable"
                        />
                      </v-col>
                      <v-col cols="12" sm="6">
                        <v-combobox
                          v-model="form.dstPorts"
                          label="Puertos destino"
                          multiple
                          chips
                          closable-chips
                          clearable
                          variant="outlined"
                          density="comfortable"
                        />
                      </v-col>
                      <v-col cols="12">
                        <v-combobox
                          v-model="form.ips"
                          label="IPs"
                          multiple
                          chips
                          closable-chips
                          clearable
                          variant="outlined"
                          density="comfortable"
                        />
                      </v-col>
                      <v-col cols="12">
                        <v-combobox
                          v-model="form.payloadContains"
                          label="Payload contiene"
                          multiple
                          chips
                          closable-chips
                          clearable
                          variant="outlined"
                          density="comfortable"
                        />
                      </v-col>
                      <v-col cols="12" class="d-flex align-start ga-2">
                        <v-combobox
                          v-model="form.payloadRegex"
                          label="Regex de payload"
                          multiple
                          chips
                          closable-chips
                          clearable
                          variant="outlined"
                          density="comfortable"
                          :error-messages="regexErrors"
                          class="flex-grow-1"
                        />
                        <RegexHelperButton class="mt-2" @apply="(pattern) => form.payloadRegex.push(pattern)" />
                      </v-col>
                      <v-col cols="12" sm="6">
                        <v-combobox
                          v-model="form.ipRegex"
                          label="Regex de IP"
                          multiple
                          chips
                          closable-chips
                          clearable
                          variant="outlined"
                          density="comfortable"
                        />
                      </v-col>
                      <v-col cols="12" sm="6">
                        <v-combobox
                          v-model="form.portRegex"
                          label="Regex de puerto"
                          multiple
                          chips
                          closable-chips
                          clearable
                          variant="outlined"
                          density="comfortable"
                        />
                      </v-col>
                      <v-col cols="12" sm="6">
                        <v-combobox
                          v-model="form.protocolRegex"
                          label="Regex de protocolo"
                          multiple
                          chips
                          closable-chips
                          clearable
                          variant="outlined"
                          density="comfortable"
                        />
                      </v-col>
                      <v-col cols="12" sm="6">
                        <v-combobox
                          v-model="form.payloadPrefixHex"
                          label="Prefijo hex de payload"
                          multiple
                          chips
                          closable-chips
                          clearable
                          variant="outlined"
                          density="comfortable"
                        />
                      </v-col>
                    </v-row>
                  </v-expansion-panel-text>
                </v-expansion-panel>

                <v-expansion-panel value="exclude">
                  <v-expansion-panel-title>Excluir</v-expansion-panel-title>
                  <v-expansion-panel-text>
                    <v-row density="compact">
                      <v-col cols="12" sm="6">
                        <v-select
                          v-model="form.excludeProtocols"
                          :items="protocolOptions"
                          label="Protocolos"
                          multiple
                          chips
                          closable-chips
                          clearable
                          variant="outlined"
                          density="comfortable"
                        />
                      </v-col>
                      <v-col cols="12" sm="6">
                        <v-combobox
                          v-model="form.excludePorts"
                          label="Puertos"
                          multiple
                          chips
                          closable-chips
                          clearable
                          variant="outlined"
                          density="comfortable"
                        />
                      </v-col>
                      <v-col cols="12">
                        <v-combobox
                          v-model="form.excludeIps"
                          label="IPs"
                          multiple
                          chips
                          closable-chips
                          clearable
                          variant="outlined"
                          density="comfortable"
                        />
                      </v-col>
                      <v-col cols="12">
                        <v-combobox
                          v-model="form.excludePayloadContains"
                          label="Payload contiene"
                          multiple
                          chips
                          closable-chips
                          clearable
                          variant="outlined"
                          density="comfortable"
                        />
                      </v-col>
                      <v-col cols="12">
                        <v-combobox
                          v-model="form.payloadRegexExclude"
                          label="Regex de payload"
                          multiple
                          chips
                          closable-chips
                          clearable
                          variant="outlined"
                          density="comfortable"
                          :error-messages="regexErrors"
                        />
                      </v-col>
                      <v-col cols="12" sm="6">
                        <v-combobox
                          v-model="form.excludeIpRegex"
                          label="Regex de IP"
                          multiple
                          chips
                          closable-chips
                          clearable
                          variant="outlined"
                          density="comfortable"
                        />
                      </v-col>
                      <v-col cols="12" sm="6">
                        <v-combobox
                          v-model="form.excludePortRegex"
                          label="Regex de puerto"
                          multiple
                          chips
                          closable-chips
                          clearable
                          variant="outlined"
                          density="comfortable"
                        />
                      </v-col>
                      <v-col cols="12" sm="6">
                        <v-combobox
                          v-model="form.excludeProtocolRegex"
                          label="Regex de protocolo"
                          multiple
                          chips
                          closable-chips
                          clearable
                          variant="outlined"
                          density="comfortable"
                        />
                      </v-col>
                      <v-col cols="12" sm="6">
                        <v-combobox
                          v-model="form.excludePayloadPrefixHex"
                          label="Prefijo hex de payload"
                          multiple
                          chips
                          closable-chips
                          clearable
                          variant="outlined"
                          density="comfortable"
                        />
                      </v-col>
                    </v-row>
                  </v-expansion-panel-text>
                </v-expansion-panel>

                <v-expansion-panel value="advanced">
                  <v-expansion-panel-title>Avanzado</v-expansion-panel-title>
                  <v-expansion-panel-text>
                    <v-row density="compact">
                      <v-col cols="12" sm="6">
                        <v-text-field
                          v-model.number="form.minLength"
                          type="number"
                          label="Longitud mínima de paquete"
                          variant="outlined"
                          density="comfortable"
                        />
                      </v-col>
                      <v-col cols="12" sm="6">
                        <v-text-field
                          v-model.number="form.maxLength"
                          type="number"
                          label="Longitud máxima de paquete"
                          variant="outlined"
                          density="comfortable"
                        />
                      </v-col>
                      <v-col cols="12">
                        <v-checkbox
                          v-model="form.requestOnly"
                          label="Solo tráfico de solicitud"
                          color="primary"
                          density="compact"
                          hide-details
                        />
                      </v-col>
                      <v-col cols="12" sm="4">
                        <v-combobox
                          v-model="form.tcpFlags"
                          label="Flags TCP exactos"
                          multiple
                          chips
                          closable-chips
                          clearable
                          variant="outlined"
                          density="comfortable"
                        />
                      </v-col>
                      <v-col cols="12" sm="4">
                        <v-combobox
                          v-model="form.tcpFlagsAny"
                          label="Cualquier flag TCP"
                          multiple
                          chips
                          closable-chips
                          clearable
                          variant="outlined"
                          density="comfortable"
                        />
                      </v-col>
                      <v-col cols="12" sm="4">
                        <v-combobox
                          v-model="form.tcpFlagsAll"
                          label="Todos los flags TCP"
                          multiple
                          chips
                          closable-chips
                          clearable
                          variant="outlined"
                          density="comfortable"
                        />
                      </v-col>
                      <v-col v-if="form.mode === 'stateful'" cols="12" sm="4">
                        <v-text-field
                          v-model.number="form.countThreshold"
                          type="number"
                          label="Umbral de conteo"
                          variant="outlined"
                          density="comfortable"
                        />
                      </v-col>
                      <v-col v-if="form.mode === 'stateful'" cols="12" sm="4">
                        <v-text-field
                          v-model.number="form.windowSeconds"
                          type="number"
                          label="Ventana en segundos"
                          variant="outlined"
                          density="comfortable"
                        />
                      </v-col>
                      <v-col v-if="form.mode === 'stateful'" cols="12" sm="4">
                        <v-select
                          v-model="form.groupBy"
                          :items="groupByOptions"
                          label="Agrupar por"
                          variant="outlined"
                          density="comfortable"
                        />
                      </v-col>
                      <v-col cols="12">
                        <v-textarea
                          v-model="form.advancedMatchJson"
                          label="JSON avanzado de coincidencia"
                          rows="7"
                          auto-grow
                          variant="outlined"
                          density="comfortable"
                          :error-messages="advancedJsonError ? [advancedJsonError] : []"
                        />
                      </v-col>
                    </v-row>
                  </v-expansion-panel-text>
                </v-expansion-panel>
              </v-expansion-panels>
            </v-card-text>
            <v-card-actions>
              <v-spacer />
              <v-btn variant="text" @click="dialogOpen = false">Cancelar</v-btn>
              <v-btn color="primary" variant="tonal" :loading="formSubmitting" @click="submitForm">
                Guardar monitor
              </v-btn>
            </v-card-actions>
          </v-card>
        </v-dialog>
      </v-window-item>

      <v-window-item value="blacklist">
        <BlacklistPanel />
      </v-window-item>

      <v-window-item value="exclusions">
        <ExclusionsPanel />
      </v-window-item>

      <v-window-item value="connection">
        <dl class="settings-connection">
          <dt>WebSocket</dt>
          <dd>{{ store.state.wsStatus === 'online' ? 'Conectado' : store.state.wsStatus }}</dd>
          <dt>API</dt>
          <dd>{{ store.state.apiBase || 'Local' }}</dd>
          <dt>Autenticación</dt>
          <dd>{{ store.state.authRequired ? (store.state.authStatus === 'authenticated' ? 'Sesión autenticada' : 'Sesión requerida') : 'No requerida' }}</dd>
        </dl>
        <v-btn v-if="store.state.authRequired && store.state.authStatus !== 'authenticated'" class="mt-4" prepend-icon="mdi-lock-open-outline" @click="store.state.authPromptOpen = true">
          Autenticar
        </v-btn>
        <v-btn class="mt-4" variant="outlined" prepend-icon="mdi-refresh" :loading="statusRefreshing" @click="refreshGraph">Actualizar conexión</v-btn>

        <DataPanel
          title="Stream móvil en vivo"
          subtitle="Vincula un teléfono con un QR y un código de un solo uso de 6 dígitos. La página móvil es de solo lectura y recibe solo eventos en vivo redactados."
          variant="tonal"
          class="mt-5"
          :count="mobileSessions.length"
          count-label="sesiones móviles"
        >
          <template #header-actions>
            <v-chip size="small" :color="mobileServer.running ? 'success' : 'default'" variant="tonal" prepend-icon="mdi-cellphone-link">
              {{ mobileServer.running ? `${mobileServer.interface} · ${mobileServer.address}` : "sin conexión" }}
            </v-chip>
          </template>

          <v-row class="mt-1" align="start">
            <v-col cols="12" md="5">
              <v-select
                v-model="mobileInterface"
                :items="mobileInterfaceOptions"
                item-title="label"
                item-value="name"
                label="Interfaz de escucha"
                variant="outlined"
                density="comfortable"
                hide-details="auto"
                :loading="mobileLoading"
                :disabled="mobileLoading"
              />
              <v-text-field
                v-model.number="mobilePort"
                class="mt-3"
                label="Puerto"
                type="number"
                min="1"
                max="65535"
                variant="outlined"
                density="comfortable"
                hide-details="auto"
              />
              <div class="d-flex flex-wrap ga-2 mt-3">
                <v-btn color="primary" prepend-icon="mdi-qrcode" :loading="mobilePairingBusy" :disabled="!mobileInterface" @click="createMobilePairing">
                  Nuevo QR
                </v-btn>
                <v-btn variant="outlined" prepend-icon="mdi-refresh" :loading="mobileLoading" @click="loadMobileStream">
                  Actualizar
                </v-btn>
                <v-btn v-if="mobileServer.running" variant="outlined" color="error" prepend-icon="mdi-stop-circle-outline" :loading="mobileStopping" @click="stopMobileStream">
                  Detener
                </v-btn>
              </div>
              <v-alert v-if="mobileError" class="mt-3" type="error" variant="tonal" density="comfortable">
                {{ mobileError }}
              </v-alert>
            </v-col>
            <v-col cols="12" md="4">
              <div v-if="mobilePairing.url" class="mobile-qr-wrap">
                <img v-if="mobileQrDataUrl" :src="mobileQrDataUrl" alt="QR del stream móvil" class="mobile-qr" />
                <div class="text-caption text-medium-emphasis mt-2">{{ mobilePairing.url }}</div>
              </div>
              <v-alert v-else type="info" variant="tonal" density="comfortable">
                Elige una interfaz y crea un QR. El teléfono debe estar en la misma red.
              </v-alert>
            </v-col>
            <v-col cols="12" md="3">
              <div class="mobile-code-box">
                <div class="text-caption text-medium-emphasis">Código de vinculación</div>
                <div class="mobile-code">{{ mobilePairing.code || "------" }}</div>
                <div class="text-caption text-medium-emphasis">
                  {{ mobilePairingStatus }}
                </div>
              </div>
            </v-col>
          </v-row>

          <!-- A device has reached the link but is trusted with nothing yet.
               No code exists until this is accepted, so this card is the
               security decision: the operator judges the address and browser
               shown here before anything is issued. -->
          <v-alert
            v-if="mobilePairingAwaitingApproval"
            class="mt-3"
            type="warning"
            variant="tonal"
            density="comfortable"
            prepend-icon="mdi-shield-account-outline"
          >
            <div class="text-subtitle-2">Un dispositivo solicita conexión</div>
            <div class="text-caption mt-1">
              Dirección {{ mobilePairing.client || "desconocida" }}
              <span v-if="mobilePairing.seen_at"> · {{ mobilePairing.seen_at }}</span>
            </div>
            <div class="text-caption text-medium-emphasis mobile-approval-ua">
              {{ mobilePairing.user_agent || "sin User-Agent reportado" }}
            </div>
            <div class="text-caption mt-2">
              Aprueba solo si es el teléfono que tienes a mano. Aceptar genera el código
              de 6 dígitos e inicia su ventana breve de ingreso.
            </div>
            <template #append>
              <v-btn
                color="warning"
                variant="flat"
                prepend-icon="mdi-check"
                :loading="mobileApproving"
                @click="approveMobilePairing"
              >
                Aceptar
              </v-btn>
            </template>
          </v-alert>

          <v-divider class="my-4" />
          <div class="text-subtitle-2 mb-2">Teléfonos activos</div>
          <v-list v-if="mobileSessions.length" density="compact" bg-color="transparent">
            <v-list-item v-for="session in mobileSessions" :key="session.token">
              <template #prepend>
                <v-icon icon="mdi-cellphone-check" />
              </template>
              <v-list-item-title>{{ session.client || "dispositivo móvil" }}</v-list-item-title>
              <v-list-item-subtitle>{{ session.user_agent || session.token_hint }} · {{ session.event_count || 0 }} eventos</v-list-item-subtitle>
              <template #append>
                <v-btn icon="mdi-close" variant="text" color="error" :loading="mobileRevoking === session.token" @click="revokeMobileSession(session.token)" />
              </template>
            </v-list-item>
          </v-list>
          <div v-else class="text-caption text-medium-emphasis">No hay teléfonos vinculados.</div>
        </DataPanel>
      </v-window-item>

      <v-window-item value="notifications">
        <v-card variant="tonal" class="pa-4 notify-card">
          <div class="d-flex align-start justify-space-between flex-wrap ga-3">
            <div>
              <div class="text-subtitle-2 font-weight-medium">Notificar detecciones de monitores</div>
              <div class="text-caption text-medium-emphasis mt-1">
                Una notificación por cada detección de un monitor, sin agrupar ni silenciar.
                Se guarda localmente en el navegador.
              </div>
            </div>
            <v-switch
              :model-value="store.state.notifyDetectionsEnabled"
              aria-label="Notificar detecciones de monitores"
              color="primary"
              hide-details
              inset
              @update:model-value="(value) => store.setNotifyDetectionsEnabled(value)"
            />
          </div>
          <div class="d-flex align-start justify-space-between flex-wrap ga-3 mt-4">
            <div>
              <div class="text-subtitle-2 font-weight-medium">Severidad mínima para notificar</div>
              <div class="text-caption text-medium-emphasis mt-1">
                Por debajo de esta severidad las detecciones siguen en la lista pero no avisan.
                Por defecto, media en adelante.
              </div>
            </div>
            <v-select
              :model-value="store.state.notifyMinSeverity"
              :items="[
                { title: 'Info', value: 'info' },
                { title: 'Baja', value: 'low' },
                { title: 'Media', value: 'medium' },
                { title: 'Alta', value: 'high' },
                { title: 'Crítica', value: 'critical' },
              ]"
              aria-label="Severidad mínima para notificar"
              variant="outlined"
              density="compact"
              hide-details
              style="max-width: 180px"
              @update:model-value="(value) => store.setNotifyMinSeverity(value)"
            />
          </div>
          <div class="d-flex align-start justify-space-between flex-wrap ga-3 mt-4">
            <div>
              <div class="text-subtitle-2 font-weight-medium">Sonido de notificación</div>
              <div class="text-caption text-medium-emphasis mt-1">
                Reproduce un sonido en esta pestaña cuando llegue una alerta nueva. Se guarda
                localmente en el navegador, no en el servidor.
              </div>
            </div>
            <v-switch
              :model-value="store.state.notifySoundEnabled"
              aria-label="Sonido de notificaciones"
              color="primary"
              hide-details
              inset
              @update:model-value="(value) => store.setNotifySoundEnabled(value)"
            />
          </div>
        </v-card>
      </v-window-item>

      <v-window-item value="packetcache">
        <v-card variant="tonal" class="pa-4 pipeline-card">
          <div class="text-subtitle-2 font-weight-medium">Caché de paquetes</div>
          <div class="text-caption text-medium-emphasis mt-1 mb-3">
            El sniffer deposita cada paquete capturado en esta caché y los jobs lo consumen desde aquí, así que la captura no espera al procesamiento. Si la caché se llena, se descartan los paquetes más antiguos.
          </div>
          <v-text-field
            v-model.number="pipelineDraft.cache_limit"
            label="Límite de retención (paquetes)"
            type="number"
            min="1000"
            max="1000000"
            step="1000"
            variant="outlined"
            density="comfortable"
            :disabled="!pipelineConfig || pipelineSaving"
            hint="Entre 1.000 y 1.000.000 paquetes en espera."
            persistent-hint
          />
          <div v-if="pipelineLive" class="mt-4">
            <div class="d-flex flex-wrap align-center justify-space-between ga-2 mb-2">
              <span class="text-caption text-medium-emphasis">Contadores desde {{ formatTimestamp(pipelineLive.since) || "el inicio" }}</span>
              <v-btn size="small" variant="tonal" prepend-icon="mdi-restart" :loading="pipelineResetting" :disabled="pipelineResetting" @click="resetPipelineCounters">
                Reiniciar contadores
              </v-btn>
            </div>
            <v-row dense>
              <v-col cols="6">
                <div class="text-caption text-medium-emphasis">En espera</div>
                <div class="text-body-1 font-weight-medium">{{ (pipelineLive.cache_depth ?? 0).toLocaleString() }}</div>
              </v-col>
              <v-col cols="6">
                <div class="text-caption text-medium-emphasis">Límite</div>
                <div class="text-body-1 font-weight-medium">{{ (pipelineLive.cache_limit ?? 0).toLocaleString() }}</div>
              </v-col>
              <v-col cols="6">
                <div class="text-caption text-medium-emphasis">Aceptados</div>
                <div class="text-body-1 font-weight-medium">{{ (pipelineLive.cache_accepted ?? 0).toLocaleString() }}</div>
              </v-col>
              <v-col cols="6">
                <div class="text-caption text-medium-emphasis">Descartados por límite</div>
                <div class="text-body-1 font-weight-medium text-warning">{{ (pipelineLive.cache_dropped ?? 0).toLocaleString() }}</div>
              </v-col>
              <v-col cols="6">
                <div class="text-caption text-medium-emphasis">Pico de ocupación</div>
                <div class="text-body-1 font-weight-medium">{{ (pipelineLive.cache_peak ?? 0).toLocaleString() }}</div>
              </v-col>
            </v-row>
          </div>
          <v-alert v-if="pipelineError" type="error" variant="tonal" density="comfortable" class="mt-3">
            {{ pipelineError }}
          </v-alert>
          <div class="d-flex justify-end mt-3">
            <v-btn color="primary" variant="tonal" :loading="pipelineSaving" :disabled="!pipelineConfig" @click="savePipelineConfig">
              Guardar
            </v-btn>
          </div>
        </v-card>
      </v-window-item>

      <v-window-item value="packetjobs">
        <v-card variant="tonal" class="pa-4 pipeline-card">
          <div class="text-subtitle-2 font-weight-medium">Jobs de procesamiento</div>
          <div class="text-caption text-medium-emphasis mt-1 mb-3">
            Workers que toman paquetes de la caché, los evalúan con monitores y anomalías, y persisten los que corresponden en SniffStore.
          </div>
          <v-text-field
            v-model.number="pipelineDraft.jobs"
            label="Número de jobs"
            type="number"
            min="1"
            max="16"
            variant="outlined"
            density="comfortable"
            :disabled="!pipelineConfig || pipelineSaving"
            hint="Entre 1 y 16. Se aplica al iniciar la captura."
            persistent-hint
            class="mb-2"
          />
          <v-select
            v-model="pipelineDraft.persist_mode"
            label="Persistencia"
            :items="[{ title: 'Solo paquetes con alerta', value: 'alerts' }, { title: 'Todo el tráfico procesado', value: 'all' }]"
            item-title="title"
            item-value="value"
            variant="outlined"
            density="comfortable"
            :disabled="!pipelineConfig || pipelineSaving"
            hint="Qué paquetes llegan a SniffStore después de procesarse. «Todo» escribe cada paquete en la base de datos."
            persistent-hint
          />
          <div v-if="pipelineLive" class="mt-4">
            <div class="d-flex flex-wrap align-center justify-space-between ga-2 mb-2">
              <span class="text-caption text-medium-emphasis">Contadores desde {{ formatTimestamp(pipelineLive.since) || "el inicio" }}</span>
              <v-btn size="small" variant="tonal" prepend-icon="mdi-restart" :loading="pipelineResetting" :disabled="pipelineResetting" @click="resetPipelineCounters">
                Reiniciar contadores
              </v-btn>
            </div>
            <v-row dense>
              <v-col cols="6">
                <div class="text-caption text-medium-emphasis">Procesados</div>
                <div class="text-body-1 font-weight-medium">{{ (pipelineLive.processed ?? 0).toLocaleString() }}</div>
              </v-col>
              <v-col cols="6">
                <div class="text-caption text-medium-emphasis">Persistidos</div>
                <div class="text-body-1 font-weight-medium">{{ (pipelineLive.persisted ?? 0).toLocaleString() }}</div>
              </v-col>
              <v-col cols="6">
                <div class="text-caption text-medium-emphasis">Omitidos (sin alerta)</div>
                <div class="text-body-1 font-weight-medium">{{ (pipelineLive.skipped ?? 0).toLocaleString() }}</div>
              </v-col>
              <v-col cols="6">
                <div class="text-caption text-medium-emphasis">Escrituras fallidas (BD)</div>
                <div class="text-body-1 font-weight-medium text-warning">{{ (pipelineLive.write_errors ?? 0).toLocaleString() }}</div>
              </v-col>
              <v-col cols="6">
                <div class="text-caption text-medium-emphasis">Errores de evaluación</div>
                <div class="text-body-1 font-weight-medium text-warning">{{ (pipelineLive.errors ?? 0).toLocaleString() }}</div>
              </v-col>
            </v-row>
          </div>
          <v-alert v-if="pipelineError" type="error" variant="tonal" density="comfortable" class="mt-3">
            {{ pipelineError }}
          </v-alert>
          <div class="d-flex justify-end mt-3">
            <v-btn color="primary" variant="tonal" :loading="pipelineSaving" :disabled="!pipelineConfig" @click="savePipelineConfig">
              Guardar
            </v-btn>
          </div>
        </v-card>
      </v-window-item>

      <v-window-item value="limits">
        <v-card variant="tonal" class="pa-4 mb-4">
          <div class="text-subtitle-2 font-weight-medium">Límites de recursos</div>
          <div class="text-caption text-medium-emphasis mt-1 mb-3">
            Si la captura supera un límite en dos mediciones seguidas, se paran la captura y los jobs de procesamiento, como en un reinicio. Vuelven solos cuando todos los valores bajan del porcentaje de reanudación. Un valor de 0 desactiva ese límite.
          </div>
          <v-row dense v-if="limitDraft">
            <v-col cols="12" sm="6" md="4">
              <v-text-field v-model.number="limitDraft.cpu_percent" label="CPU máxima" type="number" min="0" max="100" suffix="%" variant="outlined" density="comfortable" :disabled="limitSaving" hint="Del total de la máquina. 0 = sin límite." persistent-hint />
            </v-col>
            <v-col cols="12" sm="6" md="4">
              <v-text-field v-model.number="limitDraft.ram_mb" label="RAM máxima" type="number" min="0" suffix="MB" variant="outlined" density="comfortable" :disabled="limitSaving" hint="Memoria del proceso de captura." persistent-hint />
            </v-col>
            <v-col cols="12" sm="6" md="4">
              <v-text-field v-model.number="limitDraft.storage_mb" label="Almacenamiento máximo" type="number" min="0" suffix="MB" variant="outlined" density="comfortable" :disabled="limitSaving" hint="Base de datos, WAL y logs." persistent-hint />
            </v-col>
            <v-col cols="12" sm="6" md="4">
              <v-text-field v-model.number="limitDraft.resume_percent" label="Reanudar al" type="number" min="10" max="99" suffix="%" variant="outlined" density="comfortable" :disabled="limitSaving" hint="Porcentaje del límite por debajo del cual se reanuda." persistent-hint />
            </v-col>
            <v-col cols="12" sm="6" md="4">
              <v-text-field v-model.number="limitDraft.sample_seconds" label="Medición cada" type="number" min="1" max="300" suffix="s" variant="outlined" density="comfortable" :disabled="limitSaving" />
            </v-col>
            <v-col cols="12" sm="6" md="4">
              <v-text-field v-model.number="limitDraft.cooldown_seconds" label="Espera antes de reanudar" type="number" min="0" max="3600" suffix="s" variant="outlined" density="comfortable" :disabled="limitSaving" hint="Evita encender y apagar la captura en bucle." persistent-hint />
            </v-col>
          </v-row>
          <div v-if="limitsData" class="mt-3">
            <div class="d-flex flex-wrap align-center justify-space-between ga-2 mb-2">
              <span class="text-caption text-medium-emphasis">
                Estado: {{ limitsData.state && limitsData.state.paused ? `pausado (${limitsData.state.reason || 'límite'})` : 'capturando' }}
                <span v-if="limitsData.state && limitsData.state.paused_at"> · desde {{ formatTimestamp(limitsData.state.paused_at) }}</span>
              </span>
              <v-btn size="small" variant="tonal" prepend-icon="mdi-restart" :loading="limitResetting" :disabled="limitResetting" @click="resetLimitCounters">Reiniciar contadores</v-btn>
            </div>
            <v-row dense>
              <v-col cols="6" sm="3"><div class="text-caption text-medium-emphasis">Pausas totales</div><div class="text-body-1 font-weight-medium">{{ (limitsData.state?.counters?.trips ?? 0).toLocaleString() }}</div></v-col>
              <v-col cols="6" sm="3"><div class="text-caption text-medium-emphasis">Por CPU</div><div class="text-body-1 font-weight-medium">{{ limitsData.state?.counters?.by_kind?.cpu ?? 0 }}</div></v-col>
              <v-col cols="6" sm="3"><div class="text-caption text-medium-emphasis">Por RAM</div><div class="text-body-1 font-weight-medium">{{ limitsData.state?.counters?.by_kind?.ram ?? 0 }}</div></v-col>
              <v-col cols="6" sm="3"><div class="text-caption text-medium-emphasis">Por almacenamiento</div><div class="text-body-1 font-weight-medium">{{ limitsData.state?.counters?.by_kind?.storage ?? 0 }}</div></v-col>
              <v-col cols="12"><div class="text-caption text-medium-emphasis">Tiempo pausado acumulado</div><div class="text-body-1 font-weight-medium">{{ Math.round(limitsData.state?.counters?.paused_seconds ?? 0) }} s</div></v-col>
            </v-row>
          </div>
          <v-alert v-if="limitError" type="error" variant="tonal" density="comfortable" class="mt-3">{{ limitError }}</v-alert>
          <v-alert v-if="limitSaved" type="success" variant="tonal" density="comfortable" class="mt-3">Límites guardados.</v-alert>
          <div class="d-flex justify-end mt-3">
            <v-btn color="primary" variant="tonal" :loading="limitSaving" :disabled="!limitDraft || limitSaving" @click="saveLimits">Guardar</v-btn>
          </div>
        </v-card>
      </v-window-item>

      <v-window-item value="logs">
        <v-card variant="tonal" class="pa-4 mb-4">
          <div class="text-subtitle-2 font-weight-medium">Configuración de logs</div>
          <div class="text-caption text-medium-emphasis mt-1 mb-3">
            Un archivo NDJSON por proceso en la carpeta de datos (<code>logs/web.ndjson</code> y <code>logs/capture.ndjson</code>). Rota al alcanzar el tamaño y conserva las copias y los días indicados. Los cambios se aplican sin reiniciar.
          </div>
          <v-row dense v-if="logDraft">
            <v-col cols="12" sm="6" md="4">
              <v-select
                v-model="logDraft.level"
                label="Nivel"
                :items="['DEBUG', 'INFO', 'WARNING', 'ERROR']"
                variant="outlined"
                density="comfortable"
                :disabled="logSaving"
                hint="DEBUG registra el ciclo de vida de jobs, lotes de captura y sentencias SQL."
                persistent-hint
              />
            </v-col>
            <v-col cols="12" sm="6" md="4">
              <v-text-field v-model.number="logDraft.max_mb" label="Tamaño por archivo" type="number" min="1" max="1024" suffix="MB" variant="outlined" density="comfortable" :disabled="logSaving" />
            </v-col>
            <v-col cols="12" sm="6" md="4">
              <v-text-field v-model.number="logDraft.backups" label="Copias rotadas" type="number" min="0" max="100" variant="outlined" density="comfortable" :disabled="logSaving" hint="0 = sin copias, el archivo se trunca." persistent-hint />
            </v-col>
            <v-col cols="12" sm="6" md="4">
              <v-text-field v-model.number="logDraft.retention_days" label="Retención" type="number" min="0" max="3650" suffix="días" variant="outlined" density="comfortable" :disabled="logSaving" hint="0 = conservar todas las copias." persistent-hint />
            </v-col>
            <v-col cols="12" sm="6" md="4">
              <v-text-field v-model.number="logDraft.slow_ms" label="Sentencia SQL lenta" type="number" min="10" max="60000" suffix="ms" variant="outlined" density="comfortable" :disabled="logSaving" hint="Por encima de este tiempo se registra como WARNING." persistent-hint />
            </v-col>
          </v-row>
          <v-alert v-if="logError" type="error" variant="tonal" density="comfortable" class="mt-3">{{ logError }}</v-alert>
          <v-alert v-if="logSaved" type="success" variant="tonal" density="comfortable" class="mt-3">Configuración de logs guardada.</v-alert>
          <div class="d-flex justify-end mt-3">
            <v-btn color="primary" variant="tonal" :loading="logSaving" :disabled="!logDraft || logSaving" @click="saveLogConfig">Guardar</v-btn>
          </div>
        </v-card>

        <v-card variant="tonal" class="pa-4">
          <div class="d-flex align-center flex-wrap ga-2 mb-3">
            <div class="text-subtitle-2 font-weight-medium mr-auto">Registro</div>
            <v-select v-model="logSource" :items="[{ title: 'Web', value: 'web' }, { title: 'Captura', value: 'capture' }]" item-title="title" item-value="value" label="Origen" variant="outlined" density="compact" hide-details style="max-width:160px" @update:model-value="loadLogTail" />
            <v-select v-model="logLevel" :items="[{ title: 'Todos', value: '' }, { title: 'Desde INFO', value: 'INFO' }, { title: 'Desde WARNING', value: 'WARNING' }, { title: 'Solo ERROR', value: 'ERROR' }]" item-title="title" item-value="value" label="Nivel" variant="outlined" density="compact" hide-details style="max-width:170px" @update:model-value="loadLogTail" />
            <v-btn variant="tonal" prepend-icon="mdi-refresh" :loading="logTailLoading" @click="loadLogTail">Actualizar</v-btn>
          </div>
          <v-alert v-if="logTailError" type="error" variant="tonal" density="comfortable" class="mb-3">{{ logTailError }}</v-alert>
          <div v-if="logRows.length" class="log-tail">
            <div v-for="(row, index) in logRows" :key="index" class="log-tail__row" :class="'is-' + String(row.level || '').toLowerCase()">
              <span class="log-tail__time">{{ String(row.timestamp || '').replace('T', ' ').slice(11, 23) }}</span>
              <span class="log-tail__level">{{ row.level }}</span>
              <span class="log-tail__logger">{{ row.logger }}</span>
              <span class="log-tail__msg">{{ row.message }}<span v-if="logExtras(row)" class="log-tail__extra"> {{ logExtras(row) }}</span></span>
            </div>
          </div>
          <div v-else class="text-caption text-medium-emphasis">Sin registros. Pulsa Actualizar para leer el archivo.</div>
        </v-card>
      </v-window-item>

    </v-window>
    </ConfigGraphNav>
  </div>
</template>

<script>
import QRCode from "qrcode";
import store from "../state/appStore";
import EntityTablePanel from "../components/ui/EntityTablePanel.vue";
import DataPanel from "../components/ui/DataPanel.vue";
import LocationPicker from "../components/settings/LocationPicker.vue";
import RegexHelperButton from "../components/ui/RegexHelperButton.vue";
import BlacklistPanel from "../components/settings/BlacklistPanel.vue";
import ExclusionsPanel from "../components/settings/ExclusionsPanel.vue";
import RuleDetailDialog from "../components/monitors/RuleDetailDialog.vue";
import ConfigGraphNav from "../components/settings/ConfigGraphNav.vue";
import { SETTINGS_NODES } from "../components/settings/settingsGraph";
import { formatTimestamp, matchesSearch, uniqueSorted } from "../utils/traffic";

const PROTOCOL_OPTIONS = [
  "tcp",
  "udp",
  "icmp",
  "icmpv6",
  "arp",
  "sctp",
  "modbus",
  "dnp3",
  "snmp",
  "syslog",
  "tftp",
  "radius",
  "mqtt",
  "llc",
  "llc-snap",
  "llc-ipx",
  "llc-netbios",
  "llc-osi",
];
const SEVERITY_OPTIONS = ["info", "low", "medium", "high", "critical"];
const VALID_TABS = new Set(SETTINGS_NODES.map(node => node.section));
const GROUP_BY_OPTIONS = ["src_ip", "dst_ip", "src_ip+dst_port", "dst_ip+dst_port", "src_ip+dst_ip"];
const MATCH_REGEX_KEYS = [
  "payload_regex",
  "payload_regex_exclude",
  "ip_regex",
  "exclude_ip_regex",
  "port_regex",
  "exclude_port_regex",
  "protocol_regex",
  "exclude_protocol_regex",
];
const CONDITION_KEYS = ["all", "any", "none"];

function collectMatchRegexes(match, depth = 0) {
  if (!match || typeof match !== "object" || Array.isArray(match) || depth > 6) return [];
  const patterns = MATCH_REGEX_KEYS
    .flatMap((key) => Array.isArray(match[key]) ? match[key] : [])
    .map((item) => String(item || "").trim())
    .filter(Boolean);
  const groups = CONDITION_KEYS.flatMap((key) => match[key] || []);
  const nested = match.conditions && typeof match.conditions === "object" && !Array.isArray(match.conditions)
    ? CONDITION_KEYS.flatMap((key) => match.conditions[key] || [])
    : [];
  return [...patterns, ...[...groups, ...nested].flatMap((item) => collectMatchRegexes(item, depth + 1))];
}

function emptyForm() {
  return {
    name: "",
    description: "",
    priority: 100,
    severity: "medium",
    tag: "",
    mode: "rule",
    protocols: [],
    excludeProtocols: [],
    ports: [],
    srcPorts: [],
    dstPorts: [],
    excludePorts: [],
    ips: [],
    excludeIps: [],
    ipRegex: [],
    excludeIpRegex: [],
    portRegex: [],
    excludePortRegex: [],
    protocolRegex: [],
    excludeProtocolRegex: [],
    payloadContains: [],
    excludePayloadContains: [],
    payloadPrefixHex: [],
    excludePayloadPrefixHex: [],
    minLength: null,
    maxLength: null,
    requestOnly: false,
    tcpFlags: [],
    tcpFlagsAny: [],
    tcpFlagsAll: [],
    countThreshold: null,
    windowSeconds: null,
    groupBy: "src_ip",
    payloadRegex: [],
    payloadRegexExclude: [],
    advancedMatchJson: "",
  };
}

export default {
  name: "SettingsView",
  components: {
    EntityTablePanel,
    DataPanel,
    RegexHelperButton,
    BlacklistPanel,
    ExclusionsPanel,
    LocationPicker,
    RuleDetailDialog,
    ConfigGraphNav,
  },
  data() {
    const requested = String((this.$route && this.$route.query && this.$route.query.section) || "").trim();
    return {
      store,
      activeTab: VALID_TABS.has(requested) ? requested : "",
      statusRefreshing: false,
      graphStatusTimer: null,
      mobilePairingTimer: null,
      pipelineConfig: null,
      pipelineDraft: { cache_limit: 20000, jobs: 2, persist_mode: "alerts" },
      pipelineSaving: false,
      pipelineError: "",
      limitsData: null,
      limitDraft: null,
      limitSaving: false,
      limitSaved: false,
      limitError: "",
      limitResetting: false,
      logConfig: null,
      logDraft: null,
      logSaving: false,
      logSaved: false,
      logError: "",
      logSource: "web",
      logLevel: "",
      logLines: 200,
      logRows: [],
      logTailLoading: false,
      logTailError: "",
      pipelineResetting: false,
      graphExtras: { blacklist: null, whitelist: null, exclusions: null, retentionDays: null },
      enginePending: "",
      engineError: "",
      ruleDetailOpen: false,
      ruleDetailMonitor: null,

      // Capture
      interfaceSubmitting: false,
      interfaceError: "",
      detectionScopes: [],
      detectionScopeCatalog: [],
      detectionScopesSubmitting: false,
      detectionScopesError: "",
      locationSaved: { lat: null, lon: null, label: "", configured: false },
      locationDraft: { lat: null, lon: null, label: "" },
      locationSubmitting: false,
      locationError: "",
      purgeDialog: false,
      purgeScope: "all",
      purging: false,
      purgeError: "",
      purgeResult: "",

      // Storage stats
      storageStats: null,
      storageLoading: false,
      storageError: "",
      compactDialog: false,
      compacting: false,
      compactResult: "",

      // Retention config
      retentionConfig: null,
      retentionDraft: null,
      retentionLoading: false,
      retentionSaving: false,
      retentionSaved: false,
      retentionError: "",

      // Mobile stream
      mobileLoading: false,
      mobileStopping: false,
      mobilePairingBusy: false,
      mobileApproving: false,
      mobileRevoking: "",
      mobileError: "",
      mobileInterfaces: [],
      mobileInterface: "",
      mobilePort: 45679,
      mobileStatus: null,
      mobilePairing: {},
      mobileQrDataUrl: "",

      // Service listeners
      listeners: [],
      listenersError: "",
      listenerTogglePending: "",
      listenerSearch: "",
      listenerHeaders: [
        { title: "Listener", key: "endpoint", value: (item) => `${item.proto}/${item.port}` },
        { title: "Etiqueta", key: "label" },
        { title: "Origen", key: "source" },
        { title: "Estado", key: "running" },
        { title: "Habilitado", key: "enabled", sortable: false },
      ],
      newListenerDialog: false,
      newListenerSubmitting: false,
      newListenerError: "",
      newListener: { proto: "tcp", port: null, label: "" },

      // Detection monitors
      loading: false,
      error: "",
      lastUpdated: "",
      monitors: [],
      monitorStats: null,
      filterEnabled: true,
      monitorMinSeverity: "info",
      suppressGeneratedInfo: true,
      monitorSeverityCatalog: ["info", "low", "medium", "high", "critical"],
      configSubmitting: false,
      configError: "",
      busyIds: {},
      dialogOpen: false,
      editingId: "",
      form: emptyForm(),
      formError: "",
      formSubmitting: false,
      monitorBuilderPanels: ["include"],
      protocolOptions: PROTOCOL_OPTIONS,
      severityOptions: SEVERITY_OPTIONS,
      groupByOptions: GROUP_BY_OPTIONS,
      columns: [
        { key: "name", label: "Nombre" },
        { key: "mode", label: "Modo" },
        { key: "match_summary", label: "Coincidencia", sortable: false },
        { key: "severity", label: "Severidad" },
        { key: "source", label: "Origen" },
        { key: "enabled", label: "Habilitado", sortable: false },
        { key: "actions", label: "", sortable: false, width: 200 },
      ],
    };
  },
  computed: {
    graphStates() {
      const online = this.store.state.wsStatus === "online";
      const runtime = this.runtime;
      const sniffer = runtime.sniffer || {};
      const honeypot = runtime.honeypot || {};
      const live = online && Boolean(sniffer.running || honeypot.running);
      const pipeline = this.pipelineLive || {};
      const cfg = this.pipelineConfig || {};
      const extras = this.graphExtras || {};
      const exclusions = extras.exclusions || {};
      const storage = this.storageStats || null;
      const show = (value) => (online ? value : "—");
      const num = (value) => Number(value || 0).toLocaleString();
      const metric = (label, value, tone = "") => ({ label, value: show(value), tone: online ? tone : "" });
      const state = (label, active, metrics = []) => ({ label, metrics, active: online && Boolean(active), unknown: !online });
      const engineState = (name) => state(
        !online ? "Sin conexión" : runtime[name]?.running ? "En ejecución" : "Detenido",
        runtime[name]?.running,
      );
      const errorCount = (map) => Object.keys(map || {}).length;
      const listenersEnabled = this.listeners.filter(item => item.enabled).length;
      const freeBytes = storage ? Number(storage.free_bytes || 0) : 0;
      const liveBytes = storage ? Number(storage.live_bytes || 0) : 0;
      const configured = this.locationConfigured;
      const saved = this.locationSaved || {};
      // Counts from the stats endpoint; the full catalog is only loaded for the detection tab.
      const enabledMonitors = this.monitorStats ? this.monitorStats.enabled : this.monitors.filter(item => item.enabled).length;
      const totalMonitors = this.monitorStats ? this.monitorStats.total : this.monitors.length;
      const ipCount = (exclusions.ip_types || []).length;
      return {
        runtime: state(online ? (live ? "Captura activa" : "Motores detenidos") : "Sin conexión", live, [
          metric("Motores", `${(runtime.running_engines || []).length}/2`, live ? "ok" : ""),
          metric("Modo", runtime.mode ? runtime.mode.charAt(0).toUpperCase() + runtime.mode.slice(1) : "—"),
          metric("Concurrentes", runtime.concurrent ? "Sí" : "No"),
          metric("Auto-inicio", runtime.auto_start ? "Sí" : "No"),
        ]),
        capture: {
          ...engineState("sniffer"),
          metrics: [
            metric("Interfaces", num((sniffer.selected_interfaces || []).length)),
            metric("Vistos", num(sniffer.packets_seen)),
            metric("Almacenados", num(sniffer.packets_stored)),
            metric("Errores", num(errorCount(sniffer.errors)), errorCount(sniffer.errors) ? "alert" : "ok"),
          ],
        },
        honeypot: {
          ...engineState("honeypot"),
          label: online ? `${listenersEnabled} listeners habilitados` : "Sin conexión",
          metrics: [
            metric("Habilitados", num(honeypot.enabled_listener_count ?? listenersEnabled)),
            metric("Escuchando", num(honeypot.running_listener_count)),
            metric("Vistos", num(honeypot.packets_seen)),
            metric("Errores", num(errorCount(honeypot.errors)), errorCount(honeypot.errors) ? "alert" : "ok"),
          ],
        },
        location: state(this.locationConfigured ? this.locationSummary : "Sin ubicación", true, [
          metric("Latitud", configured && Number.isFinite(saved.lat) ? Number(saved.lat).toFixed(4) : "—"),
          metric("Longitud", configured && Number.isFinite(saved.lon) ? Number(saved.lon).toFixed(4) : "—"),
          metric("Estado", configured ? "Configurada" : "Pendiente", configured ? "ok" : "warn"),
          metric("Etiqueta", saved.label || "—"),
        ]),
        detection: state(this.error ? "Sin datos" : enabledMonitors ? `${enabledMonitors} reglas habilitadas` : "Detección apagada", enabledMonitors > 0, [
          metric("Habilitadas", `${enabledMonitors}/${totalMonitors}`),
          metric("Severidad mín.", String(this.monitorMinSeverity || "info").toUpperCase()),
          metric("Info generada", this.suppressGeneratedInfo ? "Silenciada" : "Visible"),
          metric("Ámbitos", num(this.detectionScopes.length), this.detectionScopes.length ? "warn" : ""),
        ]),
        scope: state(this.detectionScopes.length ? `${this.detectionScopes.length} ámbitos silenciados` : "Todo el tráfico", true, [
          metric("Silenciados", num(this.detectionScopes.length), this.detectionScopes.length ? "warn" : "ok"),
          metric("Disponibles", num(this.detectionScopeOptions.length)),
        ]),
        storage: state(online ? (storage ? this.formatDbBytes(liveBytes) + " datos vivos" : "SQLite local") : "Sin conexión", true, [
          metric("Datos", storage ? this.formatDbBytes(liveBytes) : "—"),
          metric("Libre", storage ? this.formatDbBytes(freeBytes) : "—", storage && freeBytes > liveBytes * 0.2 ? "warn" : ""),
          metric("Retención", extras.retentionDays != null ? `${extras.retentionDays} días` : "—"),
          metric("Auto-vacuum", storage ? (storage.incremental_reclaim ? "Activa" : "Inactiva") : "—", storage && !storage.incremental_reclaim ? "warn" : "ok"),
        ]),
        exclusions: state("Filtros compartidos", true, [
          metric("Tipos IP", num(ipCount)),
          metric("CIDR", num((exclusions.cidrs || []).length)),
          metric("Puertos", num((exclusions.ports || []).length)),
          metric("Protocolos", num((exclusions.protocols || []).length)),
        ]),
        blacklist: state("Bloqueados / permitidos", true, [
          metric("Bloqueados", num(extras.blacklist?.length)),
          metric("Permitidos", num(extras.whitelist?.length), "ok"),
        ]),
        connection: state(online ? "Conectado" : "Sin conexión", online, [
          metric("Estado", online ? "En línea" : "Caída", online ? "ok" : "alert"),
          metric("Canal", online ? "WebSocket" : "—"),
        ]),
        logs: state(this.logConfig ? `${this.logConfig.level} · ${this.logConfig.max_mb} MB por archivo` : "Sin datos", online && Boolean(this.logConfig), [
          metric("Nivel", this.logConfig ? this.logConfig.level : "—", this.logConfig && this.logConfig.level === "DEBUG" ? "warn" : ""),
          metric("Rotación", this.logConfig ? `${this.logConfig.max_mb} MB` : "—"),
          metric("Copias", this.logConfig ? num(this.logConfig.backups) : "—"),
          metric("Retención", this.logConfig ? `${this.logConfig.retention_days} días` : "—"),
        ]),
        limits: (() => {
          const data = this.limitsData;
          const cfg = data?.config || {};
          const st = data?.state || {};
          const m = st.measured || {};
          const cap = (value, limit) => (limit ? `${num(value)} / ${num(limit)}` : `${num(value)} / ∞`);
          const label = !data ? "Sin datos" : st.paused ? `Pausado · ${st.reason || "límite"}` : "Dentro de los límites";
          return state(label, online && data && !st.paused, [
            metric("CPU", data ? cap(m.cpu_percent ?? 0, cfg.cpu_percent) + " %" : "—", st.paused ? "alert" : ""),
            metric("RAM", data ? cap(m.ram_mb ?? 0, cfg.ram_mb) + " MB" : "—", st.paused ? "alert" : ""),
            metric("Disco", data ? cap(m.storage_mb ?? 0, cfg.storage_mb) + " MB" : "—", st.paused ? "alert" : ""),
            metric("Pausas", data ? num(st.counters?.trips ?? 0) : "—", (st.counters?.trips ?? 0) ? "warn" : "ok"),
          ]);
        })(),
        notifications: state(this.store.state.notifySoundEnabled ? "Sonido activado" : "Sonido desactivado", online && this.store.state.notifySoundEnabled, [
          metric("Sonido", this.store.state.notifySoundEnabled ? "Activo" : "Apagado", this.store.state.notifySoundEnabled ? "ok" : ""),
          metric("Alcance", "Este equipo"),
        ]),
        packetcache: state(
          pipeline.cache_limit ? `${num(pipeline.cache_depth)} / ${num(pipeline.cache_limit)} en espera` : `Límite ${num(cfg.cache_limit)}`,
          live,
          [
            metric("En espera", num(pipeline.cache_depth)),
            metric("Límite", num(pipeline.cache_limit ?? cfg.cache_limit)),
            metric("Descartados", num(pipeline.cache_dropped), pipeline.cache_dropped ? "warn" : "ok"),
            metric("Pico", num(pipeline.cache_peak)),
          ],
        ),
        packetjobs: state(
          cfg.jobs ? `${cfg.jobs} jobs · ${cfg.persist_mode === "all" ? "todo el tráfico" : "solo alertas"}` : "Sin datos",
          live,
          [
            metric("Procesados", num(pipeline.processed)),
            metric("Persistidos", num(pipeline.persisted), "ok"),
            metric("Escrituras fallidas", num(pipeline.write_errors), pipeline.write_errors ? "alert" : "ok"),
            metric("Errores", num(pipeline.errors), pipeline.errors ? "warn" : "ok"),
          ],
        ),
      };
    },
    retentionTables() {
      return this.retentionConfig ? Object.keys(this.retentionConfig.table_limits || {}) : [];
    },
    retentionOverriddenAny() {
      return Boolean(this.retentionConfig && this.retentionConfig.overridden && this.retentionConfig.overridden.length);
    },
    retentionDirty() {
      if (!this.retentionConfig || !this.retentionDraft) return false;
      const config = this.retentionConfig;
      const draft = this.retentionDraft;
      const fields = ["retention_days", "retention_alert_days", "retention_interval_seconds", "retention_max_packets"];
      if (fields.some((field) => Number(draft[field]) !== config[field])) return true;
      return this.retentionTables.some((table) => Number(draft.table_limits[table]) !== config.table_limits[table]);
    },
    pipelineLive() {
      // Counters live in the capture process and survive a stop, so they stay
      // readable whether or not capture is running.
      return this.runtime.sniffer?.packet_pipeline || null;
    },
    mobileInterfaceOptions() {
      return (this.mobileInterfaces || [])
        .filter((item) => !item.loopback)
        .map((item) => ({
          ...item,
          label: item.label || `${item.name} - ${item.address}`,
        }));
    },
    mobileServer() {
      return (this.mobileStatus && typeof this.mobileStatus === "object") ? this.mobileStatus : {};
    },
    mobileSessions() {
      return Array.isArray(this.mobileServer.sessions)
        ? this.mobileServer.sessions.filter((item) => !item.revoked)
        : [];
    },
    mobilePairingStatus() {
      const status = String(this.mobilePairing.status || "").replace(/_/g, " ");
      if (!this.mobilePairing.id) return "Esperando QR";
      const expires = Number(this.mobilePairing.expires_in || 0);
      if (this.mobilePairing.code) return `${this.mobilePairingStatusLabel(status || "waiting")} · ${expires}s`;
      if (this.mobilePairingAwaitingApproval) return `${this.mobilePairingStatusLabel(status)} · acepta para emitir código`;
      return `${this.mobilePairingStatusLabel(status || "pending")} · escanea el QR`;
    },
    mobilePairingAwaitingApproval() {
      return String(this.mobilePairing.status || "") === "awaiting_approval";
    },
    runtime() {
      return this.store.state.runtime || {};
    },
    snifferRuntime() {
      const runtime = this.runtime.sniffer;
      return runtime && typeof runtime === "object" ? runtime : {};
    },
    snifferBlocked() {
      return String(this.snifferRuntime.capture_state || "").trim().toLowerCase() === "blocked";
    },
    selectedInterfacesLabel() {
      const values = Array.isArray(this.snifferRuntime.selected_interfaces) ? this.snifferRuntime.selected_interfaces : [];
      if (!values.length) return "todas visibles";
      return values.join(", ");
    },
    selectedSnifferInterfaces() {
      const values = Array.isArray(this.snifferRuntime.selected_interfaces) ? this.snifferRuntime.selected_interfaces : [];
      return [...new Set(values.map((item) => String(item || "").trim()).filter(Boolean))];
    },
    snifferInterfaceOptions() {
      const values = Array.isArray(this.snifferRuntime.available_interfaces) ? this.snifferRuntime.available_interfaces : [];
      return uniqueSorted(values).map((value) => ({ label: value, value }));
    },
    snifferInterfaceStatus() {
      const active = Array.isArray(this.snifferRuntime.interfaces)
        ? this.snifferRuntime.interfaces.map((item) => String(item || "").trim()).filter(Boolean)
        : [];
      const state = String(this.snifferRuntime.capture_state || "").trim().toLowerCase();
      if (state === "blocked") {
        return `La captura está bloqueada en ${active.length || this.selectedSnifferInterfaces.length || 0} interfaces.`;
      }
      if (state === "running") {
        if (active.length === 1) return `Escuchando en ${active[0]}.`;
        if (active.length > 1) return `Escuchando en ${active.length} interfaces.`;
        return "Escuchando en todas las interfaces visibles.";
      }
      if (!this.selectedSnifferInterfaces.length) {
        return "Listo para escuchar en todas las interfaces visibles.";
      }
      return `Listo para escuchar en ${this.selectedInterfacesLabel}.`;
    },
    locationConfigured() {
      return Boolean(this.locationSaved.configured);
    },
    locationSummary() {
      const label = String(this.locationSaved.label || "").trim();
      if (label) return label;
      const { lat, lon } = this.locationSaved;
      return Number.isFinite(lat) && Number.isFinite(lon)
        ? `${Number(lat).toFixed(2)}, ${Number(lon).toFixed(2)}`
        : "Sin configurar";
    },
    locationDraftValid() {
      const { lat, lon } = this.locationDraft;
      return Number.isFinite(lat) && Number.isFinite(lon);
    },
    locationDirty() {
      return (
        this.locationDraft.lat !== this.locationSaved.lat ||
        this.locationDraft.lon !== this.locationSaved.lon ||
        String(this.locationDraft.label || "") !== String(this.locationSaved.label || "")
      );
    },
    detectionScopeOptions() {
      const labels = {
        loopback: "Loopback (127.0.0.0/8, ::1)",
        private: "Privado / LAN (RFC1918, link-local)",
        public: "Público (internet enrutable)",
      };
      const catalog = this.detectionScopeCatalog.length
        ? this.detectionScopeCatalog
        : ["loopback", "private", "public"];
      return catalog.map((value) => ({ value, label: labels[value] || value }));
    },
    detectionScopeStatus() {
      if (!this.detectionScopes.length) return "Todo el tráfico capturado se analiza.";
      const names = this.detectionScopes.join(", ");
      return `El tráfico entre direcciones ${names} se ignora por completo.`;
    },
    snifferInterfaceHint() {
      if (!this.snifferInterfaceOptions.length) {
        return "Aún no se reportaron interfaces. Actualiza para redescubrirlas.";
      }
      return "Una selección vacía hace que Sniff4Hound escuche en todas las interfaces visibles.";
    },
    regexErrors() {
      const invalid = [
        ...(this.form.payloadRegex || []),
        ...(this.form.payloadRegexExclude || []),
        ...(this.form.ipRegex || []),
        ...(this.form.excludeIpRegex || []),
        ...(this.form.portRegex || []),
        ...(this.form.excludePortRegex || []),
        ...(this.form.protocolRegex || []),
        ...(this.form.excludeProtocolRegex || []),
      ].map((pattern) => String(pattern || "").trim()).filter((pattern) => pattern && !this.isValidRegex(pattern));
      return invalid.length ? [`Regex inválida: ${invalid.join(", ")}`] : [];
    },
    advancedJsonError() {
      const text = String(this.form.advancedMatchJson || "").trim();
      if (!text) return "";
      try {
        const parsed = JSON.parse(text);
        if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
          return "El JSON avanzado de coincidencia debe ser un objeto";
        }
        const invalid = collectMatchRegexes(parsed).filter((pattern) => !this.isValidRegex(pattern));
        return invalid.length ? `Regex avanzada inválida: ${invalid.join(", ")}` : "";
      } catch (err) {
        return (err && err.message) || "JSON inválido";
      }
    },
    monitorSeverityOptions() {
      const labels = {
        info: "Info y superior",
        low: "Baja y superior",
        medium: "Media y superior",
        high: "Alta y crítica",
        critical: "Solo crítica",
      };
      return (this.monitorSeverityCatalog.length ? this.monitorSeverityCatalog : this.severityOptions)
        .map((value) => ({ value, label: labels[value] || value }));
    },
  },
  watch: {
    "$route.query.section"(next) {
      const requested = String(next || "").trim();
      this.activeTab = VALID_TABS.has(requested) ? requested : "";
    },
    activeTab(next) {
      if (String(this.$route.query.section || "") === next) return;
      // The full catalog is tens of megabytes: fetch it only when its tab opens.
      if (next === "detection" && !this.loading) this.load({ silent: true });
      const query = { ...this.$route.query };
      if (next) query.section = next;
      else delete query.section;
      this.$router.replace({ query });
    },
  },
  mounted() {
    this.refreshGraph();
    this.graphStatusTimer = setInterval(this.refreshGraph, 10000);
    this.loadListeners();
    this.loadDetectionScopes();
    this.loadLocation();
    this.loadMobileStream();
    this.loadStorageStats();
    this.loadRetentionConfig();
    // Opened straight on the detection tab (deep link): the watcher will not fire on mount.
    if (this.activeTab === "detection") this.load({ silent: true });
  },
  beforeUnmount() {
    clearInterval(this.graphStatusTimer);
    clearInterval(this.mobilePairingTimer);
  },
  methods: {
    async refreshGraph() {
      if (this.statusRefreshing) return;
      this.statusRefreshing = true;
      const results = await Promise.allSettled([
        this.store.initRuntime(),
        this.store.fetchJsonPromise("/api/pipeline/config"),
        this.store.fetchJsonPromise("/api/blacklist/"),
        this.store.fetchJsonPromise("/api/whitelist/"),
        this.store.fetchJsonPromise("/api/detection/exclusions"),
        this.store.fetchJsonPromise("/api/data/retention"),
        this.store.fetchJsonPromise("/api/logs/config"),
        this.store.getStorageStats(),
        this.store.fetchJsonPromise("/api/limits"),
        this.store.fetchJsonPromise("/api/monitors/stats"),
      ]);
      const value = (index) => (results[index].status === "fulfilled" ? results[index].value : null);
      this.graphExtras = {
        blacklist: value(2),
        whitelist: value(3),
        exclusions: value(4)?.exclusion_filters || null,
        retentionDays: value(5)?.retention_days ?? null,
      };
      // Indices follow the request list above: logs is 6, storage is 7.
      if (value(7)) this.storageStats = value(7);
      if (value(9)) this.monitorStats = value(9);
      if (value(8)) {
        this.limitsData = value(8);
        if (!this.limitDraft) this.limitDraft = { ...value(8).config };
      }
      if (value(6)) {
        this.logConfig = value(6);
        if (!this.logDraft) this.logDraft = { ...value(6) };
      }
      // Seed the form from the server only on first load: a periodic refresh
      // must not overwrite values the operator is still typing.
      if (results[1].status === "fulfilled") {
        if (!this.pipelineConfig) this.pipelineDraft = { ...results[1].value };
        this.pipelineConfig = results[1].value;
      }
      this.statusRefreshing = false;
    },
    async saveLimits() {
      if (this.limitSaving || !this.limitDraft) return;
      this.limitSaving = true;
      this.limitSaved = false;
      this.limitError = "";
      try {
        const payload = Object.fromEntries(
          ["cpu_percent", "ram_mb", "storage_mb", "resume_percent", "sample_seconds", "cooldown_seconds"].map((f) => [f, Number(this.limitDraft[f])]),
        );
        this.limitsData = await this.store.fetchJsonPromise("/api/limits", { method: "POST", body: JSON.stringify(payload) });
        this.limitDraft = { ...this.limitsData.config };
        this.limitSaved = true;
      } catch (err) {
        this.limitError = err.message || "No se pudieron guardar los límites.";
      } finally {
        this.limitSaving = false;
      }
    },
    async resetLimitCounters() {
      if (this.limitResetting) return;
      this.limitResetting = true;
      this.limitError = "";
      try {
        this.limitsData = await this.store.fetchJsonPromise("/api/limits/reset", { method: "POST" });
      } catch (err) {
        this.limitError = err.message || "No se pudieron reiniciar los contadores.";
      } finally {
        this.limitResetting = false;
      }
    },
    async saveLogConfig() {
      if (this.logSaving || !this.logDraft) return;
      this.logSaving = true;
      this.logSaved = false;
      this.logError = "";
      try {
        const payload = Object.fromEntries(
          ["level", "max_mb", "backups", "retention_days", "slow_ms"].map((field) => [field, this.logDraft[field]]),
        );
        this.logConfig = await this.store.fetchJsonPromise("/api/logs/config", {
          method: "POST",
          body: JSON.stringify(payload),
        });
        this.logDraft = { ...this.logConfig };
        this.logSaved = true;
      } catch (err) {
        this.logError = err.message || "No se pudo guardar la configuración de logs.";
      } finally {
        this.logSaving = false;
      }
    },
    async loadLogTail() {
      if (this.logTailLoading) return;
      this.logTailLoading = true;
      this.logTailError = "";
      try {
        const params = new URLSearchParams({ source: this.logSource, lines: String(this.logLines) });
        if (this.logLevel) params.set("level", this.logLevel);
        const payload = await this.store.fetchJsonPromise(`/api/logs/tail?${params.toString()}`);
        this.logRows = (payload.rows || []).slice().reverse();
      } catch (err) {
        this.logRows = [];
        this.logTailError = err.message || "No se pudo leer el log.";
      } finally {
        this.logTailLoading = false;
      }
    },
    logExtras(row) {
      const skip = new Set(["timestamp", "level", "logger", "message", "module", "function", "line"]);
      const extras = Object.entries(row).filter(([key]) => !skip.has(key));
      return extras.length ? extras.map(([key, value]) => `${key}=${typeof value === "object" ? JSON.stringify(value) : value}`).join(" ") : "";
    },
    async resetPipelineCounters() {
      if (this.pipelineResetting) return;
      this.pipelineResetting = true;
      this.pipelineError = "";
      try {
        await this.store.fetchJsonPromise("/api/pipeline/reset", { method: "POST" });
        await this.refreshGraph();
      } catch (err) {
        this.pipelineError = err.message || "No se pudieron reiniciar los contadores.";
      } finally {
        this.pipelineResetting = false;
      }
    },
    async savePipelineConfig() {
      if (this.pipelineSaving) return;
      const fields = { cache_limit: "Límite de retención", jobs: "Número de jobs" };
      for (const [field, label] of Object.entries(fields)) {
        if (!Number.isInteger(Number(this.pipelineDraft[field])) || this.pipelineDraft[field] === "") {
          this.pipelineError = `${label}: introduce un número entero.`;
          return;
        }
      }
      this.pipelineSaving = true;
      this.pipelineError = "";
      try {
        const saved = await this.store.fetchJsonPromise("/api/pipeline/config", {
          method: "POST",
          body: JSON.stringify({
            cache_limit: Number(this.pipelineDraft.cache_limit),
            jobs: Number(this.pipelineDraft.jobs),
            persist_mode: this.pipelineDraft.persist_mode,
          }),
        });
        this.pipelineConfig = saved;
        this.pipelineDraft = { ...saved };
      } catch (err) {
        this.pipelineError = err.message || "No se pudo guardar la configuración de la caché.";
      } finally {
        this.pipelineSaving = false;
      }
    },
    async toggleEngine(engine, enabled) {
      if (this.enginePending) return;
      this.enginePending = engine;
      this.engineError = "";
      try {
        await this.store.controlEngine(engine, enabled ? "start" : "stop");
      } catch (err) {
        this.engineError = err.message || "No se pudo cambiar el estado del motor.";
      } finally {
        this.enginePending = "";
      }
    },
    formatTimestamp,
    matchesSearch,
    mobilePairingStatusLabel(value) {
      const labels = {
        waiting: "esperando",
        pending: "pendiente",
        awaiting_approval: "esperando aprobación",
        "awaiting approval": "esperando aprobación",
        paired: "vinculado",
        expired: "expirado",
        closed: "cerrado",
      };
      return labels[String(value || "").trim().toLowerCase()] || String(value || "pendiente");
    },
    async loadMobileStream() {
      this.mobileLoading = true;
      this.mobileError = "";
      try {
        const [interfaces, status] = await Promise.all([
          this.store.listMobileStreamInterfaces(),
          this.store.getMobileStreamStatus(),
        ]);
        this.mobileInterfaces = Array.isArray(interfaces.interfaces) ? interfaces.interfaces : [];
        this.mobileStatus = status || {};
        if (!this.mobileInterface) {
          const current = String(status?.interface || "");
          const fallback = this.mobileInterfaceOptions[0]?.name || "";
          this.mobileInterface = current || fallback;
        }
        if (Number(status?.port)) this.mobilePort = Number(status.port);
      } catch (err) {
        this.mobileError = err.message || "No se pudo cargar la configuración del stream móvil.";
      } finally {
        this.mobileLoading = false;
      }
    },
    async createMobilePairing() {
      if (!this.mobileInterface || this.mobilePairingBusy) return;
      this.mobilePairingBusy = true;
      this.mobileError = "";
      clearInterval(this.mobilePairingTimer);
      try {
        const payload = await this.store.createMobileStreamPairing(this.mobileInterface, this.mobilePort);
        this.mobilePairing = payload || {};
        this.mobileStatus = payload.server || this.mobileStatus;
        this.mobileQrDataUrl = payload.url
          ? await QRCode.toDataURL(payload.url, { margin: 1, width: 240, errorCorrectionLevel: "M" })
          : "";
        this.mobilePairingTimer = setInterval(this.refreshMobilePairing, 1500);
      } catch (err) {
        this.mobileError = err.message || "No se pudo crear el QR de vinculación móvil.";
      } finally {
        this.mobilePairingBusy = false;
      }
    },
    async approveMobilePairing() {
      if (!this.mobilePairing.id || this.mobileApproving) return;
      this.mobileApproving = true;
      this.mobileError = "";
      try {
        // The response already carries the freshly issued code, so the
        // operator sees it without waiting for the next poll tick.
        this.mobilePairing = await this.store.approveMobileStreamPairing(this.mobilePairing.id);
      } catch (err) {
        this.mobileError = err.message || "No se pudo aprobar el dispositivo.";
      } finally {
        this.mobileApproving = false;
      }
    },
    async refreshMobilePairing() {
      if (!this.mobilePairing.id) return;
      try {
        this.mobilePairing = await this.store.getMobileStreamPairing(this.mobilePairing.id);
        const status = String(this.mobilePairing.status || "");
        if (["paired", "closed", "expired"].includes(status) || Number(this.mobilePairing.expires_in || 0) <= 0) {
          clearInterval(this.mobilePairingTimer);
          await this.loadMobileStream();
        }
      } catch {
        clearInterval(this.mobilePairingTimer);
        await this.loadMobileStream();
      }
    },
    async stopMobileStream() {
      this.mobileStopping = true;
      this.mobileError = "";
      try {
        this.mobileStatus = await this.store.stopMobileStreamServer();
        this.mobilePairing = {};
        this.mobileQrDataUrl = "";
        clearInterval(this.mobilePairingTimer);
      } catch (err) {
        this.mobileError = err.message || "No se pudo detener el stream móvil.";
      } finally {
        this.mobileStopping = false;
      }
    },
    async revokeMobileSession(token) {
      this.mobileRevoking = token;
      this.mobileError = "";
      try {
        await this.store.revokeMobileStreamSession(token);
        await this.loadMobileStream();
      } catch (err) {
        this.mobileError = err.message || "No se pudo revocar la sesión móvil.";
      } finally {
        this.mobileRevoking = "";
      }
    },
    // Capture
    loadLocation() {
      this.store
        .getDeclaredLocation()
        .then((payload) => this.applyLocation(payload))
        .catch((err) => {
          this.locationError = (err && err.message) || "No se pudo cargar la ubicación del sensor";
        });
    },
    applyLocation(payload) {
      const row = payload && typeof payload === "object" ? payload : {};
      const lat = Number.isFinite(row.lat) ? row.lat : null;
      const lon = Number.isFinite(row.lon) ? row.lon : null;
      this.locationSaved = { lat, lon, label: row.label || "", configured: Boolean(row.configured) };
      this.locationDraft = { lat, lon, label: row.label || "" };
    },
    saveLocation() {
      if (this.locationSubmitting || !this.locationDraftValid) return;
      this.locationSubmitting = true;
      this.locationError = "";
      this.store
        .setDeclaredLocation(this.locationDraft.lat, this.locationDraft.lon, this.locationDraft.label)
        .then((payload) => this.applyLocation(payload))
        .catch((err) => {
          this.locationError = (err && err.message) || "No se pudo guardar la ubicación del sensor";
        })
        .finally(() => {
          this.locationSubmitting = false;
        });
    },
    clearLocation() {
      if (this.locationSubmitting) return;
      this.locationSubmitting = true;
      this.locationError = "";
      this.store
        .clearDeclaredLocation()
        .then((payload) => this.applyLocation(payload))
        .catch((err) => {
          this.locationError = (err && err.message) || "No se pudo borrar la ubicación del sensor";
        })
        .finally(() => {
          this.locationSubmitting = false;
        });
    },
    loadDetectionScopes() {
      this.store
        .getDetectionScopes()
        .then((payload) => {
          this.detectionScopeCatalog = Array.isArray(payload && payload.available_scopes)
            ? payload.available_scopes
            : [];
          this.detectionScopes = Array.isArray(payload && payload.exclude_scopes)
            ? payload.exclude_scopes
            : [];
        })
        .catch((err) => {
          this.detectionScopesError = (err && err.message) || "No se pudo cargar el filtro de alcance de detección";
        });
    },
    async loadStorageStats() {
      this.storageLoading = true;
      this.storageError = "";
      try {
        this.storageStats = await this.store.getStorageStats();
      } catch (err) {
        this.storageError = (err && err.message) || "No se pudieron cargar las estadísticas de almacenamiento.";
      } finally {
        this.storageLoading = false;
      }
    },
    openCompact() {
      this.compactResult = "";
      this.storageError = "";
      this.compactDialog = true;
    },
    async confirmCompact() {
      if (this.compacting) return;
      this.compacting = true;
      this.storageError = "";
      this.compactResult = "";
      try {
        const result = await this.store.compactDatabase();
        const before = result && result.before ? result.before.file_bytes : null;
        const after = result && result.after ? result.after.file_bytes : null;
        if (Number.isFinite(before) && Number.isFinite(after)) {
          const saved = Math.max(0, before - after);
          this.compactResult = saved > 0
            ? `Completado. Se liberaron ${this.formatDbBytes(saved)} (${this.formatDbBytes(before)} → ${this.formatDbBytes(after)}).`
            : `Completado. El archivo ya estaba optimizado (${this.formatDbBytes(after)}).`;
        } else {
          this.compactResult = "Compactación completada.";
        }
        this.compactDialog = false;
        await this.loadStorageStats();
      } catch (err) {
        this.storageError = (err && err.message) || "Falló la compactación.";
        this.compactDialog = false;
      } finally {
        this.compacting = false;
      }
    },
    async loadRetentionConfig() {
      this.retentionLoading = true;
      try {
        this.retentionConfig = await this.store.getRetentionConfig();
        this.retentionDraft = this.retentionDraftFrom(this.retentionConfig);
      } catch {
        // Non-critical: the tab still works without it
      } finally {
        this.retentionLoading = false;
      }
    },
    formatDbBytes(value) {
      const n = Number(value || 0);
      if (!Number.isFinite(n) || n <= 0) return "0 B";
      if (n >= 1073741824) return `${(n / 1073741824).toFixed(2)} GB`;
      if (n >= 1048576) return `${(n / 1048576).toFixed(1)} MB`;
      if (n >= 1024) return `${(n / 1024).toFixed(0)} KB`;
      return `${n} B`;
    },
    retentionFieldHint(field, envName) {
      const config = this.retentionConfig;
      if (!config) return envName;
      const overridden = this.retentionOverridden(field);
      return overridden ? `Propio: ${config[field]} · Por defecto (${envName}): ${config.defaults[field]}` : `Por defecto: ${envName}`;
    },
    retentionOverridden(key) {
      return Boolean(this.retentionConfig && this.retentionConfig.overridden && this.retentionConfig.overridden.includes(key));
    },
    retentionTableOrigin(table) {
      if (this.retentionOverridden(`limit_${table}`)) return "valor propio";
      if (["packets", "payloads", "flows"].includes(table)) return "= base de paquetes";
      if (table === "tags") return "= base × 2";
      return "fijo";
    },
    async saveRetentionConfig() {
      if (!this.retentionConfig || !this.retentionDraft) return;
      const config = this.retentionConfig;
      const payload = {};
      for (const field of ["retention_days", "retention_alert_days", "retention_interval_seconds", "retention_max_packets"]) {
        const value = Number(this.retentionDraft[field]);
        if (Number.isFinite(value) && value !== config[field]) payload[field] = value;
      }
      const tables = {};
      for (const table of this.retentionTables) {
        const value = Number(this.retentionDraft.table_limits[table]);
        if (Number.isFinite(value) && value !== config.table_limits[table]) tables[table] = value;
      }
      if (Object.keys(tables).length) payload.table_limits = tables;
      await this.submitRetentionPayload(payload);
    },
    async clearRetentionOverride({ table = "" } = {}) {
      if (!this.retentionConfig) return;
      if (table) {
        await this.submitRetentionPayload({ table_limits: { [table]: null } });
        return;
      }
      const payload = {
        retention_days: null,
        retention_alert_days: null,
        retention_interval_seconds: null,
        retention_max_packets: null,
        table_limits: Object.fromEntries(this.retentionTables.map((name) => [name, null])),
      };
      await this.submitRetentionPayload(payload);
    },
    async submitRetentionPayload(payload) {
      if (this.retentionSaving) return;
      this.retentionSaving = true;
      this.retentionError = "";
      this.retentionSaved = false;
      try {
        this.retentionConfig = await this.store.setRetentionConfig(payload);
        this.retentionDraft = this.retentionDraftFrom(this.retentionConfig);
        this.retentionSaved = true;
      } catch (err) {
        this.retentionError = err.message || "No se pudo guardar la política de retención.";
      } finally {
        this.retentionSaving = false;
      }
    },
    retentionDraftFrom(config) {
      return {
        retention_days: config.retention_days,
        retention_alert_days: config.retention_alert_days,
        retention_interval_seconds: config.retention_interval_seconds,
        retention_max_packets: config.retention_max_packets,
        table_limits: { ...config.table_limits },
      };
    },
    openPurge(scope) {
      this.purgeScope = scope;
      this.purgeError = "";
      this.purgeResult = "";
      this.purgeDialog = true;
    },
    confirmPurge() {
      if (this.purging) return;
      const scope = this.purgeScope;
      this.purging = true;
      this.purgeError = "";
      this.store
        .clearDetections(scope)
        .then((payload) => {
          const rows = payload && typeof payload === "object" ? payload : {};
          const detail = Object.entries(rows)
            .filter(([, value]) => Number(value) > 0)
            .map(([table, value]) => `${Number(value).toLocaleString()} ${table}`)
            .join(", ");
          this.purgeResult = detail ? `Eliminado: ${detail}.` : "No quedaba nada por eliminar.";
          this.purgeDialog = false;
          this.store.initRuntime();
        })
        .catch((err) => {
          this.purgeError = (err && err.message) || "No se pudieron limpiar los datos guardados";
        })
        .finally(() => {
          this.purging = false;
        });
    },
    toggleDetectionScope(scope, checked) {
      if (this.detectionScopesSubmitting) return;
      const next = new Set(this.detectionScopes);
      if (checked) {
        next.add(scope);
      } else {
        next.delete(scope);
      }
      const wanted = [...next].sort();
      const previous = [...this.detectionScopes];
      // Optimistic: the checkbox is bound to this array, so without it the box
      // would visibly snap back until the round trip lands.
      this.detectionScopes = wanted;
      this.detectionScopesError = "";
      this.detectionScopesSubmitting = true;
      this.store
        .setDetectionScopes(wanted)
        .then((payload) => {
          this.detectionScopes = Array.isArray(payload && payload.exclude_scopes)
            ? payload.exclude_scopes
            : wanted;
        })
        .catch((err) => {
          this.detectionScopes = previous;
          this.detectionScopesError = (err && err.message) || "No se pudo actualizar el filtro de alcance de detección";
        })
        .finally(() => {
          this.detectionScopesSubmitting = false;
        });
    },
    updateSnifferInterfaces(value) {
      const normalized = Array.isArray(value)
        ? [...new Set(value.map((item) => String(item || "").trim()).filter(Boolean))]
        : [];
      if (this.interfaceSubmitting) {
        return;
      }
      const current = [...this.selectedSnifferInterfaces].sort();
      const incoming = [...normalized].sort();
      if (incoming.length === current.length && incoming.every((item, index) => item === current[index])) {
        return;
      }
      this.interfaceError = "";
      this.interfaceSubmitting = true;
      this.store
        .setSnifferInterfaces(normalized)
        .catch((err) => {
          this.interfaceError = err && err.message ? err.message : "No se pudieron actualizar las interfaces";
        })
        .finally(() => {
          this.interfaceSubmitting = false;
        });
    },
    // Service listeners
    filterListenerRows(value, query, item) {
      const needle = String(query || "").trim().toLowerCase();
      if (!needle) return true;
      const raw = item && item.raw ? item.raw : item;
      const haystack = [raw.proto, raw.port, raw.label, raw.source, this.sourceLabel(raw.source), raw.running ? "running en ejecución" : "stopped detenido"]
        .map((part) => String(part == null ? "" : part).toLowerCase())
        .join(" ");
      return haystack.includes(needle);
    },
    sourceLabel(value) {
      const source = String(value || "").trim().toLowerCase();
      if (source === "builtin") return "Integrado";
      if (source === "custom") return "Personalizado";
      return value || "-";
    },
    loadListeners() {
      return this.store
        .listHoneypotListeners()
        .then((payload) => {
          this.listeners = this.store.extractArray(payload);
          this.listenersError = "";
        })
        .catch((err) => {
          this.listeners = [];
          this.listenersError = (err && err.message) || "No se pudieron cargar los listeners";
        });
    },
    toggleListener(listener, value) {
      if (this.listenerTogglePending) return;
      this.listenerTogglePending = listener.id;
      this.listenersError = "";
      this.store
        .toggleHoneypotListenerEnabled(listener.id, value)
        .then((snapshot) => {
          this.listeners = this.store.extractArray(snapshot && snapshot.listeners);
        })
        .catch((err) => {
          this.listenersError = (err && err.message) || `No se pudo ${value ? "habilitar" : "deshabilitar"} ${listener.id}`;
        })
        .finally(() => {
          this.listenerTogglePending = "";
        });
    },
    openNewListenerDialog() {
      this.newListener = { proto: "tcp", port: null, label: "" };
      this.newListenerError = "";
      this.newListenerDialog = true;
    },
    createListener() {
      const port = Number(this.newListener.port);
      if (!Number.isInteger(port) || port < 1 || port > 65535) {
        this.newListenerError = "El puerto debe ser un número entero entre 1 y 65535";
        return;
      }
      const listenerId = `${this.newListener.proto}/${port}`;
      if (this.listeners.some((item) => item.id === listenerId)) {
        this.newListenerError = `${listenerId} ya existe`;
        return;
      }
      this.newListenerSubmitting = true;
      this.newListenerError = "";
      this.store
        .createHoneypotListener(this.newListener.proto, port, this.newListener.label)
        .then((snapshot) => {
          this.listeners = this.store.extractArray(snapshot && snapshot.listeners);
          this.newListenerDialog = false;
        })
        .catch((err) => {
          this.newListenerError = (err && err.message) || "No se pudo crear el listener";
        })
        .finally(() => {
          this.newListenerSubmitting = false;
        });
    },
    // Detection monitors
    isBusy(id) {
      return Boolean(this.busyIds[id]);
    },
    setBusy(id, value) {
      this.busyIds = { ...this.busyIds, [id]: value };
    },
    severityColor(value) {
      const severity = String(value || "info").trim().toLowerCase();
      if (severity === "critical") return "error";
      if (severity === "high") return "error";
      if (severity === "medium") return "warning";
      if (severity === "low") return "info";
      return "secondary";
    },
    modeLabel(value) {
      const mode = String(value || "").trim().toLowerCase();
      if (mode === "regex") return "Regex";
      if (mode === "stateful") return "Con estado";
      return "Regla";
    },
    modeColor(value) {
      const mode = String(value || "").trim().toLowerCase();
      if (mode === "regex") return "info";
      if (mode === "stateful") return "warning";
      return "primary";
    },
    matchSummary(item) {
      const match = item.match || {};
      const parts = [];
      if (match.protocols && match.protocols.length) parts.push(match.protocols.join("/").toUpperCase());
      if (match.exclude_protocols && match.exclude_protocols.length) parts.push(`sin ${match.exclude_protocols.join("/").toUpperCase()}`);
      if (match.ports && match.ports.length) parts.push(`puertos ${match.ports.join(",")}`);
      if (match.src_ports && match.src_ports.length) parts.push(`origen ${match.src_ports.join(",")}`);
      if (match.dst_ports && match.dst_ports.length) parts.push(`destino ${match.dst_ports.join(",")}`);
      if (match.exclude_ports && match.exclude_ports.length) parts.push(`sin puertos ${match.exclude_ports.join(",")}`);
      if (match.ips && match.ips.length) parts.push(`ips ${match.ips.join(",")}`);
      if (match.exclude_ips && match.exclude_ips.length) parts.push(`sin ips ${match.exclude_ips.join(",")}`);
      if (match.eth_types && match.eth_types.length) {
        parts.push(`eth 0x${match.eth_types.map((value) => Number(value).toString(16)).join(",0x")}`);
      }
      if (match.payload_contains && match.payload_contains.length) {
        parts.push(`contiene "${match.payload_contains.join('", "')}"`);
      }
      if (match.payload_regex && match.payload_regex.length) {
        parts.push(`regex ${match.payload_regex.length === 1 ? match.payload_regex[0] : `${match.payload_regex.length} patrones`}`);
      }
      if (match.payload_regex_exclude && match.payload_regex_exclude.length) {
        parts.push(`sin regex ${match.payload_regex_exclude.length === 1 ? match.payload_regex_exclude[0] : `${match.payload_regex_exclude.length} patrones`}`);
      }
      if (match.min_length) parts.push(`>=${match.min_length}B`);
      if (match.max_length) parts.push(`<=${match.max_length}B`);
      if (match.min_payload_text_length) parts.push(`>=${match.min_payload_text_length} caracteres legibles`);
      if (match.request_only) parts.push("solo solicitudes");
      if (match.all && match.all.length) parts.push(`todas ${match.all.length}`);
      if (match.any && match.any.length) parts.push(`cualquiera ${match.any.length}`);
      if (match.none && match.none.length) parts.push(`ninguna ${match.none.length}`);
      return parts.length ? parts.join(" · ") : "-";
    },
    isValidRegex(pattern) {
      try {
        new RegExp(pattern);
        return true;
      } catch {
        return false;
      }
    },
    toggleFilter(value) {
      this.configSubmitting = true;
      this.configError = "";
      this.store
        .setMonitorConfig({ filter_enabled: Boolean(value) })
        .then((payload) => {
          this.applyMonitorConfig(payload);
        })
        .catch((err) => {
          this.configError = (err && err.message) || "No se pudo actualizar el filtro de persistencia";
        })
        .finally(() => {
          this.configSubmitting = false;
        });
    },
    updateMonitorMinSeverity(value) {
      this.configSubmitting = true;
      this.configError = "";
      this.store
        .setMonitorConfig({ min_severity: String(value || "info") })
        .then((payload) => {
          this.applyMonitorConfig(payload);
        })
        .catch((err) => {
          this.configError = (err && err.message) || "No se pudo actualizar la severidad de monitores";
        })
        .finally(() => {
          this.configSubmitting = false;
        });
    },
    toggleGeneratedInfoFilter(value) {
      this.configSubmitting = true;
      this.configError = "";
      this.store
        .setMonitorConfig({ suppress_generated_info: Boolean(value) })
        .then((payload) => {
          this.applyMonitorConfig(payload);
        })
        .catch((err) => {
          this.configError = (err && err.message) || "No se pudo actualizar el filtro de señales generadas";
        })
        .finally(() => {
          this.configSubmitting = false;
        });
    },
    applyMonitorConfig(payload) {
      const row = payload && typeof payload === "object" ? payload : {};
      this.filterEnabled = Boolean(row.filter_enabled);
      this.monitorMinSeverity = String(row.min_severity || "info");
      this.suppressGeneratedInfo = row.suppress_generated_info !== false;
      this.monitorSeverityCatalog = Array.isArray(row.severity_options)
        ? row.severity_options
        : this.monitorSeverityCatalog;
    },
    toggleEnabled(item, value) {
      this.setBusy(item.id, true);
      this.store
        .toggleMonitorEnabled(item.id, Boolean(value))
        .then(() => this.load())
        .catch((err) => {
          this.error = (err && err.message) || "No se pudo actualizar el monitor";
        })
        .finally(() => {
          this.setBusy(item.id, false);
        });
    },
    removeMonitor(item) {
      if (item.source === "builtin") return;
      const confirmed = typeof window !== "undefined" ? window.confirm(`¿Eliminar el monitor "${item.name}"?`) : true;
      if (!confirmed) return;
      this.setBusy(item.id, true);
      this.store
        .deleteMonitor(item.id)
        .then(() => this.load())
        .catch((err) => {
          this.error = (err && err.message) || "No se pudo eliminar el monitor";
        })
        .finally(() => {
          this.setBusy(item.id, false);
        });
    },
    openCreateDialog() {
      this.editingId = "";
      this.form = emptyForm();
      this.monitorBuilderPanels = ["include"];
      this.formError = "";
      this.dialogOpen = true;
    },
    openRuleDetail(item) {
      this.ruleDetailMonitor = item;
      this.ruleDetailOpen = true;
    },
    openEditDialog(item) {
      const match = item.match || {};
      const action = item.action || {};
      this.editingId = item.id;
      this.form = {
        name: item.name || "",
        description: item.description || "",
        priority: item.priority || 100,
        severity: action.severity || "medium",
        tag: action.tag || "",
        mode: item.mode === "stateful" ? "stateful" : item.mode === "regex" ? "regex" : "rule",
        protocols: Array.isArray(match.protocols) ? [...match.protocols] : [],
        excludeProtocols: Array.isArray(match.exclude_protocols) ? [...match.exclude_protocols] : [],
        ports: Array.isArray(match.ports) ? match.ports.map(String) : [],
        srcPorts: Array.isArray(match.src_ports) ? match.src_ports.map(String) : [],
        dstPorts: Array.isArray(match.dst_ports) ? match.dst_ports.map(String) : [],
        excludePorts: Array.isArray(match.exclude_ports) ? match.exclude_ports.map(String) : [],
        ips: Array.isArray(match.ips) ? [...match.ips] : [],
        excludeIps: Array.isArray(match.exclude_ips) ? [...match.exclude_ips] : [],
        ipRegex: Array.isArray(match.ip_regex) ? [...match.ip_regex] : [],
        excludeIpRegex: Array.isArray(match.exclude_ip_regex) ? [...match.exclude_ip_regex] : [],
        portRegex: Array.isArray(match.port_regex) ? [...match.port_regex] : [],
        excludePortRegex: Array.isArray(match.exclude_port_regex) ? [...match.exclude_port_regex] : [],
        protocolRegex: Array.isArray(match.protocol_regex) ? [...match.protocol_regex] : [],
        excludeProtocolRegex: Array.isArray(match.exclude_protocol_regex) ? [...match.exclude_protocol_regex] : [],
        payloadContains: Array.isArray(match.payload_contains) ? [...match.payload_contains] : [],
        excludePayloadContains: Array.isArray(match.exclude_payload_contains) ? [...match.exclude_payload_contains] : [],
        payloadPrefixHex: Array.isArray(match.payload_prefix_hex) ? [...match.payload_prefix_hex] : [],
        excludePayloadPrefixHex: Array.isArray(match.exclude_payload_prefix_hex) ? [...match.exclude_payload_prefix_hex] : [],
        minLength: match.min_length || null,
        maxLength: match.max_length || null,
        requestOnly: Boolean(match.request_only),
        tcpFlags: Array.isArray(match.tcp_flags) ? [...match.tcp_flags] : [],
        tcpFlagsAny: Array.isArray(match.tcp_flags_any) ? [...match.tcp_flags_any] : [],
        tcpFlagsAll: Array.isArray(match.tcp_flags_all) ? [...match.tcp_flags_all] : [],
        countThreshold: match.count_threshold || null,
        windowSeconds: match.window_seconds || null,
        groupBy: match.group_by || "src_ip",
        payloadRegex: Array.isArray(match.payload_regex) ? [...match.payload_regex] : [],
        payloadRegexExclude: Array.isArray(match.payload_regex_exclude) ? [...match.payload_regex_exclude] : [],
        advancedMatchJson: (match.all && match.all.length) || (match.any && match.any.length) || (match.none && match.none.length)
          ? JSON.stringify(
              {
                ...(match.all && match.all.length ? { all: match.all } : {}),
                ...(match.any && match.any.length ? { any: match.any } : {}),
                ...(match.none && match.none.length ? { none: match.none } : {}),
              },
              null,
              2
            )
          : "",
      };
      this.monitorBuilderPanels = ["include"];
      if (
        this.form.excludeProtocols.length
        || this.form.excludePorts.length
        || this.form.excludeIps.length
        || this.form.excludePayloadContains.length
        || this.form.payloadRegexExclude.length
        || this.form.excludeIpRegex.length
        || this.form.excludePortRegex.length
        || this.form.excludeProtocolRegex.length
      ) {
        this.monitorBuilderPanels.push("exclude");
      }
      if (this.form.advancedMatchJson || this.form.mode === "stateful") {
        this.monitorBuilderPanels.push("advanced");
      }
      this.formError = "";
      this.dialogOpen = true;
    },
    cleanTextList(values) {
      return (Array.isArray(values) ? values : [])
        .map((item) => String(item || "").trim())
        .filter(Boolean);
    },
    cleanNumberList(values) {
      return this.cleanTextList(values)
        .map((item) => Number(item))
        .filter((value) => Number.isInteger(value) && value > 0);
    },
    assignList(target, key, values) {
      if (values.length) target[key] = values;
    },
    assignNumber(target, key, value) {
      const parsed = Number(value);
      if (Number.isFinite(parsed) && parsed > 0) target[key] = Math.floor(parsed);
    },
    buildMatchPayload() {
      const match = {};
      this.assignList(match, "protocols", this.cleanTextList(this.form.protocols));
      this.assignList(match, "exclude_protocols", this.cleanTextList(this.form.excludeProtocols));
      this.assignList(match, "ports", this.cleanNumberList(this.form.ports));
      this.assignList(match, "src_ports", this.cleanNumberList(this.form.srcPorts));
      this.assignList(match, "dst_ports", this.cleanNumberList(this.form.dstPorts));
      this.assignList(match, "exclude_ports", this.cleanNumberList(this.form.excludePorts));
      this.assignList(match, "ips", this.cleanTextList(this.form.ips));
      this.assignList(match, "exclude_ips", this.cleanTextList(this.form.excludeIps));
      this.assignList(match, "ip_regex", this.cleanTextList(this.form.ipRegex));
      this.assignList(match, "exclude_ip_regex", this.cleanTextList(this.form.excludeIpRegex));
      this.assignList(match, "port_regex", this.cleanTextList(this.form.portRegex));
      this.assignList(match, "exclude_port_regex", this.cleanTextList(this.form.excludePortRegex));
      this.assignList(match, "protocol_regex", this.cleanTextList(this.form.protocolRegex));
      this.assignList(match, "exclude_protocol_regex", this.cleanTextList(this.form.excludeProtocolRegex));
      this.assignList(match, "payload_contains", this.cleanTextList(this.form.payloadContains));
      this.assignList(match, "exclude_payload_contains", this.cleanTextList(this.form.excludePayloadContains));
      this.assignList(match, "payload_prefix_hex", this.cleanTextList(this.form.payloadPrefixHex));
      this.assignList(match, "exclude_payload_prefix_hex", this.cleanTextList(this.form.excludePayloadPrefixHex));
      this.assignList(match, "payload_regex", this.cleanTextList(this.form.payloadRegex));
      this.assignList(match, "payload_regex_exclude", this.cleanTextList(this.form.payloadRegexExclude));
      this.assignList(match, "tcp_flags", this.cleanTextList(this.form.tcpFlags));
      this.assignList(match, "tcp_flags_any", this.cleanTextList(this.form.tcpFlagsAny));
      this.assignList(match, "tcp_flags_all", this.cleanTextList(this.form.tcpFlagsAll));
      this.assignNumber(match, "min_length", this.form.minLength);
      this.assignNumber(match, "max_length", this.form.maxLength);
      if (this.form.requestOnly) match.request_only = true;
      if (this.form.mode === "stateful") {
        this.assignNumber(match, "count_threshold", this.form.countThreshold);
        this.assignNumber(match, "window_seconds", this.form.windowSeconds);
        match.group_by = this.form.groupBy || "src_ip";
      }
      const advanced = String(this.form.advancedMatchJson || "").trim();
      if (advanced) {
        Object.assign(match, JSON.parse(advanced));
      }
      return match;
    },
    submitForm() {
      this.formError = "";
      const name = String(this.form.name || "").trim();
      if (!name) {
        this.formError = "El nombre es obligatorio";
        return;
      }
      if (this.regexErrors.length) {
        this.formError = this.regexErrors[0];
        return;
      }
      if (this.advancedJsonError) {
        this.formError = this.advancedJsonError;
        return;
      }
      if (this.form.mode === "regex") {
        const patterns = this.cleanTextList(this.form.payloadRegex);
        if (!patterns.length) {
          this.formError = "Agrega al menos un patrón regex";
          return;
        }
      }
      if (this.form.mode === "stateful") {
        if (!(Number(this.form.countThreshold) > 0) || !(Number(this.form.windowSeconds) > 0)) {
          this.formError = "Los monitores con estado requieren umbral de conteo y ventana en segundos";
          return;
        }
      }
      let match;
      try {
        match = this.buildMatchPayload();
      } catch (err) {
        this.formError = (err && err.message) || "Coincidencia de monitor inválida";
        return;
      }
      const payload = {
        id: this.editingId || undefined,
        name,
        description: String(this.form.description || "").trim(),
        priority: Number(this.form.priority) || 100,
        mode: this.form.mode,
        match,
        action: {
          severity: this.form.severity,
          tag: String(this.form.tag || "").trim(),
          label: name,
        },
      };
      this.formSubmitting = true;
      this.store
        .saveMonitor(payload)
        .then(() => {
          this.dialogOpen = false;
          return this.load();
        })
        .catch((err) => {
          this.formError = (err && err.message) || "No se pudo guardar el monitor";
        })
        .finally(() => {
          this.formSubmitting = false;
        });
    },
    load(options = {}) {
      if (!options.silent) this.loading = true;
      this.error = "";
      return Promise.allSettled([this.store.listMonitors(), this.store.getMonitorConfig()])
        .then(([monitorsRes, configRes]) => {
          if (monitorsRes.status === "fulfilled") {
            this.monitors = this.store.extractArray(monitorsRes.value);
          } else {
            this.monitors = [];
            this.error = (monitorsRes.reason && monitorsRes.reason.message) || "No se pudieron cargar los monitores";
          }
          if (configRes.status === "fulfilled") {
            this.applyMonitorConfig(configRes.value);
            this.configError = "";
          } else {
            this.configError = (configRes.reason && configRes.reason.message) || "No se pudo cargar el estado del filtro de persistencia";
          }
          this.lastUpdated = new Date().toLocaleTimeString();
        })
        .finally(() => {
          this.loading = false;
        });
    },
  },
};
</script>

<style scoped>

.log-tail { max-height: 460px; overflow: auto; font-family: ui-monospace, Consolas, monospace; font-size: 12px; border-radius: 6px; background: rgba(0,0,0,.25); padding: 6px 8px; }
.log-tail__row { display: grid; grid-template-columns: 96px 70px 170px minmax(0, 1fr); gap: 10px; padding: 3px 0; border-bottom: 1px solid rgba(255,255,255,.04); }
.log-tail__time { color: var(--text-dim); }
.log-tail__level { font-weight: 600; color: #8fb8ff; }
.log-tail__row.is-warning .log-tail__level { color: #e4b96c; }
.log-tail__row.is-error .log-tail__level, .log-tail__row.is-critical .log-tail__level { color: #ef7a7a; }
.log-tail__row.is-debug .log-tail__level { color: #7d7f8c; }
.log-tail__logger { color: var(--text-dim); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.log-tail__msg { word-break: break-word; }
.log-tail__extra { color: var(--text-dim); }
.settings-view { min-width: 0; }
.settings-engine { display: flex; align-items: center; justify-content: space-between; gap: 16px; padding: 14px 0; border-bottom: 1px solid #35363e; }
.settings-engine h3 { font-size: 15px; }
.settings-engine span { color: #b1b3be; font-size: 12px; }
.settings-engine .v-switch { flex: 0 0 auto; }
.settings-connection { display: grid; grid-template-columns: auto 1fr; gap: 18px; font-size: 13px; }
.settings-connection dt { color: #a4a6b1; }
.settings-connection dd { margin: 0; overflow-wrap: anywhere; }
.settings-view :deep(.config-overlay__body .data-panel),
.settings-view :deep(.config-overlay__body .v-window-item > .v-card) {
  padding: 0 !important;
  background: transparent !important;
  border: 0;
  box-shadow: none;
  border-radius: 0;
}
.settings-view :deep(.config-overlay__body .v-card__underlay) { display: none; }
.settings-view :deep(.config-overlay__body .panel-pulse) { display: none; }
.settings-view :deep(.config-overlay__body .panel-head) { align-items: flex-start !important; }
.settings-view :deep(.config-overlay__body .panel-head > div) { min-width: 0; flex-wrap: wrap; }
.settings-view :deep(.config-overlay__body .v-btn) { max-width: 100%; }
.settings-view :deep(.config-overlay__body .v-btn__content) { white-space: normal; }
.settings-view :deep(.config-overlay__body .v-window) { overflow: visible; }
.settings-view :deep(.config-overlay__body .v-window-item) { transition: none !important; }
.settings-view :deep(.config-overlay__body .v-window__container) { height: auto !important; }

.interface-card,
.scope-card,
.purge-card,
.location-card,
.listeners-card,
.filter-card,
.notify-card,
.storage-card,
.retention-card {
  border-radius: 8px;
}

.storage-path {
  font-size: 0.78rem;
  word-break: break-all;
  opacity: 0.72;
}

.storage-stat-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 12px;
}

.storage-stat-item {
  padding: 10px 12px;
  border-radius: 8px;
  border: 1px solid rgba(118, 191, 232, 0.12);
  background: rgba(10, 18, 29, 0.55);
}

.retention-field {
  padding: 10px 12px;
  border-radius: 8px;
  border: 1px solid rgba(118, 191, 232, 0.12);
  background: rgba(10, 18, 29, 0.55);
  margin-bottom: 4px;
}

.retention-table {
  background: transparent !important;
}

.retention-table :deep(th) {
  font-size: 0.75rem;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  opacity: 0.7;
  font-weight: 500;
}

.retention-table :deep(td) {
  font-size: 0.82rem;
  border-bottom: 1px solid rgba(255,255,255,0.05) !important;
}

.mono {
  font-family: var(--font-mono);
}

.mode-toggle {
  width: 100%;
}

.monitor-dialog-card {
  max-height: calc(100dvh - 48px);
  display: flex;
  flex-direction: column;
}

.monitor-dialog-body {
  overflow-y: auto;
}

.match-summary {
  /* See the banner-cell note in EntityTablePanel: `overflow-wrap: anywhere`
     drops the cell's min-content width to one character, letting the table
     collapse the column and wrap the text vertically. */
  width: 420px;
  display: -webkit-box;
  -webkit-box-orient: vertical;
  -webkit-line-clamp: 2;
  line-clamp: 2;
  overflow: hidden;
  overflow-wrap: anywhere;
  vertical-align: top;
  font-family: var(--font-mono);
  font-size: 0.85rem;
}

.interface-status {
  min-height: 38px;
  padding: 9px 11px;
  border-radius: 8px;
  border: 1px solid rgba(118, 191, 232, 0.16);
  background: linear-gradient(180deg, rgba(10, 18, 29, 0.82), rgba(9, 15, 24, 0.76));
  color: rgba(229, 239, 249, 0.88);
  font-size: 0.86rem;
  line-height: 1.45;
}

.mobile-qr-wrap {
  max-width: 280px;
}

.mobile-qr {
  display: block;
  width: 240px;
  max-width: 100%;
  aspect-ratio: 1;
  border-radius: 8px;
  background: #fff;
  padding: 10px;
}

/* A User-Agent is long and has no spaces to wrap on; without this the
   approval card stretches instead of wrapping. */
.mobile-approval-ua {
  font-family: var(--font-mono);
  overflow-wrap: anywhere;
}

.mobile-code-box {
  min-height: 144px;
  display: flex;
  flex-direction: column;
  justify-content: center;
  gap: 8px;
  padding: 16px;
  border-radius: 8px;
  border: 1px solid rgba(118, 191, 232, 0.16);
  background: linear-gradient(180deg, rgba(10, 18, 29, 0.82), rgba(9, 15, 24, 0.76));
}

.mobile-code {
  font-family: var(--font-mono);
  font-size: 2rem;
  line-height: 1;
  letter-spacing: 0;
}

.settings-view :deep(.v-field) {
  border-radius: 8px;
}

@media (max-width: 600px) {
  .log-tail__row { grid-template-columns: 96px minmax(0, 1fr); gap: 4px 8px; padding-block: 8px; }
  .log-tail__logger, .log-tail__msg { grid-column: 1 / -1; }
  .settings-connection { grid-template-columns: minmax(0, 1fr); gap: 4px; }
  .settings-connection dd { margin-bottom: 12px; }
  .storage-stat-grid { grid-template-columns: minmax(0, 1fr); }
  .settings-engine { gap: 10px; }
}
</style>
