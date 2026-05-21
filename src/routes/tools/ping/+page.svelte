<script lang="ts">
  import { onMount } from 'svelte';
  import { invoke } from '@tauri-apps/api/core';
  import { save, open } from '@tauri-apps/plugin-dialog';
  import { writeFile, readFile } from '@tauri-apps/plugin-fs';
  import { tr } from '$lib/i18n';


  interface PingResponse {
    sequence: number;
    rtt: number | null;
    bytes: number;
    status: string;
    error_message: string | null;
  }

  interface PingResult {
    target: string;
    packet_sent: number;
    packet_received: number;
    packet_loss: number;
    min_rtt: number | null;
    max_rtt: number | null;
    avg_rtt: number | null;
    std_dev_rtt: number | null;
    status: string;
    error_message: string | null;
    ping_responses: PingResponse[];
  }

  interface PingHistoryRecord {
    id: number;
    target_host: string;
    packet_sent: number;
    packet_received: number;
    packet_loss: number;
    min_rtt: number | null;
    max_rtt: number | null;
    avg_rtt: number | null;
    std_dev_rtt: number | null;
    status: string;
    error_message: string | null;
    created_at: string;
  }

  let target = '';

  let count = 4;
  let timeout = 2;
  let interval = 1;
  let packetSize = 64;
  let pinging = false;
  let results: PingResult[] = [];
  let error = '';
  let currentTab = 'ping';
  let history: PingHistoryRecord[] = [];
  let loadingHistory = false;
  let historyError = '';
  let showHistoryDetail = false;
  let selectedHistoryItem: PingHistoryRecord | null = null;
  let showExportMenu = false;
  let showConfirmDialog = false;
  let confirmDialogTitle = '';
  let confirmDialogMessage = '';
  let confirmAction: (() => Promise<void>) | null = null;
  let showHelpModal = false;

  onMount(() => {
    if (currentTab === 'history') {
      loadHistory();
    }
  });

  async function performPing() {
    if (!target.trim()) {
      error = $tr('ping.errors.emptyTarget');
      return;
    }

    pinging = true;
    error = '';
    results = [];

    const targets = target.split(',').map(t => t.trim()).filter(t => t);

    try {
      for (const t of targets) {
        try {
          const result = await invoke<PingResult>('ping', {
            target: t,
            count: count,
            timeout: timeout,
            interval: interval,
            packetSize: packetSize,
            targetId: selectedTargetIds.length > 0 ? selectedTargetIds[0] : null,
          });

          results = [...results, result];

          await invoke('save_ping_result', {
            result: {
              target_host: result.target,
              packet_sent: result.packet_sent,
              packet_received: result.packet_received,
              packet_loss: result.packet_loss,
              min_rtt: result.min_rtt,
              max_rtt: result.max_rtt,
              avg_rtt: result.avg_rtt,
              std_dev_rtt: result.std_dev_rtt,
              status: result.status,
              error_message: result.error_message,
              created_at: new Date().toISOString(),
            },
          });
        } catch (e: any) {
          error = $tr('ping.errors.pingFailed', { error: e.toString() });
        }
      }
    } finally {
      pinging = false;
    }
  }

  let showTargetSelector = false;
  let targetList: any[] = [];
  let selectedTargets: any[] = [];
  let selectedTargetIds: number[] = [];
  let loadingTargets = false;
  let targetSearchQuery = '';
  
  $: filteredTargets = targetList.filter(t => 
    !targetSearchQuery || 
    t.name.toLowerCase().includes(targetSearchQuery.toLowerCase()) ||
    t.target_value.toLowerCase().includes(targetSearchQuery.toLowerCase())
  );

  async function openTargetSelector() {
    showTargetSelector = true;
    await loadTargets();
  }

  async function loadTargets() {
    loadingTargets = true;
    try {
      const result = await invoke<{ targets: any[], total: number }>('target_manager', {
        action: 'list',
        page: 1,
        pageSize: 100
      });
      targetList = result.targets || [];
    } catch (e) {
      console.error('Failed to load targets:', e);
      targetList = [];
    } finally {
      loadingTargets = false;
    }
  }

  function toggleTargetSelection(t: any) {
    const index = selectedTargets.findIndex(st => st.id === t.id);
    if (index >= 0) {
      selectedTargets.splice(index, 1);
      selectedTargets = selectedTargets;
    } else {
      selectedTargets = [...selectedTargets, t];
    }
  }

  function confirmTargetSelection() {
    if (selectedTargets.length > 0) {
      const targetValues = selectedTargets.map(t => t.target_value).join(',');
      target = target ? `${target},${targetValues}` : targetValues;
      selectedTargetIds = selectedTargets.map(t => t.id).filter((id: number | null): id is number => id !== null);
    }
    showTargetSelector = false;
    selectedTargets = [];
  }

  async function importTargets() {
    try {
      const selected = await open({
        multiple: false,
        filters: [
          {
            name: 'Text',
            extensions: ['txt', 'csv'],
          },
        ],
      });

      if (selected) {
        const contents = await readFile(selected as string);
        const text = new TextDecoder().decode(contents);
        const lines = text
          .split('\n')
          .map((line) => line.trim())
          .filter((line) => line && !line.startsWith('#'));

        target = lines.join(',');
      }
    } catch (e) {
      error = $tr('ping.errors.importFailed', { error: String(e) });
    }
  }

  async function loadHistory() {
    loadingHistory = true;
    historyError = '';

    try {
      history = await invoke<PingHistoryRecord[]>('get_ping_history', {
        limit: 100,
        offset: 0,
      });
    } catch (e) {
      historyError = $tr('ping.errors.loadHistoryFailed', { error: String(e) });
    } finally {
      loadingHistory = false;
    }
  }

  function showConfirm(title: string, message: string, action: () => Promise<void>) {
    confirmDialogTitle = title;
    confirmDialogMessage = message;
    confirmAction = action;
    showConfirmDialog = true;
  }

  async function executeConfirmAction() {
    if (confirmAction) {
      showConfirmDialog = false;
      await confirmAction();
      confirmAction = null;
    }
  }

  function cancelConfirm() {
    showConfirmDialog = false;
    confirmAction = null;
  }

  async function deleteHistoryRecord(id: number) {
    showConfirm(
      $tr('ping.history.messages.deleteConfirm'),
      $tr('ping.history.messages.deleteConfirmMessage'),
      async () => {
        try {
          await invoke('delete_ping_record', { id });
          await loadHistory();
        } catch (e) {
          historyError = $tr('ping.errors.deleteFailed', { error: String(e) });
        }
      }
    );
  }

  async function clearAllHistory() {
    showConfirm(
      $tr('ping.history.messages.clearConfirm'),
      $tr('ping.history.messages.clearConfirmMessage'),
      async () => {
        try {
          await invoke('clear_ping_history');
          await loadHistory();
        } catch (e) {
          historyError = $tr('ping.errors.clearFailed', { error: String(e) });
        }
      }
    );
  }

  function viewHistoryDetail(record: PingHistoryRecord) {
    selectedHistoryItem = record;
    showHistoryDetail = true;
  }

  function formatDateTime(dateStr: string): string {
    const date = new Date(dateStr);
    return date.toLocaleString();
  }

  function formatRtt(rtt: number | null): string {
    if (rtt === null) return '-';
    return `${rtt.toFixed(2)}ms`;
  }

  function getPacketLossColor(loss: number): string {
    if (loss === 0) return '#10b981';
    if (loss < 25) return '#f59e0b';
    if (loss < 50) return '#f97316';
    return '#ef4444';
  }

  function getStatusColor(status: string): string {
    switch (status.toLowerCase()) {
      case 'success':
        return '#10b981';
      case 'failed':
        return '#ef4444';
      default:
        return '#6b7280';
    }
  }

  function handleKeyPress(event: KeyboardEvent) {
    if (event.key === 'Enter' && !pinging) {
      performPing();
    }
  }

  function toggleExportMenu(event: MouseEvent) {
    event.stopPropagation();
    showExportMenu = !showExportMenu;
  }

  function reset() {
    target = '';
    count = 4;
    timeout = 2;
    interval = 1;
    packetSize = 64;
    pinging = false;
    results = [];
    error = '';
  }

  async function exportResults(format: 'json' | 'csv' | 'txt') {
    showExportMenu = false;
    if (results.length === 0) {
      error = $tr('ping.errors.noResults');
      return;
    }

    try {
      let filePath;
      let data: string;

      if (format === 'json') {
        filePath = await save({
          filters: [{ name: 'JSON', extensions: ['json'] }],
          defaultPath: `ping-results-${Date.now()}.json`,
        });
        data = JSON.stringify(results, null, 2);
      } else if (format === 'csv') {
        filePath = await save({
          filters: [{ name: 'CSV', extensions: ['csv'] }],
          defaultPath: `ping-results-${Date.now()}.csv`,
        });
        const headers = ['Target', 'Packets Sent', 'Packets Received', 'Packet Loss', 'Min RTT', 'Max RTT', 'Avg RTT', 'Status'];
        const rows = results.map(r => [
          r.target,
          r.packet_sent,
          r.packet_received,
          r.packet_loss,
          r.min_rtt || '',
          r.max_rtt || '',
          r.avg_rtt || '',
          r.status
        ].join(','));
        data = [headers.join(','), ...rows].join('\n');
      } else {
        filePath = await save({
          filters: [{ name: 'Text', extensions: ['txt'] }],
          defaultPath: `ping-results-${Date.now()}.txt`,
        });
        data = results.map(r => 
          `Target: ${r.target}\nStatus: ${r.status}\nPackets: ${r.packet_sent}/${r.packet_received}\nLoss: ${r.packet_loss}%\nRTT: ${r.min_rtt || 'N/A'}/${r.max_rtt || 'N/A'}/${r.avg_rtt || 'N/A'}`
        ).join('\n\n');
      }

      if (filePath) {
        await writeFile(filePath, new TextEncoder().encode(data));
      }
    } catch (e) {
      error = $tr('ping.errors.exportFailed', { error: String(e) });
    }
  }

  $: if (currentTab === 'history') {
    loadHistory();
  }
</script>

<div class="ping-page">
  <div class="page-header">
    <a href="/" class="back-link">{$tr('common.backToHome')}</a>
    <div class="header-content">
      <div class="title-section">
        <h1 class="page-title">{$tr('ping.title')}</h1>
        <p class="page-subtitle">{$tr('ping.subtitle')}</p>
      </div>
      <button class="help-btn" on:click={() => showHelpModal = true} title={$tr('common.userManual')}>
        {$tr('common.userManual')}
      </button>
    </div>
  </div>

  <div class="tabs">
    <button 
      class="tab-button {currentTab === 'ping' ? 'active' : ''}" 
      on:click={() => currentTab = 'ping'}
    >
      {$tr('ping.tabs.ping')}
    </button>
    <button 
      class="tab-button {currentTab === 'history' ? 'active' : ''}" 
      on:click={() => { currentTab = 'history'; loadHistory(); }}
    >
      {$tr('ping.tabs.history')}
    </button>
  </div>

  {#if currentTab === 'ping'}
    <div class="content-grid">
      <div class="config-section">
        <div class="section-card">
          <h2 class="section-title">{$tr('ping.config.title')}</h2>
          
          <div class="form-group">
            <label for="ping-target">{$tr('ping.labels.target')} *</label>
            <div class="target-input-wrapper">
              <textarea
                id="ping-target"
                bind:value={target}
                placeholder={$tr('ping.placeholders.target')}
                on:keypress={handleKeyPress}
                disabled={pinging}
                rows="6"
                required
              ></textarea>
              <div class="target-buttons">
                <button
                  class="btn-select-target"
                  on:click={openTargetSelector}
                  disabled={pinging}
                >
                  {$tr('ping.buttons.selectTarget')}
                </button>
                <button
                  class="btn-import"
                  on:click={importTargets}
                  disabled={pinging}
                >
                  {$tr('ping.buttons.import')}
                </button>
              </div>
            </div>
            <span class="hint">{$tr('ping.hints.target')}</span>
          </div>

          <div class="form-row">
            <div class="form-group">
              <label for="ping-count">{$tr('ping.labels.count')}</label>
              <input
                id="ping-count"
                type="number"
                bind:value={count}
                min="1"
                max="100"
                disabled={pinging}
              />
            </div>

            <div class="form-group">
              <label for="ping-timeout">{$tr('ping.labels.timeout')}</label>
              <input
                id="ping-timeout"
                type="number"
                bind:value={timeout}
                min="1"
                max="10"
                disabled={pinging}
              />
            </div>
          </div>

          <div class="form-row">
            <div class="form-group">
              <label for="ping-interval">{$tr('ping.labels.interval')}</label>
              <input
                id="ping-interval"
                type="number"
                bind:value={interval}
                min="1"
                max="10"
                disabled={pinging}
              />
            </div>

            <div class="form-group">
              <label for="ping-packet-size">{$tr('ping.labels.packetSize')}</label>
              <input
                id="ping-packet-size"
                type="number"
                bind:value={packetSize}
                min="32"
                max="65507"
                disabled={pinging}
              />
            </div>
          </div>

          <div class="button-group">
            <button
              class="btn-primary"
              on:click={performPing}
              disabled={pinging || !target.trim()}
            >
              {#if pinging}
                <span class="spinner"></span>
                {$tr('ping.buttons.pinging')}
              {:else}
                🚀 {$tr('ping.buttons.ping')}
              {/if}
            </button>

            <button
              class="btn-secondary"
              on:click={reset}
              disabled={pinging}
            >
              🔄 {$tr('ping.buttons.reset')}
            </button>
          </div>
        </div>
      </div>

      <div class="result-section">
        {#if error}
          <div class="error-card">
            <div class="error-icon">⚠️</div>
            <div class="error-message">{error}</div>
          </div>
        {/if}

        {#if results.length > 0}
          <div class="result-card">
            <div class="result-header">
              <h2>{$tr('ping.results.title')} ({results.length})</h2>
              <div class="result-actions">
                <button type="button" class="copy-btn" on:click={() => navigator.clipboard.writeText(JSON.stringify(results, null, 2))}>
                  📋 {$tr('common.copy')}
                </button>
                <div class="export-dropdown">
                  <button type="button" class="export-btn" on:click={toggleExportMenu}>📥 {$tr('common.export')}</button>
                  {#if showExportMenu}
                    <div class="export-menu">
                      <button type="button" on:click={() => exportResults('json')}>{$tr('portScanner.results.exportFormats.json')}</button>
                      <button type="button" on:click={() => exportResults('csv')}>{$tr('portScanner.results.exportFormats.csv')}</button>
                      <button type="button" on:click={() => exportResults('txt')}>{$tr('portScanner.results.exportFormats.txt')}</button>
                    </div>
                  {/if}
                </div>
              </div>
            </div>
            
            {#each results as result}
              <div class="ping-result-item">
                <div class="ping-result-header">
                  <h3>{result.target}</h3>
                  <span
                    class="status-badge"
                    style="background-color: {getStatusColor(result.status)}20; color: {getStatusColor(result.status)}"
                  >
                    {result.status}
                  </span>
                </div>

                <div class="result-stats">
                  <div class="stat-item">
                    <span class="stat-label">{$tr('ping.results.packets')}</span>
                    <span class="stat-value">{result.packet_sent} / {result.packet_received}</span>
                  </div>

                  <div class="stat-item">
                    <span class="stat-label">{$tr('ping.results.loss')}</span>
                    <span
                      class="stat-value"
                      style="color: {getPacketLossColor(result.packet_loss)}"
                    >
                      {result.packet_loss.toFixed(1)}%
                    </span>
                  </div>

                  <div class="stat-item">
                    <span class="stat-label">{$tr('ping.results.min')}</span>
                    <span class="stat-value">{formatRtt(result.min_rtt)}</span>
                  </div>

                  <div class="stat-item">
                    <span class="stat-label">{$tr('ping.results.max')}</span>
                    <span class="stat-value">{formatRtt(result.max_rtt)}</span>
                  </div>

                  <div class="stat-item">
                    <span class="stat-label">{$tr('ping.results.avg')}</span>
                    <span class="stat-value">{formatRtt(result.avg_rtt)}</span>
                  </div>

                  <div class="stat-item">
                    <span class="stat-label">{$tr('ping.results.stdDev')}</span>
                    <span class="stat-value">{formatRtt(result.std_dev_rtt)}</span>
                  </div>
                </div>

                {#if result.ping_responses && result.ping_responses.length > 0}
                  <div class="responses-table">
                    <table>
                      <thead>
                        <tr>
                          <th>{$tr('ping.results.table.sequence')}</th>
                          <th>{$tr('ping.results.table.status')}</th>
                          <th>{$tr('ping.results.table.rtt')}</th>
                          <th>{$tr('ping.results.table.bytes')}</th>
                        </tr>
                      </thead>
                      <tbody>
                        {#each result.ping_responses as response}
                          <tr>
                            <td>{response.sequence + 1}</td>
                            <td>
                              <span
                                class="status-badge small"
                                style="background-color: {getStatusColor(response.status)}20; color: {getStatusColor(response.status)}"
                              >
                                {response.status}
                              </span>
                            </td>
                            <td>{formatRtt(response.rtt)}</td>
                            <td>{response.bytes}</td>
                          </tr>
                        {/each}
                      </tbody>
                    </table>
                  </div>
                {/if}
              </div>
            {/each}
          </div>
        {:else if !error}
          <div class="empty-state">
            <div class="empty-icon">🌐</div>
            <p>{$tr('ping.results.empty')}</p>
          </div>
        {/if}
      </div>
    </div>
  {:else}
    <div class="history-section">
      <div class="history-header">
        <h2>{$tr('ping.history.title')}</h2>
        <div class="history-actions">
          <button type="button" class="btn-clear-history" on:click={clearAllHistory}>
            🗑️ {$tr('ping.history.actions.clearAll')}
          </button>
        </div>
      </div>

      {#if loadingHistory}
        <div class="loading-state">
          <div class="loading-spinner"></div>
          <p>{$tr('common.loading')}</p>
        </div>
      {:else if historyError}
        <div class="error-state">
          <p>{historyError}</p>
          <button type="button" on:click={loadHistory}>{$tr('common.retry')}</button>
        </div>
      {:else if history.length === 0}
        <div class="empty-state">
          <div class="empty-icon">📋</div>
          <p>{$tr('ping.history.messages.noHistory')}</p>
        </div>
      {:else}
        <div class="history-table">
          <table>
            <thead>
              <tr>
                <th>{$tr('ping.history.table.target')}</th>
                <th>{$tr('ping.history.table.packets')}</th>
                <th>{$tr('ping.history.table.loss')}</th>
                <th>{$tr('ping.history.table.avgRtt')}</th>
                <th>{$tr('ping.history.table.status')}</th>
                <th>{$tr('ping.history.table.createdAt')}</th>
                <th>{$tr('ping.history.table.actions')}</th>
              </tr>
            </thead>
            <tbody>
              {#each history as record}
                <tr>
                  <td class="target-cell">{record.target_host}</td>
                  <td>{record.packet_sent} / {record.packet_received}</td>
                  <td style="color: {getPacketLossColor(record.packet_loss)}">
                    {record.packet_loss.toFixed(1)}%
                  </td>
                  <td>{formatRtt(record.avg_rtt)}</td>
                  <td>
                    <span
                      class="status-badge small"
                      style="background-color: {getStatusColor(record.status)}20; color: {getStatusColor(record.status)}"
                    >
                      {record.status}
                    </span>
                  </td>
                  <td>{formatDateTime(record.created_at)}</td>
                  <td class="actions-cell">
                    <button
                      type="button"
                      class="btn-icon"
                      on:click={() => viewHistoryDetail(record)}
                      title={$tr('ping.history.actions.view')}
                    >
                      👁️
                    </button>
                    <button
                      type="button"
                      class="btn-icon danger"
                      on:click={() => deleteHistoryRecord(record.id)}
                      title={$tr('ping.history.actions.delete')}
                    >
                      🗑️
                    </button>
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
    </div>
  {/if}

{#if showConfirmDialog}
  <div class="modal-overlay" role="dialog" aria-modal="true">
    <div class="modal-content confirm-dialog">
      <div class="modal-header">
        <h3>{confirmDialogTitle}</h3>
        <button type="button" class="modal-close" on:click={cancelConfirm}>✕</button>
      </div>
      <div class="modal-body">
        <p>{confirmDialogMessage}</p>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn-cancel" on:click={cancelConfirm}>
          {$tr('common.cancel')}
        </button>
        <button type="button" class="btn-confirm-danger" on:click={executeConfirmAction}>
          {$tr('common.confirm')}
        </button>
      </div>
    </div>
  </div>
{/if}

{#if showHelpModal}
  <div
    class="modal-overlay"
    role="button"
    tabindex="-1"
    on:click={() => showHelpModal = false}
    on:keydown={(e) => e.key === 'Escape' && (showHelpModal = false)}
  >
    <div
      class="modal-content help-modal"
      role="dialog"
      aria-modal="true"
      tabindex="-1"
      on:click|stopPropagation
      on:keydown|stopPropagation
    >
      <div class="modal-header">
        <h2>{$tr('ping.helpModal.title')}</h2>
        <button class="modal-close" on:click={() => showHelpModal = false}>✕</button>
      </div>

      <div class="modal-body">
        <div class="help-section">
          <h3>{$tr('ping.helpModal.overview')}</h3>
          <p>{$tr('ping.helpModal.overviewText')}</p>
          <ul>
            <li>{$tr('ping.helpModal.features.connectivityTest')}</li>
            <li>{$tr('ping.helpModal.features.rttMeasurement')}</li>
            <li>{$tr('ping.helpModal.features.packetLoss')}</li>
            <li>{$tr('ping.helpModal.features.multiTarget')}</li>
            <li>{$tr('ping.helpModal.features.customParams')}</li>
            <li>{$tr('ping.helpModal.features.resultExport')}</li>
            <li>{$tr('ping.helpModal.features.pingHistory')}</li>
          </ul>
        </div>

        <div class="help-section">
          <h3>{$tr('ping.helpModal.targetInput')}</h3>

          <div class="help-subsection">
            <h4>{$tr('ping.helpModal.singleTarget')}</h4>
            <p>{$tr('ping.helpModal.singleTargetDesc')}</p>
            <div class="code-example">
              <code>{$tr('ping.helpModal.singleTargetExamples.example1')}</code>
              <code>{$tr('ping.helpModal.singleTargetExamples.example2')}</code>
              <code>{$tr('ping.helpModal.singleTargetExamples.example3')}</code>
            </div>
          </div>

          <div class="help-subsection">
            <h4>{$tr('ping.helpModal.batchInput')}</h4>
            <p>{$tr('ping.helpModal.batchInputDesc')}</p>
            <div class="code-example">
              <code>{$tr('ping.helpModal.batchInputExamples.example1')}</code>
            </div>
            <p class="help-tip">{$tr('ping.helpModal.batchTip')}</p>
          </div>
        </div>

        <div class="help-section">
          <h3>{$tr('ping.helpModal.configParams')}</h3>

          <div class="param-grid">
            <div class="param-card">
              <h4>{$tr('ping.labels.count')}</h4>
              <p>{$tr('ping.helpModal.params.countDesc')}</p>
              <div class="param-example">{$tr('ping.helpModal.params.countExample')}</div>
            </div>

            <div class="param-card">
              <h4>{$tr('ping.labels.timeout')}</h4>
              <p>{$tr('ping.helpModal.params.timeoutDesc')}</p>
              <div class="param-example">{$tr('ping.helpModal.params.timeoutExample')}</div>
            </div>

            <div class="param-card">
              <h4>{$tr('ping.labels.interval')}</h4>
              <p>{$tr('ping.helpModal.params.intervalDesc')}</p>
              <div class="param-example">{$tr('ping.helpModal.params.intervalExample')}</div>
            </div>

            <div class="param-card">
              <h4>{$tr('ping.labels.packetSize')}</h4>
              <p>{$tr('ping.helpModal.params.packetSizeDesc')}</p>
              <div class="param-example">{$tr('ping.helpModal.params.packetSizeExample')}</div>
            </div>
          </div>
        </div>

        <div class="help-section">
          <h3>{$tr('ping.helpModal.resultsTitle')}</h3>
          <ul>
            <li><strong>{$tr('ping.helpModal.resultFeatures.targetColumn')}</strong></li>
            <li><strong>{$tr('ping.helpModal.resultFeatures.packetsColumn')}</strong></li>
            <li><strong>{$tr('ping.helpModal.resultFeatures.lossColumn')}</strong></li>
            <li><strong>{$tr('ping.helpModal.resultFeatures.rttStats')}</strong></li>
            <li><strong>{$tr('ping.helpModal.resultFeatures.statusColumn')}</strong></li>
            <li><strong>{$tr('ping.helpModal.resultFeatures.exportButton')}</strong></li>
          </ul>
        </div>

        <div class="help-section">
          <h3>{$tr('ping.helpModal.tipsTitle')}</h3>
          <ul>
            <li>{$tr('ping.helpModal.tips.tip1')}</li>
            <li>{$tr('ping.helpModal.tips.tip2')}</li>
            <li>{$tr('ping.helpModal.tips.tip3')}</li>
            <li>{$tr('ping.helpModal.tips.tip4')}</li>
          </ul>
        </div>
      </div>
    </div>
  </div>
{/if}

{#if showHistoryDetail && selectedHistoryItem}
  <div class="modal-overlay">
    <div class="modal-content detail-modal">
      <div class="modal-header">
        <h2>📋 {$tr('ping.history.actions.view')} - {selectedHistoryItem.target_host}</h2>
        <button class="modal-close" on:click={() => (showHistoryDetail = false)}>
          ✕
        </button>
      </div>

      <div class="modal-body">
        <div class="detail-info">
          <div class="detail-item">
            <span class="detail-label">🌐 {$tr('ping.history.table.target')}:</span>
            <span class="detail-value">{selectedHistoryItem.target_host}</span>
          </div>
          <div class="detail-item">
            <span class="detail-label">📦 {$tr('ping.history.table.packets')}:</span>
            <span class="detail-value"
              >{selectedHistoryItem.packet_sent} / {selectedHistoryItem.packet_received}</span
            >
          </div>
          <div class="detail-item">
            <span class="detail-label">📊 {$tr('ping.history.table.loss')}:</span>
            <span
              class="detail-value"
              style="color: {getPacketLossColor(selectedHistoryItem.packet_loss)}"
            >
              {selectedHistoryItem.packet_loss.toFixed(1)}%
            </span>
          </div>
          <div class="detail-item">
            <span class="detail-label">⏱️ {$tr('ping.results.min')}:</span>
            <span class="detail-value">{formatRtt(selectedHistoryItem.min_rtt)}</span>
          </div>
          <div class="detail-item">
            <span class="detail-label">⏱️ {$tr('ping.results.max')}:</span>
            <span class="detail-value">{formatRtt(selectedHistoryItem.max_rtt)}</span>
          </div>
          <div class="detail-item">
            <span class="detail-label">⏱️ {$tr('ping.results.avg')}:</span>
            <span class="detail-value">{formatRtt(selectedHistoryItem.avg_rtt)}</span>
          </div>
          <div class="detail-item">
            <span class="detail-label">⏱️ {$tr('ping.results.stdDev')}:</span>
            <span class="detail-value">{formatRtt(selectedHistoryItem.std_dev_rtt)}</span>
          </div>
          <div class="detail-item">
            <span class="detail-label">📊 {$tr('ping.history.table.status')}:</span>
            <span
              class="detail-value"
              style="color: {getStatusColor(selectedHistoryItem.status)}"
            >
              {selectedHistoryItem.status}
            </span>
          </div>
          <div class="detail-item">
            <span class="detail-label">🕐 {$tr('ping.history.table.createdAt')}:</span>
            <span class="detail-value">{formatDateTime(selectedHistoryItem.created_at)}</span>
          </div>
        </div>
      </div>
    </div>
  </div>
{/if}

{#if showTargetSelector}
  <div 
    class="modal-overlay" 
    role="button"
    tabindex="-1"
    on:click={() => showTargetSelector = false}
    on:keydown={(e) => e.key === 'Escape' && (showTargetSelector = false)}
  >
    <div 
      class="modal-content target-selector-modal" 
      role="dialog"
      aria-modal="true"
      tabindex="-1"
      on:click|stopPropagation
      on:keydown|stopPropagation
    >
      <div class="modal-header">
        <h2>🎯 {$tr('ping.targetSelector.title')}</h2>
        <button class="modal-close" on:click={() => showTargetSelector = false}>✕</button>
      </div>
      
      <div class="modal-body">
        <div class="target-search">
          <input
            type="text"
            bind:value={targetSearchQuery}
            placeholder={$tr('ping.targetSelector.searchPlaceholder')}
          />
        </div>
        
        {#if loadingTargets}
          <div class="loading-message">
            <div class="spinner"></div>
            {$tr('ping.targetSelector.loading')}
          </div>
        {:else if filteredTargets.length === 0}
          <div class="empty-message">
            {#if targetSearchQuery}
              {$tr('ping.targetSelector.noResults')}
            {:else}
              {$tr('ping.targetSelector.noTargets')}
            {/if}
          </div>
        {:else}
          <div class="target-list">
            {#each filteredTargets as t (t.id)}
              <div 
                class="target-item {selectedTargets.findIndex(st => st.id === t.id) >= 0 ? 'selected' : ''}"
                on:click={() => toggleTargetSelection(t)}
                on:keydown={(e) => e.key === 'Enter' && toggleTargetSelection(t)}
                role="button"
                tabindex="0"
              >
                <div class="target-info">
                  <div class="target-name">{t.name}</div>
                  <div class="target-value">{t.target_value}</div>
                  {#if t.description}
                    <div class="target-description">{t.description}</div>
                  {/if}
                </div>
                <div class="target-checkbox">
                  {#if selectedTargets.findIndex(st => st.id === t.id) >= 0}
                    ✓
                  {/if}
                </div>
              </div>
            {/each}
          </div>
        {/if}
      </div>
      
      <div class="modal-footer">
        <div class="selection-info">
          {$tr('ping.targetSelector.selectedCount', { count: selectedTargets.length })}
        </div>
        <div class="modal-actions">
          <button class="btn-cancel" on:click={() => showTargetSelector = false}>
            {$tr('common.cancel')}
          </button>
          <button 
            class="btn-confirm" 
            on:click={confirmTargetSelection}
            disabled={selectedTargets.length === 0}
          >
            {$tr('common.confirm')}
          </button>
        </div>
      </div>
    </div>
  </div>
{/if}
</div>

<style>


	.section-card { background: var(--bg-secondary); border-radius: 12px; padding: 20px; }
  .ping-page {
    min-height: 100vh;
    background: linear-gradient(135deg, #0a0e17 0%, #1a1a2e 100%);
    color: #f1f5f9;
    padding: 2rem;
  }

  .page-header {
    margin-bottom: 2rem;
  }

  .back-link {
    display: inline-block;
    color: #94a3b8;
    text-decoration: none;
    margin-bottom: 1rem;
    transition: color 0.2s;
  }

  .back-link:hover {
    color: #a855f7;
  }

  .header-content {
    display: flex;
    justify-content: space-between;
    align-items: center;
  }

  .page-title {
    font-size: 2rem;
    font-weight: 700;
    background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    margin-bottom: 0.5rem;
  }

  .page-subtitle {
    color: #94a3b8;
    font-size: 1rem;
  }

  .tabs {
    display: flex;
    gap: 0;
    margin-bottom: 2rem;
    border-bottom: 1px solid rgba(168, 85, 247, 0.2);
    padding-bottom: 0.5rem;
  }

  .tab-button {
    padding: 0.75rem 1.5rem;
    background: transparent;
    border: none;
    color: #94a3b8;
    font-size: 1rem;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.2s;
    border-radius: 0.5rem 0.5rem 0 0;
    position: relative;
  }

  .tab-button:hover {
    color: #a855f7;
    background: rgba(168, 85, 247, 0.1);
  }

  .tab-button.active {
    color: #a855f7;
    background: rgba(168, 85, 247, 0.1);
  }

  .tab-button.active::after {
    content: '';
    position: absolute;
    bottom: -0.5rem;
    left: 0;
    right: 0;
    height: 2px;
    background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%);
  }

  .content-grid {
    display: grid;
    grid-template-columns: 400px 1fr;
    gap: 2rem;
    align-items: start;
  }

  .config-section {
    display: flex;
    flex-direction: column;
    gap: 1.5rem;
  }

  .section-card {
    background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
    border: 1px solid rgba(168, 85, 247, 0.2);
    border-radius: 1rem;
    padding: 1.5rem;
  }

  .section-title {
    font-size: 1.25rem;
    font-weight: 600;
    margin-bottom: 1.5rem;
    color: #f1f5f9;
  }

  .form-group {
    margin-bottom: 1.25rem;
  }

  .form-group label {
    display: block;
    font-size: 0.875rem;
    font-weight: 500;
    color: #94a3b8;
    margin-bottom: 0.5rem;
  }

  .form-group input {
    width: 100%;
    padding: 0.75rem;
    background: rgba(10, 14, 23, 0.6);
    border: 1px solid rgba(168, 85, 247, 0.3);
    border-radius: 0.5rem;
    color: #f1f5f9;
    font-size: 0.875rem;
    transition: all 0.2s;
  }

  .form-group input:focus {
    outline: none;
    border-color: #a855f7;
    box-shadow: 0 0 0 3px rgba(168, 85, 247, 0.1);
  }

  .form-group input:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }

  .form-group input::placeholder {
    color: #64748b;
  }

  .target-input-wrapper {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }

  .target-input-wrapper textarea:focus {
    outline: none;
    border-color: #a855f7;
    box-shadow: 0 0 0 3px rgba(168, 85, 247, 0.1);
  }

  .target-input-wrapper textarea::placeholder {
    color: #64748b;
  }

  .target-buttons {
    display: flex;
    gap: 0.5rem;
  }

  .target-buttons button {
    flex: 1;
  }

  .hint {
    display: block;
    font-size: 0.75rem;
    color: #64748b;
    margin-top: 0.375rem;
  }

  .form-row {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1rem;
  }

  .button-group {
    display: flex;
    gap: 1rem;
    margin-top: 1.5rem;
  }

  .btn-primary {
    flex: 1;
    background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%);
    color: white;
    font-weight: 600;
    padding: 0.75rem 1.5rem;
    border: none;
    border-radius: 0.5rem;
    cursor: pointer;
    transition: all 0.2s;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 0.5rem;
  }

  .btn-primary:hover:not(:disabled) {
    transform: translateY(-2px);
    box-shadow: 0 4px 12px rgba(168, 85, 247, 0.4);
  }

  .btn-secondary {
    background: rgba(59, 130, 246, 0.2);
    color: #3b82f6;
    border: 1px solid rgba(59, 130, 246, 0.3);
    font-weight: 600;
    padding: 0.75rem 1.5rem;
    border-radius: 0.5rem;
    cursor: pointer;
    transition: all 0.2s;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 0.5rem;
  }

  .btn-secondary:hover:not(:disabled) {
    background: rgba(59, 130, 246, 0.3);
  }

  .btn-select-target {
    padding: 0.625rem 1rem;
    background: linear-gradient(135deg, #10b981 0%, #059669 100%);
    color: white;
    border: none;
    border-radius: 0.5rem;
    font-size: 0.875rem;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.2s;
    white-space: nowrap;
  }

  .btn-select-target:hover:not(:disabled) {
    background: linear-gradient(135deg, #059669 0%, #047857 100%);
    transform: translateY(-1px);
  }

  .btn-select-target:active {
    transform: translateY(0);
  }

  .btn-import {
    padding: 0.625rem 1rem;
    background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);
    color: white;
    border: none;
    border-radius: 0.5rem;
    font-size: 0.875rem;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.2s;
    white-space: nowrap;
  }

  .btn-import:hover:not(:disabled) {
    background: linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%);
    transform: translateY(-1px);
  }

  .btn-import:active {
    transform: translateY(0);
  }

  .btn-primary:disabled,
  .btn-secondary:disabled,
  .btn-select-target:disabled,
  .btn-import:disabled {
    opacity: 0.5;
    cursor: not-allowed;
    transform: none;
  }

  .spinner {
    width: 16px;
    height: 16px;
    border: 2px solid rgba(255, 255, 255, 0.3);
    border-top-color: white;
    border-radius: 50%;
    animation: spin 0.6s linear infinite;
  }

  @keyframes spin {
    to {
      transform: rotate(360deg);
    }
  }

  .result-section {
    min-height: 400px;
  }

  .error-card {
    background: rgba(239, 68, 68, 0.1);
    border: 1px solid rgba(239, 68, 68, 0.3);
    border-radius: 0.75rem;
    padding: 1.5rem;
    display: flex;
    align-items: center;
    gap: 1rem;
    margin-bottom: 1.5rem;
  }

  .error-icon {
    font-size: 1.5rem;
  }

  .error-message {
    color: #fca5a5;
    font-size: 0.875rem;
  }

  .result-card {
    background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
    border: 1px solid rgba(168, 85, 247, 0.2);
    border-radius: 1rem;
    padding: 1.5rem;
  }

  .result-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 1rem;
  }

  .result-header h2 {
    font-size: 1.25rem;
    font-weight: 600;
    color: #f1f5f9;
  }

  .result-actions {
    display: flex;
    gap: 0.75rem;
  }

  .copy-btn,
  .export-btn {
    background: rgba(168, 85, 247, 0.1);
    border: 1px solid rgba(168, 85, 247, 0.3);
    color: #a855f7;
    padding: 0.5rem 1rem;
    border-radius: 0.5rem;
    cursor: pointer;
    font-size: 0.875rem;
    transition: all 0.2s;
    white-space: nowrap;
  }

  .copy-btn:hover,
  .export-btn:hover {
    background: rgba(168, 85, 247, 0.2);
  }

  .export-dropdown {
    position: relative;
  }

  .export-menu {
    position: absolute;
    top: 100%;
    right: 0;
    margin-top: 0.5rem;
    background: #1a1a2e;
    border: 1px solid rgba(168, 85, 247, 0.3);
    border-radius: 0.5rem;
    overflow: hidden;
    z-index: 10;
    min-width: 120px;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
  }

  .export-menu button {
    display: block;
    width: 100%;
    padding: 0.75rem 1rem;
    background: none;
    border: none;
    color: #f1f5f9;
    text-align: left;
    cursor: pointer;
    transition: background 0.2s;
    white-space: nowrap;
  }

  .export-menu button:hover {
    background: rgba(168, 85, 247, 0.1);
  }

  .ping-result-item {
    background: rgba(10, 14, 23, 0.6);
    border: 1px solid rgba(168, 85, 247, 0.2);
    border-radius: 0.75rem;
    padding: 1.5rem;
    margin-bottom: 1rem;
  }

  .ping-result-item:last-child {
    margin-bottom: 0;
  }

  .ping-result-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 1rem;
    padding-bottom: 1rem;
    border-bottom: 1px solid rgba(168, 85, 247, 0.2);
  }

  .ping-result-header h3 {
    color: #f1f5f9;
    margin: 0;
    font-size: 1.1rem;
    font-weight: 600;
  }

  .status-badge {
    display: inline-block;
    padding: 0.25rem 0.75rem;
    border-radius: 9999px;
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
  }

  .status-badge.small {
    padding: 0.125rem 0.5rem;
    font-size: 0.7rem;
  }

  .result-stats {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
    gap: 1rem;
    margin-bottom: 1.5rem;
  }

  .stat-item {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
  }

  .stat-label {
    color: #94a3b8;
    font-size: 0.8rem;
  }

  .stat-value {
    color: #f1f5f9;
    font-size: 1rem;
    font-weight: 600;
  }

  .responses-table {
    margin-top: 1rem;
    overflow-x: auto;
  }

  .responses-table table {
    width: 100%;
    border-collapse: collapse;
    background: rgba(10, 14, 23, 0.4);
    border-radius: 0.5rem;
    overflow: hidden;
  }

  .responses-table th {
    background: rgba(168, 85, 247, 0.1);
    padding: 0.875rem 1rem;
    text-align: left;
    font-weight: 600;
    color: #a855f7;
    border-bottom: 1px solid rgba(168, 85, 247, 0.2);
    font-size: 0.875rem;
  }

  .responses-table td {
    padding: 0.875rem 1rem;
    border-bottom: 1px solid rgba(168, 85, 247, 0.1);
    color: #f1f5f9;
    font-size: 0.875rem;
  }

  .responses-table tr:hover {
    background: rgba(168, 85, 247, 0.05);
  }

  .empty-state {
    text-align: center;
    padding: 4rem 2rem;
    color: #94a3b8;
  }

  .empty-icon {
    font-size: 4rem;
    margin-bottom: 1rem;
    opacity: 0.5;
  }

  .empty-state p {
    margin: 0;
    font-size: 1.1rem;
  }

  .history-section {
    background: rgba(168, 85, 247, 0.05);
    border: 1px solid rgba(168, 85, 247, 0.2);
    border-radius: 1rem;
    padding: 1.5rem;
  }

  .history-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 1.5rem;
  }

  .history-header h2 {
    color: #a855f7;
    margin: 0;
    font-size: 1.25rem;
  }

  .btn-clear-history {
    display: inline-flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.75rem 1.5rem;
    font-size: 0.9rem;
    font-weight: 600;
    border: none;
    border-radius: 0.5rem;
    cursor: pointer;
    transition: all 0.3s ease;
    background: linear-gradient(135deg, rgba(168, 85, 247, 0.2) 0%, rgba(139, 69, 219, 0.15) 100%);
    color: #a855f7;
    box-shadow: 0 4px 6px -1px rgba(168, 85, 247, 0.2);
  }

  .btn-clear-history:hover {
    background: linear-gradient(135deg, rgba(168, 85, 247, 0.3) 0%, rgba(139, 69, 219, 0.25) 100%);
    transform: translateY(-2px);
    box-shadow: 0 8px 12px -1px rgba(168, 85, 247, 0.3);
  }

  .btn-clear-history:active {
    transform: translateY(0);
  }

  .history-table {
    overflow-x: auto;
  }

  .history-table table {
    width: 100%;
    border-collapse: collapse;
  }

  .history-table th,
  .history-table td {
    padding: 1rem;
    text-align: left;
    border-bottom: 1px solid rgba(168, 85, 247, 0.2);
  }

  .history-table .actions-cell {
    white-space: nowrap;
  }

  .history-table th {
    background: rgba(168, 85, 247, 0.1);
    color: #a855f7;
    font-weight: 600;
    font-size: 0.875rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }

  .history-table tr:hover {
    background: rgba(168, 85, 247, 0.05);
  }

  .target-cell {
    font-family: 'Courier New', monospace;
    color: #60a5fa;
  }

  .btn-icon {
    padding: 0.375rem 0.75rem;
    font-size: 0.875rem;
    border: none;
    border-radius: 0.375rem;
    cursor: pointer;
    transition: all 0.2s;
    margin-right: 0.5rem;
    display: inline-flex;
    align-items: center;
    gap: 0.25rem;
    background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);
    color: white;
  }

  .btn-icon:hover {
    background: linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%);
    transform: translateY(-1px);
  }

  .btn-icon.danger {
    background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
  }

  .btn-icon.danger:hover {
    background: linear-gradient(135deg, #dc2626 0%, #b91c1c 100%);
  }

  .loading-state {
    text-align: center;
    padding: 3rem;
    color: #94a3b8;
  }

  .loading-spinner {
    width: 40px;
    height: 40px;
    border: 3px solid rgba(168, 85, 247, 0.3);
    border-top-color: #a855f7;
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
    margin: 0 auto 1rem;
  }

  .error-state {
    text-align: center;
    padding: 3rem;
    color: #fca5a5;
  }

  .error-state button {
    margin-top: 1rem;
    padding: 0.5rem 1rem;
    background: rgba(239, 68, 68, 0.2);
    border: 1px solid rgba(239, 68, 68, 0.3);
    color: #fca5a5;
    border-radius: 0.375rem;
    cursor: pointer;
  }

  .modal-overlay {
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: rgba(0, 0, 0, 0.8);
    display: flex;
    justify-content: center;
    align-items: center;
    z-index: 1000;
    padding: 2rem;
  }

  .modal-content {
    background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
    border: 1px solid rgba(168, 85, 247, 0.3);
    border-radius: 1rem;
    max-width: 900px;
    width: 100%;
    max-height: 90vh;
    overflow-y: auto;
    box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
  }

  .confirm-dialog {
    max-width: 450px;
    border-color: rgba(239, 68, 68, 0.4);
  }

  .confirm-dialog .modal-header {
    background: linear-gradient(135deg, rgba(239, 68, 68, 0.15) 0%, rgba(185, 28, 28, 0.1) 100%);
    border-bottom: 1px solid rgba(239, 68, 68, 0.3);
  }

  .confirm-dialog .modal-header h3 {
    color: #fca5a5;
    font-size: 1.25rem;
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }

  .confirm-dialog .modal-header h3::before {
    content: '⚠️';
    font-size: 1.5rem;
  }

  .confirm-dialog .modal-body {
    padding: 2rem;
    text-align: center;
  }

  .confirm-dialog .modal-body p {
    color: #d1d5db;
    font-size: 1rem;
    line-height: 1.6;
    margin: 0;
  }

  .confirm-dialog .modal-footer {
    padding: 1.5rem 2rem;
    border-top: 1px solid rgba(239, 68, 68, 0.2);
    display: flex;
    justify-content: flex-end;
    gap: 1rem;
  }

  .btn-cancel {
    padding: 0.75rem 1.5rem;
    background: linear-gradient(135deg, #374151 0%, #1f2937 100%);
    color: #d1d5db;
    border: 1px solid #4b5563;
    border-radius: 0.5rem;
    cursor: pointer;
    transition: all 0.3s ease;
    font-weight: 500;
  }

  .btn-cancel:hover {
    background: linear-gradient(135deg, #4b5563 0%, #374151 100%);
    transform: translateY(-1px);
  }

  .btn-confirm-danger {
    padding: 0.75rem 1.5rem;
    background: linear-gradient(135deg, #dc2626 0%, #b91c1c 100%);
    color: white;
    border: none;
    border-radius: 0.5rem;
    cursor: pointer;
    transition: all 0.3s ease;
    font-weight: 600;
  }

  .btn-confirm-danger:hover {
    background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
    transform: translateY(-1px);
    box-shadow: 0 4px 12px rgba(239, 68, 68, 0.4);
  }

  .detail-modal {
    max-width: 1200px;
    max-height: 85vh;
  }

  .modal-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 1.5rem 2rem;
    border-bottom: 1px solid rgba(168, 85, 247, 0.2);
  }

  .modal-header h2 {
    color: #a855f7;
    margin: 0;
    font-size: 1.5rem;
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }

  .modal-close {
    background: rgba(239, 68, 68, 0.2);
    border: 1px solid rgba(239, 68, 68, 0.3);
    color: #ef4444;
    width: 2rem;
    height: 2rem;
    border-radius: 0.5rem;
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    transition: all 0.2s;
  }

  .modal-close:hover {
    background: rgba(239, 68, 68, 0.3);
    transform: scale(1.1);
  }

  .modal-body {
    padding: 2rem;
  }

  .detail-info {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 1rem;
  }

  .detail-item {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
  }

  .detail-label {
    color: #94a3b8;
    font-size: 0.875rem;
    font-weight: 500;
  }

  .detail-value {
    color: #f1f5f9;
    font-size: 1rem;
  }

  @media (max-width: 768px) {
    .ping-page {
      padding: 1rem;
    }

    .form-row {
      grid-template-columns: 1fr;
    }

    .detail-info {
      grid-template-columns: 1fr;
    }
  }

  .target-selector-modal {
    max-width: 700px;
    max-height: 80vh;
  }

  .target-selector-modal .modal-body {
    max-height: calc(80vh - 200px);
    overflow-y: auto;
  }

  .target-search {
    margin-bottom: 1rem;
  }

  .target-search input {
    width: 100%;
    padding: 0.75rem 1rem;
    background: rgba(255, 255, 255, 0.05);
    border: 1px solid rgba(255, 255, 255, 0.1);
    border-radius: 0.5rem;
    color: #e5e7eb;
    font-size: 0.95rem;
  }

  .target-search input:focus {
    outline: none;
    border-color: #10b981;
    background: rgba(255, 255, 255, 0.08);
  }

  .target-list {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }

  .target-item {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 1rem;
    background: rgba(255, 255, 255, 0.05);
    border: 1px solid rgba(255, 255, 255, 0.1);
    border-radius: 0.5rem;
    cursor: pointer;
    transition: all 0.2s;
  }

  .target-item:hover {
    background: rgba(255, 255, 255, 0.08);
    border-color: rgba(16, 185, 129, 0.3);
  }

  .target-item.selected {
    background: rgba(16, 185, 129, 0.15);
    border-color: #10b981;
  }

  .target-info {
    flex: 1;
  }

  .target-name {
    font-size: 1rem;
    font-weight: 600;
    color: #e5e7eb;
    margin-bottom: 0.25rem;
  }

  .target-value {
    font-size: 0.875rem;
    color: #9ca3af;
    margin-bottom: 0.25rem;
  }

  .target-description {
    font-size: 0.8rem;
    color: #6b7280;
  }

  .target-checkbox {
    width: 2rem;
    height: 2rem;
    display: flex;
    align-items: center;
    justify-content: center;
    background: rgba(16, 185, 129, 0.2);
    border-radius: 0.375rem;
    color: #10b981;
    font-size: 1.25rem;
    font-weight: bold;
  }

  .modal-footer {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 1rem 1.5rem;
    border-top: 1px solid rgba(255, 255, 255, 0.1);
    background: rgba(0, 0, 0, 0.2);
  }

  .selection-info {
    font-size: 0.9rem;
    color: #9ca3af;
  }

  .modal-actions {
    display: flex;
    gap: 0.75rem;
  }

  .btn-cancel, .btn-confirm {
    padding: 0.5rem 1.25rem;
    border-radius: 0.5rem;
    font-size: 0.875rem;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.2s;
  }

  .btn-cancel {
    background: rgba(255, 255, 255, 0.1);
    border: 1px solid rgba(255, 255, 255, 0.2);
    color: #e5e7eb;
  }

  .btn-cancel:hover {
    background: rgba(255, 255, 255, 0.15);
  }

  .btn-confirm {
    background: linear-gradient(135deg, #10b981 0%, #059669 100%);
    border: none;
    color: white;
  }

  .btn-confirm:hover:not(:disabled) {
    background: linear-gradient(135deg, #059669 0%, #047857 100%);
    transform: translateY(-1px);
  }

  .btn-confirm:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .loading-message, .empty-message {
    text-align: center;
    padding: 3rem 1rem;
    color: #9ca3af;
  }

  .spinner {
    width: 2rem;
    height: 2rem;
    border: 3px solid rgba(16, 185, 129, 0.3);
    border-top-color: #10b981;
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
    margin: 0 auto 1rem;
  }

  @keyframes spin {
    to { transform: rotate(360deg); }
  }

  .help-btn {
    padding: 0.75rem 1.5rem;
    background: linear-gradient(135deg, #8b5cf6 0%, #6366f1 100%);
    color: white;
    border: none;
    border-radius: 0.5rem;
    font-size: 0.875rem;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.2s;
    white-space: nowrap;
    box-shadow: 0 4px 6px -1px rgba(139, 92, 246, 0.3);
  }

  .help-btn:hover {
    background: linear-gradient(135deg, #7c3aed 0%, #4f46e5 100%);
    transform: translateY(-2px);
    box-shadow: 0 6px 12px -1px rgba(139, 92, 246, 0.4);
  }

  .help-btn:active {
    transform: translateY(0);
  }

  .help-modal {
    max-width: 900px;
    max-height: 85vh;
  }

  .help-section {
    margin-bottom: 2rem;
  }

  .help-section:last-child {
    margin-bottom: 0;
  }

  .help-section h3 {
    font-size: 1.25rem;
    font-weight: 600;
    color: #a855f7;
    margin-bottom: 1rem;
    padding-bottom: 0.5rem;
    border-bottom: 2px solid rgba(168, 85, 247, 0.2);
  }

  .help-section p {
    color: #cbd5e1;
    line-height: 1.6;
    margin-bottom: 0.75rem;
  }

  .help-section ul {
    list-style: none;
    padding: 0;
    margin: 0.75rem 0;
  }

  .help-section ul li {
    color: #e2e8f0;
    padding: 0.5rem 0;
    padding-left: 1.5rem;
    position: relative;
  }

  .help-section ul li::before {
    content: '•';
    color: #a855f7;
    position: absolute;
    left: 0;
    font-weight: bold;
  }

  .help-subsection {
    margin: 1.5rem 0;
    padding: 1rem;
    background: rgba(168, 85, 247, 0.05);
    border-radius: 0.5rem;
    border-left: 3px solid #a855f7;
  }

  .help-subsection h4 {
    font-size: 1rem;
    font-weight: 600;
    color: #f1f5f9;
    margin-bottom: 0.75rem;
  }

  .code-example {
    background: rgba(0, 0, 0, 0.3);
    border: 1px solid rgba(168, 85, 247, 0.2);
    border-radius: 0.5rem;
    padding: 1rem;
    margin-top: 0.75rem;
  }

  .code-example code {
    display: block;
    color: #00ff88;
    font-family: 'Monaco', 'Menlo', monospace;
    font-size: 0.875rem;
    padding: 0.25rem 0;
  }

  .help-tip {
    background: rgba(59, 130, 246, 0.1);
    border-left: 3px solid #3b82f6;
    padding: 0.75rem 1rem;
    border-radius: 0.25rem;
    color: #93c5fd !important;
    margin-top: 1rem;
  }

  .param-grid {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 1rem;
    margin-top: 1rem;
  }

  .param-card {
    background: rgba(168, 85, 247, 0.05);
    border: 1px solid rgba(168, 85, 247, 0.2);
    border-radius: 0.75rem;
    padding: 1.25rem;
    transition: all 0.2s;
  }

  .param-card:hover {
    background: rgba(168, 85, 247, 0.1);
    border-color: rgba(168, 85, 247, 0.3);
    transform: translateY(-2px);
  }

  .param-card h4 {
    font-size: 1rem;
    font-weight: 600;
    color: #f1f5f9;
    margin-bottom: 0.5rem;
  }

  .param-card p {
    color: #94a3b8;
    font-size: 0.875rem;
    margin-bottom: 0.5rem;
  }

  .param-example {
    color: #00ff88;
    font-family: 'Monaco', 'Menlo', monospace;
    font-size: 0.75rem;
    background: rgba(0, 0, 0, 0.2);
    padding: 0.5rem;
    border-radius: 0.25rem;
    margin-top: 0.5rem;
  }
</style>
