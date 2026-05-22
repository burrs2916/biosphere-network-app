<script lang="ts">
  import { invoke } from '@tauri-apps/api/core';
  import { open } from '@tauri-apps/plugin-dialog';
  import { readFile } from '@tauri-apps/plugin-fs';
  import { t, tr, locale } from '$lib/i18n';


  interface DnsRecord {
    name: string;
    type: string;
    class: string;
    ttl: number;
    data: string;
  }

  interface DnsQueryResult {
    domain: string;
    query_type: string;
    records: DnsRecord[];
    query_time: number;
    dns_server: string | null;
    error: string | null;
  }

  interface BatchQueryResult {
    domain: string;
    result: DnsQueryResult | null;
    error: string | null;
  }

  let domains = '';

  let queryType = 'A';
  let dnsServer = '';
  let timeout = 5;
  let querying = false;
  let batchResults: BatchQueryResult[] = [];
  let error = '';
  let showExportMenu = false;
  let currentPage = 1;
  let pageSize = 10;

  let activeTab = 'query';
  let history: any[] = [];
  let loadingHistory = false;
  let historyError = '';
  let historyCurrentPage = 1;
  let historyPageSize = 20;
  let selectedHistoryItem: any = null;
  let showHistoryDetail = false;
  let showConfirmDialog = false;
  let confirmDialogTitle = '';
  let confirmDialogMessage = '';
  let confirmAction: (() => Promise<void>) | null = null;
  let showHelpModal = false;

  $: queryTypes = [
    { value: 'A', label: $tr('dnsQuery.types.A') },
    { value: 'AAAA', label: $tr('dnsQuery.types.AAAA') },
    { value: 'MX', label: $tr('dnsQuery.types.MX') },
    { value: 'NS', label: $tr('dnsQuery.types.NS') },
    { value: 'CNAME', label: $tr('dnsQuery.types.CNAME') },
    { value: 'TXT', label: $tr('dnsQuery.types.TXT') },
    { value: 'SOA', label: $tr('dnsQuery.types.SOA') },
    { value: 'PTR', label: $tr('dnsQuery.types.PTR') },
    { value: 'ANY', label: $tr('dnsQuery.types.ANY') },
  ];

  $: totalPages = Math.ceil(batchResults.length / pageSize);
  $: paginatedResults = batchResults.slice((currentPage - 1) * pageSize, currentPage * pageSize);
  $: successCount = batchResults.filter(r => r.result && r.result.records.length > 0).length;
  $: failedCount = batchResults.filter(r => r.error || (r.result && r.result.error)).length;

  function cleanDomain(domain: string): string {
    let cleaned = domain.trim();
    
    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
    const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::$|^([0-9a-fA-F]{1,4}:){1,7}:|^([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}$|^([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}$|^([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}$|^([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}$|^([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}$|^[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})$|^:((:[0-9a-fA-F]{1,4}){1,7}|:)$/;
    
    if (ipv4Regex.test(cleaned) || ipv6Regex.test(cleaned)) {
      return cleaned.toLowerCase();
    }
    
    cleaned = cleaned.replace(/^(https?:\/\/)?/, '');
    cleaned = cleaned.replace(/^www\./, '');
    cleaned = cleaned.split('/')[0];
    cleaned = cleaned.split(':')[0];
    return cleaned.toLowerCase();
  }

  function validateDomain(domain: string): boolean {
    const domainRegex = /^[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,}$/i;
    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
    const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::$|^([0-9a-fA-F]{1,4}:){1,7}:|^([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}$|^([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}$|^([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}$|^([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}$|^([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}$|^[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})$|^:((:[0-9a-fA-F]{1,4}){1,7}|:)$/;
    
    return domainRegex.test(domain) || ipv4Regex.test(domain) || ipv6Regex.test(domain);
  }

  function parseDomains(input: string): string[] {
    return input
      .split(/[\n,;]+/)
      .map(d => cleanDomain(d))
      .filter(d => d.length > 0 && validateDomain(d));
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
      const targetValues = selectedTargets.map(t => t.target_value).join('\n');
      domains = domains ? `${domains}\n${targetValues}` : targetValues;
      selectedTargetIds = selectedTargets.map(t => t.id).filter((id: number | null): id is number => id !== null);
    }
    showTargetSelector = false;
    selectedTargets = [];
  }

  async function importDomains() {
    try {
      const selected = await open({
        multiple: false,
        filters: [
          {
            name: 'Text',
            extensions: ['txt', 'csv', 'list']
          }
        ]
      });

      if (selected) {
        const fileData = await readFile(selected as string);
        const content = new TextDecoder('utf-8').decode(fileData);
        
        const domainList = content
          .split(/[\n,;]+/)
          .map(d => cleanDomain(d))
          .filter(d => d && !d.startsWith('#') && validateDomain(d));
        
        if (domainList.length > 0) {
          domains = domainList.join('\n');
          error = '';
        } else {
          error = $tr('dnsQuery.errors.noValidDomains');
        }
      }
    } catch (e) {
      error = $tr('dnsQuery.errors.importFailed', { error: String(e) });
    }
  }

  async function performBatchQuery() {
    const domainList = parseDomains(domains);
    
    if (domainList.length === 0) {
      error = $tr('dnsQuery.errors.emptyDomain');
      return;
    }

    querying = true;
    error = '';
    batchResults = [];
    currentPage = 1;

    console.log('=== Starting DNS query ===');
    console.log('Domains:', domainList);
    console.log('Query type:', queryType);
    console.log('DNS server:', dnsServer || 'System DNS');
    console.log('Timeout:', timeout);

    try {
      for (const domain of domainList) {
        try {
          console.log(`\n--- Querying ${domain} ---`);
          
          const params = {
            domain: domain,
            queryType: queryType,
            dnsServer: dnsServer.trim() || null,
            timeout: timeout,
            targetId: selectedTargetIds.length > 0 ? selectedTargetIds[0] : null,
          };
          
          console.log('Request params:', params);
          
          const response = await invoke<DnsQueryResult>('dns_query', params);

          console.log('Response:', JSON.stringify(response, null, 2));
          console.log('Records count:', response.records?.length || 0);

          batchResults = [...batchResults, {
            domain: domain,
            result: response,
            error: null
          }];
          
          console.log('Added to batchResults, total:', batchResults.length);
        } catch (e: any) {
          console.error('Error querying', domain, ':', e);
          console.error('Error details:', e.message, e.stack);
          batchResults = [...batchResults, {
            domain: domain,
            result: null,
            error: e.toString()
          }];
        }
      }
      
      console.log('\n=== Query completed ===');
      console.log('Total results:', batchResults.length);
      console.log('batchResults:', JSON.stringify(batchResults, null, 2));
    } finally {
      querying = false;
    }
  }

  function handleKeyPress(event: KeyboardEvent) {
    if (event.key === 'Enter' && !querying) {
      performBatchQuery();
    }
  }

  async function exportResults(format: 'json' | 'csv' | 'txt') {
    if (batchResults.length === 0) return;

    let content = '';
    let filename = '';
    let mimeType = '';

    switch (format) {
      case 'json':
        content = JSON.stringify(batchResults, null, 2);
        filename = 'dns_query_results.json';
        mimeType = 'application/json';
        break;
      
      case 'csv':
        const csvLines = ['Domain,Type,Record,Data,TTL'];
        batchResults.forEach(r => {
          if (r.result && r.result.records.length > 0) {
            r.result.records.forEach(record => {
              csvLines.push(`${r.domain},${record.type},${record.name},${record.data},${record.ttl}`);
            });
          } else {
            csvLines.push(`${r.domain},ERROR,,,`);
          }
        });
        content = csvLines.join('\n');
        filename = 'dns_query_results.csv';
        mimeType = 'text/csv';
        break;
      
      case 'txt':
        const txtLines: string[] = [];
        batchResults.forEach(r => {
          txtLines.push(`\n${'='.repeat(60)}`);
          txtLines.push(`Domain: ${r.domain}`);
          if (r.result) {
            txtLines.push(`Query Type: ${r.result.query_type}`);
            txtLines.push(`Query Time: ${r.result.query_time}ms`);
            txtLines.push(`DNS Server: ${r.result.dns_server || 'System DNS'}`);
            if (r.result.records.length > 0) {
              txtLines.push('\nRecords:');
              r.result.records.forEach(record => {
                txtLines.push(`  ${record.type}\t${record.ttl}s\t${record.data}`);
              });
            } else {
              txtLines.push('\nNo records found');
            }
          } else if (r.error) {
            txtLines.push(`Error: ${r.error}`);
          }
        });
        content = txtLines.join('\n');
        filename = 'dns_query_results.txt';
        mimeType = 'text/plain';
        break;
    }

    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
    showExportMenu = false;
  }

  function toggleExportMenu() {
    showExportMenu = !showExportMenu;
  }

  function reset() {
    domains = '';
    batchResults = [];
    error = '';
    currentPage = 1;
  }

  async function loadHistory() {
    loadingHistory = true;
    historyError = '';
    
    try {
      history = await invoke('get_dns_query_history', {
        limit: historyPageSize,
        offset: (historyCurrentPage - 1) * historyPageSize,
      });
    } catch (e) {
      historyError = `${$tr('dnsQuery.history.messages.loadFailed')}: ${e}`;
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

  async function deleteHistoryItem(id: number) {
    showConfirm(
      $tr('dnsQuery.history.messages.deleteConfirm'),
      $tr('dnsQuery.history.messages.deleteConfirmMessage'),
      async () => {
        try {
          await invoke('delete_dns_query', { id });
          await loadHistory();
        } catch (e) {
          historyError = `${$tr('dnsQuery.history.messages.deleteFailed')}: ${e}`;
        }
      }
    );
  }

  async function clearAllHistory() {
    showConfirm(
      $tr('dnsQuery.history.messages.clearAllConfirm'),
      $tr('dnsQuery.history.messages.clearAllConfirmMessage'),
      async () => {
        try {
          await invoke('clear_dns_query_history');
          await loadHistory();
        } catch (e) {
          historyError = `${$tr('dnsQuery.history.messages.clearFailed')}: ${e}`;
        }
      }
    );
  }

  function viewHistoryDetail(item: any) {
    selectedHistoryItem = item;
    showHistoryDetail = true;
  }

  function formatDateTime(dateStr: string): string {
    const date = new Date(dateStr);
    return date.toLocaleString($locale === 'zh' ? 'zh-CN' : 'en-US', {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    });
  }

  function previousPage() {
    if (currentPage > 1) {
      currentPage--;
    }
  }

  function nextPage() {
    if (currentPage < totalPages) {
      currentPage++;
    }
  }
</script>

<div class="dns-query-page">
  <div class="page-header">
    <a href="/" class="back-link">{$tr('common.backToHome')}</a>
    <div class="header-content">
      <div class="title-section">
        <h1 class="page-title">{$tr('dnsQuery.title')}</h1>
        <p class="page-subtitle">{$tr('dnsQuery.subtitle')}</p>
      </div>
      <button class="help-btn" on:click={() => showHelpModal = true} title={$tr('common.userManual')}>
        {$tr('common.userManual')}
      </button>
    </div>
  </div>

  <div class="tabs">
    <button 
      class="tab-button {activeTab === 'query' ? 'active' : ''}" 
      on:click={() => activeTab = 'query'}
    >
      {$tr('dnsQuery.history.tabs.query')}
    </button>
    <button 
      class="tab-button {activeTab === 'history' ? 'active' : ''}" 
      on:click={() => { activeTab = 'history'; loadHistory(); }}
    >
      {$tr('dnsQuery.history.tabs.history')}
    </button>
  </div>

  {#if activeTab === 'query'}
  <div class="content-grid">
    <div class="config-section">
      <div class="section-card">
        <h2 class="section-title">{$tr('portScanner.scanConfig')}</h2>
        
        <form on:submit|preventDefault={performBatchQuery}>
          <div class="form-group">
            <label for="domains">{$tr('dnsQuery.labels.domains')} *</label>
            <div class="target-input-wrapper">
              <textarea
                id="domains"
                bind:value={domains}
                placeholder={$tr('dnsQuery.placeholders.domains')}
                on:keypress={handleKeyPress}
                disabled={querying}
                rows="6"
                required
              ></textarea>
              <div class="target-buttons">
                <button type="button" class="select-target-btn" on:click={openTargetSelector} disabled={querying}>
                  {$tr('dnsQuery.buttons.selectTarget')}
                </button>
                <button type="button" class="import-btn" on:click={importDomains} title={$tr('dnsQuery.buttons.import')}>
                  {$tr('dnsQuery.buttons.import')}
                </button>
              </div>
            </div>
            <span class="input-hint">{$tr('dnsQuery.help.domains')}</span>
          </div>

          <div class="form-group">
            <label for="queryType">{$tr('dnsQuery.labels.queryType')}</label>
            <select id="queryType" bind:value={queryType} disabled={querying}>
              {#each queryTypes as type}
                <option value={type.value}>{type.label}</option>
              {/each}
            </select>
          </div>

          <div class="form-group">
            <label for="dnsServer">{$tr('dnsQuery.labels.dnsServer')}</label>
            <input
              type="text"
              id="dnsServer"
              bind:value={dnsServer}
              placeholder={$tr('dnsQuery.placeholders.dnsServer')}
              disabled={querying}
            />
          </div>

          <div class="form-group">
            <label for="timeout">{$tr('dnsQuery.labels.timeout')}</label>
            <input
              type="number"
              id="timeout"
              bind:value={timeout}
              min="1"
              max="30"
              disabled={querying}
            />
          </div>

          <div class="button-group">
            <button type="submit" class="btn-primary" disabled={querying || !domains.trim()}>
              {#if querying}
                <span class="spinner"></span>
                {$tr('dnsQuery.buttons.querying')}
              {:else}
                {$tr('dnsQuery.buttons.query')}
              {/if}
            </button>
            <button type="button" class="btn-secondary" on:click={reset}>
              {$tr('portScanner.reset')}
            </button>
          </div>
        </form>
      </div>

      <div class="info-card">
        <h3>📖 {$tr('portScanner.usageGuide')}</h3>
        <ul>
          <li>{$tr('portScanner.usageGuideItems.item1')}</li>
          <li>{$tr('portScanner.usageGuideItems.item2')}</li>
          <li>{$tr('portScanner.usageGuideItems.item3')}</li>
          <li>{$tr('dnsQuery.help.removePrefixDesc')}</li>
          <li>{$tr('dnsQuery.help.batchQueryDesc')}</li>
          <li>{$tr('dnsQuery.help.fileImportDesc')}</li>
        </ul>
      </div>
    </div>

    <div class="result-section">
      {#if error}
        <div class="error-card">
          <div class="error-icon">⚠️</div>
          <div class="error-message">{error}</div>
        </div>
      {/if}

      {#if batchResults.length > 0}
        <div class="result-card">
          <div class="result-header">
            <h2>{$tr('dnsQuery.results.title')}</h2>
            <div class="result-actions">
              <div class="export-dropdown">
                <button type="button" class="export-btn" on:click={toggleExportMenu}>📥 {$tr('dnsQuery.buttons.export')}</button>
                {#if showExportMenu}
                  <div class="export-menu">
                    <button type="button" on:click={() => exportResults('json')}>📄 JSON</button>
                    <button type="button" on:click={() => exportResults('csv')}>📊 CSV</button>
                    <button type="button" on:click={() => exportResults('txt')}>📝 TXT</button>
                  </div>
                {/if}
              </div>
            </div>
          </div>
          
          <div class="results-info">
            <span class="results-count">{$tr('dnsQuery.results.total')}: {batchResults.length}</span>
            <span class="results-separator">|</span>
            <span class="success-count">✓ {$tr('dnsQuery.results.success')}: {successCount}</span>
            <span class="results-separator">|</span>
            <span class="failed-count">✗ {$tr('dnsQuery.results.failed')}: {failedCount}</span>
          </div>

          <div class="batch-results">
            {#each paginatedResults as item, index}
              <div class="result-item">
                <div class="result-item-header">
                  <h3 class="domain-name">{item.domain}</h3>
                  <div class="result-meta">
                    {#if item.result}
                      <span class="meta-badge type-badge">{item.result.query_type}</span>
                      <span class="meta-badge time-badge">{item.result.query_time}ms</span>
                      {#if item.result.dns_server}
                        <span class="meta-badge server-badge">DNS: {item.result.dns_server}</span>
                      {/if}
                      <span class="meta-badge count-badge">{item.result.records.length} {$tr('dnsQuery.results.recordsCount')}</span>
                    {/if}
                  </div>
                </div>

                {#if item.result && item.result.records.length > 0}
                  {#if item.result.query_type === 'A' || item.result.query_type === 'AAAA'}
                    <div class="resolved-ips">
                      <span class="resolved-label">{$tr('dnsQuery.results.resolvedIps')}:</span>
                      {#each item.result.records as record}
                        <span class="ip-chip">{record.data}</span>
                      {/each}
                    </div>
                  {/if}
                  {#if item.result.query_type === 'MX'}
                    <div class="resolved-ips">
                      <span class="resolved-label">{$tr('dnsQuery.results.mailServers')}:</span>
                      {#each item.result.records as record}
                        <span class="ip-chip mx-chip">{record.data}</span>
                      {/each}
                    </div>
                  {/if}
                  {#if item.result.query_type === 'NS'}
                    <div class="resolved-ips">
                      <span class="resolved-label">{$tr('dnsQuery.results.nameServers')}:</span>
                      {#each item.result.records as record}
                        <span class="ip-chip ns-chip">{record.data}</span>
                      {/each}
                    </div>
                  {/if}
                  <div class="records-table">
                    <table>
                      <thead>
                        <tr>
                          <th>{$tr('dnsQuery.results.table.type')}</th>
                          <th>{$tr('dnsQuery.results.table.name')}</th>
                          <th>{$tr('dnsQuery.results.table.ttl')}</th>
                          <th>{$tr('dnsQuery.results.table.data')}</th>
                        </tr>
                      </thead>
                      <tbody>
                        {#each item.result.records as record}
                          <tr>
                            <td><span class="record-type">{record.type}</span></td>
                            <td>{record.name}</td>
                            <td>{record.ttl}s</td>
                            <td class="record-data">{record.data}</td>
                          </tr>
                        {/each}
                      </tbody>
                    </table>
                  </div>
                {:else if item.error || (item.result && item.result.error)}
                  <div class="result-error">
                    <span class="error-icon">⚠️</span>
                    {item.error || item.result?.error}
                  </div>
                {:else}
                  <div class="no-records">
                    <span class="no-records-icon">📋</span>
                    {$tr('dnsQuery.results.noRecords')}
                  </div>
                {/if}
              </div>
            {/each}
          </div>

          {#if totalPages > 1}
            <div class="pagination">
              <button 
                class="pagination-btn" 
                disabled={currentPage === 1} 
                on:click={() => currentPage--}
              >
                ← {$tr('portScanner.pagination.previous')}
              </button>
              <span class="pagination-info">
                {currentPage} / {totalPages}
              </span>
              <button 
                class="pagination-btn" 
                disabled={currentPage === totalPages} 
                on:click={() => currentPage++}
              >
                {$tr('portScanner.pagination.next')} →
              </button>
            </div>
          {/if}
        </div>
      {:else}
        <div class="empty-state">
          <div class="empty-icon">🔍</div>
          <p>{$tr('portScanner.results.emptyState')}</p>
        </div>
      {/if}
    </div>
  </div>
  {:else}
  <div class="history-section">
    <div class="history-header">
      <h2>{$tr('dnsQuery.history.title')}</h2>
      <div class="history-actions">
        <button type="button" class="btn-clear-history" on:click={clearAllHistory}>
          🗑️ {$tr('dnsQuery.history.actions.clearAll')}
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
        <p>{$tr('dnsQuery.history.messages.noHistory')}</p>
      </div>
    {:else}
      <div class="history-table">
        <table>
          <thead>
            <tr>
              <th>{$tr('dnsQuery.history.table.domain')}</th>
              <th>{$tr('dnsQuery.history.table.type')}</th>
              <th>{$tr('dnsQuery.history.table.dnsServer')}</th>
              <th>{$tr('dnsQuery.history.table.queryTime')}</th>
              <th>{$tr('dnsQuery.history.table.createdAt')}</th>
              <th>{$tr('dnsQuery.history.table.actions')}</th>
            </tr>
          </thead>
          <tbody>
            {#each history as item (item.id)}
              <tr>
                <td>{item.query_domain}</td>
                <td>{item.query_type}</td>
                <td>{item.dns_server || 'System DNS'}</td>
                <td>{item.query_time}ms</td>
                <td>{formatDateTime(item.created_at)}</td>
                <td class="actions-cell">
                  <button 
                    class="btn-small btn-primary" 
                    on:click|stopPropagation={() => viewHistoryDetail(item)}
                  >
                    👁️ {$tr('dnsQuery.history.actions.view')}
                  </button>
                  <button 
                    type="button"
                    class="btn-small btn-danger" 
                    on:click|stopPropagation={() => deleteHistoryItem(item.id)}
                  >
                    🗑️ {$tr('dnsQuery.history.actions.delete')}
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
        <h2>{$tr('dnsQuery.helpModal.title')}</h2>
        <button class="modal-close" on:click={() => showHelpModal = false}>✕</button>
      </div>

      <div class="modal-body">
        <div class="help-section">
          <h3>{$tr('dnsQuery.helpModal.overview')}</h3>
          <p>{$tr('dnsQuery.helpModal.overviewText')}</p>
          <ul>
            <li>{$tr('dnsQuery.helpModal.features.batchQuery')}</li>
            <li>{$tr('dnsQuery.helpModal.features.multiRecordType')}</li>
            <li>{$tr('dnsQuery.helpModal.features.customDnsServer')}</li>
            <li>{$tr('dnsQuery.helpModal.features.ptrLookup')}</li>
            <li>{$tr('dnsQuery.helpModal.features.resultExport')}</li>
            <li>{$tr('dnsQuery.helpModal.features.queryHistory')}</li>
          </ul>
        </div>

        <div class="help-section">
          <h3>{$tr('dnsQuery.helpModal.inputFormat')}</h3>

          <div class="help-subsection">
            <h4>{$tr('dnsQuery.helpModal.singleDomain')}</h4>
            <p>{$tr('dnsQuery.helpModal.singleDomainDesc')}</p>
            <div class="code-example">
              <code>{$tr('dnsQuery.helpModal.singleDomainExamples.example1')}</code>
              <code>{$tr('dnsQuery.helpModal.singleDomainExamples.example2')}</code>
            </div>
          </div>

          <div class="help-subsection">
            <h4>{$tr('dnsQuery.helpModal.batchInput')}</h4>
            <p>{$tr('dnsQuery.helpModal.batchInputDesc')}</p>
            <div class="code-example">
              <code>{$tr('dnsQuery.helpModal.batchInputExamples.example1')}</code>
              <code>{$tr('dnsQuery.helpModal.batchInputExamples.example2')}</code>
              <code>{$tr('dnsQuery.helpModal.batchInputExamples.example3')}</code>
            </div>
            <p class="help-tip">{$tr('dnsQuery.helpModal.batchTip')}</p>
          </div>

          <div class="help-subsection">
            <h4>{$tr('dnsQuery.helpModal.ptrInput')}</h4>
            <p>{$tr('dnsQuery.helpModal.ptrInputDesc')}</p>
            <div class="code-example">
              <code>{$tr('dnsQuery.helpModal.ptrInputExamples.example1')}</code>
              <code>{$tr('dnsQuery.helpModal.ptrInputExamples.example2')}</code>
            </div>
          </div>
        </div>

        <div class="help-section">
          <h3>{$tr('dnsQuery.helpModal.recordTypes')}</h3>

          <div class="record-type-grid">
            <div class="type-card">
              <h4>A</h4>
              <p>{$tr('dnsQuery.helpModal.recordTypesDesc.aRecord')}</p>
            </div>
            <div class="type-card">
              <h4>AAAA</h4>
              <p>{$tr('dnsQuery.helpModal.recordTypesDesc.aaaaRecord')}</p>
            </div>
            <div class="type-card">
              <h4>CNAME</h4>
              <p>{$tr('dnsQuery.helpModal.recordTypesDesc.cnameRecord')}</p>
            </div>
            <div class="type-card">
              <h4>MX</h4>
              <p>{$tr('dnsQuery.helpModal.recordTypesDesc.mxRecord')}</p>
            </div>
            <div class="type-card">
              <h4>NS</h4>
              <p>{$tr('dnsQuery.helpModal.recordTypesDesc.nsRecord')}</p>
            </div>
            <div class="type-card">
              <h4>PTR</h4>
              <p>{$tr('dnsQuery.helpModal.recordTypesDesc.ptrRecord')}</p>
            </div>
            <div class="type-card">
              <h4>TXT</h4>
              <p>{$tr('dnsQuery.helpModal.recordTypesDesc.txtRecord')}</p>
            </div>
            <div class="type-card">
              <h4>SOA</h4>
              <p>{$tr('dnsQuery.helpModal.recordTypesDesc.soaRecord')}</p>
            </div>
          </div>
        </div>

        <div class="help-section">
          <h3>{$tr('dnsQuery.helpModal.dnsServer')}</h3>
          <p>{$tr('dnsQuery.helpModal.dnsServerDesc')}</p>
          <ul>
            <li><strong>{$tr('dnsQuery.helpModal.dnsServers.google')}</strong></li>
            <li><strong>{$tr('dnsQuery.helpModal.dnsServers.cloudflare')}</strong></li>
            <li><strong>{$tr('dnsQuery.helpModal.dnsServers.systemDns')}</strong></li>
          </ul>
          <div class="code-example">
            <code>{$tr('dnsQuery.helpModal.dnsServerExamples.example1')}</code>
            <code>{$tr('dnsQuery.helpModal.dnsServerExamples.example2')}</code>
          </div>
          <p class="help-tip">{$tr('dnsQuery.helpModal.dnsServerTip')}</p>
        </div>

        <div class="help-section">
          <h3>{$tr('dnsQuery.helpModal.resultsTitle')}</h3>
          <ul>
            <li><strong>{$tr('dnsQuery.helpModal.resultFeatures.domainColumn')}</strong></li>
            <li><strong>{$tr('dnsQuery.helpModal.resultFeatures.typeColumn')}</strong></li>
            <li><strong>{$tr('dnsQuery.helpModal.resultFeatures.recordsColumn')}</strong></li>
            <li><strong>{$tr('dnsQuery.helpModal.resultFeatures.timeColumn')}</strong></li>
            <li><strong>{$tr('dnsQuery.helpModal.resultFeatures.serverColumn')}</strong></li>
            <li><strong>{$tr('dnsQuery.helpModal.resultFeatures.exportButton')}</strong></li>
          </ul>
        </div>

        <div class="help-section">
          <h3>{$tr('dnsQuery.helpModal.tipsTitle')}</h3>
          <ul>
            <li>{$tr('dnsQuery.helpModal.tips.tip1')}</li>
            <li>{$tr('dnsQuery.helpModal.tips.tip2')}</li>
            <li>{$tr('dnsQuery.helpModal.tips.tip3')}</li>
            <li>{$tr('dnsQuery.helpModal.tips.tip4')}</li>
          </ul>
        </div>
      </div>
    </div>
  </div>
{/if}

{#if showHistoryDetail && selectedHistoryItem}
  <div class="modal-overlay">
    <div 
      class="modal-content detail-modal" 
      role="dialog"
      aria-modal="true"
    >
      <div class="modal-header">
        <h2>📋 {$tr('dnsQuery.history.actions.view')} - {selectedHistoryItem.query_domain}</h2>
        <button class="modal-close" on:click={() => showHistoryDetail = false}>✕</button>
      </div>
      
      <div class="modal-body">
        <div class="detail-info">
          <div class="detail-item">
            <span class="detail-label">🌐 {$tr('dnsQuery.history.table.domain')}:</span>
            <span class="detail-value">{selectedHistoryItem.query_domain}</span>
          </div>
          <div class="detail-item">
            <span class="detail-label">📝 {$tr('dnsQuery.history.table.type')}:</span>
            <span class="detail-value">{selectedHistoryItem.query_type}</span>
          </div>
          <div class="detail-item">
            <span class="detail-label">🖥️ {$tr('dnsQuery.history.table.dnsServer')}:</span>
            <span class="detail-value">{selectedHistoryItem.dns_server || 'System DNS'}</span>
          </div>
          <div class="detail-item">
            <span class="detail-label">⏱️ {$tr('dnsQuery.history.table.queryTime')}:</span>
            <span class="detail-value">{selectedHistoryItem.query_time}ms</span>
          </div>
          <div class="detail-item">
            <span class="detail-label">🕐 {$tr('dnsQuery.history.table.createdAt')}:</span>
            <span class="detail-value">{formatDateTime(selectedHistoryItem.created_at)}</span>
          </div>
        </div>
        
        <div class="detail-result">
          <h3>📊 {$tr('dnsQuery.history.table.result')}</h3>
          <div class="result-wrapper">
            <pre>{JSON.stringify(JSON.parse(selectedHistoryItem.result), null, 2)}</pre>
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
        <h2>🎯 {$tr('dnsQuery.targetSelector.title')}</h2>
        <button class="modal-close" on:click={() => showTargetSelector = false}>✕</button>
      </div>
      
      <div class="modal-body">
        <div class="target-search">
          <input
            type="text"
            bind:value={targetSearchQuery}
            placeholder={$tr('dnsQuery.targetSelector.searchPlaceholder')}
          />
        </div>
        
        {#if loadingTargets}
          <div class="loading-message">
            <div class="spinner"></div>
            {$tr('dnsQuery.targetSelector.loading')}
          </div>
        {:else if filteredTargets.length === 0}
          <div class="empty-message">
            {#if targetSearchQuery}
              {$tr('dnsQuery.targetSelector.noResults')}
            {:else}
              {$tr('dnsQuery.targetSelector.noTargets')}
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
          {$tr('dnsQuery.targetSelector.selectedCount', { count: selectedTargets.length })}
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
    overflow-y: auto;
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
    overflow-y: auto;
  }

  .dns-query-page {
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

  .target-input-wrapper {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }

  .target-input-wrapper textarea {
    width: 100%;
    padding: 0.75rem;
    background: rgba(10, 14, 23, 0.6);
    border: 1px solid rgba(168, 85, 247, 0.3);
    border-radius: 0.5rem;
    color: #f1f5f9;
    font-size: 0.875rem;
    font-family: inherit;
    resize: vertical;
    min-height: 120px;
    transition: all 0.2s;
  }

  .target-input-wrapper textarea:focus {
    outline: none;
    border-color: #a855f7;
    box-shadow: 0 0 0 3px rgba(168, 85, 247, 0.1);
  }

  .target-buttons {
    display: flex;
    gap: 0.5rem;
  }

  .target-buttons button {
    flex: 1;
  }

  .select-target-btn {
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

  .select-target-btn:hover {
    background: linear-gradient(135deg, #059669 0%, #047857 100%);
    transform: translateY(-1px);
  }

  .select-target-btn:active {
    transform: translateY(0);
  }

  .import-btn {
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

  .import-btn:hover {
    background: linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%);
    transform: translateY(-1px);
  }

  .import-btn:active {
    transform: translateY(0);
  }

  .form-group input,
  .form-group select {
    width: 100%;
    padding: 0.75rem;
    background: rgba(10, 14, 23, 0.6);
    border: 1px solid rgba(168, 85, 247, 0.3);
    border-radius: 0.5rem;
    color: #f1f5f9;
    font-size: 0.875rem;
    transition: all 0.2s;
  }

  .form-group input:focus,
  .form-group select:focus {
    outline: none;
    border-color: #a855f7;
    box-shadow: 0 0 0 3px rgba(168, 85, 247, 0.1);
  }

  .form-group select {
    cursor: pointer;
  }

  .input-hint {
    display: block;
    font-size: 0.75rem;
    color: #64748b;
    margin-top: 0.5rem;
  }

  .button-group {
    display: flex;
    gap: 1rem;
    margin-top: 1.5rem;
  }

  .btn-primary {
    flex: 1;
    padding: 0.875rem;
    background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%);
    border: none;
    border-radius: 0.5rem;
    color: white;
    font-size: 1rem;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.2s;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 0.5rem;
  }

  .btn-primary:hover:not(:disabled) {
    transform: translateY(-1px);
    box-shadow: 0 4px 12px rgba(168, 85, 247, 0.3);
  }

  .btn-primary:disabled {
    opacity: 0.5;
    cursor: not-allowed;
    transform: none;
  }

  .btn-secondary {
    padding: 0.875rem 1.5rem;
    background: rgba(168, 85, 247, 0.1);
    border: 1px solid rgba(168, 85, 247, 0.3);
    border-radius: 0.5rem;
    color: #a855f7;
    font-size: 1rem;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.2s;
  }

  .btn-secondary:hover {
    background: rgba(168, 85, 247, 0.2);
  }

  .spinner {
    width: 16px;
    height: 16px;
    border: 2px solid #ffffff;
    border-top-color: transparent;
    border-radius: 50%;
    animation: spin 0.6s linear infinite;
  }

  @keyframes spin {
    to {
      transform: rotate(360deg);
    }
  }

  .info-card {
    background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
    border: 1px solid rgba(168, 85, 247, 0.2);
    border-radius: 1rem;
    padding: 1.5rem;
  }

  .info-card h3 {
    font-size: 1rem;
    font-weight: 600;
    margin-bottom: 1rem;
    color: #f1f5f9;
  }

  .info-card ul {
    list-style: none;
    padding: 0;
    margin: 0;
  }

  .info-card li {
    padding: 0.5rem 0;
    padding-left: 1.5rem;
    position: relative;
    color: #94a3b8;
    font-size: 0.875rem;
  }

  .info-card li::before {
    content: '•';
    position: absolute;
    left: 0;
    color: #a855f7;
  }

  .result-section {
    min-height: 600px;
  }

  .error-card {
    background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
    border: 1px solid rgba(239, 68, 68, 0.3);
    border-radius: 1rem;
    padding: 2rem;
    display: flex;
    align-items: center;
    gap: 1rem;
    margin-bottom: 1.5rem;
  }

  .error-icon {
    font-size: 2rem;
  }

  .error-message {
    color: #fca5a5;
    font-size: 1rem;
  }

  .result-card {
    background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
    border: 1px solid rgba(168, 85, 247, 0.2);
    border-radius: 1rem;
    padding: 1.5rem;
    overflow: hidden;
  }

  .result-header {
    padding: 1.5rem;
    border-bottom: 1px solid rgba(168, 85, 247, 0.1);
    display: flex;
    justify-content: space-between;
    align-items: center;
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

  .export-dropdown {
    position: relative;
  }

  .export-btn {
    padding: 0.5rem 1rem;
    background: linear-gradient(135deg, #8b5cf6 0%, #7c3aed 100%);
    border: none;
    border-radius: 0.5rem;
    color: white;
    font-size: 0.875rem;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.2s;
  }

  .export-btn:hover {
    transform: translateY(-1px);
    box-shadow: 0 4px 12px rgba(139, 92, 246, 0.3);
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
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
    z-index: 10;
    min-width: 150px;
  }

  .export-menu button {
    width: 100%;
    padding: 0.75rem 1rem;
    background: none;
    border: none;
    color: #f1f5f9;
    text-align: left;
    cursor: pointer;
    transition: background 0.2s;
    font-size: 0.875rem;
  }

  .export-menu button:hover {
    background: rgba(168, 85, 247, 0.2);
  }

  .results-info {
    padding: 1rem 1.5rem;
    background: rgba(10, 14, 23, 0.4);
    display: flex;
    align-items: center;
    gap: 1rem;
    font-size: 0.875rem;
    color: #94a3b8;
  }

  .results-count {
    color: #f1f5f9;
    font-weight: 500;
  }

  .success-count {
    color: #10b981;
    font-weight: 500;
  }

  .failed-count {
    color: #ef4444;
    font-weight: 500;
  }

  .results-separator {
    color: #475569;
  }

  .batch-results {
    max-height: 600px;
    overflow-y: auto;
  }

  .result-item {
    border-bottom: 1px solid rgba(168, 85, 247, 0.1);
    padding: 1.5rem;
  }

  .result-item:last-child {
    border-bottom: none;
  }

  .result-item-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 1rem;
    flex-wrap: wrap;
    gap: 0.5rem;
  }

  .domain-name {
    font-size: 1.125rem;
    font-weight: 600;
    color: #f1f5f9;
  }

  .result-meta {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    flex-wrap: wrap;
  }

  .meta-badge {
    font-size: 0.75rem;
    padding: 0.2rem 0.6rem;
    border-radius: 0.375rem;
    font-weight: 500;
  }

  .type-badge {
    background: rgba(168, 85, 247, 0.15);
    color: #a855f7;
    border: 1px solid rgba(168, 85, 247, 0.3);
  }

  .time-badge {
    background: rgba(34, 197, 94, 0.1);
    color: #22c55e;
    border: 1px solid rgba(34, 197, 94, 0.2);
  }

  .server-badge {
    background: rgba(59, 130, 246, 0.1);
    color: #3b82f6;
    border: 1px solid rgba(59, 130, 246, 0.2);
  }

  .count-badge {
    background: rgba(245, 158, 11, 0.1);
    color: #f59e0b;
    border: 1px solid rgba(245, 158, 11, 0.2);
  }

  .resolved-ips {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 0.5rem;
    padding: 0.75rem 1rem;
    background: rgba(255, 255, 255, 0.02);
    border: 1px solid rgba(255, 255, 255, 0.06);
    border-radius: 0.5rem;
    margin-bottom: 0.75rem;
  }

  .resolved-label {
    font-size: 0.8rem;
    color: #94a3b8;
    font-weight: 500;
    white-space: nowrap;
  }

  .ip-chip {
    font-size: 0.8rem;
    padding: 0.2rem 0.6rem;
    background: rgba(34, 197, 94, 0.1);
    color: #22c55e;
    border: 1px solid rgba(34, 197, 94, 0.2);
    border-radius: 0.375rem;
    font-family: 'JetBrains Mono', monospace;
  }

  .mx-chip {
    background: rgba(168, 85, 247, 0.1);
    color: #a855f7;
    border-color: rgba(168, 85, 247, 0.2);
  }

  .ns-chip {
    background: rgba(59, 130, 246, 0.1);
    color: #3b82f6;
    border-color: rgba(59, 130, 246, 0.2);
  }


  .records-table {
    overflow-x: auto;
    margin-top: 1rem;
  }

  .records-table table {
    width: 100%;
    border-collapse: collapse;
  }

  .records-table thead {
    background: rgba(10, 14, 23, 0.6);
  }

  .records-table th {
    padding: 0.75rem 1rem;
    text-align: left;
    font-size: 0.75rem;
    font-weight: 600;
    color: #94a3b8;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }

  .records-table td {
    padding: 0.75rem 1rem;
    border-top: 1px solid rgba(168, 85, 247, 0.1);
    font-size: 0.875rem;
    color: #cbd5e1;
  }

  .record-type {
    display: inline-block;
    padding: 0.25rem 0.75rem;
    background: rgba(168, 85, 247, 0.2);
    color: #c084fc;
    border-radius: 0.25rem;
    font-size: 0.75rem;
    font-weight: 600;
  }

  .record-data {
    font-family: 'Courier New', monospace;
    font-size: 0.875rem;
    color: #a5b4fc;
  }

  .result-error {
    background: rgba(239, 68, 68, 0.1);
    border: 1px solid rgba(239, 68, 68, 0.3);
    border-radius: 0.5rem;
    padding: 1rem;
    display: flex;
    align-items: center;
    gap: 0.75rem;
    color: #fca5a5;
    font-size: 0.875rem;
    margin-top: 1rem;
  }

  .no-records {
    padding: 2rem;
    text-align: center;
    color: #64748b;
    margin-top: 1rem;
  }

  .no-records-icon {
    font-size: 2rem;
    margin-bottom: 0.5rem;
    display: block;
  }

  .pagination {
    display: flex;
    justify-content: center;
    align-items: center;
    gap: 1rem;
    padding: 1.5rem;
    border-top: 1px solid rgba(168, 85, 247, 0.1);
  }

  .pagination-btn {
    padding: 0.5rem 1rem;
    background: rgba(168, 85, 247, 0.1);
    border: 1px solid rgba(168, 85, 247, 0.3);
    border-radius: 0.5rem;
    color: #a855f7;
    font-size: 0.875rem;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.2s;
  }

  .pagination-btn:hover:not(:disabled) {
    background: rgba(168, 85, 247, 0.2);
  }

  .pagination-btn:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .pagination-info {
    font-size: 0.875rem;
    color: #94a3b8;
  }

  .empty-state {
    background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
    border: 1px solid rgba(168, 85, 247, 0.2);
    border-radius: 1rem;
    padding: 4rem 2rem;
    text-align: center;
  }

  .empty-icon {
    font-size: 4rem;
    margin-bottom: 1rem;
    opacity: 0.5;
  }

  .empty-state p {
    color: #64748b;
    font-size: 1rem;
  }

  @media (max-width: 1024px) {
    .content-grid {
      grid-template-columns: 1fr;
    }

    .result-section {
      min-height: auto;
    }
  }

  @media (max-width: 640px) {
    .dns-query-page {
      padding: 1rem;
    }

    .page-title {
      font-size: 1.5rem;
    }

    .header-content {
      flex-direction: column;
      align-items: flex-start;
      gap: 1rem;
    }

    .result-header {
      flex-direction: column;
      align-items: flex-start;
      gap: 1rem;
    }

    .result-actions {
      width: 100%;
    }

    .export-btn {
      width: 100%;
    }

    .export-menu {
      width: 100%;
    }

    .results-info {
      flex-direction: column;
      align-items: flex-start;
      gap: 0.5rem;
    }

    .pagination {
      flex-direction: column;
      gap: 0.75rem;
    }
  }

  .tabs {
    display: flex;
    gap: 0.5rem;
    margin-bottom: 2rem;
    border-bottom: 2px solid rgba(168, 85, 247, 0.2);
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

  .history-section {
    background: rgba(10, 14, 23, 0.6);
    border: 1px solid rgba(168, 85, 247, 0.3);
    border-radius: 1rem;
    padding: 2rem;
  }

  .history-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 2rem;
  }

  .history-header h2 {
    font-size: 1.5rem;
    font-weight: 600;
    background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
  }

  .history-actions {
    display: flex;
    gap: 0.5rem;
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

  .btn-small {
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
  }

  .btn-primary {
    background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);
    color: white;
  }

  .btn-primary:hover {
    background: linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%);
    transform: translateY(-1px);
  }

  .btn-danger {
    background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
    color: white;
  }

  .btn-danger:hover {
    background: linear-gradient(135deg, #dc2626 0%, #b91c1c 100%);
    transform: translateY(-1px);
  }

  .detail-info {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 1rem;
    margin-bottom: 2rem;
  }

  .detail-item {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
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

  .detail-result {
    background: rgba(0, 0, 0, 0.3);
    border-radius: 0.5rem;
    padding: 1.5rem;
    margin-top: 1.5rem;
  }

  .detail-result h3 {
    color: #a855f7;
    margin-bottom: 1rem;
    font-size: 1.125rem;
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }

  .result-wrapper {
    max-height: 400px;
    overflow-y: auto;
    border-radius: 0.5rem;
    border: 1px solid rgba(168, 85, 247, 0.2);
    background: rgba(0, 0, 0, 0.2);
  }

  .result-wrapper::-webkit-scrollbar {
    width: 8px;
  }

  .result-wrapper::-webkit-scrollbar-track {
    background: rgba(0, 0, 0, 0.2);
    border-radius: 4px;
  }

  .result-wrapper::-webkit-scrollbar-thumb {
    background: rgba(168, 85, 247, 0.5);
    border-radius: 4px;
  }

  .result-wrapper::-webkit-scrollbar-thumb:hover {
    background: rgba(168, 85, 247, 0.7);
  }

  .detail-result pre {
    margin: 0;
    padding: 1rem;
    color: #e2e8f0;
    font-family: 'Courier New', monospace;
    font-size: 0.875rem;
    line-height: 1.6;
    white-space: pre-wrap;
    word-wrap: break-word;
  }

  .detail-result pre {
    color: #e2e8f0;
    font-size: 0.875rem;
    line-height: 1.6;
    overflow-x: auto;
    margin: 0;
  }

  .loading-state,
  .error-state,
  .empty-state {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    padding: 4rem 2rem;
    text-align: center;
  }

  .loading-spinner {
    width: 40px;
    height: 40px;
    border: 3px solid rgba(168, 85, 247, 0.3);
    border-top-color: #a855f7;
    border-radius: 50%;
    animation: spin 1s linear infinite;
    margin-bottom: 1rem;
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

  .record-type-grid {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 1rem;
    margin-top: 1rem;
  }

  .type-card {
    background: rgba(168, 85, 247, 0.05);
    border: 1px solid rgba(168, 85, 247, 0.2);
    border-radius: 0.75rem;
    padding: 1.25rem;
    transition: all 0.2s;
  }

  .type-card:hover {
    background: rgba(168, 85, 247, 0.1);
    border-color: rgba(168, 85, 247, 0.3);
    transform: translateY(-2px);
  }

  .type-card h4 {
    font-size: 1rem;
    font-weight: 600;
    color: #f1f5f9;
    margin-bottom: 0.5rem;
  }

  .type-card p {
    color: #94a3b8;
    font-size: 0.875rem;
    margin-bottom: 0.5rem;
  }

  .empty-icon {
    font-size: 4rem;
    margin-bottom: 1rem;
  }

  .error-state button {
    margin-top: 1rem;
    padding: 0.625rem 1.25rem;
    background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);
    color: white;
    border: none;
    border-radius: 0.5rem;
    cursor: pointer;
    transition: all 0.2s;
  }

  .error-state button:hover {
    background: linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%);
    transform: translateY(-1px);
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
</style>
