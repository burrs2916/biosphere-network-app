<script lang="ts">
  import { invoke } from '@tauri-apps/api/core';
  import { tr } from '$lib/i18n';
  import { onMount } from 'svelte';

  interface WhoisHistoryItem {
    id: number;
    query_target: string;
    registrar: string | null;
    registrant_name: string | null;
    registrant_email: string | null;
    registrant_org: string | null;
    created_date: string | null;
    expiration_date: string | null;
    updated_date: string | null;
    name_servers: string | null;
    created_at: string;
  }

  interface WhoisResult {
    domain: string;
    registrar: string | null;
    created_date: string | null;
    updated_date: string | null;
    expiry_date: string | null;
    status: string[];
    name_servers: string[];
    registrant_name: string | null;
    registrant_organization: string | null;
    registrant_country: string | null;
    registrant_email: string | null;
    admin_name: string | null;
    admin_email: string | null;
    tech_name: string | null;
    tech_email: string | null;
    dnssec: string | null;
    raw_response: string;
    query_time: number;
    queried_at: string;
  }

  interface QueryProgress {
    current: number;
    total: number;
    domain: string;
    status: 'pending' | 'querying' | 'success' | 'error';
  }

  let domains = '';
  let timeout = 5;
  let querying = false;
  let results: WhoisResult[] = [];
  let errors: { domain: string; error: string }[] = [];
  let progress: QueryProgress | null = null;
  let selectedResultIndex = 0;
  let showRawResponse = false;
  let showHelpModal = false;
  let showExportMenu = false;
  let activeTab = 'query';
  let viewMode: 'detail' | 'overview' = 'detail';
  let showConfirmDialog = false;
  let confirmDialogTitle = '';
  let confirmDialogMessage = '';
  let confirmAction: (() => Promise<void>) | null = null;
  let showTargetSelector = false;
  let targets: any[] = [];
  let loadingTargets = false;
  let selectedTargets: any[] = [];
  let selectedTargetIds: number[] = [];
  let targetSearchQuery = '';
  let history: WhoisHistoryItem[] = [];

  onMount(async () => {
    await loadHistory();
  });

  async function loadHistory() {
    try {
      history = await invoke<WhoisHistoryItem[]>('get_whois_history', { limit: 50, offset: 0 });
    } catch (e) {
      console.error('Failed to load whois history:', e);
    }
  }

  function cleanDomain(input: string): string {
    let cleaned = input.trim();
    cleaned = cleaned.replace(/^(https?:\/\/)?/, '');
    cleaned = cleaned.replace(/^www\./, '');
    cleaned = cleaned.split('/')[0];
    cleaned = cleaned.split(':')[0];
    return cleaned.toLowerCase();
  }

  function validateDomain(input: string): boolean {
    const domainRegex = /^[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,}$/i;
    return domainRegex.test(input);
  }

  function parseDomains(input: string): string[] {
    return input
      .split(/[\n,;]+/)
      .map(d => cleanDomain(d))
      .filter(d => d.length > 0);
  }

  async function queryWhois() {
    const domainList = parseDomains(domains);
    
    if (domainList.length === 0) {
      errors = [{ domain: '', error: $tr('whois.error.invalidDomain') }];
      return;
    }

    querying = true;
    results = [];
    errors = [];
    progress = { current: 0, total: domainList.length, domain: '', status: 'pending' };

    for (let i = 0; i < domainList.length; i++) {
      const domain = domainList[i];
      progress = { current: i + 1, total: domainList.length, domain, status: 'querying' };

      if (!validateDomain(domain)) {
        errors.push({ domain, error: $tr('whois.error.invalidDomain') });
        progress = { current: i + 1, total: domainList.length, domain, status: 'error' };
        continue;
      }

      try {
        console.log('Querying whois for:', domain);
        const response = await invoke<WhoisResult>('whois_query', {
          domain,
          timeoutMs: timeout * 1000,
          targetId: selectedTargetIds.length > 0 ? selectedTargetIds[0] : null,
        });
        
        console.log('Whois response:', response);
        results = [...results, response];
        progress = { current: i + 1, total: domainList.length, domain, status: 'success' };
        
        if (results.length === 1) {
          selectedResultIndex = 0;
        }
        
        try {
          await invoke('save_whois_record', {
            record: {
              query_target: response.domain,
              query_type: 'domain',
              registrar: response.registrar,
              registrant_name: response.registrant_name,
              registrant_email: response.registrant_email,
              registrant_org: response.registrant_organization,
              created_date: response.created_date,
              expiration_date: response.expiry_date,
              updated_date: response.updated_date,
              name_servers: response.name_servers ? response.name_servers.join(', ') : null,
              raw_data: response.raw_response,
              created_at: new Date().toISOString()
            }
          });
          await loadHistory();
        } catch (e) {
          console.error('Failed to save whois record:', e);
        }
      } catch (e) {
        console.error('Whois query error:', e);
        const errorMessage = e instanceof Error ? e.message : String(e);
        errors = [...errors, { domain, error: errorMessage }];
        progress = { current: i + 1, total: domainList.length, domain, status: 'error' };
      }
    }

    querying = false;
    progress = null;
    
    console.log('Query complete. Results:', results.length, 'Errors:', errors.length);
    
    if (results.length > 0) {
      selectedResultIndex = 0;
      if (results.length > 1) {
        viewMode = 'overview';
      } else {
        viewMode = 'detail';
      }
    }
  }

  function reset() {
    domains = '';
    results = [];
    errors = [];
    progress = null;
    selectedResultIndex = 0;
    showRawResponse = false;
  }

  function formatDate(dateStr: string | null): string {
    if (!dateStr) return '-';
    return dateStr;
  }

  function copyToClipboard(text: string) {
    navigator.clipboard.writeText(text);
  }

  async function queryFromHistory(item: WhoisHistoryItem) {
    domains = item.query_target;
    activeTab = 'query';
    await queryWhois();
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

  function deleteHistoryItem(id: number) {
    showConfirm(
      $tr('whois.history.deleteConfirm'),
      $tr('whois.history.deleteConfirmMessage'),
      async () => {
        try {
          await invoke('delete_whois_record', { id });
          await loadHistory();
        } catch (e) {
          console.error('Failed to delete whois record:', e);
        }
      }
    );
  }

  function clearAllHistory() {
    showConfirm(
      $tr('whois.history.clear'),
      $tr('whois.history.clearConfirm'),
      async () => {
        try {
          await invoke('clear_whois_history');
          await loadHistory();
        } catch (e) {
          console.error('Failed to clear whois history:', e);
        }
      }
    );
  }

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
        pageSize: 100,
        targetType: 'Domain'
      });
      targets = result.targets || [];
    } catch (error) {
      console.error('Failed to load targets:', error);
      targets = [];
    } finally {
      loadingTargets = false;
    }
  }

  $: filteredTargets = targets.filter(t => {
    if (!targetSearchQuery) return true;
    const query = targetSearchQuery.toLowerCase();
    return (
      t.name.toLowerCase().includes(query) ||
      t.target_value.toLowerCase().includes(query) ||
      (t.description && t.description.toLowerCase().includes(query))
    );
  });

  function toggleTargetSelection(target: any) {
    const index = selectedTargets.findIndex(t => t.id === target.id);
    if (index >= 0) {
      selectedTargets = selectedTargets.filter(t => t.id !== target.id);
    } else {
      selectedTargets = [...selectedTargets, target];
    }
  }

  function confirmTargetSelection() {
    const domainList = selectedTargets.map(t => t.target_value).join('\n');
    domains = domains ? `${domains}\n${domainList}` : domainList;
    selectedTargetIds = selectedTargets.map(t => t.id).filter((id: number | null): id is number => id !== null);
    selectedTargets = [];
    showTargetSelector = false;
  }

  function formatQueryTime(timestamp: string): string {
    try {
      const date = new Date(timestamp);
      return date.toLocaleString();
    } catch {
      return timestamp;
    }
  }

  function exportAsJSON() {
    if (results.length === 0) return;
    
    const exportData = results.map(result => ({
      domain: result.domain,
      registrar: result.registrar,
      created_date: result.created_date,
      updated_date: result.updated_date,
      expiry_date: result.expiry_date,
      status: result.status,
      name_servers: result.name_servers,
      registrant: {
        name: result.registrant_name,
        organization: result.registrant_organization,
        country: result.registrant_country,
        email: result.registrant_email
      },
      admin: {
        name: result.admin_name,
        email: result.admin_email
      },
      tech: {
        name: result.tech_name,
        email: result.tech_email
      },
      dnssec: result.dnssec,
      query_time: result.query_time,
      queried_at: result.queried_at
    }));
    
    const json = JSON.stringify(exportData, null, 2);
    downloadFile(json, `whois_results_${Date.now()}.json`, 'application/json');
    showExportMenu = false;
  }

  function exportAsCSV() {
    if (results.length === 0) return;
    
    const headers = [
      'Domain',
      'Registrar',
      'Created Date',
      'Updated Date',
      'Expiry Date',
      'Status',
      'Name Servers',
      'Registrant Name',
      'Registrant Organization',
      'Registrant Country',
      'Registrant Email',
      'DNSSEC',
      'Query Time'
    ];
    
    const rows = results.map(result => [
      result.domain,
      result.registrar || '',
      result.created_date || '',
      result.updated_date || '',
      result.expiry_date || '',
      result.status.join('; '),
      result.name_servers.join('; '),
      result.registrant_name || '',
      result.registrant_organization || '',
      result.registrant_country || '',
      result.registrant_email || '',
      result.dnssec || '',
      result.queried_at
    ]);
    
    const csv = [headers.join(','), ...rows.map(row => row.map(cell => `"${cell}"`).join(','))].join('\n');
    downloadFile(csv, `whois_results_${Date.now()}.csv`, 'text/csv');
    showExportMenu = false;
  }

  function exportAsMarkdown() {
    if (results.length === 0) return;
    
    const md = results.map(result => `${$tr('whois.export.markdownTemplate.title').replace('{domain}', result.domain)}

${$tr('whois.export.markdownTemplate.basicInfo')}
- **${$tr('whois.export.markdownTemplate.domain')}**: ${result.domain}
- **${$tr('whois.export.markdownTemplate.registrar')}**: ${result.registrar || $tr('whois.export.markdownTemplate.notAvailable')}
- **${$tr('whois.export.markdownTemplate.createdDate')}**: ${result.created_date || $tr('whois.export.markdownTemplate.notAvailable')}
- **${$tr('whois.export.markdownTemplate.updatedDate')}**: ${result.updated_date || $tr('whois.export.markdownTemplate.notAvailable')}
- **${$tr('whois.export.markdownTemplate.expiryDate')}**: ${result.expiry_date || $tr('whois.export.markdownTemplate.notAvailable')}
- **${$tr('whois.export.markdownTemplate.dnssec')}**: ${result.dnssec || $tr('whois.export.markdownTemplate.notAvailable')}

${$tr('whois.export.markdownTemplate.domainStatus')}
${result.status.map(s => `- ${s}`).join('\n')}

${$tr('whois.export.markdownTemplate.nameServers')}
${result.name_servers.map(ns => `- ${ns}`).join('\n')}

${$tr('whois.export.markdownTemplate.registrantInfo')}
- **${$tr('whois.export.markdownTemplate.registrantName')}**: ${result.registrant_name || $tr('whois.export.markdownTemplate.notAvailable')}
- **${$tr('whois.export.markdownTemplate.registrantOrg')}**: ${result.registrant_organization || $tr('whois.export.markdownTemplate.notAvailable')}
- **${$tr('whois.export.markdownTemplate.registrantCountry')}**: ${result.registrant_country || $tr('whois.export.markdownTemplate.notAvailable')}
- **${$tr('whois.export.markdownTemplate.registrantEmail')}**: ${result.registrant_email || $tr('whois.export.markdownTemplate.notAvailable')}

${$tr('whois.export.markdownTemplate.adminContact')}
- **${$tr('whois.export.markdownTemplate.registrantName')}**: ${result.admin_name || $tr('whois.export.markdownTemplate.notAvailable')}
- **${$tr('whois.export.markdownTemplate.registrantEmail')}**: ${result.admin_email || $tr('whois.export.markdownTemplate.notAvailable')}

${$tr('whois.export.markdownTemplate.techContact')}
- **${$tr('whois.export.markdownTemplate.registrantName')}**: ${result.tech_name || $tr('whois.export.markdownTemplate.notAvailable')}
- **${$tr('whois.export.markdownTemplate.registrantEmail')}**: ${result.tech_email || $tr('whois.export.markdownTemplate.notAvailable')}

${$tr('whois.export.markdownTemplate.queryMetadata')}
- **${$tr('whois.export.markdownTemplate.queryTime')}**: ${result.queried_at}
- **${$tr('whois.export.markdownTemplate.responseTime')}**: ${result.query_time}ms

---
`).join('\n');
    
    downloadFile(md, `whois_results_${Date.now()}.md`, 'text/markdown');
    showExportMenu = false;
  }

  function downloadFile(content: string, filename: string, mimeType: string) {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  $: selectedResult = results[selectedResultIndex] || null;
</script>

<svelte:head>
  <title>{$tr('whois.title')} - Biosphere Network Tools</title>
</svelte:head>

<div class="page-container">
  <a href="/" class="back-link">{$tr('common.backToHome')}</a>
  <div class="page-header">
    <div class="header-content">
      <h1 class="page-title">{$tr('whois.title')}</h1>
      <p class="page-subtitle">{$tr('whois.subtitle')}</p>
    </div>
    <button class="help-button" on:click={() => showHelpModal = true}>
      {$tr('common.userManual')}
    </button>
  </div>

  <div class="tabs">
    <button 
      class="tab-button {activeTab === 'query' ? 'active' : ''}" 
      on:click={() => activeTab = 'query'}
    >
      {$tr('whois.title')}
    </button>
    <button 
      class="tab-button {activeTab === 'history' ? 'active' : ''}" 
      on:click={() => activeTab = 'history'}
    >
      {$tr('whois.history.title')}
    </button>
  </div>

  {#if activeTab === 'query'}
    <div class="content-grid">
      <div class="config-section">
        <div class="section-card">
          <h2 class="section-title">{$tr('whois.config.title')}</h2>
          
          <div class="form-group">
            <label class="form-label" for="domains">{$tr('whois.labels.domain')} *</label>
            <textarea
              id="domains"
              bind:value={domains}
              placeholder={$tr('whois.placeholder.domain')}
              class="form-textarea"
              rows="6"
              disabled={querying}
            ></textarea>
            <div class="target-buttons">
              <button
                type="button"
                class="select-target-btn"
                on:click={openTargetSelector}
                disabled={querying}
              >
                {$tr('whois.buttons.selectTarget')}
              </button>
            </div>
            <span class="hint">{$tr('whois.hints.domain')}</span>
          </div>

          <div class="form-group">
            <label class="form-label" for="timeout">{$tr('whois.labels.timeout')}</label>
            <input
              id="timeout"
              type="number"
              bind:value={timeout}
              min="1"
              max="60"
              class="form-input"
              disabled={querying}
            />
            <span class="hint">{$tr('whois.hints.timeout')}</span>
          </div>

          <div class="button-group">
            <button
              class="btn btn-primary"
              on:click={queryWhois}
              disabled={querying || !domains.trim()}
            >
              {#if querying}
                <span class="spinner"></span>
                {$tr('whois.buttons.querying')}
              {:else}
                🔍 {$tr('whois.buttons.query')}
              {/if}
            </button>
            <button
              class="btn btn-secondary"
              on:click={reset}
              disabled={querying}
            >
              🔄 {$tr('whois.buttons.reset')}
            </button>
          </div>
        </div>

        {#if progress}
          <div class="progress-card">
            <div class="progress-header">
              <span class="progress-text">
                {$tr('whois.progress.querying')
                  .replace('{current}', progress.current.toString())
                  .replace('{total}', progress.total.toString())
                  .replace('{domain}', progress.domain)}
              </span>
            </div>
            <div class="progress-bar">
              <div 
                class="progress-fill" 
                style="width: {(progress.current / progress.total) * 100}%"
              ></div>
            </div>
          </div>
        {/if}

        {#if errors.length > 0}
          <div class="error-card">
            <div class="error-header">
              <span class="error-icon">⚠️</span>
              <span class="error-title">{$tr('whois.progress.queryError').replace('{count}', errors.length.toString())}</span>
            </div>
            <div class="error-list">
              {#each errors as err}
                <div class="error-item">
                  <strong>{err.domain || $tr('whois.error.unknownDomain')}:</strong> {err.error}
                </div>
              {/each}
            </div>
          </div>
        {/if}
      </div>

      <div class="result-section">
        {#if results.length > 0}
          <div class="results-container">
            <div class="results-list">
              <div class="results-header">
                <h2 class="section-title">{$tr('whois.progress.queryResults').replace('{count}', results.length.toString())}</h2>
                <div class="result-actions">
                  <div class="view-toggle">
                    <button
                      class="toggle-btn {viewMode === 'detail' ? 'active' : ''}"
                      on:click={() => viewMode = 'detail'}
                      title={$tr('whois.view.detail')}
                    >
                      📋
                    </button>
                    <button
                      class="toggle-btn {viewMode === 'overview' ? 'active' : ''}"
                      on:click={() => viewMode = 'overview'}
                      title={$tr('whois.view.overview')}
                    >
                      📊
                    </button>
                  </div>
                  <div class="export-dropdown">
                    <button
                      class="btn btn-small"
                      on:click={() => showExportMenu = !showExportMenu}
                    >
                      📥 {$tr('whois.export.title')}
                    </button>
                    {#if showExportMenu}
                      <div class="export-menu">
                        <button class="export-option" on:click={exportAsJSON}>
                          📄 {$tr('whois.export.json')}
                        </button>
                        <button class="export-option" on:click={exportAsCSV}>
                          📊 {$tr('whois.export.csv')}
                        </button>
                        <button class="export-option" on:click={exportAsMarkdown}>
                          📝 {$tr('whois.export.markdown')}
                        </button>
                      </div>
                    {/if}
                  </div>
                </div>
              </div>
              
              {#if viewMode === 'overview'}
                <div class="overview-container">
                  <div class="overview-table">
                    <div class="overview-header">
                      <div class="overview-cell">{$tr('whois.results.domain')}</div>
                      <div class="overview-cell">{$tr('whois.results.registrar')}</div>
                      <div class="overview-cell">{$tr('whois.results.createdDate')}</div>
                      <div class="overview-cell">{$tr('whois.results.expiryDate')}</div>
                      <div class="overview-cell">{$tr('whois.results.queryTime')}</div>
                    </div>
                    {#each results as result, index}
                      <div 
                        class="overview-row {selectedResultIndex === index ? 'active' : ''}"
                        on:click={() => {
                          selectedResultIndex = index;
                          viewMode = 'detail';
                        }}
                        role="button"
                        tabindex="0"
                        on:keydown={(e) => {
                          if (e.key === 'Enter' || e.key === ' ') {
                            selectedResultIndex = index;
                            viewMode = 'detail';
                          }
                        }}
                      >
                        <div class="overview-cell">
                          <strong>{result.domain}</strong>
                        </div>
                        <div class="overview-cell">{result.registrar || '-'}</div>
                        <div class="overview-cell">{formatDate(result.created_date) || '-'}</div>
                        <div class="overview-cell">{formatDate(result.expiry_date) || '-'}</div>
                        <div class="overview-cell">{result.query_time}ms</div>
                      </div>
                    {/each}
                  </div>
                </div>
              {:else}
                <div class="domain-tabs">
                  {#each results as result, index}
                    <button
                      class="domain-tab {selectedResultIndex === index ? 'active' : ''}"
                      on:click={() => selectedResultIndex = index}
                    >
                      {result.domain}
                    </button>
                  {/each}
                </div>
              {/if}
            </div>

            {#if viewMode === 'detail' && selectedResult}
              <div class="result-details">
                <div class="result-meta">
                  <span class="meta-item">
                    <strong>{$tr('whois.results.domain')}:</strong> {selectedResult.domain}
                  </span>
                  <span class="meta-item">
                    <strong>{$tr('whois.results.queryTime')}:</strong> {selectedResult.query_time}ms
                  </span>
                  <div class="result-actions-inline">
                    <button
                      class="btn btn-small"
                      on:click={() => copyToClipboard(selectedResult.raw_response)}
                    >
                      📋 {$tr('whois.buttons.copyRaw')}
                    </button>
                    <button
                      class="btn btn-small"
                      on:click={() => showRawResponse = !showRawResponse}
                    >
                      {#if showRawResponse}
                        📄 {$tr('whois.buttons.hideRaw')}
                      {:else}
                        📄 {$tr('whois.buttons.showRaw')}
                      {/if}
                    </button>
                  </div>
                </div>

                {#if selectedResult.registrar === null && selectedResult.raw_response.includes('No match for')}
                  <div class="available-notice">
                    ✅ {$tr('whois.results.available')}
                  </div>
                {:else}
                  <div class="result-grid">
                    {#if selectedResult.registrar}
                      <div class="result-item">
                        <div class="result-label">{$tr('whois.results.registrar')}</div>
                        <div class="result-value">{selectedResult.registrar}</div>
                      </div>
                    {/if}

                    {#if selectedResult.created_date}
                      <div class="result-item">
                        <div class="result-label">{$tr('whois.results.createdDate')}</div>
                        <div class="result-value">{formatDate(selectedResult.created_date)}</div>
                      </div>
                    {/if}

                    {#if selectedResult.updated_date}
                      <div class="result-item">
                        <div class="result-label">{$tr('whois.results.updatedDate')}</div>
                        <div class="result-value">{formatDate(selectedResult.updated_date)}</div>
                      </div>
                    {/if}

                    {#if selectedResult.expiry_date}
                      <div class="result-item">
                        <div class="result-label">{$tr('whois.results.expiryDate')}</div>
                        <div class="result-value">{formatDate(selectedResult.expiry_date)}</div>
                      </div>
                    {/if}

                    {#if selectedResult.registrant_name}
                      <div class="result-item">
                        <div class="result-label">{$tr('whois.results.registrantName')}</div>
                        <div class="result-value">{selectedResult.registrant_name}</div>
                      </div>
                    {/if}

                    {#if selectedResult.registrant_organization}
                      <div class="result-item">
                        <div class="result-label">{$tr('whois.results.registrantOrg')}</div>
                        <div class="result-value">{selectedResult.registrant_organization}</div>
                      </div>
                    {/if}

                    {#if selectedResult.registrant_country}
                      <div class="result-item">
                        <div class="result-label">{$tr('whois.results.registrantCountry')}</div>
                        <div class="result-value">{selectedResult.registrant_country}</div>
                      </div>
                    {/if}

                    {#if selectedResult.registrant_email}
                      <div class="result-item">
                        <div class="result-label">{$tr('whois.results.registrantEmail')}</div>
                        <div class="result-value">{selectedResult.registrant_email}</div>
                      </div>
                    {/if}

                    {#if selectedResult.dnssec}
                      <div class="result-item">
                        <div class="result-label">{$tr('whois.results.dnssec')}</div>
                        <div class="result-value">{selectedResult.dnssec}</div>
                      </div>
                    {/if}

                    {#if selectedResult.status.length > 0}
                      <div class="result-item full-width">
                        <div class="result-label">{$tr('whois.results.status')}</div>
                        <div class="result-value">
                          {#each selectedResult.status as status}
                            <span class="status-tag">{status}</span>
                          {/each}
                        </div>
                      </div>
                    {/if}

                    {#if selectedResult.name_servers.length > 0}
                      <div class="result-item full-width">
                        <div class="result-label">{$tr('whois.results.nameServers')}</div>
                        <div class="result-value">
                          {#each selectedResult.name_servers as ns}
                            <span class="ns-tag">{ns}</span>
                          {/each}
                        </div>
                      </div>
                    {/if}
                  </div>
                {/if}

                {#if showRawResponse}
                  <div class="raw-response-section">
                    <h3 class="subsection-title">{$tr('whois.results.rawResponse')}</h3>
                    <pre class="raw-response">{selectedResult.raw_response}</pre>
                  </div>
                {/if}
              </div>
            {/if}
          </div>
        {:else}
          <div class="empty-result">
            <div class="empty-icon">🔍</div>
            <p class="empty-text">{$tr('whois.results.emptyTitle')}</p>
            <p class="empty-hint">{$tr('whois.results.emptyHint')}</p>
          </div>
        {/if}
      </div>
    </div>
  {:else if activeTab === 'history'}
    <div class="history-section">
      <div class="section-card">
        <div class="history-header">
          <h2 class="section-title">{$tr('whois.history.title')}</h2>
          <button class="btn btn-secondary" on:click={clearAllHistory}>
            🗑️ {$tr('whois.history.clear')}
          </button>
        </div>
        
        {#if history.length === 0}
          <div class="empty-state">
            <p>{$tr('whois.history.empty')}</p>
          </div>
        {:else}
          <div class="history-list">
            {#each history as item (item.id)}
              <div class="history-item">
                <div class="history-item-header">
                  <h3 class="history-domain">{item.query_target}</h3>
                  <div class="history-actions">
                    <button 
                      class="btn btn-small"
                      on:click={() => queryFromHistory(item)}
                      title={$tr('whois.history.tooltip.queryAgain')}
                    >
                      🔄 {$tr('whois.history.queryAgain')}
                    </button>
                    <button 
                      class="btn btn-small btn-danger"
                      on:click={() => deleteHistoryItem(item.id)}
                      title={$tr('whois.history.tooltip.delete')}
                    >
                      🗑️
                    </button>
                  </div>
                </div>
                <div class="history-item-details">
                  <div class="detail-row">
                    <span class="detail-label">{$tr('whois.history.columns.registrar')}:</span>
                    <span class="detail-value">{item.registrar || '-'}</span>
                  </div>
                  <div class="detail-row">
                    <span class="detail-label">{$tr('whois.history.columns.createdDate')}:</span>
                    <span class="detail-value">{formatDate(item.created_date) || '-'}</span>
                  </div>
                  <div class="detail-row">
                    <span class="detail-label">{$tr('whois.history.columns.expiry')}:</span>
                    <span class="detail-value">{formatDate(item.expiration_date) || '-'}</span>
                  </div>
                  {#if item.registrant_org}
                    <div class="detail-row">
                      <span class="detail-label">{$tr('whois.history.columns.registrantOrg')}:</span>
                      <span class="detail-value">{item.registrant_org}</span>
                    </div>
                  {/if}
                  {#if item.name_servers}
                    <div class="detail-row">
                      <span class="detail-label">{$tr('whois.history.columns.nameServers')}:</span>
                      <span class="detail-value">{item.name_servers}</span>
                    </div>
                  {/if}
                  <div class="detail-row">
                    <span class="detail-label">{$tr('whois.history.columns.queryTime')}:</span>
                    <span class="detail-value">{formatDate(item.created_at)}</span>
                  </div>
                </div>
              </div>
            {/each}
          </div>
        {/if}
      </div>
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
        <h2>🎯 {$tr('whois.targetSelector.title')}</h2>
        <button class="modal-close" on:click={() => showTargetSelector = false}>✕</button>
      </div>
      
      <div class="modal-body">
        <div class="target-search">
          <input
            type="text"
            bind:value={targetSearchQuery}
            placeholder={$tr('whois.targetSelector.searchPlaceholder')}
          />
        </div>
        
        {#if loadingTargets}
          <div class="loading-message">
            <div class="spinner"></div>
            {$tr('whois.targetSelector.loading')}
          </div>
        {:else if filteredTargets.length === 0}
          <div class="empty-message">
            {#if targetSearchQuery}
              {$tr('whois.targetSelector.noResults')}
            {:else}
              {$tr('whois.targetSelector.noTargets')}
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
          {$tr('whois.targetSelector.selectedCount', { count: selectedTargets.length })}
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

  {#if showHelpModal}
    <div 
      class="modal-overlay" 
      role="button"
      tabindex="-1"
      on:click={() => showHelpModal = false}
      on:keydown={(e) => e.key === 'Escape' && (showHelpModal = false)}
    >
      <div 
        class="modal-content" 
        role="dialog"
        aria-modal="true"
        tabindex="-1"
        on:click|stopPropagation
        on:keydown|stopPropagation
      >
        <div class="modal-header">
          <h2>{$tr('whois.helpModal.title')}</h2>
          <button class="modal-close" on:click={() => showHelpModal = false}>✕</button>
        </div>
        
        <div class="modal-body">
          <section class="help-section">
            <h3>{$tr('whois.helpModal.overview')}</h3>
            <p>{$tr('whois.helpModal.overviewText')}</p>
          </section>

          <section class="help-section">
            <h3>{$tr('whois.helpModal.batchQuery')}</h3>
            <p>{$tr('whois.helpModal.batchQueryText')}</p>
            <ul class="example-list">
              <li><code>example.com</code></li>
              <li><code>test.org, demo.net</code></li>
              <li><code>{$tr('whois.helpModal.batchQueryExamples')}</code></li>
            </ul>
          </section>

          <section class="help-section">
            <h3>{$tr('whois.helpModal.configParams')}</h3>
            <ul class="feature-list">
              <li><strong>{$tr('whois.labels.timeout')}</strong> - {$tr('whois.helpModal.params.timeoutDesc')}</li>
              <li class="example">{$tr('whois.helpModal.params.timeoutExample')}</li>
            </ul>
          </section>

          <section class="help-section">
            <h3>{$tr('whois.helpModal.resultsTitle')}</h3>
            <ul class="feature-list">
              <li>{$tr('whois.helpModal.resultFeatures.registrar')}</li>
              <li>{$tr('whois.helpModal.resultFeatures.dates')}</li>
              <li>{$tr('whois.helpModal.resultFeatures.registrant')}</li>
              <li>{$tr('whois.helpModal.resultFeatures.status')}</li>
              <li>{$tr('whois.helpModal.resultFeatures.nameservers')}</li>
              <li>{$tr('whois.helpModal.resultFeatures.dnssec')}</li>
            </ul>
          </section>

          <section class="help-section">
            <h3>{$tr('whois.helpModal.tipsTitle')}</h3>
            <ul class="tip-list">
              <li>{$tr('whois.helpModal.tips.tip1')}</li>
              <li>{$tr('whois.helpModal.tips.tip2')}</li>
              <li>{$tr('whois.helpModal.tips.tip3')}</li>
              <li>{$tr('whois.helpModal.tips.tip4')}</li>
            </ul>
          </section>

          <section class="help-section">
            <h3>{$tr('whois.helpModal.warningTitle')}</h3>
            <ul class="tip-list">
              <li>{$tr('whois.helpModal.warnings.warning1')}</li>
              <li>{$tr('whois.helpModal.warnings.warning2')}</li>
              <li>{$tr('whois.helpModal.warnings.warning3')}</li>
              <li>{$tr('whois.helpModal.warnings.warning4')}</li>
            </ul>
          </section>
        </div>
      </div>
    </div>
  {/if}
</div>

<style>
  .section-card { background: var(--bg-secondary); border-radius: 12px; padding: 20px; }
  .page-container {
    padding: 2rem;
    max-width: 1400px;
    margin: 0 auto;
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

  .page-header {
    margin-bottom: 2rem;
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
  }

  .header-content {
    flex: 1;
  }

  .help-button {
    background: linear-gradient(135deg, #a855f7, #6366f1);
    color: white;
    border: none;
    padding: 0.5rem 1rem;
    border-radius: 0.5rem;
    cursor: pointer;
    font-size: 0.875rem;
    font-weight: 600;
    transition: all 0.3s;
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }

  .help-button:hover {
    transform: translateY(-2px);
    box-shadow: 0 6px 20px rgba(168, 85, 247, 0.4);
  }

  .page-title {
    font-size: 2rem;
    font-weight: 700;
    margin-bottom: 0.5rem;
    background: linear-gradient(135deg, #a855f7, #6366f1);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
  }

  .page-subtitle {
    font-size: 1rem;
    color: #9ca3af;
  }

  .tabs {
    display: flex;
    gap: 0.5rem;
    margin-bottom: 2rem;
    border-bottom: 2px solid rgba(168, 85, 247, 0.2);
    padding-bottom: 0;
  }

  .tab-button {
    background: none;
    border: none;
    color: #9ca3af;
    padding: 0.75rem 1.5rem;
    font-size: 0.875rem;
    font-weight: 500;
    cursor: pointer;
    border-bottom: 2px solid transparent;
    margin-bottom: -2px;
    transition: all 0.2s;
  }

  .tab-button:hover {
    color: #e5e7eb;
  }

  .tab-button.active {
    color: #a855f7;
    border-bottom-color: #a855f7;
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

  .form-label {
    display: block;
    font-size: 0.875rem;
    font-weight: 500;
    color: #d1d5db;
    margin-bottom: 0.5rem;
  }

  .form-input,
  .form-textarea {
    width: 100%;
    padding: 0.75rem 1rem;
    background: rgba(15, 15, 35, 0.6);
    border: 1px solid rgba(168, 85, 247, 0.3);
    border-radius: 0.5rem;
    color: #e5e7eb;
    font-size: 0.875rem;
    transition: all 0.2s;
    font-family: inherit;
  }

  .form-textarea {
    resize: vertical;
    min-height: 120px;
  }

  .form-input:focus,
  .form-textarea:focus {
    outline: none;
    border-color: #a855f7;
    box-shadow: 0 0 0 3px rgba(168, 85, 247, 0.1);
  }

  .form-input:disabled,
  .form-textarea:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .hint {
    display: block;
    font-size: 0.75rem;
    color: #9ca3af;
    margin-top: 0.25rem;
  }

  .button-group {
    display: flex;
    gap: 1rem;
    margin-top: 1.5rem;
  }

  .btn {
    padding: 0.75rem 1.5rem;
    border-radius: 0.5rem;
    font-size: 0.875rem;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.2s;
    display: inline-flex;
    align-items: center;
    gap: 0.5rem;
    border: 1px solid transparent;
  }

  .btn-primary {
    background: linear-gradient(135deg, #a855f7, #6366f1);
    color: white;
  }

  .btn-primary:hover:not(:disabled) {
    transform: translateY(-2px);
    box-shadow: 0 6px 20px rgba(168, 85, 247, 0.4);
  }

  .btn-secondary {
    background: rgba(168, 85, 247, 0.1);
    border-color: rgba(168, 85, 247, 0.3);
    color: #a855f7;
  }

  .btn-secondary:hover:not(:disabled) {
    background: rgba(168, 85, 247, 0.2);
  }

  .btn:disabled {
    opacity: 0.5;
    cursor: not-allowed;
    transform: none !important;
  }

  .btn-small {
    padding: 0.5rem 1rem;
    font-size: 0.75rem;
  }

  .spinner {
    display: inline-block;
    width: 1rem;
    height: 1rem;
    border: 2px solid rgba(255, 255, 255, 0.3);
    border-top-color: white;
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
  }

  @keyframes spin {
    to { transform: rotate(360deg); }
  }

  .progress-card {
    background: rgba(59, 130, 246, 0.1);
    border: 1px solid rgba(59, 130, 246, 0.3);
    border-radius: 0.75rem;
    padding: 1rem;
  }

  .progress-header {
    margin-bottom: 0.75rem;
  }

  .progress-text {
    font-size: 0.875rem;
    color: #93c5fd;
  }

  .progress-bar {
    height: 8px;
    background: rgba(59, 130, 246, 0.2);
    border-radius: 4px;
    overflow: hidden;
  }

  .progress-fill {
    height: 100%;
    background: linear-gradient(90deg, #3b82f6, #8b5cf6);
    transition: width 0.3s ease;
  }

  .error-card {
    background: rgba(239, 68, 68, 0.1);
    border: 1px solid rgba(239, 68, 68, 0.3);
    border-radius: 0.75rem;
    padding: 1rem;
  }

  .error-header {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    margin-bottom: 0.75rem;
  }

  .error-icon {
    font-size: 1.25rem;
  }

  .error-title {
    font-size: 0.875rem;
    font-weight: 600;
    color: #fca5a5;
  }

  .error-list {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }

  .error-item {
    font-size: 0.75rem;
    color: #fca5a5;
    padding: 0.5rem;
    background: rgba(239, 68, 68, 0.1);
    border-radius: 0.25rem;
  }

  .result-section {
    display: flex;
    flex-direction: column;
    gap: 1.5rem;
  }

  .results-container {
    display: flex;
    flex-direction: column;
    gap: 1rem;
  }

  .results-list {
    background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
    border: 1px solid rgba(168, 85, 247, 0.2);
    border-radius: 1rem;
    padding: 1.5rem;
  }

  .results-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 1rem;
  }

  .result-actions {
    display: flex;
    gap: 0.75rem;
    align-items: center;
  }

  .export-dropdown {
    position: relative;
  }

  .export-menu {
    position: absolute;
    top: 100%;
    right: 0;
    margin-top: 0.5rem;
    background: rgba(15, 15, 35, 0.95);
    border: 1px solid rgba(168, 85, 247, 0.3);
    border-radius: 0.5rem;
    overflow: hidden;
    z-index: 10;
    min-width: 150px;
  }

  .export-option {
    display: block;
    width: 100%;
    padding: 0.75rem 1rem;
    background: none;
    border: none;
    color: #e5e7eb;
    font-size: 0.875rem;
    text-align: left;
    cursor: pointer;
    transition: background 0.2s;
  }

  .export-option:hover {
    background: rgba(168, 85, 247, 0.1);
  }

  .view-toggle {
    display: flex;
    gap: 0.25rem;
    background: rgba(15, 15, 35, 0.4);
    border-radius: 0.5rem;
    padding: 0.25rem;
  }

  .toggle-btn {
    padding: 0.5rem 0.75rem;
    background: transparent;
    border: none;
    border-radius: 0.375rem;
    cursor: pointer;
    font-size: 1rem;
    transition: all 0.2s;
  }

  .toggle-btn.active {
    background: rgba(168, 85, 247, 0.2);
    color: #a855f7;
  }

  .toggle-btn:hover:not(.active) {
    background: rgba(168, 85, 247, 0.1);
  }

  .overview-container {
    margin-top: 1rem;
    overflow-x: auto;
  }

  .overview-table {
    width: 100%;
    border-collapse: collapse;
    background: rgba(15, 15, 35, 0.4);
    border-radius: 0.5rem;
    overflow: hidden;
  }

  .overview-header {
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    background: rgba(168, 85, 247, 0.2);
    font-weight: 600;
  }

  .overview-row {
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    border-bottom: 1px solid rgba(168, 85, 247, 0.1);
    cursor: pointer;
    transition: background 0.2s;
  }

  .overview-row:hover {
    background: rgba(168, 85, 247, 0.1);
  }

  .overview-row.active {
    background: rgba(168, 85, 247, 0.2);
  }

  .overview-cell {
    padding: 0.75rem 1rem;
    text-align: left;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .overview-header .overview-cell {
    color: #a855f7;
    font-size: 0.875rem;
  }

  .domain-tabs {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
  }

  .domain-tab {
    padding: 0.5rem 1rem;
    background: rgba(15, 15, 35, 0.4);
    border: 1px solid rgba(168, 85, 247, 0.2);
    border-radius: 0.5rem;
    color: #d1d5db;
    font-size: 0.75rem;
    cursor: pointer;
    transition: all 0.2s;
  }

  .domain-tab:hover {
    background: rgba(168, 85, 247, 0.1);
    border-color: rgba(168, 85, 247, 0.4);
  }

  .domain-tab.active {
    background: rgba(168, 85, 247, 0.2);
    border-color: #a855f7;
    color: #a855f7;
  }

  .result-details {
    background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
    border: 1px solid rgba(168, 85, 247, 0.2);
    border-radius: 1rem;
    padding: 1.5rem;
  }

  .result-meta {
    display: flex;
    gap: 2rem;
    padding: 1rem;
    background: rgba(15, 15, 35, 0.4);
    border-radius: 0.5rem;
    margin-bottom: 1.5rem;
    align-items: center;
    flex-wrap: wrap;
  }

  .meta-item {
    font-size: 0.875rem;
    color: #d1d5db;
  }

  .meta-item strong {
    color: #a855f7;
  }

  .result-actions-inline {
    margin-left: auto;
    display: flex;
    gap: 0.5rem;
  }

  .available-notice {
    text-align: center;
    padding: 2rem;
    background: rgba(34, 197, 94, 0.1);
    border: 1px solid rgba(34, 197, 94, 0.3);
    border-radius: 0.75rem;
    font-size: 1.125rem;
    color: #86efac;
  }

  .result-grid {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 1rem;
  }

  .result-item {
    background: rgba(15, 15, 35, 0.4);
    padding: 1rem;
    border-radius: 0.5rem;
    border: 1px solid rgba(168, 85, 247, 0.1);
  }

  .result-item.full-width {
    grid-column: 1 / -1;
  }

  .result-label {
    font-size: 0.75rem;
    color: #9ca3af;
    margin-bottom: 0.5rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }

  .result-value {
    font-size: 0.875rem;
    color: #e5e7eb;
    word-break: break-word;
  }

  .status-tag,
  .ns-tag {
    display: inline-block;
    padding: 0.25rem 0.75rem;
    background: rgba(168, 85, 247, 0.1);
    border: 1px solid rgba(168, 85, 247, 0.3);
    border-radius: 1rem;
    font-size: 0.75rem;
    color: #c4b5fd;
    margin: 0.25rem;
  }

  .raw-response-section {
    margin-top: 1.5rem;
    padding-top: 1.5rem;
    border-top: 1px solid rgba(168, 85, 247, 0.2);
  }

  .subsection-title {
    font-size: 1rem;
    font-weight: 600;
    margin-bottom: 1rem;
    color: #d1d5db;
  }

  .raw-response {
    background: rgba(15, 15, 35, 0.6);
    padding: 1rem;
    border-radius: 0.5rem;
    font-size: 0.75rem;
    color: #9ca3af;
    overflow-x: auto;
    max-height: 400px;
    overflow-y: auto;
    white-space: pre-wrap;
    word-break: break-word;
  }

  .empty-result {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    padding: 4rem 2rem;
    background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
    border: 1px solid rgba(168, 85, 247, 0.2);
    border-radius: 1rem;
    text-align: center;
  }

  .empty-icon {
    font-size: 4rem;
    margin-bottom: 1rem;
    opacity: 0.5;
  }

  .empty-text {
    font-size: 1.25rem;
    color: #d1d5db;
    margin-bottom: 0.5rem;
  }

  .empty-hint {
    font-size: 0.875rem;
    color: #9ca3af;
  }

  .history-section {
    margin-top: 0;
  }

  .history-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 1.5rem;
  }

  .empty-state {
    text-align: center;
    padding: 3rem 1rem;
    color: #9ca3af;
  }

  .empty-state p {
    font-size: 1rem;
    margin: 0;
  }

  .history-list {
    display: flex;
    flex-direction: column;
    gap: 1rem;
  }

  .history-item {
    background: rgba(15, 15, 35, 0.6);
    border: 1px solid rgba(168, 85, 247, 0.2);
    border-radius: 0.75rem;
    padding: 1rem;
    transition: all 0.2s;
  }

  .history-item:hover {
    border-color: rgba(168, 85, 247, 0.4);
    background: rgba(15, 15, 35, 0.8);
  }

  .history-item-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 0.75rem;
  }

  .history-domain {
    font-size: 1.125rem;
    font-weight: 600;
    color: #a855f7;
    margin: 0;
  }

  .history-actions {
    display: flex;
    gap: 0.5rem;
  }

  .history-item-details {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }

  .detail-row {
    display: flex;
    gap: 0.5rem;
    font-size: 0.875rem;
  }

  .detail-label {
    color: #9ca3af;
    min-width: 80px;
  }

  .detail-value {
    color: #d1d5db;
    flex: 1;
  }

  .btn-danger {
    background: rgba(239, 68, 68, 0.1);
    border-color: rgba(239, 68, 68, 0.3);
  }

  .btn-danger:hover {
    background: rgba(239, 68, 68, 0.2);
    border-color: rgba(239, 68, 68, 0.5);
  }

  .modal-overlay {
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: rgba(0, 0, 0, 0.7);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 1000;
    padding: 2rem;
  }

  .modal-content {
    background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
    border: 1px solid rgba(168, 85, 247, 0.3);
    border-radius: 1rem;
    max-width: 600px;
    width: 100%;
    max-height: 80vh;
    overflow-y: auto;
    box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
  }

  .modal-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 1.5rem;
    border-bottom: 1px solid rgba(168, 85, 247, 0.2);
  }

  .modal-header h2 {
    font-size: 1.5rem;
    font-weight: 600;
    color: #f1f5f9;
    margin: 0;
  }

  .modal-close {
    background: none;
    border: none;
    color: #9ca3af;
    font-size: 1.5rem;
    cursor: pointer;
    padding: 0.25rem;
    transition: color 0.2s;
  }

  .modal-close:hover {
    color: #e5e7eb;
  }

  .modal-body {
    padding: 1.5rem;
  }

  .help-section {
    margin-bottom: 2rem;
  }

  .help-section:last-child {
    margin-bottom: 0;
  }

  .help-section h3 {
    font-size: 1.125rem;
    font-weight: 600;
    color: #a855f7;
    margin-bottom: 1rem;
  }

  .help-section p {
    color: #d1d5db;
    line-height: 1.6;
    margin-bottom: 1rem;
  }

  .example-list,
  .feature-list,
  .tip-list {
    list-style: none;
    padding: 0;
    margin: 0;
  }

  .example-list li,
  .feature-list li,
  .tip-list li {
    padding: 0.5rem 0;
    color: #d1d5db;
    font-size: 0.875rem;
  }

  .example-list li {
    padding-left: 1rem;
  }

  .example-list code {
    background: rgba(168, 85, 247, 0.1);
    padding: 0.25rem 0.5rem;
    border-radius: 0.25rem;
    font-size: 0.875rem;
    color: #c4b5fd;
  }

  .feature-list li {
    border-bottom: 1px solid rgba(168, 85, 247, 0.1);
  }

  .feature-list li:last-child {
    border-bottom: none;
  }

  .feature-list li.example {
    font-style: italic;
    color: #9ca3af;
    font-size: 0.75rem;
    padding-left: 1.5rem;
  }

  .tip-list li {
    position: relative;
    padding-left: 1.5rem;
  }

  .tip-list li::before {
    content: '💡';
    position: absolute;
    left: 0;
  }

  @media (max-width: 768px) {
    .content-grid {
      grid-template-columns: 1fr;
    }

    .page-header {
      flex-direction: column;
      gap: 1rem;
    }

    .result-grid {
      grid-template-columns: 1fr;
    }

    .result-meta {
      flex-direction: column;
      align-items: flex-start;
    }

    .result-actions-inline {
      margin-left: 0;
      margin-top: 1rem;
    }
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
    background: linear-gradient(135deg, #dc2626 0%, #991b1b 100%);
    color: white;
    border: 1px solid #ef4444;
    border-radius: 0.5rem;
    cursor: pointer;
    transition: all 0.3s ease;
    font-weight: 500;
  }

  .btn-confirm-danger:hover {
    background: linear-gradient(135deg, #ef4444 0%, #b91c1c 100%);
    transform: translateY(-1px);
    box-shadow: 0 4px 12px rgba(239, 68, 68, 0.3);
  }

  .target-buttons {
    display: flex;
    gap: 0.5rem;
    margin-top: 0.5rem;
    margin-bottom: 0.5rem;
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

  .select-target-btn:hover:not(:disabled) {
    background: linear-gradient(135deg, #059669 0%, #047857 100%);
    transform: translateY(-1px);
  }

  .select-target-btn:active {
    transform: translateY(0);
  }

  .select-target-btn:disabled {
    opacity: 0.5;
    cursor: not-allowed;
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

  .loading-message {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    padding: 3rem;
    color: #9ca3af;
  }

  .spinner {
    width: 2rem;
    height: 2rem;
    border: 3px solid rgba(16, 185, 129, 0.2);
    border-top-color: #10b981;
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
    margin-bottom: 1rem;
  }

  @keyframes spin {
    to { transform: rotate(360deg); }
  }

  .empty-message {
    text-align: center;
    padding: 3rem;
    color: #9ca3af;
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
</style>
