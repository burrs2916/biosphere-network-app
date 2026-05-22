<script lang="ts">
  import { onMount } from 'svelte';
  import { invoke } from '@tauri-apps/api/core';
  import { listen } from '@tauri-apps/api/event';
  import { save, open } from '@tauri-apps/plugin-dialog';
  import { writeFile, readFile } from '@tauri-apps/plugin-fs';
  import { tr, locale } from '$lib/i18n';


  interface ServiceVersion {
    service: string;
    version: string;
    banner?: string;
  }

  interface ScanResult {
    data: string;
    success: boolean;
    error?: string;
  }

  interface PortResult {
    target?: string;
    port: number;
    status: string;
    service?: string;
    version?: ServiceVersion;
    banner?: string;
  }

  interface ProgressEvent {
    scanned: number;
    total: number;
    open: number;
  }

  interface OSDetectionResult {
    os_type: string;
    os_family: string;
    confidence: number;
    ttl: number | null;
    details: string[];
    display: string;
  }

  let target = '';

  let startPort = 1;
  let endPort = 1024;
  let timeoutMs = 1000;
  let scanMode = 'standard';
  let scanning = false;
  let result = '';
  let error = '';
  let portResults: PortResult[] = [];
  let scannedCount = 0;
  let totalPorts = 0;
  let openCount = 0;
  let scanStartTime = 0;
  let showExportMenu = false;
  let showHelpModal = false;
  let showOSDetailModal = false;
  let showConfirmDialog = false;
  let confirmDialogTitle = '';
  let confirmDialogMessage = '';
  let confirmAction: (() => Promise<void>) | null = null;
  let osDetectionResults: Map<string, OSDetectionResult> = new Map();
  let selectedOSResult: OSDetectionResult | null = null;
  
  let currentPage = 1;
  let jumpPage = 1;
  let pageSize = 10;
  
  interface SystemInfo {
    cpu_cores: number;
    total_memory_mb: number;
    available_memory_mb: number;
    cpu_usage_percent: number;
    load_average: number;
    optimal_concurrency: number;
    recommended_timeout: number;
  }
  
  let systemInfo: SystemInfo | null = null;

  let activeTab = 'scan';
  let history: any[] = [];
  let loadingHistory = false;
  let historyError = '';
  let historyCurrentPage = 1;
  let historyPageSize = 20;
  let selectedHistoryItem: any = null;
  let showHistoryDetail = false;

  $: scanModes = [
    { value: 'quick', label: $tr('portScanner.modes.quick') },
    { value: 'standard', label: $tr('portScanner.modes.standard') },
    { value: 'full', label: $tr('portScanner.modes.full') },
    { value: 'custom', label: $tr('portScanner.modes.custom') },
  ];

  $: progress = totalPorts > 0 ? Math.round((scannedCount / totalPorts) * 100) : 0;
  $: scanSpeed = scanStartTime > 0 ? Math.round(scannedCount / ((Date.now() - scanStartTime) / 1000)) : 0;
  $: estimatedTime = scanSpeed > 0 ? Math.round((totalPorts - scannedCount) / scanSpeed) : 0;
  
  $: totalPages = Math.ceil(portResults.length / pageSize);
  $: paginatedResults = portResults.slice((currentPage - 1) * pageSize, currentPage * pageSize);

  let showTargetSelector = false;
  let targetList: any[] = [];
  let selectedTargets: any[] = [];
  let selectedTargetIds: number[] = [];
  let loadingTargets = false;
  let targetSearchQuery = '';
  
  let portInfoCache: Map<number, any> = new Map();
  
  $: filteredTargets = targetList.filter(t => 
    !targetSearchQuery || 
    t.name.toLowerCase().includes(targetSearchQuery.toLowerCase()) ||
    t.target_value.toLowerCase().includes(targetSearchQuery.toLowerCase())
  );

  async function getPortInfo(port: number) {
    if (portInfoCache.has(port)) {
      return portInfoCache.get(port);
    }
    
    try {
      const info = await invoke('get_port_info', { port });
      portInfoCache.set(port, info);
      return info;
    } catch (e) {
      return null;
    }
  }

  function getRiskColor(risk: string): string {
    switch (risk) {
      case 'Critical': return '#dc2626';
      case 'High': return '#ea580c';
      case 'Medium': return '#ca8a04';
      case 'Low': return '#16a34a';
      case 'Info': return '#6b7280';
      default: return '#6b7280';
    }
  }

  function getCategoryIcon(category: string): string {
    const icons: Record<string, string> = {
      'Web': '🌐',
      'Database': '🗄️',
      'RemoteAccess': '🖥️',
      'Mail': '📧',
      'FileTransfer': '📁',
      'Administration': '⚙️',
      'IoT': '🔌',
      'Development': '💻',
      'Messaging': '💬',
      'Streaming': '🎬',
      'VPN': '🔒',
      'Proxy': '🔄',
      'Printing': '🖨️',
      'Gaming': '🎮',
      'Other': '❓'
    };
    return icons[category] || '❓';
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
            extensions: ['txt', 'csv', 'list']
          }
        ]
      });

      if (selected) {
        const fileData = await readFile(selected as string);
        const content = new TextDecoder('utf-8').decode(fileData);
        
        const targets = content
          .split(/[\n,;]/)
          .map(t => t.trim())
          .filter(t => t && !t.startsWith('#') && t.length > 0);
        
        if (targets.length > 0) {
          target = targets.join(',');
          error = '';
        } else {
          error = $tr('portScanner.errors.noValidTargets');
        }
      }
    } catch (e) {
      error = $tr('portScanner.errors.importFailed', { error: String(e) });
    }
  }

  async function scanPorts() {
    if (!target.trim()) {
      error = $tr('portScanner.errors.emptyTarget');
      return;
    }

    const targets = target.split(',').map(t => t.trim()).filter(t => t);
    if (targets.length === 0) {
      error = $tr('portScanner.errors.invalidTarget');
      return;
    }

    scanning = true;
    error = '';
    result = '';
    portResults = [];
    scannedCount = 0;
    openCount = 0;
    scanStartTime = Date.now();
    currentPage = 1;
    osDetectionResults = new Map();

    let taskId: number | null = null;
    
    try {
      taskId = await invoke<number>('save_scan_task', {
        target: targets.join(','),
        scanMode: scanMode,
      });
    } catch (e) {
      console.error('Failed to save scan task:', e);
    }

    const osDetectionPromise = detectOS();

    const unlisten = await listen<ProgressEvent>('scan-progress', (event) => {
      scannedCount = event.payload.scanned;
      totalPorts = event.payload.total;
      openCount = event.payload.open;
    });

    try {
      const output = await invoke<ScanResult>('scan_ports', {
        target: targets.join(','),
        startPort: startPort,
        endPort: endPort,
        timeoutMs: timeoutMs,
        scanMode: scanMode,
        targetId: selectedTargetIds.length > 0 ? selectedTargetIds[0] : null,
      });

      result = output.data || $tr('portScanner.noOpenPorts');
      
      if (output.success && output.data) {
        portResults = parseResults(output.data);
        
        // Load port information for all open ports
        const openPorts = [...new Set(portResults.filter(r => r.status === 'Open').map(r => r.port))];
        await Promise.all(openPorts.map(port => getPortInfo(port)));
        
        await osDetectionPromise;
        
        if (taskId && portResults.length > 0) {
          try {
            const scanResults = portResults.map(r => {
              const osResult = getOSForTarget(r.target);
              return {
                task_id: taskId,
                target: r.target || targets[0],
                port: r.port,
                status: r.status,
                service: r.service || null,
                version: r.version?.version || null,
                banner: r.banner || null,
                os_detection: osResult?.display || null,
                created_at: new Date().toISOString(),
              };
            });
            
            await invoke('save_scan_results', {
              taskId: taskId,
              results: scanResults,
            });
            
            await invoke('update_scan_task', {
              taskId: taskId,
              totalPorts: totalPorts,
              openPorts: openCount,
              status: 'completed',
            });
          } catch (e) {
            console.error('Failed to save scan results:', e);
          }
        }
      }
    } catch (e) {
      error = $tr('portScanner.errors.scanFailed', { error: String(e) });
      
      if (taskId) {
        try {
          await invoke('update_scan_task', {
            taskId: taskId,
            totalPorts: totalPorts,
            openPorts: openCount,
            status: 'failed',
          });
        } catch (updateError) {
          console.error('Failed to update task status:', updateError);
        }
      }
    } finally {
      unlisten();
      scanning = false;
    }
  }

  function parseResults(data: string): PortResult[] {
    const results: PortResult[] = [];
    const lines = data.split('\n');
    let currentTarget: string | undefined;
    
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (!line || line.length < 10) continue;
      
      if (line[0] === '[' && line[line.length - 1] === ']') {
        currentTarget = line.substring(1, line.length - 1).trim();
        continue;
      }
      
      const colonIndex = line.indexOf(':');
      if (colonIndex > 0 && line.indexOf('Port ') > colonIndex) {
        const target = line.substring(0, colonIndex).trim();
        const portStart = line.indexOf('Port ') + 5;
        const portEnd = line.indexOf(' - ', portStart);
        const port = parseInt(line.substring(portStart, portEnd));
        const statusStart = portEnd + 3;
        const statusEnd = line.indexOf(' ', statusStart);
        const status = line.substring(statusStart, statusEnd);
        let serviceInfo = line.substring(statusEnd + 1).trim();
        
        let service: string | undefined;
        let version: ServiceVersion | undefined;
        let banner: string | undefined;

        const bannerMarker = ' | Banner: ';
        const bannerIndex = serviceInfo.lastIndexOf(bannerMarker);
        if (bannerIndex > 0) {
          banner = serviceInfo.substring(bannerIndex + bannerMarker.length).trim();
          serviceInfo = serviceInfo.substring(0, bannerIndex).trim();
        }

        if (serviceInfo && serviceInfo !== 'unknown') {
          const parenIndex = serviceInfo.indexOf('(');
          if (parenIndex > 0 && serviceInfo[serviceInfo.length - 1] === ')') {
            service = serviceInfo.substring(0, parenIndex - 1);
            version = {
              service: service,
              version: serviceInfo.substring(parenIndex + 1, serviceInfo.length - 1),
            };
          } else {
            service = serviceInfo;
          }
        }

        results.push({
          target,
          port,
          status,
          service,
          version,
          banner,
        });
        continue;
      }
      
      const portIndex = line.indexOf('Port ');
      if (portIndex >= 0 && currentTarget) {
        const portStart = portIndex + 5;
        const portEnd = line.indexOf(' - ', portStart);
        if (portEnd > portStart) {
          const port = parseInt(line.substring(portStart, portEnd));
          const statusStart = portEnd + 3;
          const statusEnd = line.indexOf(' ', statusStart);
          const status = line.substring(statusStart, statusEnd);
          let serviceInfo = line.substring(statusEnd + 1).trim();
          
          let service: string | undefined;
          let version: ServiceVersion | undefined;
          let banner: string | undefined;

          const bannerMarker = ' | Banner: ';
          const bannerIndex = serviceInfo.lastIndexOf(bannerMarker);
          if (bannerIndex > 0) {
            banner = serviceInfo.substring(bannerIndex + bannerMarker.length).trim();
            serviceInfo = serviceInfo.substring(0, bannerIndex).trim();
          }

          if (serviceInfo && serviceInfo !== 'unknown') {
            const parenIndex = serviceInfo.indexOf('(');
            if (parenIndex > 0 && serviceInfo[serviceInfo.length - 1] === ')') {
              service = serviceInfo.substring(0, parenIndex - 1);
              version = {
                service: service,
                version: serviceInfo.substring(parenIndex + 1, serviceInfo.length - 1),
              };
            } else {
              service = serviceInfo;
            }
          }

          results.push({
            target: currentTarget,
            port,
            status,
            service,
            version,
            banner,
          });
        }
      }
    }
    
    return results;
  }

  async function detectOS() {
    if (!target.trim()) {
      return;
    }

    const targets = target.split(',').map(t => t.trim()).filter(t => t);
    if (targets.length === 0) {
      return;
    }
    
    osDetectionResults = new Map();

    const detectionPromises = targets.map(async (t) => {
      try {
        const result = await invoke<OSDetectionResult>('detect_os', {
          target: t,
          timeoutMs: 3000,
        });
        return { target: t, result };
      } catch (e) {
        return { target: t, result: null };
      }
    });

    const results = await Promise.all(detectionPromises);
    
    for (const item of results) {
      if (item && item.result) {
        osDetectionResults.set(item.target, item.result);
      }
    }
  }

  function getOSForTarget(targetName: string | undefined): OSDetectionResult | null {
    if (!targetName) return null;
    
    const baseTarget = targetName.split(' ')[0].split('(')[0].trim();
    
    if (osDetectionResults.has(baseTarget)) {
      return osDetectionResults.get(baseTarget) || null;
    }
    
    for (const [key, value] of osDetectionResults.entries()) {
      if (baseTarget.includes(key) || key.includes(baseTarget)) {
        return value;
      }
    }
    
    return null;
  }

  function openOSDetail(targetName: string | undefined) {
    const osResult = getOSForTarget(targetName);
    if (osResult) {
      selectedOSResult = osResult;
      showOSDetailModal = true;
    }
  }

  async function reset() {
    if (scanning) {
      try {
        await invoke('cancel_scan');
      } catch (e) {
        console.error($tr('portScanner.errors.cancelFailed'), e);
      }
    }
    
    target = '';
    startPort = 1;
    endPort = 1024;
    timeoutMs = 1000;
    scanMode = 'standard';
    scanning = false;
    result = '';
    error = '';
    portResults = [];
    scannedCount = 0;
    totalPorts = 0;
    openCount = 0;
    currentPage = 1;
    osDetectionResults = new Map();
    selectedOSResult = null;
  }

  function escapeCSVField(field: string): string {
    if (field.includes(',') || field.includes('"') || field.includes('\n')) {
      return `"${field.replace(/"/g, '""')}"`;
    }
    return field;
  }

  async function exportResults(format: 'json' | 'csv' | 'txt') {
    showExportMenu = false;
    
    if (portResults.length === 0) {
      error = $tr('portScanner.noResults');
      return;
    }

    try {
      const filePath = await save({
        defaultPath: `port_scan_${target.replace(/\./g, '_')}_${Date.now()}.${format}`,
        filters: [
          { name: format.toUpperCase(), extensions: [format] }
        ]
      });

      if (!filePath) return;

      let content = '';
      const encoder = new TextEncoder();

      switch (format) {
        case 'json':
          content = JSON.stringify({
            target,
            scanMode,
            timestamp: new Date().toISOString(),
            totalPorts,
            openPorts: openCount,
            results: portResults
          }, null, 2);
          break;

        case 'csv':
          content = 'Port,Status,Service,Version,Banner\n';
          content += portResults.map(r => {
            const port = r.port.toString();
            const status = escapeCSVField(r.status);
            const service = escapeCSVField(r.service || 'N/A');
            const version = escapeCSVField(r.version?.version || 'N/A');
            const banner = escapeCSVField(r.banner || 'N/A');
            return `${port},${status},${service},${version},${banner}`;
          }).join('\n');
          break;

        case 'txt':
          content = `Port Scan Results for ${target}\n`;
          content += `Scan Mode: ${scanMode}\n`;
          content += `Timestamp: ${new Date().toISOString()}\n`;
          content += `Total Ports: ${totalPorts}\n`;
          content += `Open Ports: ${openCount}\n\n`;
          content += result;
          break;
      }

      const data = encoder.encode(content);
      await writeFile(filePath, data);
      
      error = '';
    } catch (e) {
      error = $tr('portScanner.errors.exportFailed', { error: String(e) });
      console.error('Export error:', e);
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

  function toggleExportMenu(event: MouseEvent) {
    event.stopPropagation();
    showExportMenu = !showExportMenu;
  }

  function handleClickOutside(event: MouseEvent) {
    const targetElement = event.target as HTMLElement;
    if (!targetElement.closest('.export-dropdown')) {
      showExportMenu = false;
    }
  }

  function goToPage(page: number) {
    if (page >= 1 && page <= totalPages) {
      currentPage = page;
    }
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

  async function loadHistory() {
    loadingHistory = true;
    historyError = '';
    
    try {
      history = await invoke('get_scan_history', {
        limit: historyPageSize,
        offset: (historyCurrentPage - 1) * historyPageSize,
      });
    } catch (e) {
      historyError = `${$tr('portScanner.history.messages.loadFailed')}: ${e}`;
    } finally {
      loadingHistory = false;
    }
  }

  async function deleteHistoryItem(id: number) {
    showConfirm(
      $tr('portScanner.history.messages.deleteConfirm'),
      $tr('portScanner.history.messages.deleteConfirmMessage'),
      async () => {
        try {
          await invoke('delete_scan_task', { taskId: id });
          await loadHistory();
        } catch (e) {
          historyError = `${$tr('portScanner.history.messages.deleteFailed')}: ${e}`;
        }
      }
    );
  }

  async function clearAllHistory() {
    showConfirm(
      $tr('portScanner.history.messages.clearAllConfirm'),
      $tr('portScanner.history.messages.clearAllConfirmMessage'),
      async () => {
        try {
          const allTasks: any[] = await invoke('get_scan_history', { limit: 1000, offset: 0 });
          for (const task of allTasks) {
            await invoke('delete_scan_task', { taskId: task.id });
          }
          await loadHistory();
        } catch (e) {
          historyError = `${$tr('portScanner.history.messages.clearFailed')}: ${e}`;
        }
      }
    );
  }

  async function viewHistoryDetail(item: any) {
    try {
      const detail = await invoke('get_scan_task_detail', { taskId: item.id });
      if (detail) {
        selectedHistoryItem = {
          ...item,
          results: (detail as any).results || []
        };
        showHistoryDetail = true;
      }
    } catch (e) {
      console.error('Failed to load scan task detail:', e);
      selectedHistoryItem = item;
      showHistoryDetail = true;
    }
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

  async function loadSystemInfo() {
    try {
      systemInfo = await invoke<SystemInfo>('get_system_info');
    } catch (e) {
      console.error('Failed to load system info:', e);
    }
  }

  onMount(() => {
    loadSystemInfo();
    document.addEventListener('click', handleClickOutside);
    return () => {
      document.removeEventListener('click', handleClickOutside);
    };
  });
</script>

<svelte:window on:click={handleClickOutside} />

<div class="port-scanner-page">
  <div class="page-header">
    <a href="/" class="back-link">{$tr('common.backToHome')}</a>
    <div class="header-content">
      <div class="title-section">
        <h1 class="page-title">{$tr('portScanner.title')}</h1>
        <p class="page-subtitle">{$tr('portScanner.subtitle')}</p>
      </div>
        <button class="help-btn" on:click={() => showHelpModal = true} title={$tr('common.userManual')}>
        {$tr('common.userManual')}
      </button>
    </div>
  </div>

  <div class="tabs">
    <button 
      class="tab-button {activeTab === 'scan' ? 'active' : ''}" 
      on:click={() => activeTab = 'scan'}
    >
      {$tr('portScanner.history.tabs.scan')}
    </button>
    <button 
      class="tab-button {activeTab === 'history' ? 'active' : ''}" 
      on:click={() => { activeTab = 'history'; loadHistory(); }}
    >
      {$tr('portScanner.history.tabs.history')}
    </button>
  </div>

  {#if activeTab === 'scan'}
  <div class="content-grid">
    <div class="config-section">
      <div class="section-card">
        <h2 class="section-title">{$tr('portScanner.scanConfig')}</h2>
        
        <form on:submit|preventDefault={scanPorts}>
            <div class="form-group">
              <label for="target">{$tr('portScanner.target')} *</label>
              <div class="target-input-wrapper">
                <textarea
                  id="target"
                  bind:value={target}
                  placeholder={$tr('portScanner.targetPlaceholder')}
                  rows="6"
                  required
                ></textarea>
                <div class="target-buttons">
                  <button type="button" class="select-target-btn" on:click={openTargetSelector}>
                    {$tr('portScanner.selectFromTargets')}
                  </button>
                  <button type="button" class="import-btn" on:click={importTargets} title={$tr('portScanner.importFileTitle')}>
                    {$tr('portScanner.importFromFile')}
                  </button>
                </div>
              </div>
              <span class="input-hint">{$tr('portScanner.targetHint')}</span>
            </div>

          <div class="form-group">
            <label for="scanMode">{$tr('portScanner.scanMode')}</label>
            <select id="scanMode" bind:value={scanMode}>
              {#each scanModes as mode}
                <option value={mode.value}>{mode.label}</option>
              {/each}
            </select>
          </div>

          {#if scanMode === 'custom'}
            <div class="form-row">
              <div class="form-group">
                <label for="startPort">{$tr('portScanner.startPort')}</label>
                <input
                  type="number"
                  id="startPort"
                  bind:value={startPort}
                  min="1"
                  max="65535"
                />
              </div>

              <div class="form-group">
                <label for="endPort">{$tr('portScanner.endPort')}</label>
                <input
                  type="number"
                  id="endPort"
                  bind:value={endPort}
                  min="1"
                  max="65535"
                />
              </div>
            </div>
          {/if}

          <div class="form-group">
            <label for="timeout">{$tr('portScanner.timeout')}</label>
            <input
              type="number"
              id="timeout"
              bind:value={timeoutMs}
              min="100"
              max="10000"
              step="100"
            />
          </div>

          <div class="button-group">
            <button type="submit" class="btn-primary" disabled={scanning}>
              {#if scanning}
                <span class="spinner"></span>
                {$tr('portScanner.scanning')}
              {:else}
                {$tr('portScanner.startScan')}
              {/if}
            </button>
            <button type="button" class="btn-secondary" on:click={reset}>
              {$tr('portScanner.reset')}
            </button>
          </div>
        </form>
      </div>

      <div class="info-card">
        <h3>{$tr('portScanner.usageGuide')}</h3>
        <ul>
          <li>{$tr('portScanner.usageGuideItems.item1')}</li>
          <li>{$tr('portScanner.usageGuideItems.item2')}</li>
          <li>{$tr('portScanner.usageGuideItems.item3')}</li>
          <li>{$tr('portScanner.usageGuideItems.item4')}</li>
          <li>{$tr('portScanner.usageGuideItems.item5')}</li>
          <li>{$tr('portScanner.usageGuideItems.item6')}</li>
        </ul>
      </div>
      
      {#if systemInfo}
        <div class="info-card system-info-card">
          <h3>{$tr('portScanner.systemInfo')}</h3>
          <div class="system-info-grid">
            <div class="info-item">
              <span class="info-label">{$tr('portScanner.systemInfoLabels.cpuCores')}</span>
              <span class="info-value">{systemInfo.cpu_cores} {$tr('common.cores')}</span>
            </div>
            <div class="info-item">
              <span class="info-label">{$tr('portScanner.systemInfoLabels.availableMemory')}</span>
              <span class="info-value">{(systemInfo.available_memory_mb / 1024).toFixed(1)} GB</span>
            </div>
            <div class="info-item">
              <span class="info-label">{$tr('portScanner.systemInfoLabels.cpuUsage')}</span>
              <span class="info-value">{systemInfo.cpu_usage_percent.toFixed(1)}%</span>
            </div>
            <div class="info-item">
              <span class="info-label">{$tr('portScanner.systemInfoLabels.systemLoad')}</span>
              <span class="info-value">{systemInfo.load_average.toFixed(2)}</span>
            </div>
            <div class="info-item highlight">
              <span class="info-label">{$tr('portScanner.systemInfoLabels.recommendedConcurrency')}</span>
              <span class="info-value">{systemInfo.optimal_concurrency}</span>
            </div>
            <div class="info-item">
              <span class="info-label">{$tr('portScanner.systemInfoLabels.recommendedTimeout')}</span>
              <span class="info-value">{systemInfo.recommended_timeout} ms</span>
            </div>
          </div>
          <p class="info-note">{$tr('portScanner.systemInfoNote')}</p>
        </div>
      {/if}
    </div>

    <div class="result-section">
      {#if error}
        <div class="error-card">
          <div class="error-icon">⚠️</div>
          <div class="error-message">{error}</div>
        </div>
      {/if}

      {#if result}
        <div class="result-card">
          <div class="result-header">
            <h2>{$tr('portScanner.results.scanResults')}</h2>
            <div class="result-actions">
              <button type="button" class="copy-btn" on:click={() => navigator.clipboard.writeText(result)}>
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
          
          {#if portResults.length > 0}
            <div class="results-info">
              <span class="results-count">{$tr('portScanner.results.totalResults', { count: portResults.length })}</span>
              <span class="results-separator">|</span>
              <span class="open-count">{$tr('portScanner.results.openPortsCount', { count: openCount })}</span>
            </div>
            
            <div class="results-table">
              <table>
                <thead>
                  <tr>
                    <th>{$tr('portScanner.results.target')}</th>
                    <th>{$tr('portScanner.results.port')}</th>
                    <th>{$tr('portScanner.results.status')}</th>
                    <th>{$tr('portScanner.results.service')}</th>
                    <th class="os-header">{$tr('portScanner.results.action')}</th>
                  </tr>
                </thead>
                <tbody>
                  {#each paginatedResults as portResult}
                    <tr>
                      <td class="target-cell">{portResult.target || '-'}</td>
                      <td class="port-cell">{portResult.port}</td>
                      <td class="status-cell">
                        <span class="status-badge {portResult.status.toLowerCase()}">
                          {portResult.status}
                        </span>
                      </td>
                      <td class="service-cell">
                        {#if portResult.status === 'Open'}
                          {@const portInfo = portInfoCache.get(portResult.port)}
                          <div class="service-info">
                            <div class="service-main">
                              {#if portInfo}
                                <span class="category-icon">{getCategoryIcon(portInfo.category)}</span>
                              {/if}
                              <span class="service-name">
                                {portResult.service || portInfo?.service || 'unknown'}
                              </span>
                              {#if portInfo}
                                <span 
                                  class="risk-badge" 
                                  style="background-color: {getRiskColor(portInfo.risk_level)}"
                                  title={$tr('portScanner.results.riskLevelLabel', { level: portInfo.risk_level })}
                                >
                                  {portInfo.risk_level}
                                </span>
                              {/if}
                            </div>
                            {#if portInfo?.description}
                              <div class="service-description">{portInfo.description}</div>
                            {/if}
                          </div>
                        {:else if portResult.service}
                          <span class="service-name">{portResult.service}</span>
                        {:else}
                          <span class="unknown">-</span>
                        {/if}
                      </td>
                      <td class="os-cell">
                        {#if getOSForTarget(portResult.target)}
                          {@const osResult = getOSForTarget(portResult.target)}
                          <button class="os-badge clickable" on:click={() => openOSDetail(portResult.target)} title={$tr('portScanner.results.clickForDetails')}>
                            {#if osResult?.os_family === 'Windows'}
                              🪟 Windows
                            {:else if osResult?.os_family === 'Unix-like'}
                              🐧 Linux
                            {:else if osResult?.os_family === 'Network'}
                              🌐 Network
                            {:else}
                              ❓ Other
                            {/if}
                          </button>
                        {:else}
                          <span class="no-os">-</span>
                        {/if}
                      </td>
                    </tr>
                  {/each}
                </tbody>
              </table>
            </div>
            
            {#if totalPages > 1}
              <div class="pagination">
                <button 
                  class="pagination-btn" 
                  on:click={previousPage}
                  disabled={currentPage === 1}
                >
                  ← {$tr('common.previous')}
                </button>
                
                <div class="pagination-info">
                  <span class="page-info">{$tr('common.page')} {currentPage} / {totalPages}</span>
                  
                  <div class="page-jump">
                    <span>{$tr('common.jumpTo')}</span>
                    <input 
                      type="number" 
                      min="1" 
                      max={totalPages}
                      bind:value={jumpPage}
                      on:keypress={(e) => {
                        if (e.key === 'Enter') {
                          goToPage(jumpPage);
                        }
                      }}
                    />
                    <button 
                      class="jump-btn"
                      on:click={() => goToPage(jumpPage)}
                      disabled={jumpPage < 1 || jumpPage > totalPages}
                    >
                      {$tr('common.go')}
                    </button>
                  </div>
                </div>
                
                <button 
                  class="pagination-btn" 
                  on:click={nextPage}
                  disabled={currentPage === totalPages}
                >
                  {$tr('common.next')} →
                </button>
              </div>
            {/if}
          {:else}
            <pre class="result-output">{result}</pre>
          {/if}
        </div>
      {:else if !scanning}
        <div class="empty-state">
          <div class="empty-icon">🔍</div>
          <p>{$tr('portScanner.results.emptyState')}</p>
        </div>
      {/if}

      {#if scanning}
        <div class="loading-state">
          <div class="spinner-large"></div>
          <div class="progress-info">
            <div class="progress-bar">
              <div class="progress-fill" style="width: {progress}%"></div>
            </div>
            <div class="progress-stats">
              <div class="stat-item">
                <span class="stat-label">{$tr('portScanner.progress')}</span>
                <span class="stat-value">{scannedCount} / {totalPorts}</span>
              </div>
              <div class="stat-item">
                <span class="stat-label">{$tr('portScanner.openPorts')}</span>
                <span class="stat-value open">{openCount}</span>
              </div>
              <div class="stat-item">
                <span class="stat-label">{$tr('portScanner.scanSpeed')}</span>
                <span class="stat-value">{scanSpeed} {$tr('common.portsPerSec')}</span>
              </div>
              <div class="stat-item">
                <span class="stat-label">{$tr('portScanner.estimatedTime')}</span>
                <span class="stat-value">{estimatedTime}s</span>
              </div>
            </div>
          </div>
        </div>
      {/if}
    </div>
  </div>
  {:else}
  <div class="history-section">
    <div class="history-header">
      <h2>{$tr('portScanner.history.title')}</h2>
      <div class="history-actions">
        <button type="button" class="btn-clear-history" on:click={clearAllHistory}>
          🗑️ {$tr('portScanner.history.actions.clearAll')}
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
        <button on:click={loadHistory}>{$tr('common.retry')}</button>
      </div>
    {:else if history.length === 0}
      <div class="empty-state">
        <div class="empty-icon">📋</div>
        <p>{$tr('portScanner.history.messages.noHistory')}</p>
      </div>
    {:else}
      <div class="history-table">
        <table>
          <thead>
            <tr>
              <th>{$tr('portScanner.history.table.target')}</th>
              <th>{$tr('portScanner.history.table.scanMode')}</th>
              <th>{$tr('portScanner.history.table.ports')}</th>
              <th>{$tr('portScanner.history.table.status')}</th>
              <th>{$tr('portScanner.history.table.createdAt')}</th>
              <th>{$tr('portScanner.history.table.actions')}</th>
            </tr>
          </thead>
          <tbody>
            {#each history as item (item.id)}
              <tr>
                <td>{item.target}</td>
                <td>{item.scan_mode}</td>
                <td>{item.total_ports} ({$tr('portScanner.results.openLabel', { count: item.open_ports })})</td>
                <td>{item.status}</td>
                <td>{formatDateTime(item.created_at)}</td>
                <td class="actions-cell">
                  <button 
                    class="btn-small btn-primary" 
                    on:click|stopPropagation={() => viewHistoryDetail(item)}
                  >
                    👁️ {$tr('portScanner.history.actions.view')}
                  </button>
                  <button 
                    type="button"
                    class="btn-small btn-danger" 
                    on:click|stopPropagation={() => deleteHistoryItem(item.id)}
                  >
                    🗑️ {$tr('portScanner.history.actions.delete')}
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

{#if showHistoryDetail && selectedHistoryItem}
  <div class="modal-overlay">
    <div 
      class="modal-content detail-modal" 
      role="dialog"
      aria-modal="true"
    >
      <div class="modal-header">
        <h2>📋 {$tr('portScanner.history.actions.view')} - {selectedHistoryItem.target}</h2>
        <button class="modal-close" on:click={() => showHistoryDetail = false}>✕</button>
      </div>
      
      <div class="modal-body">
        <div class="detail-info">
          <div class="detail-item">
            <span class="detail-label">🎯 {$tr('portScanner.history.table.target')}:</span>
            <span class="detail-value">{selectedHistoryItem.target}</span>
          </div>
          <div class="detail-item">
            <span class="detail-label">⚙️ {$tr('portScanner.history.table.scanMode')}:</span>
            <span class="detail-value">{selectedHistoryItem.scan_mode}</span>
          </div>
          <div class="detail-item">
            <span class="detail-label">🔢 {$tr('portScanner.history.table.ports')}:</span>
            <span class="detail-value">{selectedHistoryItem.total_ports} ({$tr('portScanner.results.openLabel', { count: selectedHistoryItem.open_ports })})</span>
          </div>
          <div class="detail-item">
            <span class="detail-label">📊 {$tr('portScanner.history.table.status')}:</span>
            <span class="detail-value status-{selectedHistoryItem.status}">{selectedHistoryItem.status}</span>
          </div>
          <div class="detail-item">
            <span class="detail-label">🕐 {$tr('portScanner.history.table.createdAt')}:</span>
            <span class="detail-value">{formatDateTime(selectedHistoryItem.created_at)}</span>
          </div>
        </div>
        
        {#if selectedHistoryItem.results && selectedHistoryItem.results.length > 0}
          <div class="detail-results">
            <h3>📊 {$tr('portScanner.history.table.results')} ({selectedHistoryItem.results.length})</h3>
            <div class="results-table-wrapper">
              <table>
                <thead>
                  <tr>
                    <th>Target</th>
                    <th>Port</th>
                    <th>Status</th>
                    <th>Service</th>
                    <th>OS</th>
                  </tr>
                </thead>
                <tbody>
                  {#each selectedHistoryItem.results as result}
                    <!-- svelte-ignore component_name_lowercase -->
                    <tr>
                      <td class="target-cell">{result.target}</td>
                      <td class="port-cell">{result.port}</td>
                      <td class="status-cell">
                        <span class="status-badge status-{result.status}">{result.status}</span>
                      </td>
                      <td class="service-cell">{result.service || '-'}</td>
                      <td class="os-cell">
                        {#if result.os_detection && !result.os_detection.includes('Unknown')}
                          {result.os_detection}
                        {:else}
                          -
                        {/if}
                      </td>
                    </tr>
                  {/each}
                </tbody>
              </table>
            </div>
          </div>
        {:else}
          <div class="empty-state">
            <div class="empty-icon">📋</div>
            <p>{$tr('portScanner.history.messages.noHistory')}</p>
          </div>
        {/if}
      </div>
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
        <h2>{$tr('portScanner.helpModal.title')}</h2>
        <button class="modal-close" on:click={() => showHelpModal = false}>✕</button>
      </div>
      
      <div class="modal-body">
        <div class="help-section">
          <h3>{$tr('portScanner.helpModal.overview')}</h3>
          <p>{$tr('portScanner.helpModal.overviewText')}</p>
          <ul>
            <li>{$tr('portScanner.helpModal.overviewFeatures.asyncScan')}</li>
            <li>{$tr('portScanner.helpModal.overviewFeatures.serviceIdent')}</li>
            <li>{$tr('portScanner.helpModal.overviewFeatures.bannerGrab')}</li>
            <li>{$tr('portScanner.helpModal.overviewFeatures.multiTarget')}</li>
            <li>{$tr('portScanner.helpModal.overviewFeatures.cidrScan')}</li>
            <li>{$tr('portScanner.helpModal.overviewFeatures.dnsResolve')}</li>
            <li>{$tr('portScanner.helpModal.overviewFeatures.dynamicConcurrency')}</li>
            <li>{$tr('portScanner.helpModal.overviewFeatures.realtimeProgress')}</li>
            <li>{$tr('portScanner.helpModal.overviewFeatures.resultExport')}</li>
            <li>{$tr('portScanner.helpModal.overviewFeatures.scanCancel')}</li>
          </ul>
        </div>

        <div class="help-section">
          <h3>{$tr('portScanner.helpModal.targetInput')}</h3>
          
          <div class="help-subsection">
            <h4>{$tr('portScanner.helpModal.singleTarget')}</h4>
            <p>{$tr('portScanner.helpModal.singleTargetDesc')}</p>
            <div class="code-example">
              <code>192.168.1.1</code>
              <code>example.com</code>
            </div>
          </div>

          <div class="help-subsection">
            <h4>{$tr('portScanner.helpModal.multiTarget')}</h4>
            <p>{$tr('portScanner.helpModal.multiTargetDesc')}</p>
            <div class="code-example">
              <code>192.168.1.1,192.168.1.2,example.com</code>
            </div>
          </div>

          <div class="help-subsection">
            <h4>{$tr('portScanner.helpModal.cidrScan')}</h4>
            <p>{$tr('portScanner.helpModal.cidrScanDesc')}</p>
            <div class="code-example">
              <code>192.168.1.0/24</code>
              <code>10.0.0.0/16</code>
              <code>192.168.1.0/30,example.com</code>
            </div>
            <p class="help-tip">{$tr('portScanner.helpModal.cidrTip')}</p>
          </div>

          <div class="help-subsection">
            <h4>{$tr('portScanner.helpModal.fileImport')}</h4>
            <p>{$tr('portScanner.helpModal.fileImportDesc')}</p>
            <ul>
              <li><strong>{$tr('portScanner.helpModal.fileImportFormats.onePerLine')}</strong></li>
              <li><strong>{$tr('portScanner.helpModal.fileImportFormats.commaSep')}</strong></li>
              <li><strong>{$tr('portScanner.helpModal.fileImportFormats.semicolonSep')}</strong></li>
              <li><strong>{$tr('portScanner.helpModal.fileImportFormats.comments')}</strong></li>
            </ul>
            <div class="code-example">
              <code>{$tr('portScanner.helpModal.fileImportExample')}</code>
              <code>192.168.1.1</code>
              <code>example.com</code>
              <code>test.example.com</code>
            </div>
          </div>
        </div>

        <div class="help-section">
          <h3>{$tr('portScanner.helpModal.modesTitle')}</h3>
          
          <div class="mode-grid">
            <div class="mode-card">
              <h4>{$tr('portScanner.helpModal.quickScan')}</h4>
              <p>{$tr('portScanner.helpModal.quickScanDesc')}</p>
              <div class="port-list">{$tr('portScanner.helpModal.quickScanPorts')}</div>
            </div>
            
            <div class="mode-card">
              <h4>{$tr('portScanner.helpModal.standardScan')}</h4>
              <p>{$tr('portScanner.helpModal.standardScanDesc')}</p>
              <div class="port-list">{$tr('portScanner.helpModal.standardScanPorts')}</div>
            </div>
            
            <div class="mode-card">
              <h4>{$tr('portScanner.helpModal.fullScan')}</h4>
              <p>{$tr('portScanner.helpModal.fullScanDesc')}</p>
              <div class="port-list">{$tr('portScanner.helpModal.fullScanPorts')}</div>
            </div>
            
            <div class="mode-card">
              <h4>{$tr('portScanner.helpModal.customScan')}</h4>
              <p>{$tr('portScanner.helpModal.customScanDesc')}</p>
              <div class="port-list">{$tr('portScanner.helpModal.customScanPorts')}</div>
            </div>
          </div>
        </div>

        <div class="help-section">
          <h3>{$tr('portScanner.helpModal.timeoutTitle')}</h3>
          <p>{$tr('portScanner.helpModal.timeoutDesc')}</p>
          <ul>
            <li><strong>{$tr('portScanner.helpModal.timeoutLan')}</strong></li>
            <li><strong>{$tr('portScanner.helpModal.timeoutInternet')}</strong></li>
            <li><strong>{$tr('portScanner.helpModal.timeoutSlow')}</strong></li>
          </ul>
          <p class="help-tip">{$tr('portScanner.helpModal.timeoutTip')}</p>
        </div>

        <div class="help-section">
          <h3>{$tr('portScanner.helpModal.resultsTitle')}</h3>
          <ul>
            <li><strong>{$tr('portScanner.helpModal.resultFeatures.realtimeProgress')}</strong></li>
            <li><strong>{$tr('portScanner.helpModal.resultFeatures.pagination')}</strong></li>
            <li><strong>{$tr('portScanner.helpModal.resultFeatures.targetColumn')}</strong></li>
            <li><strong>{$tr('portScanner.helpModal.resultFeatures.ipDisplay')}</strong></li>
            <li><strong>{$tr('portScanner.helpModal.resultFeatures.serviceInfo')}</strong></li>
            <li><strong>{$tr('portScanner.helpModal.resultFeatures.scanCancel')}</strong></li>
          </ul>
        </div>

        <div class="help-section">
          <h3>{$tr('portScanner.helpModal.ipFormatTitle')}</h3>
          <p>{$tr('portScanner.helpModal.ipFormatDesc')}</p>
          <div class="code-example">
            <code>{$tr('portScanner.helpModal.ipFormatExample')}</code>
          </div>
          <p><strong>{$tr('portScanner.helpModal.ipFormatNote')}</strong></p>
          <ul>
            <li><strong>{$tr('portScanner.helpModal.ipFormatDetails.domain')}</strong></li>
            <li><strong>{$tr('portScanner.helpModal.ipFormatDetails.ipv4')}</strong></li>
            <li><strong>{$tr('portScanner.helpModal.ipFormatDetails.ipv6')}</strong></li>
            <li><strong>{$tr('portScanner.helpModal.ipFormatDetails.separator')}</strong></li>
          </ul>
          <p class="help-tip">{$tr('portScanner.helpModal.ipFormatTip')}</p>
        </div>

        <div class="help-section">
          <h3>{$tr('portScanner.helpModal.exportTitle')}</h3>
          <p>{$tr('portScanner.helpModal.exportDesc')}</p>
          <ul>
            <li><strong>{$tr('portScanner.helpModal.exportFormats.json')}</strong></li>
            <li><strong>{$tr('portScanner.helpModal.exportFormats.csv')}</strong></li>
            <li><strong>{$tr('portScanner.helpModal.exportFormats.txt')}</strong></li>
          </ul>
        </div>

        <div class="help-section">
          <h3>{$tr('portScanner.helpModal.tipsTitle')}</h3>
          <ul>
            <li>{$tr('portScanner.helpModal.tips.0')}</li>
            <li>{$tr('portScanner.helpModal.tips.1')}</li>
            <li>{$tr('portScanner.helpModal.tips.2')}</li>
            <li>{$tr('portScanner.helpModal.tips.3')}</li>
            <li>{$tr('portScanner.helpModal.tips.4')}</li>
            <li>{$tr('portScanner.helpModal.tips.5')}</li>
            <li>{$tr('portScanner.helpModal.tips.6')}</li>
            <li>{$tr('portScanner.helpModal.tips.7')}</li>
          </ul>
        </div>

        <div class="help-section">
          <h3>{$tr('portScanner.helpModal.warningTitle')}</h3>
          <ul>
            <li>{$tr('portScanner.helpModal.warnings.0')}</li>
            <li>{$tr('portScanner.helpModal.warnings.1')}</li>
            <li>{$tr('portScanner.helpModal.warnings.2')}</li>
            <li>{$tr('portScanner.helpModal.warnings.3')}</li>
          </ul>
        </div>
      </div>
    </div>
  </div>
{/if}

{#if showOSDetailModal && selectedOSResult}
  <div 
    class="modal-overlay" 
    role="button"
    tabindex="-1"
    on:click={() => showOSDetailModal = false}
    on:keydown={(e) => e.key === 'Escape' && (showOSDetailModal = false)}
  >
    <div 
      class="modal-content os-detail-modal" 
      role="dialog"
      aria-modal="true"
      tabindex="-1"
      on:click|stopPropagation
      on:keydown|stopPropagation
    >
      <div class="modal-header">
        <h2>🖥️ {$tr('portScanner.osDetection.detailTitle')}</h2>
        <button class="modal-close" on:click={() => showOSDetailModal = false}>✕</button>
      </div>
      
      <div class="modal-body">
        <div class="os-detail-content">
          <div class="os-detail-main">
            <div class="os-detail-icon">
              {#if selectedOSResult.os_family === 'Windows'}
                🪟
              {:else if selectedOSResult.os_family === 'Unix-like'}
                🐧
              {:else if selectedOSResult.os_family === 'Network'}
                🌐
              {:else}
                ❓
              {/if}
            </div>
            <div class="os-detail-info">
              <div class="os-detail-type">{selectedOSResult.os_type}</div>
              <div class="os-detail-family">{$tr('portScanner.osDetection.osFamilyLabel', { family: selectedOSResult.os_family })}</div>
              <div class="os-detail-confidence">
                {$tr('portScanner.osDetection.confidenceLabel')}
                <span class="confidence-value {selectedOSResult.confidence >= 80 ? 'high' : selectedOSResult.confidence >= 50 ? 'medium' : 'low'}">
                  {selectedOSResult.confidence}%
                </span>
              </div>
            </div>
          </div>
          
          {#if selectedOSResult.ttl !== null}
            <div class="os-detail-item">
              <span class="detail-label">{$tr('portScanner.osDetection.ttlLabel')}</span>
              <span class="detail-value">{selectedOSResult.ttl}</span>
            </div>
          {/if}
          
          {#if selectedOSResult.details.length > 0}
            <div class="os-detail-section">
              <h4>{$tr('portScanner.osDetection.detailsLabel')}</h4>
              <ul class="detail-list">
                {#each selectedOSResult.details as detail}
                  <li>{detail}</li>
                {/each}
              </ul>
            </div>
          {/if}
          
          <div class="os-detail-section">
            <h4>{$tr('portScanner.osDetection.detectionNote')}</h4>
            <p class="os-detail-description">
              {$tr('portScanner.osDetection.detectionDescription')}
            </p>
            <ul class="os-ttl-list">
              <li><strong>{$tr('portScanner.osDetection.ttlInfo.linux')}</strong></li>
              <li><strong>{$tr('portScanner.osDetection.ttlInfo.windows')}</strong></li>
              <li><strong>{$tr('portScanner.osDetection.ttlInfo.network')}</strong></li>
            </ul>
            <p class="os-detail-note">
              {$tr('portScanner.osDetection.warning')}
            </p>
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
        <h2>🎯 {$tr('portScanner.targetSelector.title')}</h2>
        <button class="modal-close" on:click={() => showTargetSelector = false}>✕</button>
      </div>
      
      <div class="modal-body">
        <div class="target-search">
          <input
            type="text"
            bind:value={targetSearchQuery}
            placeholder={$tr('portScanner.targetSelector.searchPlaceholder')}
          />
        </div>
        
        {#if loadingTargets}
          <div class="loading-message">
            <div class="spinner"></div>
            {$tr('portScanner.targetSelector.loading')}
          </div>
        {:else if filteredTargets.length === 0}
          <div class="empty-message">
            {#if targetSearchQuery}
              {$tr('portScanner.targetSelector.noResults')}
            {:else}
              {$tr('portScanner.targetSelector.noTargets')}
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
          {$tr('portScanner.targetSelector.selectedCount', { count: selectedTargets.length })}
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
  .port-scanner-page {
    max-width: 1400px;
    margin: 0 auto;
    padding: 2rem;
  }

  .page-header {
    margin-bottom: 2rem;
  }

  .header-content {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    margin-top: 1rem;
  }

  .title-section {
    flex: 1;
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

  .page-title {
    font-size: 2rem;
    font-weight: 700;
    margin-bottom: 0.5rem;
    background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%);
    -webkit-background-clip: text;
    background-clip: text;
    -webkit-text-fill-color: transparent;
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

  .form-group input::placeholder {
    color: #64748b;
  }

  .input-hint {
    display: block;
    font-size: 0.75rem;
    color: #64748b;
    margin-top: 0.375rem;
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

  .btn-primary:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }

  .btn-secondary {
    background: rgba(168, 85, 247, 0.1);
    border: 1px solid #a855f7;
    color: #a855f7;
    font-weight: 600;
    padding: 0.75rem 1.5rem;
    border-radius: 0.5rem;
    cursor: pointer;
    transition: all 0.2s;
  }

  .btn-secondary:hover {
    background: rgba(168, 85, 247, 0.2);
  }

  .btn-os-detect {
    flex: 1;
    padding: 0.75rem 1.5rem;
    background: linear-gradient(135deg, #10b981 0%, #059669 100%);
    color: white;
    border: none;
    border-radius: 0.5rem;
    font-size: 0.95rem;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.2s;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 0.5rem;
  }

  .btn-os-detect:hover:not(:disabled) {
    transform: translateY(-1px);
    box-shadow: 0 4px 12px rgba(16, 185, 129, 0.3);
  }

  .btn-os-detect:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }

  .spinner {
    width: 1rem;
    height: 1rem;
    border: 2px solid rgba(255, 255, 255, 0.3);
    border-top-color: white;
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
  }

  @keyframes spin {
    to {
      transform: rotate(360deg);
    }
  }

  .info-card {
    background: rgba(168, 85, 247, 0.05);
    border: 1px solid rgba(168, 85, 247, 0.2);
    border-radius: 0.75rem;
    padding: 1.25rem;
  }

  .info-card h3 {
    font-size: 1rem;
    font-weight: 600;
    margin-bottom: 0.75rem;
    color: #a855f7;
  }

  .info-card ul {
    list-style: none;
    padding: 0;
  }

  .info-card li {
    font-size: 0.875rem;
    color: #94a3b8;
    margin-bottom: 0.5rem;
    padding-left: 1.25rem;
    position: relative;
  }

  .info-card li::before {
    content: '•';
    position: absolute;
    left: 0;
    color: #a855f7;
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

  .results-info {
    display: flex;
    align-items: center;
    gap: 1rem;
    margin-bottom: 1rem;
    padding: 0.75rem 1rem;
    background: rgba(168, 85, 247, 0.05);
    border-radius: 0.5rem;
    font-size: 0.875rem;
  }

  .results-count {
    color: #f1f5f9;
    font-weight: 500;
  }

  .results-separator {
    color: #475569;
  }

  .open-count {
    color: #10b981;
    font-weight: 500;
  }

  .results-table {
    margin-top: 1rem;
    overflow-x: auto;
  }

  table {
    width: 100%;
    border-collapse: collapse;
    background: rgba(10, 14, 23, 0.4);
    border-radius: 0.5rem;
    overflow: hidden;
  }

  th {
    background: rgba(168, 85, 247, 0.1);
    padding: 0.875rem 1rem;
    text-align: left;
    font-weight: 600;
    color: #a855f7;
    border-bottom: 1px solid rgba(168, 85, 247, 0.2);
    font-size: 0.875rem;
  }

  .os-header {
    text-align: center;
    line-height: 1.4;
    white-space: nowrap;
  }

  td {
    padding: 0.875rem 1rem;
    border-bottom: 1px solid rgba(168, 85, 247, 0.1);
    color: #f1f5f9;
  }

  tr:hover {
    background: rgba(168, 85, 247, 0.05);
  }

  .target-cell {
    font-family: 'Monaco', 'Menlo', monospace;
    font-size: 0.875rem;
    color: #60a5fa;
    font-weight: 500;
  }

  .port-cell {
    font-family: 'Monaco', 'Menlo', monospace;
    font-weight: 600;
    color: #00ff88;
  }

  .status-badge {
    display: inline-block;
    padding: 0.25rem 0.75rem;
    border-radius: 9999px;
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
  }

  .status-badge.open {
    background: rgba(16, 185, 129, 0.2);
    color: #10b981;
    border: 1px solid rgba(16, 185, 129, 0.3);
  }

  .status-badge.closed {
    background: rgba(239, 68, 68, 0.2);
    color: #ef4444;
    border: 1px solid rgba(239, 68, 68, 0.3);
  }

  .status-badge.filtered {
    background: rgba(245, 158, 11, 0.2);
    color: #f59e0b;
    border: 1px solid rgba(245, 158, 11, 0.3);
  }

  .service-name {
    font-weight: 500;
    color: #60a5fa;
  }

  .unknown {
    color: #64748b;
  }

  .version-info {
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }

  .version-text {
    font-family: 'Monaco', 'Menlo', monospace;
    font-size: 0.875rem;
    color: #94a3b8;
  }

  .banner-indicator {
    cursor: help;
    font-size: 1rem;
  }

  .no-version {
    color: #475569;
  }

  .pagination {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-top: 1.5rem;
    padding-top: 1.5rem;
    border-top: 1px solid rgba(168, 85, 247, 0.2);
  }

  .pagination-btn {
    background: rgba(168, 85, 247, 0.1);
    border: 1px solid rgba(168, 85, 247, 0.3);
    color: #a855f7;
    padding: 0.5rem 1rem;
    border-radius: 0.5rem;
    cursor: pointer;
    font-size: 0.875rem;
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
    display: flex;
    align-items: center;
    gap: 1.5rem;
  }

  .page-info {
    color: #f1f5f9;
    font-size: 0.875rem;
    font-weight: 500;
  }

  .page-jump {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    color: #94a3b8;
    font-size: 0.875rem;
  }

  .page-jump input {
    width: 60px;
    padding: 0.375rem 0.5rem;
    background: rgba(10, 14, 23, 0.6);
    border: 1px solid rgba(168, 85, 247, 0.3);
    border-radius: 0.375rem;
    color: #f1f5f9;
    text-align: center;
    font-size: 0.875rem;
  }

  .page-jump input:focus {
    outline: none;
    border-color: #a855f7;
  }

  .jump-btn {
    padding: 0.375rem 0.75rem;
    background: rgba(168, 85, 247, 0.1);
    border: 1px solid rgba(168, 85, 247, 0.3);
    color: #a855f7;
    border-radius: 0.375rem;
    cursor: pointer;
    font-size: 0.875rem;
    transition: all 0.2s;
  }

  .jump-btn:hover:not(:disabled) {
    background: rgba(168, 85, 247, 0.2);
  }

  .jump-btn:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .result-output {
    background: rgba(10, 14, 23, 0.6);
    border: 1px solid rgba(168, 85, 247, 0.2);
    border-radius: 0.5rem;
    padding: 1rem;
    color: #f1f5f9;
    font-family: 'Monaco', 'Menlo', monospace;
    font-size: 0.875rem;
    white-space: pre-wrap;
    word-wrap: break-word;
    max-height: 500px;
    overflow-y: auto;
  }

  .empty-state {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    min-height: 400px;
    background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
    border: 1px solid rgba(168, 85, 247, 0.2);
    border-radius: 1rem;
  }

  .empty-icon {
    font-size: 4rem;
    margin-bottom: 1rem;
  }

  .empty-state p {
    color: #94a3b8;
    font-size: 1rem;
  }

  .loading-state {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    min-height: 400px;
    background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
    border: 1px solid rgba(168, 85, 247, 0.2);
    border-radius: 1rem;
    padding: 2rem;
  }

  .spinner-large {
    width: 3rem;
    height: 3rem;
    border: 3px solid rgba(168, 85, 247, 0.3);
    border-top-color: #a855f7;
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
    margin-bottom: 2rem;
  }

  .progress-info {
    width: 100%;
    max-width: 500px;
  }

  .progress-bar {
    width: 100%;
    height: 0.5rem;
    background: rgba(168, 85, 247, 0.2);
    border-radius: 9999px;
    overflow: hidden;
    margin-bottom: 1.5rem;
  }

  .progress-fill {
    height: 100%;
    background: linear-gradient(90deg, #a855f7 0%, #6366f1 100%);
    transition: width 0.3s ease;
  }

  .progress-stats {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 1rem;
  }

  .stat-item {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
  }

  .stat-label {
    font-size: 0.75rem;
    color: #94a3b8;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }

  .stat-value {
    font-size: 1.25rem;
    font-weight: 600;
    color: #f1f5f9;
  }

  .stat-value.open {
    color: #10b981;
  }

  @media (max-width: 1024px) {
    .content-grid {
      grid-template-columns: 1fr;
    }

    .config-section {
      order: 1;
    }

    .result-section {
      order: 2;
    }

    .pagination {
      flex-direction: column;
      gap: 1rem;
    }

    .pagination-info {
      flex-direction: column;
      gap: 0.75rem;
    }
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
    position: sticky;
    top: 0;
    background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
    z-index: 10;
  }

  .modal-header h2 {
    font-size: 1.5rem;
    font-weight: 600;
    color: #f1f5f9;
    margin: 0;
  }

  .modal-close {
    background: rgba(239, 68, 68, 0.2);
    border: 1px solid rgba(239, 68, 68, 0.3);
    color: #ef4444;
    width: 2.5rem;
    height: 2.5rem;
    border-radius: 0.5rem;
    cursor: pointer;
    font-size: 1.25rem;
    display: flex;
    align-items: center;
    justify-content: center;
    transition: all 0.2s;
  }

  .modal-close:hover {
    background: rgba(239, 68, 68, 0.3);
    border-color: rgba(239, 68, 68, 0.5);
  }

  .modal-body {
    padding: 2rem;
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

  .mode-grid {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 1rem;
    margin-top: 1rem;
  }

  .mode-card {
    background: rgba(168, 85, 247, 0.05);
    border: 1px solid rgba(168, 85, 247, 0.2);
    border-radius: 0.75rem;
    padding: 1.25rem;
    transition: all 0.2s;
  }

  .mode-card:hover {
    background: rgba(168, 85, 247, 0.1);
    border-color: rgba(168, 85, 247, 0.3);
    transform: translateY(-2px);
  }

  .mode-card h4 {
    font-size: 1rem;
    font-weight: 600;
    color: #f1f5f9;
    margin-bottom: 0.5rem;
  }

  .mode-card p {
    color: #94a3b8;
    font-size: 0.875rem;
    margin-bottom: 0.5rem;
  }

  .port-list {
    color: #00ff88;
    font-family: 'Monaco', 'Menlo', monospace;
    font-size: 0.75rem;
    background: rgba(0, 0, 0, 0.2);
    padding: 0.5rem;
    border-radius: 0.25rem;
    margin-top: 0.5rem;
  }

  .help-tip {
    background: rgba(59, 130, 246, 0.1);
    border-left: 3px solid #3b82f6;
    padding: 0.75rem 1rem;
    border-radius: 0.25rem;
    color: #93c5fd !important;
    margin-top: 1rem;
  }

  @media (max-width: 768px) {
    .modal-overlay {
      padding: 1rem;
    }

    .modal-content {
      max-height: 95vh;
    }

    .modal-header {
      padding: 1rem 1.5rem;
    }

    .modal-body {
      padding: 1.5rem;
    }

    .mode-grid {
      grid-template-columns: 1fr;
    }
  }

  .os-cell {
    padding: 0.75rem;
    text-align: left;
  }

  .os-badge {
    display: inline-flex;
    align-items: center;
    gap: 0.25rem;
    padding: 0.375rem 0.75rem;
    background: rgba(16, 185, 129, 0.15);
    border: 1px solid rgba(16, 185, 129, 0.3);
    border-radius: 0.375rem;
    font-size: 0.875rem;
    font-weight: 500;
    color: #10b981;
    cursor: pointer;
    transition: all 0.2s;
  }

  .os-badge.clickable:hover {
    background: rgba(16, 185, 129, 0.25);
    transform: translateY(-1px);
  }

  .no-os {
    color: #6b7280;
  }

  .os-detail-modal {
    max-width: 600px;
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

  .os-detail-content {
    display: flex;
    flex-direction: column;
    gap: 1.5rem;
  }

  .os-detail-main {
    display: flex;
    align-items: center;
    gap: 1.5rem;
    padding: 1rem;
    background: rgba(16, 185, 129, 0.1);
    border-radius: 0.75rem;
  }

  .os-detail-icon {
    font-size: 3.5rem;
    width: 5rem;
    height: 5rem;
    display: flex;
    align-items: center;
    justify-content: center;
    background: rgba(16, 185, 129, 0.2);
    border-radius: 1rem;
  }

  .os-detail-info {
    flex: 1;
  }

  .os-detail-type {
    font-size: 1.5rem;
    font-weight: 600;
    color: #e5e7eb;
    margin-bottom: 0.5rem;
  }

  .os-detail-family {
    font-size: 0.95rem;
    color: #9ca3af;
    margin-bottom: 0.25rem;
  }

  .os-detail-confidence {
    font-size: 0.9rem;
    color: #9ca3af;
  }

  .confidence-value {
    font-weight: 600;
    padding: 0.125rem 0.5rem;
    border-radius: 0.25rem;
  }

  .confidence-value.high {
    background: rgba(16, 185, 129, 0.2);
    color: #10b981;
  }

  .confidence-value.medium {
    background: rgba(251, 191, 36, 0.2);
    color: #fbbf24;
  }

  .confidence-value.low {
    background: rgba(239, 68, 68, 0.2);
    color: #ef4444;
  }

  .os-detail-item {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    padding: 0.75rem 1rem;
    background: rgba(0, 0, 0, 0.2);
    border-radius: 0.5rem;
  }

  .detail-label {
    font-size: 0.9rem;
    color: #9ca3af;
    font-weight: 500;
  }

  .detail-value {
    font-size: 0.95rem;
    color: #e5e7eb;
    font-family: monospace;
  }

  .os-detail-section {
    background: rgba(0, 0, 0, 0.2);
    border-radius: 0.5rem;
    padding: 1rem;
  }

  .os-detail-section h4 {
    font-size: 0.95rem;
    color: #e5e7eb;
    margin: 0 0 0.75rem 0;
    font-weight: 600;
  }

  .detail-list {
    margin: 0;
    padding-left: 1.5rem;
    list-style-type: disc;
  }

  .detail-list li {
    font-size: 0.9rem;
    color: #d1d5db;
    margin-bottom: 0.5rem;
  }

  .os-detail-description {
    font-size: 0.9rem;
    color: #d1d5db;
    line-height: 1.6;
    margin-bottom: 0.75rem;
  }

  .os-ttl-list {
    margin: 0.75rem 0;
    padding-left: 1.5rem;
    list-style-type: disc;
  }

  .os-ttl-list li {
    font-size: 0.85rem;
    color: #d1d5db;
    margin-bottom: 0.375rem;
  }

  .os-detail-note {
    font-size: 0.85rem;
    color: #fbbf24;
    background: rgba(251, 191, 36, 0.1);
    padding: 0.75rem;
    border-radius: 0.375rem;
    border-left: 3px solid #fbbf24;
    margin-top: 0.75rem;
  }

  .system-info-card {
    margin-top: 1rem;
  }

  .system-info-grid {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 1rem;
    margin-top: 0.75rem;
  }

  .system-info-grid .info-item {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
    padding: 0.75rem;
    background: rgba(30, 41, 59, 0.5);
    border-radius: 0.5rem;
    border: 1px solid rgba(148, 163, 184, 0.1);
  }

  .system-info-grid .info-item.highlight {
    background: rgba(168, 85, 247, 0.1);
    border-color: rgba(168, 85, 247, 0.3);
  }

  .system-info-grid .info-label {
    font-size: 0.75rem;
    color: #94a3b8;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }

  .system-info-grid .info-value {
    font-size: 1.125rem;
    font-weight: 600;
    color: #f1f5f9;
  }

  .system-info-grid .info-item.highlight .info-value {
    color: #a855f7;
  }

  .info-note {
    margin-top: 1rem;
    font-size: 0.85rem;
    color: #94a3b8;
    text-align: center;
  }

  @media (max-width: 768px) {
    .system-info-grid {
      grid-template-columns: repeat(2, 1fr);
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

  .detail-results {
    background: rgba(0, 0, 0, 0.3);
    border-radius: 0.5rem;
    padding: 1.5rem;
    margin-top: 1.5rem;
  }

  .detail-results h3 {
    color: #a855f7;
    margin-bottom: 1rem;
    font-size: 1.125rem;
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }

  .results-table-wrapper {
    max-height: 400px;
    overflow-y: auto;
    border-radius: 0.5rem;
    border: 1px solid rgba(168, 85, 247, 0.2);
  }

  .results-table-wrapper::-webkit-scrollbar {
    width: 8px;
  }

  .results-table-wrapper::-webkit-scrollbar-track {
    background: rgba(0, 0, 0, 0.2);
    border-radius: 4px;
  }

  .results-table-wrapper::-webkit-scrollbar-thumb {
    background: rgba(168, 85, 247, 0.5);
    border-radius: 4px;
  }

  .results-table-wrapper::-webkit-scrollbar-thumb:hover {
    background: rgba(168, 85, 247, 0.7);
  }

  .detail-results table {
    width: 100%;
    border-collapse: collapse;
  }

  .detail-results th,
  .detail-results td {
    padding: 0.75rem;
    text-align: left;
    border-bottom: 1px solid rgba(168, 85, 247, 0.2);
  }

  .detail-results th {
    background: rgba(168, 85, 247, 0.1);
    color: #a855f7;
    font-weight: 600;
    font-size: 0.875rem;
    position: sticky;
    top: 0;
    z-index: 1;
  }

  .detail-results td {
    padding: 0.75rem;
    font-size: 0.875rem;
  }

  .target-cell {
    font-family: 'Courier New', monospace;
    color: #60a5fa;
  }

  .port-cell {
    font-weight: 600;
    color: #f1f5f9;
  }

  .status-cell {
    text-align: center;
  }

  .status-badge {
    display: inline-block;
    padding: 0.25rem 0.75rem;
    border-radius: 9999px;
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
  }

  .status-badge.status-open {
    background: rgba(34, 197, 94, 0.2);
    color: #22c55e;
    border: 1px solid rgba(34, 197, 94, 0.3);
  }

  .status-badge.status-closed {
    background: rgba(239, 68, 68, 0.2);
    color: #ef4444;
    border: 1px solid rgba(239, 68, 68, 0.3);
  }

  .status-badge.status-filtered {
    background: rgba(251, 191, 36, 0.2);
    color: #fbbf24;
    border: 1px solid rgba(251, 191, 36, 0.3);
  }

  .service-cell {
    color: #94a3b8;
  }

  .service-info {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
  }

  .service-main {
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }

  .category-icon {
    font-size: 1.1rem;
  }

  .risk-badge {
    display: inline-block;
    padding: 0.125rem 0.5rem;
    border-radius: 0.25rem;
    font-size: 0.75rem;
    color: white;
    font-weight: 500;
  }

  .service-description {
    font-size: 0.85rem;
    color: #6b7280;
    max-width: 300px;
  }

  .os-cell {
    color: #60a5fa;
    font-weight: 500;
  }

  .detail-value.status-completed {
    color: #22c55e;
    font-weight: 600;
  }

  .detail-value.status-running {
    color: #3b82f6;
    font-weight: 600;
  }

  .detail-value.status-failed {
    color: #ef4444;
    font-weight: 600;
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
</style>
