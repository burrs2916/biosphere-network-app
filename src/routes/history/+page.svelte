<script lang="ts">
  import { onMount } from 'svelte';
  import { invoke } from '@tauri-apps/api/core';
  import { tr } from '$lib/i18n';

  interface ScanTask {
    id: number | null;
    target: string;
    scan_mode: string;
    start_time: string;
    end_time: string | null;
    status: string;
    total_ports: number | null;
    open_ports: number | null;
    created_at: string;
  }

  let tasks: ScanTask[] = [];
  let loading = false;
  let error = '';
  let currentPage = 1;
  let pageSize = 10;
  let totalCount = 0;
  let searchQuery = '';
  let statusFilter = '';
  let modeFilter = '';
  let selectedTask: ScanTask | null = null;
  let taskDetails: any = null;
  let loadingDetails = false;
  let detailsSearchQuery = '';
  let expandedTargets = new Set<string>();
  let showAllTargets = false;
  let targetPages = new Map<string, number>();
  let targetPageInputs = new Map<string, string>();
  const detailsPageSize = 10;

  $: totalPages = Math.ceil(totalCount / pageSize);

  $: filteredResults = taskDetails?.results?.filter((r: any) => {
    if (!detailsSearchQuery.trim()) return true;
    const query = detailsSearchQuery.toLowerCase();
    return r.target.toLowerCase().includes(query) ||
           r.port.toString().includes(query) ||
           (r.service && r.service.toLowerCase().includes(query)) ||
           (r.version && r.version.toLowerCase().includes(query)) ||
           (r.banner && r.banner.toLowerCase().includes(query));
  }) || [];

  $: groupedResults = groupResultsByTarget(filteredResults);

  $: targetList = Array.from(groupedResults.entries());

  $: displayedTargets = showAllTargets ? targetList : targetList.slice(0, 10);

  $: totalResults = filteredResults.length;

  $: paginatedResultsMap = new Map<string, any[]>(
    Array.from(groupedResults.entries()).map(([target, results]) => {
      const page = targetPages.get(target) || 1;
      const start = (page - 1) * detailsPageSize;
      const end = start + detailsPageSize;
      return [target, results.slice(start, end)];
    })
  );

  async function loadHistory() {
    loading = true;
    error = '';
    
    try {
      if (searchQuery.trim()) {
        tasks = await invoke<ScanTask[]>('search_scan_history', {
          query: searchQuery.trim(),
          limit: pageSize,
          offset: (currentPage - 1) * pageSize,
        });
        totalCount = tasks.length;
      } else {
        tasks = await invoke<ScanTask[]>('get_scan_history', {
          limit: pageSize,
          offset: (currentPage - 1) * pageSize,
        });
        totalCount = tasks.length < pageSize && currentPage === 1 ? tasks.length : (currentPage * pageSize) + tasks.length;
      }
    } catch (e) {
      error = `${$tr('history.loadFailed')} ${e}`;
    } finally {
      loading = false;
    }
  }

  async function deleteTask(taskId: number) {
    if (!confirm($tr('history.deleteConfirm'))) {
      return;
    }

    try {
      await invoke('delete_scan_task', { taskId: taskId });
      await loadHistory();
    } catch (e) {
      error = `${$tr('history.deleteFailed')} ${e}`;
    }
  }

  async function loadTaskDetails(taskId: number) {
    loadingDetails = true;
    try {
      taskDetails = await invoke('get_scan_task_detail', { taskId });
    } catch (e) {
      error = `${$tr('history.details.loadDetailsFailed')} ${e}`;
    } finally {
      loadingDetails = false;
    }
  }

  function groupResultsByTarget(results: any[]): Map<string, any[]> {
    const grouped = new Map<string, any[]>();
    for (const result of results) {
      if (!grouped.has(result.target)) {
        grouped.set(result.target, []);
      }
      grouped.get(result.target)!.push(result);
    }
    return grouped;
  }

  function toggleTarget(target: string) {
    if (expandedTargets.has(target)) {
      expandedTargets.delete(target);
    } else {
      expandedTargets.add(target);
      if (!targetPages.has(target)) {
        targetPages.set(target, 1);
      }
    }
    expandedTargets = new Set(expandedTargets);
    targetPages = new Map(targetPages);
  }

  function toggleShowAllTargets() {
    showAllTargets = !showAllTargets;
  }

  function getPaginatedResults(results: any[], target: string): any[] {
    const page = targetPages.get(target) || 1;
    const start = (page - 1) * detailsPageSize;
    const end = start + detailsPageSize;
    return results.slice(start, end);
  }

  function getTargetPageInfo(results: any[], target: string) {
    const page = targetPages.get(target) || 1;
    const start = (page - 1) * detailsPageSize;
    const end = start + detailsPageSize;
    return { page, start, end, totalPages: Math.ceil(results.length / detailsPageSize) };
  }

  function changeTargetPage(target: string, delta: number, totalResults: number) {
    const currentPage = targetPages.get(target) || 1;
    const totalPages = Math.ceil(totalResults / detailsPageSize);
    const newPage = Math.max(1, Math.min(totalPages, currentPage + delta));
    targetPages.set(target, newPage);
    targetPageInputs.set(target, newPage.toString());
    targetPages = new Map(targetPages);
    targetPageInputs = new Map(targetPageInputs);
  }

  function goToTargetPage(target: string, totalPages: number) {
    const input = targetPageInputs.get(target) || '1';
    const page = parseInt(input);
    if (!isNaN(page) && page >= 1 && page <= totalPages) {
      targetPages.set(target, page);
      targetPages = new Map(targetPages);
    }
  }

  function highlightBanner(banner: string): string {
    if (!banner) return banner;
    
    let highlighted = banner
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');
    
    const patterns = [
      { regex: /\b(SSH-[\d.]+-[^\s]+)/g, color: 'text-green-400' },
      { regex: /\b(Server:\s*[^\s|]+)/g, color: 'text-blue-400' },
      { regex: /\b(HTTP\/[\d.]+)/g, color: 'text-purple-400' },
      { regex: /\b(MySQL\s*[\d.]+)/g, color: 'text-orange-400' },
      { regex: /\b(Postfix|Sendmail|Exim)\b/g, color: 'text-yellow-400' },
      { regex: /\b(vsftpd|ProFTPD|FileZilla)\b/g, color: 'text-cyan-400' },
      { regex: /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g, color: 'text-pink-400' },
    ];
    
    patterns.forEach(({ regex, color }) => {
      highlighted = highlighted.replace(regex, `<span class="${color} font-semibold">$1</span>`);
    });
    
    return highlighted;
  }

  async function copyBanner(banner: string) {
    try {
      await navigator.clipboard.writeText(banner);
    } catch (e) {
      console.error('Failed to copy banner:', e);
    }
  }

  function formatDate(dateStr: string): string {
    const date = new Date(dateStr);
    return date.toLocaleString('zh-CN', {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
    });
  }

  function getStatusColor(status: string): string {
    switch (status) {
      case 'completed':
        return 'text-green-400';
      case 'running':
        return 'text-blue-400';
      case 'failed':
        return 'text-red-400';
      default:
        return 'text-gray-400';
    }
  }

  function getStatusText(status: string): string {
    switch (status) {
      case 'completed':
        return $tr('history.statusText.completed');
      case 'running':
        return $tr('history.statusText.running');
      case 'failed':
        return $tr('history.statusText.failed');
      default:
        return status;
    }
  }

  function getScanModeText(mode: string): string {
    switch (mode) {
      case 'quick':
        return $tr('history.scanModes.quick');
      case 'standard':
        return $tr('history.scanModes.standard');
      case 'full':
        return $tr('history.scanModes.full');
      case 'custom':
        return $tr('history.scanModes.custom');
      default:
        return mode;
    }
  }

  onMount(() => {
    loadHistory();
    
    const handleEscape = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && selectedTask) {
        selectedTask = null;
      }
    };
    
    document.addEventListener('keydown', handleEscape);
    
    return () => {
      document.removeEventListener('keydown', handleEscape);
    };
  });

  function handleSearch() {
    currentPage = 1;
    loadHistory();
  }

  function handleKeyPress(event: KeyboardEvent) {
    if (event.key === 'Enter') {
      handleSearch();
    }
  }

  function prevPage() {
    if (currentPage > 1) {
      currentPage--;
      loadHistory();
    }
  }

  function nextPage() {
    if (currentPage < totalPages) {
      currentPage++;
      loadHistory();
    }
  }
</script>

<div class="min-h-screen bg-gray-900 text-white p-6" role="main">
  <div class="max-w-7xl mx-auto">
    <div class="mb-8">
      <h1 class="text-3xl font-bold mb-2">{$tr('history.title')}</h1>
      <p class="text-gray-400">{$tr('history.subtitle')}</p>
    </div>

    <div class="mb-6 flex gap-4">
      <div class="flex-1">
        <input
          type="text"
          bind:value={searchQuery}
          on:keypress={handleKeyPress}
          placeholder={$tr('history.searchPlaceholder')}
          class="w-full px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg focus:outline-none focus:border-blue-500"
        />
      </div>
      <select
        bind:value={statusFilter}
        on:change={() => {
          currentPage = 1;
          loadHistory();
        }}
        class="px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg focus:outline-none focus:border-blue-500"
      >
        <option value="">{$tr('history.allStatus')}</option>
        <option value="completed">{$tr('history.statusText.completed')}</option>
        <option value="running">{$tr('history.statusText.running')}</option>
        <option value="failed">{$tr('history.statusText.failed')}</option>
      </select>
      <select
        bind:value={modeFilter}
        on:change={() => {
          currentPage = 1;
          loadHistory();
        }}
        class="px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg focus:outline-none focus:border-blue-500"
      >
        <option value="">{$tr('history.allModes')}</option>
        <option value="quick">{$tr('history.scanModes.quick')}</option>
        <option value="standard">{$tr('history.scanModes.standard')}</option>
        <option value="full">{$tr('history.scanModes.full')}</option>
        <option value="custom">{$tr('history.scanModes.custom')}</option>
      </select>
      <button
        type="button"
        on:click={handleSearch}
        class="px-6 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg transition-colors"
      >
        {$tr('common.search')}
      </button>
      <button
        type="button"
        on:click={() => {
          searchQuery = '';
          statusFilter = '';
          modeFilter = '';
          currentPage = 1;
          loadHistory();
        }}
        class="px-6 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg transition-colors"
      >
        {$tr('common.reset')}
      </button>
    </div>

    {#if error}
      <div class="mb-4 p-4 bg-red-900/50 border border-red-700 rounded-lg">
        {error}
      </div>
    {/if}

    {#if loading}
      <div class="flex justify-center items-center py-12">
        <div class="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-blue-500"></div>
      </div>
    {:else if tasks.length === 0}
      <div class="text-center py-12 text-gray-400">
        <svg class="mx-auto h-12 w-12 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>
        </svg>
        <p>{$tr('history.noRecords')}</p>
      </div>
    {:else}
      <div class="bg-gray-800 rounded-lg overflow-hidden">
        <table class="w-full">
          <thead class="bg-gray-700">
            <!-- svelte-ignore component-name-lowercase -->
            <tr>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                {$tr('history.target')}
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                {$tr('history.scanMode')}
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                {$tr('history.startTime')}
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                {$tr('history.status')}
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                {$tr('history.openPorts')}
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                {$tr('history.actions')}
              </th>
            </tr>
          </thead>
          <tbody class="divide-y divide-gray-700">
            {#each tasks as task (task.id)}
              <!-- svelte-ignore component-name-lowercase -->
              <tr class="hover:bg-gray-750 transition-colors">
                <td class="px-6 py-4 whitespace-nowrap">
                  <div class="text-sm font-medium">{task.target}</div>
                </td>
                <td class="px-6 py-4 whitespace-nowrap">
                  <div class="text-sm text-gray-300">{getScanModeText(task.scan_mode)}</div>
                </td>
                <td class="px-6 py-4 whitespace-nowrap">
                  <div class="text-sm text-gray-300">{formatDate(task.start_time)}</div>
                </td>
                <td class="px-6 py-4 whitespace-nowrap">
                  <span class="text-sm font-medium {getStatusColor(task.status)}">
                    {getStatusText(task.status)}
                  </span>
                </td>
                <td class="px-6 py-4 whitespace-nowrap">
                  <div class="text-sm text-gray-300">
                    {task.open_ports !== null ? task.open_ports : '-'}
                  </div>
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm">
                  <button
                    type="button"
                    on:click={() => {
                      selectedTask = task;
                      taskDetails = null;
                      if (task.id) loadTaskDetails(task.id);
                    }}
                    class="text-blue-400 hover:text-blue-300 mr-4 transition-colors"
                  >
                    {$tr('history.viewDetails')}
                  </button>
                  <button
                    type="button"
                    on:click={() => task.id && deleteTask(task.id)}
                    class="text-red-400 hover:text-red-300 transition-colors"
                  >
                    {$tr('history.delete')}
                  </button>
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>

      {#if totalPages > 1}
        <div class="mt-6 flex items-center justify-between">
          <div class="text-sm text-gray-400">
            {$tr('common.showing')} {(currentPage - 1) * pageSize + 1} - {Math.min(currentPage * pageSize, totalCount)} {$tr('common.of')} {totalCount} {$tr('common.total')}
          </div>
          <div class="flex gap-2">
            <button
              type="button"
              on:click={prevPage}
              disabled={currentPage === 1}
              class="px-4 py-2 bg-gray-700 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed hover:bg-gray-600 transition-colors"
            >
              {$tr('common.previous')}
            </button>
            <div class="flex items-center gap-2">
              {#each Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
                const startPage = Math.max(1, Math.min(currentPage - 2, totalPages - 4));
                return startPage + i;
              }) as page (page)}
                <button
                  type="button"
                  on:click={() => {
                    currentPage = page;
                    loadHistory();
                  }}
                  class="px-3 py-1 rounded {currentPage === page ? 'bg-blue-600' : 'bg-gray-700 hover:bg-gray-600'} transition-colors"
                >
                  {page}
                </button>
              {/each}
            </div>
            <button
              type="button"
              on:click={nextPage}
              disabled={currentPage === totalPages}
              class="px-4 py-2 bg-gray-700 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed hover:bg-gray-600 transition-colors"
            >
              {$tr('common.next')}
            </button>
          </div>
        </div>
      {/if}
    {/if}

    {#if selectedTask}
      <!-- svelte-ignore a11y-click-events-have-key-events -->
      <!-- svelte-ignore a11y-no-static-element-interactions -->
      <div 
        class="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50" 
        role="dialog" 
        aria-modal="true"
        aria-labelledby="dialog-title"
        tabindex="-1"
        on:click={() => selectedTask = null}
      >
        <!-- svelte-ignore a11y-no-noninteractive-element-interactions -->
        <div 
          class="bg-gray-800 rounded-xl p-6 max-w-5xl w-full mx-4 max-h-[90vh] overflow-y-auto shadow-2xl" 
          role="document"
          on:click|stopPropagation
        >
          <div class="flex justify-between items-center mb-6 pb-4 border-b border-gray-700">
            <h2 id="dialog-title" class="text-2xl font-bold text-white">{$tr('history.scanDetails')}</h2>
            <button 
              on:click={() => selectedTask = null} 
              class="text-gray-400 hover:text-white transition-colors p-1 hover:bg-gray-700 rounded"
              aria-label={$tr('common.close')}
            >
              <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
              </svg>
            </button>
          </div>
          
          {#if loadingDetails}
            <div class="flex justify-center items-center py-16">
              <div class="animate-spin rounded-full h-10 w-10 border-t-2 border-b-2 border-blue-500"></div>
            </div>
          {:else if taskDetails && taskDetails.results}
            <div class="space-y-6">
              <div class="bg-gray-900 rounded-lg p-5">
                <h3 class="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-4">{$tr('history.details.basicInfo')}</h3>
                <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
                  <div class="bg-gray-800 rounded-lg p-3">
                    <div class="text-xs text-gray-500 mb-1">{$tr('history.details.scanTarget')}</div>
                    <div class="text-sm font-medium text-white break-all">{selectedTask.target}</div>
                  </div>
                  <div class="bg-gray-800 rounded-lg p-3">
                    <div class="text-xs text-gray-500 mb-1">{$tr('history.details.scanMode')}</div>
                    <div class="text-sm font-medium text-white">{getScanModeText(selectedTask.scan_mode)}</div>
                  </div>
                  <div class="bg-gray-800 rounded-lg p-3">
                    <div class="text-xs text-gray-500 mb-1">{$tr('history.details.startTime')}</div>
                    <div class="text-sm font-medium text-white">{formatDate(selectedTask.start_time)}</div>
                  </div>
                  <div class="bg-gray-800 rounded-lg p-3">
                    <div class="text-xs text-gray-500 mb-1">{$tr('history.details.status')}</div>
                    <div class="text-sm font-medium {getStatusColor(selectedTask.status)}">{getStatusText(selectedTask.status)}</div>
                  </div>
                  {#if selectedTask.total_ports !== null}
                    <div class="bg-gray-800 rounded-lg p-3">
                      <div class="text-xs text-gray-500 mb-1">{$tr('history.details.totalPorts')}</div>
                      <div class="text-sm font-medium text-white">{selectedTask.total_ports}</div>
                    </div>
                  {/if}
                  {#if selectedTask.open_ports !== null}
                    <div class="bg-gray-800 rounded-lg p-3">
                      <div class="text-xs text-gray-500 mb-1">{$tr('history.details.openPorts')}</div>
                      <div class="text-sm font-bold text-green-400">{selectedTask.open_ports}</div>
                    </div>
                  {/if}
                  {#if selectedTask.end_time}
                    <div class="bg-gray-800 rounded-lg p-3">
                      <div class="text-xs text-gray-500 mb-1">{$tr('history.details.endTime')}</div>
                      <div class="text-sm font-medium text-white">{formatDate(selectedTask.end_time)}</div>
                    </div>
                  {/if}
                </div>
              </div>

              <div>
                <div class="flex items-center justify-between mb-4">
                  <h3 class="text-lg font-semibold text-white flex items-center gap-2">
                    <svg class="w-5 h-5 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"></path>
                    </svg>
                    {$tr('history.details.scanResults')}
                    <span class="text-sm font-normal text-gray-400">({totalResults} {$tr('history.details.records')})</span>
                  </h3>
                  <div class="flex items-center gap-2">
                    <input
                      type="text"
                      bind:value={detailsSearchQuery}
                      placeholder={$tr('history.details.searchPlaceholder')}
                      class="px-3 py-1.5 text-sm bg-gray-700 border border-gray-600 rounded-lg focus:outline-none focus:border-blue-500 w-64"
                    />
                  </div>
                </div>

                {#if targetList.length === 0}
                  <div class="text-center py-8 text-gray-400">
                    <p>{$tr('history.details.noResults')}</p>
                  </div>
                {:else}
                  <div class="space-y-3">
                    {#each displayedTargets as [target, results] (target)}
                      <div class="bg-gray-900 rounded-lg border border-gray-700 overflow-hidden">
                        <button
                          on:click={() => toggleTarget(target)}
                          class="w-full px-4 py-3 flex items-center justify-between hover:bg-gray-800 transition-colors"
                        >
                          <div class="flex items-center gap-2">
                            <svg class="w-4 h-4 text-gray-400 transition-transform {expandedTargets.has(target) ? 'rotate-90' : ''}" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path>
                            </svg>
                            <div class="w-2 h-2 bg-blue-400 rounded-full"></div>
                            <span class="text-base font-semibold text-blue-400">{target}</span>
                            <span class="text-xs text-gray-500">({results.length} {$tr('history.details.ports')})</span>
                          </div>
                        </button>
                        
                        {#if expandedTargets.has(target)}
                          <div class="px-4 pb-4">
                            <div class="overflow-x-auto">
                              <table class="w-full text-sm">
                                <thead>
                                  <tr class="border-b border-gray-700">
                                    <th class="text-left py-2 px-3 text-gray-400 font-medium">{$tr('history.details.port')}</th>
                                    <th class="text-left py-2 px-3 text-gray-400 font-medium">{$tr('history.details.status')}</th>
                                    <th class="text-left py-2 px-3 text-gray-400 font-medium">{$tr('history.details.service')}</th>
                                    <th class="text-left py-2 px-3 text-gray-400 font-medium">{$tr('history.details.version')}</th>
                                    <th class="text-left py-2 px-3 text-gray-400 font-medium">{$tr('history.details.protocol')}</th>
                                    <th class="text-left py-2 px-3 text-gray-400 font-medium">{$tr('history.details.banner')}</th>
                                  </tr>
                                </thead>
                                <tbody>
                                  {#each (paginatedResultsMap.get(target) || []) as result}
                                    <tr class="border-b border-gray-800 hover:bg-gray-800 transition-colors">
                                      <td class="py-2 px-3">
                                        <span class="font-mono font-bold text-blue-400">{result.port}</span>
                                      </td>
                                      <td class="py-2 px-3">
                                        <span class="px-2 py-1 text-xs font-medium rounded-full {result.status === 'open' ? 'bg-green-900 text-green-300' : 'bg-gray-700 text-gray-300'}">
                                          {result.status === 'open' ? $tr('history.details.open') : result.status}
                                        </span>
                                      </td>
                                      <td class="py-2 px-3 text-gray-300">
                                        {result.service || '-'}
                                      </td>
                                      <td class="py-2 px-3 text-gray-400 text-xs">
                                        {result.version || '-'}
                                      </td>
                                      <td class="py-2 px-3 text-gray-400 text-xs">
                                        {result.protocol || 'tcp'}
                                      </td>
                                      <td class="py-2 px-3 text-xs max-w-xs">
                                        {#if result.banner}
                                          <div class="flex items-center gap-2">
                                            <span class="text-gray-300 truncate flex-1 font-mono" title={result.banner}>
                                              {@html highlightBanner(result.banner)}
                                            </span>
                                            <button
                                              type="button"
                                              on:click={() => copyBanner(result.banner)}
                                              class="text-gray-500 hover:text-blue-400 transition-colors flex-shrink-0"
                                              title={$tr('common.copy')}
                                            >
                                              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"></path>
                                              </svg>
                                            </button>
                                          </div>
                                        {:else}
                                          <span class="text-gray-500">-</span>
                                        {/if}
                                      </td>
                                    </tr>
                                  {/each}
                                </tbody>
                              </table>
                            </div>
                            
                            {#if results.length > detailsPageSize}
                              {@const totalPages = Math.ceil(results.length / detailsPageSize)}
                              {@const currentPage = targetPages.get(target) || 1}
                              <div class="mt-3 flex items-center justify-center gap-3">
                                <button
                                  on:click={() => changeTargetPage(target, -1, results.length)}
                                  disabled={currentPage === 1}
                                  class="px-3 py-1 text-sm bg-gray-700 rounded disabled:opacity-50 hover:bg-gray-600 transition-colors"
                                >
                                  {$tr('history.details.previous')}
                                </button>
                                <div class="flex items-center gap-2">
                                  <input
                                    type="number"
                                    min="1"
                                    max={totalPages}
                                    value={targetPageInputs.get(target) || currentPage.toString()}
                                    on:input={(e) => {
                                      const input = e.target as HTMLInputElement;
                                      targetPageInputs.set(target, input.value);
                                      targetPageInputs = new Map(targetPageInputs);
                                    }}
                                    on:keydown={(e) => {
                                      if (e.key === 'Enter') {
                                        goToTargetPage(target, totalPages);
                                      }
                                    }}
                                    class="w-16 px-2 py-1 text-sm text-center bg-gray-800 border border-gray-600 rounded text-gray-300 focus:outline-none focus:border-blue-500"
                                  />
                                  <span class="text-sm text-gray-400">/ {totalPages}</span>
                                  <button
                                    type="button"
                                    on:click={() => goToTargetPage(target, totalPages)}
                                    class="px-3 py-1 text-sm bg-gray-700 hover:bg-gray-600 rounded disabled:opacity-50 transition-colors"
                                  >
                                    {$tr('history.details.go')}
                                  </button>
                                </div>
                                <button
                                  on:click={() => changeTargetPage(target, 1, results.length)}
                                  disabled={currentPage >= totalPages}
                                  class="px-3 py-1 text-sm bg-gray-700 rounded disabled:opacity-50 hover:bg-gray-600 transition-colors"
                                >
                                  {$tr('history.details.next')}
                                </button>
                              </div>
                            {/if}
                          </div>
                        {/if}
                      </div>
                    {/each}
                  </div>

                  {#if targetList.length > 10 && !showAllTargets}
                    <div class="text-center pt-4">
                      <button
                        on:click={toggleShowAllTargets}
                        class="px-4 py-2 text-sm bg-blue-600 hover:bg-blue-700 rounded-lg transition-colors"
                      >
                        {$tr('history.details.showAllTargets', { count: targetList.length })}
                      </button>
                    </div>
                  {:else if showAllTargets}
                    <div class="text-center pt-4">
                      <button
                        on:click={toggleShowAllTargets}
                        class="px-4 py-2 text-sm bg-gray-700 hover:bg-gray-600 rounded-lg transition-colors"
                      >
                        {$tr('history.details.showFirstTargets')}
                      </button>
                    </div>
                  {/if}
                {/if}
              </div>
            </div>
          {:else}
            <div class="text-center py-12 text-gray-400">
              <svg class="mx-auto h-12 w-12 mb-4 text-gray-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>
              </svg>
              <p class="text-lg">{$tr('history.details.noScanResults')}</p>
            </div>
          {/if}
        </div>
      </div>
    {/if}
  </div>
</div>
