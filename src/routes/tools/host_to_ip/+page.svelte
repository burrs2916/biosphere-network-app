<script lang="ts">
	import { onMount } from 'svelte';
	import { invoke } from '@tauri-apps/api/core';
	import { tr, locale } from '$lib/i18n';

	interface HostDnsRecord {
		record_type: string;
		name: string;
		value: string;
		ttl: number | null;
	}

	interface HostInfo {
		ip: string;
		ip_version: string;
		reverse_dns: string | null;
		is_private: boolean;
		asn: string | null;
		country: string | null;
		org: string | null;
	}

	interface HostSecurityFinding {
		severity: string;
		category: string;
		description: string;
		recommendation: string;
	}

	interface ResolveResult {
		hostname: string;
		ip_addresses: string[];
		host_info: HostInfo[];
		dns_records: HostDnsRecord[];
		cname: string | null;
		is_cdn: boolean;
		cdn_provider: string | null;
		security_findings: HostSecurityFinding[];
		summary: string;
	}

	interface ToolHistoryItem {
		id: number;
		tool_type: string;
		tool_name: string;
		input_summary: string;
		result_summary: string | null;
		result_json: string;
		status: string;
		created_at: string;
	}

	let hostname = '';
	let queryAllRecords = true;
	let includeReverseDns = true;
	let includeCname = true;
	let result: ResolveResult | null = null;
	let error = '';
	let processing = false;
	let activeTab = 'resolve';
	let activeResultTab = 'overview';
	let showHelpModal = false;
	let showConfirmDialog = false;
	let confirmDialogTitle = '';
	let confirmDialogMessage = '';
	let confirmAction: (() => Promise<void>) | null = null;

	let history: ToolHistoryItem[] = [];
	let loadingHistory = false;
	let historyError = '';
	let selectedHistoryItem: ToolHistoryItem | null = null;
	let showHistoryDetail = false;

	$: $locale;

	async function resolve() {
		if (!hostname.trim()) { error = $tr('hostToIp.hostname') + ' required'; return; }
		processing = true; error = ''; result = null;
		try {
			result = await invoke<ResolveResult>('resolve_host', {
				host: hostname.trim()
			});
			await invoke('save_tool_history', {
				toolType: 'host_to_ip',
				toolName: $tr('hostToIp.title'),
				inputSummary: hostname.trim(),
				resultSummary: result.summary || null,
				resultJson: JSON.stringify(result),
				status: 'completed',
			});
		} catch (e: any) {
			error = e.toString();
			try {
				await invoke('save_tool_history', {
					toolType: 'host_to_ip',
					toolName: $tr('hostToIp.title'),
					inputSummary: hostname.trim(),
					resultSummary: null,
					resultJson: '',
					status: 'failed',
				});
			} catch (_) {}
		} finally {
			processing = false;
		}
	}

	async function loadHistory() {
		loadingHistory = true;
		historyError = '';
		try {
			history = await invoke<ToolHistoryItem[]>('get_tool_history', {
				toolType: 'host_to_ip',
				limit: 100,
				offset: 0,
			});
		} catch (e: any) {
			const msg = e.toString();
			if (msg.includes('no such table')) {
				history = [];
			} else {
				historyError = `${$tr('hostToIp.history.messages.loadFailed')}: ${e}`;
			}
		} finally {
			loadingHistory = false;
		}
	}

	async function deleteHistoryItem(id: number) {
		showConfirm(
			$tr('hostToIp.history.messages.deleteConfirm'),
			$tr('hostToIp.history.messages.deleteConfirmMessage'),
			async () => {
				try {
					await invoke('delete_tool_history', { id });
					await loadHistory();
				} catch (e) {
					historyError = `${$tr('hostToIp.history.messages.deleteFailed')}: ${e}`;
				}
			}
		);
	}

	async function clearAllHistory() {
		showConfirm(
			$tr('hostToIp.history.messages.clearAllConfirm'),
			$tr('hostToIp.history.messages.clearAllConfirmMessage'),
			async () => {
				try {
					await invoke('clear_tool_history', { toolType: 'host_to_ip' });
					await loadHistory();
				} catch (e) {
					historyError = `${$tr('hostToIp.history.messages.clearFailed')}: ${e}`;
				}
			}
		);
	}

	function viewHistoryDetail(item: ToolHistoryItem) {
		selectedHistoryItem = item;
		showHistoryDetail = true;
	}

	function showConfirm(title: string, message: string, action: () => Promise<void>) {
		confirmDialogTitle = title;
		confirmDialogMessage = message;
		confirmAction = action;
		showConfirmDialog = true;
	}

	async function executeConfirm() {
		showConfirmDialog = false;
		if (confirmAction) {
			await confirmAction();
			confirmAction = null;
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

	function getSeverityColor(severity: string): string {
		switch (severity) {
			case 'high': return 'text-red-400';
			case 'medium': return 'text-yellow-400';
			case 'low': return 'text-blue-400';
			default: return 'text-gray-400';
		}
	}

	function getSeverityBg(severity: string): string {
		switch (severity) {
			case 'high': return 'bg-red-500/20 border-red-500/30';
			case 'medium': return 'bg-yellow-500/20 border-yellow-500/30';
			case 'low': return 'bg-blue-500/20 border-blue-500/30';
			default: return 'bg-gray-500/20 border-gray-500/30';
		}
	}

	function getRecordTypeColor(type: string): string {
		switch (type) {
			case 'A': return 'bg-green-500/20 text-green-400';
			case 'AAAA': return 'bg-emerald-500/20 text-emerald-400';
			case 'MX': return 'bg-blue-500/20 text-blue-400';
			case 'NS': return 'bg-purple-500/20 text-purple-400';
			case 'TXT': return 'bg-yellow-500/20 text-yellow-400';
			case 'CNAME': return 'bg-pink-500/20 text-pink-400';
			default: return 'bg-gray-500/20 text-gray-400';
		}
	}

	function getStatusBadge(status: string): string {
		switch (status) {
			case 'completed': return '✅';
			case 'failed': return '❌';
			case 'error': return '⚠️';
			default: return 'ℹ️';
		}
	}

	onMount(() => {
		loadHistory();
	});
</script>

<svelte:window on:click={() => {}} />

<div class="host2ip-page">
	<div class="page-header">
		<a href="/" class="back-link">{$tr('common.backToHome')}</a>
		<div class="header-content">
			<div class="title-section">
				<h1 class="page-title">🌐 {$tr('hostToIp.title')}</h1>
				<p class="page-subtitle">{$tr('hostToIp.subtitle')}</p>
			</div>
			<button class="help-btn" on:click={() => showHelpModal = true} title={$tr('common.userManual')}>
				{$tr('common.userManual')}
			</button>
		</div>
	</div>

	<div class="tabs">
		<button
			class="tab-button {activeTab === 'resolve' ? 'active' : ''}"
			on:click={() => activeTab = 'resolve'}
		>
			{$tr('hostToIp.tabs.resolve')}
		</button>
		<button
			class="tab-button {activeTab === 'history' ? 'active' : ''}"
			on:click={() => { activeTab = 'history'; loadHistory(); }}
		>
			{$tr('hostToIp.tabs.history')}
		</button>
	</div>

	{#if activeTab === 'resolve'}
		<div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
			<div class="lg:col-span-1 space-y-4">
				<div class="bg-gray-900 rounded-lg p-4 border border-gray-700">
					<h2 class="text-lg font-semibold mb-4">{$tr('hostToIp.hostname')}</h2>
					<div class="space-y-3">
						<div>
							<label class="block text-sm text-gray-400 mb-1">{$tr('hostToIp.hostname')}</label>
							<input type="text" bind:value={hostname} placeholder={$tr('hostToIp.hostnamePlaceholder')} class="w-full bg-gray-800 border border-gray-600 rounded px-3 py-2 text-sm focus:border-blue-500 focus:outline-none" />
						</div>
						<div class="space-y-2">
							<div class="flex items-center gap-2">
								<input type="checkbox" id="chkAll" bind:checked={queryAllRecords} class="rounded" />
								<label for="chkAll" class="text-sm text-gray-300">{$tr('hostToIp.queryAllRecords')}</label>
							</div>
							<div class="flex items-center gap-2">
								<input type="checkbox" id="chkRev" bind:checked={includeReverseDns} class="rounded" />
								<label for="chkRev" class="text-sm text-gray-300">{$tr('hostToIp.includeReverseDns')}</label>
							</div>
							<div class="flex items-center gap-2">
								<input type="checkbox" id="chkCname" bind:checked={includeCname} class="rounded" />
								<label for="chkCname" class="text-sm text-gray-300">{$tr('hostToIp.includeCname')}</label>
							</div>
						</div>
						<button on:click={resolve} disabled={processing} class="w-full bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 disabled:cursor-not-allowed rounded px-4 py-2 text-sm font-medium transition-colors">
							{processing ? $tr('hostToIp.resolving') : $tr('hostToIp.resolve')}
						</button>
					</div>
				</div>
			</div>

			<div class="lg:col-span-2 space-y-4">
				{#if error}
					<div class="bg-red-500/20 border border-red-500/30 rounded-lg p-4 text-red-300 text-sm">{error}</div>
				{/if}

				{#if result}
					<div class="bg-gray-900 rounded-lg p-4 border border-gray-700">
						<div class="bg-blue-500/10 border border-blue-500/20 rounded p-3 mb-4 text-sm text-blue-300">{result.summary}</div>

						<div class="grid grid-cols-4 gap-2 mb-4">
							<button on:click={() => activeResultTab = 'overview'} class="bg-gray-800 rounded p-2 text-center hover:bg-gray-700 transition-colors {activeResultTab === 'overview' ? 'ring-1 ring-blue-500' : ''}">
								<div class="text-lg font-bold text-white">{result.ip_addresses.length}</div>
								<div class="text-xs text-gray-400">{$tr('hostToIp.result.ipAddresses')}</div>
							</button>
							<button on:click={() => activeResultTab = 'dns'} class="bg-gray-800 rounded p-2 text-center hover:bg-gray-700 transition-colors {activeResultTab === 'dns' ? 'ring-1 ring-blue-500' : ''}">
								<div class="text-lg font-bold text-green-400">{result.dns_records.length}</div>
								<div class="text-xs text-gray-400">{$tr('hostToIp.result.dnsRecords')}</div>
							</button>
							<button on:click={() => activeResultTab = 'hosts'} class="bg-gray-800 rounded p-2 text-center hover:bg-gray-700 transition-colors {activeResultTab === 'hosts' ? 'ring-1 ring-blue-500' : ''}">
								<div class="text-lg font-bold text-yellow-400">{result.host_info.length}</div>
								<div class="text-xs text-gray-400">{$tr('hostToIp.result.hostInfo')}</div>
							</button>
							<button on:click={() => activeResultTab = 'findings'} class="bg-gray-800 rounded p-2 text-center hover:bg-gray-700 transition-colors {activeResultTab === 'findings' ? 'ring-1 ring-blue-500' : ''}">
								<div class="text-lg font-bold text-red-400">{result.security_findings.length}</div>
								<div class="text-xs text-gray-400">{$tr('hostToIp.result.securityFindings')}</div>
							</button>
						</div>

						{#if activeResultTab === 'overview'}
							<div class="space-y-4">
								<div>
									<h3 class="text-sm font-medium text-gray-300 mb-2">{$tr('hostToIp.result.ipAddresses')}</h3>
									<div class="flex flex-wrap gap-2">
										{#each result.ip_addresses as ip}
											<span class="bg-green-500/10 text-green-300 px-3 py-1 rounded text-sm font-mono">{ip}</span>
										{/each}
									</div>
								</div>
								{#if result.cname}
									<div>
										<h3 class="text-sm font-medium text-gray-300 mb-2">{$tr('hostToIp.result.cname')}</h3>
										<span class="bg-pink-500/10 text-pink-300 px-3 py-1 rounded text-sm font-mono">{result.cname}</span>
									</div>
								{/if}
								{#if result.is_cdn}
									<div class="bg-purple-500/10 border border-purple-500/20 rounded p-3">
										<span class="text-purple-300 text-sm">{$tr('hostToIp.result.isCdn')}: {result.cdn_provider || '未知'}</span>
									</div>
								{/if}
							</div>
						{:else if activeResultTab === 'dns'}
							<div class="overflow-x-auto">
								<table class="w-full text-sm">
									<thead>
										<tr class="text-gray-400 border-b border-gray-700">
											<th class="text-left py-2 px-3">Type</th>
											<th class="text-left py-2 px-3">Name</th>
											<th class="text-left py-2 px-3">Value</th>
										</tr>
									</thead>
									<tbody>
										{#each result.dns_records as record}
											<tr class="border-b border-gray-800">
												<td class="py-2 px-3"><span class="px-2 py-0.5 rounded text-xs font-bold {getRecordTypeColor(record.record_type)}">{record.record_type}</span></td>
												<td class="py-2 px-3 font-mono text-gray-300">{record.name}</td>
												<td class="py-2 px-3 font-mono text-blue-400 break-all">{record.value}</td>
											</tr>
										{/each}
									</tbody>
								</table>
							</div>
						{:else if activeResultTab === 'hosts'}
							<div class="space-y-2">
								{#each result.host_info as info}
									<div class="bg-gray-800 rounded p-3 border border-gray-700">
										<div class="flex items-center justify-between mb-2">
											<span class="font-mono text-yellow-400 text-lg">{info.ip}</span>
											<div class="flex gap-2">
												<span class="px-2 py-0.5 rounded text-xs {info.ip_version === 'IPv4' ? 'bg-blue-500/20 text-blue-400' : 'bg-purple-500/20 text-purple-400'}">{info.ip_version}</span>
												{#if info.is_private}
													<span class="px-2 py-0.5 rounded text-xs bg-red-500/20 text-red-400">Private</span>
												{/if}
											</div>
										</div>
										<div class="grid grid-cols-2 gap-1 text-xs text-gray-400">
											{#if info.reverse_dns}<span>rDNS: <span class="text-gray-300">{info.reverse_dns}</span></span>{/if}
											{#if info.asn}<span>ASN: {info.asn}</span>{/if}
											{#if info.country}<span>{$tr('hostToIp.result.ipAddresses')}: {info.country}</span>{/if}
											{#if info.org}<span>ORG: {info.org}</span>{/if}
										</div>
									</div>
								{/each}
							</div>
						{:else if activeResultTab === 'findings'}
							<div class="space-y-2">
								{#each result.security_findings as finding}
									<div class="rounded p-3 border {getSeverityBg(finding.severity)}">
										<div class="flex items-center gap-2 mb-1">
											<span class="text-xs font-bold uppercase {getSeverityColor(finding.severity)}">{finding.severity}</span>
											<span class="text-sm font-medium">{finding.category}</span>
										</div>
										<p class="text-sm text-gray-300 mb-1">{finding.description}</p>
										<p class="text-xs text-green-400">{finding.recommendation}</p>
									</div>
								{/each}
							</div>
						{/if}
					</div>
				{:else if !processing}
					<div class="text-center py-12 text-gray-500">
						<div class="text-4xl mb-3">🌐</div>
						<p>{$tr('hostToIp.result.noResults')}</p>
					</div>
				{/if}

				{#if processing}
					<div class="text-center py-8">
						<div class="inline-block w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full animate-spin"></div>
						<p class="mt-3 text-gray-400">{$tr('hostToIp.resolving')}</p>
					</div>
				{/if}
			</div>
		</div>
	{:else}
		<div class="history-section">
			<div class="history-header">
				<h2>{$tr('hostToIp.history.title')}</h2>
				<div class="history-actions">
					<button type="button" class="btn-clear-history" on:click={clearAllHistory}>
						🗑️ {$tr('hostToIp.history.actions.clearAll')}
					</button>
				</div>
			</div>

			{#if loadingHistory}
				<div class="text-center py-8">
					<div class="inline-block w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full animate-spin"></div>
					<p class="mt-2 text-gray-400">{$tr('common.loading')}</p>
				</div>
			{:else if historyError}
				<div class="bg-red-500/20 border border-red-500/30 rounded p-4 text-red-300 text-sm">
					<p>{historyError}</p>
					<button on:click={loadHistory} class="mt-2 text-blue-400 hover:text-blue-300">{$tr('common.retry')}</button>
				</div>
			{:else if history.length === 0}
				<div class="text-center py-12 text-gray-500">
					<div class="text-4xl mb-3">📋</div>
					<p>{$tr('hostToIp.history.messages.noHistory')}</p>
				</div>
			{:else}
				<div class="history-table">
					<table>
						<thead>
							<tr>
								<th>{$tr('hostToIp.history.table.input')}</th>
								<th>{$tr('hostToIp.history.table.status')}</th>
								<th>{$tr('hostToIp.history.table.summary')}</th>
								<th>{$tr('hostToIp.history.table.createdAt')}</th>
								<th>{$tr('hostToIp.history.table.actions')}</th>
							</tr>
						</thead>
						<tbody>
							{#each history as item (item.id)}
								<tr>
									<td class="font-mono">{item.input_summary}</td>
									<td>{getStatusBadge(item.status)} {item.status}</td>
									<td class="max-w-xs truncate">{item.result_summary || '-'}</td>
									<td>{formatDateTime(item.created_at)}</td>
									<td class="actions-cell">
										<button
											class="btn-small btn-primary"
											on:click|stopPropagation={() => viewHistoryDetail(item)}
										>
											👁️ {$tr('hostToIp.history.actions.view')}
										</button>
										<button
											type="button"
											class="btn-small btn-danger"
											on:click|stopPropagation={() => deleteHistoryItem(item.id)}
										>
											🗑️ {$tr('hostToIp.history.actions.delete')}
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
		<div class="modal-overlay" on:click={() => showHistoryDetail = false}>
			<div class="modal-content" on:click|stopPropagation>
				<div class="modal-header">
					<h2>📋 {$tr('hostToIp.history.actions.view')} - {selectedHistoryItem.input_summary}</h2>
					<button class="modal-close" on:click={() => showHistoryDetail = false}>✕</button>
				</div>
				<div class="modal-body">
					<div class="detail-row">
						<span class="detail-label">{$tr('hostToIp.history.table.input')}:</span>
						<span class="detail-value">{selectedHistoryItem.input_summary}</span>
					</div>
					<div class="detail-row">
						<span class="detail-label">{$tr('hostToIp.history.table.status')}:</span>
						<span class="detail-value">{getStatusBadge(selectedHistoryItem.status)} {selectedHistoryItem.status}</span>
					</div>
					<div class="detail-row">
						<span class="detail-label">{$tr('hostToIp.history.table.createdAt')}:</span>
						<span class="detail-value">{formatDateTime(selectedHistoryItem.created_at)}</span>
					</div>
					{#if selectedHistoryItem.result_summary}
						<div class="detail-row">
							<span class="detail-label">{$tr('hostToIp.history.table.summary')}:</span>
							<span class="detail-value">{selectedHistoryItem.result_summary}</span>
						</div>
					{/if}
					{#if selectedHistoryItem.result_json}
						<div class="detail-json">
							<div class="detail-label">Result JSON:</div>
							<pre class="json-content">{JSON.stringify(JSON.parse(selectedHistoryItem.result_json), null, 2)}</pre>
						</div>
					{/if}
				</div>
			</div>
		</div>
	{/if}

	{#if showConfirmDialog}
		<div class="modal-overlay" on:click={() => showConfirmDialog = false}>
			<div class="confirm-dialog" on:click|stopPropagation>
				<h3>{confirmDialogTitle}</h3>
				<p>{confirmDialogMessage}</p>
				<div class="confirm-actions">
					<button class="btn-secondary" on:click={() => showConfirmDialog = false}>{$tr('common.cancel')}</button>
					<button class="btn-danger" on:click={executeConfirm}>{$tr('common.confirm')}</button>
				</div>
			</div>
		</div>
	{/if}

	{#if showHelpModal}
		<div
			class="modal-overlay"
			on:click={() => showHelpModal = false}
			on:keydown={(e) => e.key === 'Escape' && (showHelpModal = false)}
		>
			<div class="modal-content help-modal" on:click|stopPropagation>
				<div class="modal-header">
					<h2>{$tr('hostToIp.helpModal.title')}</h2>
					<button class="modal-close" on:click={() => showHelpModal = false}>✕</button>
				</div>
				<div class="help-body">
					<div class="help-section">
						<h3>{$tr('hostToIp.helpModal.overview')}</h3>
						<p>{$tr('hostToIp.helpModal.overviewText')}</p>
					</div>

					<div class="help-section">
						<h3>{$tr('hostToIp.helpModal.inputTitle')}</h3>
						<p>{$tr('hostToIp.helpModal.inputDesc')}</p>
					</div>

					<div class="help-section">
						<h3>{$tr('hostToIp.helpModal.optionsTitle')}</h3>
						<ul>
							<li><strong>{$tr('hostToIp.queryAllRecords')}:</strong> {$tr('hostToIp.helpModal.options.queryAllRecords')}</li>
							<li><strong>{$tr('hostToIp.includeReverseDns')}:</strong> {$tr('hostToIp.helpModal.options.includeReverseDns')}</li>
							<li><strong>{$tr('hostToIp.includeCname')}:</strong> {$tr('hostToIp.helpModal.options.includeCname')}</li>
						</ul>
					</div>

					<div class="help-section">
						<h3>{$tr('hostToIp.helpModal.resultsTitle')}</h3>
						<ul>
							<li><strong>{$tr('hostToIp.result.ipAddresses')}:</strong> {$tr('hostToIp.helpModal.results.ipAddresses')}</li>
							<li><strong>{$tr('hostToIp.result.dnsRecords')}:</strong> {$tr('hostToIp.helpModal.results.dnsRecords')}</li>
							<li><strong>{$tr('hostToIp.result.hostInfo')}:</strong> {$tr('hostToIp.helpModal.results.hostInfo')}</li>
							<li><strong>{$tr('hostToIp.result.securityFindings')}:</strong> {$tr('hostToIp.helpModal.results.securityFindings')}</li>
							<li><strong>{$tr('hostToIp.result.isCdn')}:</strong> {$tr('hostToIp.helpModal.results.cdnDetection')}</li>
						</ul>
					</div>

					<div class="help-section">
						<h3>{$tr('hostToIp.helpModal.tipsTitle')}</h3>
						<ul>
							<li>{$tr('hostToIp.helpModal.tips.0')}</li>
							<li>{$tr('hostToIp.helpModal.tips.1')}</li>
							<li>{$tr('hostToIp.helpModal.tips.2')}</li>
							<li>{$tr('hostToIp.helpModal.tips.3')}</li>
						</ul>
					</div>

					<div class="help-section">
						<h3>{$tr('hostToIp.helpModal.warningTitle')}</h3>
						<ul>
							<li>{$tr('hostToIp.helpModal.warnings.0')}</li>
							<li>{$tr('hostToIp.helpModal.warnings.1')}</li>
							<li>{$tr('hostToIp.helpModal.warnings.2')}</li>
						</ul>
					</div>
				</div>
			</div>
		</div>
	{/if}
</div>

<style>
	.host2ip-page {
		max-width: 1400px;
		margin: 0 auto;
		padding: 2rem;
		min-height: 100vh;
		background: linear-gradient(135deg, #0a0e17 0%, #1a1a2e 100%);
		color: #f1f5f9;
	}

	.page-header { margin-bottom: 2rem; }
	.back-link { color: #60a5fa; text-decoration: none; font-size: 0.9rem; }
	.back-link:hover { text-decoration: underline; }
	.header-content { display: flex; justify-content: space-between; align-items: center; margin-top: 0.5rem; }
	.title-section { flex: 1; }
	.page-title { font-size: 1.8rem; font-weight: 700; margin: 0; }
	.page-subtitle { color: #94a3b8; font-size: 0.9rem; margin-top: 0.25rem; }
	.help-btn { padding: 8px 16px; border-radius: 8px; border: 1px solid #334155; background: #1e293b; color: #94a3b8; cursor: pointer; font-size: 0.85rem; transition: all 0.2s; }
	.help-btn:hover { background: #334155; color: #e2e8f0; }

	.tabs { display: flex; gap: 0; margin-bottom: 1.5rem; border-bottom: 2px solid #1e293b; }
	.tab-button { padding: 10px 24px; border: none; background: transparent; color: #64748b; font-size: 0.95rem; cursor: pointer; border-bottom: 2px solid transparent; margin-bottom: -2px; transition: all 0.2s; }
	.tab-button.active { color: #60a5fa; border-bottom-color: #3b82f6; }
	.tab-button:hover:not(.active) { color: #94a3b8; }

	.history-section { background: #0f172a; border-radius: 12px; padding: 20px; border: 1px solid #1e293b; }
	.history-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; }
	.history-header h2 { margin: 0; font-size: 1.1rem; }
	.btn-clear-history { padding: 6px 14px; border-radius: 6px; border: 1px solid #334155; background: #1e293b; color: #94a3b8; cursor: pointer; font-size: 0.85rem; transition: all 0.2s; }
	.btn-clear-history:hover { background: #334155; color: #f87171; border-color: #ef4444; }

	.history-table { overflow-x: auto; }
	.history-table table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
	.history-table th { text-align: left; padding: 10px 12px; border-bottom: 1px solid #1e293b; color: #64748b; font-weight: 600; }
	.history-table td { padding: 10px 12px; border-bottom: 1px solid #0f172a; color: #cbd5e1; }
	.history-table tr:hover td { background: #1e293b; }
	.actions-cell { white-space: nowrap; }
	.btn-small { padding: 4px 10px; border-radius: 6px; border: none; cursor: pointer; font-size: 0.8rem; margin-right: 4px; transition: all 0.2s; }
	.btn-primary { background: #1e3a5f; color: #60a5fa; }
	.btn-primary:hover { background: #1e4a7f; }
	.btn-danger { background: #3b1111; color: #f87171; }
	.btn-danger:hover { background: #5b1111; }

	.modal-overlay { position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.6); display: flex; align-items: center; justify-content: center; z-index: 1000; }
	.modal-content { background: #1e293b; border-radius: 12px; padding: 24px; max-width: 700px; width: 90%; max-height: 80vh; overflow-y: auto; border: 1px solid #334155; }
	.modal-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; }
	.modal-header h2, .modal-header h3 { margin: 0; font-size: 1.1rem; }
	.modal-close { background: none; border: none; cursor: pointer; font-size: 1.3rem; color: #64748b; }
	.modal-close:hover { color: #e2e8f0; }
	.modal-body { display: flex; flex-direction: column; gap: 10px; }
	.detail-row { display: flex; gap: 8px; font-size: 0.9rem; }
	.detail-label { color: #64748b; min-width: 60px; }
	.detail-value { flex: 1; word-break: break-all; color: #cbd5e1; }
	.detail-json { margin-top: 8px; }
	.json-content { background: #0f172a; border-radius: 8px; padding: 12px; font-size: 0.8rem; overflow-x: auto; max-height: 400px; overflow-y: auto; white-space: pre-wrap; word-break: break-all; color: #94a3b8; }

	.confirm-dialog { background: #1e293b; border-radius: 12px; padding: 24px; max-width: 400px; width: 90%; text-align: center; border: 1px solid #334155; }
	.confirm-dialog h3 { margin: 0 0 8px; font-size: 1rem; }
	.confirm-dialog p { margin: 0 0 16px; font-size: 0.9rem; color: #94a3b8; }
	.confirm-actions { display: flex; gap: 8px; justify-content: center; }
	.btn-secondary { padding: 8px 20px; border-radius: 8px; border: 1px solid #334155; background: #0f172a; color: #94a3b8; cursor: pointer; font-size: 0.9rem; }
	.btn-secondary:hover { background: #1e293b; }
	.btn-danger { padding: 8px 20px; border-radius: 8px; border: none; background: #ef4444; color: white; cursor: pointer; font-size: 0.9rem; }
	.btn-danger:hover { background: #dc2626; }

	.help-modal { max-width: 800px; }
	.help-body { display: flex; flex-direction: column; gap: 16px; }
	.help-section { padding: 12px; background: #0f172a; border-radius: 8px; border: 1px solid #1e293b; }
	.help-section h3 { margin: 0 0 8px; font-size: 0.95rem; color: #60a5fa; }
	.help-section p { margin: 0; font-size: 0.85rem; color: #94a3b8; line-height: 1.6; }
	.help-section ul { margin: 4px 0; padding-left: 20px; }
	.help-section li { font-size: 0.85rem; color: #94a3b8; line-height: 1.8; }
	.help-section li strong { color: #e2e8f0; }
</style>
