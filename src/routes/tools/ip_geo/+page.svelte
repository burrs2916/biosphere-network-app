<script lang="ts">
	import { tr } from '$lib/i18n';
	import { open } from '@tauri-apps/plugin-dialog';
	import { readFile } from '@tauri-apps/plugin-fs';

	interface IpGeoInfo {
		ip: string;
		country: string;
		country_code: string;
		region: string;
		city: string;
		latitude: number;
		longitude: number;
		isp: string;
		org: string;
		timezone: string;
	}

	interface BatchIpGeoResult {
		ip: string;
		result: IpGeoInfo | null;
		error: string | null;
	}

	let ip = '';
	let result: IpGeoInfo | null = null;
	let batchResults: BatchIpGeoResult[] = [];
	let error = '';
	let processing = false;
	let showHelpModal = false;
	let activeTab = 'single';

	let showTargetSelector = false;
	let targetList: any[] = [];
	let selectedTargets: any[] = [];
	let selectedTargetIds: number[] = [];
	let targetSearchQuery = '';
	let loadingTargets = false;

	let currentPage = 1;
	let pageSize = 10;

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

	$: totalPages = Math.ceil(batchResults.length / pageSize);
	$: paginatedResults = batchResults.slice((currentPage - 1) * pageSize, currentPage * pageSize);
	$: successCount = batchResults.filter(r => r.result).length;
	$: failedCount = batchResults.filter(r => r.error).length;
	$: filteredTargets = targetList.filter((t: any) =>
		!targetSearchQuery ||
		t.name?.toLowerCase().includes(targetSearchQuery.toLowerCase()) ||
		t.target_value?.toLowerCase().includes(targetSearchQuery.toLowerCase())
	);

	async function lookupIp() {
		if (!ip.trim()) {
			error = $tr('ipGeo.error.emptyInput');
			return;
		}

		processing = true;
		error = '';
		result = null;

		try {
			const { invoke } = await import('@tauri-apps/api/core');
			result = await invoke<IpGeoInfo>('lookup_ip_geo_command', { ip: ip.trim(), targetId: selectedTargetIds.length > 0 ? selectedTargetIds[0] : null });

			if (result) {
				try {
					await invoke('save_ip_geo_record', {
						ip: result.ip,
						country: result.country,
						countryCode: result.country_code,
						region: result.region,
						city: result.city,
						latitude: result.latitude,
						longitude: result.longitude,
						isp: result.isp,
						org: result.org,
						timezone: result.timezone,
					});
				} catch (e) {
					console.error('Failed to save history:', e);
				}
			}
		} catch (e: any) {
			error = e.toString();
		} finally {
			processing = false;
		}
	}

	async function batchLookup() {
		const ips = ip
			.split(/[\n,;]+/)
			.map(h => h.trim())
			.filter(h => h.length > 0);

		if (ips.length === 0) {
			error = $tr('ipGeo.error.emptyInput');
			return;
		}

		processing = true;
		error = '';
		batchResults = [];

		try {
			const { invoke } = await import('@tauri-apps/api/core');
			for (const targetIp of ips) {
				try {
					const r = await invoke<IpGeoInfo>('lookup_ip_geo_command', { ip: targetIp });
					batchResults.push({ ip: targetIp, result: r, error: null });

					try {
						await invoke('save_ip_geo_record', {
							ip: r.ip,
							country: r.country,
							countryCode: r.country_code,
							region: r.region,
							city: r.city,
							latitude: r.latitude,
							longitude: r.longitude,
							isp: r.isp,
							org: r.org,
							timezone: r.timezone,
						});
					} catch (e) {
						console.error('Failed to save history:', e);
					}
				} catch (e: any) {
					batchResults.push({ ip: targetIp, result: null, error: e.toString() });
				}
			}
		} catch (e: any) {
			error = e.toString();
		} finally {
			processing = false;
		}
	}

	async function lookupMyIp() {
		processing = true;
		error = '';
		result = null;

		try {
			const response = await fetch('https://api.ipify.org?format=json');
			const data = await response.json();
			ip = data.ip;
			await lookupIp();
		} catch (e: any) {
			error = $tr('ipGeo.error.myIpFailed');
			processing = false;
		}
	}

	async function openTargetSelectorModal() {
		showTargetSelector = true;
		await loadTargets();
	}

	async function loadTargets() {
		loadingTargets = true;
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			const result = await invoke<{ targets: any[], total: number }>('target_manager', {
				action: 'list',
				page: 1,
				pageSize: 100
			});
			targetList = result.targets || [];
		} catch (e) {
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
			ip = ip ? `${ip}\n${targetValues}` : targetValues;
			selectedTargetIds = selectedTargets.map(t => t.id).filter((id: number | null): id is number => id !== null);
		}
		showTargetSelector = false;
		selectedTargets = [];
	}

	async function importIps() {
		try {
			const selected = await open({
				multiple: false,
				filters: [{ name: 'Text', extensions: ['txt', 'csv', 'list'] }]
			});
			if (selected) {
				const fileData = await readFile(selected as string);
				const content = new TextDecoder('utf-8').decode(fileData);
				const ips = content
					.split(/[\n,;]+/)
					.map(h => h.trim())
					.filter(h => h.length > 0);
				if (ips.length > 0) {
					ip = ip ? `${ip}\n${ips.join('\n')}` : ips.join('\n');
				}
			}
		} catch (e) {
			console.error('Import failed:', e);
		}
	}

	function clearAll() {
		ip = '';
		result = null;
		batchResults = [];
		error = '';
	}

	function switchTab(tab: string) {
		activeTab = tab;
		error = '';
		result = null;
		batchResults = [];
		if (tab === 'history') {
			loadHistory();
		}
	}

	function getCountryFlag(code: string): string {
		if (!code || code.length !== 2) return '🌐';
		const codePoints = code
			.toUpperCase()
			.split('')
			.map(char => 127397 + char.charCodeAt(0));
		return String.fromCodePoint(...codePoints);
	}

	async function loadHistory() {
		loadingHistory = true;
		historyError = '';

		try {
			const { invoke } = await import('@tauri-apps/api/core');
			history = await invoke('get_ip_geo_history', {
				limit: historyPageSize,
				offset: (historyCurrentPage - 1) * historyPageSize,
			});
		} catch (e) {
			historyError = `${$tr('ipGeo.history.messages.loadFailed')}: ${e}`;
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
			$tr('ipGeo.history.messages.deleteConfirm'),
			$tr('ipGeo.history.messages.deleteConfirmMessage'),
			async () => {
				try {
					const { invoke } = await import('@tauri-apps/api/core');
					await invoke('delete_ip_geo_record', { id });
					await loadHistory();
				} catch (e) {
					historyError = `${$tr('ipGeo.history.messages.deleteFailed')}: ${e}`;
				}
			}
		);
	}

	async function clearAllHistory() {
		showConfirm(
			$tr('ipGeo.history.messages.clearAllConfirm'),
			$tr('ipGeo.history.messages.clearAllConfirmMessage'),
			async () => {
				try {
					const { invoke } = await import('@tauri-apps/api/core');
					await invoke('clear_ip_geo_history');
					await loadHistory();
				} catch (e) {
					historyError = `${$tr('ipGeo.history.messages.clearFailed')}: ${e}`;
				}
			}
		);
	}

	function viewHistoryDetail(item: any) {
		selectedHistoryItem = item;
		showHistoryDetail = true;
	}

	function requeryFromHistory(item: any) {
		ip = item.ip;
		activeTab = 'single';
		result = null;
		batchResults = [];
		error = '';
		lookupIp();
	}

	function formatDateTime(dateStr: string): string {
		const date = new Date(dateStr);
		return date.toLocaleString('zh-CN', {
			year: 'numeric',
			month: '2-digit',
			day: '2-digit',
			hour: '2-digit',
			minute: '2-digit',
			second: '2-digit',
		});
	}
</script>

<div class="ip-geo-page">
	<div class="page-header">
		<div class="header-left">
			<a href="/" class="back-link">{$tr('common.backToHome')}</a>
			<h1 class="page-title">🗺️ {$tr('ipGeo.title')}</h1>
			<p class="page-subtitle">{$tr('ipGeo.subtitle')}</p>
		</div>
		<button class="help-button" on:click={() => showHelpModal = true}>
			{$tr('common.userManual')}
		</button>
	</div>

	<div class="tabs">
		<button
			class="tab-button {activeTab === 'single' ? 'active' : ''}"
			on:click={() => switchTab('single')}
		>
			{$tr('ipGeo.tabs.single')}
		</button>
		<button
			class="tab-button {activeTab === 'batch' ? 'active' : ''}"
			on:click={() => switchTab('batch')}
		>
			{$tr('ipGeo.tabs.batch')}
		</button>
		<button
			class="tab-button {activeTab === 'history' ? 'active' : ''}"
			on:click={() => { activeTab = 'history'; loadHistory(); }}
		>
			{$tr('ipGeo.tabs.history')}
		</button>
	</div>

	{#if activeTab !== 'history'}
	<div class="content-grid">
		<div class="input-section">
			<div class="section-card">
				{#if activeTab === 'single'}
					<h2 class="section-title">{$tr('ipGeo.input.title')}</h2>
					<div class="form-group">
						<label class="form-label">{$tr('ipGeo.input.label')}</label>
						<div class="input-row">
							<input
								type="text"
								bind:value={ip}
								placeholder={$tr('ipGeo.input.placeholder')}
								class="form-input"
								disabled={processing}
								on:keydown={(e) => e.key === 'Enter' && lookupIp()}
							/>
							<button
								class="btn btn-secondary"
								on:click={lookupMyIp}
								disabled={processing}
								title={$tr('ipGeo.buttons.myIp')}
							>
								📍
							</button>
						</div>
					</div>
					<div class="button-group">
						<button class="btn btn-primary" on:click={lookupIp} disabled={processing || !ip.trim()}>
							{#if processing}⏳ {$tr('ipGeo.buttons.searching')}{:else}🔍 {$tr('ipGeo.buttons.search')}{/if}
						</button>
						<button class="btn btn-secondary" on:click={clearAll} disabled={processing}>
							🗑️ {$tr('ipGeo.buttons.clear')}
						</button>
					</div>
				{:else}
					<h2 class="section-title">{$tr('ipGeo.batch.inputTitle')}</h2>
					<div class="form-group">
						<label class="form-label">{$tr('ipGeo.batch.inputLabel')}</label>
						<textarea
							bind:value={ip}
							placeholder={$tr('ipGeo.batch.inputPlaceholder')}
							class="form-textarea"
							rows="8"
							disabled={processing}
						></textarea>
						<div class="textarea-actions">
							<button type="button" class="action-btn" on:click={openTargetSelectorModal} disabled={processing}>
								🎯 {$tr('ipGeo.batch.selectTarget')}
							</button>
							<button type="button" class="action-btn" on:click={importIps} disabled={processing}>
								📥 {$tr('ipGeo.batch.import')}
							</button>
						</div>
					</div>
					<span class="input-hint">{$tr('ipGeo.batch.inputHint')}</span>
					<div class="button-group">
						<button class="btn btn-primary" on:click={batchLookup} disabled={processing || !ip.trim()}>
							{#if processing}⏳ {$tr('ipGeo.buttons.searching')}{:else}🔍 {$tr('ipGeo.batch.lookupAll')}{/if}
						</button>
						<button class="btn btn-secondary" on:click={clearAll} disabled={processing}>
							🗑️ {$tr('ipGeo.buttons.clear')}
						</button>
					</div>
				{/if}
			</div>
		</div>

		<div class="result-section">
			<div class="section-card">
				{#if activeTab === 'single'}
					<h2 class="section-title">{$tr('ipGeo.result.title')}</h2>
					{#if error}
						<div class="error-card">
							<div class="error-icon">⚠️</div>
							<div class="error-content">
								<h3>{$tr('ipGeo.result.error')}</h3>
								<p>{error}</p>
							</div>
						</div>
					{:else if result}
						<div class="result-content">
							<div class="geo-header">
								<span class="country-flag">{getCountryFlag(result.country_code)}</span>
								<div class="geo-title">
									<h3>{result.ip}</h3>
									<p>{result.city}, {result.region}, {result.country}</p>
								</div>
							</div>
							<div class="geo-details">
								<div class="detail-item">
									<span class="detail-label">🌍 {$tr('ipGeo.result.country')}</span>
									<span class="detail-value">{result.country} ({result.country_code})</span>
								</div>
								<div class="detail-item">
									<span class="detail-label">🏙️ {$tr('ipGeo.result.region')}</span>
									<span class="detail-value">{result.region}</span>
								</div>
								<div class="detail-item">
									<span class="detail-label">📍 {$tr('ipGeo.result.city')}</span>
									<span class="detail-value">{result.city}</span>
								</div>
								<div class="detail-item">
									<span class="detail-label">🌐 {$tr('ipGeo.result.coordinates')}</span>
									<span class="detail-value">{result.latitude}, {result.longitude}</span>
								</div>
								<div class="detail-item">
									<span class="detail-label">📡 {$tr('ipGeo.result.isp')}</span>
									<span class="detail-value">{result.isp}</span>
								</div>
								<div class="detail-item">
									<span class="detail-label">🏢 {$tr('ipGeo.result.org')}</span>
									<span class="detail-value">{result.org}</span>
								</div>
								<div class="detail-item">
									<span class="detail-label">🕐 {$tr('ipGeo.result.timezone')}</span>
									<span class="detail-value">{result.timezone}</span>
								</div>
							</div>
							<div class="map-link">
								<a href="https://www.openstreetmap.org/?mlat={result.latitude}&mlon={result.longitude}#map=12/{result.latitude}/{result.longitude}" target="_blank" rel="noopener noreferrer">
									🗺️ {$tr('ipGeo.result.viewMap')}
								</a>
							</div>
						</div>
					{:else}
						<div class="empty-state">
							<div class="empty-icon">🗺️</div>
							<p>{$tr('ipGeo.result.empty')}</p>
							<p class="empty-hint">{$tr('ipGeo.result.hint')}</p>
						</div>
					{/if}
				{:else}
					<h2 class="section-title">{$tr('ipGeo.batch.resultTitle')}</h2>
					{#if batchResults.length > 0}
						<div class="batch-stats">
							<div class="stat-item">
								<span class="stat-label">{$tr('ipGeo.batch.total')}</span>
								<span class="stat-value">{batchResults.length}</span>
							</div>
							<div class="stat-item success">
								<span class="stat-label">{$tr('ipGeo.batch.success')}</span>
								<span class="stat-value">{successCount}</span>
							</div>
							<div class="stat-item failed">
								<span class="stat-label">{$tr('ipGeo.batch.failed')}</span>
								<span class="stat-value">{failedCount}</span>
							</div>
						</div>
						<div class="batch-results">
							{#each paginatedResults as item}
								<div class="batch-item {item.error ? 'error' : 'success'}">
									<div class="batch-item-header">
										<span class="batch-ip">{item.ip}</span>
										{#if item.result}
											<span class="country-flag-small">{getCountryFlag(item.result.country_code)}</span>
											<span class="batch-location">{item.result.city}, {item.result.country}</span>
										{:else}
											<span class="batch-error-text">❌ {item.error}</span>
										{/if}
									</div>
									{#if item.result}
										<div class="batch-item-details">
											<span>📡 {item.result.isp}</span>
											<span>🕐 {item.result.timezone}</span>
										</div>
									{/if}
								</div>
							{/each}
						</div>
						{#if totalPages > 1}
							<div class="pagination">
								<button class="pagination-btn" disabled={currentPage === 1} on:click={() => currentPage--}>
									←
								</button>
								<span class="pagination-info">{$tr('common.page')} {currentPage}/{totalPages}</span>
								<button class="pagination-btn" disabled={currentPage >= totalPages} on:click={() => currentPage++}>
									→
								</button>
							</div>
						{/if}
					{:else}
						<div class="empty-state">
							<div class="empty-icon">🗺️</div>
							<p>{$tr('ipGeo.result.empty')}</p>
							<p class="empty-hint">{$tr('ipGeo.batch.hint')}</p>
						</div>
					{/if}
				{/if}
			</div>
		</div>
	</div>
	{:else}
		<div class="history-section">
			<div class="section-card">
				<div class="history-header">
					<h2 class="section-title">📋 {$tr('ipGeo.history.title')}</h2>
					<div class="history-actions">
						<button class="btn btn-secondary" on:click={loadHistory} disabled={loadingHistory}>
							🔄 {$tr('ipGeo.history.refresh')}
						</button>
						<button class="btn btn-danger" on:click={clearAllHistory} disabled={loadingHistory || history.length === 0}>
							🗑️ {$tr('ipGeo.history.clearAll')}
						</button>
					</div>
				</div>

				{#if historyError}
					<div class="error-card">
						<div class="error-icon">⚠️</div>
						<div class="error-content">
							<p>{historyError}</p>
						</div>
					</div>
				{/if}

				{#if loadingHistory}
					<div class="loading-state">
						<div class="spinner"></div>
						<p>{$tr('common.loading')}</p>
					</div>
				{:else if history.length === 0}
					<div class="empty-state">
						<div class="empty-icon">📋</div>
						<p>{$tr('ipGeo.history.empty')}</p>
						<p class="empty-hint">{$tr('ipGeo.history.hint')}</p>
					</div>
				{:else}
					<div class="history-table-wrapper">
						<table class="history-table">
							<thead>
								<tr>
									<th>{$tr('ipGeo.history.table.ip')}</th>
									<th>{$tr('ipGeo.history.table.location')}</th>
									<th>{$tr('ipGeo.history.table.isp')}</th>
									<th>{$tr('ipGeo.history.table.time')}</th>
									<th>{$tr('ipGeo.history.table.actions')}</th>
								</tr>
							</thead>
							<tbody>
								{#each history as item}
									<tr>
										<td class="ip-cell"><code>{item.ip}</code></td>
										<td>
											<span class="country-flag-small">{getCountryFlag(item.country_code)}</span>
											{item.city}, {item.country}
										</td>
										<td class="isp-cell">{item.isp}</td>
										<td class="time-cell">{formatDateTime(item.created_at)}</td>
										<td class="actions-cell">
											<button class="action-link" on:click={() => requeryFromHistory(item)} title={$tr('ipGeo.history.requery')}>🔄</button>
											<button class="action-link" on:click={() => viewHistoryDetail(item)} title={$tr('ipGeo.history.viewDetail')}>👁️</button>
											<button class="action-link delete" on:click={() => deleteHistoryItem(item.id)} title={$tr('ipGeo.history.deleteRecord')}>🗑️</button>
										</td>
									</tr>
								{/each}
							</tbody>
						</table>
					</div>

					<div class="history-pagination">
						<button class="pagination-btn" disabled={historyCurrentPage === 1} on:click={() => { historyCurrentPage--; loadHistory(); }}>
							← {$tr('common.previous')}
						</button>
						<span class="pagination-info">{historyCurrentPage}</span>
						<button class="pagination-btn" disabled={history.length < historyPageSize} on:click={() => { historyCurrentPage++; loadHistory(); }}>
							{$tr('common.next')} →
						</button>
					</div>
				{/if}
			</div>
		</div>
	{/if}
</div>

{#if showTargetSelector}
	<div class="modal-overlay" on:click={() => showTargetSelector = false} on:keydown={(e) => e.key === 'Escape' && (showTargetSelector = false)}>
		<div class="modal-content target-selector-modal" on:click|stopPropagation on:keydown|stopPropagation>
			<div class="modal-header">
				<h2>🎯 {$tr('ipGeo.batch.targetSelector.title')}</h2>
				<button class="modal-close" on:click={() => showTargetSelector = false}>✕</button>
			</div>
			<div class="modal-body">
				<div class="target-search">
					<input type="text" bind:value={targetSearchQuery} placeholder={$tr('ipGeo.batch.targetSelector.searchPlaceholder')} />
				</div>
				{#if loadingTargets}
					<div class="loading-message">⏳ {$tr('ipGeo.batch.targetSelector.loading')}</div>
				{:else if filteredTargets.length === 0}
					<div class="empty-message">{$tr('ipGeo.batch.targetSelector.noTargets')}</div>
				{:else}
					<div class="target-list">
						{#each filteredTargets as t (t.id)}
							<div
								class="target-item {selectedTargets.findIndex(st => st.id === t.id) >= 0 ? 'selected' : ''}"
								on:click={() => toggleTargetSelection(t)}
								role="button"
								tabindex="0"
								on:keydown={(e) => e.key === 'Enter' && toggleTargetSelection(t)}
							>
								<div class="target-info">
									<div class="target-name">{t.name}</div>
									<div class="target-value">{t.target_value}</div>
								</div>
								<div class="target-checkbox">
									{#if selectedTargets.findIndex(st => st.id === t.id) >= 0}✓{/if}
								</div>
							</div>
						{/each}
					</div>
				{/if}
			</div>
			<div class="modal-footer">
				<div class="selection-info">{$tr('ipGeo.batch.targetSelector.selectedCount', { count: selectedTargets.length })}</div>
				<div class="modal-actions">
					<button class="btn-cancel" on:click={() => showTargetSelector = false}>{$tr('common.cancel')}</button>
					<button class="btn-confirm" on:click={confirmTargetSelection} disabled={selectedTargets.length === 0}>{$tr('common.confirm')}</button>
				</div>
			</div>
		</div>
	</div>
{/if}

{#if showHistoryDetail && selectedHistoryItem}
	<div class="modal-overlay" on:click={() => showHistoryDetail = false} on:keydown={(e) => e.key === 'Escape' && (showHistoryDetail = false)}>
		<div class="modal-content" on:click|stopPropagation on:keydown|stopPropagation>
			<div class="modal-header">
				<h2>{$tr('ipGeo.history.detailTitle')}</h2>
				<button class="modal-close" on:click={() => showHistoryDetail = false}>✕</button>
			</div>
			<div class="modal-body">
				<div class="detail-section">
					<div class="detail-label">{$tr('ipGeo.history.table.ip')}</div>
					<code class="detail-value ip-detail-value">{selectedHistoryItem.ip}</code>
				</div>
				<div class="detail-section">
					<div class="detail-label">{$tr('ipGeo.result.country')}</div>
					<div class="detail-value">{getCountryFlag(selectedHistoryItem.country_code)} {selectedHistoryItem.country} ({selectedHistoryItem.country_code})</div>
				</div>
				<div class="detail-section">
					<div class="detail-label">{$tr('ipGeo.result.region')}</div>
					<div class="detail-value">{selectedHistoryItem.region}</div>
				</div>
				<div class="detail-section">
					<div class="detail-label">{$tr('ipGeo.result.city')}</div>
					<div class="detail-value">{selectedHistoryItem.city}</div>
				</div>
				<div class="detail-section">
					<div class="detail-label">{$tr('ipGeo.result.coordinates')}</div>
					<div class="detail-value">{selectedHistoryItem.latitude}, {selectedHistoryItem.longitude}</div>
				</div>
				<div class="detail-section">
					<div class="detail-label">{$tr('ipGeo.result.isp')}</div>
					<div class="detail-value">{selectedHistoryItem.isp}</div>
				</div>
				<div class="detail-section">
					<div class="detail-label">{$tr('ipGeo.result.org')}</div>
					<div class="detail-value">{selectedHistoryItem.org}</div>
				</div>
				<div class="detail-section">
					<div class="detail-label">{$tr('ipGeo.result.timezone')}</div>
					<div class="detail-value">{selectedHistoryItem.timezone}</div>
				</div>
				<div class="detail-section">
					<div class="detail-label">{$tr('ipGeo.history.table.time')}</div>
					<div class="detail-value">{formatDateTime(selectedHistoryItem.created_at)}</div>
				</div>
				<div class="detail-actions">
					<button class="btn btn-primary" on:click={() => { showHistoryDetail = false; requeryFromHistory(selectedHistoryItem); }}>
						🔄 {$tr('ipGeo.history.requery')}
					</button>
					<a class="btn btn-secondary map-link-btn" href="https://www.openstreetmap.org/?mlat={selectedHistoryItem.latitude}&mlon={selectedHistoryItem.longitude}#map=12/{selectedHistoryItem.latitude}/{selectedHistoryItem.longitude}" target="_blank" rel="noopener noreferrer">
						🗺️ {$tr('ipGeo.result.viewMap')}
					</a>
				</div>
			</div>
		</div>
	</div>
{/if}

{#if showConfirmDialog}
	<div class="modal-overlay" on:click={cancelConfirm} on:keydown={(e) => e.key === 'Escape' && cancelConfirm()}>
		<div class="modal-content confirm-modal" on:click|stopPropagation on:keydown|stopPropagation>
			<div class="modal-header">
				<h2>⚠️ {confirmDialogTitle}</h2>
				<button class="modal-close" on:click={cancelConfirm}>✕</button>
			</div>
			<div class="modal-body">
				<p>{confirmDialogMessage}</p>
			</div>
			<div class="modal-footer">
				<button class="btn-cancel" on:click={cancelConfirm}>{$tr('common.cancel')}</button>
				<button class="btn-danger" on:click={executeConfirmAction}>{$tr('common.confirm')}</button>
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
				<h2>{$tr('ipGeo.helpModal.title')}</h2>
				<button class="modal-close" on:click={() => showHelpModal = false}>✕</button>
			</div>
			<div class="modal-body">
				<section class="help-section">
					<h3>{$tr('ipGeo.helpModal.overview')}</h3>
					<p>{$tr('ipGeo.helpModal.overviewText')}</p>
				</section>
				<section class="help-section">
					<h3>{$tr('ipGeo.helpModal.howToUse')}</h3>
					<ol>
						<li>{$tr('ipGeo.helpModal.step1')}</li>
						<li>{$tr('ipGeo.helpModal.step2')}</li>
						<li>{$tr('ipGeo.helpModal.step3')}</li>
						<li>{$tr('ipGeo.helpModal.step4')}</li>
					</ol>
				</section>
				<section class="help-section">
					<h3>{$tr('ipGeo.helpModal.batchTitle')}</h3>
					<p>{$tr('ipGeo.helpModal.batchDesc')}</p>
				</section>
				<section class="help-section">
					<h3>{$tr('ipGeo.helpModal.resultTitle')}</h3>
					<ul class="tip-list">
						<li>{$tr('ipGeo.helpModal.resultFeatures.country')}</li>
						<li>{$tr('ipGeo.helpModal.resultFeatures.region')}</li>
						<li>{$tr('ipGeo.helpModal.resultFeatures.city')}</li>
						<li>{$tr('ipGeo.helpModal.resultFeatures.coordinates')}</li>
						<li>{$tr('ipGeo.helpModal.resultFeatures.isp')}</li>
						<li>{$tr('ipGeo.helpModal.resultFeatures.org')}</li>
						<li>{$tr('ipGeo.helpModal.resultFeatures.timezone')}</li>
					</ul>
				</section>
				<section class="help-section">
					<h3>{$tr('ipGeo.helpModal.tips')}</h3>
					<ul class="tip-list">
						<li>{$tr('ipGeo.helpModal.tip1')}</li>
						<li>{$tr('ipGeo.helpModal.tip2')}</li>
						<li>{$tr('ipGeo.helpModal.tip3')}</li>
						<li>{$tr('ipGeo.helpModal.tip4')}</li>
					</ul>
				</section>
				<section class="help-section">
					<h3>{$tr('ipGeo.helpModal.warningTitle')}</h3>
					<ul class="tip-list">
						<li>{$tr('ipGeo.helpModal.warnings.warning1')}</li>
						<li>{$tr('ipGeo.helpModal.warnings.warning2')}</li>
						<li>{$tr('ipGeo.helpModal.warnings.warning3')}</li>
						<li>{$tr('ipGeo.helpModal.warnings.warning4')}</li>
					</ul>
				</section>
			</div>
		</div>
	</div>
{/if}

<style>
	.ip-geo-page {
		padding: 2rem;
		max-width: 1400px;
		margin: 0 auto;
	}

	.page-header {
		display: flex;
		justify-content: space-between;
		align-items: flex-start;
		margin-bottom: 2rem;
	}

	.header-left {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
	}

	.back-link {
		color: var(--text-muted);
		text-decoration: none;
		font-size: 0.875rem;
		transition: color 0.2s;
	}

	.back-link:hover {
		color: var(--primary);
	}

	.page-title {
		font-size: 1.75rem;
		font-weight: 700;
		background: linear-gradient(135deg, #10b981, #06b6d4);
		-webkit-background-clip: text;
		-webkit-text-fill-color: transparent;
		background-clip: text;
	}

	.page-subtitle {
		color: var(--text-muted);
		font-size: 0.95rem;
	}

	.help-button {
		padding: 0.5rem 1rem;
		background: rgba(16, 185, 129, 0.1);
		border: 1px solid rgba(16, 185, 129, 0.3);
		border-radius: 0.5rem;
		color: #10b981;
		cursor: pointer;
		font-size: 0.875rem;
		transition: all 0.2s;
	}

	.help-button:hover {
		background: rgba(16, 185, 129, 0.2);
	}

	.tabs {
		display: flex;
		gap: 0;
		margin-bottom: 1.5rem;
		background: rgba(255, 255, 255, 0.03);
		border: 1px solid rgba(255, 255, 255, 0.08);
		border-radius: 0.5rem;
		overflow: hidden;
	}

	.tab-button {
		flex: 1;
		padding: 0.75rem 1.5rem;
		background: transparent;
		border: none;
		color: var(--text-muted);
		cursor: pointer;
		font-size: 0.875rem;
		font-weight: 500;
		transition: all 0.2s;
	}

	.tab-button.active {
		background: rgba(16, 185, 129, 0.1);
		color: #10b981;
	}

	.tab-button:hover:not(.active) {
		background: rgba(255, 255, 255, 0.05);
	}

	.content-grid {
		display: grid;
		grid-template-columns: 1fr 1fr;
		gap: 2rem;
	}

	.section-card {
		background: rgba(255, 255, 255, 0.03);
		border: 1px solid rgba(255, 255, 255, 0.08);
		border-radius: 1rem;
		padding: 1.5rem;
	}

	.section-title {
		font-size: 1.1rem;
		font-weight: 600;
		margin-bottom: 1.25rem;
		color: var(--text-primary);
	}

	.form-group {
		margin-bottom: 1.25rem;
	}

	.form-label {
		display: block;
		margin-bottom: 0.5rem;
		font-size: 0.875rem;
		font-weight: 500;
		color: var(--text-secondary);
	}

	.input-row {
		display: flex;
		gap: 0.5rem;
	}

	.form-input {
		flex: 1;
		padding: 0.75rem;
		background: rgba(0, 0, 0, 0.3);
		border: 1px solid rgba(255, 255, 255, 0.1);
		border-radius: 0.5rem;
		color: var(--text-primary);
		font-family: 'JetBrains Mono', monospace;
		font-size: 0.875rem;
		transition: border-color 0.2s;
	}

	.form-input:focus {
		outline: none;
		border-color: #10b981;
	}

	.form-textarea {
		width: 100%;
		padding: 0.75rem;
		background: rgba(0, 0, 0, 0.3);
		border: 1px solid rgba(255, 255, 255, 0.1);
		border-radius: 0.5rem;
		color: var(--text-primary);
		font-family: 'JetBrains Mono', monospace;
		font-size: 0.875rem;
		resize: vertical;
		transition: border-color 0.2s;
	}

	.form-textarea:focus {
		outline: none;
		border-color: #10b981;
	}

	.textarea-actions {
		display: flex;
		gap: 0.5rem;
		margin-top: 0.5rem;
	}

	.action-btn {
		padding: 0.4rem 0.75rem;
		background: rgba(255, 255, 255, 0.05);
		border: 1px solid rgba(255, 255, 255, 0.1);
		border-radius: 0.375rem;
		color: var(--text-secondary);
		cursor: pointer;
		font-size: 0.8rem;
		transition: all 0.2s;
	}

	.action-btn:hover:not(:disabled) {
		background: rgba(255, 255, 255, 0.1);
	}

	.action-btn:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

	.input-hint {
		display: block;
		font-size: 0.8rem;
		color: var(--text-muted);
		margin-top: 0.25rem;
		margin-bottom: 1rem;
	}

	.button-group {
		display: flex;
		gap: 0.75rem;
	}

	.btn {
		padding: 0.75rem 1.5rem;
		border-radius: 0.5rem;
		font-size: 0.875rem;
		font-weight: 500;
		cursor: pointer;
		transition: all 0.2s;
		border: none;
	}

	.btn:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

	.btn-primary {
		background: linear-gradient(135deg, #10b981, #06b6d4);
		color: white;
	}

	.btn-primary:hover:not(:disabled) {
		transform: translateY(-1px);
		box-shadow: 0 4px 12px rgba(16, 185, 129, 0.4);
	}

	.btn-secondary {
		background: rgba(255, 255, 255, 0.05);
		border: 1px solid rgba(255, 255, 255, 0.1);
		color: var(--text-secondary);
	}

	.btn-secondary:hover:not(:disabled) {
		background: rgba(255, 255, 255, 0.1);
	}

	.btn-danger {
		background: rgba(239, 68, 68, 0.1);
		border: 1px solid rgba(239, 68, 68, 0.3);
		color: #ef4444;
		padding: 0.5rem 1rem;
		border-radius: 0.5rem;
		cursor: pointer;
		font-size: 0.85rem;
	}

	.btn-danger:hover:not(:disabled) {
		background: rgba(239, 68, 68, 0.2);
	}

	.btn-danger:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

	.error-card {
		display: flex;
		align-items: flex-start;
		gap: 1rem;
		padding: 1rem;
		background: rgba(239, 68, 68, 0.1);
		border: 1px solid rgba(239, 68, 68, 0.3);
		border-radius: 0.5rem;
	}

	.error-icon {
		font-size: 1.5rem;
	}

	.error-content h3 {
		color: #ef4444;
		font-size: 0.95rem;
		margin-bottom: 0.25rem;
	}

	.error-content p {
		color: var(--text-muted);
		font-size: 0.85rem;
	}

	.result-content {
		display: flex;
		flex-direction: column;
		gap: 1rem;
	}

	.geo-header {
		display: flex;
		align-items: center;
		gap: 1rem;
		padding: 1rem;
		background: rgba(16, 185, 129, 0.05);
		border: 1px solid rgba(16, 185, 129, 0.2);
		border-radius: 0.75rem;
	}

	.country-flag {
		font-size: 2.5rem;
	}

	.country-flag-small {
		font-size: 1.1rem;
		margin-right: 0.25rem;
	}

	.geo-title h3 {
		font-size: 1.1rem;
		font-weight: 600;
		color: var(--text-primary);
		font-family: 'JetBrains Mono', monospace;
	}

	.geo-title p {
		font-size: 0.9rem;
		color: var(--text-muted);
	}

	.geo-details {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
	}

	.detail-item {
		display: flex;
		justify-content: space-between;
		align-items: center;
		padding: 0.6rem 0.75rem;
		background: rgba(255, 255, 255, 0.02);
		border-radius: 0.375rem;
	}

	.detail-item:nth-child(odd) {
		background: rgba(255, 255, 255, 0.04);
	}

	.detail-label {
		font-size: 0.85rem;
		color: var(--text-muted);
	}

	.detail-value {
		font-size: 0.85rem;
		color: var(--text-primary);
		font-weight: 500;
		text-align: right;
		max-width: 60%;
		word-break: break-word;
	}

	.map-link {
		text-align: center;
		padding-top: 0.5rem;
	}

	.map-link a {
		color: #10b981;
		text-decoration: none;
		font-size: 0.9rem;
		transition: color 0.2s;
	}

	.map-link a:hover {
		color: #06b6d4;
		text-decoration: underline;
	}

	.empty-state {
		text-align: center;
		padding: 3rem 1rem;
	}

	.empty-icon {
		font-size: 3rem;
		margin-bottom: 1rem;
		opacity: 0.5;
	}

	.empty-state p {
		color: var(--text-muted);
		font-size: 0.95rem;
	}

	.empty-hint {
		font-size: 0.85rem !important;
		margin-top: 0.5rem;
	}

	.batch-stats {
		display: flex;
		gap: 1rem;
		margin-bottom: 1rem;
	}

	.stat-item {
		padding: 0.5rem 1rem;
		background: rgba(255, 255, 255, 0.05);
		border-radius: 0.5rem;
		display: flex;
		align-items: center;
		gap: 0.5rem;
	}

	.stat-item.success {
		background: rgba(16, 185, 129, 0.1);
		color: #10b981;
	}

	.stat-item.failed {
		background: rgba(239, 68, 68, 0.1);
		color: #ef4444;
	}

	.stat-label {
		font-size: 0.8rem;
		color: var(--text-muted);
	}

	.stat-value {
		font-size: 1rem;
		font-weight: 600;
	}

	.batch-results {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
		max-height: 400px;
		overflow-y: auto;
	}

	.batch-item {
		padding: 0.75rem;
		border-radius: 0.5rem;
		border: 1px solid rgba(255, 255, 255, 0.05);
	}

	.batch-item.success {
		background: rgba(16, 185, 129, 0.03);
		border-color: rgba(16, 185, 129, 0.1);
	}

	.batch-item.error {
		background: rgba(239, 68, 68, 0.03);
		border-color: rgba(239, 68, 68, 0.1);
	}

	.batch-item-header {
		display: flex;
		align-items: center;
		gap: 0.5rem;
	}

	.batch-ip {
		font-family: 'JetBrains Mono', monospace;
		font-size: 0.85rem;
		color: #10b981;
		font-weight: 600;
	}

	.batch-location {
		font-size: 0.85rem;
		color: var(--text-secondary);
	}

	.batch-error-text {
		font-size: 0.85rem;
		color: #ef4444;
	}

	.batch-item-details {
		display: flex;
		gap: 1rem;
		margin-top: 0.5rem;
		font-size: 0.8rem;
		color: var(--text-muted);
	}

	.pagination {
		display: flex;
		align-items: center;
		justify-content: center;
		gap: 1rem;
		margin-top: 1rem;
	}

	.pagination-btn {
		padding: 0.4rem 0.75rem;
		background: rgba(255, 255, 255, 0.05);
		border: 1px solid rgba(255, 255, 255, 0.1);
		border-radius: 0.375rem;
		color: var(--text-secondary);
		cursor: pointer;
		font-size: 0.85rem;
	}

	.pagination-btn:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

	.pagination-info {
		font-size: 0.85rem;
		color: var(--text-muted);
	}

	.history-section {
		margin-top: 0;
	}

	.history-header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		margin-bottom: 1rem;
	}

	.history-actions {
		display: flex;
		gap: 0.5rem;
	}

	.loading-state {
		text-align: center;
		padding: 3rem 1rem;
	}

	.spinner {
		width: 40px;
		height: 40px;
		border: 3px solid rgba(16, 185, 129, 0.2);
		border-top-color: #10b981;
		border-radius: 50%;
		animation: spin 0.8s linear infinite;
		margin: 0 auto 1rem;
	}

	@keyframes spin {
		to { transform: rotate(360deg); }
	}

	.history-table-wrapper {
		overflow-x: auto;
	}

	.history-table {
		width: 100%;
		border-collapse: collapse;
		font-size: 0.85rem;
	}

	.history-table th {
		padding: 0.75rem 1rem;
		text-align: left;
		font-weight: 600;
		color: var(--text-secondary);
		border-bottom: 1px solid rgba(255, 255, 255, 0.1);
		font-size: 0.8rem;
		text-transform: uppercase;
		letter-spacing: 0.05em;
	}

	.history-table td {
		padding: 0.75rem 1rem;
		border-bottom: 1px solid rgba(255, 255, 255, 0.05);
		color: var(--text-primary);
	}

	.history-table tr:hover {
		background: rgba(255, 255, 255, 0.02);
	}

	.ip-cell code {
		font-family: 'JetBrains Mono', monospace;
		font-size: 0.8rem;
		color: #10b981;
		word-break: break-all;
	}

	.isp-cell {
		font-size: 0.8rem;
		color: var(--text-muted);
		max-width: 200px;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.time-cell {
		font-size: 0.8rem;
		color: var(--text-muted);
		white-space: nowrap;
	}

	.actions-cell {
		white-space: nowrap;
	}

	.action-link {
		background: none;
		border: none;
		cursor: pointer;
		font-size: 1rem;
		padding: 0.2rem 0.4rem;
		border-radius: 0.25rem;
		transition: background 0.2s;
	}

	.action-link:hover {
		background: rgba(255, 255, 255, 0.1);
	}

	.action-link.delete:hover {
		background: rgba(239, 68, 68, 0.2);
	}

	.history-pagination {
		display: flex;
		align-items: center;
		justify-content: center;
		gap: 1rem;
		margin-top: 1rem;
	}

	.detail-section {
		margin-bottom: 1.5rem;
	}

	.detail-label {
		font-size: 0.8rem;
		color: var(--text-muted);
		text-transform: uppercase;
		letter-spacing: 0.05em;
		margin-bottom: 0.5rem;
	}

	.detail-value {
		font-size: 0.9rem;
		color: var(--text-primary);
	}

	.ip-detail-value {
		font-family: 'JetBrains Mono', monospace;
		font-size: 0.85rem;
		color: #10b981;
		word-break: break-all;
		background: rgba(0, 0, 0, 0.3);
		padding: 0.5rem 0.75rem;
		border-radius: 0.375rem;
	}

	.detail-actions {
		display: flex;
		gap: 0.75rem;
		margin-top: 1.5rem;
		padding-top: 1rem;
		border-top: 1px solid rgba(255, 255, 255, 0.08);
	}

	.map-link-btn {
		text-decoration: none;
		display: inline-flex;
		align-items: center;
		gap: 0.25rem;
	}

	.modal-overlay {
		position: fixed;
		inset: 0;
		background: rgba(0, 0, 0, 0.7);
		display: flex;
		align-items: center;
		justify-content: center;
		z-index: 1000;
	}

	.modal-content {
		background: #1a1a2e;
		border: 1px solid rgba(16, 185, 129, 0.3);
		border-radius: 1rem;
		width: 90%;
		max-width: 700px;
		max-height: 80vh;
		overflow-y: auto;
	}

	.target-selector-modal {
		max-width: 500px;
	}

	.modal-header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		padding: 1.25rem 1.5rem;
		border-bottom: 1px solid rgba(255, 255, 255, 0.1);
	}

	.modal-header h2 {
		font-size: 1.1rem;
		font-weight: 600;
	}

	.modal-close {
		background: none;
		border: none;
		color: var(--text-muted);
		font-size: 1.25rem;
		cursor: pointer;
		padding: 0.25rem;
	}

	.modal-body {
		padding: 1.5rem;
	}

	.modal-footer {
		display: flex;
		justify-content: space-between;
		align-items: center;
		padding: 1rem 1.5rem;
		border-top: 1px solid rgba(255, 255, 255, 0.1);
	}

	.confirm-modal .modal-body p {
		color: var(--text-secondary);
		font-size: 0.95rem;
		line-height: 1.6;
	}

	.target-search input {
		width: 100%;
		padding: 0.6rem 0.75rem;
		background: rgba(0, 0, 0, 0.3);
		border: 1px solid rgba(255, 255, 255, 0.1);
		border-radius: 0.5rem;
		color: var(--text-primary);
		font-size: 0.875rem;
		margin-bottom: 1rem;
	}

	.target-search input:focus {
		outline: none;
		border-color: #10b981;
	}

	.target-list {
		max-height: 300px;
		overflow-y: auto;
	}

	.target-item {
		display: flex;
		justify-content: space-between;
		align-items: center;
		padding: 0.75rem;
		border-radius: 0.5rem;
		cursor: pointer;
		transition: background 0.2s;
	}

	.target-item:hover {
		background: rgba(255, 255, 255, 0.05);
	}

	.target-item.selected {
		background: rgba(16, 185, 129, 0.1);
		border: 1px solid rgba(16, 185, 129, 0.3);
	}

	.target-info {
		display: flex;
		flex-direction: column;
		gap: 0.2rem;
	}

	.target-name {
		font-size: 0.9rem;
		font-weight: 500;
		color: var(--text-primary);
	}

	.target-value {
		font-size: 0.8rem;
		color: var(--text-muted);
		font-family: 'JetBrains Mono', monospace;
	}

	.target-checkbox {
		font-size: 1rem;
		color: #10b981;
	}

	.loading-message, .empty-message {
		text-align: center;
		padding: 2rem;
		color: var(--text-muted);
	}

	.selection-info {
		font-size: 0.85rem;
		color: var(--text-muted);
	}

	.modal-actions {
		display: flex;
		gap: 0.5rem;
	}

	.btn-cancel {
		padding: 0.5rem 1rem;
		background: rgba(255, 255, 255, 0.05);
		border: 1px solid rgba(255, 255, 255, 0.1);
		border-radius: 0.375rem;
		color: var(--text-secondary);
		cursor: pointer;
		font-size: 0.85rem;
	}

	.btn-confirm {
		padding: 0.5rem 1rem;
		background: rgba(16, 185, 129, 0.2);
		border: 1px solid rgba(16, 185, 129, 0.4);
		border-radius: 0.375rem;
		color: #10b981;
		cursor: pointer;
		font-size: 0.85rem;
	}

	.btn-confirm:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

	.help-section {
		margin-bottom: 1.5rem;
	}

	.help-section h3 {
		font-size: 1rem;
		font-weight: 600;
		margin-bottom: 0.75rem;
		color: #10b981;
	}

	.help-section p {
		color: var(--text-muted);
		font-size: 0.9rem;
		line-height: 1.6;
	}

	.help-section ul, .help-section ol {
		padding-left: 1.5rem;
		color: var(--text-muted);
		font-size: 0.9rem;
		line-height: 1.8;
	}

	.help-section li {
		margin-bottom: 0.25rem;
	}

	@media (max-width: 768px) {
		.content-grid {
			grid-template-columns: 1fr;
		}
	}
</style>
