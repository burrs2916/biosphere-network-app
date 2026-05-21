<script lang="ts">
	import { tr } from '$lib/i18n';
	import { open } from '@tauri-apps/plugin-dialog';
	import { readFile } from '@tauri-apps/plugin-fs';

	interface SiteCheckResult {
		url: string;
		is_online: boolean;
		status_code: number | null;
		response_time_ms: number | null;
		title: string | null;
		server: string | null;
		content_type: string | null;
		content_length: number | null;
		redirect_url: string | null;
		is_redirect: boolean;
		dns_resolved: boolean;
		ssl_valid: boolean | null;
		ip_address: string | null;
		x_powered_by: string | null;
		x_frame_options: string | null;
		content_security_policy: string | null;
		strict_transport_security: string | null;
		x_content_type_options: string | null;
		x_xss_protection: string | null;
		referrer_policy: string | null;
		permissions_policy: string | null;
		cache_control: string | null;
		etag: string | null;
		issues: string[];
		summary: string;
	}

	interface BatchSiteCheckResult {
		url: string;
		result: SiteCheckResult | null;
		error: string | null;
	}

	let url = '';
	let timeout = 10;
	let result: SiteCheckResult | null = null;
	let batchResults: BatchSiteCheckResult[] = [];
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
	$: onlineCount = batchResults.filter(r => r.result?.is_online).length;
	$: offlineCount = batchResults.filter(r => r.result && !r.result.is_online).length;
	$: errorCount = batchResults.filter(r => r.error).length;
	$: filteredTargets = targetList.filter((t: any) =>
		!targetSearchQuery ||
		t.name?.toLowerCase().includes(targetSearchQuery.toLowerCase()) ||
		t.target_value?.toLowerCase().includes(targetSearchQuery.toLowerCase())
	);

	async function checkSite() {
		if (!url.trim()) {
			error = $tr('siteChecker.error.emptyInput');
			return;
		}

		processing = true;
		error = '';
		result = null;

		try {
			const { invoke } = await import('@tauri-apps/api/core');
			result = await invoke<SiteCheckResult>('check_site_command', {
				url: url.trim(),
				timeout: timeout !== 10 ? timeout : undefined,
				targetId: selectedTargetIds.length > 0 ? selectedTargetIds[0] : null,
			});

			if (result) {
				try {
					await invoke('save_site_check_record', {
						url: result.url,
						isOnline: result.is_online,
						statusCode: result.status_code,
						responseTimeMs: result.response_time_ms,
						title: result.title,
						server: result.server,
						dnsResolved: result.dns_resolved,
						sslValid: result.ssl_valid,
						isRedirect: result.is_redirect,
						summary: result.summary,
						result: JSON.stringify(result),
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

	async function batchCheck() {
		const urls = url
			.split(/[\n,;]+/)
			.map(u => u.trim())
			.filter(u => u.length > 0);

		if (urls.length === 0) {
			error = $tr('siteChecker.error.emptyInput');
			return;
		}

		processing = true;
		error = '';
		batchResults = [];

		try {
			const { invoke } = await import('@tauri-apps/api/core');
			for (const targetUrl of urls) {
				try {
					const r = await invoke<SiteCheckResult>('check_site_command', {
						url: targetUrl,
						timeout: timeout !== 10 ? timeout : undefined,
					});
					batchResults.push({ url: targetUrl, result: r, error: null });

					try {
						await invoke('save_site_check_record', {
							url: r.url,
							isOnline: r.is_online,
							statusCode: r.status_code,
							responseTimeMs: r.response_time_ms,
							title: r.title,
							server: r.server,
							dnsResolved: r.dns_resolved,
							sslValid: r.ssl_valid,
							isRedirect: r.is_redirect,
							summary: r.summary,
							result: JSON.stringify(r),
						});
					} catch (e) {
						console.error('Failed to save history:', e);
					}
				} catch (e: any) {
					batchResults.push({ url: targetUrl, result: null, error: e.toString() });
				}
			}
		} catch (e: any) {
			error = e.toString();
		} finally {
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
			const res = await invoke<{ targets: any[], total: number }>('target_manager', {
				action: 'list',
				page: 1,
				pageSize: 100,
			});
			targetList = res.targets || [];
		} catch (e) {
			targetList = [];
		} finally {
			loadingTargets = false;
		}
	}

	function toggleTargetSelection(t: any) {
		const index = selectedTargets.findIndex((st: any) => st.id === t.id);
		if (index >= 0) {
			selectedTargets.splice(index, 1);
			selectedTargets = selectedTargets;
		} else {
			selectedTargets = [...selectedTargets, t];
		}
	}

	function confirmTargetSelection() {
		if (selectedTargets.length > 0) {
			const targetValues = selectedTargets.map((t: any) => t.target_value).join('\n');
			url = url ? `${url}\n${targetValues}` : targetValues;
			selectedTargetIds = selectedTargets.map((t: any) => t.id).filter((id: number | null): id is number => id !== null);
		}
		showTargetSelector = false;
		selectedTargets = [];
	}

	async function importUrls() {
		try {
			const selected = await open({
				multiple: false,
				filters: [{ name: 'Text', extensions: ['txt', 'csv', 'list'] }],
			});
			if (selected) {
				const fileData = await readFile(selected as string);
				const content = new TextDecoder('utf-8').decode(fileData);
				const urls = content
					.split(/[\n,;]+/)
					.map(u => u.trim())
					.filter(u => u.length > 0);
				if (urls.length > 0) {
					url = url ? `${url}\n${urls.join('\n')}` : urls.join('\n');
				}
			}
		} catch (e) {
			console.error('Import failed:', e);
		}
	}

	function clearAll() {
		url = '';
		timeout = 10;
		result = null;
		batchResults = [];
		error = '';
	}

	function switchTab(tab: string) {
		activeTab = tab;
		error = '';
		result = null;
		batchResults = [];
	}

	function getStatusColor(code: number | null): string {
		if (code === null) return '#94a3b8';
		if (code >= 200 && code < 300) return '#22c55e';
		if (code >= 300 && code < 400) return '#3b82f6';
		if (code >= 400 && code < 500) return '#f97316';
		return '#ef4444';
	}

	function getResponseTimeColor(ms: number | null): string {
		if (ms === null) return '#94a3b8';
		if (ms < 200) return '#22c55e';
		if (ms < 500) return '#eab308';
		if (ms < 1000) return '#f97316';
		return '#ef4444';
	}

	async function loadHistory() {
		loadingHistory = true;
		historyError = '';

		try {
			const { invoke } = await import('@tauri-apps/api/core');
			history = await invoke('get_site_check_history', {
				limit: historyPageSize,
				offset: (historyCurrentPage - 1) * historyPageSize,
			});
		} catch (e) {
			historyError = `${$tr('siteChecker.history.messages.loadFailed')}: ${e}`;
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
			$tr('siteChecker.history.messages.deleteConfirm'),
			$tr('siteChecker.history.messages.deleteConfirmMessage'),
			async () => {
				try {
					const { invoke } = await import('@tauri-apps/api/core');
					await invoke('delete_site_check_record', { id });
					await loadHistory();
				} catch (e) {
					historyError = `${$tr('siteChecker.history.messages.deleteFailed')}: ${e}`;
				}
			}
		);
	}

	async function clearAllHistory() {
		showConfirm(
			$tr('siteChecker.history.messages.clearAllConfirm'),
			$tr('siteChecker.history.messages.clearAllConfirmMessage'),
			async () => {
				try {
					const { invoke } = await import('@tauri-apps/api/core');
					await invoke('clear_site_check_history');
					await loadHistory();
				} catch (e) {
					historyError = `${$tr('siteChecker.history.messages.clearFailed')}: ${e}`;
				}
			}
		);
	}

	function viewHistoryDetail(item: any) {
		try {
			selectedHistoryItem = JSON.parse(item.result);
		} catch {
			selectedHistoryItem = null;
		}
		showHistoryDetail = true;
	}

	function recheckFromHistory(item: any) {
		url = item.url;
		activeTab = 'single';
		result = null;
		batchResults = [];
		error = '';
		checkSite();
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

	function formatBytes(bytes: number | null): string {
		if (bytes === null) return '-';
		if (bytes < 1024) return `${bytes} B`;
		if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
		return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
	}
</script>

<div class="site-checker-page">
	<div class="page-header">
		<div class="header-left">
			<a href="/" class="back-link">{$tr('common.backToHome')}</a>
			<h1 class="page-title">🌐 {$tr('siteChecker.title')}</h1>
			<p class="page-subtitle">{$tr('siteChecker.subtitle')}</p>
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
			{$tr('siteChecker.tabs.single')}
		</button>
		<button
			class="tab-button {activeTab === 'batch' ? 'active' : ''}"
			on:click={() => switchTab('batch')}
		>
			{$tr('siteChecker.tabs.batch')}
		</button>
		<button
			class="tab-button {activeTab === 'history' ? 'active' : ''}"
			on:click={() => { activeTab = 'history'; loadHistory(); }}
		>
			{$tr('siteChecker.tabs.history')}
		</button>
	</div>

	{#if activeTab !== 'history'}
	<div class="content-grid">
		<div class="input-section">
			<div class="section-card">
				{#if activeTab === 'single'}
					<h2 class="section-title">{$tr('siteChecker.input.title')}</h2>
					<div class="form-group">
						<label class="form-label">{$tr('siteChecker.input.urlLabel')}</label>
						<input
							type="text"
							bind:value={url}
							placeholder={$tr('siteChecker.input.urlPlaceholder')}
							class="form-input"
							disabled={processing}
							on:keydown={(e) => e.key === 'Enter' && checkSite()}
						/>
					</div>
					<div class="form-group">
						<label class="form-label">{$tr('siteChecker.input.timeoutLabel')}</label>
						<input
							type="number"
							bind:value={timeout}
							placeholder="10"
							class="form-input"
							disabled={processing}
							min="1"
							max="60"
						/>
					</div>
					<div class="button-group">
						<button class="btn btn-primary" on:click={checkSite} disabled={processing || !url.trim()}>
							{#if processing}⏳ {$tr('siteChecker.buttons.checking')}{:else}🔍 {$tr('siteChecker.buttons.check')}{/if}
						</button>
						<button class="btn btn-secondary" on:click={clearAll} disabled={processing}>
							🗑️ {$tr('siteChecker.buttons.clear')}
						</button>
					</div>
				{:else}
					<h2 class="section-title">{$tr('siteChecker.batch.inputTitle')}</h2>
					<div class="form-group">
						<label class="form-label">{$tr('siteChecker.batch.inputLabel')}</label>
						<textarea
							bind:value={url}
							placeholder={$tr('siteChecker.batch.inputPlaceholder')}
							class="form-textarea"
							rows="8"
							disabled={processing}
						></textarea>
						<div class="textarea-actions">
							<button type="button" class="action-btn" on:click={openTargetSelectorModal} disabled={processing}>
								🎯 {$tr('siteChecker.batch.selectTarget')}
							</button>
							<button type="button" class="action-btn" on:click={importUrls} disabled={processing}>
								📥 {$tr('siteChecker.batch.import')}
							</button>
						</div>
					</div>
					<div class="form-group">
						<label class="form-label">{$tr('siteChecker.input.timeoutLabel')}</label>
						<input
							type="number"
							bind:value={timeout}
							placeholder="10"
							class="form-input"
							disabled={processing}
							min="1"
							max="60"
						/>
					</div>
					<div class="button-group">
						<button class="btn btn-primary" on:click={batchCheck} disabled={processing || !url.trim()}>
							{#if processing}⏳ {$tr('siteChecker.buttons.checking')}{:else}🔍 {$tr('siteChecker.batch.checkAll')}{/if}
						</button>
						<button class="btn btn-secondary" on:click={clearAll} disabled={processing}>
							🗑️ {$tr('siteChecker.buttons.clear')}
						</button>
					</div>
				{/if}
			</div>
		</div>

		<div class="result-section">
			<div class="section-card">
				{#if activeTab === 'single'}
					<h2 class="section-title">{$tr('siteChecker.result.title')}</h2>
					{#if error}
						<div class="error-card">
							<div class="error-icon">⚠️</div>
							<div class="error-content">
								<h3>{$tr('siteChecker.result.error')}</h3>
								<p>{error}</p>
							</div>
						</div>
					{:else if result}
						<div class="result-content">
							<div class="status-header">
								<div class="status-badge" class:online={result.is_online} class:offline={!result.is_online}>
									{#if result.is_online}✅{:else}❌{/if}
									<span class="status-text">{result.is_online ? $tr('siteChecker.result.online') : $tr('siteChecker.result.offline')}</span>
								</div>
								<div class="status-info">
									<h3>{result.url}</h3>
									<p class="status-summary">{result.summary}</p>
								</div>
							</div>

							<div class="site-details">
								<div class="detail-section">
									<h4>📊 {$tr('siteChecker.result.responseInfo')}</h4>
									<div class="detail-item">
										<span class="detail-label">{$tr('siteChecker.result.statusCode')}</span>
										<span class="detail-value" style="color: {getStatusColor(result.status_code)}">
											{result.status_code ?? '-'}
										</span>
									</div>
									<div class="detail-item">
										<span class="detail-label">{$tr('siteChecker.result.responseTime')}</span>
										<span class="detail-value" style="color: {getResponseTimeColor(result.response_time_ms)}">
											{result.response_time_ms ?? '-'} ms
										</span>
									</div>
									<div class="detail-item">
										<span class="detail-label">{$tr('siteChecker.result.contentType')}</span>
										<span class="detail-value">{result.content_type ?? '-'}</span>
									</div>
									<div class="detail-item">
										<span class="detail-label">{$tr('siteChecker.result.contentLength')}</span>
										<span class="detail-value">{formatBytes(result.content_length)}</span>
									</div>
									<div class="detail-item">
										<span class="detail-label">{$tr('siteChecker.result.server')}</span>
										<span class="detail-value">{result.server ?? '-'}</span>
									</div>
								</div>

								<div class="detail-section">
									<h4>🔗 {$tr('siteChecker.result.connectivityInfo')}</h4>
									<div class="detail-item">
										<span class="detail-label">{$tr('siteChecker.result.dnsResolved')}</span>
										<span class="detail-value" class:secure={result.dns_resolved} class:insecure={!result.dns_resolved}>
											{result.dns_resolved ? '✅ ' + $tr('siteChecker.result.yes') : '❌ ' + $tr('siteChecker.result.no')}
										</span>
									</div>
									{#if result.ip_address}
										<div class="detail-item">
											<span class="detail-label">{$tr('siteChecker.result.ipAddress')}</span>
											<span class="detail-value">{result.ip_address}</span>
										</div>
									{/if}
									{#if result.ssl_valid !== null}
										<div class="detail-item">
											<span class="detail-label">{$tr('siteChecker.result.sslValid')}</span>
											<span class="detail-value" class:secure={result.ssl_valid} class:insecure={!result.ssl_valid}>
												{result.ssl_valid ? '✅ ' + $tr('siteChecker.result.valid') : '❌ ' + $tr('siteChecker.result.invalid')}
											</span>
										</div>
									{/if}
									{#if result.is_redirect}
										<div class="detail-item">
											<span class="detail-label">{$tr('siteChecker.result.redirect')}</span>
											<span class="detail-value warning">⚠️ {result.redirect_url ?? '-'}</span>
										</div>
									{/if}
								</div>

								{#if result.x_powered_by || result.x_frame_options || result.content_security_policy || result.strict_transport_security || result.x_content_type_options || result.x_xss_protection || result.referrer_policy || result.permissions_policy || result.cache_control || result.etag}
									<div class="detail-section">
										<h4>🛡️ {$tr('siteChecker.result.securityHeaders')}</h4>
										{#if result.x_powered_by}
											<div class="detail-item">
												<span class="detail-label">X-Powered-By</span>
												<span class="detail-value warning">⚠️ {result.x_powered_by}</span>
											</div>
										{/if}
										{#if result.x_frame_options}
											<div class="detail-item">
												<span class="detail-label">X-Frame-Options</span>
												<span class="detail-value secure">✅ {result.x_frame_options}</span>
											</div>
										{/if}
										{#if result.content_security_policy}
											<div class="detail-item">
												<span class="detail-label">Content-Security-Policy</span>
												<span class="detail-value secure">✅ {result.content_security_policy}</span>
											</div>
										{/if}
										{#if result.strict_transport_security}
											<div class="detail-item">
												<span class="detail-label">Strict-Transport-Security</span>
												<span class="detail-value secure">✅ {result.strict_transport_security}</span>
											</div>
										{/if}
										{#if result.x_content_type_options}
											<div class="detail-item">
												<span class="detail-label">X-Content-Type-Options</span>
												<span class="detail-value secure">✅ {result.x_content_type_options}</span>
											</div>
										{/if}
										{#if result.x_xss_protection}
											<div class="detail-item">
												<span class="detail-label">X-XSS-Protection</span>
												<span class="detail-value">{result.x_xss_protection}</span>
											</div>
										{/if}
										{#if result.referrer_policy}
											<div class="detail-item">
												<span class="detail-label">Referrer-Policy</span>
												<span class="detail-value">{result.referrer_policy}</span>
											</div>
										{/if}
										{#if result.permissions_policy}
											<div class="detail-item">
												<span class="detail-label">Permissions-Policy</span>
												<span class="detail-value">{result.permissions_policy}</span>
											</div>
										{/if}
										{#if result.cache_control}
											<div class="detail-item">
												<span class="detail-label">Cache-Control</span>
												<span class="detail-value">{result.cache_control}</span>
											</div>
										{/if}
										{#if result.etag}
											<div class="detail-item">
												<span class="detail-label">ETag</span>
												<span class="detail-value">{result.etag}</span>
											</div>
										{/if}
									</div>
								{/if}

								{#if result.title}
									<div class="detail-section">
										<h4>📄 {$tr('siteChecker.result.pageInfo')}</h4>
										<div class="detail-item">
											<span class="detail-label">{$tr('siteChecker.result.pageTitle')}</span>
											<span class="detail-value">{result.title}</span>
										</div>
									</div>
								{/if}

								{#if result.issues.length > 0}
									<div class="detail-section issues">
										<h4>⚠️ {$tr('siteChecker.result.issues')} ({result.issues.length})</h4>
										{#each result.issues as issue}
											<div class="issue-item">⚠️ {issue}</div>
										{/each}
									</div>
								{/if}
							</div>
						</div>
					{:else}
						<div class="empty-state">
							<div class="empty-icon">🌐</div>
							<p>{$tr('siteChecker.result.empty')}</p>
							<p class="empty-hint">{$tr('siteChecker.result.hint')}</p>
						</div>
					{/if}
				{:else}
					<h2 class="section-title">{$tr('siteChecker.batch.resultTitle')}</h2>
					{#if batchResults.length > 0}
						<div class="batch-stats">
							<div class="stat-item">
								<span class="stat-label">{$tr('siteChecker.batch.total')}</span>
								<span class="stat-value">{batchResults.length}</span>
							</div>
							<div class="stat-item success">
								<span class="stat-label">{$tr('siteChecker.batch.online')}</span>
								<span class="stat-value">{onlineCount}</span>
							</div>
							<div class="stat-item failed">
								<span class="stat-label">{$tr('siteChecker.batch.offline')}</span>
								<span class="stat-value">{offlineCount}</span>
							</div>
							{#if errorCount > 0}
								<div class="stat-item error">
									<span class="stat-label">{$tr('siteChecker.batch.error')}</span>
									<span class="stat-value">{errorCount}</span>
								</div>
							{/if}
						</div>
						<div class="batch-results">
							{#each paginatedResults as item}
								<div class="batch-item {item.result?.is_online ? 'online' : 'offline'}">
									<div class="batch-item-header">
										<span class="batch-status">{item.result?.is_online ? '🟢' : '🔴'}</span>
										<span class="batch-url">{item.url}</span>
										{#if item.result}
											<span class="batch-status-code" style="color: {getStatusColor(item.result.status_code)}">
												{item.result.status_code ?? '-'}
											</span>
											<span class="batch-time" style="color: {getResponseTimeColor(item.result.response_time_ms)}">
												{item.result.response_time_ms ?? '-'}ms
											</span>
										{:else}
											<span class="batch-error-text">❌ {item.error}</span>
										{/if}
									</div>
									{#if item.result}
										<div class="batch-item-details">
											{#if item.result.title}<span>📄 {item.result.title}</span>{/if}
											{#if item.result.server}<span>🖥️ {item.result.server}</span>{/if}
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
							<div class="empty-icon">🌐</div>
							<p>{$tr('siteChecker.result.empty')}</p>
							<p class="empty-hint">{$tr('siteChecker.batch.hint')}</p>
						</div>
					{/if}
				{/if}
			</div>
		</div>
	</div>
	{/if}

	{#if activeTab === 'history'}
		<div class="history-section">
			<div class="section-card">
				<div class="history-header">
					<h2 class="section-title">📋 {$tr('siteChecker.history.title')}</h2>
					<div class="history-actions">
						<button class="btn btn-secondary" on:click={loadHistory} disabled={loadingHistory}>
							🔄 {$tr('siteChecker.history.refresh')}
						</button>
						<button class="btn btn-danger" on:click={clearAllHistory} disabled={loadingHistory || history.length === 0}>
							🗑️ {$tr('siteChecker.history.clearAll')}
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
						<p>{$tr('siteChecker.history.empty')}</p>
						<p class="empty-hint">{$tr('siteChecker.history.hint')}</p>
					</div>
				{:else}
					<div class="history-table-wrapper">
						<table class="history-table">
							<thead>
								<tr>
									<th>{$tr('siteChecker.history.table.url')}</th>
									<th>{$tr('siteChecker.history.table.status')}</th>
									<th>{$tr('siteChecker.history.table.responseTime')}</th>
									<th>{$tr('siteChecker.history.table.title')}</th>
									<th>{$tr('siteChecker.history.table.time')}</th>
									<th>{$tr('siteChecker.history.table.actions')}</th>
								</tr>
							</thead>
							<tbody>
								{#each history as item}
									<tr>
										<td class="url-cell"><code>{item.url}</code></td>
										<td>
											{#if item.is_online}
												<span class="status-tag online">🟢 {item.status_code ?? '-'}</span>
											{:else}
												<span class="status-tag offline">🔴 {item.status_code ?? $tr('siteChecker.result.offline')}</span>
											{/if}
										</td>
										<td class="time-cell">{item.response_time_ms ?? '-'} ms</td>
										<td class="title-cell">{item.title ?? '-'}</td>
										<td class="time-cell">{formatDateTime(item.created_at)}</td>
										<td class="actions-cell">
											<button class="action-link" on:click={() => recheckFromHistory(item)} title={$tr('siteChecker.history.recheck')}>🔄</button>
											<button class="action-link" on:click={() => viewHistoryDetail(item)} title={$tr('siteChecker.history.viewDetail')}>👁️</button>
											<button class="action-link delete" on:click={() => deleteHistoryItem(item.id)} title={$tr('siteChecker.history.deleteRecord')}>🗑️</button>
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
				<h2>🎯 {$tr('siteChecker.batch.targetSelector.title')}</h2>
				<button class="modal-close" on:click={() => showTargetSelector = false}>✕</button>
			</div>
			<div class="modal-body">
				<div class="target-search">
					<input type="text" bind:value={targetSearchQuery} placeholder={$tr('siteChecker.batch.targetSelector.searchPlaceholder')} />
				</div>
				{#if loadingTargets}
					<div class="loading-message">⏳ {$tr('siteChecker.batch.targetSelector.loading')}</div>
				{:else if filteredTargets.length === 0}
					<div class="empty-message">{$tr('siteChecker.batch.targetSelector.noTargets')}</div>
				{:else}
					<div class="target-list">
						{#each filteredTargets as t (t.id)}
							<div
								class="target-item {selectedTargets.some((st: any) => st.id === t.id) ? 'selected' : ''}"
								on:click={() => toggleTargetSelection(t)}
							>
								<div class="target-checkbox">
									{#if selectedTargets.some((st: any) => st.id === t.id)}✓{/if}
								</div>
								<div class="target-info">
									<span class="target-name">{t.name}</span>
									<span class="target-value">{t.target_value}</span>
								</div>
							</div>
						{/each}
					</div>
				{/if}
			</div>
			<div class="modal-footer">
				<span class="selected-count">{$tr('siteChecker.batch.targetSelector.selectedCount', { count: selectedTargets.length })}</span>
				<div class="modal-actions">
					<button class="btn btn-secondary" on:click={() => showTargetSelector = false}>{$tr('common.cancel')}</button>
					<button class="btn btn-primary" on:click={confirmTargetSelection} disabled={selectedTargets.length === 0}>
						{$tr('common.confirm')}
					</button>
				</div>
			</div>
		</div>
	</div>
{/if}

{#if showHistoryDetail && selectedHistoryItem}
	<div class="modal-overlay" on:click={() => showHistoryDetail = false} on:keydown={(e) => e.key === 'Escape' && (showHistoryDetail = false)}>
		<div class="modal-content history-detail-modal" on:click|stopPropagation on:keydown|stopPropagation>
			<div class="modal-header">
				<h2>📋 {$tr('siteChecker.history.detailTitle')}</h2>
				<button class="modal-close" on:click={() => showHistoryDetail = false}>✕</button>
			</div>
			<div class="modal-body">
				<div class="status-header">
					<div class="status-badge" class:online={selectedHistoryItem.is_online} class:offline={!selectedHistoryItem.is_online}>
						{#if selectedHistoryItem.is_online}✅{:else}❌{/if}
						<span class="status-text">{selectedHistoryItem.is_online ? $tr('siteChecker.result.online') : $tr('siteChecker.result.offline')}</span>
					</div>
					<div class="status-info">
						<h3>{selectedHistoryItem.url}</h3>
						<p>{selectedHistoryItem.summary}</p>
					</div>
				</div>
				<div class="detail-section">
					<h4>📊 {$tr('siteChecker.result.responseInfo')}</h4>
					<div class="detail-item">
						<span class="detail-label">{$tr('siteChecker.result.statusCode')}</span>
						<span class="detail-value" style="color: {getStatusColor(selectedHistoryItem.status_code)}">{selectedHistoryItem.status_code ?? '-'}</span>
					</div>
					<div class="detail-item">
						<span class="detail-label">{$tr('siteChecker.result.responseTime')}</span>
						<span class="detail-value" style="color: {getResponseTimeColor(selectedHistoryItem.response_time_ms)}">{selectedHistoryItem.response_time_ms ?? '-'} ms</span>
					</div>
					{#if selectedHistoryItem.server}
						<div class="detail-item">
							<span class="detail-label">{$tr('siteChecker.result.server')}</span>
							<span class="detail-value">{selectedHistoryItem.server}</span>
						</div>
					{/if}
					{#if selectedHistoryItem.content_type}
						<div class="detail-item">
							<span class="detail-label">{$tr('siteChecker.result.contentType')}</span>
							<span class="detail-value">{selectedHistoryItem.content_type}</span>
						</div>
					{/if}
					{#if selectedHistoryItem.content_length}
						<div class="detail-item">
							<span class="detail-label">{$tr('siteChecker.result.contentLength')}</span>
							<span class="detail-value">{formatBytes(selectedHistoryItem.content_length)}</span>
						</div>
					{/if}
				</div>
				<div class="detail-section">
					<h4>🔗 {$tr('siteChecker.result.connectivityInfo')}</h4>
					<div class="detail-item">
						<span class="detail-label">{$tr('siteChecker.result.dnsResolved')}</span>
						<span class="detail-value" class:secure={selectedHistoryItem.dns_resolved} class:insecure={!selectedHistoryItem.dns_resolved}>
							{selectedHistoryItem.dns_resolved ? '✅ ' + $tr('siteChecker.result.yes') : '❌ ' + $tr('siteChecker.result.no')}
						</span>
					</div>
					{#if selectedHistoryItem.ip_address}
						<div class="detail-item">
							<span class="detail-label">{$tr('siteChecker.result.ipAddress')}</span>
							<span class="detail-value">{selectedHistoryItem.ip_address}</span>
						</div>
					{/if}
					{#if selectedHistoryItem.ssl_valid !== null && selectedHistoryItem.ssl_valid !== undefined}
						<div class="detail-item">
							<span class="detail-label">{$tr('siteChecker.result.sslValid')}</span>
							<span class="detail-value" class:secure={selectedHistoryItem.ssl_valid} class:insecure={!selectedHistoryItem.ssl_valid}>
								{selectedHistoryItem.ssl_valid ? '✅ ' + $tr('siteChecker.result.valid') : '❌ ' + $tr('siteChecker.result.invalid')}
							</span>
						</div>
					{/if}
					{#if selectedHistoryItem.is_redirect}
						<div class="detail-item">
							<span class="detail-label">{$tr('siteChecker.result.redirect')}</span>
							<span class="detail-value warning">⚠️ {selectedHistoryItem.redirect_url ?? '-'}</span>
						</div>
					{/if}
				</div>
				{#if selectedHistoryItem.x_powered_by || selectedHistoryItem.x_frame_options || selectedHistoryItem.content_security_policy || selectedHistoryItem.strict_transport_security || selectedHistoryItem.x_content_type_options || selectedHistoryItem.x_xss_protection || selectedHistoryItem.referrer_policy || selectedHistoryItem.permissions_policy || selectedHistoryItem.cache_control || selectedHistoryItem.etag}
					<div class="detail-section">
						<h4>🛡️ {$tr('siteChecker.result.securityHeaders')}</h4>
						{#if selectedHistoryItem.x_powered_by}
							<div class="detail-item">
								<span class="detail-label">X-Powered-By</span>
								<span class="detail-value warning">⚠️ {selectedHistoryItem.x_powered_by}</span>
							</div>
						{/if}
						{#if selectedHistoryItem.x_frame_options}
							<div class="detail-item">
								<span class="detail-label">X-Frame-Options</span>
								<span class="detail-value secure">✅ {selectedHistoryItem.x_frame_options}</span>
							</div>
						{/if}
						{#if selectedHistoryItem.content_security_policy}
							<div class="detail-item">
								<span class="detail-label">Content-Security-Policy</span>
								<span class="detail-value secure">✅ {selectedHistoryItem.content_security_policy}</span>
							</div>
						{/if}
						{#if selectedHistoryItem.strict_transport_security}
							<div class="detail-item">
								<span class="detail-label">Strict-Transport-Security</span>
								<span class="detail-value secure">✅ {selectedHistoryItem.strict_transport_security}</span>
							</div>
						{/if}
						{#if selectedHistoryItem.x_content_type_options}
							<div class="detail-item">
								<span class="detail-label">X-Content-Type-Options</span>
								<span class="detail-value secure">✅ {selectedHistoryItem.x_content_type_options}</span>
							</div>
						{/if}
						{#if selectedHistoryItem.x_xss_protection}
							<div class="detail-item">
								<span class="detail-label">X-XSS-Protection</span>
								<span class="detail-value">{selectedHistoryItem.x_xss_protection}</span>
							</div>
						{/if}
						{#if selectedHistoryItem.referrer_policy}
							<div class="detail-item">
								<span class="detail-label">Referrer-Policy</span>
								<span class="detail-value">{selectedHistoryItem.referrer_policy}</span>
							</div>
						{/if}
						{#if selectedHistoryItem.permissions_policy}
							<div class="detail-item">
								<span class="detail-label">Permissions-Policy</span>
								<span class="detail-value">{selectedHistoryItem.permissions_policy}</span>
							</div>
						{/if}
						{#if selectedHistoryItem.cache_control}
							<div class="detail-item">
								<span class="detail-label">Cache-Control</span>
								<span class="detail-value">{selectedHistoryItem.cache_control}</span>
							</div>
						{/if}
						{#if selectedHistoryItem.etag}
							<div class="detail-item">
								<span class="detail-label">ETag</span>
								<span class="detail-value">{selectedHistoryItem.etag}</span>
							</div>
						{/if}
					</div>
				{/if}
				{#if selectedHistoryItem.issues && selectedHistoryItem.issues.length > 0}
					<div class="detail-section issues">
						<h4>⚠️ {$tr('siteChecker.result.issues')} ({selectedHistoryItem.issues.length})</h4>
						{#each selectedHistoryItem.issues as issue}
							<div class="issue-item">⚠️ {issue}</div>
						{/each}
					</div>
				{/if}
			</div>
			<div class="modal-footer">
				<button class="btn btn-primary" on:click={() => { showHistoryDetail = false; recheckFromHistory(selectedHistoryItem); }}>
					🔄 {$tr('siteChecker.history.recheck')}
				</button>
				<button class="btn btn-secondary" on:click={() => showHistoryDetail = false}>{$tr('common.close')}</button>
			</div>
		</div>
	</div>
{/if}

{#if showConfirmDialog}
	<div class="modal-overlay" on:click={cancelConfirm}>
		<div class="modal-content confirm-modal" on:click|stopPropagation on:keydown|stopPropagation>
			<div class="modal-header">
				<h2>⚠️ {confirmDialogTitle}</h2>
			</div>
			<div class="modal-body">
				<p>{confirmDialogMessage}</p>
			</div>
			<div class="modal-footer">
				<button class="btn btn-secondary" on:click={cancelConfirm}>{$tr('common.cancel')}</button>
				<button class="btn btn-danger" on:click={executeConfirmAction}>{$tr('common.confirm')}</button>
			</div>
		</div>
	</div>
{/if}

{#if showHelpModal}
	<div class="modal-overlay" on:click={() => showHelpModal = false} on:keydown={(e) => e.key === 'Escape' && (showHelpModal = false)}>
		<div class="modal-content help-modal" on:click|stopPropagation on:keydown|stopPropagation>
			<div class="modal-header">
				<h2>{$tr('siteChecker.help.title')}</h2>
				<button class="modal-close" on:click={() => showHelpModal = false}>✕</button>
			</div>
			<div class="modal-body">
				<div class="help-section">
					<h3>{$tr('siteChecker.help.whatIsSiteCheck')}</h3>
					<p>{$tr('siteChecker.help.whatIsSiteCheckDesc')}</p>
				</div>
				<div class="help-section">
					<h3>{$tr('siteChecker.help.howToUse')}</h3>
					<ul>
						<li>{$tr('siteChecker.help.step1')}</li>
						<li>{$tr('siteChecker.help.step2')}</li>
						<li>{$tr('siteChecker.help.step3')}</li>
						<li>{$tr('siteChecker.help.step4')}</li>
					</ul>
				</div>
				<div class="help-section">
					<h3>{$tr('siteChecker.help.checkingItems')}</h3>
					<ul>
						<li>{$tr('siteChecker.help.checkHttpStatus')}</li>
						<li>{$tr('siteChecker.help.checkResponseTime')}</li>
						<li>{$tr('siteChecker.help.checkDns')}</li>
						<li>{$tr('siteChecker.help.checkSsl')}</li>
						<li>{$tr('siteChecker.help.checkRedirect')}</li>
						<li>{$tr('siteChecker.help.checkSecurityHeaders')}</li>
						<li>{$tr('siteChecker.help.checkIpAddress')}</li>
					</ul>
				</div>
				<div class="help-section">
					<h3>{$tr('siteChecker.help.resultTitle')}</h3>
					<ul>
						<li>{$tr('siteChecker.help.resultFeatures.statusCode')}</li>
						<li>{$tr('siteChecker.help.resultFeatures.responseTime')}</li>
						<li>{$tr('siteChecker.help.resultFeatures.ipAddress')}</li>
						<li>{$tr('siteChecker.help.resultFeatures.securityHeaders')}</li>
						<li>{$tr('siteChecker.help.resultFeatures.xPoweredBy')}</li>
						<li>{$tr('siteChecker.help.resultFeatures.issues')}</li>
					</ul>
				</div>
				<div class="help-section">
					<h3>{$tr('siteChecker.help.warningTitle')}</h3>
					<ul>
						<li>{$tr('siteChecker.help.warnings.warning1')}</li>
						<li>{$tr('siteChecker.help.warnings.warning2')}</li>
						<li>{$tr('siteChecker.help.warnings.warning3')}</li>
						<li>{$tr('siteChecker.help.warnings.warning4')}</li>
					</ul>
				</div>
			</div>
			<div class="modal-footer">
				<button class="btn btn-primary" on:click={() => showHelpModal = false}>{$tr('common.close')}</button>
			</div>
		</div>
	</div>
{/if}

<style>
	.site-checker-page {
		padding: 1.5rem;
		max-width: 1200px;
		margin: 0 auto;
	}

	.page-header {
		display: flex;
		justify-content: space-between;
		align-items: flex-start;
		margin-bottom: 1.5rem;
	}

	.header-left {
		display: flex;
		flex-direction: column;
		gap: 0.25rem;
	}

	.back-link {
		color: var(--text-muted);
		text-decoration: none;
		font-size: 0.85rem;
		margin-bottom: 0.25rem;
	}

	.back-link:hover {
		color: var(--primary);
	}

	.page-title {
		font-size: 1.75rem;
		font-weight: 700;
		color: var(--text-primary);
		margin: 0;
	}

	.page-subtitle {
		color: var(--text-secondary);
		font-size: 0.9rem;
		margin: 0;
	}

	.help-button {
		padding: 0.5rem 1rem;
		border-radius: 8px;
		border: 1px solid rgba(168, 85, 247, 0.3);
		background: rgba(168, 85, 247, 0.1);
		color: var(--primary);
		cursor: pointer;
		font-size: 0.85rem;
	}

	.help-button:hover {
		background: rgba(168, 85, 247, 0.2);
	}

	.tabs {
		display: flex;
		gap: 0.5rem;
		margin-bottom: 1rem;
	}

	.tab-button {
		padding: 0.5rem 1rem;
		border-radius: 6px;
		border: 1px solid rgba(168, 85, 247, 0.2);
		background: transparent;
		color: var(--text-secondary);
		cursor: pointer;
		font-size: 0.85rem;
		transition: all 0.2s;
	}

	.tab-button.active {
		background: var(--primary);
		color: white;
		border-color: var(--primary);
	}

	.tab-button:hover {
		background: rgba(168, 85, 247, 0.1);
	}

	.content-grid {
		display: grid;
		grid-template-columns: 1fr 1.5fr;
		gap: 1.5rem;
	}

	.section-card {
		background: var(--card-bg);
		border: 1px solid rgba(168, 85, 247, 0.15);
		border-radius: 12px;
		padding: 1.5rem;
	}

	.section-title {
		font-size: 1.1rem;
		font-weight: 600;
		color: var(--text-primary);
		margin: 0 0 1rem 0;
	}

	.form-group {
		margin-bottom: 1rem;
	}

	.form-label {
		display: block;
		font-size: 0.85rem;
		font-weight: 500;
		color: var(--text-secondary);
		margin-bottom: 0.4rem;
	}

	.form-input {
		width: 100%;
		padding: 0.6rem 0.8rem;
		border-radius: 8px;
		border: 1px solid rgba(168, 85, 247, 0.2);
		background: var(--input-bg);
		color: var(--text-primary);
		font-size: 0.9rem;
		box-sizing: border-box;
	}

	.form-input:focus {
		outline: none;
		border-color: var(--primary);
		box-shadow: 0 0 0 2px rgba(168, 85, 247, 0.2);
	}

	.form-textarea {
		width: 100%;
		padding: 0.6rem 0.8rem;
		border-radius: 8px;
		border: 1px solid rgba(168, 85, 247, 0.2);
		background: var(--input-bg);
		color: var(--text-primary);
		font-size: 0.9rem;
		resize: vertical;
		font-family: monospace;
		box-sizing: border-box;
	}

	.form-textarea:focus {
		outline: none;
		border-color: var(--primary);
		box-shadow: 0 0 0 2px rgba(168, 85, 247, 0.2);
	}

	.textarea-actions {
		display: flex;
		gap: 0.5rem;
		margin-top: 0.5rem;
	}

	.action-btn {
		padding: 0.3rem 0.6rem;
		border-radius: 6px;
		border: 1px solid rgba(168, 85, 247, 0.2);
		background: rgba(168, 85, 247, 0.05);
		color: var(--text-secondary);
		cursor: pointer;
		font-size: 0.8rem;
	}

	.action-btn:hover {
		background: rgba(168, 85, 247, 0.15);
	}

	.button-group {
		display: flex;
		gap: 0.75rem;
		margin-top: 1rem;
	}

	.btn {
		padding: 0.6rem 1.2rem;
		border-radius: 8px;
		border: none;
		cursor: pointer;
		font-size: 0.9rem;
		font-weight: 500;
		transition: all 0.2s;
	}

	.btn:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

	.btn-primary {
		background: linear-gradient(135deg, #a855f7, #6366f1);
		color: white;
	}

	.btn-primary:hover:not(:disabled) {
		transform: translateY(-1px);
		box-shadow: 0 4px 12px rgba(168, 85, 247, 0.4);
	}

	.btn-secondary {
		background: rgba(168, 85, 247, 0.1);
		color: var(--text-secondary);
		border: 1px solid rgba(168, 85, 247, 0.2);
	}

	.btn-secondary:hover:not(:disabled) {
		background: rgba(168, 85, 247, 0.2);
	}

	.btn-danger {
		background: rgba(239, 68, 68, 0.1);
		color: #ef4444;
		border: 1px solid rgba(239, 68, 68, 0.2);
	}

	.btn-danger:hover:not(:disabled) {
		background: rgba(239, 68, 68, 0.2);
	}

	.error-card {
		display: flex;
		align-items: center;
		gap: 1rem;
		padding: 1rem;
		border-radius: 8px;
		background: rgba(239, 68, 68, 0.1);
		border: 1px solid rgba(239, 68, 68, 0.2);
	}

	.error-icon {
		font-size: 1.5rem;
	}

	.error-content h3 {
		color: #ef4444;
		margin: 0 0 0.25rem 0;
	}

	.error-content p {
		color: var(--text-secondary);
		margin: 0;
		font-size: 0.85rem;
	}

	.status-header {
		display: flex;
		align-items: center;
		gap: 1.25rem;
		margin-bottom: 1.5rem;
		padding-bottom: 1rem;
		border-bottom: 1px solid rgba(168, 85, 247, 0.1);
	}

	.status-badge {
		display: flex;
		flex-direction: column;
		align-items: center;
		justify-content: center;
		width: 80px;
		height: 80px;
		border-radius: 16px;
		flex-shrink: 0;
		font-size: 1.5rem;
	}

	.status-badge.online {
		background: rgba(34, 197, 94, 0.15);
		border: 2px solid #22c55e;
	}

	.status-badge.offline {
		background: rgba(239, 68, 68, 0.15);
		border: 2px solid #ef4444;
	}

	.status-text {
		font-size: 0.75rem;
		font-weight: 600;
		margin-top: 0.25rem;
	}

	.status-badge.online .status-text {
		color: #22c55e;
	}

	.status-badge.offline .status-text {
		color: #ef4444;
	}

	.status-info h3 {
		color: var(--text-primary);
		margin: 0 0 0.25rem 0;
		font-size: 1.1rem;
		word-break: break-all;
	}

	.status-summary {
		color: var(--text-secondary);
		font-size: 0.85rem;
		margin: 0;
	}

	.site-details {
		display: flex;
		flex-direction: column;
		gap: 1rem;
	}

	.detail-section {
		padding: 0.75rem;
		border-radius: 8px;
		background: rgba(168, 85, 247, 0.03);
		border: 1px solid rgba(168, 85, 247, 0.08);
	}

	.detail-section h4 {
		color: var(--text-primary);
		margin: 0 0 0.75rem 0;
		font-size: 0.95rem;
	}

	.detail-section.issues {
		background: rgba(234, 179, 8, 0.05);
		border-color: rgba(234, 179, 8, 0.15);
	}

	.detail-item {
		display: flex;
		justify-content: space-between;
		align-items: flex-start;
		padding: 0.4rem 0;
		border-bottom: 1px solid rgba(168, 85, 247, 0.05);
		gap: 0.5rem;
	}

	.detail-item:last-child {
		border-bottom: none;
	}

	.detail-label {
		color: var(--text-secondary);
		font-size: 0.85rem;
		white-space: nowrap;
		flex-shrink: 0;
	}

	.detail-value {
		color: var(--text-primary);
		font-size: 0.85rem;
		text-align: right;
		word-break: break-all;
	}

	.detail-value.secure {
		color: #22c55e;
	}

	.detail-value.insecure {
		color: #ef4444;
	}

	.detail-value.warning {
		color: #eab308;
	}

	.issue-item {
		padding: 0.4rem 0.6rem;
		border-radius: 4px;
		margin-bottom: 0.4rem;
		font-size: 0.85rem;
		background: rgba(234, 179, 8, 0.08);
		color: #f97316;
	}

	.empty-state {
		text-align: center;
		padding: 2rem;
	}

	.empty-icon {
		font-size: 3rem;
		margin-bottom: 0.5rem;
	}

	.empty-state p {
		color: var(--text-secondary);
		margin: 0;
	}

	.empty-hint {
		font-size: 0.85rem;
		margin-top: 0.25rem !important;
	}

	.batch-stats {
		display: flex;
		gap: 1rem;
		margin-bottom: 1rem;
		flex-wrap: wrap;
	}

	.stat-item {
		padding: 0.5rem 1rem;
		border-radius: 8px;
		background: rgba(168, 85, 247, 0.05);
		border: 1px solid rgba(168, 85, 247, 0.1);
	}

	.stat-item.success {
		background: rgba(34, 197, 94, 0.05);
		border-color: rgba(34, 197, 94, 0.15);
	}

	.stat-item.failed {
		background: rgba(239, 68, 68, 0.05);
		border-color: rgba(239, 68, 68, 0.15);
	}

	.stat-item.error {
		background: rgba(249, 115, 22, 0.05);
		border-color: rgba(249, 115, 22, 0.15);
	}

	.stat-label {
		color: var(--text-secondary);
		font-size: 0.8rem;
		display: block;
	}

	.stat-value {
		color: var(--text-primary);
		font-size: 1.25rem;
		font-weight: 700;
	}

	.batch-results {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
	}

	.batch-item {
		padding: 0.75rem;
		border-radius: 8px;
		border: 1px solid rgba(168, 85, 247, 0.1);
	}

	.batch-item.online {
		background: rgba(34, 197, 94, 0.03);
		border-color: rgba(34, 197, 94, 0.1);
	}

	.batch-item.offline {
		background: rgba(239, 68, 68, 0.03);
		border-color: rgba(239, 68, 68, 0.1);
	}

	.batch-item-header {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		flex-wrap: wrap;
	}

	.batch-url {
		font-weight: 600;
		color: var(--text-primary);
		font-family: monospace;
	}

	.batch-status-code {
		font-weight: 600;
		font-size: 0.85rem;
	}

	.batch-time {
		font-size: 0.85rem;
		font-weight: 500;
	}

	.batch-error-text {
		color: #ef4444;
		font-size: 0.85rem;
	}

	.batch-item-details {
		display: flex;
		gap: 1rem;
		margin-top: 0.4rem;
		font-size: 0.8rem;
		color: var(--text-secondary);
	}

	.pagination {
		display: flex;
		align-items: center;
		justify-content: center;
		gap: 0.75rem;
		margin-top: 1rem;
	}

	.pagination-btn {
		padding: 0.4rem 0.8rem;
		border-radius: 6px;
		border: 1px solid rgba(168, 85, 247, 0.2);
		background: transparent;
		color: var(--text-secondary);
		cursor: pointer;
	}

	.pagination-btn:disabled {
		opacity: 0.4;
		cursor: not-allowed;
	}

	.pagination-info {
		color: var(--text-secondary);
		font-size: 0.85rem;
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

	.history-table-wrapper {
		overflow-x: auto;
	}

	.history-table {
		width: 100%;
		border-collapse: collapse;
	}

	.history-table th {
		text-align: left;
		padding: 0.6rem;
		color: var(--text-secondary);
		font-size: 0.8rem;
		font-weight: 600;
		border-bottom: 1px solid rgba(168, 85, 247, 0.15);
	}

	.history-table td {
		padding: 0.6rem;
		border-bottom: 1px solid rgba(168, 85, 247, 0.05);
		font-size: 0.85rem;
	}

	.url-cell code {
		font-family: monospace;
		color: var(--primary);
	}

	.status-tag {
		display: inline-block;
		padding: 0.15rem 0.5rem;
		border-radius: 4px;
		font-size: 0.8rem;
		font-weight: 500;
	}

	.status-tag.online {
		background: rgba(34, 197, 94, 0.1);
		color: #22c55e;
	}

	.status-tag.offline {
		background: rgba(239, 68, 68, 0.1);
		color: #ef4444;
	}

	.time-cell {
		color: var(--text-secondary);
		font-size: 0.8rem;
		white-space: nowrap;
	}

	.title-cell {
		max-width: 150px;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.actions-cell {
		white-space: nowrap;
	}

	.action-link {
		background: none;
		border: none;
		cursor: pointer;
		padding: 0.2rem;
		font-size: 1rem;
	}

	.action-link.delete:hover {
		filter: brightness(1.3);
	}

	.history-pagination {
		display: flex;
		align-items: center;
		justify-content: center;
		gap: 0.75rem;
		margin-top: 1rem;
	}

	.modal-overlay {
		position: fixed;
		top: 0;
		left: 0;
		right: 0;
		bottom: 0;
		background: rgba(0, 0, 0, 0.6);
		display: flex;
		align-items: center;
		justify-content: center;
		z-index: 1000;
	}

	.modal-content {
		background: var(--card-bg);
		border-radius: 12px;
		max-width: 600px;
		width: 90%;
		max-height: 80vh;
		overflow-y: auto;
	}

	.target-selector-modal {
		max-width: 500px;
	}

	.history-detail-modal {
		max-width: 700px;
	}

	.confirm-modal {
		max-width: 400px;
	}

	.help-modal {
		max-width: 600px;
	}

	.modal-header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		padding: 1rem 1.5rem;
		border-bottom: 1px solid rgba(168, 85, 247, 0.1);
	}

	.modal-header h2 {
		margin: 0;
		font-size: 1.1rem;
		color: var(--text-primary);
	}

	.modal-close {
		background: none;
		border: none;
		color: var(--text-secondary);
		cursor: pointer;
		font-size: 1.2rem;
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
		border-top: 1px solid rgba(168, 85, 247, 0.1);
	}

	.modal-actions {
		display: flex;
		gap: 0.5rem;
	}

	.selected-count {
		color: var(--text-secondary);
		font-size: 0.85rem;
	}

	.target-search input {
		width: 100%;
		padding: 0.5rem;
		border-radius: 6px;
		border: 1px solid rgba(168, 85, 247, 0.2);
		background: var(--input-bg);
		color: var(--text-primary);
		box-sizing: border-box;
	}

	.target-list {
		max-height: 300px;
		overflow-y: auto;
	}

	.target-item {
		display: flex;
		align-items: center;
		gap: 0.75rem;
		padding: 0.6rem;
		border-radius: 6px;
		cursor: pointer;
		transition: background 0.2s;
	}

	.target-item:hover {
		background: rgba(168, 85, 247, 0.05);
	}

	.target-item.selected {
		background: rgba(168, 85, 247, 0.1);
	}

	.target-checkbox {
		width: 20px;
		height: 20px;
		border: 2px solid rgba(168, 85, 247, 0.3);
		border-radius: 4px;
		display: flex;
		align-items: center;
		justify-content: center;
		flex-shrink: 0;
	}

	.target-item.selected .target-checkbox {
		background: var(--primary);
		border-color: var(--primary);
		color: white;
	}

	.target-info {
		display: flex;
		flex-direction: column;
	}

	.target-name {
		font-weight: 500;
		color: var(--text-primary);
	}

	.target-value {
		font-size: 0.8rem;
		color: var(--text-secondary);
	}

	.loading-message, .empty-message {
		text-align: center;
		padding: 1rem;
		color: var(--text-secondary);
	}

	.loading-state {
		text-align: center;
		padding: 2rem;
	}

	.spinner {
		width: 2rem;
		height: 2rem;
		border: 3px solid rgba(168, 85, 247, 0.2);
		border-top-color: var(--primary);
		border-radius: 50%;
		animation: spin 0.8s linear infinite;
		margin: 0 auto 0.5rem;
	}

	@keyframes spin {
		to { transform: rotate(360deg); }
	}

	.help-section {
		margin-bottom: 1.25rem;
	}

	.help-section h3 {
		color: var(--text-primary);
		margin: 0 0 0.5rem 0;
		font-size: 1rem;
	}

	.help-section p {
		color: var(--text-secondary);
		font-size: 0.85rem;
		margin: 0;
		line-height: 1.5;
	}

	.help-section ul {
		list-style: none;
		padding: 0;
		margin: 0;
	}

	.help-section li {
		padding: 0.25rem 0;
		color: var(--text-secondary);
		font-size: 0.85rem;
	}
</style>
