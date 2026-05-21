<script lang="ts">
	import { tr, t } from '$lib/i18n';
	import ToolHistory from '$lib/components/ToolHistory.svelte';
	import ToolHelp from '$lib/components/ToolHelp.svelte';

	interface DirEntry {
		path: string;
		full_url: string;
		status_code: number;
		content_length: number | null;
		content_type: string | null;
		redirect_url: string | null;
		response_time_ms: number;
		depth: number;
		is_directory: boolean;
	}

	interface SslInfo {
		subject: string | null;
		issuer: string | null;
		valid_from: string | null;
		valid_to: string | null;
		is_expired: boolean;
		protocol: string | null;
		cipher: string | null;
	}

	interface WafDetection {
		detected: boolean;
		waf_name: string | null;
		evidence: string[];
	}

	interface SensitivePath {
		path: string;
		category: string;
		severity: string;
		description: string;
	}

	interface DirScanResult {
		url: string;
		found_paths: DirEntry[];
		total_found: number;
		total_scanned: number;
		summary: string;
		ssl_info: SslInfo | null;
		waf_detected: WafDetection | null;
		sensitive_paths: SensitivePath[];
		scan_duration_ms: number;
	}

	let url = $state('');
	let activeMainTab = $state('analyze');
	let historyComponent: ToolHistory;
	let timeout = $state(10);
	let threads = $state(20);
	let followRedirects = $state(false);
	let extensions = $state('');
	let scanMode = $state('normal');
	let recursive = $state(false);
	let maxDepth = $state(2);
	let excludePatterns = $state('');
	let randomizeUa = $state(true);
	let showTargetSelector = $state(false);
	let targetList: any[] = $state([]);
	let selectedTargets: any[] = $state([]);
	let selectedTargetIds: number[] = $state([]);
	let targetSearchQuery = $state('');
	let loadingTargets = $state(false);
	let collectSslInfo = $state(true);
	let result: DirScanResult | null = $state(null);
	let error = $state('');
	let processing = $state(false);
	let activeResultTab = $state('overview');
	let statusFilter = $state('all');
	let searchQuery = $state('');

	async function scan() {
		if (!url.trim()) { error = t('dirScanner.error.emptyInput'); return; }
		processing = true; error = ''; result = null;
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			const extList = extensions ? extensions.split(',').map((e: string) => e.trim()).filter((e: string) => e) : [];
			const excludeList = excludePatterns ? excludePatterns.split(',').map((e: string) => e.trim()).filter((e: string) => e) : [];
			result = await invoke<DirScanResult>('scan_dirs_command', {
				config: {
					url: url.trim(),
					timeout,
					threads,
					extensions: extList,
					wordlist: [],
					follow_redirects: followRedirects,
					scan_mode: scanMode,
					recursive,
					max_depth: maxDepth,
					exclude_patterns: excludeList,
					user_agent: null,
					randomize_ua: randomizeUa,
					collect_ssl_info: collectSslInfo
				},
				targetId: selectedTargetIds.length > 0 ? selectedTargetIds[0] : null
			});
			if (result && historyComponent) {
				await historyComponent.saveHistory(
					url.trim(),
					JSON.stringify(result),
					result.summary,
					'completed'
				);
			}
		} catch (e: any) {
			error = e.toString();
			if (historyComponent) {
				await historyComponent.saveHistory(url.trim(), JSON.stringify({ error: e.toString() }), undefined, 'failed');
			}
		} finally { processing = false; }
	}

	function clearAll() { url = ''; result = null; error = ''; extensions = ''; excludePatterns = ''; }

	async function openTargetSelectorModal() {
		showTargetSelector = true;
		await loadTargets();
	}

	async function loadTargets() {
		loadingTargets = true;
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			const res = await invoke<{ targets: any[], total: number }>('target_manager', { action: 'list', page: 1, pageSize: 100 });
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

	function getStatusColor(code: number): string {
		if (code >= 200 && code < 300) return '#22c55e';
		if (code >= 300 && code < 400) return '#3b82f6';
		if (code >= 400 && code < 500) return '#f97316';
		return '#ef4444';
	}

	function getStatusLabel(code: number): string {
		if (code >= 200 && code < 300) return t('dirScanner.labels.status2xx');
		if (code >= 300 && code < 400) return t('dirScanner.labels.status3xx');
		if (code >= 400 && code < 500) return t('dirScanner.labels.status4xx');
		return t('dirScanner.labels.status5xx');
	}

	function getStatusIcon(code: number): string {
		if (code >= 200 && code < 300) return '✅';
		if (code >= 300 && code < 400) return '↪️';
		if (code >= 400 && code < 500) return '⚠️';
		return '❌';
	}

	function getSeverityColor(sev: string): string {
		if (sev === 'critical') return '#ef4444';
		if (sev === 'high') return '#f97316';
		return '#eab308';
	}

	function getSeverityIcon(sev: string): string {
		if (sev === 'critical') return '🔴';
		if (sev === 'high') return '🟠';
		return '🟡';
	}

	function formatSize(bytes: number | null): string {
		if (bytes === null) return '-';
		if (bytes < 1024) return `${bytes}B`;
		if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)}KB`;
		return `${(bytes / (1024 * 1024)).toFixed(1)}MB`;
	}

	function formatDuration(ms: number): string {
		if (ms < 1000) return `${ms}ms`;
		return `${(ms / 1000).toFixed(1)}s`;
	}

	function getFilteredEntries(): DirEntry[] {
		if (!result) return [];
		let entries = result.found_paths;
		if (statusFilter !== 'all') {
			const range = parseInt(statusFilter);
			entries = entries.filter(e => Math.floor(e.status_code / 100) === range);
		}
		if (searchQuery.trim()) {
			const q = searchQuery.toLowerCase();
			entries = entries.filter(e =>
				e.path.toLowerCase().includes(q) ||
				(e.content_type && e.content_type.toLowerCase().includes(q)) ||
				e.status_code.toString().includes(q)
			);
		}
		return entries;
	}

	function getStatusGroups(): { label: string; icon: string; color: string; count: number; code: string }[] {
		if (!result) return [];
		const groups: Record<string, { label: string; icon: string; color: string; count: number; code: string }> = {};
		for (const entry of result.found_paths) {
			const range = Math.floor(entry.status_code / 100);
			const key = range.toString();
			if (!groups[key]) {
				groups[key] = {
					label: getStatusLabel(entry.status_code),
					icon: getStatusIcon(entry.status_code),
					color: getStatusColor(entry.status_code),
					count: 0,
					code: key
				};
			}
			groups[key].count++;
		}
		return Object.values(groups).sort((a, b) => parseInt(a.code) - parseInt(b.code));
	}

	function getContentTypeGroups(): { type: string; count: number }[] {
		if (!result) return [];
		const groups: Record<string, number> = {};
		for (const entry of result.found_paths) {
			const ct = entry.content_type ? entry.content_type.split(';')[0].trim() : 'unknown';
			groups[ct] = (groups[ct] || 0) + 1;
		}
		return Object.entries(groups).map(([type, count]) => ({ type, count })).sort((a, b) => b.count - a.count);
	}

	function exportJSON() {
		if (!result) return;
		const blob = new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' });
		const a = document.createElement('a');
		a.href = URL.createObjectURL(blob);
		a.download = `dirscan_${new Date().toISOString().slice(0, 10)}.json`;
		a.click();
		URL.revokeObjectURL(a.href);
	}

	function exportCSV() {
		if (!result) return;
		const headers = ['Path', 'Status', 'Content-Type', 'Size', 'Response Time (ms)', 'Depth', 'Redirect'];
		const rows = result.found_paths.map(e => [
			e.path, e.status_code, e.content_type || '',
			e.content_length || '', e.response_time_ms, e.depth,
			e.redirect_url || ''
		]);
		const csv = [headers.join(','), ...rows.map(r => r.map(c => `"${c}"`).join(','))].join('\n');
		const blob = new Blob([csv], { type: 'text/csv' });
		const a = document.createElement('a');
		a.href = URL.createObjectURL(blob);
		a.download = `dirscan_${new Date().toISOString().slice(0, 10)}.csv`;
		a.click();
		URL.revokeObjectURL(a.href);
	}
</script>

<div class="nd-page">
	<div class="page-header">
		<div class="header-left">
			<a href="/" class="back-link">{$tr('common.backToHome')}</a>
			<h1 class="page-title">📂 {$tr('dirScanner.title')}</h1>
			<p class="page-subtitle">{$tr('dirScanner.subtitle')}</p>
		</div>
	</div>

	<div class="tabs">
		<button class="tab-btn {activeMainTab === 'analyze' ? 'active' : ''}" onclick={() => activeMainTab = 'analyze'}>
			<span class="tab-icon">🔍</span> {$tr('dirScanner.buttons.scan')}
		</button>
		<button class="tab-btn {activeMainTab === 'history' ? 'active' : ''}" onclick={() => activeMainTab = 'history'}>
			<span class="tab-icon">📋</span> {$tr('dirScanner.history')}
		</button>
		<button class="tab-btn {activeMainTab === 'help' ? 'active' : ''}" onclick={() => activeMainTab = 'help'}>
			<span class="tab-icon">📖</span> {$tr('dirScanner.help')}
		</button>
	</div>

	{#if activeMainTab === 'analyze'}
		<div class="content-grid">
			<div class="input-section">
				<div class="section-card">
					<h2 class="section-title">{$tr('dirScanner.config.title')}</h2>
					<p class="section-desc">{$tr('dirScanner.config.desc')}</p>

					<div class="form-group">
						<label class="form-label">{$tr('dirScanner.config.url')}</label>
						<div class="input-with-action">
							<input type="text" bind:value={url} placeholder="https://example.com" class="form-input" disabled={processing} onkeydown={(e) => e.key === 'Enter' && scan()} />
							<button type="button" class="action-btn" onclick={openTargetSelectorModal} disabled={processing} title={$tr('common.selectTarget')}>
								🎯
							</button>
						</div>
					</div>

					<div class="form-row">
						<div class="form-group">
							<label class="form-label">{$tr('dirScanner.config.timeout')}</label>
							<input type="number" bind:value={timeout} class="form-input" min="5" max="60" disabled={processing} />
						</div>
						<div class="form-group">
							<label class="form-label">{$tr('dirScanner.config.threads')}</label>
							<input type="number" bind:value={threads} class="form-input" min="1" max="50" disabled={processing} />
						</div>
					</div>

					<div class="form-group">
						<label class="form-label">{$tr('dirScanner.config.scanMode')}</label>
						<div class="target-grid">
							<label class="target-chip {scanMode === 'quick' ? 'active' : ''}">
								<input type="radio" name="scanMode" value="quick" bind:group={scanMode} disabled={processing} />
								<span>⚡ {$tr('dirScanner.config.modeQuick')}</span>
							</label>
							<label class="target-chip {scanMode === 'normal' ? 'active' : ''}">
								<input type="radio" name="scanMode" value="normal" bind:group={scanMode} disabled={processing} />
								<span>⚖️ {$tr('dirScanner.config.modeNormal')}</span>
							</label>
							<label class="target-chip {scanMode === 'deep' ? 'active' : ''}">
								<input type="radio" name="scanMode" value="deep" bind:group={scanMode} disabled={processing} />
								<span>🔬 {$tr('dirScanner.config.modeDeep')}</span>
							</label>
						</div>
					</div>

					<div class="form-group">
						<label class="form-label">{$tr('dirScanner.config.extensions')}</label>
						<input type="text" bind:value={extensions} placeholder=".html,.php,.json,.txt,.bak" class="form-input" disabled={processing} />
					</div>

					<div class="form-group">
						<label class="form-label">{$tr('dirScanner.config.excludePatterns')}</label>
						<input type="text" bind:value={excludePatterns} placeholder=".css,.js,.png" class="form-input" disabled={processing} />
					</div>

					{#if recursive}
						<div class="form-group">
							<label class="form-label">{$tr('dirScanner.config.maxDepth')}</label>
							<input type="number" bind:value={maxDepth} class="form-input" min="1" max="5" disabled={processing} />
						</div>
					{/if}

					<div class="checkbox-grid">
						<label class="target-chip {followRedirects ? 'active' : ''}">
							<input type="checkbox" bind:checked={followRedirects} disabled={processing} />
							<span>↪️ {$tr('dirScanner.config.followRedirects')}</span>
						</label>
						<label class="target-chip {recursive ? 'active' : ''}">
							<input type="checkbox" bind:checked={recursive} disabled={processing} />
							<span>🔄 {$tr('dirScanner.config.recursive')}</span>
						</label>
						<label class="target-chip {randomizeUa ? 'active' : ''}">
							<input type="checkbox" bind:checked={randomizeUa} disabled={processing} />
							<span>🎭 {$tr('dirScanner.config.randomUa')}</span>
						</label>
						<label class="target-chip {collectSslInfo ? 'active' : ''}">
							<input type="checkbox" bind:checked={collectSslInfo} disabled={processing} />
							<span>🔒 {$tr('dirScanner.config.collectSsl')}</span>
						</label>
					</div>

					<div class="button-group">
						<button class="btn-primary" onclick={scan} disabled={processing || !url.trim()}>
							{#if processing}<span class="spinner"></span>{$tr('dirScanner.buttons.scanning')}{:else}📂 {$tr('dirScanner.buttons.scan')}{/if}
						</button>
						<button class="btn-secondary" onclick={clearAll} disabled={processing}>🗑️</button>
					</div>
				</div>
			</div>

			<div class="result-section">
				{#if error}
					<div class="section-card">
						<div class="error-card">
							<span class="error-icon">⚠️</span>
							<span class="error-text">{error}</span>
						</div>
					</div>
				{:else if result}
					<div class="section-card">
						<div class="result-header">
							<h2 class="section-title">{$tr('dirScanner.result.title')}</h2>
							<div class="result-header-actions">
								<div class="result-score-badge">
									<span class="score-value">{result.total_found}</span>
									<span class="score-label">{$tr('dirScanner.result.found')}</span>
								</div>
								<div class="export-group">
									<button class="export-btn" onclick={exportJSON} title="JSON">📋 JSON</button>
									<button class="export-btn" onclick={exportCSV} title="CSV">📊 CSV</button>
								</div>
							</div>
						</div>

						<div class="summary-bar">
							{result.summary}
							<span class="duration-badge">⏱ {formatDuration(result.scan_duration_ms)}</span>
						</div>

						{#if result.waf_detected?.detected}
							<div class="waf-alert">
								<span class="waf-icon">🛡️</span>
								<div class="waf-info">
									<span class="waf-title">{$tr('dirScanner.result.wafDetected')}: {result.waf_detected.waf_name}</span>
									{#if result.waf_detected.evidence.length > 0}
										<span class="waf-evidence">{result.waf_detected.evidence.join(' | ')}</span>
									{/if}
								</div>
							</div>
						{/if}

						{#if result.ssl_info}
							<div class="ssl-info-bar">
								<span class="ssl-icon">🔒</span>
								<div class="ssl-details">
									<span class="ssl-subject">{result.ssl_info.subject || '-'}</span>
									<span class="ssl-meta">
										{result.ssl_info.protocol || '-'} | {result.ssl_info.cipher || '-'}
										{#if result.ssl_info.is_expired}<span class="ssl-expired">⚠️ EXPIRED</span>{/if}
									</span>
								</div>
							</div>
						{/if}

						{#if result.sensitive_paths.length > 0}
							<div class="sensitive-section">
								<div class="sensitive-header">🔐 {$tr('dirScanner.result.sensitivePaths')} ({result.sensitive_paths.length})</div>
								<div class="sensitive-grid">
									{#each result.sensitive_paths.slice(0, 10) as sp}
										<span class="sensitive-chip" style="border-color: {getSeverityColor(sp.severity)}40; background: {getSeverityColor(sp.severity)}10; color: {getSeverityColor(sp.severity)}">
											{getSeverityIcon(sp.severity)} {sp.path}
											<span class="sensitive-badge">{sp.severity}</span>
										</span>
									{/each}
								</div>
							</div>
						{/if}

						{#if getStatusGroups().length > 0}
							<div class="status-grid" style="margin-bottom: 1rem;">
								{#each getStatusGroups() as group}
									<span class="status-chip" style="border-color: {group.color}40; background: {group.color}10; color: {group.color}">
										<span>{group.icon}</span>
										<span class="status-chip-label">{group.label}</span>
										<span class="status-chip-count">{group.count}</span>
									</span>
								{/each}
							</div>
						{/if}

						<div class="result-tabs">
							<button class="result-tab {activeResultTab === 'overview' ? 'active' : ''}" onclick={() => activeResultTab = 'overview'}>
								📊 {$tr('dirScanner.result.overview')}
							</button>
							<button class="result-tab {activeResultTab === 'list' ? 'active' : ''}" onclick={() => activeResultTab = 'list'}>
								📋 {$tr('dirScanner.result.list')}
							</button>
							<button class="result-tab {activeResultTab === 'status' ? 'active' : ''}" onclick={() => activeResultTab = 'status'}>
								🗂️ {$tr('dirScanner.result.byStatus')}
							</button>
							<button class="result-tab {activeResultTab === 'sensitive' ? 'active' : ''}" onclick={() => activeResultTab = 'sensitive'}>
								🔐 {$tr('dirScanner.result.sensitive')}
							</button>
						</div>

						{#if activeResultTab === 'overview'}
							<div class="overview-grid">
								<div class="overview-stat">
									<span class="stat-icon">📂</span>
									<span class="stat-value">{result.total_found}</span>
									<span class="stat-label">{$tr('dirScanner.result.found')}</span>
								</div>
								<div class="overview-stat">
									<span class="stat-icon">🔍</span>
									<span class="stat-value">{result.total_scanned}</span>
									<span class="stat-label">{$tr('dirScanner.result.scanned')}</span>
								</div>
								<div class="overview-stat">
									<span class="stat-icon">📊</span>
									<span class="stat-value">{result.total_scanned > 0 ? ((result.total_found / result.total_scanned) * 100).toFixed(1) : 0}%</span>
									<span class="stat-label">Rate</span>
								</div>
								<div class="overview-stat">
									<span class="stat-icon">🏷️</span>
									<span class="stat-value">{getContentTypeGroups().length}</span>
									<span class="stat-label">{$tr('dirScanner.labels.contentType')}</span>
								</div>
							</div>

							{#if getContentTypeGroups().length > 0}
								<div class="subsection-title">{$tr('dirScanner.labels.contentType')}</div>
								<div class="tech-grid">
									{#each getContentTypeGroups().slice(0, 12) as ctGroup}
										<span class="tech-chip">
											<span class="tech-name">{ctGroup.type}</span>
											<span class="tech-count">{ctGroup.count}</span>
										</span>
									{/each}
								</div>
							{/if}

							<div class="subsection-title">{$tr('dirScanner.result.found')}</div>
							<div class="tech-grid">
								{#each result.found_paths.slice(0, 30) as entry}
									<span class="tech-chip">
										<span class="tech-icon">{getStatusIcon(entry.status_code)}</span>
										<span class="tech-name">{entry.path}</span>
										<span class="status-mini" style="color: {getStatusColor(entry.status_code)}">{entry.status_code}</span>
										{#if entry.depth > 0}<span class="depth-mini">D{entry.depth}</span>{/if}
									</span>
								{/each}
							</div>
						{:else if activeResultTab === 'list'}
							<div class="filter-bar">
								<button class="filter-btn {statusFilter === 'all' ? 'active' : ''}" onclick={() => statusFilter = 'all'}>
									{$tr('dirScanner.labels.all')} ({result.found_paths.length})
								</button>
								{#each getStatusGroups() as group}
									<button class="filter-btn {statusFilter === group.code ? 'active' : ''}" onclick={() => statusFilter = group.code}>
										{group.icon} {group.label} ({group.count})
									</button>
								{/each}
							</div>

							<div class="search-bar">
								<input type="text" bind:value={searchQuery} placeholder="{$tr('dirScanner.labels.search')}" class="search-input" />
							</div>

							<div class="links-table-wrapper">
								<table class="data-table">
									<thead>
										<tr>
											<th>{$tr('dirScanner.labels.statusCode')}</th>
											<th>{$tr('dirScanner.labels.path')}</th>
											<th>{$tr('dirScanner.labels.contentType')}</th>
											<th>{$tr('dirScanner.labels.size')}</th>
											<th>{$tr('dirScanner.labels.responseTime')}</th>
											<th>{$tr('dirScanner.labels.depth')}</th>
											<th>{$tr('dirScanner.labels.redirect')}</th>
										</tr>
									</thead>
									<tbody>
										{#each getFilteredEntries() as entry}
											<tr>
												<td>
													<span class="status-badge-table" style="color: {getStatusColor(entry.status_code)}; border-color: {getStatusColor(entry.status_code)}40; background: {getStatusColor(entry.status_code)}15;">
														{entry.status_code}
													</span>
												</td>
												<td>
													<span class="path-cell">
														<span class="tech-icon">{getStatusIcon(entry.status_code)}</span>
														{entry.path}
													</span>
												</td>
												<td>
													<span class="content-type-badge">{entry.content_type || '-'}</span>
												</td>
												<td>
													<span class="size-text">{formatSize(entry.content_length)}</span>
												</td>
												<td>
													<span class="time-text">{entry.response_time_ms}ms</span>
												</td>
												<td>
													{#if entry.depth > 0}
														<span class="depth-badge">D{entry.depth}</span>
													{:else}
														<span class="text-muted">-</span>
													{/if}
												</td>
												<td>
													{#if entry.redirect_url}
														<span class="redirect-text" title={entry.redirect_url}>→ {entry.redirect_url}</span>
													{:else}
														<span class="text-muted">-</span>
													{/if}
												</td>
											</tr>
										{/each}
									</tbody>
								</table>
							</div>
						{:else if activeResultTab === 'status'}
							{#each getStatusGroups() as group}
								<div class="category-section">
									<div class="category-header" style="border-color: {group.color}30;">
										<span class="category-icon">{group.icon}</span>
										<span class="category-name" style="color: {group.color}">{group.label}</span>
										<span class="category-count" style="background: {group.color}20; color: {group.color}">{group.count}</span>
									</div>
									<div class="category-techs">
										{#each result.found_paths.filter(e => Math.floor(e.status_code / 100) === parseInt(group.code)) as entry}
											<div class="category-tech-item">
												<div class="cti-left">
													<span class="tech-icon">{getStatusIcon(entry.status_code)}</span>
													<span class="cti-name">{entry.path}</span>
													{#if entry.content_length}
														<span class="tech-version-mini">{formatSize(entry.content_length)}</span>
													{/if}
													{#if entry.depth > 0}
														<span class="depth-mini">D{entry.depth}</span>
													{/if}
												</div>
												<div class="cti-right">
													<span class="status-mini" style="color: {getStatusColor(entry.status_code)}">
														{entry.status_code}
													</span>
													<span class="method-mini">{entry.response_time_ms}ms</span>
												</div>
											</div>
										{/each}
									</div>
								</div>
							{/each}
						{:else if activeResultTab === 'sensitive'}
							{#if result.sensitive_paths.length > 0}
								<div class="sensitive-list">
									{#each result.sensitive_paths as sp}
										<div class="sensitive-item" style="border-left: 3px solid {getSeverityColor(sp.severity)}">
											<div class="si-header">
												<span class="si-icon">{getSeverityIcon(sp.severity)}</span>
												<span class="si-path">{sp.path}</span>
												<span class="si-severity" style="background: {getSeverityColor(sp.severity)}20; color: {getSeverityColor(sp.severity)}">{sp.severity}</span>
												<span class="si-category">{sp.category}</span>
											</div>
											<div class="si-desc">{sp.description}</div>
										</div>
									{/each}
								</div>
							{:else}
								<div class="empty-mini">{$tr('dirScanner.result.noSensitive')}</div>
							{/if}
						{/if}
					</div>
				{:else}
					<div class="section-card">
						<div class="empty-state">
							<div class="empty-icon">📂</div>
							<p class="empty-text">{$tr('dirScanner.result.empty')}</p>
							<p class="empty-sub">{$tr('dirScanner.result.emptySub')}</p>
						</div>
					</div>
				{/if}
			</div>
		</div>
	{:else if activeMainTab === 'history'}
		<div class="section-card">
			<ToolHistory toolType="dir_scanner" toolName={$tr('dirScanner.title')} bind:this={historyComponent} />
		</div>
	{:else if activeMainTab === 'help'}
		<div class="section-card">
			<ToolHelp toolType="dir_scanner" />
		</div>
	{/if}
</div>

{#if showTargetSelector}
	<div class="modal-overlay" onclick={() => showTargetSelector = false}>
		<div class="modal-content" onclick={(e) => e.stopPropagation()}>
			<div class="modal-header">
				<h3>🎯 {$tr('common.selectTarget')}</h3>
				<button class="modal-close" onclick={() => showTargetSelector = false}>✕</button>
			</div>
			<div class="modal-body">
				<input type="text" bind:value={targetSearchQuery} placeholder={$tr('common.search')} class="form-input" />
				{#if loadingTargets}
					<div class="loading-state"><span class="spinner"></span> {$tr('common.loading')}</div>
				{:else if targetList.length === 0}
					<div class="empty-state"><p>{$tr('common.noData')}</p></div>
				{:else}
					<div class="target-list">
						{#each targetList.filter((t: any) => !targetSearchQuery || t.name?.toLowerCase().includes(targetSearchQuery.toLowerCase()) || t.target_value?.toLowerCase().includes(targetSearchQuery.toLowerCase())) as t}
							<label class="target-select-item {selectedTargets.some((st: any) => st.id === t.id) ? 'selected' : ''}">
								<input type="checkbox" checked={selectedTargets.some((st: any) => st.id === t.id)} onchange={() => toggleTargetSelection(t)} />
								<span>{t.name || t.target_value}</span>
							</label>
						{/each}
					</div>
				{/if}
			</div>
			<div class="modal-footer">
				<span class="selected-count">{$tr('common.selectedCount', { count: selectedTargets.length })}</span>
				<button class="btn-secondary" onclick={() => showTargetSelector = false}>{$tr('common.cancel')}</button>
				<button class="btn-primary-sm" onclick={confirmTargetSelection} disabled={selectedTargets.length === 0}>{$tr('common.confirm')}</button>
			</div>
		</div>
	</div>
{/if}

<style>
	.nd-page { padding: 1.5rem; max-width: 1200px; margin: 0 auto; min-height: 100vh; }
	.page-header { margin-bottom: 1.5rem; padding-bottom: 1rem; border-bottom: 1px solid rgba(168, 85, 247, 0.15); }
	.back-link { color: #94a3b8; text-decoration: none; font-size: 0.8rem; transition: color 0.2s; }
	.back-link:hover { color: #a855f7; }
	.page-title { font-size: 1.5rem; font-weight: 700; margin: 0.5rem 0 0.25rem; color: #f1f5f9; }
	.page-subtitle { color: #94a3b8; font-size: 0.875rem; margin: 0; }
	.tabs { display: flex; gap: 0.25rem; margin-bottom: 1.25rem; background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(168, 85, 247, 0.15); border-radius: 0.75rem; padding: 0.25rem; }
	.tab-btn { flex: 1; padding: 0.6rem 1rem; border: none; border-radius: 0.5rem; background: transparent; cursor: pointer; font-size: 0.85rem; color: #94a3b8; transition: all 0.2s; display: flex; align-items: center; justify-content: center; gap: 0.4rem; }
	.tab-btn.active { background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%); color: white; font-weight: 600; box-shadow: 0 2px 8px rgba(168, 85, 247, 0.3); }
	.tab-btn:hover:not(.active) { background: rgba(168, 85, 247, 0.1); color: #c4b5fd; }
	.tab-icon { font-size: 0.9rem; }
	.content-grid { display: grid; grid-template-columns: 340px 1fr; gap: 1.25rem; }
	.section-card { background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(168, 85, 247, 0.15); border-radius: 0.75rem; padding: 1.25rem; }
	.section-title { font-size: 1rem; font-weight: 600; color: #f1f5f9; margin: 0 0 1rem; }
	.section-desc { font-size: 0.8rem; color: #94a3b8; margin: 0.25rem 0 0; }
	.form-group { margin-bottom: 0.75rem; }
	.form-label { display: block; font-size: 0.75rem; color: #94a3b8; margin-bottom: 0.3rem; font-weight: 500; text-transform: uppercase; letter-spacing: 0.05em; }
	.form-input { width: 100%; padding: 0.55rem 0.75rem; border-radius: 0.5rem; border: 1px solid rgba(148, 163, 184, 0.15); background: rgba(15, 23, 42, 0.8); color: #f1f5f9; font-size: 0.85rem; box-sizing: border-box; transition: border-color 0.2s; }
	.form-input:focus { outline: none; border-color: #a855f7; box-shadow: 0 0 0 2px rgba(168, 85, 247, 0.15); }
	.form-input::placeholder { color: #475569; }
	.form-row { display: grid; grid-template-columns: 1fr 1fr; gap: 0.75rem; }
	.target-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 0.35rem; }
	.target-chip { display: flex; align-items: center; gap: 0.35rem; padding: 0.35rem 0.5rem; border: 1px solid rgba(148, 163, 184, 0.15); border-radius: 0.4rem; background: rgba(15, 23, 42, 0.6); cursor: pointer; font-size: 0.75rem; color: #94a3b8; transition: all 0.2s; }
	.target-chip.active { border-color: rgba(168, 85, 247, 0.4); background: rgba(168, 85, 247, 0.1); color: #c4b5fd; }
	.target-chip input[type="checkbox"], .target-chip input[type="radio"] { accent-color: #a855f7; width: 0.8rem; height: 0.8rem; }
	.target-chip:hover:not(.active) { border-color: rgba(148, 163, 184, 0.3); }
	.checkbox-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 0.35rem; margin-bottom: 0.75rem; }
	.button-group { display: flex; gap: 0.5rem; margin-top: 1rem; }
	.btn-primary { flex: 1; background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%); color: white; font-weight: 600; padding: 0.65rem 1.25rem; border: none; border-radius: 0.5rem; cursor: pointer; transition: all 0.2s; display: flex; align-items: center; justify-content: center; gap: 0.4rem; font-size: 0.85rem; }
	.btn-primary:hover:not(:disabled) { box-shadow: 0 4px 12px rgba(168, 85, 247, 0.4); transform: translateY(-1px); }
	.btn-primary:disabled { opacity: 0.5; cursor: not-allowed; }
	.btn-secondary { padding: 0.65rem 0.85rem; border: 1px solid rgba(148, 163, 184, 0.15); border-radius: 0.5rem; background: rgba(15, 23, 42, 0.6); color: #94a3b8; cursor: pointer; transition: all 0.2s; font-size: 0.85rem; }
	.btn-secondary:hover:not(:disabled) { border-color: rgba(239, 68, 68, 0.4); color: #f87171; }
	.spinner { width: 1rem; height: 1rem; border: 2px solid rgba(255,255,255,0.3); border-top-color: white; border-radius: 50%; animation: spin 0.6s linear infinite; display: inline-block; }
	@keyframes spin { to { transform: rotate(360deg); } }
	.error-card { display: flex; align-items: center; gap: 0.75rem; padding: 1rem; background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.2); border-radius: 0.5rem; }
	.error-icon { font-size: 1.5rem; }
	.error-text { color: #fca5a5; font-size: 0.85rem; word-break: break-all; }
	.result-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem; flex-wrap: wrap; gap: 0.5rem; }
	.result-header-actions { display: flex; align-items: center; gap: 0.5rem; }
	.result-score-badge { display: flex; flex-direction: column; align-items: center; padding: 0.5rem 1rem; border-radius: 0.5rem; border: 1px solid rgba(168, 85, 247, 0.3); background: rgba(168, 85, 247, 0.1); }
	.score-value { font-size: 1.5rem; font-weight: 700; color: #a855f7; line-height: 1; }
	.score-label { font-size: 0.65rem; color: #a855f7; opacity: 0.8; margin-top: 0.2rem; }
	.export-group { display: flex; gap: 0.3rem; }
	.export-btn { padding: 0.3rem 0.5rem; border-radius: 0.3rem; border: 1px solid rgba(148, 163, 184, 0.15); background: rgba(15, 23, 42, 0.4); color: #94a3b8; cursor: pointer; font-size: 0.7rem; transition: all 0.2s; }
	.export-btn:hover { border-color: rgba(168, 85, 247, 0.4); color: #c4b5fd; }
	.summary-bar { font-size: 0.8rem; color: #94a3b8; padding: 0.5rem 0.75rem; background: rgba(15, 23, 42, 0.4); border-radius: 0.4rem; margin-bottom: 1rem; border: 1px solid rgba(148, 163, 184, 0.08); display: flex; justify-content: space-between; align-items: center; }
	.duration-badge { font-size: 0.7rem; color: #a855f7; font-weight: 600; }
	.waf-alert { display: flex; align-items: center; gap: 0.75rem; padding: 0.75rem; background: rgba(245, 158, 11, 0.1); border: 1px solid rgba(245, 158, 11, 0.2); border-radius: 0.5rem; margin-bottom: 1rem; }
	.waf-icon { font-size: 1.5rem; }
	.waf-info { display: flex; flex-direction: column; gap: 0.15rem; }
	.waf-title { font-size: 0.85rem; font-weight: 600; color: #fbbf24; }
	.waf-evidence { font-size: 0.7rem; color: #d97706; }
	.ssl-info-bar { display: flex; align-items: center; gap: 0.75rem; padding: 0.6rem 0.75rem; background: rgba(34, 197, 94, 0.08); border: 1px solid rgba(34, 197, 94, 0.15); border-radius: 0.5rem; margin-bottom: 1rem; }
	.ssl-icon { font-size: 1.2rem; }
	.ssl-details { display: flex; flex-direction: column; gap: 0.1rem; min-width: 0; }
	.ssl-subject { font-size: 0.8rem; color: #86efac; font-weight: 500; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
	.ssl-meta { font-size: 0.7rem; color: #94a3b8; display: flex; align-items: center; gap: 0.5rem; }
	.ssl-expired { color: #ef4444; font-weight: 600; font-size: 0.65rem; }
	.sensitive-section { margin-bottom: 1rem; }
	.sensitive-header { font-size: 0.85rem; font-weight: 600; color: #fbbf24; margin-bottom: 0.5rem; }
	.sensitive-grid { display: flex; flex-wrap: wrap; gap: 0.35rem; }
	.sensitive-chip { display: flex; align-items: center; gap: 0.3rem; padding: 0.3rem 0.5rem; border: 1px solid; border-radius: 0.35rem; font-size: 0.72rem; }
	.sensitive-badge { font-size: 0.6rem; padding: 0.05rem 0.25rem; border-radius: 0.15rem; font-weight: 600; background: rgba(255,255,255,0.1); }
	.status-grid { display: flex; flex-wrap: wrap; gap: 0.4rem; }
	.status-chip { display: flex; align-items: center; gap: 0.3rem; padding: 0.35rem 0.6rem; border: 1px solid; border-radius: 0.4rem; font-size: 0.75rem; }
	.status-chip-label { font-size: 0.75rem; }
	.status-chip-count { font-size: 0.65rem; padding: 0.05rem 0.3rem; border-radius: 0.2rem; font-weight: 600; background: rgba(255, 255, 255, 0.1); }
	.result-tabs { display: flex; gap: 0.25rem; margin-bottom: 1rem; flex-wrap: wrap; }
	.result-tab { padding: 0.4rem 0.75rem; border-radius: 0.4rem; border: 1px solid rgba(148, 163, 184, 0.15); background: rgba(15, 23, 42, 0.4); color: #94a3b8; cursor: pointer; font-size: 0.8rem; transition: all 0.2s; }
	.result-tab.active { background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%); color: white; border-color: transparent; font-weight: 600; }
	.result-tab:hover:not(.active) { border-color: rgba(168, 85, 247, 0.3); color: #c4b5fd; }
	.overview-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 0.75rem; margin-bottom: 1rem; }
	.overview-stat { display: flex; flex-direction: column; align-items: center; padding: 0.75rem; background: rgba(15, 23, 42, 0.4); border: 1px solid rgba(148, 163, 184, 0.08); border-radius: 0.5rem; }
	.stat-icon { font-size: 1.2rem; margin-bottom: 0.25rem; }
	.stat-value { font-size: 1.25rem; font-weight: 700; color: #f1f5f9; }
	.stat-label { font-size: 0.7rem; color: #94a3b8; margin-top: 0.15rem; }
	.subsection-title { font-size: 0.9rem; font-weight: 600; color: #e2e8f0; margin: 1rem 0 0.5rem; }
	.tech-grid { display: flex; flex-wrap: wrap; gap: 0.4rem; }
	.tech-chip { display: flex; align-items: center; gap: 0.3rem; padding: 0.35rem 0.6rem; background: rgba(168, 85, 247, 0.1); border: 1px solid rgba(168, 85, 247, 0.2); border-radius: 0.4rem; font-size: 0.75rem; color: #c4b5fd; }
	.tech-icon { font-size: 0.8rem; }
	.tech-name { font-size: 0.75rem; }
	.tech-count { font-size: 0.65rem; padding: 0.05rem 0.3rem; background: rgba(168, 85, 247, 0.2); border-radius: 0.2rem; font-weight: 600; }
	.tech-version-mini { font-size: 0.55rem; padding: 0.05rem 0.25rem; background: rgba(34, 197, 94, 0.15); color: #86efac; border-radius: 0.2rem; font-weight: 600; font-family: 'SF Mono', 'Fira Code', monospace; }
	.status-mini { font-size: 0.7rem; font-weight: 600; }
	.depth-mini { font-size: 0.55rem; padding: 0.05rem 0.2rem; background: rgba(59, 130, 246, 0.15); color: #93c5fd; border-radius: 0.15rem; font-weight: 600; }
	.depth-badge { font-size: 0.65rem; padding: 0.1rem 0.3rem; background: rgba(59, 130, 246, 0.15); color: #93c5fd; border-radius: 0.2rem; font-weight: 600; }
	.filter-bar { display: flex; gap: 0.3rem; margin-bottom: 0.75rem; flex-wrap: wrap; }
	.filter-btn { padding: 0.35rem 0.6rem; border-radius: 0.3rem; border: 1px solid rgba(148, 163, 184, 0.15); background: rgba(15, 23, 42, 0.4); color: #94a3b8; cursor: pointer; font-size: 0.75rem; transition: all 0.2s; }
	.filter-btn.active { background: rgba(168, 85, 247, 0.15); border-color: rgba(168, 85, 247, 0.4); color: #c4b5fd; }
	.filter-btn:hover:not(.active) { border-color: rgba(148, 163, 184, 0.3); }
	.search-bar { margin-bottom: 0.75rem; }
	.search-input { width: 100%; padding: 0.45rem 0.75rem; border-radius: 0.4rem; border: 1px solid rgba(148, 163, 184, 0.15); background: rgba(15, 23, 42, 0.6); color: #f1f5f9; font-size: 0.8rem; box-sizing: border-box; }
	.search-input:focus { outline: none; border-color: #a855f7; }
	.search-input::placeholder { color: #475569; }
	.links-table-wrapper { max-height: 500px; overflow-y: auto; border-radius: 0.5rem; border: 1px solid rgba(148, 163, 184, 0.08); }
	.data-table { width: 100%; border-collapse: collapse; font-size: 0.8rem; }
	.data-table th { text-align: left; padding: 0.5rem 0.6rem; background: rgba(15, 23, 42, 0.6); color: #94a3b8; font-weight: 500; font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.05em; border-bottom: 1px solid rgba(148, 163, 184, 0.1); position: sticky; top: 0; z-index: 1; }
	.data-table td { padding: 0.4rem 0.6rem; border-bottom: 1px solid rgba(148, 163, 184, 0.06); color: #cbd5e1; }
	.data-table tr:hover td { background: rgba(168, 85, 247, 0.05); }
	.status-badge-table { display: inline-block; padding: 0.15rem 0.4rem; border-radius: 0.25rem; font-size: 0.7rem; font-weight: 600; border: 1px solid; }
	.path-cell { display: flex; align-items: center; gap: 0.3rem; font-weight: 500; color: #f1f5f9; font-family: 'SF Mono', 'Fira Code', monospace; font-size: 0.8rem; }
	.content-type-badge { font-size: 0.7rem; color: #94a3b8; max-width: 150px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; display: block; }
	.size-text { font-size: 0.75rem; color: #86efac; font-family: 'SF Mono', 'Fira Code', monospace; }
	.time-text { font-size: 0.75rem; color: #94a3b8; font-family: 'SF Mono', 'Fira Code', monospace; }
	.redirect-text { font-size: 0.7rem; color: #3b82f6; max-width: 150px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; display: block; }
	.text-muted { color: #475569; }
	.category-section { margin-bottom: 1rem; }
	.category-header { display: flex; align-items: center; gap: 0.5rem; padding: 0.5rem 0.75rem; background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(168, 85, 247, 0.15); border-radius: 0.5rem; margin-bottom: 0.5rem; }
	.category-icon { font-size: 1rem; }
	.category-name { font-weight: 600; font-size: 0.9rem; color: #e2e8f0; }
	.category-count { margin-left: auto; font-size: 0.75rem; padding: 0.1rem 0.4rem; border-radius: 0.25rem; font-weight: 600; }
	.category-techs { display: flex; flex-direction: column; gap: 0.3rem; }
	.category-tech-item { display: flex; justify-content: space-between; align-items: center; padding: 0.4rem 0.6rem; background: rgba(15, 23, 42, 0.4); border-radius: 0.3rem; border: 1px solid rgba(148, 163, 184, 0.06); }
	.category-tech-item:hover { background: rgba(168, 85, 247, 0.05); }
	.cti-left { display: flex; align-items: center; gap: 0.35rem; }
	.cti-name { font-size: 0.85rem; font-weight: 500; color: #e2e8f0; font-family: 'SF Mono', 'Fira Code', monospace; }
	.cti-right { display: flex; align-items: center; gap: 0.5rem; }
	.method-mini { font-size: 0.7rem; color: #64748b; }
	.sensitive-list { display: flex; flex-direction: column; gap: 0.4rem; }
	.sensitive-item { padding: 0.6rem 0.75rem; background: rgba(15, 23, 42, 0.4); border-radius: 0.4rem; }
	.si-header { display: flex; align-items: center; gap: 0.4rem; margin-bottom: 0.2rem; flex-wrap: wrap; }
	.si-icon { font-size: 0.85rem; }
	.si-path { font-size: 0.85rem; font-weight: 600; color: #f1f5f9; font-family: 'SF Mono', 'Fira Code', monospace; }
	.si-severity { font-size: 0.65rem; padding: 0.1rem 0.35rem; border-radius: 0.2rem; font-weight: 600; }
	.si-category { font-size: 0.7rem; color: #94a3b8; text-transform: capitalize; }
	.si-desc { font-size: 0.75rem; color: #94a3b8; padding-left: 1.5rem; }
	.empty-mini { text-align: center; padding: 2rem; color: #94a3b8; font-size: 0.85rem; }
	.empty-state { text-align: center; padding: 3rem 1rem; }
	.empty-icon { font-size: 3rem; margin-bottom: 0.75rem; opacity: 0.5; }
	.empty-text { color: #94a3b8; font-size: 1rem; margin: 0 0 0.25rem; }
	.empty-sub { color: #475569; font-size: 0.8rem; margin: 0; }

	@media (max-width: 768px) {
		.content-grid { grid-template-columns: 1fr; }
		.overview-grid { grid-template-columns: repeat(2, 1fr); }
		.checkbox-grid { grid-template-columns: 1fr; }
	}

	.input-with-action { display: flex; gap: 0.5rem; }
	.input-with-action .form-input { flex: 1; }
	.action-btn { padding: 0.5rem 0.75rem; border: 1px solid rgba(168, 85, 247, 0.3); border-radius: 0.5rem; background: rgba(168, 85, 247, 0.1); color: #c4b5fd; cursor: pointer; font-size: 1rem; transition: all 0.2s; white-space: nowrap; }
	.action-btn:hover:not(:disabled) { background: rgba(168, 85, 247, 0.2); border-color: rgba(168, 85, 247, 0.5); }
	.action-btn:disabled { opacity: 0.5; cursor: not-allowed; }

	.modal-overlay { position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0, 0, 0, 0.6); display: flex; align-items: center; justify-content: center; z-index: 1000; }
	.modal-content { background: #1e293b; border: 1px solid rgba(168, 85, 247, 0.2); border-radius: 0.75rem; width: 90%; max-width: 500px; max-height: 80vh; display: flex; flex-direction: column; }
	.modal-header { display: flex; justify-content: space-between; align-items: center; padding: 1rem 1.25rem; border-bottom: 1px solid rgba(148, 163, 184, 0.1); }
	.modal-header h3 { margin: 0; color: #f1f5f9; font-size: 1rem; }
	.modal-close { background: none; border: none; color: #94a3b8; cursor: pointer; font-size: 1.2rem; }
	.modal-body { padding: 1rem 1.25rem; overflow-y: auto; flex: 1; }
	.modal-footer { display: flex; justify-content: flex-end; align-items: center; gap: 0.75rem; padding: 0.75rem 1.25rem; border-top: 1px solid rgba(148, 163, 184, 0.1); }
	.selected-count { flex: 1; color: #94a3b8; font-size: 0.8rem; }
	.target-list { max-height: 300px; overflow-y: auto; display: flex; flex-direction: column; gap: 0.25rem; }
	.target-select-item { display: flex; align-items: center; gap: 0.5rem; padding: 0.5rem 0.75rem; border-radius: 0.4rem; cursor: pointer; transition: background 0.2s; color: #cbd5e1; font-size: 0.85rem; }
	.target-select-item:hover { background: rgba(168, 85, 247, 0.08); }
	.target-select-item.selected { background: rgba(168, 85, 247, 0.15); border: 1px solid rgba(168, 85, 247, 0.3); }
	.target-select-item input[type="checkbox"] { accent-color: #a855f7; }
	.loading-state, .empty-state { text-align: center; padding: 2rem; color: #94a3b8; }
	.spinner { display: inline-block; width: 1rem; height: 1rem; border: 2px solid rgba(168, 85, 247, 0.2); border-top-color: #a855f7; border-radius: 50%; animation: spin 0.8s linear infinite; }
	@keyframes spin { to { transform: rotate(360deg); } }
	.btn-primary-sm { padding: 0.4rem 1rem; border: none; border-radius: 0.4rem; background: linear-gradient(135deg, #a855f7, #6366f1); color: white; cursor: pointer; font-size: 0.8rem; font-weight: 600; }
	.btn-primary-sm:disabled { opacity: 0.5; cursor: not-allowed; }
	.btn-secondary { padding: 0.4rem 1rem; border: 1px solid rgba(148, 163, 184, 0.2); border-radius: 0.4rem; background: transparent; color: #94a3b8; cursor: pointer; font-size: 0.8rem; }
</style>
