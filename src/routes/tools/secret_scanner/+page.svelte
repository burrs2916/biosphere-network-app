<script lang="ts">
	import { tr } from '$lib/i18n';
	import ToolHistory from '$lib/components/ToolHistory.svelte';
	import ToolHelp from '$lib/components/ToolHelp.svelte';

	interface DetectedSecret {
		secret_type: string;
		category: string;
		severity: string;
		value_preview: string;
		full_value: string;
		source_url: string;
		source_type: string;
		line_context: string;
		line_number: number | null;
		confidence: number;
		is_custom: boolean;
		remediation: string;
	}

	interface SeverityStats {
		critical: number;
		high: number;
		medium: number;
		low: number;
		info: number;
	}

	interface CategoryStat {
		category: string;
		count: number;
		critical_count: number;
		high_count: number;
	}

	interface SecretScanResult {
		url: string;
		secrets: DetectedSecret[];
		pages_scanned: number;
		js_files_scanned: number;
		css_files_scanned: number;
		scan_duration_ms: number;
		summary: string;
		severity_stats: SeverityStats;
		category_stats: CategoryStat[];
		urls_scanned: string[];
		duplicate_count: number;
	}

	let url = $state('');
	let activeMainTab = $state('analyze');
	let activeResultTab = $state('overview');
	let historyComponent: ToolHistory;
	let scanMode = $state('balanced');
	let timeout = $state(15);
	let maxPages = $state(20);
	let crawlDepth = $state(1);
	let concurrentRequests = $state(5);
	let scanJs = $state(true);
	let scanHtml = $state(true);
	let scanComments = $state(true);
	let scanCss = $state(false);
	let scanMeta = $state(true);
	let showAdvanced = $state(false);
	let minConfidence = $state(0.5);
	let severityFilter = $state('');
	let customPatternInput = $state('');
	let customPatterns = $state<string[]>([]);
	let proxyUrl = $state('');
	let followRedirects = $state(true);
	let verifySsl = $state(false);
	let deduplicate = $state(true);
	let result: SecretScanResult | null = $state(null);
	let error = $state('');
	let processing = $state(false);
	let showFullValue: string | null = $state(null);
	let searchQuery = $state('');
	let listFilter = $state('all');
	let exportFormat = $state('json');
	let copiedId = $state('');
	let selectedSecret: DetectedSecret | null = $state(null);

	function applyScanMode(mode: string) {
		scanMode = mode;
		switch (mode) {
			case 'quick': maxPages = 5; crawlDepth = 0; concurrentRequests = 3; break;
			case 'balanced': maxPages = 20; crawlDepth = 1; concurrentRequests = 5; break;
			case 'deep': maxPages = 50; crawlDepth = 2; concurrentRequests = 8; break;
			case 'full': maxPages = 100; crawlDepth = 3; concurrentRequests = 10; break;
		}
	}

	function getScanModeLabel(mode: string): string {
		switch (mode) {
			case 'quick': return $tr('secretScanner.modeQuick');
			case 'balanced': return $tr('secretScanner.modeBalanced');
			case 'deep': return $tr('secretScanner.modeDeep');
			case 'full': return $tr('secretScanner.modeFull');
			default: return mode;
		}
	}

	function addCustomPattern() {
		const p = customPatternInput.trim();
		if (p && !customPatterns.includes(p)) {
			customPatterns = [...customPatterns, p];
			customPatternInput = '';
		}
	}

	function removeCustomPattern(p: string) {
		customPatterns = customPatterns.filter(x => x !== p);
	}

	function getSeverityColor(s: string): string {
		switch (s) {
			case 'critical': return '#ef4444';
			case 'high': return '#f97316';
			case 'medium': return '#eab308';
			case 'low': return '#22c55e';
			case 'info': return '#3b82f6';
			default: return '#94a3b8';
		}
	}

	function getSeverityIcon(s: string): string {
		switch (s) {
			case 'critical': return '🔴';
			case 'high': return '🟠';
			case 'medium': return '🟡';
			case 'low': return '🟢';
			default: return 'ℹ️';
		}
	}

	function getCategoryIcon(c: string): string {
		switch (c) {
			case 'Cloud': return '☁️';
			case 'API Key': return '🔑';
			case 'Payment': return '💳';
			case 'Crypto': return '🔐';
			case 'Database': return '🗄️';
			case 'Credential': return '🗝️';
			case 'Email': return '📧';
			case 'Messaging': return '💬';
			case 'Comment': return '💬';
			case 'Config': return '⚙️';
			case 'Custom': return '✏️';
			case 'Meta': return '🏷️';
			default: return '🔍';
		}
	}

	function getFilteredSecrets(): DetectedSecret[] {
		if (!result) return [];
		let secrets = result.secrets;
		if (listFilter === 'critical') secrets = secrets.filter(s => s.severity === 'critical');
		else if (listFilter === 'high') secrets = secrets.filter(s => s.severity === 'high');
		else if (listFilter === 'medium') secrets = secrets.filter(s => s.severity === 'medium');
		else if (listFilter === 'low') secrets = secrets.filter(s => s.severity === 'low');
		else if (listFilter === 'info') secrets = secrets.filter(s => s.severity === 'info');
		if (searchQuery.trim()) {
			const q = searchQuery.toLowerCase();
			secrets = secrets.filter(s =>
				s.secret_type.toLowerCase().includes(q) ||
				s.category.toLowerCase().includes(q) ||
				s.value_preview.toLowerCase().includes(q) ||
				s.source_url.toLowerCase().includes(q)
			);
		}
		return secrets;
	}

	async function scan() {
		if (!url.trim()) { error = $tr('secretScanner.error.emptyInput'); return; }
		processing = true; error = ''; result = null;
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			result = await invoke<SecretScanResult>('scan_secrets_command', {
				config: {
					url: url.trim(),
					timeout,
					scan_js: scanJs,
					scan_html: scanHtml,
					scan_comments: scanComments,
					max_pages: maxPages,
					custom_patterns: customPatterns,
					min_confidence: minConfidence,
					severity_filter: severityFilter || null,
					scan_mode: scanMode,
					crawl_depth: crawlDepth,
					concurrent_requests: concurrentRequests,
					user_agent: null,
					proxy_url: proxyUrl || null,
					follow_redirects: followRedirects,
					verify_ssl: verifySsl,
					scan_css: scanCss,
					scan_meta: scanMeta,
					deduplicate,
				}
			});
			if (result && historyComponent) {
				await historyComponent.saveHistory(url.trim(), JSON.stringify(result), result.summary, 'completed');
			}
		} catch (e: any) {
			error = e.toString();
			if (historyComponent) {
				await historyComponent.saveHistory(url.trim(), JSON.stringify({ error: e.toString() }), undefined, 'failed');
			}
		} finally { processing = false; }
	}

	async function exportResults() {
		if (!result) return;
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			const { open } = await import('@tauri-apps/plugin-dialog');
			const savePath = await open({ directory: true, multiple: false, title: $tr('secretScanner.selectSaveDir') });
			if (!savePath) return;
			const ext = exportFormat === 'csv' ? 'csv' : 'json';
			const fileName = `secret-scan-${new Date().toISOString().slice(0, 10)}.${ext}`;
			let content: string;
			if (exportFormat === 'csv') {
				const header = 'Type,Category,Severity,Preview,Source,Line,Confidence,Remediation';
				const rows = result.secrets.map(s =>
					`"${s.secret_type}","${s.category}","${s.severity}","${s.value_preview.replace(/"/g, '""')}","${s.source_url}","${s.line_number || '-'}","${(s.confidence * 100).toFixed(0)}%","${s.remediation.replace(/"/g, '""')}"`
				);
				content = [header, ...rows].join('\n');
			} else {
				content = JSON.stringify(result, null, 2);
			}
			const { writeTextFile } = await import('@tauri-apps/plugin-fs');
			await writeTextFile(`${savePath}/${fileName}`, content);
		} catch (e: any) {
			console.error('Export failed:', e);
		}
	}

	function copyToClipboard(text: string) {
		navigator.clipboard.writeText(text);
		copiedId = text;
		setTimeout(() => { copiedId = ''; }, 2000);
	}

	function clearAll() {
		url = ''; result = null; error = '';
		listFilter = 'all'; searchQuery = '';
		activeResultTab = 'overview';
		selectedSecret = null;
		showFullValue = null;
	}

	function handleKeydown(e: KeyboardEvent) {
		if (e.key === 'Enter' && !processing && url.trim()) {
			scan();
		}
	}
</script>

<svelte:window on:keydown={handleKeydown} />

<div class="nd-page">
	<div class="page-header">
		<div class="header-left">
			<a href="/" class="back-link">{$tr('common.backToHome')}</a>
			<h1 class="page-title">🔑 {$tr('secretScanner.title')}</h1>
			<p class="page-subtitle">{$tr('secretScanner.subtitle')}</p>
		</div>
	</div>

	<div class="tabs">
		<button class="tab-btn {activeMainTab === 'analyze' ? 'active' : ''}" on:click={() => activeMainTab = 'analyze'}>
			<span class="tab-icon">🔍</span> {$tr('secretScanner.tabScan')}
		</button>
		<button class="tab-btn {activeMainTab === 'history' ? 'active' : ''}" on:click={() => activeMainTab = 'history'}>
			<span class="tab-icon">📋</span> {$tr('secretScanner.tabHistory')}
		</button>
		<button class="tab-btn {activeMainTab === 'help' ? 'active' : ''}" on:click={() => activeMainTab = 'help'}>
			<span class="tab-icon">📖</span> {$tr('secretScanner.tabHelp')}
		</button>
	</div>

	{#if activeMainTab === 'analyze'}
		<div class="content-grid">
			<div class="input-section">
				<div class="section-card">
					<h2 class="section-title">{$tr('secretScanner.configTitle')}</h2>
					<p class="section-desc">{$tr('secretScanner.configDesc')}</p>

					<div class="form-group">
						<label class="form-label">{$tr('secretScanner.targetUrl')}</label>
						<input type="text" bind:value={url} placeholder="https://example.com" class="form-input" disabled={processing} />
					</div>

					<div class="form-group">
						<label class="form-label">{$tr('secretScanner.scanMode')}</label>
						<div class="mode-grid">
							{#each ['quick', 'balanced', 'deep', 'full'] as mode}
								<button class="mode-btn {scanMode === mode ? 'active' : ''}" on:click={() => applyScanMode(mode)} disabled={processing}>
									<span class="mode-name">{getScanModeLabel(mode)}</span>
								</button>
							{/each}
						</div>
					</div>

					<div class="form-row">
						<div class="form-group">
							<label class="form-label">{$tr('secretScanner.crawlDepth')}</label>
							<input type="number" bind:value={crawlDepth} class="form-input" min="0" max="5" disabled={processing} />
						</div>
						<div class="form-group">
							<label class="form-label">{$tr('secretScanner.maxPages')}</label>
							<input type="number" bind:value={maxPages} class="form-input" min="1" max="500" disabled={processing} />
						</div>
					</div>

					<div class="form-row">
						<div class="form-group">
							<label class="form-label">{$tr('secretScanner.timeout')}</label>
							<input type="number" bind:value={timeout} class="form-input" min="5" max="120" disabled={processing} />
						</div>
						<div class="form-group">
							<label class="form-label">{$tr('secretScanner.concurrent')}</label>
							<input type="number" bind:value={concurrentRequests} class="form-input" min="1" max="20" disabled={processing} />
						</div>
					</div>

					<div class="form-group">
						<label class="form-label">{$tr('secretScanner.scanTargets')}</label>
						<div class="target-grid">
							<label class="target-chip {scanHtml ? 'active' : ''}">
								<input type="checkbox" bind:checked={scanHtml} disabled={processing} />
								<span>🌐 HTML</span>
							</label>
							<label class="target-chip {scanJs ? 'active' : ''}">
								<input type="checkbox" bind:checked={scanJs} disabled={processing} />
								<span>📜 JS</span>
							</label>
							<label class="target-chip {scanCss ? 'active' : ''}">
								<input type="checkbox" bind:checked={scanCss} disabled={processing} />
								<span>🎨 CSS</span>
							</label>
							<label class="target-chip {scanComments ? 'active' : ''}">
								<input type="checkbox" bind:checked={scanComments} disabled={processing} />
								<span>💬 {$tr('secretScanner.comments')}</span>
							</label>
							<label class="target-chip {scanMeta ? 'active' : ''}">
								<input type="checkbox" bind:checked={scanMeta} disabled={processing} />
								<span>🏷️ Meta</span>
							</label>
							<label class="target-chip {deduplicate ? 'active' : ''}">
								<input type="checkbox" bind:checked={deduplicate} disabled={processing} />
								<span>🔄 {$tr('secretScanner.deduplicate')}</span>
							</label>
						</div>
					</div>

					<div class="form-group">
						<button class="target-chip {showAdvanced ? 'active' : ''}" on:click={() => showAdvanced = !showAdvanced}>
							<span>⚙️ {$tr('secretScanner.advancedOptions')}</span>
						</button>
					</div>

					{#if showAdvanced}
						<div class="form-row">
							<div class="form-group">
								<label class="form-label">{$tr('secretScanner.minConfidence')}</label>
								<input type="number" bind:value={minConfidence} class="form-input" min="0" max="1" step="0.1" disabled={processing} />
							</div>
							<div class="form-group">
								<label class="form-label">{$tr('secretScanner.severityFilter')}</label>
								<select bind:value={severityFilter} class="form-input" disabled={processing}>
									<option value="">{$tr('secretScanner.allSeverities')}</option>
									<option value="critical">🔴 Critical</option>
									<option value="high">🟠 High</option>
									<option value="medium">🟡 Medium</option>
									<option value="low">🟢 Low</option>
									<option value="info">ℹ️ Info</option>
								</select>
							</div>
						</div>

						<div class="form-row">
							<div class="form-group">
								<label class="form-label">🌐 Proxy URL</label>
								<input type="text" bind:value={proxyUrl} placeholder="http://proxy:port" class="form-input" disabled={processing} />
							</div>
							<div class="form-group">
								<label class="form-label">🔗 {$tr('secretScanner.redirects')}</label>
								<select bind:value={followRedirects} class="form-input" disabled={processing}>
									<option value={true}>{$tr('secretScanner.followRedirects')}</option>
									<option value={false}>{$tr('secretScanner.noRedirects')}</option>
								</select>
							</div>
						</div>

						<div class="form-group">
							<label class="target-chip {verifySsl ? 'active' : ''}">
								<input type="checkbox" bind:checked={verifySsl} disabled={processing} />
								<span>🔒 {$tr('secretScanner.verifySsl')}</span>
							</label>
						</div>

						<div class="form-group">
							<label class="form-label">{$tr('secretScanner.customPatterns')}</label>
							<div class="custom-pattern-input">
								<input type="text" bind:value={customPatternInput} placeholder="e.g. api_key=..." class="form-input" disabled={processing} />
								<button class="btn-add-pattern" on:click={addCustomPattern} disabled={processing || !customPatternInput.trim()}>+</button>
							</div>
							{#if customPatterns.length > 0}
								<div class="pattern-tags">
									{#each customPatterns as p}
										<span class="pattern-tag">
											<code>{p}</code>
											<button class="tag-remove" on:click={() => removeCustomPattern(p)}>✕</button>
										</span>
									{/each}
								</div>
							{/if}
						</div>
					{/if}

					<div class="button-group">
						<button class="btn-primary" on:click={scan} disabled={processing || !url.trim()}>
							{#if processing}<span class="spinner"></span>{$tr('secretScanner.scanning')}{:else}🔍 {$tr('secretScanner.startScan')}{/if}
						</button>
						<button class="btn-secondary" on:click={clearAll} disabled={processing}>🗑️</button>
					</div>
				</div>
			</div>

			<div class="result-section">
				<div class="section-card">
					{#if error}
						<div class="error-card">
							<span class="error-icon">⚠️</span>
							<span class="error-text">{error}</span>
						</div>
					{:else if result}
						<div class="result-header">
							<div class="result-domain">
								<h2 class="section-title" style="margin-bottom:0">🔑 {result.url}</h2>
							</div>
							<div class="header-actions">
								<div class="resource-score-badge">
									<span class="score-value">{result.secrets.length}</span>
									<span class="score-label">{$tr('secretScanner.topSecrets')}</span>
								</div>
								<select bind:value={exportFormat} class="export-select">
									<option value="json">JSON</option>
									<option value="csv">CSV</option>
								</select>
								<button class="btn-export" on:click={exportResults} disabled={!result}>
									📤 {$tr('secretScanner.export')}
								</button>
							</div>
						</div>

						<div class="summary-bar">{result.summary}</div>

						<div class="result-tabs">
							<button class="result-tab {activeResultTab === 'overview' ? 'active' : ''}" on:click={() => activeResultTab = 'overview'}>
								📊 {$tr('secretScanner.tabOverview')}
							</button>
							<button class="result-tab {activeResultTab === 'list' ? 'active' : ''}" on:click={() => activeResultTab = 'list'}>
								📋 {$tr('secretScanner.tabList')} ({result.secrets.length})
							</button>
							<button class="result-tab {activeResultTab === 'categories' ? 'active' : ''}" on:click={() => activeResultTab = 'categories'}>
								📂 {$tr('secretScanner.tabCategories')} ({result.category_stats.length})
							</button>
							<button class="result-tab {activeResultTab === 'urls' ? 'active' : ''}" on:click={() => activeResultTab = 'urls'}>
								🌐 {$tr('secretScanner.scannedUrls')} ({result.urls_scanned.length})
							</button>
						</div>

						{#if activeResultTab === 'overview'}
							<div class="overview-grid">
								<div class="overview-stat">
									<span class="stat-label">📄 {$tr('secretScanner.pagesScanned')}</span>
									<span class="stat-value">{result.pages_scanned}</span>
								</div>
								<div class="overview-stat">
									<span class="stat-label">📜 JS</span>
									<span class="stat-value" style="color: {result.js_files_scanned > 0 ? '#f59e0b' : '#64748b'}">{result.js_files_scanned}</span>
								</div>
								<div class="overview-stat">
									<span class="stat-label">🎨 CSS</span>
									<span class="stat-value" style="color: {result.css_files_scanned > 0 ? '#a855f7' : '#64748b'}">{result.css_files_scanned}</span>
								</div>
								<div class="overview-stat">
									<span class="stat-label">⏱️ {$tr('secretScanner.scanDuration')}</span>
									<span class="stat-value">{result.scan_duration_ms < 1000 ? result.scan_duration_ms + 'ms' : (result.scan_duration_ms / 1000).toFixed(1) + 's'}</span>
								</div>
							</div>

							{#if result.duplicate_count > 0}
								<div class="info-bar">
									🔄 {$tr('secretScanner.duplicatesRemoved', { count: result.duplicate_count })}
								</div>
							{/if}

							<h3 class="subsection-title">📊 {$tr('secretScanner.severityDistribution')}</h3>
							<div class="severity-grid">
								{#each [
									{ key: 'critical', label: '🔴 Critical', count: result.severity_stats.critical },
									{ key: 'high', label: '🟠 High', count: result.severity_stats.high },
									{ key: 'medium', label: '🟡 Medium', count: result.severity_stats.medium },
									{ key: 'low', label: '🟢 Low', count: result.severity_stats.low },
									{ key: 'info', label: 'ℹ️ Info', count: result.severity_stats.info },
								] as item}
									<div class="severity-stat" style="border-color: {getSeverityColor(item.key)}30; background: {getSeverityColor(item.key)}08;">
										<span class="severity-label">{item.label}</span>
										<span class="severity-count" style="color: {getSeverityColor(item.key)}">{item.count}</span>
										<div class="severity-bar-bg">
											<div class="severity-bar-fill" style="width: {result.secrets.length > 0 ? (item.count / result.secrets.length * 100) : 0}%; background: {getSeverityColor(item.key)};"></div>
										</div>
									</div>
								{/each}
							</div>

							{#if result.secrets.length > 0}
								<h3 class="subsection-title">🔑 {$tr('secretScanner.topSecrets')}</h3>
								<div class="top-secrets-list">
									{#each result.secrets.slice(0, 5) as secret, i}
										<div class="top-secret-item" on:click={() => { selectedSecret = secret; activeResultTab = 'list'; }}>
											<span class="severity-dot" style="background: {getSeverityColor(secret.severity)};"></span>
											<span class="secret-type-label">{getCategoryIcon(secret.category)} {secret.secret_type}</span>
											<code class="secret-preview">{secret.value_preview}</code>
											<span class="confidence-mini" style="color: {getSeverityColor(secret.severity)};">{(secret.confidence * 100).toFixed(0)}%</span>
										</div>
									{/each}
									{#if result.secrets.length > 5}
										<div class="more-link" on:click={() => activeResultTab = 'list'}>
											{$tr('secretScanner.viewAll')} ({result.secrets.length}) →
										</div>
									{/if}
								</div>
							{:else}
								<div class="empty-state">
									<div class="empty-icon">✅</div>
									<p>{$tr('secretScanner.noSecrets')}</p>
								</div>
							{/if}

						{:else if activeResultTab === 'list'}
							<div class="filter-bar">
								<button class="filter-btn {listFilter === 'all' ? 'active' : ''}" on:click={() => listFilter = 'all'}>
									{$tr('secretScanner.all')} ({result.secrets.length})
								</button>
								<button class="filter-btn {listFilter === 'critical' ? 'active' : ''}" on:click={() => listFilter = 'critical'}>
									🔴 Critical ({result.severity_stats.critical})
								</button>
								<button class="filter-btn {listFilter === 'high' ? 'active' : ''}" on:click={() => listFilter = 'high'}>
									🟠 High ({result.severity_stats.high})
								</button>
								<button class="filter-btn {listFilter === 'medium' ? 'active' : ''}" on:click={() => listFilter = 'medium'}>
									🟡 Medium ({result.severity_stats.medium})
								</button>
								<button class="filter-btn {listFilter === 'low' ? 'active' : ''}" on:click={() => listFilter = 'low'}>
									🟢 Low ({result.severity_stats.low})
								</button>
							</div>

							<div class="search-bar">
								<input type="text" bind:value={searchQuery} placeholder="{$tr('secretScanner.searchPlaceholder')}" class="search-input" />
							</div>

							{#if getFilteredSecrets().length > 0}
								<div class="links-table-wrapper">
									<table class="data-table">
										<thead>
											<tr>
												<th>{$tr('secretScanner.severityFilter')}</th>
												<th>Type</th>
												<th>Category</th>
												<th>Preview</th>
												<th>Source</th>
												<th>Line</th>
												<th>Confidence</th>
											</tr>
										</thead>
										<tbody>
											{#each getFilteredSecrets().slice(0, 100) as secret, i}
												<tr>
													<td>
														<span class="severity-badge" style="background: {getSeverityColor(secret.severity)}15; color: {getSeverityColor(secret.severity)}; border: 1px solid {getSeverityColor(secret.severity)}40">
															{getSeverityIcon(secret.severity)} {secret.severity.toUpperCase()}
														</span>
													</td>
													<td class="secret-type-cell">{secret.secret_type}</td>
													<td>
														<span class="category-chip">{getCategoryIcon(secret.category)} {secret.category}</span>
													</td>
													<td class="mono">
														<div class="preview-cell">
															<code>{secret.value_preview}</code>
															<button class="btn-dl-single" on:click={() => copyToClipboard(secret.full_value)} title="Copy">
																{copiedId === secret.full_value ? '✅' : '📋'}
															</button>
															<button class="btn-dl-single" on:click={() => showFullValue = showFullValue === String(i) ? null : String(i)}>
																{showFullValue === String(i) ? '▲' : '▼'}
															</button>
														</div>
														{#if showFullValue === String(i)}
															<div class="full-value-block"><code>{secret.full_value}</code></div>
														{/if}
														{#if secret.line_context}
															<div class="context-block">
																<span class="context-label">{$tr('secretScanner.context')}:</span>
																<code>{secret.line_context}</code>
															</div>
														{/if}
													</td>
													<td class="mono">
														<a href={secret.source_url} target="_blank" class="link-url">{secret.source_type}</a>
													</td>
													<td>
														<span class="depth-badge">{secret.line_number ? 'L' + secret.line_number : '-'}</span>
													</td>
													<td>
														<span style="color: {getSeverityColor(secret.severity)}; font-weight: 600;">{(secret.confidence * 100).toFixed(0)}%</span>
													</td>
												</tr>
											{/each}
										</tbody>
									</table>
								</div>
								{#if getFilteredSecrets().length > 100}
									<div class="table-footer">{$tr('secretScanner.showingFirst')} 100 / {getFilteredSecrets().length}</div>
								{/if}
							{:else}
								<div class="empty-state">
									<div class="empty-icon">🔍</div>
									<p>{$tr('secretScanner.noMatchingResults')}</p>
								</div>
							{/if}

						{:else if activeResultTab === 'categories'}
							{#if result.category_stats.length > 0}
								<div class="category-grid">
									{#each result.category_stats as cat}
										<div class="category-card">
											<div class="category-header">
												<span class="category-icon">{getCategoryIcon(cat.category)}</span>
												<span class="category-name">{cat.category}</span>
												<span class="category-count">{cat.count}</span>
											</div>
											<div class="category-detail">
												{#if cat.critical_count > 0}
													<span class="cat-sev" style="color: #ef4444;">🔴 {cat.critical_count}</span>
												{/if}
												{#if cat.high_count > 0}
													<span class="cat-sev" style="color: #f97316;">🟠 {cat.high_count}</span>
												{/if}
											</div>
											<div class="category-bar-bg">
												<div class="category-bar-fill" style="width: {cat.count / result.secrets.length * 100}%; background: #a855f7;"></div>
											</div>
										</div>
									{/each}
								</div>
							{:else}
								<div class="empty-state">
									<div class="empty-icon">📂</div>
									<p>{$tr('secretScanner.noSecrets')}</p>
								</div>
							{/if}

						{:else if activeResultTab === 'urls'}
							{#if result.urls_scanned.length > 0}
								<div class="url-list">
									{#each result.urls_scanned as scannedUrl}
										<div class="url-item">
											<span class="url-icon">🌐</span>
											<a href={scannedUrl} target="_blank" class="link-url">{scannedUrl}</a>
										</div>
									{/each}
								</div>
							{:else}
								<div class="empty-state">
									<div class="empty-icon">🌐</div>
									<p>{$tr('secretScanner.noScannedUrls')}</p>
								</div>
							{/if}
						{/if}

					{:else}
						<div class="empty-state">
							<div class="empty-icon">🔑</div>
							<p>{$tr('secretScanner.emptyState')}</p>
						</div>
					{/if}
				</div>
			</div>
		</div>
	{:else if activeMainTab === 'history'}
		<div class="section-card">
			<ToolHistory toolType="secret_scanner" toolName={$tr('secretScanner.title')} bind:this={historyComponent} />
		</div>
	{:else if activeMainTab === 'help'}
		<div class="section-card">
			<ToolHelp toolType="secret_scanner" />
		</div>
	{/if}
</div>

<style>
	.nd-page {
		padding: 1.5rem;
		max-width: 1200px;
		margin: 0 auto;
		min-height: 100vh;
	}

	.page-header {
		margin-bottom: 1.5rem;
		padding-bottom: 1rem;
		border-bottom: 1px solid rgba(168, 85, 247, 0.15);
	}

	.back-link {
		color: #94a3b8;
		text-decoration: none;
		font-size: 0.8rem;
		transition: color 0.2s;
	}

	.back-link:hover { color: #a855f7; }

	.page-title {
		font-size: 1.5rem;
		font-weight: 700;
		margin: 0.5rem 0 0.25rem;
		color: #f1f5f9;
	}

	.page-subtitle {
		color: #94a3b8;
		font-size: 0.875rem;
		margin: 0;
	}

	.tabs {
		display: flex;
		gap: 0.25rem;
		margin-bottom: 1.25rem;
		background: rgba(15, 23, 42, 0.6);
		border: 1px solid rgba(168, 85, 247, 0.15);
		border-radius: 0.75rem;
		padding: 0.25rem;
	}

	.tab-btn {
		flex: 1;
		padding: 0.6rem 1rem;
		border: none;
		border-radius: 0.5rem;
		background: transparent;
		cursor: pointer;
		font-size: 0.85rem;
		color: #94a3b8;
		transition: all 0.2s;
		display: flex;
		align-items: center;
		justify-content: center;
		gap: 0.4rem;
	}

	.tab-btn.active {
		background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%);
		color: white;
		font-weight: 600;
		box-shadow: 0 2px 8px rgba(168, 85, 247, 0.3);
	}

	.tab-btn:hover:not(.active) { background: rgba(168, 85, 247, 0.1); color: #c4b5fd; }

	.tab-icon { font-size: 0.9rem; }

	.content-grid {
		display: grid;
		grid-template-columns: 340px 1fr;
		gap: 1.25rem;
	}

	.section-card {
		background: rgba(15, 23, 42, 0.6);
		border: 1px solid rgba(168, 85, 247, 0.15);
		border-radius: 0.75rem;
		padding: 1.25rem;
	}

	.section-title {
		font-size: 1rem;
		font-weight: 600;
		color: #f1f5f9;
		margin: 0 0 1rem;
	}

	.section-desc {
		font-size: 0.8rem;
		color: #94a3b8;
		margin: 0.25rem 0 0;
	}

	.form-group { margin-bottom: 0.75rem; }

	.form-label {
		display: block;
		font-size: 0.75rem;
		color: #94a3b8;
		margin-bottom: 0.3rem;
		font-weight: 500;
		text-transform: uppercase;
		letter-spacing: 0.05em;
	}

	.form-input {
		width: 100%;
		padding: 0.55rem 0.75rem;
		border-radius: 0.5rem;
		border: 1px solid rgba(148, 163, 184, 0.15);
		background: rgba(15, 23, 42, 0.8);
		color: #f1f5f9;
		font-size: 0.85rem;
		box-sizing: border-box;
		transition: border-color 0.2s;
	}

	.form-input:focus {
		outline: none;
		border-color: #a855f7;
		box-shadow: 0 0 0 2px rgba(168, 85, 247, 0.15);
	}

	.form-input::placeholder { color: #475569; }

	.form-row {
		display: grid;
		grid-template-columns: 1fr 1fr;
		gap: 0.75rem;
	}

	.mode-grid {
		display: grid;
		grid-template-columns: repeat(4, 1fr);
		gap: 0.35rem;
	}

	.mode-btn {
		padding: 0.4rem 0.5rem;
		border: 1px solid rgba(148, 163, 184, 0.15);
		border-radius: 0.4rem;
		background: rgba(15, 23, 42, 0.6);
		color: #94a3b8;
		cursor: pointer;
		font-size: 0.75rem;
		transition: all 0.2s;
		text-align: center;
	}

	.mode-btn.active {
		background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%);
		color: white;
		border-color: transparent;
		font-weight: 600;
		box-shadow: 0 2px 6px rgba(168, 85, 247, 0.3);
	}

	.mode-btn:hover:not(.active) {
		border-color: rgba(168, 85, 247, 0.3);
		color: #c4b5fd;
	}

	.mode-name { font-size: 0.75rem; }

	.target-grid {
		display: grid;
		grid-template-columns: repeat(2, 1fr);
		gap: 0.35rem;
	}

	.target-chip {
		display: flex;
		align-items: center;
		gap: 0.35rem;
		padding: 0.35rem 0.5rem;
		border: 1px solid rgba(148, 163, 184, 0.15);
		border-radius: 0.4rem;
		background: rgba(15, 23, 42, 0.6);
		cursor: pointer;
		font-size: 0.75rem;
		color: #94a3b8;
		transition: all 0.2s;
	}

	.target-chip.active {
		border-color: rgba(168, 85, 247, 0.4);
		background: rgba(168, 85, 247, 0.1);
		color: #c4b5fd;
	}

	.target-chip input[type="checkbox"] {
		accent-color: #a855f7;
		width: 0.8rem;
		height: 0.8rem;
	}

	.target-chip:hover:not(.active) {
		border-color: rgba(148, 163, 184, 0.3);
	}

	.custom-pattern-input {
		display: flex;
		gap: 0.35rem;
	}

	.custom-pattern-input .form-input { flex: 1; }

	.btn-add-pattern {
		padding: 0.55rem 0.85rem;
		border: 1px solid rgba(168, 85, 247, 0.3);
		border-radius: 0.5rem;
		background: rgba(168, 85, 247, 0.1);
		color: #a855f7;
		cursor: pointer;
		font-size: 1rem;
		font-weight: 600;
		transition: all 0.2s;
	}

	.btn-add-pattern:hover:not(:disabled) {
		background: rgba(168, 85, 247, 0.2);
		border-color: rgba(168, 85, 247, 0.5);
	}

	.btn-add-pattern:disabled { opacity: 0.4; cursor: not-allowed; }

	.pattern-tags {
		display: flex;
		flex-wrap: wrap;
		gap: 0.3rem;
		margin-top: 0.5rem;
	}

	.pattern-tag {
		display: flex;
		align-items: center;
		gap: 0.3rem;
		padding: 0.2rem 0.5rem;
		border: 1px solid rgba(168, 85, 247, 0.3);
		border-radius: 0.3rem;
		background: rgba(168, 85, 247, 0.08);
		font-size: 0.7rem;
	}

	.pattern-tag code {
		color: #c4b5fd;
		font-family: 'SF Mono', 'Fira Code', monospace;
		font-size: 0.68rem;
		max-width: 200px;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.tag-remove {
		background: none;
		border: none;
		color: #94a3b8;
		cursor: pointer;
		font-size: 0.65rem;
		padding: 0.1rem;
	}

	.tag-remove:hover { color: #ef4444; }

	.button-group {
		display: flex;
		gap: 0.5rem;
		margin-top: 1rem;
	}

	.btn-primary {
		flex: 1;
		background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%);
		color: white;
		font-weight: 600;
		padding: 0.65rem 1.25rem;
		border: none;
		border-radius: 0.5rem;
		cursor: pointer;
		transition: all 0.2s;
		display: flex;
		align-items: center;
		justify-content: center;
		gap: 0.5rem;
		font-size: 0.9rem;
	}

	.btn-primary:hover:not(:disabled) {
		box-shadow: 0 4px 15px rgba(168, 85, 247, 0.4);
		transform: translateY(-1px);
	}

	.btn-primary:disabled {
		opacity: 0.5;
		cursor: not-allowed;
		transform: none;
		box-shadow: none;
	}

	.btn-secondary {
		background: rgba(148, 163, 184, 0.1);
		color: #94a3b8;
		padding: 0.65rem 1rem;
		border: 1px solid rgba(148, 163, 184, 0.15);
		border-radius: 0.5rem;
		cursor: pointer;
		transition: all 0.2s;
		font-size: 0.9rem;
	}

	.btn-secondary:hover:not(:disabled) {
		background: rgba(148, 163, 184, 0.2);
		color: #e2e8f0;
	}

	.btn-secondary:disabled { opacity: 0.5; cursor: not-allowed; }

	.spinner {
		display: inline-block;
		width: 1rem;
		height: 1rem;
		border: 2px solid rgba(255, 255, 255, 0.3);
		border-top-color: white;
		border-radius: 50%;
		animation: spin 0.6s linear infinite;
	}

	@keyframes spin { to { transform: rotate(360deg); } }

	.error-card {
		display: flex;
		align-items: center;
		gap: 0.75rem;
		padding: 1rem;
		background: rgba(239, 68, 68, 0.1);
		border: 1px solid rgba(239, 68, 68, 0.2);
		border-radius: 0.5rem;
	}

	.error-icon { font-size: 1.25rem; }
	.error-text { color: #fca5a5; font-size: 0.85rem; }

	.result-header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		margin-bottom: 0.75rem;
		flex-wrap: wrap;
		gap: 0.5rem;
	}

	.header-actions {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		flex-wrap: wrap;
	}

	.resource-score-badge {
		display: flex;
		flex-direction: column;
		align-items: center;
		padding: 0.5rem 1rem;
		border-radius: 0.5rem;
		border: 1px solid rgba(168, 85, 247, 0.3);
		background: rgba(168, 85, 247, 0.1);
	}

	.score-value {
		font-size: 1.5rem;
		font-weight: 700;
		color: #a855f7;
		line-height: 1;
	}

	.score-label {
		font-size: 0.65rem;
		color: #a855f7;
		opacity: 0.8;
		margin-top: 0.2rem;
	}

	.export-select {
		padding: 0.35rem 0.5rem;
		border-radius: 0.375rem;
		border: 1px solid rgba(148, 163, 184, 0.2);
		background: rgba(15, 23, 42, 0.8);
		color: #e2e8f0;
		font-size: 0.75rem;
	}

	.btn-export {
		display: flex;
		align-items: center;
		gap: 0.35rem;
		padding: 0.5rem 0.85rem;
		border-radius: 0.5rem;
		border: 1px solid rgba(34, 197, 94, 0.3);
		background: rgba(34, 197, 94, 0.1);
		color: #22c55e;
		cursor: pointer;
		font-size: 0.8rem;
		font-weight: 600;
		transition: all 0.2s;
		white-space: nowrap;
	}

	.btn-export:hover:not(:disabled) {
		background: rgba(34, 197, 94, 0.2);
		border-color: rgba(34, 197, 94, 0.5);
	}

	.btn-export:disabled { opacity: 0.5; cursor: not-allowed; }

	.summary-bar {
		font-size: 0.8rem;
		color: #94a3b8;
		padding: 0.5rem 0.75rem;
		background: rgba(15, 23, 42, 0.4);
		border-radius: 0.4rem;
		margin-bottom: 1rem;
		border: 1px solid rgba(148, 163, 184, 0.08);
	}

	.info-bar {
		font-size: 0.8rem;
		color: #3b82f6;
		padding: 0.5rem 0.75rem;
		background: rgba(59, 130, 246, 0.08);
		border: 1px solid rgba(59, 130, 246, 0.15);
		border-radius: 0.4rem;
		margin-bottom: 1rem;
	}

	.result-tabs {
		display: flex;
		gap: 0.25rem;
		margin-bottom: 1rem;
		flex-wrap: wrap;
	}

	.result-tab {
		padding: 0.4rem 0.75rem;
		border-radius: 0.4rem;
		border: 1px solid rgba(148, 163, 184, 0.15);
		background: rgba(15, 23, 42, 0.4);
		color: #94a3b8;
		cursor: pointer;
		font-size: 0.8rem;
		transition: all 0.2s;
	}

	.result-tab.active {
		background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%);
		color: white;
		border-color: transparent;
		font-weight: 600;
	}

	.result-tab:hover:not(.active) {
		border-color: rgba(168, 85, 247, 0.3);
		color: #c4b5fd;
	}

	.overview-grid {
		display: grid;
		grid-template-columns: repeat(4, 1fr);
		gap: 0.75rem;
		margin-bottom: 1rem;
	}

	.overview-stat {
		display: flex;
		flex-direction: column;
		align-items: center;
		padding: 0.75rem;
		background: rgba(15, 23, 42, 0.4);
		border: 1px solid rgba(148, 163, 184, 0.08);
		border-radius: 0.5rem;
	}

	.stat-label {
		font-size: 0.7rem;
		color: #94a3b8;
		margin-bottom: 0.3rem;
	}

	.stat-value {
		font-size: 1.25rem;
		font-weight: 700;
		color: #f1f5f9;
	}

	.subsection-title {
		font-size: 0.85rem;
		font-weight: 600;
		color: #f1f5f9;
		margin: 1rem 0 0.5rem;
	}

	.severity-grid {
		display: grid;
		grid-template-columns: repeat(5, 1fr);
		gap: 0.5rem;
		margin-bottom: 1rem;
	}

	.severity-stat {
		display: flex;
		flex-direction: column;
		align-items: center;
		padding: 0.6rem;
		border-radius: 0.5rem;
		border: 1px solid;
		gap: 0.3rem;
	}

	.severity-label {
		font-size: 0.7rem;
		color: #94a3b8;
	}

	.severity-count {
		font-size: 1.2rem;
		font-weight: 700;
	}

	.severity-bar-bg {
		width: 100%;
		height: 3px;
		background: rgba(148, 163, 184, 0.1);
		border-radius: 2px;
		overflow: hidden;
	}

	.severity-bar-fill {
		height: 100%;
		border-radius: 2px;
		transition: width 0.3s;
	}

	.top-secrets-list {
		display: flex;
		flex-direction: column;
		gap: 0.35rem;
	}

	.top-secret-item {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		padding: 0.5rem 0.6rem;
		background: rgba(15, 23, 42, 0.4);
		border: 1px solid rgba(148, 163, 184, 0.06);
		border-radius: 0.3rem;
		cursor: pointer;
		transition: all 0.2s;
	}

	.top-secret-item:hover {
		background: rgba(168, 85, 247, 0.05);
		border-color: rgba(168, 85, 247, 0.15);
	}

	.severity-dot {
		width: 8px;
		height: 8px;
		border-radius: 50%;
		flex-shrink: 0;
	}

	.secret-type-label {
		font-size: 0.78rem;
		color: #cbd5e1;
		white-space: nowrap;
	}

	.secret-preview {
		flex: 1;
		font-family: 'SF Mono', 'Fira Code', monospace;
		font-size: 0.72rem;
		color: #94a3b8;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.confidence-mini {
		font-size: 0.7rem;
		font-weight: 600;
		flex-shrink: 0;
	}

	.more-link {
		text-align: center;
		padding: 0.4rem;
		color: #a855f7;
		cursor: pointer;
		font-size: 0.78rem;
		transition: color 0.2s;
	}

	.more-link:hover { color: #c4b5fd; }

	.filter-bar {
		display: flex;
		flex-wrap: wrap;
		gap: 0.35rem;
		margin-bottom: 0.75rem;
	}

	.filter-btn {
		padding: 0.35rem 0.6rem;
		border-radius: 0.3rem;
		border: 1px solid rgba(148, 163, 184, 0.15);
		background: rgba(15, 23, 42, 0.4);
		color: #94a3b8;
		cursor: pointer;
		font-size: 0.75rem;
		transition: all 0.2s;
	}

	.filter-btn.active {
		background: rgba(168, 85, 247, 0.15);
		border-color: rgba(168, 85, 247, 0.4);
		color: #c4b5fd;
	}

	.filter-btn:hover:not(.active) {
		border-color: rgba(148, 163, 184, 0.3);
	}

	.search-bar { margin-bottom: 0.75rem; }

	.search-input {
		width: 100%;
		padding: 0.45rem 0.75rem;
		border-radius: 0.4rem;
		border: 1px solid rgba(148, 163, 184, 0.15);
		background: rgba(15, 23, 42, 0.6);
		color: #f1f5f9;
		font-size: 0.8rem;
		box-sizing: border-box;
	}

	.search-input:focus {
		outline: none;
		border-color: #a855f7;
	}

	.search-input::placeholder { color: #475569; }

	.links-table-wrapper {
		max-height: 500px;
		overflow-y: auto;
		border-radius: 0.5rem;
		border: 1px solid rgba(148, 163, 184, 0.08);
	}

	.data-table {
		width: 100%;
		border-collapse: collapse;
		font-size: 0.8rem;
	}

	.data-table th {
		text-align: left;
		padding: 0.5rem 0.6rem;
		background: rgba(15, 23, 42, 0.6);
		color: #94a3b8;
		font-weight: 500;
		font-size: 0.7rem;
		text-transform: uppercase;
		letter-spacing: 0.05em;
		border-bottom: 1px solid rgba(148, 163, 184, 0.1);
		position: sticky;
		top: 0;
		z-index: 1;
	}

	.data-table td {
		padding: 0.4rem 0.6rem;
		border-bottom: 1px solid rgba(148, 163, 184, 0.06);
		color: #cbd5e1;
	}

	.data-table tr:hover td { background: rgba(168, 85, 247, 0.05); }

	.severity-badge {
		display: inline-block;
		padding: 0.15rem 0.4rem;
		border-radius: 0.25rem;
		font-size: 0.7rem;
		font-weight: 600;
		border: 1px solid;
		white-space: nowrap;
	}

	.category-chip {
		display: inline-flex;
		align-items: center;
		gap: 0.25rem;
		padding: 0.1rem 0.4rem;
		border-radius: 0.2rem;
		background: rgba(148, 163, 184, 0.1);
		font-size: 0.72rem;
		color: #94a3b8;
	}

	.mono { font-family: 'SF Mono', 'Fira Code', monospace; font-size: 0.78rem; }

	.secret-type-cell {
		font-weight: 500;
		color: #e2e8f0;
		font-size: 0.78rem;
	}

	.preview-cell {
		display: flex;
		align-items: center;
		gap: 0.3rem;
	}

	.preview-cell code {
		flex: 1;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
		font-size: 0.72rem;
	}

	.btn-dl-single {
		background: none;
		border: 1px solid rgba(34, 197, 94, 0.3);
		border-radius: 0.25rem;
		color: #22c55e;
		cursor: pointer;
		font-size: 0.75rem;
		padding: 0.15rem 0.3rem;
		flex-shrink: 0;
		transition: all 0.2s;
	}

	.btn-dl-single:hover {
		background: rgba(34, 197, 94, 0.1);
	}

	.full-value-block {
		margin-top: 0.3rem;
		padding: 0.4rem 0.5rem;
		background: rgba(239, 68, 68, 0.08);
		border: 1px solid rgba(239, 68, 68, 0.15);
		border-radius: 0.25rem;
		word-break: break-all;
	}

	.full-value-block code {
		font-size: 0.72rem;
		color: #fca5a5;
	}

	.context-block {
		margin-top: 0.2rem;
		font-size: 0.7rem;
		color: #64748b;
	}

	.context-label {
		font-size: 0.65rem;
		color: #475569;
	}

	.context-block code {
		font-size: 0.68rem;
		color: #64748b;
	}

	.link-url {
		color: #a855f7;
		text-decoration: none;
		font-size: 0.78rem;
		display: inline-block;
		max-width: 120px;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.link-url:hover { color: #c4b5fd; text-decoration: underline; }

	.depth-badge {
		display: inline-block;
		padding: 0.1rem 0.35rem;
		border-radius: 0.2rem;
		background: rgba(148, 163, 184, 0.1);
		font-size: 0.7rem;
		color: #94a3b8;
	}

	.table-footer {
		text-align: center;
		padding: 0.5rem;
		font-size: 0.75rem;
		color: #64748b;
	}

	.category-grid {
		display: grid;
		grid-template-columns: repeat(3, 1fr);
		gap: 0.5rem;
	}

	.category-card {
		padding: 0.6rem;
		background: rgba(15, 23, 42, 0.4);
		border: 1px solid rgba(148, 163, 184, 0.08);
		border-radius: 0.5rem;
	}

	.category-header {
		display: flex;
		align-items: center;
		gap: 0.4rem;
		margin-bottom: 0.3rem;
	}

	.category-icon { font-size: 0.85rem; }

	.category-name {
		flex: 1;
		font-size: 0.8rem;
		color: #e2e8f0;
		font-weight: 500;
	}

	.category-count {
		font-size: 1rem;
		font-weight: 700;
		color: #a855f7;
	}

	.category-detail {
		display: flex;
		gap: 0.5rem;
		margin-bottom: 0.3rem;
	}

	.cat-sev {
		font-size: 0.7rem;
		font-weight: 600;
	}

	.category-bar-bg {
		width: 100%;
		height: 3px;
		background: rgba(148, 163, 184, 0.1);
		border-radius: 2px;
		overflow: hidden;
	}

	.category-bar-fill {
		height: 100%;
		border-radius: 2px;
		transition: width 0.3s;
	}

	.url-list {
		display: flex;
		flex-direction: column;
		gap: 0.3rem;
		max-height: 500px;
		overflow-y: auto;
	}

	.url-item {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		padding: 0.4rem 0.6rem;
		background: rgba(15, 23, 42, 0.4);
		border: 1px solid rgba(148, 163, 184, 0.06);
		border-radius: 0.3rem;
	}

	.url-icon { font-size: 0.85rem; flex-shrink: 0; }

	.url-item .link-url {
		max-width: none;
		flex: 1;
	}

	.empty-state {
		display: flex;
		flex-direction: column;
		align-items: center;
		padding: 2rem;
		color: #64748b;
	}

	.empty-icon { font-size: 2.5rem; margin-bottom: 0.5rem; }
	.empty-state p { font-size: 0.85rem; margin: 0; }

	@media (max-width: 768px) {
		.content-grid {
			grid-template-columns: 1fr;
		}
		.overview-grid {
			grid-template-columns: repeat(2, 1fr);
		}
		.severity-grid {
			grid-template-columns: repeat(3, 1fr);
		}
		.category-grid {
			grid-template-columns: repeat(2, 1fr);
		}
	}
</style>
