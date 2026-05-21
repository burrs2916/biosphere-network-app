<script lang="ts">
	import { tr, t } from '$lib/i18n';
	import ToolHistory from '$lib/components/ToolHistory.svelte';
	import ToolHelp from '$lib/components/ToolHelp.svelte';

	interface ParamEntry {
		param_name: string;
		method: string;
		evidence: string;
		response_diff: number | null;
		status_code: number;
		content_length: number | null;
		response_time_ms: number;
		test_value: string;
		category: string;
		risk_level: string;
		is_reflected: boolean;
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

	interface SensitiveParam {
		param_name: string;
		category: string;
		severity: string;
		description: string;
	}

	interface ParamDiscoveryResult {
		url: string;
		found_params: ParamEntry[];
		total_found: number;
		total_tested: number;
		summary: string;
		scan_duration_ms: number;
		baseline_status: number;
		baseline_length: number;
		form_params: string[];
		url_params: string[];
		ssl_info: SslInfo | null;
		waf_detected: WafDetection | null;
		sensitive_params: SensitiveParam[];
	}

	let url = $state('');
	let activeMainTab = $state('analyze');
	let historyComponent: ToolHistory = $state(null!);
	let method = $state('GET');
	let timeout = $state(10);
	let threads = $state(10);
	let scanMode = $state('normal');
	let diffThreshold = $state(0.05);
	let followRedirects = $state(false);
	let extractFormParams = $state(true);
	let randomizeUa = $state(true);
	let multiValueTest = $state(true);
	let detectReflection = $state(true);
	let collectSslInfo = $state(true);
	let excludeParams = $state('');
	let result: ParamDiscoveryResult | null = $state(null);
	let error = $state('');
	let processing = $state(false);
	let activeResultTab = $state('overview');
	let categoryFilter = $state('all');
	let riskFilter = $state('all');
	let searchQuery = $state('');

	async function discover() {
		if (!url.trim()) { error = t('paramDiscovery.error.emptyInput'); return; }
		processing = true; error = ''; result = null;
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			const excludeList = excludeParams ? excludeParams.split(',').map((e: string) => e.trim()).filter((e: string) => e) : [];
			result = await invoke<ParamDiscoveryResult>('discover_params_command', {
				config: {
					url: url.trim(),
					timeout,
					method,
					wordlist: [],
					threads,
					follow_redirects: followRedirects,
					diff_threshold: diffThreshold,
					extract_form_params: extractFormParams,
					randomize_ua: randomizeUa,
					user_agent: null,
					multi_value_test: multiValueTest,
					custom_values: [],
					scan_mode: scanMode,
					collect_ssl_info: collectSslInfo,
					detect_reflection: detectReflection,
					exclude_params: excludeList
				}
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

	function clearAll() { url = ''; result = null; error = ''; excludeParams = ''; }

	function getRiskColor(risk: string): string {
		if (risk === 'critical') return '#ef4444';
		if (risk === 'high') return '#f97316';
		if (risk === 'medium') return '#eab308';
		if (risk === 'low') return '#22c55e';
		return '#94a3b8';
	}

	function getRiskIcon(risk: string): string {
		if (risk === 'critical') return '🔴';
		if (risk === 'high') return '🟠';
		if (risk === 'medium') return '🟡';
		if (risk === 'low') return '🟢';
		return '⚪';
	}

	function getCategoryIcon(cat: string): string {
		if (cat === 'command') return '💻';
		if (cat === 'file') return '📁';
		if (cat === 'ssrf') return '🌐';
		if (cat === 'database') return '🗄️';
		if (cat === 'auth') return '🔐';
		if (cat === 'debug') return '🐛';
		if (cat === 'pagination') return '📄';
		if (cat === 'i18n') return '🌍';
		if (cat === 'content') return '📝';
		return '📌';
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

	function formatDuration(ms: number): string {
		if (ms < 1000) return `${ms}ms`;
		return `${(ms / 1000).toFixed(1)}s`;
	}

	function formatSize(bytes: number | null): string {
		if (bytes === null) return '-';
		if (bytes < 1024) return `${bytes}B`;
		if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)}KB`;
		return `${(bytes / (1024 * 1024)).toFixed(1)}MB`;
	}

	function getFilteredEntries(): ParamEntry[] {
		if (!result) return [];
		let entries = result.found_params;
		if (categoryFilter !== 'all') {
			entries = entries.filter(e => e.category === categoryFilter);
		}
		if (riskFilter !== 'all') {
			entries = entries.filter(e => e.risk_level === riskFilter);
		}
		if (searchQuery.trim()) {
			const q = searchQuery.toLowerCase();
			entries = entries.filter(e =>
				e.param_name.toLowerCase().includes(q) ||
				e.evidence.toLowerCase().includes(q) ||
				e.category.toLowerCase().includes(q)
			);
		}
		return entries;
	}

	function getCategoryGroups(): { category: string; icon: string; count: number }[] {
		if (!result) return [];
		const groups: Record<string, { category: string; icon: string; count: number }> = {};
		for (const entry of result.found_params) {
			if (!groups[entry.category]) {
				groups[entry.category] = {
					category: entry.category,
					icon: getCategoryIcon(entry.category),
					count: 0
				};
			}
			groups[entry.category].count++;
		}
		return Object.values(groups).sort((a, b) => b.count - a.count);
	}

	function getRiskGroups(): { risk: string; icon: string; color: string; count: number }[] {
		if (!result) return [];
		const groups: Record<string, { risk: string; icon: string; color: string; count: number }> = {};
		for (const entry of result.found_params) {
			if (!groups[entry.risk_level]) {
				groups[entry.risk_level] = {
					risk: entry.risk_level,
					icon: getRiskIcon(entry.risk_level),
					color: getRiskColor(entry.risk_level),
					count: 0
				};
			}
			groups[entry.risk_level].count++;
		}
		const order = ['critical', 'high', 'medium', 'low', 'info'];
		return Object.values(groups).sort((a, b) => order.indexOf(a.risk) - order.indexOf(b.risk));
	}

	function exportJSON() {
		if (!result) return;
		const blob = new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' });
		const a = document.createElement('a');
		a.href = URL.createObjectURL(blob);
		a.download = `param_discovery_${new Date().toISOString().slice(0, 10)}.json`;
		a.click();
		URL.revokeObjectURL(a.href);
	}

	function exportCSV() {
		if (!result) return;
		const headers = ['Parameter', 'Method', 'Status', 'Category', 'Risk', 'Diff %', 'Reflected', 'Test Value', 'Evidence', 'Response Time (ms)'];
		const rows = result.found_params.map(e => [
			e.param_name, e.method, e.status_code, e.category, e.risk_level,
			e.response_diff !== null ? (e.response_diff * 100).toFixed(1) : '',
			e.is_reflected ? 'Yes' : 'No', e.test_value, e.evidence, e.response_time_ms
		]);
		const csv = [headers.join(','), ...rows.map(r => r.map(c => `"${c}"`).join(','))].join('\n');
		const blob = new Blob([csv], { type: 'text/csv' });
		const a = document.createElement('a');
		a.href = URL.createObjectURL(blob);
		a.download = `param_discovery_${new Date().toISOString().slice(0, 10)}.csv`;
		a.click();
		URL.revokeObjectURL(a.href);
	}
</script>

<div class="nd-page">
	<div class="page-header">
		<div class="header-left">
			<a href="/" class="back-link">{$tr('common.backToHome')}</a>
			<h1 class="page-title">🔍 {$tr('paramDiscovery.title')}</h1>
			<p class="page-subtitle">{$tr('paramDiscovery.subtitle')}</p>
		</div>
	</div>

	<div class="tabs">
		<button class="tab-btn {activeMainTab === 'analyze' ? 'active' : ''}" on:click={() => activeMainTab = 'analyze'}>
			<span class="tab-icon">🔍</span> {$tr('paramDiscovery.buttons.discover')}
		</button>
		<button class="tab-btn {activeMainTab === 'history' ? 'active' : ''}" on:click={() => activeMainTab = 'history'}>
			<span class="tab-icon">📋</span> {$tr('paramDiscovery.history')}
		</button>
		<button class="tab-btn {activeMainTab === 'help' ? 'active' : ''}" on:click={() => activeMainTab = 'help'}>
			<span class="tab-icon">📖</span> {$tr('paramDiscovery.help')}
		</button>
	</div>

	{#if activeMainTab === 'analyze'}
		<div class="content-grid">
			<div class="input-section">
				<div class="section-card">
					<h2 class="section-title">{$tr('paramDiscovery.config.title')}</h2>
					<p class="section-desc">{$tr('paramDiscovery.config.desc')}</p>

					<div class="form-group">
						<label class="form-label">{$tr('paramDiscovery.config.url')}</label>
						<input type="text" bind:value={url} placeholder="https://example.com/page" class="form-input" disabled={processing} on:keydown={(e) => e.key === 'Enter' && discover()} />
					</div>

					<div class="form-row">
						<div class="form-group">
							<label class="form-label">{$tr('paramDiscovery.config.method')}</label>
							<select bind:value={method} class="form-input" disabled={processing}>
								<option value="GET">GET</option>
								<option value="POST">POST</option>
							</select>
						</div>
						<div class="form-group">
							<label class="form-label">{$tr('paramDiscovery.config.timeout')}</label>
							<input type="number" bind:value={timeout} class="form-input" min="5" max="60" disabled={processing} />
						</div>
					</div>

					<div class="form-row">
						<div class="form-group">
							<label class="form-label">{$tr('paramDiscovery.config.threads')}</label>
							<input type="number" bind:value={threads} class="form-input" min="1" max="50" disabled={processing} />
						</div>
						<div class="form-group">
							<label class="form-label">{$tr('paramDiscovery.config.diffThreshold')}</label>
							<input type="number" bind:value={diffThreshold} class="form-input" min="0.01" max="1.0" step="0.01" disabled={processing} />
						</div>
					</div>

					<div class="form-group">
						<label class="form-label">{$tr('paramDiscovery.config.scanMode')}</label>
						<div class="target-grid">
							<label class="target-chip {scanMode === 'quick' ? 'active' : ''}">
								<input type="radio" name="scanMode" value="quick" bind:group={scanMode} disabled={processing} />
								<span>⚡ {$tr('paramDiscovery.config.modeQuick')}</span>
							</label>
							<label class="target-chip {scanMode === 'normal' ? 'active' : ''}">
								<input type="radio" name="scanMode" value="normal" bind:group={scanMode} disabled={processing} />
								<span>⚖️ {$tr('paramDiscovery.config.modeNormal')}</span>
							</label>
							<label class="target-chip {scanMode === 'deep' ? 'active' : ''}">
								<input type="radio" name="scanMode" value="deep" bind:group={scanMode} disabled={processing} />
								<span>🔬 {$tr('paramDiscovery.config.modeDeep')}</span>
							</label>
						</div>
					</div>

					<div class="form-group">
						<label class="form-label">{$tr('paramDiscovery.config.excludeParams')}</label>
						<input type="text" bind:value={excludeParams} placeholder="page,limit,offset" class="form-input" disabled={processing} />
					</div>

					<div class="checkbox-grid">
						<label class="target-chip {extractFormParams ? 'active' : ''}">
							<input type="checkbox" bind:checked={extractFormParams} disabled={processing} />
							<span>📝 {$tr('paramDiscovery.config.extractFormParams')}</span>
						</label>
						<label class="target-chip {multiValueTest ? 'active' : ''}">
							<input type="checkbox" bind:checked={multiValueTest} disabled={processing} />
							<span>🧪 {$tr('paramDiscovery.config.multiValueTest')}</span>
						</label>
						<label class="target-chip {detectReflection ? 'active' : ''}">
							<input type="checkbox" bind:checked={detectReflection} disabled={processing} />
							<span>🪞 {$tr('paramDiscovery.config.detectReflection')}</span>
						</label>
						<label class="target-chip {followRedirects ? 'active' : ''}">
							<input type="checkbox" bind:checked={followRedirects} disabled={processing} />
							<span>↪️ {$tr('paramDiscovery.config.followRedirects')}</span>
						</label>
						<label class="target-chip {randomizeUa ? 'active' : ''}">
							<input type="checkbox" bind:checked={randomizeUa} disabled={processing} />
							<span>🎭 {$tr('paramDiscovery.config.randomUa')}</span>
						</label>
						<label class="target-chip {collectSslInfo ? 'active' : ''}">
							<input type="checkbox" bind:checked={collectSslInfo} disabled={processing} />
							<span>🔒 {$tr('paramDiscovery.config.collectSsl')}</span>
						</label>
					</div>

					<div class="button-group">
						<button class="btn-primary" on:click={discover} disabled={processing || !url.trim()}>
							{#if processing}<span class="spinner"></span>{$tr('paramDiscovery.buttons.discovering')}{:else}🔍 {$tr('paramDiscovery.buttons.discover')}{/if}
						</button>
						<button class="btn-secondary" on:click={clearAll} disabled={processing}>🗑️</button>
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
							<h2 class="section-title">{$tr('paramDiscovery.result.title')}</h2>
							<div class="result-header-actions">
								<div class="result-score-badge">
									<span class="score-value">{result.total_found}</span>
									<span class="score-label">{$tr('paramDiscovery.result.found')}</span>
								</div>
								<div class="export-group">
									<button class="export-btn" on:click={exportJSON} title="JSON">📋 JSON</button>
									<button class="export-btn" on:click={exportCSV} title="CSV">📊 CSV</button>
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
									<span class="waf-title">{$tr('paramDiscovery.result.wafDetected')}: {result.waf_detected.waf_name}</span>
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

						{#if result.sensitive_params.length > 0}
							<div class="sensitive-section">
								<div class="sensitive-header">🔐 {$tr('paramDiscovery.result.sensitiveParams')} ({result.sensitive_params.length})</div>
								<div class="sensitive-grid">
									{#each result.sensitive_params.slice(0, 10) as sp}
										<span class="sensitive-chip" style="border-color: {getSeverityColor(sp.severity)}40; background: {getSeverityColor(sp.severity)}10; color: {getSeverityColor(sp.severity)}">
											{getSeverityIcon(sp.severity)} {sp.param_name}
											<span class="sensitive-badge">{sp.severity}</span>
										</span>
									{/each}
								</div>
							</div>
						{/if}

						{#if getRiskGroups().length > 0}
							<div class="status-grid" style="margin-bottom: 1rem;">
								{#each getRiskGroups() as group}
									<span class="status-chip" style="border-color: {group.color}40; background: {group.color}10; color: {group.color}">
										<span>{group.icon}</span>
										<span class="status-chip-label">{group.risk}</span>
										<span class="status-chip-count">{group.count}</span>
									</span>
								{/each}
							</div>
						{/if}

						{#if result.form_params.length > 0 || result.url_params.length > 0}
							<div class="extracted-params-section">
								{#if result.form_params.length > 0}
									<div class="extracted-group">
										<span class="extracted-label">📝 {$tr('paramDiscovery.result.formParams')}:</span>
										<div class="extracted-chips">
											{#each result.form_params as fp}
												<span class="extracted-chip">📝 {fp}</span>
											{/each}
										</div>
									</div>
								{/if}
								{#if result.url_params.length > 0}
									<div class="extracted-group">
										<span class="extracted-label">🔗 {$tr('paramDiscovery.result.urlParams')}:</span>
										<div class="extracted-chips">
											{#each result.url_params as up}
												<span class="extracted-chip">🔗 {up}</span>
											{/each}
										</div>
									</div>
								{/if}
							</div>
						{/if}

						<div class="result-tabs">
							<button class="result-tab {activeResultTab === 'overview' ? 'active' : ''}" on:click={() => activeResultTab = 'overview'}>
								📊 {$tr('paramDiscovery.result.overview')}
							</button>
							<button class="result-tab {activeResultTab === 'list' ? 'active' : ''}" on:click={() => activeResultTab = 'list'}>
								📋 {$tr('paramDiscovery.result.list')}
							</button>
							<button class="result-tab {activeResultTab === 'category' ? 'active' : ''}" on:click={() => activeResultTab = 'category'}>
								🗂️ {$tr('paramDiscovery.result.byCategory')}
							</button>
							<button class="result-tab {activeResultTab === 'sensitive' ? 'active' : ''}" on:click={() => activeResultTab = 'sensitive'}>
								🔐 {$tr('paramDiscovery.result.sensitive')}
							</button>
						</div>

						{#if activeResultTab === 'overview'}
							<div class="overview-grid">
								<div class="overview-stat">
									<span class="stat-icon">🔍</span>
									<span class="stat-value">{result.total_found}</span>
									<span class="stat-label">{$tr('paramDiscovery.result.found')}</span>
								</div>
								<div class="overview-stat">
									<span class="stat-icon">🧪</span>
									<span class="stat-value">{result.total_tested}</span>
									<span class="stat-label">{$tr('paramDiscovery.result.tested')}</span>
								</div>
								<div class="overview-stat">
									<span class="stat-icon">📊</span>
									<span class="stat-value">{result.total_tested > 0 ? ((result.total_found / result.total_tested) * 100).toFixed(1) : 0}%</span>
									<span class="stat-label">Hit Rate</span>
								</div>
								<div class="overview-stat">
									<span class="stat-icon">🪞</span>
									<span class="stat-value">{result.found_params.filter(p => p.is_reflected).length}</span>
									<span class="stat-label">{$tr('paramDiscovery.result.reflected')}</span>
								</div>
							</div>

							{#if getCategoryGroups().length > 0}
								<div class="subsection-title">{$tr('paramDiscovery.result.byCategory')}</div>
								<div class="tech-grid">
									{#each getCategoryGroups() as catGroup}
										<span class="tech-chip">
											<span class="tech-icon">{catGroup.icon}</span>
											<span class="tech-name">{catGroup.category}</span>
											<span class="tech-count">{catGroup.count}</span>
										</span>
									{/each}
								</div>
							{/if}

							<div class="subsection-title">{$tr('paramDiscovery.result.foundParams')}</div>
							<div class="tech-grid">
								{#each result.found_params.slice(0, 30) as entry}
									<span class="tech-chip">
										<span class="tech-icon">{getRiskIcon(entry.risk_level)}</span>
										<span class="tech-name">{entry.param_name}</span>
										<span class="status-mini" style="color: {getRiskColor(entry.risk_level)}">{entry.risk_level}</span>
										{#if entry.is_reflected}<span class="depth-mini">🪞</span>{/if}
									</span>
								{/each}
							</div>
						{:else if activeResultTab === 'list'}
							<div class="filter-bar">
								<button class="filter-btn {riskFilter === 'all' && categoryFilter === 'all' ? 'active' : ''}" on:click={() => { riskFilter = 'all'; categoryFilter = 'all'; }}>
									{$tr('paramDiscovery.labels.all')} ({result.found_params.length})
								</button>
								{#each getRiskGroups() as group}
									<button class="filter-btn {riskFilter === group.risk && categoryFilter === 'all' ? 'active' : ''}" on:click={() => { riskFilter = group.risk; categoryFilter = 'all'; }}>
										{group.icon} {group.risk} ({group.count})
									</button>
								{/each}
								{#if getCategoryGroups().length > 0}
									<span class="filter-divider">|</span>
									{#each getCategoryGroups() as group}
										<button class="filter-btn {categoryFilter === group.category && riskFilter === 'all' ? 'active' : ''}" on:click={() => { categoryFilter = group.category; riskFilter = 'all'; }}>
											{group.icon} {group.category} ({group.count})
										</button>
									{/each}
								{/if}
							</div>

							<div class="search-bar">
								<input type="text" bind:value={searchQuery} placeholder="{$tr('paramDiscovery.labels.search')}" class="search-input" />
								{#if searchQuery.trim() || riskFilter !== 'all' || categoryFilter !== 'all'}
									<button class="clear-filter-btn" on:click={() => { searchQuery = ''; riskFilter = 'all'; categoryFilter = 'all'; }}>✕</button>
								{/if}
								<span class="filter-count">{getFilteredEntries().length} / {result.found_params.length}</span>
							</div>

							<div class="links-table-wrapper">
								<table class="data-table">
									<thead>
										<tr>
											<th>{$tr('paramDiscovery.labels.parameter')}</th>
											<th>{$tr('paramDiscovery.labels.method')}</th>
											<th>{$tr('paramDiscovery.labels.category')}</th>
											<th>{$tr('paramDiscovery.labels.risk')}</th>
											<th>{$tr('paramDiscovery.labels.status')}</th>
											<th>{$tr('paramDiscovery.labels.diff')}</th>
											<th>{$tr('paramDiscovery.labels.reflected')}</th>
											<th>{$tr('paramDiscovery.labels.evidence')}</th>
										</tr>
									</thead>
									<tbody>
										{#each getFilteredEntries() as entry}
											<tr>
												<td>
													<span class="path-cell">
														<span class="tech-icon">{getRiskIcon(entry.risk_level)}</span>
														{entry.param_name}
													</span>
												</td>
												<td>
													<span class="method-badge">{entry.method}</span>
												</td>
												<td>
													<span class="category-badge">{getCategoryIcon(entry.category)} {entry.category}</span>
												</td>
												<td>
													<span class="risk-badge" style="color: {getRiskColor(entry.risk_level)}; border-color: {getRiskColor(entry.risk_level)}40; background: {getRiskColor(entry.risk_level)}15;">
														{entry.risk_level}
													</span>
												</td>
												<td>
													<span class="status-badge-table" style="color: {entry.status_code >= 400 ? '#f97316' : '#22c55e'}; border-color: {entry.status_code >= 400 ? '#f9731640' : '#22c55e40'}; background: {entry.status_code >= 400 ? '#f9731615' : '#22c55e15'};">
														{entry.status_code}
													</span>
												</td>
												<td>
													<span class="diff-text">{entry.response_diff !== null ? (entry.response_diff * 100).toFixed(1) + '%' : '-'}</span>
												</td>
												<td>
													{#if entry.is_reflected}
														<span class="reflected-badge">🪞 Yes</span>
													{:else}
														<span class="text-muted">-</span>
													{/if}
												</td>
												<td>
													<span class="evidence-text" title={entry.evidence}>{entry.evidence}</span>
												</td>
											</tr>
										{/each}
									</tbody>
								</table>
							</div>
						{:else if activeResultTab === 'category'}
							{#each getCategoryGroups() as group}
								<div class="category-section">
									<div class="category-header" style="border-color: rgba(168, 85, 247, 0.15);">
										<span class="category-icon">{group.icon}</span>
										<span class="category-name" style="color: #c4b5fd">{group.category}</span>
										<span class="category-count" style="background: rgba(168, 85, 247, 0.2); color: #c4b5fd">{group.count}</span>
									</div>
									<div class="category-techs">
										{#each result.found_params.filter(e => e.category === group.category) as entry}
											<div class="category-tech-item">
												<div class="cti-left">
													<span class="tech-icon">{getRiskIcon(entry.risk_level)}</span>
													<span class="cti-name">{entry.param_name}</span>
													<span class="risk-mini" style="color: {getRiskColor(entry.risk_level)}">{entry.risk_level}</span>
													{#if entry.is_reflected}<span class="depth-mini">🪞</span>{/if}
												</div>
												<div class="cti-right">
													<span class="method-mini">{entry.method}</span>
													<span class="status-mini" style="color: {entry.status_code >= 400 ? '#f97316' : '#22c55e'}">{entry.status_code}</span>
													<span class="method-mini">{entry.response_time_ms}ms</span>
												</div>
											</div>
										{/each}
									</div>
								</div>
							{/each}
						{:else if activeResultTab === 'sensitive'}
							{#if result.sensitive_params.length > 0}
								<div class="sensitive-list">
									{#each result.sensitive_params as sp}
										<div class="sensitive-item" style="border-left: 3px solid {getSeverityColor(sp.severity)}">
											<div class="si-header">
												<span class="si-icon">{getSeverityIcon(sp.severity)}</span>
												<span class="si-path">{sp.param_name}</span>
												<span class="si-severity" style="background: {getSeverityColor(sp.severity)}20; color: {getSeverityColor(sp.severity)}">{sp.severity}</span>
												<span class="si-category">{sp.category}</span>
											</div>
											<div class="si-desc">{sp.description}</div>
										</div>
									{/each}
								</div>
							{:else}
								<div class="empty-mini">{$tr('paramDiscovery.result.noSensitive')}</div>
							{/if}
						{/if}
					</div>
				{:else}
					<div class="section-card">
						<div class="empty-state">
							<div class="empty-icon">🔍</div>
							<p class="empty-text">{$tr('paramDiscovery.result.empty')}</p>
							<p class="empty-sub">{$tr('paramDiscovery.result.emptySub')}</p>
						</div>
					</div>
				{/if}
			</div>
		</div>
	{:else if activeMainTab === 'history'}
		<div class="section-card">
			<ToolHistory toolType="param_discovery" toolName={$tr('paramDiscovery.title')} bind:this={historyComponent} />
		</div>
	{:else if activeMainTab === 'help'}
		<div class="section-card">
			<ToolHelp toolType="param_discovery" />
		</div>
	{/if}
</div>

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
	.status-chip-label { font-size: 0.75rem; text-transform: capitalize; }
	.status-chip-count { font-size: 0.65rem; padding: 0.05rem 0.3rem; border-radius: 0.2rem; font-weight: 600; background: rgba(255, 255, 255, 0.1); }
	.extracted-params-section { margin-bottom: 1rem; }
	.extracted-group { margin-bottom: 0.5rem; }
	.extracted-label { font-size: 0.8rem; color: #94a3b8; font-weight: 500; margin-bottom: 0.3rem; display: block; }
	.extracted-chips { display: flex; flex-wrap: wrap; gap: 0.3rem; }
	.extracted-chip { padding: 0.2rem 0.5rem; background: rgba(59, 130, 246, 0.1); border: 1px solid rgba(59, 130, 246, 0.2); border-radius: 0.3rem; font-size: 0.72rem; color: #93c5fd; font-family: 'SF Mono', 'Fira Code', monospace; }
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
	.status-mini { font-size: 0.7rem; font-weight: 600; }
	.depth-mini { font-size: 0.55rem; padding: 0.05rem 0.2rem; background: rgba(59, 130, 246, 0.15); color: #93c5fd; border-radius: 0.15rem; font-weight: 600; }
	.filter-bar { display: flex; gap: 0.3rem; margin-bottom: 0.75rem; flex-wrap: wrap; }
	.filter-btn { padding: 0.35rem 0.6rem; border-radius: 0.3rem; border: 1px solid rgba(148, 163, 184, 0.15); background: rgba(15, 23, 42, 0.4); color: #94a3b8; cursor: pointer; font-size: 0.75rem; transition: all 0.2s; text-transform: capitalize; }
	.filter-btn.active { background: rgba(168, 85, 247, 0.15); border-color: rgba(168, 85, 247, 0.4); color: #c4b5fd; }
	.filter-btn:hover:not(.active) { border-color: rgba(148, 163, 184, 0.3); }
	.search-bar { margin-bottom: 0.75rem; display: flex; align-items: center; gap: 0.5rem; }
	.search-input { flex: 1; padding: 0.45rem 0.75rem; border-radius: 0.4rem; border: 1px solid rgba(148, 163, 184, 0.15); background: rgba(15, 23, 42, 0.6); color: #f1f5f9; font-size: 0.8rem; box-sizing: border-box; }
	.search-input:focus { outline: none; border-color: #a855f7; }
	.search-input::placeholder { color: #475569; }
	.clear-filter-btn { padding: 0.35rem 0.5rem; border-radius: 0.3rem; border: 1px solid rgba(239, 68, 68, 0.3); background: rgba(239, 68, 68, 0.1); color: #f87171; cursor: pointer; font-size: 0.75rem; transition: all 0.2s; }
	.clear-filter-btn:hover { background: rgba(239, 68, 68, 0.2); }
	.filter-count { font-size: 0.72rem; color: #94a3b8; white-space: nowrap; }
	.filter-divider { color: #334155; margin: 0 0.15rem; }
	.links-table-wrapper { max-height: 500px; overflow-y: auto; border-radius: 0.5rem; border: 1px solid rgba(148, 163, 184, 0.08); }
	.data-table { width: 100%; border-collapse: collapse; font-size: 0.8rem; }
	.data-table th { text-align: left; padding: 0.5rem 0.6rem; background: rgba(15, 23, 42, 0.6); color: #94a3b8; font-weight: 500; font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.05em; border-bottom: 1px solid rgba(148, 163, 184, 0.1); position: sticky; top: 0; z-index: 1; }
	.data-table td { padding: 0.4rem 0.6rem; border-bottom: 1px solid rgba(148, 163, 184, 0.06); color: #cbd5e1; }
	.data-table tr:hover td { background: rgba(168, 85, 247, 0.05); }
	.path-cell { display: flex; align-items: center; gap: 0.3rem; font-weight: 500; color: #f1f5f9; font-family: 'SF Mono', 'Fira Code', monospace; font-size: 0.8rem; }
	.method-badge { padding: 0.1rem 0.35rem; border-radius: 0.2rem; font-size: 0.65rem; font-weight: 600; background: rgba(168, 85, 247, 0.15); color: #c4b5fd; border: 1px solid rgba(168, 85, 247, 0.25); }
	.category-badge { font-size: 0.72rem; color: #94a3b8; text-transform: capitalize; }
	.risk-badge { display: inline-block; padding: 0.15rem 0.4rem; border-radius: 0.25rem; font-size: 0.7rem; font-weight: 600; border: 1px solid; text-transform: capitalize; }
	.status-badge-table { display: inline-block; padding: 0.15rem 0.4rem; border-radius: 0.25rem; font-size: 0.7rem; font-weight: 600; border: 1px solid; }
	.diff-text { font-size: 0.75rem; color: #86efac; font-family: 'SF Mono', 'Fira Code', monospace; }
	.reflected-badge { font-size: 0.72rem; color: #fbbf24; font-weight: 500; }
	.evidence-text { font-size: 0.72rem; color: #94a3b8; max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; display: block; }
	.text-muted { color: #475569; }
	.category-section { margin-bottom: 1rem; }
	.category-header { display: flex; align-items: center; gap: 0.5rem; padding: 0.5rem 0.75rem; background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(168, 85, 247, 0.15); border-radius: 0.5rem; margin-bottom: 0.5rem; }
	.category-icon { font-size: 1rem; }
	.category-name { font-weight: 600; font-size: 0.9rem; color: #e2e8f0; text-transform: capitalize; }
	.category-count { margin-left: auto; font-size: 0.75rem; padding: 0.1rem 0.4rem; border-radius: 0.25rem; font-weight: 600; }
	.category-techs { display: flex; flex-direction: column; gap: 0.3rem; }
	.category-tech-item { display: flex; justify-content: space-between; align-items: center; padding: 0.4rem 0.6rem; background: rgba(15, 23, 42, 0.4); border-radius: 0.3rem; border: 1px solid rgba(148, 163, 184, 0.06); }
	.category-tech-item:hover { background: rgba(168, 85, 247, 0.05); }
	.cti-left { display: flex; align-items: center; gap: 0.35rem; }
	.cti-name { font-size: 0.85rem; font-weight: 500; color: #e2e8f0; font-family: 'SF Mono', 'Fira Code', monospace; }
	.risk-mini { font-size: 0.65rem; font-weight: 600; text-transform: capitalize; }
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
</style>
