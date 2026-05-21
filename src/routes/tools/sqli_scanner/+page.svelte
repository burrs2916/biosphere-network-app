<script lang="ts">
	import { tr } from '$lib/i18n';
	import ToolHistory from '$lib/components/ToolHistory.svelte';
	import ToolHelp from '$lib/components/ToolHelp.svelte';

	interface SqliVulnerability {
		parameter: string;
		injection_type: string;
		injection_category: string;
		severity: string;
		payload: string;
		evidence: string;
		request_url: string;
		confidence: number;
		db_type: string;
		response_time_ms: number | null;
		http_status: number | null;
		method: string;
	}

	interface SqliSafeEntry {
		parameter: string;
		tests_run: number;
		method: string;
	}

	interface SqliErrorEntry {
		parameter: string;
		payload: string;
		error: string;
		method: string;
	}

	interface DbTypeDistribution {
		db_type: string;
		count: number;
		vulnerable_count: number;
	}

	interface SqliScanResult {
		url: string;
		vulnerabilities: SqliVulnerability[];
		safe_parameters: SqliSafeEntry[];
		errors: SqliErrorEntry[];
		tests_performed: number;
		parameters_tested: string[];
		scan_duration_ms: number;
		summary: string;
		db_type_distribution: DbTypeDistribution[];
	}

	let url = $state('');
	let timeout = $state(15);
	let threads = $state(5);
	let scanLevel = $state('moderate');
	let testGet = $state(true);
	let testPost = $state(false);
	let testCookies = $state(false);
	let testHeaders = $state(false);
	let customParams = $state('');
	let result: SqliScanResult | null = $state(null);
	let error = $state('');
	let processing = $state(false);
	let activeMainTab = $state('analyze');
	let activeResultTab = $state('overview');
	let searchQuery = $state('');
	let severityFilter = $state('all');
	let categoryFilter = $state('all');
	let methodFilter = $state('all');
	let exportFormat = $state('json');
	let showTargetSelector = $state(false);
	let targetList: any[] = $state([]);
	let selectedTargets: any[] = $state([]);
	let selectedTargetIds: number[] = $state([]);
	let targetSearchQuery = $state('');
	let loadingTargets = $state(false);

	const TOOL_NAME = 'sqli_scanner';
	let historyComponent: ToolHistory;

	function getScanLevelLabel(level: string): string {
		const labels: Record<string, string> = {
			basic: $tr('sqliScanner.levelBasic'),
			moderate: $tr('sqliScanner.levelModerate'),
			aggressive: $tr('sqliScanner.levelAggressive')
		};
		return labels[level] || level;
	}

	function getSeverityColor(severity: string): string {
		switch (severity) {
			case 'high': return '#ef4444';
			case 'medium': return '#f59e0b';
			case 'low': return '#22c55e';
			default: return '#64748b';
		}
	}

	function getSeverityBg(severity: string): string {
		switch (severity) {
			case 'high': return 'rgba(239, 68, 68, 0.15)';
			case 'medium': return 'rgba(245, 158, 11, 0.15)';
			case 'low': return 'rgba(34, 197, 94, 0.15)';
			default: return 'rgba(100, 116, 139, 0.15)';
		}
	}

	function getMethodIcon(method: string): string {
		switch (method) {
			case 'GET': return '🔗';
			case 'POST': return '📝';
			case 'Cookie': return '🍪';
			case 'Header': return '📋';
			default: return '🔍';
		}
	}

	function getDbColor(db: string): string {
		switch (db) {
			case 'MySQL': return '#00758f';
			case 'PostgreSQL': return '#336791';
			case 'MSSQL': return '#cc2927';
			case 'Oracle': return '#f80000';
			case 'SQLite': return '#003b57';
			default: return '#64748b';
		}
	}

	function getConfidencePercent(c: number): number {
		return Math.round(c * 100);
	}

	function formatDuration(ms: number): string {
		if (ms < 1000) return `${ms}ms`;
		return `${(ms / 1000).toFixed(1)}s`;
	}

	function getFilteredVulns() {
		return result?.vulnerabilities.filter(v => {
			if (severityFilter !== 'all' && v.severity !== severityFilter) return false;
			if (categoryFilter !== 'all' && v.injection_category !== categoryFilter) return false;
			if (methodFilter !== 'all' && v.method !== methodFilter) return false;
			if (searchQuery) {
				const q = searchQuery.toLowerCase();
				return v.parameter.toLowerCase().includes(q) ||
					v.payload.toLowerCase().includes(q) ||
					v.evidence.toLowerCase().includes(q) ||
					v.db_type.toLowerCase().includes(q);
			}
			return true;
		}) || [];
	}

	function getUniqueCategories() {
		return [...new Set(result?.vulnerabilities.map(v => v.injection_category) || [])];
	}

	function getUniqueMethods() {
		return [...new Set(result?.vulnerabilities.map(v => v.method) || [])];
	}

	function getCategoryChartData() {
		if (!result || !result.vulnerabilities.length) return [];
		const cats = getUniqueCategories();
		const maxVulns = Math.max(...cats.map(c => result!.vulnerabilities.filter(v => v.injection_category === c).length));
		return cats.map(c => ({
			category: c,
			count: result!.vulnerabilities.filter(v => v.injection_category === c).length,
			percent: maxVulns > 0 ? (result!.vulnerabilities.filter(v => v.injection_category === c).length / maxVulns) * 100 : 0
		}));
	}

	function getDbTypeChartData() {
		if (!result || !result.db_type_distribution.length) return [];
		const maxCount = Math.max(...result.db_type_distribution.map(d => d.count));
		return result.db_type_distribution.map(db => ({
			...db,
			percent: maxCount > 0 ? (db.count / maxCount) * 100 : 0
		}));
	}

	async function scan() {
		if (!url.trim()) {
			error = $tr('sqliScanner.urlRequired');
			return;
		}
		if (!testGet && !testPost && !testCookies && !testHeaders) {
			error = $tr('sqliScanner.methodRequired');
			return;
		}

		processing = true;
		error = '';
		result = null;
		activeResultTab = 'overview';

		try {
			const { invoke } = await import('@tauri-apps/api/core');
			const customParamsList = customParams
				.split(/[,，\n]/)
				.map(p => p.trim())
				.filter(p => p.length > 0);

			result = await invoke<SqliScanResult>('scan_sqli_command', {
				config: {
					url: url.trim(),
					timeout,
					threads,
					scan_level: scanLevel,
					test_get: testGet,
					test_post: testPost,
					test_cookies: testCookies,
					test_headers: testHeaders,
					custom_parameters: customParamsList
				},
				targetId: selectedTargetIds.length > 0 ? selectedTargetIds[0] : null
			});

			if (result && historyComponent) {
				await historyComponent.saveHistory(url.trim(), JSON.stringify(result), result.summary, 'completed');
			}
		} catch (e: any) {
			error = e.toString();
			if (historyComponent) {
				await historyComponent.saveHistory(url.trim(), JSON.stringify({ error: e.toString() }), `Error: ${e.toString()}`, 'error');
			}
		} finally {
			processing = false;
		}
	}

	async function exportResult() {
		if (!result) return;
		try {
			const { save } = await import('@tauri-apps/plugin-dialog');
			const { writeTextFile } = await import('@tauri-apps/plugin-fs');
			const path = await save({
				defaultPath: `sqli_scan_${Date.now()}.${exportFormat}`,
				filters: [{ name: exportFormat.toUpperCase(), extensions: [exportFormat] }]
			});
			if (!path) return;

			let content: string;
			if (exportFormat === 'json') {
				content = JSON.stringify(result, null, 2);
			} else {
				const headers = ['Parameter', 'Injection Type', 'Category', 'Severity', 'Payload', 'Evidence', 'DB Type', 'Confidence', 'Method', 'Status', 'Response Time'];
				const rows = result.vulnerabilities.map(v =>
					[v.parameter, v.injection_type, v.injection_category, v.severity, v.payload, v.evidence, v.db_type, v.confidence.toString(), v.method, (v.http_status || '').toString(), (v.response_time_ms || '').toString()]
				);
				content = [headers, ...rows].map(r => r.map(c => `"${c.replace(/"/g, '""')}"`).join(',')).join('\n');
			}
			await writeTextFile(path as string, content);
		} catch {}
	}

	function clearAll() {
		url = '';
		result = null;
		error = '';
		customParams = '';
		scanLevel = 'moderate';
		testGet = true;
		testPost = false;
		testCookies = false;
		testHeaders = false;
		timeout = 15;
		threads = 5;
		searchQuery = '';
		severityFilter = 'all';
		categoryFilter = 'all';
		methodFilter = 'all';
	}

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
</script>

<div class="nd-page">
	<div class="page-header">
		<div class="header-left">
			<a href="/" class="back-link">{$tr('common.backToHome')}</a>
			<h1 class="page-title">💉 {$tr('sqliScanner.title')}</h1>
			<p class="page-subtitle">{$tr('sqliScanner.subtitle')}</p>
		</div>
	</div>

	<div class="tabs">
		<button class="tab-btn {activeMainTab === 'analyze' ? 'active' : ''}" onclick={() => activeMainTab = 'analyze'}>
			<span class="tab-icon">🔍</span> {$tr('sqliScanner.scan')}
		</button>
		<button class="tab-btn {activeMainTab === 'history' ? 'active' : ''}" onclick={() => activeMainTab = 'history'}>
			<span class="tab-icon">📋</span> {$tr('sqliScanner.history')}
		</button>
		<button class="tab-btn {activeMainTab === 'help' ? 'active' : ''}" onclick={() => activeMainTab = 'help'}>
			<span class="tab-icon">📖</span> {$tr('sqliScanner.help')}
		</button>
	</div>

	{#if activeMainTab === 'analyze'}
		<div class="content-grid">
			<div class="input-section">
				<div class="section-card">
					<h2 class="section-title">{$tr('sqliScanner.configTitle')}</h2>
					<p class="section-desc">{$tr('sqliScanner.configDesc')}</p>

					<div class="form-group">
						<label class="form-label">{$tr('sqliScanner.targetUrl')}</label>
						<div class="input-with-action">
							<input type="text" bind:value={url} placeholder="https://example.com/page?id=1" class="form-input" disabled={processing} onkeydown={(e) => e.key === 'Enter' && scan()} />
							<button type="button" class="action-btn" onclick={openTargetSelectorModal} disabled={processing} title={$tr('common.selectTarget')}>
								🎯
							</button>
						</div>
					</div>

					<div class="form-group">
						<label class="form-label">{$tr('sqliScanner.scanLevel')}</label>
						<div class="mode-grid">
							{#each ['basic', 'moderate', 'aggressive'] as level}
								<button class="mode-btn {scanLevel === level ? 'active' : ''}" onclick={() => scanLevel = level} disabled={processing}>
									<span class="mode-name">{getScanLevelLabel(level)}</span>
								</button>
							{/each}
						</div>
					</div>

					<div class="form-row">
						<div class="form-group">
							<label class="form-label">⏱️ {$tr('sqliScanner.timeout')}</label>
							<input type="number" bind:value={timeout} class="form-input" min="5" max="60" disabled={processing} />
						</div>
						<div class="form-group">
							<label class="form-label">🔀 {$tr('sqliScanner.threads')}</label>
							<input type="number" bind:value={threads} class="form-input" min="1" max="20" disabled={processing} />
						</div>
					</div>

					<div class="form-group">
						<label class="form-label">{$tr('sqliScanner.testMethods')}</label>
						<div class="target-grid">
							<label class="target-chip {testGet ? 'active' : ''}">
								<input type="checkbox" bind:checked={testGet} disabled={processing} />
								<span>🔗 GET</span>
							</label>
							<label class="target-chip {testPost ? 'active' : ''}">
								<input type="checkbox" bind:checked={testPost} disabled={processing} />
								<span>📝 POST</span>
							</label>
							<label class="target-chip {testCookies ? 'active' : ''}">
								<input type="checkbox" bind:checked={testCookies} disabled={processing} />
								<span>🍪 Cookie</span>
							</label>
							<label class="target-chip {testHeaders ? 'active' : ''}">
								<input type="checkbox" bind:checked={testHeaders} disabled={processing} />
								<span>📋 Header</span>
							</label>
						</div>
					</div>

					<div class="form-group">
						<label class="form-label">🎯 {$tr('sqliScanner.customParams')}</label>
						<textarea bind:value={customParams} placeholder="id, user, search..." class="form-input" style="height: 60px; resize: vertical;" disabled={processing}></textarea>
					</div>

					<div class="button-group">
						<button class="btn-primary" onclick={scan} disabled={processing || !url.trim() || (!testGet && !testPost && !testCookies && !testHeaders)}>
							{#if processing}<span class="spinner"></span>{$tr('sqliScanner.scanning')}{:else}💉 {$tr('sqliScanner.startScan')}{/if}
						</button>
						<button class="btn-secondary" onclick={clearAll} disabled={processing}>🗑️</button>
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
								<h2 class="section-title" style="margin-bottom:0">💉 {result.url}</h2>
							</div>
							<div class="header-actions">
								<div class="resource-score-badge">
									<span class="score-value">{result.vulnerabilities.length}</span>
									<span class="score-label">{$tr('sqliScanner.vulnsFound')}</span>
								</div>
								<select bind:value={exportFormat} class="export-select">
									<option value="json">JSON</option>
									<option value="csv">CSV</option>
								</select>
								<button class="btn-export" onclick={exportResult}>
									📤 {$tr('sqliScanner.export')}
								</button>
							</div>
						</div>

						<div class="summary-bar">{result.summary}</div>

						<div class="result-tabs">
							<button class="result-tab {activeResultTab === 'overview' ? 'active' : ''}" onclick={() => activeResultTab = 'overview'}>
								📊 {$tr('sqliScanner.tabOverview')}
							</button>
							<button class="result-tab {activeResultTab === 'vulns' ? 'active' : ''}" onclick={() => activeResultTab = 'vulns'}>
								🔴 {$tr('sqliScanner.tabVulns')} ({result.vulnerabilities.length})
							</button>
							<button class="result-tab {activeResultTab === 'safe' ? 'active' : ''}" onclick={() => activeResultTab = 'safe'}>
								🟢 {$tr('sqliScanner.tabSafe')} ({result.safe_parameters.length})
							</button>
							{#if result.errors.length > 0}
								<button class="result-tab {activeResultTab === 'errors' ? 'active' : ''}" onclick={() => activeResultTab = 'errors'}>
									⚠️ {$tr('sqliScanner.tabErrors')} ({result.errors.length})
								</button>
							{/if}
							{#if result.db_type_distribution.length > 0}
								<button class="result-tab {activeResultTab === 'dbtype' ? 'active' : ''}" onclick={() => activeResultTab = 'dbtype'}>
									🗄️ {$tr('sqliScanner.tabDbType')}
								</button>
							{/if}
						</div>

						{#if activeResultTab === 'overview'}
							<div class="overview-grid">
								<div class="overview-stat">
									<span class="stat-label">{$tr('sqliScanner.testsPerformed')}</span>
									<span class="stat-value">{result.tests_performed}</span>
								</div>
								<div class="overview-stat">
									<span class="stat-label">🔴 {$tr('sqliScanner.highSeverity')}</span>
									<span class="stat-value" style="color: {result.vulnerabilities.filter(v => v.severity === 'high').length > 0 ? '#ef4444' : '#64748b'}">{result.vulnerabilities.filter(v => v.severity === 'high').length}</span>
								</div>
								<div class="overview-stat">
									<span class="stat-label">🟡 {$tr('sqliScanner.mediumSeverity')}</span>
									<span class="stat-value" style="color: {result.vulnerabilities.filter(v => v.severity === 'medium').length > 0 ? '#f59e0b' : '#64748b'}">{result.vulnerabilities.filter(v => v.severity === 'medium').length}</span>
								</div>
								<div class="overview-stat">
									<span class="stat-label">🟢 {$tr('sqliScanner.lowSeverity')}</span>
									<span class="stat-value" style="color: {result.vulnerabilities.filter(v => v.severity === 'low').length > 0 ? '#22c55e' : '#64748b'}">{result.vulnerabilities.filter(v => v.severity === 'low').length}</span>
								</div>
								<div class="overview-stat">
									<span class="stat-label">🎯 {$tr('sqliScanner.paramsTested')}</span>
									<span class="stat-value">{result.parameters_tested.length}</span>
								</div>
								<div class="overview-stat">
									<span class="stat-label">🟢 {$tr('sqliScanner.safeParams')}</span>
									<span class="stat-value" style="color: #22c55e">{result.safe_parameters.length}</span>
								</div>
								<div class="overview-stat">
									<span class="stat-label">⏱️ {$tr('sqliScanner.scanDuration')}</span>
									<span class="stat-value">{formatDuration(result.scan_duration_ms)}</span>
								</div>
								<div class="overview-stat">
									<span class="stat-label">⚠️ {$tr('sqliScanner.errorCount')}</span>
									<span class="stat-value" style="color: {result.errors.length > 0 ? '#f59e0b' : '#64748b'}">{result.errors.length}</span>
								</div>
							</div>

							{#if result && result.vulnerabilities.length > 0}
								<div class="category-chart">
									<h3 class="subsection-title">{$tr('sqliScanner.injectionCategories')}</h3>
									<div class="chart-bars">
										{#each getCategoryChartData() as data}
											<div class="chart-row">
												<span class="chart-label">{data.category}</span>
												<div class="chart-bar-track">
													<div class="chart-bar-fill" style="width: {data.percent}%; background: {data.category === 'Error-based' ? '#ef4444' : data.category === 'Boolean-based' ? '#f59e0b' : data.category === 'Time-based' ? '#a855f7' : data.category === 'UNION-based' ? '#3b82f6' : data.category === 'Stacked' ? '#ec4899' : '#64748b'}"></div>
												</div>
												<span class="chart-count">{data.count}</span>
											</div>
										{/each}
									</div>
								</div>
							{/if}

							{#if result && result.parameters_tested.length > 0}
								<div class="params-list">
									<h3 class="subsection-title">{$tr('sqliScanner.testedParamsList')}</h3>
									<div class="chip-list">
										{#each result.parameters_tested as param}
											<span class="param-chip">{param}</span>
										{/each}
									</div>
								</div>
							{/if}
						{/if}

						{#if activeResultTab === 'vulns'}
							{#if result && result.vulnerabilities.length > 0}
								<div class="filter-bar">
									<input type="text" bind:value={searchQuery} placeholder="{$tr('sqliScanner.searchVulns')}..." class="filter-input" />
									<select bind:value={severityFilter} class="filter-select">
										<option value="all">{$tr('sqliScanner.allSeverities')}</option>
										<option value="high">🔴 High</option>
										<option value="medium">🟡 Medium</option>
										<option value="low">🟢 Low</option>
									</select>
									<select bind:value={categoryFilter} class="filter-select">
										<option value="all">{$tr('sqliScanner.allCategories')}</option>
										{#each getUniqueCategories() as cat}
											<option value={cat}>{cat}</option>
										{/each}
									</select>
									<select bind:value={methodFilter} class="filter-select">
										<option value="all">{$tr('sqliScanner.allMethods')}</option>
										{#each getUniqueMethods() as m}
											<option value={m}>{m}</option>
										{/each}
									</select>
								</div>

								<div class="vuln-list">
									{#each getFilteredVulns() as vuln, i}
										<div class="vuln-card">
											<div class="vuln-header">
												<div class="vuln-header-left">
													<span class="severity-badge" style="background: {getSeverityBg(vuln.severity)}; color: {getSeverityColor(vuln.severity)}">
														{vuln.severity.toUpperCase()}
													</span>
													<span class="method-badge">{getMethodIcon(vuln.method)} {vuln.method}</span>
													<span class="category-badge">{vuln.injection_category}</span>
												</div>
												<span class="confidence-badge">
													{$tr('sqliScanner.confidence')}: {getConfidencePercent(vuln.confidence)}%
												</span>
											</div>
											<div class="vuln-body">
												<div class="vuln-field">
													<span class="field-label">🎯 {$tr('sqliScanner.parameter')}</span>
													<code class="field-value">{vuln.parameter}</code>
												</div>
												<div class="vuln-field">
													<span class="field-label">💉 {$tr('sqliScanner.injectionType')}</span>
													<code class="field-value">{vuln.injection_type}</code>
												</div>
												<div class="vuln-field">
													<span class="field-label">💣 Payload</span>
													<code class="field-value payload-code">{vuln.payload}</code>
												</div>
												<div class="vuln-field">
													<span class="field-label">🔍 Evidence</span>
													<code class="field-value">{vuln.evidence}</code>
												</div>
												<div class="vuln-meta">
													{#if vuln.db_type !== 'Unknown'}
														<span class="db-badge" style="background: {getDbColor(vuln.db_type)}20; color: {getDbColor(vuln.db_type)}">🗄️ {vuln.db_type}</span>
													{/if}
													{#if vuln.http_status}
														<span class="meta-chip">HTTP {vuln.http_status}</span>
													{/if}
													{#if vuln.response_time_ms}
														<span class="meta-chip">⏱️ {vuln.response_time_ms}ms</span>
													{/if}
												</div>
											</div>
										</div>
									{/each}
									{#if getFilteredVulns().length === 0}
									<div class="empty-state">{$tr('sqliScanner.noMatchingVulns')}</div>
								{/if}
								</div>
							{:else}
								<div class="safe-state">
									<span class="safe-icon">🛡️</span>
									<span class="safe-text">{$tr('sqliScanner.noVulnsFound')}</span>
								</div>
							{/if}
						{/if}

						{#if activeResultTab === 'safe'}
							{#if result && result.safe_parameters.length > 0}
								<div class="safe-list">
									{#each result.safe_parameters as entry}
										<div class="safe-item">
											<span class="safe-check">✅</span>
											<span class="safe-param">{entry.parameter}</span>
											<span class="safe-method">{getMethodIcon(entry.method)} {entry.method}</span>
											<span class="safe-tests">{$tr('sqliScanner.testsRun')}: {entry.tests_run}</span>
										</div>
									{/each}
								</div>
							{:else}
								<div class="empty-state">{$tr('sqliScanner.noSafeParams')}</div>
							{/if}
						{/if}

						{#if activeResultTab === 'errors'}
							{#if result && result.errors.length > 0}
								<div class="error-list">
									{#each result.errors as err, i}
										<div class="error-item">
											<div class="error-item-header">
												<span class="error-item-param">⚠️ {err.parameter}</span>
												<span class="error-item-method">{err.method}</span>
											</div>
											<code class="error-item-payload">{err.payload}</code>
											<div class="error-item-msg">{err.error}</div>
										</div>
									{/each}
								</div>
							{:else}
								<div class="empty-state">{$tr('sqliScanner.noErrors')}</div>
							{/if}
						{/if}

						{#if activeResultTab === 'dbtype'}
							{#if result && result.db_type_distribution.length > 0}
								<div class="dbtype-list">
									{#each getDbTypeChartData() as db}
										<div class="dbtype-card">
											<div class="dbtype-header">
												<span class="dbtype-name" style="color: {getDbColor(db.db_type)}">🗄️ {db.db_type}</span>
												<span class="dbtype-count">{$tr('sqliScanner.totalHits')}: {db.count}</span>
											</div>
											<div class="dbtype-bar-track">
												<div class="dbtype-bar-fill" style="width: {db.percent}%; background: {getDbColor(db.db_type)}"></div>
											</div>
											<div class="dbtype-meta">
												<span class="dbtype-vuln">🔴 {$tr('sqliScanner.highVulns')}: {db.vulnerable_count}</span>
											</div>
										</div>
									{/each}
								</div>
							{:else}
								<div class="empty-state">{$tr('sqliScanner.noDbInfo')}</div>
							{/if}
						{/if}
					{:else if processing}
						<div class="processing-state">
							<div class="processing-icon">
								<span class="pulse">💉</span>
							</div>
							<div class="processing-text">{$tr('sqliScanner.scanningProgress')}</div>
							<div class="processing-hint">{$tr('sqliScanner.scanningHint')}</div>
						</div>
					{:else}
						<div class="empty-state-main">
							<span class="empty-icon">💉</span>
							<span class="empty-text">{$tr('sqliScanner.enterUrl')}</span>
						</div>
					{/if}
				</div>
			</div>
		</div>
	{:else if activeMainTab === 'history'}
		<ToolHistory bind:this={historyComponent} toolType={TOOL_NAME} toolName={TOOL_NAME} on:select={(e) => { url = e.detail; activeMainTab = 'analyze'; }} />
	{:else if activeMainTab === 'help'}
		<ToolHelp toolType="sqli_scanner" />
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
		grid-template-columns: repeat(3, 1fr);
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
	}

	.header-actions {
		display: flex;
		align-items: center;
		gap: 0.5rem;
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
		border-radius: 0.4rem;
		border: 1px solid rgba(148, 163, 184, 0.15);
		background: rgba(15, 23, 42, 0.6);
		color: #94a3b8;
		font-size: 0.75rem;
	}

	.btn-export {
		padding: 0.35rem 0.75rem;
		border-radius: 0.4rem;
		border: 1px solid rgba(168, 85, 247, 0.3);
		background: rgba(168, 85, 247, 0.1);
		color: #c4b5fd;
		cursor: pointer;
		font-size: 0.8rem;
		transition: all 0.2s;
	}

	.btn-export:hover { background: rgba(168, 85, 247, 0.2); }

	.summary-bar {
		font-size: 0.8rem;
		color: #94a3b8;
		padding: 0.5rem 0.75rem;
		background: rgba(15, 23, 42, 0.4);
		border-radius: 0.4rem;
		margin-bottom: 1rem;
		border: 1px solid rgba(148, 163, 184, 0.08);
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
		text-align: center;
	}

	.stat-value {
		font-size: 1.25rem;
		font-weight: 700;
		color: #f1f5f9;
	}

	.subsection-title {
		font-size: 0.85rem;
		font-weight: 600;
		color: #c4b5fd;
		margin: 1rem 0 0.5rem;
	}

	.category-chart {
		margin-top: 1rem;
	}

	.chart-bars { display: flex; flex-direction: column; gap: 0.5rem; }

	.chart-row {
		display: flex;
		align-items: center;
		gap: 0.5rem;
	}

	.chart-label {
		width: 100px;
		font-size: 0.75rem;
		color: #94a3b8;
		text-align: right;
		flex-shrink: 0;
	}

	.chart-bar-track {
		flex: 1;
		height: 20px;
		background: rgba(15, 23, 42, 0.4);
		border-radius: 4px;
		overflow: hidden;
	}

	.chart-bar-fill {
		height: 100%;
		border-radius: 4px;
		transition: width 0.5s ease;
		min-width: 4px;
	}

	.chart-count {
		font-size: 0.75rem;
		color: #f1f5f9;
		font-weight: 600;
		width: 30px;
		text-align: right;
	}

	.params-list { margin-top: 1rem; }

	.chip-list {
		display: flex;
		flex-wrap: wrap;
		gap: 0.35rem;
	}

	.param-chip {
		padding: 0.25rem 0.5rem;
		border-radius: 0.3rem;
		background: rgba(168, 85, 247, 0.1);
		border: 1px solid rgba(168, 85, 247, 0.2);
		color: #c4b5fd;
		font-size: 0.7rem;
		font-family: monospace;
	}

	.filter-bar {
		display: flex;
		gap: 0.5rem;
		margin-bottom: 1rem;
		flex-wrap: wrap;
	}

	.filter-input {
		flex: 1;
		min-width: 150px;
		padding: 0.4rem 0.6rem;
		border-radius: 0.4rem;
		border: 1px solid rgba(148, 163, 184, 0.15);
		background: rgba(15, 23, 42, 0.6);
		color: #f1f5f9;
		font-size: 0.8rem;
	}

	.filter-input:focus { outline: none; border-color: #a855f7; }

	.filter-select {
		padding: 0.4rem 0.5rem;
		border-radius: 0.4rem;
		border: 1px solid rgba(148, 163, 184, 0.15);
		background: rgba(15, 23, 42, 0.6);
		color: #94a3b8;
		font-size: 0.75rem;
	}

	.vuln-list { display: flex; flex-direction: column; gap: 0.75rem; }

	.vuln-card {
		background: rgba(15, 23, 42, 0.4);
		border: 1px solid rgba(148, 163, 184, 0.08);
		border-radius: 0.5rem;
		padding: 0.75rem;
		transition: border-color 0.2s;
	}

	.vuln-card:hover { border-color: rgba(168, 85, 247, 0.3); }

	.vuln-header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		margin-bottom: 0.5rem;
	}

	.vuln-header-left {
		display: flex;
		align-items: center;
		gap: 0.4rem;
	}

	.severity-badge {
		padding: 0.15rem 0.5rem;
		border-radius: 0.3rem;
		font-size: 0.7rem;
		font-weight: 700;
	}

	.method-badge {
		padding: 0.15rem 0.4rem;
		border-radius: 0.3rem;
		background: rgba(148, 163, 184, 0.1);
		color: #94a3b8;
		font-size: 0.7rem;
	}

	.category-badge {
		padding: 0.15rem 0.4rem;
		border-radius: 0.3rem;
		background: rgba(59, 130, 246, 0.15);
		color: #93c5fd;
		font-size: 0.7rem;
	}

	.confidence-badge {
		font-size: 0.75rem;
		color: #a855f7;
		font-weight: 600;
	}

	.vuln-body { display: flex; flex-direction: column; gap: 0.35rem; }

	.vuln-field {
		display: flex;
		align-items: baseline;
		gap: 0.5rem;
	}

	.field-label {
		font-size: 0.7rem;
		color: #64748b;
		min-width: 100px;
		flex-shrink: 0;
	}

	.field-value {
		font-size: 0.8rem;
		color: #e2e8f0;
		background: rgba(15, 23, 42, 0.6);
		padding: 0.15rem 0.4rem;
		border-radius: 0.25rem;
		word-break: break-all;
	}

	.payload-code {
		color: #fbbf24;
		border: 1px solid rgba(251, 191, 36, 0.2);
	}

	.vuln-meta {
		display: flex;
		gap: 0.4rem;
		margin-top: 0.25rem;
		flex-wrap: wrap;
	}

	.db-badge {
		padding: 0.15rem 0.4rem;
		border-radius: 0.3rem;
		font-size: 0.7rem;
	}

	.meta-chip {
		padding: 0.15rem 0.4rem;
		border-radius: 0.3rem;
		background: rgba(148, 163, 184, 0.1);
		color: #94a3b8;
		font-size: 0.7rem;
	}

	.safe-state {
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: 0.75rem;
		padding: 3rem;
	}

	.safe-icon { font-size: 3rem; }
	.safe-text { color: #22c55e; font-size: 1rem; font-weight: 600; }

	.safe-list { display: flex; flex-direction: column; gap: 0.35rem; }

	.safe-item {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		padding: 0.5rem 0.75rem;
		background: rgba(15, 23, 42, 0.4);
		border: 1px solid rgba(34, 197, 94, 0.1);
		border-radius: 0.4rem;
	}

	.safe-check { font-size: 0.85rem; }

	.safe-param {
		font-family: monospace;
		color: #e2e8f0;
		font-size: 0.8rem;
		flex: 1;
	}

	.safe-method {
		font-size: 0.7rem;
		color: #94a3b8;
	}

	.safe-tests {
		font-size: 0.7rem;
		color: #64748b;
	}

	.error-list { display: flex; flex-direction: column; gap: 0.5rem; }

	.error-item {
		padding: 0.6rem 0.75rem;
		background: rgba(239, 68, 68, 0.05);
		border: 1px solid rgba(239, 68, 68, 0.1);
		border-radius: 0.4rem;
	}

	.error-item-header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		margin-bottom: 0.3rem;
	}

	.error-item-param {
		font-size: 0.8rem;
		color: #fca5a5;
		font-weight: 600;
	}

	.error-item-method {
		font-size: 0.7rem;
		color: #94a3b8;
	}

	.error-item-payload {
		display: block;
		font-size: 0.75rem;
		color: #fbbf24;
		margin-bottom: 0.25rem;
		word-break: break-all;
	}

	.error-item-msg {
		font-size: 0.75rem;
		color: #94a3b8;
	}

	.dbtype-list { display: flex; flex-direction: column; gap: 0.75rem; }

	.dbtype-card {
		padding: 0.75rem;
		background: rgba(15, 23, 42, 0.4);
		border: 1px solid rgba(148, 163, 184, 0.08);
		border-radius: 0.5rem;
	}

	.dbtype-header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		margin-bottom: 0.5rem;
	}

	.dbtype-name {
		font-size: 0.9rem;
		font-weight: 600;
	}

	.dbtype-count {
		font-size: 0.75rem;
		color: #94a3b8;
	}

	.dbtype-bar-track {
		height: 8px;
		background: rgba(15, 23, 42, 0.4);
		border-radius: 4px;
		overflow: hidden;
		margin-bottom: 0.35rem;
	}

	.dbtype-bar-fill {
		height: 100%;
		border-radius: 4px;
		transition: width 0.5s ease;
		min-width: 4px;
	}

	.dbtype-meta {
		display: flex;
		gap: 0.5rem;
	}

	.dbtype-vuln {
		font-size: 0.7rem;
		color: #fca5a5;
	}

	.empty-state {
		text-align: center;
		padding: 2rem;
		color: #64748b;
		font-size: 0.85rem;
	}

	.empty-state-main {
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: 0.75rem;
		padding: 4rem;
	}

	.empty-icon { font-size: 3rem; opacity: 0.5; }
	.empty-text { color: #64748b; font-size: 0.9rem; }

	.processing-state {
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: 1rem;
		padding: 4rem;
	}

	.processing-icon { font-size: 2.5rem; }

	.pulse {
		animation: pulse 1.5s ease-in-out infinite;
	}

	@keyframes pulse {
		0%, 100% { transform: scale(1); opacity: 1; }
		50% { transform: scale(1.2); opacity: 0.7; }
	}

	.processing-text {
		color: #c4b5fd;
		font-size: 1rem;
		font-weight: 600;
	}

	.processing-hint {
		color: #64748b;
		font-size: 0.8rem;
	}

	@media (max-width: 768px) {
		.content-grid {
			grid-template-columns: 1fr;
		}
		.overview-grid {
			grid-template-columns: repeat(2, 1fr);
		}
	}

	.input-with-action {
		display: flex;
		gap: 0.5rem;
	}
	.input-with-action .form-input {
		flex: 1;
	}
	.action-btn {
		padding: 0.5rem 0.75rem;
		border: 1px solid rgba(168, 85, 247, 0.3);
		border-radius: 0.5rem;
		background: rgba(168, 85, 247, 0.1);
		color: #c4b5fd;
		cursor: pointer;
		font-size: 1rem;
		transition: all 0.2s;
		white-space: nowrap;
	}
	.action-btn:hover:not(:disabled) {
		background: rgba(168, 85, 247, 0.2);
		border-color: rgba(168, 85, 247, 0.5);
	}
	.action-btn:disabled {
		opacity: 0.5;
		cursor: not-allowed;
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
		background: #1e293b;
		border: 1px solid rgba(168, 85, 247, 0.2);
		border-radius: 0.75rem;
		width: 90%;
		max-width: 500px;
		max-height: 80vh;
		display: flex;
		flex-direction: column;
	}
	.modal-header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		padding: 1rem 1.25rem;
		border-bottom: 1px solid rgba(148, 163, 184, 0.1);
	}
	.modal-header h3 {
		margin: 0;
		color: #f1f5f9;
		font-size: 1rem;
	}
	.modal-close {
		background: none;
		border: none;
		color: #94a3b8;
		cursor: pointer;
		font-size: 1.2rem;
	}
	.modal-body {
		padding: 1rem 1.25rem;
		overflow-y: auto;
		flex: 1;
	}
	.modal-footer {
		display: flex;
		justify-content: flex-end;
		align-items: center;
		gap: 0.75rem;
		padding: 0.75rem 1.25rem;
		border-top: 1px solid rgba(148, 163, 184, 0.1);
	}
	.selected-count {
		flex: 1;
		color: #94a3b8;
		font-size: 0.8rem;
	}
	.target-list {
		max-height: 300px;
		overflow-y: auto;
		display: flex;
		flex-direction: column;
		gap: 0.25rem;
	}
	.target-select-item {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		padding: 0.5rem 0.75rem;
		border-radius: 0.4rem;
		cursor: pointer;
		transition: background 0.2s;
		color: #cbd5e1;
		font-size: 0.85rem;
	}
	.target-select-item:hover {
		background: rgba(168, 85, 247, 0.08);
	}
	.target-select-item.selected {
		background: rgba(168, 85, 247, 0.15);
		border: 1px solid rgba(168, 85, 247, 0.3);
	}
	.target-select-item input[type="checkbox"] {
		accent-color: #a855f7;
	}
	.loading-state, .empty-state {
		text-align: center;
		padding: 2rem;
		color: #94a3b8;
	}
	.spinner {
		display: inline-block;
		width: 1rem;
		height: 1rem;
		border: 2px solid rgba(168, 85, 247, 0.2);
		border-top-color: #a855f7;
		border-radius: 50%;
		animation: spin 0.8s linear infinite;
	}
	@keyframes spin {
		to { transform: rotate(360deg); }
	}
	.btn-primary-sm {
		padding: 0.4rem 1rem;
		border: none;
		border-radius: 0.4rem;
		background: linear-gradient(135deg, #a855f7, #6366f1);
		color: white;
		cursor: pointer;
		font-size: 0.8rem;
		font-weight: 600;
	}
	.btn-primary-sm:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}
	.btn-secondary {
		padding: 0.4rem 1rem;
		border: 1px solid rgba(148, 163, 184, 0.2);
		border-radius: 0.4rem;
		background: transparent;
		color: #94a3b8;
		cursor: pointer;
		font-size: 0.8rem;
	}
</style>
