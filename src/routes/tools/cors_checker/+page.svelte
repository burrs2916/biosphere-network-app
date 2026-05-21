<script lang="ts">
	import { tr } from '$lib/i18n';
	import ToolHistory from '$lib/components/ToolHistory.svelte';
	import ToolHelp from '$lib/components/ToolHelp.svelte';

	interface CorsIssue {
		issue_type: string;
		severity: string;
		description: string;
		detail: string;
		recommendation: string;
		confidence: number;
		origin: string | null;
		method: string | null;
	}

	interface CorsOriginResult {
		origin: string;
		allowed: boolean;
		allow_credentials: boolean;
		allow_methods: string | null;
		allow_headers: string | null;
		acao_header: string | null;
		acac_header: string | null;
		is_wildcard: boolean;
		is_null: boolean;
		is_subdomain_bypass: boolean;
		is_reflection: boolean;
		http_status: number | null;
		response_time_ms: number | null;
		risk_level: string;
	}

	interface CorsMethodResult {
		method: string;
		acao_header: string | null;
		acac_header: string | null;
		allow_methods: string | null;
		allow_headers: string | null;
		is_allowed: boolean;
		http_status: number | null;
	}

	interface SecurityHeadersAnalysis {
		has_csp: boolean;
		csp_value: string | null;
		has_hsts: boolean;
		hsts_value: string | null;
		has_xfo: boolean;
		xfo_value: string | null;
		has_xcto: boolean;
		xcto_value: string | null;
		has_xss_protection: boolean;
		xss_protection_value: string | null;
		has_rp: boolean;
		rp_value: string | null;
	}

	interface CorsHeaderAnalysis {
		has_acao: boolean;
		has_acac: boolean;
		has_acam: boolean;
		has_acah: boolean;
		has_acma: boolean;
		has_acex: boolean;
		acao_value: string | null;
		acac_value: string | null;
		acam_value: string | null;
		acah_value: string | null;
		acma_value: string | null;
		acex_value: string | null;
		vary_origin: boolean;
		security_headers: SecurityHeadersAnalysis;
	}

	interface CorsCheckResult {
		url: string;
		is_vulnerable: boolean;
		severity: string;
		security_score: number;
		issues: CorsIssue[];
		origin_results: CorsOriginResult[];
		method_results: CorsMethodResult[];
		header_analysis: CorsHeaderAnalysis;
		tests_performed: number;
		scan_duration_ms: number;
		summary: string;
	}

	let url = $state('');
	let timeout = $state(15);
	let threads = $state(5);
	let scanLevel = $state('moderate');
	let customOrigins = $state('');
	let testMethods = $state(true);
	let testPreflight = $state(true);
	let testHeaders = $state(true);
	let result: CorsCheckResult | null = $state(null);
	let error = $state('');
	let processing = $state(false);
	let activeMainTab = $state('analyze');
	let activeResultTab = $state('overview');
	let searchQuery = $state('');
	let severityFilter = $state('all');
	let exportFormat = $state('json');

	const TOOL_NAME = 'cors_checker';
	let historyComponent = $state<ToolHistory>();

	function getScanLevelLabel(level: string): string {
		const labels: Record<string, string> = {
			basic: $tr('corsChecker.levelBasic'),
			moderate: $tr('corsChecker.levelModerate'),
			aggressive: $tr('corsChecker.levelAggressive')
		};
		return labels[level] || level;
	}

	function getSeverityColor(severity: string): string {
		switch (severity) {
			case 'critical': return '#ef4444';
			case 'high': return '#f97316';
			case 'medium': return '#f59e0b';
			case 'low': return '#22c55e';
			default: return '#64748b';
		}
	}

	function getSeverityBg(severity: string): string {
		switch (severity) {
			case 'critical': return 'rgba(239, 68, 68, 0.15)';
			case 'high': return 'rgba(249, 115, 22, 0.15)';
			case 'medium': return 'rgba(245, 158, 11, 0.15)';
			case 'low': return 'rgba(34, 197, 94, 0.15)';
			default: return 'rgba(100, 116, 139, 0.15)';
		}
	}

	function getRiskLevelColor(risk: string): string {
		switch (risk) {
			case 'critical': return '#ef4444';
			case 'high': return '#f97316';
			case 'medium': return '#f59e0b';
			case 'low': return '#3b82f6';
			case 'safe': return '#22c55e';
			default: return '#64748b';
		}
	}

	function getRiskLevelIcon(risk: string): string {
		switch (risk) {
			case 'critical': return '🔴';
			case 'high': return '🟠';
			case 'medium': return '🟡';
			case 'low': return '🔵';
			case 'safe': return '🟢';
			default: return '⚪';
		}
	}

	function getScoreColor(score: number): string {
		if (score >= 80) return '#22c55e';
		if (score >= 60) return '#f59e0b';
		if (score >= 40) return '#f97316';
		return '#ef4444';
	}

	function formatDuration(ms: number): string {
		if (ms < 1000) return `${ms}ms`;
		return `${(ms / 1000).toFixed(1)}s`;
	}

	function getFilteredIssues() {
		return result?.issues.filter(i => {
			if (severityFilter !== 'all' && i.severity !== severityFilter) return false;
			if (searchQuery) {
				const q = searchQuery.toLowerCase();
				return i.issue_type.toLowerCase().includes(q) ||
					i.description.toLowerCase().includes(q) ||
					i.detail.toLowerCase().includes(q) ||
					(i.origin || '').toLowerCase().includes(q);
			}
			return true;
		}) || [];
	}

	function getIssueTypeChartData() {
		if (!result || !result.issues.length) return [];
		const types = [...new Set(result.issues.map(i => i.issue_type))];
		const maxCount = Math.max(...types.map(t => result!.issues.filter(i => i.issue_type === t).length));
		return types.map(t => ({
			issue_type: t,
			count: result!.issues.filter(i => i.issue_type === t).length,
			percent: maxCount > 0 ? (result!.issues.filter(i => i.issue_type === t).length / maxCount) * 100 : 0
		}));
	}

	async function check() {
		if (!url.trim()) {
			error = $tr('corsChecker.urlRequired');
			return;
		}
		processing = true;
		error = '';
		result = null;
		activeResultTab = 'overview';

		try {
			const { invoke } = await import('@tauri-apps/api/core');
			const test_origins = customOrigins.trim()
				? customOrigins.split(/[,，\n;]+/).map(o => o.trim()).filter(o => o.length > 0)
				: [];

			result = await invoke<CorsCheckResult>('check_cors_command', {
				config: {
					url: url.trim(),
					timeout,
					threads,
					scan_level: scanLevel,
					test_origins,
					test_methods: testMethods,
					test_preflight: testPreflight,
					test_headers: testHeaders
				}
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
				defaultPath: `cors_check_${Date.now()}.${exportFormat}`,
				filters: [{ name: exportFormat.toUpperCase(), extensions: [exportFormat] }]
			});
			if (!path) return;

			let content: string;
			if (exportFormat === 'json') {
				content = JSON.stringify(result, null, 2);
			} else {
				const headers = ['Issue Type', 'Severity', 'Description', 'Detail', 'Recommendation', 'Confidence', 'Origin', 'Method'];
				const rows = result.issues.map(i =>
					[i.issue_type, i.severity, i.description, i.detail, i.recommendation, i.confidence.toString(), i.origin || '', i.method || '']
				);
				content = [headers, ...rows].map(r => r.map(c => `"${c.replace(/"/g, '""')}"`).join(',')).join('\n');
			}
			await writeTextFile(path as string, content);
		} catch {}
	}

	function clearAll() {
		url = '';
		customOrigins = '';
		result = null;
		error = '';
		scanLevel = 'moderate';
		testMethods = true;
		testPreflight = true;
		testHeaders = true;
		timeout = 15;
		threads = 5;
		searchQuery = '';
		severityFilter = 'all';
	}
</script>

<div class="nd-page">
	<div class="page-header">
		<div class="header-left">
			<a href="/" class="back-link">{$tr('common.backToHome')}</a>
			<h1 class="page-title">🌐 {$tr('corsChecker.title')}</h1>
			<p class="page-subtitle">{$tr('corsChecker.subtitle')}</p>
		</div>
	</div>

	<div class="tabs">
		<button class="tab-btn {activeMainTab === 'analyze' ? 'active' : ''}" onclick={() => activeMainTab = 'analyze'}>
			<span class="tab-icon">🔍</span> {$tr('corsChecker.check')}
		</button>
		<button class="tab-btn {activeMainTab === 'history' ? 'active' : ''}" onclick={() => activeMainTab = 'history'}>
			<span class="tab-icon">📋</span> {$tr('corsChecker.history')}
		</button>
		<button class="tab-btn {activeMainTab === 'help' ? 'active' : ''}" onclick={() => activeMainTab = 'help'}>
			<span class="tab-icon">📖</span> {$tr('corsChecker.help')}
		</button>
	</div>

	{#if activeMainTab === 'analyze'}
		<div class="content-grid">
			<div class="input-section">
				<div class="section-card">
					<h2 class="section-title">{$tr('corsChecker.configTitle')}</h2>
					<p class="section-desc">{$tr('corsChecker.configDesc')}</p>

					<div class="form-group">
						<label class="form-label">{$tr('corsChecker.targetUrl')}</label>
						<input type="text" bind:value={url} placeholder="https://example.com" class="form-input" disabled={processing} onkeydown={(e) => e.key === 'Enter' && check()} />
					</div>

					<div class="form-group">
						<label class="form-label">{$tr('corsChecker.scanLevel')}</label>
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
							<label class="form-label">⏱️ {$tr('corsChecker.timeout')}</label>
							<input type="number" bind:value={timeout} class="form-input" min="5" max="60" disabled={processing} />
						</div>
						<div class="form-group">
							<label class="form-label">🔀 {$tr('corsChecker.threads')}</label>
							<input type="number" bind:value={threads} class="form-input" min="1" max="20" disabled={processing} />
						</div>
					</div>

					<div class="form-group">
						<label class="form-label">{$tr('corsChecker.testOptions')}</label>
						<div class="target-grid">
							<label class="target-chip {testMethods ? 'active' : ''}">
								<input type="checkbox" bind:checked={testMethods} disabled={processing} />
								<span>🔧 {$tr('corsChecker.testHttpMethods')}</span>
							</label>
							<label class="target-chip {testPreflight ? 'active' : ''}">
								<input type="checkbox" bind:checked={testPreflight} disabled={processing} />
								<span>✈️ {$tr('corsChecker.testPreflight')}</span>
							</label>
							<label class="target-chip {testHeaders ? 'active' : ''}">
								<input type="checkbox" bind:checked={testHeaders} disabled={processing} />
								<span>🛡️ {$tr('corsChecker.testSecHeaders')}</span>
							</label>
						</div>
					</div>

					<div class="form-group">
						<label class="form-label">🎯 {$tr('corsChecker.customOrigins')}</label>
						<textarea bind:value={customOrigins} placeholder="https://evil.com&#10;https://attacker.com" class="form-input" style="height: 60px; resize: vertical;" disabled={processing}></textarea>
					</div>

					<div class="button-group">
						<button class="btn-primary" onclick={check} disabled={processing || !url.trim()}>
							{#if processing}<span class="spinner"></span>{$tr('corsChecker.checking')}{:else}🌐 {$tr('corsChecker.startCheck')}{/if}
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
								<h2 class="section-title" style="margin-bottom:0">🌐 {result.url}</h2>
							</div>
							<div class="header-actions">
								<div class="score-badge" style="border-color: {getScoreColor(result.security_score)}40; background: {getScoreColor(result.security_score)}15">
									<span class="score-value" style="color: {getScoreColor(result.security_score)}">{Math.round(result.security_score)}</span>
									<span class="score-label" style="color: {getScoreColor(result.security_score)}">/100</span>
								</div>
								<div class="resource-score-badge">
									<span class="score-value">{result.issues.length}</span>
									<span class="score-label">{$tr('corsChecker.issuesFound')}</span>
								</div>
								<select bind:value={exportFormat} class="export-select">
									<option value="json">JSON</option>
									<option value="csv">CSV</option>
								</select>
								<button class="btn-export" onclick={exportResult}>
									📤 {$tr('corsChecker.export')}
								</button>
							</div>
						</div>

						<div class="summary-bar" style="background: {result.is_vulnerable ? 'rgba(239,68,68,0.08)' : 'rgba(34,197,94,0.08)'}; border-color: {result.is_vulnerable ? 'rgba(239,68,68,0.15)' : 'rgba(34,197,94,0.15)'}">
							{#if result.is_vulnerable}⚠️{:else}✅{/if} {result.summary}
						</div>

						<div class="result-tabs">
							<button class="result-tab {activeResultTab === 'overview' ? 'active' : ''}" onclick={() => activeResultTab = 'overview'}>
								📊 {$tr('corsChecker.tabOverview')}
							</button>
							<button class="result-tab {activeResultTab === 'issues' ? 'active' : ''}" onclick={() => activeResultTab = 'issues'}>
								🔴 {$tr('corsChecker.tabIssues')} ({result.issues.length})
							</button>
							<button class="result-tab {activeResultTab === 'origins' ? 'active' : ''}" onclick={() => activeResultTab = 'origins'}>
								🌍 {$tr('corsChecker.tabOrigins')} ({result.origin_results.length})
							</button>
							{#if result.method_results.length > 0}
								<button class="result-tab {activeResultTab === 'methods' ? 'active' : ''}" onclick={() => activeResultTab = 'methods'}>
									🔧 {$tr('corsChecker.tabMethods')} ({result.method_results.length})
								</button>
							{/if}
							<button class="result-tab {activeResultTab === 'headers' ? 'active' : ''}" onclick={() => activeResultTab = 'headers'}>
								📋 {$tr('corsChecker.tabHeaders')}
							</button>
						</div>

						{#if activeResultTab === 'overview'}
							<div class="overview-grid">
								<div class="overview-stat">
									<span class="stat-label">{$tr('corsChecker.testsPerformed')}</span>
									<span class="stat-value">{result.tests_performed}</span>
								</div>
								<div class="overview-stat">
									<span class="stat-label">🔴 {$tr('corsChecker.criticalIssues')}</span>
									<span class="stat-value" style="color: {result.issues.filter(i => i.severity === 'critical').length > 0 ? '#ef4444' : '#64748b'}">{result.issues.filter(i => i.severity === 'critical').length}</span>
								</div>
								<div class="overview-stat">
									<span class="stat-label">🟠 {$tr('corsChecker.highIssues')}</span>
									<span class="stat-value" style="color: {result.issues.filter(i => i.severity === 'high').length > 0 ? '#f97316' : '#64748b'}">{result.issues.filter(i => i.severity === 'high').length}</span>
								</div>
								<div class="overview-stat">
									<span class="stat-label">🟡 {$tr('corsChecker.mediumIssues')}</span>
									<span class="stat-value" style="color: {result.issues.filter(i => i.severity === 'medium').length > 0 ? '#f59e0b' : '#64748b'}">{result.issues.filter(i => i.severity === 'medium').length}</span>
								</div>
								<div class="overview-stat">
									<span class="stat-label">🌍 {$tr('corsChecker.originsTested')}</span>
									<span class="stat-value">{result.origin_results.length}</span>
								</div>
								<div class="overview-stat">
									<span class="stat-label">⚠️ {$tr('corsChecker.vulnerableOrigins')}</span>
									<span class="stat-value" style="color: {result.origin_results.filter(o => o.risk_level === 'critical' || o.risk_level === 'high').length > 0 ? '#f97316' : '#22c55e'}">{result.origin_results.filter(o => o.risk_level === 'critical' || o.risk_level === 'high').length}</span>
								</div>
								<div class="overview-stat">
									<span class="stat-label">⏱️ {$tr('corsChecker.scanDuration')}</span>
									<span class="stat-value">{formatDuration(result.scan_duration_ms)}</span>
								</div>
								<div class="overview-stat">
									<span class="stat-label">🛡️ {$tr('corsChecker.securityScore')}</span>
									<span class="stat-value" style="color: {getScoreColor(result.security_score)}">{Math.round(result.security_score)}</span>
								</div>
							</div>

							{#if result.issues.length > 0}
								<div class="category-chart">
									<h3 class="subsection-title">{$tr('corsChecker.issueTypeChart')}</h3>
									<div class="chart-bars">
										{#each getIssueTypeChartData() as data}
											<div class="chart-row">
												<span class="chart-label">{data.issue_type}</span>
												<div class="chart-bar-track">
													<div class="chart-bar-fill" style="width: {data.percent}%; background: #a855f7"></div>
												</div>
												<span class="chart-count">{data.count}</span>
											</div>
										{/each}
									</div>
								</div>
							{/if}
						{/if}

						{#if activeResultTab === 'issues'}
							{#if result.issues.length > 0}
								<div class="filter-bar">
									<input type="text" bind:value={searchQuery} placeholder="{$tr('corsChecker.searchIssues')}..." class="filter-input" />
									<select bind:value={severityFilter} class="filter-select">
										<option value="all">{$tr('corsChecker.allSeverities')}</option>
										<option value="critical">🔴 Critical</option>
										<option value="high">🟠 High</option>
										<option value="medium">🟡 Medium</option>
										<option value="low">🟢 Low</option>
									</select>
								</div>

								<div class="issue-list">
									{#each getFilteredIssues() as issue}
										<div class="issue-card">
											<div class="issue-header">
												<div class="issue-header-left">
													<span class="severity-badge" style="background: {getSeverityBg(issue.severity)}; color: {getSeverityColor(issue.severity)}">
														{issue.severity.toUpperCase()}
													</span>
													<span class="issue-type-badge">{issue.issue_type}</span>
													{#if issue.origin}
														<span class="origin-badge-sm">🌍 {issue.origin}</span>
													{/if}
													{#if issue.method}
														<span class="method-badge-sm">🔧 {issue.method}</span>
													{/if}
												</div>
												<span class="confidence-badge">
													{$tr('corsChecker.confidence')}: {Math.round(issue.confidence * 100)}%
												</span>
											</div>
											<div class="issue-body">
												<p class="issue-desc">{issue.description}</p>
												<p class="issue-detail">{issue.detail}</p>
												<p class="issue-rec">💡 {issue.recommendation}</p>
											</div>
										</div>
									{/each}
								</div>
							{:else}
								<div class="safe-state">
									<span class="safe-icon">✅</span>
									<span class="safe-text">{$tr('corsChecker.noIssues')}</span>
								</div>
							{/if}
						{/if}

						{#if activeResultTab === 'origins'}
							{#if result.origin_results.length > 0}
								<div class="origin-list">
									{#each result.origin_results as or}
										<div class="origin-card" style="border-left: 3px solid {getRiskLevelColor(or.risk_level)}">
											<div class="origin-header">
												<div class="origin-header-left">
													<span class="risk-icon">{getRiskLevelIcon(or.risk_level)}</span>
													<span class="origin-url">{or.origin}</span>
												</div>
												<div class="origin-badges">
													{#if or.is_wildcard}<span class="origin-badge wildcard">{$tr('corsChecker.badgeWildcard')}</span>{/if}
													{#if or.is_null}<span class="origin-badge null">Null</span>{/if}
													{#if or.is_subdomain_bypass}<span class="origin-badge bypass">{$tr('corsChecker.badgeBypass')}</span>{/if}
													{#if or.is_reflection}<span class="origin-badge reflection">{$tr('corsChecker.badgeReflection')}</span>{/if}
													{#if or.allow_credentials}<span class="origin-badge cred">{$tr('corsChecker.badgeCred')}</span>{/if}
													<span class="origin-badge risk" style="background: {getRiskLevelColor(or.risk_level)}15; color: {getRiskLevelColor(or.risk_level)}">{or.risk_level}</span>
												</div>
											</div>
											<div class="origin-details">
												{#if or.acao_header}
													<div class="origin-detail-row">
														<span class="detail-label">ACAO:</span>
														<code class="detail-value">{or.acao_header}</code>
													</div>
												{/if}
												{#if or.acac_header}
													<div class="origin-detail-row">
														<span class="detail-label">ACAC:</span>
														<code class="detail-value">{or.acac_header}</code>
													</div>
												{/if}
												{#if or.allow_methods}
													<div class="origin-detail-row">
														<span class="detail-label">Methods:</span>
														<code class="detail-value">{or.allow_methods}</code>
													</div>
												{/if}
												{#if or.http_status}
													<span class="meta-chip">HTTP {or.http_status}</span>
												{/if}
												{#if or.response_time_ms}
													<span class="meta-chip">⏱️ {or.response_time_ms}ms</span>
												{/if}
											</div>
										</div>
									{/each}
								</div>
							{:else}
								<div class="empty-state">{$tr('corsChecker.noOriginResults')}</div>
							{/if}
						{/if}

						{#if activeResultTab === 'methods'}
							{#if result.method_results.length > 0}
								<div class="method-grid">
									{#each result.method_results as mr}
										<div class="method-card" style="border-color: {mr.is_allowed ? 'rgba(249, 115, 22, 0.3)' : 'rgba(34, 197, 94, 0.3)'}">
											<div class="method-header">
												<span class="method-name">{mr.method}</span>
												<span class="method-status" style="color: {mr.is_allowed ? '#f97316' : '#22c55e'}">
													{mr.is_allowed ? '⚠️ Allowed' : '✅ Blocked'}
												</span>
											</div>
											{#if mr.acao_header}
												<div class="method-detail"><span class="detail-label">ACAO:</span> <code>{mr.acao_header}</code></div>
											{/if}
											{#if mr.acac_header}
												<div class="method-detail"><span class="detail-label">ACAC:</span> <code>{mr.acac_header}</code></div>
											{/if}
											{#if mr.allow_methods}
												<div class="method-detail"><span class="detail-label">Allow-Methods:</span> <code>{mr.allow_methods}</code></div>
											{/if}
											{#if mr.http_status}
												<span class="meta-chip">HTTP {mr.http_status}</span>
											{/if}
										</div>
									{/each}
								</div>
							{:else}
								<div class="empty-state">{$tr('corsChecker.noMethodResults')}</div>
							{/if}
						{/if}

						{#if activeResultTab === 'headers'}
							<div class="headers-section">
								<h3 class="subsection-title">{$tr('corsChecker.corsHeaders')}</h3>
								<div class="header-grid">
									<div class="header-item {result.header_analysis.has_acao ? 'present' : 'missing'}">
										<span class="header-name">Access-Control-Allow-Origin</span>
										<span class="header-status">{result.header_analysis.has_acao ? '✅' : '❌'}</span>
										{#if result.header_analysis.acao_value}<code class="header-val">{result.header_analysis.acao_value}</code>{/if}
									</div>
									<div class="header-item {result.header_analysis.has_acac ? 'present' : 'missing'}">
										<span class="header-name">Access-Control-Allow-Credentials</span>
										<span class="header-status">{result.header_analysis.has_acac ? '✅' : '❌'}</span>
										{#if result.header_analysis.acac_value}<code class="header-val">{result.header_analysis.acac_value}</code>{/if}
									</div>
									<div class="header-item {result.header_analysis.has_acam ? 'present' : 'missing'}">
										<span class="header-name">Access-Control-Allow-Methods</span>
										<span class="header-status">{result.header_analysis.has_acam ? '✅' : '❌'}</span>
										{#if result.header_analysis.acam_value}<code class="header-val">{result.header_analysis.acam_value}</code>{/if}
									</div>
									<div class="header-item {result.header_analysis.has_acah ? 'present' : 'missing'}">
										<span class="header-name">Access-Control-Allow-Headers</span>
										<span class="header-status">{result.header_analysis.has_acah ? '✅' : '❌'}</span>
										{#if result.header_analysis.acah_value}<code class="header-val">{result.header_analysis.acah_value}</code>{/if}
									</div>
									<div class="header-item {result.header_analysis.has_acma ? 'present' : 'missing'}">
										<span class="header-name">Access-Control-Max-Age</span>
										<span class="header-status">{result.header_analysis.has_acma ? '✅' : '❌'}</span>
										{#if result.header_analysis.acma_value}<code class="header-val">{result.header_analysis.acma_value}</code>{/if}
									</div>
									<div class="header-item {result.header_analysis.has_acex ? 'present' : 'missing'}">
										<span class="header-name">Access-Control-Expose-Headers</span>
										<span class="header-status">{result.header_analysis.has_acex ? '✅' : '❌'}</span>
										{#if result.header_analysis.acex_value}<code class="header-val">{result.header_analysis.acex_value}</code>{/if}
									</div>
									<div class="header-item {result.header_analysis.vary_origin ? 'present' : 'missing'}">
										<span class="header-name">Vary: Origin</span>
										<span class="header-status">{result.header_analysis.vary_origin ? '✅' : '❌'}</span>
									</div>
								</div>

								<h3 class="subsection-title" style="margin-top: 1.25rem">{$tr('corsChecker.securityHeaders')}</h3>
								<div class="header-grid">
									<div class="header-item {result.header_analysis.security_headers.has_csp ? 'present' : 'missing'}">
										<span class="header-name">Content-Security-Policy</span>
										<span class="header-status">{result.header_analysis.security_headers.has_csp ? '✅' : '❌'}</span>
										{#if result.header_analysis.security_headers.csp_value}<code class="header-val">{result.header_analysis.security_headers.csp_value}</code>{/if}
									</div>
									<div class="header-item {result.header_analysis.security_headers.has_hsts ? 'present' : 'missing'}">
										<span class="header-name">Strict-Transport-Security</span>
										<span class="header-status">{result.header_analysis.security_headers.has_hsts ? '✅' : '❌'}</span>
										{#if result.header_analysis.security_headers.hsts_value}<code class="header-val">{result.header_analysis.security_headers.hsts_value}</code>{/if}
									</div>
									<div class="header-item {result.header_analysis.security_headers.has_xfo ? 'present' : 'missing'}">
										<span class="header-name">X-Frame-Options</span>
										<span class="header-status">{result.header_analysis.security_headers.has_xfo ? '✅' : '❌'}</span>
										{#if result.header_analysis.security_headers.xfo_value}<code class="header-val">{result.header_analysis.security_headers.xfo_value}</code>{/if}
									</div>
									<div class="header-item {result.header_analysis.security_headers.has_xcto ? 'present' : 'missing'}">
										<span class="header-name">X-Content-Type-Options</span>
										<span class="header-status">{result.header_analysis.security_headers.has_xcto ? '✅' : '❌'}</span>
										{#if result.header_analysis.security_headers.xcto_value}<code class="header-val">{result.header_analysis.security_headers.xcto_value}</code>{/if}
									</div>
									<div class="header-item {result.header_analysis.security_headers.has_xss_protection ? 'present' : 'missing'}">
										<span class="header-name">X-XSS-Protection</span>
										<span class="header-status">{result.header_analysis.security_headers.has_xss_protection ? '✅' : '❌'}</span>
									</div>
									<div class="header-item {result.header_analysis.security_headers.has_rp ? 'present' : 'missing'}">
										<span class="header-name">Referrer-Policy</span>
										<span class="header-status">{result.header_analysis.security_headers.has_rp ? '✅' : '❌'}</span>
										{#if result.header_analysis.security_headers.rp_value}<code class="header-val">{result.header_analysis.security_headers.rp_value}</code>{/if}
									</div>
								</div>
							</div>
						{/if}
					{:else if processing}
						<div class="processing-state">
							<span class="processing-icon pulse">🌐</span>
							<span class="processing-text">{$tr('corsChecker.checking')}</span>
							<span class="processing-hint">{$tr('corsChecker.checkHint')}</span>
						</div>
					{:else}
						<div class="empty-state-main">
							<span class="empty-icon">🌐</span>
							<span class="empty-text">{$tr('corsChecker.emptyHint')}</span>
						</div>
					{/if}
				</div>
			</div>
		</div>
	{:else if activeMainTab === 'history'}
		<div class="section-card"><ToolHistory toolType={TOOL_NAME} toolName={$tr('corsChecker.title')} bind:this={historyComponent} /></div>
	{:else if activeMainTab === 'help'}
		<div class="section-card"><ToolHelp toolType={TOOL_NAME} /></div>
	{/if}
</div>

<style>
	.nd-page { padding: 20px; max-width: 1400px; margin: 0 auto; }
	.page-header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 20px; }
	.back-link { color: var(--text-secondary); text-decoration: none; font-size: 0.85rem; }
	.page-title { font-size: 1.5rem; margin: 8px 0 4px; color: #f1f5f9; }
	.page-subtitle { color: var(--text-secondary); font-size: 0.9rem; }

	.tabs { display: flex; gap: 4px; margin-bottom: 16px; background: rgba(15, 23, 42, 0.6); border-radius: 10px; padding: 4px; border: 1px solid rgba(168, 85, 247, 0.15); }
	.tab-btn { flex: 1; padding: 8px 16px; border: none; border-radius: 8px; background: transparent; cursor: pointer; font-size: 0.9rem; color: #94a3b8; transition: all 0.2s; display: flex; align-items: center; justify-content: center; gap: 6px; }
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

	.mode-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 0.35rem; }
	.mode-btn { padding: 0.4rem 0.5rem; border: 1px solid rgba(148, 163, 184, 0.15); border-radius: 0.4rem; background: rgba(15, 23, 42, 0.6); color: #94a3b8; cursor: pointer; font-size: 0.75rem; transition: all 0.2s; text-align: center; }
	.mode-btn.active { background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%); color: white; border-color: transparent; font-weight: 600; box-shadow: 0 2px 6px rgba(168, 85, 247, 0.3); }
	.mode-btn:hover:not(.active) { border-color: rgba(168, 85, 247, 0.3); color: #c4b5fd; }
	.mode-name { font-size: 0.75rem; }

	.target-grid { display: grid; grid-template-columns: 1fr; gap: 0.35rem; }
	.target-chip { display: flex; align-items: center; gap: 0.35rem; padding: 0.35rem 0.5rem; border: 1px solid rgba(148, 163, 184, 0.15); border-radius: 0.4rem; background: rgba(15, 23, 42, 0.6); cursor: pointer; font-size: 0.75rem; color: #94a3b8; transition: all 0.2s; }
	.target-chip.active { border-color: rgba(168, 85, 247, 0.4); background: rgba(168, 85, 247, 0.1); color: #c4b5fd; }
	.target-chip input[type="checkbox"] { accent-color: #a855f7; width: 0.8rem; height: 0.8rem; }
	.target-chip:hover:not(.active) { border-color: rgba(148, 163, 184, 0.3); }

	.button-group { display: flex; gap: 0.5rem; margin-top: 1rem; }
	.btn-primary { flex: 1; background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%); color: white; font-weight: 600; padding: 0.65rem 1.25rem; border: none; border-radius: 0.5rem; cursor: pointer; transition: all 0.2s; display: flex; align-items: center; justify-content: center; gap: 0.5rem; font-size: 0.9rem; }
	.btn-primary:hover:not(:disabled) { box-shadow: 0 4px 15px rgba(168, 85, 247, 0.4); transform: translateY(-1px); }
	.btn-primary:disabled { opacity: 0.5; cursor: not-allowed; transform: none; box-shadow: none; }
	.btn-secondary { background: rgba(148, 163, 184, 0.1); color: #94a3b8; padding: 0.65rem 1rem; border: 1px solid rgba(148, 163, 184, 0.15); border-radius: 0.5rem; cursor: pointer; transition: all 0.2s; font-size: 0.9rem; }
	.btn-secondary:hover:not(:disabled) { background: rgba(148, 163, 184, 0.2); color: #e2e8f0; }
	.btn-secondary:disabled { opacity: 0.5; cursor: not-allowed; }

	.spinner { display: inline-block; width: 1rem; height: 1rem; border: 2px solid rgba(255, 255, 255, 0.3); border-top-color: white; border-radius: 50%; animation: spin 0.6s linear infinite; }
	@keyframes spin { to { transform: rotate(360deg); } }

	.error-card { display: flex; align-items: center; gap: 0.75rem; padding: 1rem; background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.2); border-radius: 0.5rem; }
	.error-icon { font-size: 1.25rem; }
	.error-text { color: #fca5a5; font-size: 0.85rem; }

	.result-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem; flex-wrap: wrap; gap: 0.5rem; }
	.header-actions { display: flex; align-items: center; gap: 0.5rem; }

	.score-badge { display: flex; align-items: baseline; padding: 0.4rem 0.75rem; border-radius: 0.5rem; border: 1px solid; }
	.score-badge .score-value { font-size: 1.5rem; font-weight: 700; line-height: 1; }
	.score-badge .score-label { font-size: 0.7rem; opacity: 0.8; margin-left: 2px; }

	.resource-score-badge { display: flex; flex-direction: column; align-items: center; padding: 0.5rem 1rem; border-radius: 0.5rem; border: 1px solid rgba(168, 85, 247, 0.3); background: rgba(168, 85, 247, 0.1); }
	.resource-score-badge .score-value { font-size: 1.5rem; font-weight: 700; color: #a855f7; line-height: 1; }
	.resource-score-badge .score-label { font-size: 0.65rem; color: #a855f7; opacity: 0.8; margin-top: 0.2rem; }

	.export-select { padding: 0.35rem 0.5rem; border-radius: 0.4rem; border: 1px solid rgba(148, 163, 184, 0.15); background: rgba(15, 23, 42, 0.6); color: #94a3b8; font-size: 0.75rem; }
	.btn-export { padding: 0.35rem 0.75rem; border-radius: 0.4rem; border: 1px solid rgba(168, 85, 247, 0.3); background: rgba(168, 85, 247, 0.1); color: #c4b5fd; cursor: pointer; font-size: 0.8rem; transition: all 0.2s; }
	.btn-export:hover { background: rgba(168, 85, 247, 0.2); }

	.summary-bar { font-size: 0.8rem; color: #94a3b8; padding: 0.5rem 0.75rem; border-radius: 0.4rem; margin-bottom: 1rem; border: 1px solid rgba(148, 163, 184, 0.08); }

	.result-tabs { display: flex; gap: 0.25rem; margin-bottom: 1rem; flex-wrap: wrap; }
	.result-tab { padding: 0.4rem 0.75rem; border-radius: 0.4rem; border: 1px solid rgba(148, 163, 184, 0.15); background: rgba(15, 23, 42, 0.4); color: #94a3b8; cursor: pointer; font-size: 0.8rem; transition: all 0.2s; }
	.result-tab.active { background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%); color: white; border-color: transparent; font-weight: 600; }
	.result-tab:hover:not(.active) { border-color: rgba(168, 85, 247, 0.3); color: #c4b5fd; }

	.overview-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 0.75rem; margin-bottom: 1rem; }
	.overview-stat { display: flex; flex-direction: column; align-items: center; padding: 0.75rem; background: rgba(15, 23, 42, 0.4); border: 1px solid rgba(148, 163, 184, 0.08); border-radius: 0.5rem; }
	.stat-label { font-size: 0.7rem; color: #94a3b8; margin-bottom: 0.3rem; text-align: center; }
	.stat-value { font-size: 1.25rem; font-weight: 700; color: #f1f5f9; }

	.subsection-title { font-size: 0.85rem; font-weight: 600; color: #c4b5fd; margin: 1rem 0 0.5rem; }
	.category-chart { margin-top: 1rem; }
	.chart-bars { display: flex; flex-direction: column; gap: 0.5rem; }
	.chart-row { display: flex; align-items: center; gap: 0.5rem; }
	.chart-label { width: 160px; font-size: 0.75rem; color: #94a3b8; text-align: right; flex-shrink: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
	.chart-bar-track { flex: 1; height: 20px; background: rgba(15, 23, 42, 0.4); border-radius: 4px; overflow: hidden; }
	.chart-bar-fill { height: 100%; border-radius: 4px; transition: width 0.5s ease; min-width: 4px; }
	.chart-count { font-size: 0.75rem; color: #f1f5f9; font-weight: 600; width: 30px; text-align: right; }

	.filter-bar { display: flex; gap: 0.5rem; margin-bottom: 1rem; flex-wrap: wrap; }
	.filter-input { flex: 1; min-width: 150px; padding: 0.4rem 0.6rem; border-radius: 0.4rem; border: 1px solid rgba(148, 163, 184, 0.15); background: rgba(15, 23, 42, 0.6); color: #f1f5f9; font-size: 0.8rem; }
	.filter-input:focus { outline: none; border-color: #a855f7; }
	.filter-select { padding: 0.4rem 0.5rem; border-radius: 0.4rem; border: 1px solid rgba(148, 163, 184, 0.15); background: rgba(15, 23, 42, 0.6); color: #94a3b8; font-size: 0.75rem; }

	.issue-list { display: flex; flex-direction: column; gap: 0.75rem; }
	.issue-card { background: rgba(15, 23, 42, 0.4); border: 1px solid rgba(148, 163, 184, 0.08); border-radius: 0.5rem; padding: 0.75rem; transition: border-color 0.2s; }
	.issue-card:hover { border-color: rgba(168, 85, 247, 0.3); }
	.issue-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem; }
	.issue-header-left { display: flex; align-items: center; gap: 0.4rem; flex-wrap: wrap; }
	.severity-badge { padding: 0.15rem 0.5rem; border-radius: 0.3rem; font-size: 0.7rem; font-weight: 700; }
	.issue-type-badge { padding: 0.15rem 0.4rem; border-radius: 0.3rem; background: rgba(168, 85, 247, 0.15); color: #c4b5fd; font-size: 0.7rem; }
	.origin-badge-sm { padding: 0.15rem 0.4rem; border-radius: 0.3rem; background: rgba(59, 130, 246, 0.15); color: #93c5fd; font-size: 0.7rem; }
	.method-badge-sm { padding: 0.15rem 0.4rem; border-radius: 0.3rem; background: rgba(148, 163, 184, 0.1); color: #94a3b8; font-size: 0.7rem; }
	.confidence-badge { font-size: 0.75rem; color: #a855f7; font-weight: 600; }
	.issue-body { display: flex; flex-direction: column; gap: 0.25rem; }
	.issue-desc { font-size: 0.85rem; color: #e2e8f0; margin: 0; }
	.issue-detail { font-size: 0.8rem; color: #94a3b8; margin: 0; }
	.issue-rec { font-size: 0.8rem; color: #22c55e; margin: 0; }

	.origin-list { display: flex; flex-direction: column; gap: 0.5rem; }
	.origin-card { padding: 0.75rem; background: rgba(15, 23, 42, 0.4); border: 1px solid rgba(148, 163, 184, 0.08); border-radius: 0.5rem; }
	.origin-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem; flex-wrap: wrap; gap: 0.35rem; }
	.origin-header-left { display: flex; align-items: center; gap: 0.4rem; }
	.risk-icon { font-size: 0.9rem; }
	.origin-url { font-size: 0.85rem; font-weight: 600; color: #e2e8f0; font-family: monospace; }
	.origin-badges { display: flex; gap: 0.3rem; flex-wrap: wrap; }
	.origin-badge { padding: 0.1rem 0.4rem; border-radius: 0.3rem; font-size: 0.65rem; font-weight: 600; }
	.origin-badge.wildcard { background: rgba(234, 179, 8, 0.15); color: #eab308; }
	.origin-badge.null { background: rgba(239, 68, 68, 0.15); color: #ef4444; }
	.origin-badge.bypass { background: rgba(249, 115, 22, 0.15); color: #f97316; }
	.origin-badge.reflection { background: rgba(239, 68, 68, 0.15); color: #f87171; }
	.origin-badge.cred { background: rgba(239, 68, 68, 0.15); color: #ef4444; }
	.origin-badge.risk { font-weight: 600; }
	.origin-details { display: flex; flex-direction: column; gap: 0.2rem; }
	.origin-detail-row { display: flex; align-items: baseline; gap: 0.4rem; }
	.detail-label { font-size: 0.7rem; color: #64748b; min-width: 70px; flex-shrink: 0; }
	.detail-value { font-size: 0.75rem; color: #e2e8f0; background: rgba(15, 23, 42, 0.6); padding: 0.1rem 0.3rem; border-radius: 0.2rem; word-break: break-all; }
	.meta-chip { padding: 0.15rem 0.4rem; border-radius: 0.3rem; background: rgba(148, 163, 184, 0.1); color: #94a3b8; font-size: 0.7rem; display: inline-block; margin-top: 0.2rem; }

	.method-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 0.75rem; }
	.method-card { padding: 0.75rem; background: rgba(15, 23, 42, 0.4); border: 1px solid rgba(148, 163, 184, 0.08); border-radius: 0.5rem; }
	.method-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem; }
	.method-name { font-size: 0.9rem; font-weight: 700; color: #f1f5f9; font-family: monospace; }
	.method-status { font-size: 0.75rem; font-weight: 600; }
	.method-detail { font-size: 0.75rem; color: #94a3b8; margin-bottom: 0.2rem; }
	.method-detail code { color: #e2e8f0; background: rgba(15, 23, 42, 0.6); padding: 0.1rem 0.3rem; border-radius: 0.2rem; font-size: 0.7rem; }

	.headers-section { }
	.header-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 0.5rem; }
	.header-item { padding: 0.5rem 0.75rem; border-radius: 0.4rem; display: flex; align-items: center; gap: 0.5rem; font-size: 0.8rem; }
	.header-item.present { background: rgba(34, 197, 94, 0.05); border: 1px solid rgba(34, 197, 94, 0.15); }
	.header-item.missing { background: rgba(239, 68, 68, 0.05); border: 1px solid rgba(239, 68, 68, 0.1); }
	.header-name { font-size: 0.75rem; color: #94a3b8; min-width: 180px; font-family: monospace; }
	.header-status { font-size: 0.8rem; }
	.header-val { font-size: 0.7rem; color: #c4b5fd; background: rgba(15, 23, 42, 0.6); padding: 0.1rem 0.3rem; border-radius: 0.2rem; word-break: break-all; flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

	.safe-state { display: flex; flex-direction: column; align-items: center; gap: 0.75rem; padding: 3rem; }
	.safe-icon { font-size: 3rem; }
	.safe-text { color: #22c55e; font-size: 1rem; font-weight: 600; }

	.empty-state { text-align: center; padding: 2rem; color: #64748b; font-size: 0.85rem; }
	.empty-state-main { display: flex; flex-direction: column; align-items: center; gap: 0.75rem; padding: 4rem; }
	.empty-icon { font-size: 3rem; opacity: 0.5; }
	.empty-text { color: #64748b; font-size: 0.9rem; }

	.processing-state { display: flex; flex-direction: column; align-items: center; gap: 1rem; padding: 4rem; }
	.processing-icon { font-size: 2.5rem; }
	.pulse { animation: pulse 1.5s ease-in-out infinite; }
	@keyframes pulse { 0%, 100% { transform: scale(1); opacity: 1; } 50% { transform: scale(1.2); opacity: 0.7; } }
	.processing-text { color: #c4b5fd; font-size: 1rem; font-weight: 600; }
	.processing-hint { color: #64748b; font-size: 0.8rem; }

	@media (max-width: 768px) {
		.content-grid { grid-template-columns: 1fr; }
		.overview-grid { grid-template-columns: repeat(2, 1fr); }
		.header-grid { grid-template-columns: 1fr; }
	}
</style>
