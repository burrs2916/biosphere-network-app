<script lang="ts">
	import { tr } from '$lib/i18n';
	import ToolHistory from '$lib/components/ToolHistory.svelte';
	import ToolHelp from '$lib/components/ToolHelp.svelte';

	interface HeaderDetail {
		name: string;
		value: string;
		status: string;
		severity: string;
		category: string;
		description: string;
		recommendation: string;
		cwe_id: string | null;
		owasp_category: string | null;
		importance: number;
	}

	interface HeaderIssue {
		header_name: string;
		issue_type: string;
		severity: string;
		category: string;
		description: string;
		recommendation: string;
		cwe_id: string | null;
		owasp_category: string | null;
		current_value: string | null;
	}

	interface CspDirective {
		directive: string;
		value: string;
		is_secure: boolean;
		issues: string[];
	}

	interface CspAnalysis {
		raw_value: string;
		directives: CspDirective[];
		has_default_src: boolean;
		has_script_src: boolean;
		has_style_src: boolean;
		has_img_src: boolean;
		has_connect_src: boolean;
		has_frame_src: boolean;
		has_object_src: boolean;
		has_base_uri: boolean;
		has_form_action: boolean;
		has_frame_ancestors: boolean;
		uses_unsafe_inline: boolean;
		uses_unsafe_eval: boolean;
		uses_nonce: boolean;
		uses_hash: boolean;
		has_report_uri: boolean;
		is_report_only: boolean;
		overall_assessment: string;
		score: number;
	}

	interface HstsAnalysis {
		raw_value: string;
		max_age: number;
		include_sub_domains: boolean;
		preload: boolean;
		is_secure: boolean;
		issues: string[];
		score: number;
	}

	interface InformationLeakage {
		header_name: string;
		value: string;
		risk_level: string;
		description: string;
		recommendation: string;
	}

	interface CookieSecurityInfo {
		name: string;
		has_httponly: boolean;
		has_secure: boolean;
		has_samesite: boolean;
		samesite_value: string | null;
		has_path: boolean;
		path_value: string | null;
		has_domain: boolean;
		domain_value: string | null;
		is_session_cookie: boolean;
		risk_level: string;
		issue: string | null;
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
		max_score: number;
		actual_score: number;
	}

	interface RedirectEntry {
		url: string;
		status_code: number;
	}

	interface HttpsRedirectCheck {
		original_url: string;
		final_url: string;
		redirects_to_https: boolean;
		is_permanent: boolean;
		issue: string | null;
	}

	interface SecurityHeaderReport {
		url: string;
		score: number;
		grade: string;
		summary: string;
		present_headers: HeaderDetail[];
		missing_headers: HeaderDetail[];
		issues: HeaderIssue[];
		csp_analysis: CspAnalysis | null;
		hsts_analysis: HstsAnalysis | null;
		information_leakage: InformationLeakage[];
		cookie_security: CookieSecurityInfo[];
		severity_stats: SeverityStats;
		category_stats: CategoryStat[];
		response_status: number;
		server_header: string | null;
		x_powered_by: string | null;
		scan_duration_ms: number;
		redirect_chain: RedirectEntry[];
		https_redirect: HttpsRedirectCheck | null;
	}

	let url = $state('');
	let activeMainTab = $state('analyze');
	let activeResultTab = $state('overview');
	let historyComponent: ToolHistory = $state(null!);
	let timeout = $state(15);
	let followRedirects = $state(true);
	let verifySsl = $state(false);
	let proxyUrl = $state('');
	let checkCspDetails = $state(true);
	let checkCookieHeaders = $state(true);
	let checkInfoLeakage = $state(true);
	let showAdvanced = $state(false);
	let customHeaders = $state('');
	let result: SecurityHeaderReport | null = $state(null);
	let error = $state('');
	let processing = $state(false);
	let searchQuery = $state('');
	let issueFilter = $state('all');
	let headerFilter = $state('all');
	let exportFormat = $state('json');
	let selectedIssue: HeaderIssue | null = $state(null);
	let expandedCsp = $state(false);
	let expandedHsts = $state(false);

	function getGradeColor(grade: string): string {
		switch (grade) {
			case 'A': return '#22c55e';
			case 'B': return '#84cc16';
			case 'C': return '#eab308';
			case 'D': return '#f97316';
			default: return '#ef4444';
		}
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

	function getStatusIcon(status: string): string {
		switch (status) {
			case 'good': return '✅';
			case 'warning': return '⚠️';
			case 'bad': return '❌';
			case 'missing': return '🚫';
			default: return 'ℹ️';
		}
	}

	function getStatusColor(status: string): string {
		switch (status) {
			case 'good': return '#22c55e';
			case 'warning': return '#eab308';
			case 'bad': return '#ef4444';
			case 'missing': return '#6b7280';
			default: return '#6b7280';
		}
	}

	function getCategoryIcon(c: string): string {
		switch (c) {
			case 'XSS Protection': return '🛡️';
			case 'Transport Security': return '🔒';
			case 'Clickjacking Protection': return '🖼️';
			case 'Content Sniffing': return '🔍';
			case 'Privacy': return '👁️';
			case 'Feature Control': return '🎮';
			case 'Cross-Origin Isolation': return '🌐';
			default: return '🛡️';
		}
	}

	function getFilteredIssues(): HeaderIssue[] {
		if (!result) return [];
		let issues = result.issues;
		if (issueFilter === 'critical') issues = issues.filter(i => i.severity === 'critical');
		else if (issueFilter === 'high') issues = issues.filter(i => i.severity === 'high');
		else if (issueFilter === 'medium') issues = issues.filter(i => i.severity === 'medium');
		else if (issueFilter === 'low') issues = issues.filter(i => i.severity === 'low');
		else if (issueFilter === 'info') issues = issues.filter(i => i.severity === 'info');
		if (searchQuery.trim()) {
			const q = searchQuery.toLowerCase();
			issues = issues.filter(i =>
				i.header_name.toLowerCase().includes(q) ||
				i.issue_type.toLowerCase().includes(q) ||
				i.category.toLowerCase().includes(q) ||
				i.description.toLowerCase().includes(q)
			);
		}
		return issues;
	}

	function getFilteredHeaders(): HeaderDetail[] {
		if (!result) return [];
		let headers = [...result.present_headers, ...result.missing_headers];
		if (headerFilter === 'present') headers = result.present_headers;
		else if (headerFilter === 'missing') headers = result.missing_headers;
		else if (headerFilter === 'good') headers = result.present_headers.filter(h => h.status === 'good');
		else if (headerFilter === 'warning') headers = result.present_headers.filter(h => h.status === 'warning');
		else if (headerFilter === 'bad') headers = result.present_headers.filter(h => h.status === 'bad');
		if (searchQuery.trim()) {
			const q = searchQuery.toLowerCase();
			headers = headers.filter(h =>
				h.name.toLowerCase().includes(q) ||
				h.category.toLowerCase().includes(q) ||
				h.description.toLowerCase().includes(q)
			);
		}
		return headers;
	}

	async function analyze() {
		if (!url.trim()) { error = $tr('secHeaders.error.emptyInput'); return; }
		processing = true; error = ''; result = null;
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			result = await invoke<SecurityHeaderReport>('analyze_security_headers_command', {
				url: url.trim(),
				config: {
					url: url.trim(),
					timeout,
					follow_redirects: followRedirects,
					verify_ssl: verifySsl,
					user_agent: null,
					proxy_url: proxyUrl || null,
					custom_headers: customHeaders || null,
					check_csp_details: checkCspDetails,
					check_cookie_headers: checkCookieHeaders,
					check_information_leakage: checkInfoLeakage,
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
			const { open } = await import('@tauri-apps/plugin-dialog');
			const savePath = await open({ directory: true, multiple: false });
			if (!savePath) return;
			const ext = exportFormat === 'csv' ? 'csv' : 'json';
			const fileName = `security-headers-${new Date().toISOString().slice(0, 10)}.${ext}`;
			let content: string;
			if (exportFormat === 'csv') {
				const header = 'Header,Status,Severity,Category,Description,Recommendation';
				const rows = [...result.present_headers, ...result.missing_headers].map(h =>
					`"${h.name}","${h.status}","${h.severity}","${h.category}","${h.description.replace(/"/g, '""')}","${h.recommendation.replace(/"/g, '""')}"`
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

	function clearAll() {
		url = ''; result = null; error = '';
		issueFilter = 'all'; headerFilter = 'all';
		searchQuery = ''; activeResultTab = 'overview';
		selectedIssue = null; expandedCsp = false; expandedHsts = false;
	}

	function handleKeydown(e: KeyboardEvent) {
		if (e.key === 'Enter' && !processing && url.trim()) {
			analyze();
		}
	}
</script>

<svelte:window onkeydown={handleKeydown} />

<div class="nd-page">
	<div class="page-header">
		<div class="header-left">
			<a href="/" class="back-link">{$tr('common.backToHome')}</a>
			<h1 class="page-title">🛡️ {$tr('secHeaders.title')}</h1>
			<p class="page-subtitle">{$tr('secHeaders.subtitle')}</p>
		</div>
	</div>

	<div class="tabs">
		<button class="tab-btn {activeMainTab === 'analyze' ? 'active' : ''}" onclick={() => activeMainTab = 'analyze'}>
			<span class="tab-icon">🔍</span> {$tr('secHeaders.tabs.analyze')}
		</button>
		<button class="tab-btn {activeMainTab === 'history' ? 'active' : ''}" onclick={() => activeMainTab = 'history'}>
			<span class="tab-icon">📋</span> {$tr('secHeaders.tabs.history')}
		</button>
		<button class="tab-btn {activeMainTab === 'help' ? 'active' : ''}" onclick={() => activeMainTab = 'help'}>
			<span class="tab-icon">📖</span> {$tr('secHeaders.tabs.help')}
		</button>
	</div>

	{#if activeMainTab === 'analyze'}
		<div class="content-grid">
			<div class="input-section">
				<div class="section-card">
					<h2 class="section-title">{$tr('secHeaders.configTitle')}</h2>
					<p class="section-desc">{$tr('secHeaders.configDesc')}</p>

					<div class="form-group">
						<label class="form-label">{$tr('secHeaders.targetUrl')}</label>
						<input type="text" bind:value={url} placeholder="https://example.com" class="form-input" disabled={processing} />
					</div>

					<div class="form-row">
						<div class="form-group">
							<label class="form-label">{$tr('secHeaders.timeout')}</label>
							<input type="number" bind:value={timeout} class="form-input" min="5" max="120" disabled={processing} />
						</div>
					</div>

					<div class="form-group">
						<label class="form-label">{$tr('secHeaders.scanOptions')}</label>
						<div class="target-grid">
							<label class="target-chip {checkCspDetails ? 'active' : ''}">
								<input type="checkbox" bind:checked={checkCspDetails} disabled={processing} />
								<span>📜 {$tr('secHeaders.cspDetails')}</span>
							</label>
							<label class="target-chip {checkCookieHeaders ? 'active' : ''}">
								<input type="checkbox" bind:checked={checkCookieHeaders} disabled={processing} />
								<span>🍪 {$tr('secHeaders.cookieSecurity')}</span>
							</label>
							<label class="target-chip {checkInfoLeakage ? 'active' : ''}">
								<input type="checkbox" bind:checked={checkInfoLeakage} disabled={processing} />
								<span>🔍 {$tr('secHeaders.infoLeakage')}</span>
							</label>
							<label class="target-chip {followRedirects ? 'active' : ''}">
								<input type="checkbox" bind:checked={followRedirects} disabled={processing} />
								<span>🔀 {$tr('secHeaders.followRedirects')}</span>
							</label>
						</div>
					</div>

					<div class="form-group">
						<button class="target-chip {showAdvanced ? 'active' : ''}" onclick={() => showAdvanced = !showAdvanced}>
							<span>⚙️ {$tr('secHeaders.advancedOptions')}</span>
						</button>
					</div>

					{#if showAdvanced}
						<div class="form-row">
							<div class="form-group">
								<label class="form-label">🌐 Proxy URL</label>
								<input type="text" bind:value={proxyUrl} placeholder="http://proxy:port" class="form-input" disabled={processing} />
							</div>
						</div>
						<div class="form-group">
							<label class="target-chip {verifySsl ? 'active' : ''}">
								<input type="checkbox" bind:checked={verifySsl} disabled={processing} />
								<span>🔒 {$tr('secHeaders.verifySsl')}</span>
							</label>
						</div>
						<div class="form-group">
							<label class="form-label">📋 {$tr('secHeaders.customHeaders')}</label>
							<textarea bind:value={customHeaders} placeholder="Authorization: Bearer token&#10;X-API-Key: your-key" class="form-input" style="height: 60px; resize: vertical; font-family: monospace; font-size: 12px;" disabled={processing}></textarea>
						</div>
					{/if}

					<div class="button-group">
						<button class="btn-primary" onclick={analyze} disabled={processing || !url.trim()}>
							{#if processing}<span class="spinner"></span>{$tr('secHeaders.analyzing')}{:else}🔍 {$tr('secHeaders.startAnalyze')}{/if}
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
								<h2 class="section-title" style="margin-bottom:0">🛡️ {result.url}</h2>
							</div>
							<div class="header-actions">
								<div class="score-badge" style="border-color: {getGradeColor(result.grade)}40; background: {getGradeColor(result.grade)}10;">
									<span class="score-grade" style="color: {getGradeColor(result.grade)}">{result.grade}</span>
									<span class="score-number">{result.score}/100</span>
								</div>
								<div class="resource-score-badge">
									<span class="score-value">{result.present_headers.length}</span>
									<span class="score-label">{$tr('secHeaders.present')}</span>
								</div>
								<div class="resource-score-badge">
									<span class="score-value">{result.missing_headers.length}</span>
									<span class="score-label">{$tr('secHeaders.missing')}</span>
								</div>
								<div class="resource-score-badge">
									<span class="score-value">{result.scan_duration_ms}ms</span>
									<span class="score-label">{$tr('secHeaders.duration')}</span>
								</div>
								<select bind:value={exportFormat} class="export-select">
									<option value="json">JSON</option>
									<option value="csv">CSV</option>
								</select>
								<button class="btn-export" onclick={exportResults} disabled={!result}>
									📤 {$tr('secHeaders.export')}
								</button>
							</div>
						</div>

						<div class="summary-bar">{result.summary}</div>

						<div class="result-tabs">
							<button class="result-tab {activeResultTab === 'overview' ? 'active' : ''}" onclick={() => activeResultTab = 'overview'}>
								📊 {$tr('secHeaders.tabOverview')}
							</button>
							<button class="result-tab {activeResultTab === 'issues' ? 'active' : ''}" onclick={() => activeResultTab = 'issues'}>
								⚠️ {$tr('secHeaders.tabIssues')} {#if result.issues.length}({result.issues.length}){/if}
							</button>
							<button class="result-tab {activeResultTab === 'headers' ? 'active' : ''}" onclick={() => activeResultTab = 'headers'}>
								📋 {$tr('secHeaders.tabHeaders')}
							</button>
							<button class="result-tab {activeResultTab === 'csp' ? 'active' : ''}" onclick={() => activeResultTab = 'csp'}>
								🔒 CSP {#if result.csp_analysis}✓{:else}✗{/if}
							</button>
							<button class="result-tab {activeResultTab === 'details' ? 'active' : ''}" onclick={() => activeResultTab = 'details'}>
								🔬 {$tr('secHeaders.tabDetails')}
							</button>
						</div>

						{#if activeResultTab === 'overview'}
							<div class="overview-content">
								<div class="stats-grid">
									<div class="stat-card">
										<div class="stat-icon">🛡️</div>
										<div class="stat-value" style="color: {getGradeColor(result.grade)}">{result.grade}</div>
										<div class="stat-label">{$tr('secHeaders.securityGrade')}</div>
									</div>
									<div class="stat-card">
										<div class="stat-icon">📊</div>
										<div class="stat-value">{result.score}</div>
										<div class="stat-label">{$tr('secHeaders.securityScore')}</div>
									</div>
									<div class="stat-card">
										<div class="stat-icon">✅</div>
										<div class="stat-value">{result.present_headers.length}</div>
										<div class="stat-label">{$tr('secHeaders.headersPresent')}</div>
									</div>
									<div class="stat-card">
										<div class="stat-icon">🚫</div>
										<div class="stat-value">{result.missing_headers.length}</div>
										<div class="stat-label">{$tr('secHeaders.headersMissing')}</div>
									</div>
								</div>

								{#if result.severity_stats && result.issues.length > 0}
									<div class="severity-section">
										<h3 class="subsection-title">{$tr('secHeaders.severityDistribution')}</h3>
										<div class="severity-bar">
											{#if result.severity_stats.critical > 0}
												<div class="severity-segment critical" style="width: {(result.severity_stats.critical / result.issues.length) * 100}%">
													{result.severity_stats.critical}
												</div>
											{/if}
											{#if result.severity_stats.high > 0}
												<div class="severity-segment high" style="width: {(result.severity_stats.high / result.issues.length) * 100}%">
													{result.severity_stats.high}
												</div>
											{/if}
											{#if result.severity_stats.medium > 0}
												<div class="severity-segment medium" style="width: {(result.severity_stats.medium / result.issues.length) * 100}%">
													{result.severity_stats.medium}
												</div>
											{/if}
											{#if result.severity_stats.low > 0}
												<div class="severity-segment low" style="width: {(result.severity_stats.low / result.issues.length) * 100}%">
													{result.severity_stats.low}
												</div>
											{/if}
											{#if result.severity_stats.info > 0}
												<div class="severity-segment info" style="width: {(result.severity_stats.info / result.issues.length) * 100}%">
													{result.severity_stats.info}
												</div>
											{/if}
										</div>
										<div class="severity-legend">
											{#if result.severity_stats.critical > 0}<span class="legend-item"><span class="legend-dot" style="background:#ef4444"></span>{$tr('secHeaders.critical')} {result.severity_stats.critical}</span>{/if}
											{#if result.severity_stats.high > 0}<span class="legend-item"><span class="legend-dot" style="background:#f97316"></span>{$tr('secHeaders.high')} {result.severity_stats.high}</span>{/if}
											{#if result.severity_stats.medium > 0}<span class="legend-item"><span class="legend-dot" style="background:#eab308"></span>{$tr('secHeaders.medium')} {result.severity_stats.medium}</span>{/if}
											{#if result.severity_stats.low > 0}<span class="legend-item"><span class="legend-dot" style="background:#22c55e"></span>{$tr('secHeaders.low')} {result.severity_stats.low}</span>{/if}
											{#if result.severity_stats.info > 0}<span class="legend-item"><span class="legend-dot" style="background:#3b82f6"></span>{$tr('secHeaders.info')} {result.severity_stats.info}</span>{/if}
										</div>
									</div>
								{/if}

								{#if result.category_stats && result.category_stats.length > 0}
									<div class="category-section">
										<h3 class="subsection-title">{$tr('secHeaders.categoryScores')}</h3>
										<div class="category-list">
											{#each result.category_stats as cat}
												<div class="category-item">
													<div class="category-header">
														<span class="category-icon">{getCategoryIcon(cat.category)}</span>
														<span class="category-name">{cat.category}</span>
														<span class="category-score">{cat.actual_score}/{cat.max_score}</span>
													</div>
													<div class="category-bar">
														<div class="category-bar-fill" style="width: {(cat.actual_score / cat.max_score) * 100}%; background: {cat.actual_score / cat.max_score >= 0.7 ? '#22c55e' : cat.actual_score / cat.max_score >= 0.4 ? '#eab308' : '#ef4444'}"></div>
													</div>
												</div>
											{/each}
										</div>
									</div>
								{/if}

								{#if result.information_leakage.length > 0}
									<div class="leakage-section">
										<h3 class="subsection-title">🔍 {$tr('secHeaders.infoLeakageFound')} ({result.information_leakage.length})</h3>
										{#each result.information_leakage as leak}
											<div class="leakage-item" style="border-left-color: {getSeverityColor(leak.risk_level)}">
												<div class="leakage-header">
													<span class="leakage-name">{leak.header_name}</span>
													<span class="leakage-risk" style="color: {getSeverityColor(leak.risk_level)}">{leak.risk_level}</span>
												</div>
												<div class="leakage-value"><code>{leak.value}</code></div>
												<div class="leakage-desc">{leak.description}</div>
											</div>
										{/each}
									</div>
								{/if}

								{#if result.server_header || result.x_powered_by}
									<div class="server-info">
										<h3 class="subsection-title">🖥️ {$tr('secHeaders.serverInfo')}</h3>
										{#if result.server_header}
											<div class="info-row"><span class="info-label">Server:</span> <code>{result.server_header}</code></div>
										{/if}
										{#if result.x_powered_by}
											<div class="info-row"><span class="info-label">X-Powered-By:</span> <code>{result.x_powered_by}</code></div>
										{/if}
										<div class="info-row"><span class="info-label">HTTP Status:</span> <code>{result.response_status}</code></div>
									</div>
								{/if}

								{#if result.https_redirect}
									<div class="redirect-section">
										<h3 class="subsection-title">🔀 {$tr('secHeaders.httpsRedirect')}</h3>
										{#if result.https_redirect.redirects_to_https}
											<div class="redirect-good">
												✅ {$tr('secHeaders.redirectsToHttps')}
												<div class="redirect-detail"><code>{result.https_redirect.original_url}</code> → <code>{result.https_redirect.final_url}</code></div>
											</div>
										{:else}
											<div class="redirect-bad">
												❌ {$tr('secHeaders.noHttpsRedirect')}
												{#if result.https_redirect.issue}
													<div class="redirect-issue">⚠️ {result.https_redirect.issue}</div>
												{/if}
											</div>
										{/if}
									</div>
								{/if}
							</div>

						{:else if activeResultTab === 'issues'}
							<div class="issues-content">
								<div class="filter-bar">
									<input type="text" bind:value={searchQuery} placeholder="{$tr('secHeaders.searchIssues')}" class="search-input" />
									<select bind:value={issueFilter} class="filter-select">
										<option value="all">{$tr('secHeaders.allSeverities')}</option>
										<option value="critical">🔴 Critical</option>
										<option value="high">🟠 High</option>
										<option value="medium">🟡 Medium</option>
										<option value="low">🟢 Low</option>
										<option value="info">ℹ️ Info</option>
									</select>
								</div>

								{#if getFilteredIssues().length > 0}
									<div class="data-table-container">
										<table class="data-table">
											<thead>
												<tr>
													<th>{$tr('secHeaders.severity')}</th>
													<th>{$tr('secHeaders.header')}</th>
													<th>{$tr('secHeaders.issueType')}</th>
													<th>{$tr('secHeaders.category')}</th>
													<th>{$tr('secHeaders.description')}</th>
												</tr>
											</thead>
											<tbody>
												{#each getFilteredIssues() as issue}
													<tr class="clickable-row" onclick={() => selectedIssue = selectedIssue?.header_name === issue.header_name && selectedIssue?.issue_type === issue.issue_type ? null : issue}>
														<td><span style="color: {getSeverityColor(issue.severity)}">{getSeverityIcon(issue.severity)} {issue.severity}</span></td>
														<td><strong>{issue.header_name}</strong></td>
														<td>{issue.issue_type}</td>
														<td>{getCategoryIcon(issue.category)} {issue.category}</td>
														<td class="truncate-cell">{issue.description}</td>
													</tr>
												{/each}
											</tbody>
										</table>
									</div>

									{#if selectedIssue}
										<div class="issue-detail-card">
											<div class="issue-detail-header">
												<span style="color: {getSeverityColor(selectedIssue.severity)}">{getSeverityIcon(selectedIssue.severity)}</span>
												<strong>{selectedIssue.header_name}</strong>
												<span class="issue-type-badge">{selectedIssue.issue_type}</span>
											</div>
											<div class="issue-detail-body">
												<p>{selectedIssue.description}</p>
												{#if selectedIssue.recommendation}
													<div class="recommendation-box">
														<strong>💡 {$tr('secHeaders.recommendation')}:</strong>
														<p>{selectedIssue.recommendation}</p>
													</div>
												{/if}
												{#if selectedIssue.current_value}
													<div class="current-value-box">
														<strong>{$tr('secHeaders.currentValue')}:</strong>
														<code>{selectedIssue.current_value}</code>
													</div>
												{/if}
												{#if selectedIssue.cwe_id || selectedIssue.owasp_category}
													<div class="reference-box">
														{#if selectedIssue.cwe_id}<span class="ref-badge">🔗 {selectedIssue.cwe_id}</span>{/if}
														{#if selectedIssue.owasp_category}<span class="ref-badge">🔗 {selectedIssue.owasp_category}</span>{/if}
													</div>
												{/if}
											</div>
										</div>
									{/if}
								{:else}
									<div class="empty-state">
										<span class="empty-icon">✅</span>
										<p>{$tr('secHeaders.noIssuesFound')}</p>
									</div>
								{/if}
							</div>

						{:else if activeResultTab === 'headers'}
							<div class="headers-content">
								<div class="filter-bar">
									<input type="text" bind:value={searchQuery} placeholder="{$tr('secHeaders.searchHeaders')}" class="search-input" />
									<select bind:value={headerFilter} class="filter-select">
										<option value="all">{$tr('secHeaders.allHeaders')}</option>
										<option value="present">✅ {$tr('secHeaders.presentOnly')}</option>
										<option value="missing">🚫 {$tr('secHeaders.missingOnly')}</option>
										<option value="good">✅ Good</option>
										<option value="warning">⚠️ Warning</option>
										<option value="bad">❌ Bad</option>
									</select>
								</div>

								{#if getFilteredHeaders().length > 0}
									<div class="data-table-container">
										<table class="data-table">
											<thead>
												<tr>
													<th>{$tr('secHeaders.status')}</th>
													<th>{$tr('secHeaders.header')}</th>
													<th>{$tr('secHeaders.value')}</th>
													<th>{$tr('secHeaders.severity')}</th>
													<th>{$tr('secHeaders.category')}</th>
												</tr>
											</thead>
											<tbody>
												{#each getFilteredHeaders() as header}
													<tr>
														<td>{getStatusIcon(header.status)}</td>
														<td><strong>{header.name}</strong></td>
														<td class="truncate-cell"><code>{header.value || '-'}</code></td>
														<td><span style="color: {getSeverityColor(header.severity)}">{header.severity}</span></td>
														<td>{getCategoryIcon(header.category)} {header.category}</td>
													</tr>
												{/each}
											</tbody>
										</table>
									</div>
								{:else}
									<div class="empty-state">
										<span class="empty-icon">📋</span>
										<p>{$tr('secHeaders.noHeadersMatch')}</p>
									</div>
								{/if}
							</div>

						{:else if activeResultTab === 'csp'}
							<div class="csp-content">
								{#if result.csp_analysis}
									{@const csp = result.csp_analysis}
									<div class="csp-overview">
										<div class="csp-score-card">
											<div class="csp-score" style="color: {csp.score >= 14 ? '#22c55e' : csp.score >= 10 ? '#eab308' : '#ef4444'}">
												{csp.score}/20
											</div>
											<div class="csp-assessment">{csp.overall_assessment}</div>
										</div>
									</div>

									<div class="csp-flags">
										<span class="csp-flag {csp.has_default_src ? 'good' : 'bad'}">default-src {csp.has_default_src ? '✓' : '✗'}</span>
										<span class="csp-flag {csp.has_script_src ? 'good' : 'bad'}">script-src {csp.has_script_src ? '✓' : '✗'}</span>
										<span class="csp-flag {csp.has_object_src ? 'good' : 'bad'}">object-src {csp.has_object_src ? '✓' : '✗'}</span>
										<span class="csp-flag {csp.has_base_uri ? 'good' : 'bad'}">base-uri {csp.has_base_uri ? '✓' : '✗'}</span>
										<span class="csp-flag {csp.has_form_action ? 'good' : 'bad'}">form-action {csp.has_form_action ? '✓' : '✗'}</span>
										<span class="csp-flag {csp.has_frame_ancestors ? 'good' : 'bad'}">frame-ancestors {csp.has_frame_ancestors ? '✓' : '✗'}</span>
										<span class="csp-flag {!csp.uses_unsafe_inline ? 'good' : 'bad'}">unsafe-inline {!csp.uses_unsafe_inline ? '✓' : '✗'}</span>
										<span class="csp-flag {!csp.uses_unsafe_eval ? 'good' : 'bad'}">unsafe-eval {!csp.uses_unsafe_eval ? '✓' : '✗'}</span>
										<span class="csp-flag {csp.uses_nonce || csp.uses_hash ? 'good' : 'neutral'}">{csp.uses_nonce ? 'nonce' : csp.uses_hash ? 'hash' : 'no nonce/hash'}</span>
										<span class="csp-flag {csp.has_report_uri ? 'good' : 'neutral'}">report-uri {csp.has_report_uri ? '✓' : '✗'}</span>
									</div>

									<div class="csp-raw-toggle" onclick={() => expandedCsp = !expandedCsp}>
										{expandedCsp ? '▼' : '▶'} {$tr('secHeaders.rawCsp')}
									</div>
									{#if expandedCsp}
										<div class="csp-raw-value"><code>{csp.raw_value}</code></div>
									{/if}

									{#if csp.directives.length > 0}
										<h3 class="subsection-title">{$tr('secHeaders.cspDirectives')}</h3>
										<div class="data-table-container">
											<table class="data-table">
												<thead>
													<tr>
														<th>{$tr('secHeaders.directive')}</th>
														<th>{$tr('secHeaders.value')}</th>
														<th>{$tr('secHeaders.secure')}</th>
														<th>{$tr('secHeaders.issues')}</th>
													</tr>
												</thead>
												<tbody>
													{#each csp.directives as dir}
														<tr>
															<td><strong>{dir.directive}</strong></td>
															<td class="truncate-cell"><code>{dir.value || "'none'"}</code></td>
															<td>{dir.is_secure ? '✅' : '❌'}</td>
															<td>{#if dir.issues.length > 0}{dir.issues.join('; ')}{:else}-{/if}</td>
														</tr>
													{/each}
												</tbody>
											</table>
										</div>
									{/if}
								{:else}
									<div class="empty-state">
										<span class="empty-icon">🚫</span>
										<p>{$tr('secHeaders.noCspFound')}</p>
									</div>
								{/if}
							</div>

						{:else if activeResultTab === 'details'}
							<div class="details-content">
								{#if result.hsts_analysis}
									{@const hsts = result.hsts_analysis}
									<div class="detail-section">
										<h3 class="subsection-title" onclick={() => expandedHsts = !expandedHsts} style="cursor:pointer">
											{expandedHsts ? '▼' : '▶'} 🔒 HSTS Analysis
											<span class="hsts-score" style="color: {hsts.is_secure ? '#22c55e' : '#ef4444'}">{hsts.score}/15</span>
										</h3>
										{#if expandedHsts}
											<div class="hsts-detail">
												<div class="hsts-flags">
													<span class="csp-flag {hsts.max_age >= 31536000 ? 'good' : 'bad'}">max-age: {hsts.max_age}s {hsts.max_age >= 31536000 ? '✓' : '✗'}</span>
													<span class="csp-flag {hsts.include_sub_domains ? 'good' : 'bad'}">includeSubDomains {hsts.include_sub_domains ? '✓' : '✗'}</span>
													<span class="csp-flag {hsts.preload ? 'good' : 'bad'}">preload {hsts.preload ? '✓' : '✗'}</span>
												</div>
												<div class="csp-raw-value"><code>{hsts.raw_value}</code></div>
												{#if hsts.issues.length > 0}
													<div class="hsts-issues">
														{#each hsts.issues as issue}
															<div class="hsts-issue">⚠️ {issue}</div>
														{/each}
													</div>
												{/if}
											</div>
										{/if}
									</div>
								{/if}

								{#if result.cookie_security.length > 0}
									<div class="detail-section">
										<h3 class="subsection-title">🍪 {$tr('secHeaders.cookieSecurity')} ({result.cookie_security.length})</h3>
										<div class="data-table-container">
											<table class="data-table">
												<thead>
													<tr>
														<th>{$tr('secHeaders.cookieName')}</th>
														<th>HttpOnly</th>
														<th>Secure</th>
														<th>SameSite</th>
														<th>{$tr('secHeaders.risk')}</th>
													</tr>
												</thead>
												<tbody>
													{#each result.cookie_security as cookie}
														<tr>
															<td><strong>{cookie.name}</strong></td>
															<td>{cookie.has_httponly ? '✅' : '❌'}</td>
															<td>{cookie.has_secure ? '✅' : '❌'}</td>
															<td>{#if cookie.has_samesite}{cookie.samesite_value || '✅'}{:else}❌{/if}</td>
															<td><span style="color: {getSeverityColor(cookie.risk_level)}">{cookie.risk_level}</span></td>
														</tr>
														{#if cookie.issue}
															<tr class="sub-row">
																<td colspan="5" style="color: {getSeverityColor(cookie.risk_level)}">⚠️ {cookie.issue}</td>
															</tr>
														{/if}
													{/each}
												</tbody>
											</table>
										</div>
									</div>
								{/if}

								{#if result.present_headers.length > 0}
									<div class="detail-section">
										<h3 class="subsection-title">✅ {$tr('secHeaders.presentHeadersDetail')} ({result.present_headers.length})</h3>
										{#each result.present_headers as header}
											<div class="header-detail-card" style="border-left-color: {getStatusColor(header.status)}">
												<div class="header-detail-top">
													<span>{getStatusIcon(header.status)}</span>
													<strong>{header.name}</strong>
													<span class="severity-badge" style="background: {getSeverityColor(header.severity)}20; color: {getSeverityColor(header.severity)}">{header.severity}</span>
													<span class="category-badge">{getCategoryIcon(header.category)} {header.category}</span>
												</div>
												<div class="header-detail-value"><code>{header.value || '-'}</code></div>
												<div class="header-detail-desc">{header.description}</div>
												{#if header.recommendation && header.recommendation !== 'Well configured'}
													<div class="recommendation-box">
														<strong>💡 {$tr('secHeaders.recommendation')}:</strong> {header.recommendation}
													</div>
												{/if}
												{#if header.cwe_id || header.owasp_category}
													<div class="reference-box">
														{#if header.cwe_id}<span class="ref-badge">🔗 {header.cwe_id}</span>{/if}
														{#if header.owasp_category}<span class="ref-badge">🔗 {header.owasp_category}</span>{/if}
													</div>
												{/if}
											</div>
										{/each}
									</div>
								{/if}

								{#if result.missing_headers.length > 0}
									<div class="detail-section">
										<h3 class="subsection-title">🚫 {$tr('secHeaders.missingHeadersDetail')} ({result.missing_headers.length})</h3>
										{#each result.missing_headers as header}
											<div class="header-detail-card missing">
												<div class="header-detail-top">
													<span>🚫</span>
													<strong>{header.name}</strong>
													<span class="severity-badge" style="background: {getSeverityColor(header.severity)}20; color: {getSeverityColor(header.severity)}">{header.severity}</span>
													<span class="category-badge">{getCategoryIcon(header.category)} {header.category}</span>
												</div>
												<div class="header-detail-desc">{header.description}</div>
												<div class="recommendation-box">
													<strong>💡 {$tr('secHeaders.recommendation')}:</strong> {header.recommendation}
												</div>
												{#if header.cwe_id || header.owasp_category}
													<div class="reference-box">
														{#if header.cwe_id}<span class="ref-badge">🔗 {header.cwe_id}</span>{/if}
														{#if header.owasp_category}<span class="ref-badge">🔗 {header.owasp_category}</span>{/if}
													</div>
												{/if}
											</div>
										{/each}
									</div>
								{/if}
							</div>
						{/if}
					{:else}
						<div class="empty-state">
							<span class="empty-icon">🛡️</span>
							<p>{$tr('secHeaders.emptyHint')}</p>
						</div>
					{/if}
				</div>
			</div>
		</div>
	{:else if activeMainTab === 'history'}
		<ToolHistory
			bind:this={historyComponent}
			toolType="security_headers"
			toolName={$tr('secHeaders.title')}
		/>
	{:else if activeMainTab === 'help'}
		<ToolHelp
			toolType="security_headers"
		/>
	{/if}
</div>

<style>
	.nd-page {
		max-width: 1400px;
		margin: 0 auto;
		padding: 20px;
		color: #e2e8f0;
		font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
	}

	.page-header {
		display: flex;
		justify-content: space-between;
		align-items: flex-start;
		margin-bottom: 20px;
	}

	.header-left { display: flex; flex-direction: column; gap: 4px; }

	.back-link {
		color: #64748b;
		text-decoration: none;
		font-size: 13px;
		transition: color 0.2s;
	}
	.back-link:hover { color: #94a3b8; }

	.page-title {
		font-size: 24px;
		font-weight: 700;
		color: #f1f5f9;
		margin: 0;
	}

	.page-subtitle {
		font-size: 14px;
		color: #94a3b8;
		margin: 0;
	}

	.tabs {
		display: flex;
		gap: 4px;
		margin-bottom: 20px;
		border-bottom: 1px solid #1e293b;
		padding-bottom: 0;
	}

	.tab-btn {
		padding: 10px 20px;
		border: none;
		background: transparent;
		color: #94a3b8;
		cursor: pointer;
		font-size: 14px;
		border-bottom: 2px solid transparent;
		transition: all 0.2s;
		display: flex;
		align-items: center;
		gap: 6px;
	}

	.tab-btn:hover { color: #e2e8f0; }
	.tab-btn.active { color: #f1f5f9; border-bottom-color: #3b82f6; }

	.tab-icon { font-size: 16px; }

	.content-grid {
		display: grid;
		grid-template-columns: 380px 1fr;
		gap: 20px;
	}

	.input-section, .result-section { min-width: 0; }

	.section-card {
		background: #0f172a;
		border: 1px solid #1e293b;
		border-radius: 12px;
		padding: 20px;
	}

	.section-title {
		font-size: 16px;
		font-weight: 600;
		color: #f1f5f9;
		margin: 0 0 12px 0;
	}

	.section-desc {
		font-size: 13px;
		color: #94a3b8;
		margin: 0 0 16px 0;
	}

	.form-group { margin-bottom: 14px; }

	.form-label {
		display: block;
		font-size: 13px;
		color: #94a3b8;
		margin-bottom: 6px;
	}

	.form-input {
		width: 100%;
		padding: 10px 12px;
		background: #1e293b;
		border: 1px solid #334155;
		border-radius: 8px;
		color: #e2e8f0;
		font-size: 14px;
		outline: none;
		transition: border-color 0.2s;
		box-sizing: border-box;
	}

	.form-input:focus { border-color: #3b82f6; }
	.form-input:disabled { opacity: 0.5; cursor: not-allowed; }

	.form-row {
		display: grid;
		grid-template-columns: 1fr 1fr;
		gap: 12px;
	}

	.target-grid {
		display: grid;
		grid-template-columns: 1fr 1fr;
		gap: 8px;
	}

	.target-chip {
		display: flex;
		align-items: center;
		gap: 6px;
		padding: 8px 12px;
		background: #1e293b;
		border: 1px solid #334155;
		border-radius: 8px;
		cursor: pointer;
		font-size: 13px;
		color: #94a3b8;
		transition: all 0.2s;
		width: 100%;
		text-align: left;
	}

	.target-chip:hover { border-color: #475569; }
	.target-chip.active { border-color: #3b82f6; background: #1e3a5f; color: #e2e8f0; }
	.target-chip input[type="checkbox"] { display: none; }

	.button-group {
		display: flex;
		gap: 10px;
		margin-top: 16px;
	}

	.btn-primary {
		flex: 1;
		padding: 10px 20px;
		background: #3b82f6;
		border: none;
		border-radius: 8px;
		color: white;
		font-size: 14px;
		cursor: pointer;
		transition: background 0.2s;
		display: flex;
		align-items: center;
		justify-content: center;
		gap: 6px;
	}

	.btn-primary:hover { background: #2563eb; }
	.btn-primary:disabled { opacity: 0.5; cursor: not-allowed; }

	.btn-secondary {
		padding: 10px 16px;
		background: #1e293b;
		border: 1px solid #334155;
		border-radius: 8px;
		color: #94a3b8;
		cursor: pointer;
		transition: all 0.2s;
	}

	.btn-secondary:hover { border-color: #475569; color: #e2e8f0; }

	.spinner {
		display: inline-block;
		width: 14px;
		height: 14px;
		border: 2px solid rgba(255,255,255,0.3);
		border-top-color: white;
		border-radius: 50%;
		animation: spin 0.8s linear infinite;
	}

	@keyframes spin { to { transform: rotate(360deg); } }

	.error-card {
		display: flex;
		align-items: center;
		gap: 12px;
		padding: 16px;
		background: #1c0f0f;
		border: 1px solid #7f1d1d;
		border-radius: 8px;
	}

	.error-icon { font-size: 20px; }
	.error-text { color: #fca5a5; font-size: 14px; }

	.result-header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		flex-wrap: wrap;
		gap: 12px;
		margin-bottom: 12px;
	}

	.header-actions {
		display: flex;
		align-items: center;
		gap: 10px;
		flex-wrap: wrap;
	}

	.score-badge {
		display: flex;
		align-items: center;
		gap: 8px;
		padding: 6px 14px;
		border: 1px solid;
		border-radius: 8px;
	}

	.score-grade { font-size: 20px; font-weight: 700; }
	.score-number { font-size: 13px; color: #94a3b8; }

	.resource-score-badge {
		display: flex;
		flex-direction: column;
		align-items: center;
		padding: 4px 10px;
		background: #1e293b;
		border-radius: 6px;
	}

	.score-value { font-size: 14px; font-weight: 600; color: #e2e8f0; }
	.score-label { font-size: 11px; color: #64748b; }

	.export-select {
		padding: 6px 10px;
		background: #1e293b;
		border: 1px solid #334155;
		border-radius: 6px;
		color: #e2e8f0;
		font-size: 13px;
	}

	.btn-export {
		padding: 6px 14px;
		background: #1e293b;
		border: 1px solid #334155;
		border-radius: 6px;
		color: #e2e8f0;
		cursor: pointer;
		font-size: 13px;
		transition: all 0.2s;
	}

	.btn-export:hover { border-color: #475569; }

	.summary-bar {
		padding: 10px 14px;
		background: #1e293b;
		border-radius: 8px;
		font-size: 13px;
		color: #cbd5e1;
		margin-bottom: 16px;
	}

	.result-tabs {
		display: flex;
		gap: 2px;
		margin-bottom: 16px;
		border-bottom: 1px solid #1e293b;
	}

	.result-tab {
		padding: 8px 14px;
		border: none;
		background: transparent;
		color: #94a3b8;
		cursor: pointer;
		font-size: 13px;
		border-bottom: 2px solid transparent;
		transition: all 0.2s;
	}

	.result-tab:hover { color: #e2e8f0; }
	.result-tab.active { color: #f1f5f9; border-bottom-color: #3b82f6; }

	.empty-state {
		display: flex;
		flex-direction: column;
		align-items: center;
		justify-content: center;
		padding: 60px 20px;
		color: #64748b;
	}

	.empty-icon { font-size: 48px; margin-bottom: 12px; }

	.stats-grid {
		display: grid;
		grid-template-columns: repeat(4, 1fr);
		gap: 12px;
		margin-bottom: 20px;
	}

	.stat-card {
		background: #1e293b;
		border: 1px solid #334155;
		border-radius: 10px;
		padding: 16px;
		text-align: center;
	}

	.stat-icon { font-size: 20px; margin-bottom: 6px; }
	.stat-value { font-size: 24px; font-weight: 700; color: #f1f5f9; }
	.stat-label { font-size: 12px; color: #64748b; margin-top: 4px; }

	.severity-section, .category-section, .leakage-section, .server-info {
		margin-bottom: 20px;
	}

	.subsection-title {
		font-size: 14px;
		font-weight: 600;
		color: #e2e8f0;
		margin: 0 0 12px 0;
	}

	.severity-bar {
		display: flex;
		height: 28px;
		border-radius: 6px;
		overflow: hidden;
		background: #1e293b;
	}

	.severity-segment {
		display: flex;
		align-items: center;
		justify-content: center;
		font-size: 12px;
		font-weight: 600;
		color: white;
		min-width: 30px;
	}

	.severity-segment.critical { background: #ef4444; }
	.severity-segment.high { background: #f97316; }
	.severity-segment.medium { background: #eab308; }
	.severity-segment.low { background: #22c55e; }
	.severity-segment.info { background: #3b82f6; }

	.severity-legend {
		display: flex;
		gap: 16px;
		margin-top: 8px;
		flex-wrap: wrap;
	}

	.legend-item {
		display: flex;
		align-items: center;
		gap: 6px;
		font-size: 12px;
		color: #94a3b8;
	}

	.legend-dot {
		width: 8px;
		height: 8px;
		border-radius: 50%;
	}

	.category-list { display: flex; flex-direction: column; gap: 10px; }

	.category-item {
		background: #1e293b;
		border-radius: 8px;
		padding: 10px 14px;
	}

	.category-header {
		display: flex;
		align-items: center;
		gap: 8px;
		margin-bottom: 6px;
	}

	.category-icon { font-size: 16px; }
	.category-name { font-size: 13px; color: #e2e8f0; flex: 1; }
	.category-score { font-size: 13px; color: #94a3b8; font-weight: 600; }

	.category-bar {
		height: 6px;
		background: #0f172a;
		border-radius: 3px;
		overflow: hidden;
	}

	.category-bar-fill {
		height: 100%;
		border-radius: 3px;
		transition: width 0.3s;
	}

	.leakage-item {
		padding: 10px 14px;
		background: #1e293b;
		border-radius: 8px;
		border-left: 3px solid;
		margin-bottom: 8px;
	}

	.leakage-header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		margin-bottom: 4px;
	}

	.leakage-name { font-weight: 600; color: #e2e8f0; font-size: 13px; }
	.leakage-risk { font-size: 12px; font-weight: 600; }
	.leakage-value { margin: 4px 0; }
	.leakage-value code { font-size: 12px; color: #94a3b8; }
	.leakage-desc { font-size: 12px; color: #64748b; }

	.info-row {
		display: flex;
		gap: 8px;
		align-items: center;
		padding: 6px 0;
		font-size: 13px;
	}

	.info-label { color: #94a3b8; min-width: 120px; }
	.info-row code { color: #e2e8f0; background: #1e293b; padding: 2px 6px; border-radius: 4px; font-size: 12px; }

	.filter-bar {
		display: flex;
		gap: 10px;
		margin-bottom: 14px;
	}

	.search-input {
		flex: 1;
		padding: 8px 12px;
		background: #1e293b;
		border: 1px solid #334155;
		border-radius: 8px;
		color: #e2e8f0;
		font-size: 13px;
		outline: none;
	}

	.search-input:focus { border-color: #3b82f6; }

	.filter-select {
		padding: 8px 12px;
		background: #1e293b;
		border: 1px solid #334155;
		border-radius: 8px;
		color: #e2e8f0;
		font-size: 13px;
	}

	.data-table-container {
		overflow-x: auto;
		border-radius: 8px;
		border: 1px solid #1e293b;
	}

	.data-table {
		width: 100%;
		border-collapse: collapse;
		font-size: 13px;
	}

	.data-table th {
		padding: 10px 14px;
		background: #1e293b;
		color: #94a3b8;
		font-weight: 600;
		text-align: left;
		border-bottom: 1px solid #334155;
		white-space: nowrap;
	}

	.data-table td {
		padding: 10px 14px;
		border-bottom: 1px solid #1e293b;
		color: #e2e8f0;
	}

	.data-table tr:hover { background: #1e293b40; }

	.clickable-row { cursor: pointer; }
	.clickable-row:hover { background: #1e293b80; }

	.truncate-cell {
		max-width: 200px;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.sub-row td { padding: 4px 14px 10px; font-size: 12px; }

	.issue-detail-card {
		margin-top: 14px;
		padding: 16px;
		background: #1e293b;
		border: 1px solid #334155;
		border-radius: 10px;
	}

	.issue-detail-header {
		display: flex;
		align-items: center;
		gap: 8px;
		margin-bottom: 12px;
	}

	.issue-type-badge {
		padding: 2px 8px;
		background: #334155;
		border-radius: 4px;
		font-size: 11px;
		color: #94a3b8;
	}

	.issue-detail-body p { margin: 0 0 10px; font-size: 13px; color: #cbd5e1; }

	.recommendation-box {
		padding: 10px 14px;
		background: #0f172a;
		border-radius: 8px;
		margin-top: 8px;
		font-size: 13px;
		color: #cbd5e1;
	}

	.recommendation-box p { margin: 4px 0 0; }

	.current-value-box {
		padding: 10px 14px;
		background: #0f172a;
		border-radius: 8px;
		margin-top: 8px;
		font-size: 13px;
	}

	.current-value-box code { color: #e2e8f0; }

	.reference-box {
		display: flex;
		gap: 8px;
		margin-top: 8px;
	}

	.ref-badge {
		padding: 2px 8px;
		background: #1e3a5f;
		border-radius: 4px;
		font-size: 11px;
		color: #93c5fd;
	}

	.csp-overview { margin-bottom: 16px; }

	.csp-score-card {
		text-align: center;
		padding: 16px;
		background: #1e293b;
		border-radius: 10px;
	}

	.csp-score { font-size: 32px; font-weight: 700; }
	.csp-assessment { font-size: 14px; color: #94a3b8; margin-top: 4px; }

	.csp-flags {
		display: flex;
		flex-wrap: wrap;
		gap: 8px;
		margin-bottom: 16px;
	}

	.csp-flag {
		padding: 4px 10px;
		border-radius: 6px;
		font-size: 12px;
		font-weight: 500;
	}

	.csp-flag.good { background: #052e16; color: #86efac; }
	.csp-flag.bad { background: #450a0a; color: #fca5a5; }
	.csp-flag.neutral { background: #1e293b; color: #94a3b8; }

	.csp-raw-toggle {
		padding: 8px 0;
		cursor: pointer;
		color: #94a3b8;
		font-size: 13px;
		transition: color 0.2s;
	}

	.csp-raw-toggle:hover { color: #e2e8f0; }

	.csp-raw-value {
		padding: 12px;
		background: #0f172a;
		border-radius: 8px;
		margin-bottom: 16px;
	}

	.csp-raw-value code { font-size: 12px; color: #94a3b8; word-break: break-all; }

	.hsts-score { margin-left: 8px; font-size: 14px; }

	.hsts-detail { margin-top: 12px; }

	.hsts-flags { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 12px; }

	.hsts-issues { margin-top: 8px; }

	.hsts-issue {
		padding: 6px 10px;
		background: #1e293b;
		border-radius: 6px;
		font-size: 12px;
		color: #eab308;
		margin-bottom: 4px;
	}

	.detail-section { margin-bottom: 20px; }

	.header-detail-card {
		padding: 12px 14px;
		background: #1e293b;
		border-radius: 8px;
		border-left: 3px solid;
		margin-bottom: 8px;
	}

	.header-detail-card.missing { border-left-color: #6b7280; }

	.header-detail-top {
		display: flex;
		align-items: center;
		gap: 8px;
		margin-bottom: 6px;
	}

	.severity-badge {
		padding: 1px 8px;
		border-radius: 4px;
		font-size: 11px;
		font-weight: 600;
	}

	.category-badge {
		padding: 1px 8px;
		background: #334155;
		border-radius: 4px;
		font-size: 11px;
		color: #94a3b8;
	}

	.header-detail-value {
		margin: 4px 0;
	}

	.header-detail-value code { font-size: 12px; color: #94a3b8; }

	.header-detail-desc {
		font-size: 13px;
		color: #cbd5e1;
		margin: 4px 0;
	}

	.redirect-section { margin-bottom: 20px; }

	.redirect-good {
		padding: 12px 14px;
		background: #052e16;
		border: 1px solid #166534;
		border-radius: 8px;
		color: #86efac;
		font-size: 13px;
	}

	.redirect-bad {
		padding: 12px 14px;
		background: #450a0a;
		border: 1px solid #7f1d1d;
		border-radius: 8px;
		color: #fca5a5;
		font-size: 13px;
	}

	.redirect-detail {
		margin-top: 6px;
		font-size: 12px;
		color: #94a3b8;
	}

	.redirect-detail code {
		color: #e2e8f0;
		background: #0f172a;
		padding: 2px 6px;
		border-radius: 4px;
	}

	.redirect-issue {
		margin-top: 6px;
		font-size: 12px;
		color: #fbbf24;
	}

	@media (max-width: 900px) {
		.content-grid { grid-template-columns: 1fr; }
		.stats-grid { grid-template-columns: repeat(2, 1fr); }
	}
</style>
