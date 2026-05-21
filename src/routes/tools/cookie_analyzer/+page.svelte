<script lang="ts">
	import { tr } from '$lib/i18n';
	import ToolHistory from '$lib/components/ToolHistory.svelte';
	import ToolHelp from '$lib/components/ToolHelp.svelte';

	interface CookieFlagsStatus {
		has_httponly: boolean;
		has_secure: boolean;
		has_samesite: boolean;
		has_path: boolean;
		has_domain: boolean;
		has_expiry: boolean;
		total_flags: number;
		max_flags: number;
	}

	interface CookieInfo {
		name: string;
		value_preview: string;
		value_length: number;
		domain: string | null;
		path: string | null;
		expires: string | null;
		max_age: number | null;
		http_only: boolean;
		secure: boolean;
		same_site: string | null;
		is_session: boolean;
		is_third_party: boolean;
		cookie_category: string;
		risk_level: string;
		flags_status: CookieFlagsStatus;
	}

	interface CookieIssue {
		cookie_name: string;
		issue_type: string;
		severity: string;
		category: string;
		description: string;
		recommendation: string;
		cwe_id: string | null;
		owasp_category: string | null;
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

	interface ComplianceReport {
		gdpr_compliant: boolean;
		pci_dss_compliant: boolean;
		owasp_compliant: boolean;
		gdpr_issues: string[];
		pci_dss_issues: string[];
		owasp_issues: string[];
		overall_compliance_score: number;
	}

	interface ResponseHeaderInfo {
		has_strict_transport: boolean;
		has_x_content_type_options: boolean;
		has_x_frame_options: boolean;
		has_csp: boolean;
		server_header: string | null;
		x_powered_by: string | null;
		security_headers_score: number;
	}

	interface CookieAnalyzerResult {
		url: string;
		cookies: CookieInfo[];
		issues: CookieIssue[];
		score: number;
		grade: string;
		summary: string;
		severity_stats: SeverityStats;
		category_stats: CategoryStat[];
		compliance_report: ComplianceReport;
		response_headers: ResponseHeaderInfo;
		scan_duration_ms: number;
	}

	let url = $state('');
	let activeMainTab = $state('analyze');
	let activeResultTab = $state('overview');
	let historyComponent: ToolHistory = $state(null!);
	let timeout = $state(15);
	let followRedirects = $state(true);
	let verifySsl = $state(false);
	let proxyUrl = $state('');
	let checkJsCookies = $state(true);
	let checkThirdParty = $state(true);
	let checkCompliance = $state(true);
	let showAdvanced = $state(false);
	let customHeaders = $state('');
	let result: CookieAnalyzerResult | null = $state(null);
	let error = $state('');
	let processing = $state(false);
	let searchQuery = $state('');
	let issueFilter = $state('all');
	let cookieFilter = $state('all');
	let exportFormat = $state('json');
	let selectedIssue: CookieIssue | null = $state(null);

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

	function getCategoryIcon(c: string): string {
		switch (c) {
			case 'Transport Security': return '🔒';
			case 'XSS Protection': return '🛡️';
			case 'CSRF Protection': return '🔄';
			case 'Session Management': return '⏰';
			case 'Scope Control': return '🎯';
			case 'Browser Compatibility': return '🌐';
			case 'Privacy': return '👁️';
			case 'Performance': return '⚡';
			case 'Defense in Depth': return '🏰';
			default: return '🔍';
		}
	}

	function getCookieCategoryIcon(c: string): string {
		switch (c) {
			case 'Tracking/Analytics': return '📊';
			case 'Security': return '🔒';
			case 'Authentication': return '🔑';
			case 'Preferences': return '⚙️';
			case 'E-Commerce': return '🛒';
			case 'Consent/Privacy': return '📋';
			default: return '🍪';
		}
	}

	function getFilteredIssues(): CookieIssue[] {
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
				i.cookie_name.toLowerCase().includes(q) ||
				i.issue_type.toLowerCase().includes(q) ||
				i.category.toLowerCase().includes(q) ||
				i.description.toLowerCase().includes(q)
			);
		}
		return issues;
	}

	function getFilteredCookies(): CookieInfo[] {
		if (!result) return [];
		let cookies = result.cookies;
		if (cookieFilter === 'critical') cookies = cookies.filter(c => c.risk_level === 'critical');
		else if (cookieFilter === 'high') cookies = cookies.filter(c => c.risk_level === 'high');
		else if (cookieFilter === 'medium') cookies = cookies.filter(c => c.risk_level === 'medium');
		else if (cookieFilter === 'low') cookies = cookies.filter(c => c.risk_level === 'low');
		else if (cookieFilter === 'session') cookies = cookies.filter(c => c.is_session);
		else if (cookieFilter === 'third_party') cookies = cookies.filter(c => c.is_third_party);
		else if (cookieFilter === 'insecure') cookies = cookies.filter(c => !c.secure || !c.http_only);
		if (searchQuery.trim()) {
			const q = searchQuery.toLowerCase();
			cookies = cookies.filter(c =>
				c.name.toLowerCase().includes(q) ||
				c.cookie_category.toLowerCase().includes(q) ||
				(c.domain || '').toLowerCase().includes(q)
			);
		}
		return cookies;
	}

	async function analyze() {
		if (!url.trim()) { error = $tr('cookieAnalyzer.error.emptyInput'); return; }
		processing = true; error = ''; result = null;
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			result = await invoke<CookieAnalyzerResult>('analyze_cookies_command', {
				config: {
					url: url.trim(),
					timeout,
					follow_redirects: followRedirects,
					verify_ssl: verifySsl,
					user_agent: null,
					proxy_url: proxyUrl || null,
					check_js_cookies: checkJsCookies,
					check_third_party: checkThirdParty,
					check_compliance: checkCompliance,
					custom_headers: customHeaders || null,
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
			const savePath = await open({ directory: true, multiple: false, title: $tr('cookieAnalyzer.selectSaveDir') });
			if (!savePath) return;
			const ext = exportFormat === 'csv' ? 'csv' : 'json';
			const fileName = `cookie-analysis-${new Date().toISOString().slice(0, 10)}.${ext}`;
			let content: string;
			if (exportFormat === 'csv') {
				const header = 'Name,Category,Risk,HttpOnly,Secure,SameSite,Domain,Path,Session,ThirdParty';
				const rows = result.cookies.map(c =>
					`"${c.name}","${c.cookie_category}","${c.risk_level}","${c.http_only}","${c.secure}","${c.same_site || 'None'}","${c.domain || '-'}","${c.path || '-'}","${c.is_session}","${c.is_third_party}"`
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
		issueFilter = 'all'; cookieFilter = 'all';
		searchQuery = ''; activeResultTab = 'overview';
		selectedIssue = null;
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
			<h1 class="page-title">🍪 {$tr('cookieAnalyzer.title')}</h1>
			<p class="page-subtitle">{$tr('cookieAnalyzer.subtitle')}</p>
		</div>
	</div>

	<div class="tabs">
		<button class="tab-btn {activeMainTab === 'analyze' ? 'active' : ''}" onclick={() => activeMainTab = 'analyze'}>
			<span class="tab-icon">🔍</span> {$tr('cookieAnalyzer.tabAnalyze')}
		</button>
		<button class="tab-btn {activeMainTab === 'history' ? 'active' : ''}" onclick={() => activeMainTab = 'history'}>
			<span class="tab-icon">📋</span> {$tr('cookieAnalyzer.tabHistory')}
		</button>
		<button class="tab-btn {activeMainTab === 'help' ? 'active' : ''}" onclick={() => activeMainTab = 'help'}>
			<span class="tab-icon">📖</span> {$tr('cookieAnalyzer.tabHelp')}
		</button>
	</div>

	{#if activeMainTab === 'analyze'}
		<div class="content-grid">
			<div class="input-section">
				<div class="section-card">
					<h2 class="section-title">{$tr('cookieAnalyzer.configTitle')}</h2>
					<p class="section-desc">{$tr('cookieAnalyzer.configDesc')}</p>

					<div class="form-group">
						<label class="form-label">{$tr('cookieAnalyzer.targetUrl')}</label>
						<input type="text" bind:value={url} placeholder="https://example.com" class="form-input" disabled={processing} />
					</div>

					<div class="form-row">
						<div class="form-group">
							<label class="form-label">{$tr('cookieAnalyzer.timeout')}</label>
							<input type="number" bind:value={timeout} class="form-input" min="5" max="120" disabled={processing} />
						</div>
					</div>

					<div class="form-group">
						<label class="form-label">{$tr('cookieAnalyzer.scanOptions')}</label>
						<div class="target-grid">
							<label class="target-chip {checkJsCookies ? 'active' : ''}">
								<input type="checkbox" bind:checked={checkJsCookies} disabled={processing} />
								<span>📜 {$tr('cookieAnalyzer.jsCookies')}</span>
							</label>
							<label class="target-chip {checkThirdParty ? 'active' : ''}">
								<input type="checkbox" bind:checked={checkThirdParty} disabled={processing} />
								<span>🌐 {$tr('cookieAnalyzer.thirdParty')}</span>
							</label>
							<label class="target-chip {checkCompliance ? 'active' : ''}">
								<input type="checkbox" bind:checked={checkCompliance} disabled={processing} />
								<span>📋 {$tr('cookieAnalyzer.compliance')}</span>
							</label>
							<label class="target-chip {followRedirects ? 'active' : ''}">
								<input type="checkbox" bind:checked={followRedirects} disabled={processing} />
								<span>🔀 {$tr('cookieAnalyzer.followRedirects')}</span>
							</label>
						</div>
					</div>

					<div class="form-group">
						<button class="target-chip {showAdvanced ? 'active' : ''}" onclick={() => showAdvanced = !showAdvanced}>
							<span>⚙️ {$tr('cookieAnalyzer.advancedOptions')}</span>
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
								<span>🔒 {$tr('cookieAnalyzer.verifySsl')}</span>
							</label>
						</div>
						<div class="form-group">
							<label class="form-label">📋 {$tr('cookieAnalyzer.customHeaders')}</label>
							<textarea bind:value={customHeaders} placeholder="Authorization: Bearer token&#10;X-API-Key: your-key" class="form-input" style="height: 60px; resize: vertical; font-family: monospace; font-size: 12px;" disabled={processing}></textarea>
						</div>
					{/if}

					<div class="button-group">
						<button class="btn-primary" onclick={analyze} disabled={processing || !url.trim()}>
							{#if processing}<span class="spinner"></span>{$tr('cookieAnalyzer.analyzing')}{:else}🔍 {$tr('cookieAnalyzer.startAnalyze')}{/if}
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
								<h2 class="section-title" style="margin-bottom:0">🍪 {result.url}</h2>
							</div>
							<div class="header-actions">
								<div class="score-badge" style="border-color: {getGradeColor(result.grade)}40; background: {getGradeColor(result.grade)}10;">
									<span class="score-grade" style="color: {getGradeColor(result.grade)}">{result.grade}</span>
									<span class="score-number">{result.score}/100</span>
								</div>
								<div class="resource-score-badge">
									<span class="score-value">{result.cookies.length}</span>
									<span class="score-label">{$tr('cookieAnalyzer.cookiesFound')}</span>
								</div>
								<select bind:value={exportFormat} class="export-select">
									<option value="json">JSON</option>
									<option value="csv">CSV</option>
								</select>
								<button class="btn-export" onclick={exportResults} disabled={!result}>
									📤 {$tr('cookieAnalyzer.export')}
								</button>
							</div>
						</div>

						<div class="summary-bar">{result.summary}</div>

						<div class="result-tabs">
							<button class="result-tab {activeResultTab === 'overview' ? 'active' : ''}" onclick={() => activeResultTab = 'overview'}>
								📊 {$tr('cookieAnalyzer.tabOverview')}
							</button>
							<button class="result-tab {activeResultTab === 'issues' ? 'active' : ''}" onclick={() => activeResultTab = 'issues'}>
								⚠️ {$tr('cookieAnalyzer.tabIssues')} ({result.issues.length})
							</button>
							<button class="result-tab {activeResultTab === 'cookies' ? 'active' : ''}" onclick={() => activeResultTab = 'cookies'}>
								🍪 {$tr('cookieAnalyzer.tabCookies')} ({result.cookies.length})
							</button>
							<button class="result-tab {activeResultTab === 'compliance' ? 'active' : ''}" onclick={() => activeResultTab = 'compliance'}>
								📋 {$tr('cookieAnalyzer.tabCompliance')}
							</button>
							<button class="result-tab {activeResultTab === 'headers' ? 'active' : ''}" onclick={() => activeResultTab = 'headers'}>
								🔒 {$tr('cookieAnalyzer.tabHeaders')}
							</button>
						</div>

						{#if activeResultTab === 'overview'}
							<div class="overview-grid">
								<div class="overview-stat">
									<span class="stat-label">🍪 {$tr('cookieAnalyzer.cookiesFound')}</span>
									<span class="stat-value">{result.cookies.length}</span>
								</div>
								<div class="overview-stat">
									<span class="stat-label">⚠️ {$tr('cookieAnalyzer.issuesFound')}</span>
									<span class="stat-value" style="color: {result.issues.length > 0 ? '#f97316' : '#22c55e'}">{result.issues.length}</span>
								</div>
								<div class="overview-stat">
									<span class="stat-label">🔒 {$tr('cookieAnalyzer.securityHeaders')}</span>
									<span class="stat-value" style="color: {result.response_headers.security_headers_score >= 75 ? '#22c55e' : result.response_headers.security_headers_score >= 50 ? '#eab308' : '#ef4444'}">{result.response_headers.security_headers_score}%</span>
								</div>
								<div class="overview-stat">
									<span class="stat-label">⏱️ {$tr('cookieAnalyzer.scanDuration')}</span>
									<span class="stat-value">{result.scan_duration_ms < 1000 ? result.scan_duration_ms + 'ms' : (result.scan_duration_ms / 1000).toFixed(1) + 's'}</span>
								</div>
							</div>

							<h3 class="subsection-title">📊 {$tr('cookieAnalyzer.severityDistribution')}</h3>
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
											<div class="severity-bar-fill" style="width: {result.issues.length > 0 ? (item.count / result.issues.length * 100) : 0}%; background: {getSeverityColor(item.key)};"></div>
										</div>
									</div>
								{/each}
							</div>

							{#if result.cookies.length > 0}
								<h3 class="subsection-title">🍪 {$tr('cookieAnalyzer.cookieCategories')}</h3>
								<div class="category-grid">
									{#each Object.entries(result.cookies.reduce((acc: Record<string, number>, c) => { acc[c.cookie_category] = (acc[c.cookie_category] || 0) + 1; return acc; }, {})) as [cat, count]}
										<div class="category-card">
											<div class="category-header">
												<span class="category-icon">{getCookieCategoryIcon(cat)}</span>
												<span class="category-name">{cat}</span>
												<span class="category-count">{count}</span>
											</div>
											<div class="category-bar-bg">
												<div class="category-bar-fill" style="width: {count / result.cookies.length * 100}%; background: #a855f7;"></div>
											</div>
										</div>
									{/each}
								</div>
							{/if}

							{#if result.issues.length > 0}
								<h3 class="subsection-title">⚠️ {$tr('cookieAnalyzer.topIssues')}</h3>
								<div class="top-issues-list">
									{#each result.issues.slice(0, 5) as issue}
										<div class="top-issue-item" onclick={() => { selectedIssue = issue; activeResultTab = 'issues'; }}>
											<span class="severity-dot" style="background: {getSeverityColor(issue.severity)};"></span>
											<span class="issue-type-label">{getCategoryIcon(issue.category)} {issue.issue_type}</span>
											<span class="issue-cookie-mini">🍪 {issue.cookie_name}</span>
										</div>
									{/each}
									{#if result.issues.length > 5}
										<div class="more-link" onclick={() => activeResultTab = 'issues'}>
											{$tr('cookieAnalyzer.viewAll')} ({result.issues.length}) →
										</div>
									{/if}
								</div>
							{:else}
								<div class="empty-state">
									<div class="empty-icon">✅</div>
									<p>{$tr('cookieAnalyzer.noIssues')}</p>
								</div>
							{/if}

						{:else if activeResultTab === 'issues'}
							<div class="filter-bar">
								<button class="filter-btn {issueFilter === 'all' ? 'active' : ''}" onclick={() => issueFilter = 'all'}>
									{$tr('cookieAnalyzer.all')} ({result.issues.length})
								</button>
								<button class="filter-btn {issueFilter === 'critical' ? 'active' : ''}" onclick={() => issueFilter = 'critical'}>
									🔴 Critical ({result.severity_stats.critical})
								</button>
								<button class="filter-btn {issueFilter === 'high' ? 'active' : ''}" onclick={() => issueFilter = 'high'}>
									🟠 High ({result.severity_stats.high})
								</button>
								<button class="filter-btn {issueFilter === 'medium' ? 'active' : ''}" onclick={() => issueFilter = 'medium'}>
									🟡 Medium ({result.severity_stats.medium})
								</button>
								<button class="filter-btn {issueFilter === 'low' ? 'active' : ''}" onclick={() => issueFilter = 'low'}>
									🟢 Low ({result.severity_stats.low})
								</button>
							</div>

							<div class="search-bar">
								<input type="text" bind:value={searchQuery} placeholder="{$tr('cookieAnalyzer.searchPlaceholder')}" class="search-input" />
							</div>

							{#if getFilteredIssues().length > 0}
								<div class="links-table-wrapper">
									<table class="data-table">
										<thead>
											<tr>
												<th>{$tr('cookieAnalyzer.severity')}</th>
												<th>{$tr('cookieAnalyzer.issueType')}</th>
												<th>Cookie</th>
												<th>{$tr('cookieAnalyzer.category')}</th>
												<th>{$tr('cookieAnalyzer.description')}</th>
												<th>CWE</th>
											</tr>
										</thead>
										<tbody>
											{#each getFilteredIssues().slice(0, 100) as issue}
												<tr>
													<td>
														<span class="severity-badge" style="background: {getSeverityColor(issue.severity)}15; color: {getSeverityColor(issue.severity)}; border: 1px solid {getSeverityColor(issue.severity)}40">
															{getSeverityIcon(issue.severity)} {issue.severity.toUpperCase()}
														</span>
													</td>
													<td class="issue-type-cell">{issue.issue_type}</td>
													<td>
														<span class="cookie-name-cell">🍪 {issue.cookie_name}</span>
													</td>
													<td>
														<span class="category-chip">{getCategoryIcon(issue.category)} {issue.category}</span>
													</td>
													<td class="issue-desc-cell">
														<div class="desc-text">{issue.description}</div>
														<div class="rec-text">💡 {issue.recommendation}</div>
													</td>
													<td>
														{#if issue.cwe_id}
															<span class="cwe-badge">{issue.cwe_id}</span>
														{:else}
															-
														{/if}
													</td>
												</tr>
											{/each}
										</tbody>
									</table>
								</div>
							{:else}
								<div class="empty-state">
									<div class="empty-icon">🔍</div>
									<p>{$tr('cookieAnalyzer.noMatchingResults')}</p>
								</div>
							{/if}

						{:else if activeResultTab === 'cookies'}
							<div class="filter-bar">
								<button class="filter-btn {cookieFilter === 'all' ? 'active' : ''}" onclick={() => cookieFilter = 'all'}>
									{$tr('cookieAnalyzer.all')} ({result.cookies.length})
								</button>
								<button class="filter-btn {cookieFilter === 'insecure' ? 'active' : ''}" onclick={() => cookieFilter = 'insecure'}>
									⚠️ {$tr('cookieAnalyzer.insecure')} ({result.cookies.filter(c => !c.secure || !c.http_only).length})
								</button>
								<button class="filter-btn {cookieFilter === 'session' ? 'active' : ''}" onclick={() => cookieFilter = 'session'}>
									⏰ {$tr('cookieAnalyzer.session')} ({result.cookies.filter(c => c.is_session).length})
								</button>
								<button class="filter-btn {cookieFilter === 'third_party' ? 'active' : ''}" onclick={() => cookieFilter = 'third_party'}>
									🌐 {$tr('cookieAnalyzer.thirdParty')} ({result.cookies.filter(c => c.is_third_party).length})
								</button>
							</div>

							<div class="search-bar">
								<input type="text" bind:value={searchQuery} placeholder="{$tr('cookieAnalyzer.searchCookiePlaceholder')}" class="search-input" />
							</div>

							{#if getFilteredCookies().length > 0}
								<div class="links-table-wrapper">
									<table class="data-table">
										<thead>
											<tr>
												<th>Name</th>
												<th>{$tr('cookieAnalyzer.category')}</th>
												<th>{$tr('cookieAnalyzer.risk')}</th>
												<th>Flags</th>
												<th>Domain</th>
												<th>SameSite</th>
												<th>{$tr('cookieAnalyzer.expiry')}</th>
											</tr>
										</thead>
										<tbody>
											{#each getFilteredCookies() as cookie}
												<tr>
													<td>
														<div class="cookie-name-cell">
															<span>{getCookieCategoryIcon(cookie.cookie_category)} {cookie.name}</span>
															{#if cookie.is_third_party}<span class="third-party-tag">3rd</span>{/if}
														</div>
													</td>
													<td>
														<span class="category-chip">{cookie.cookie_category}</span>
													</td>
													<td>
														<span class="severity-badge" style="background: {getSeverityColor(cookie.risk_level)}15; color: {getSeverityColor(cookie.risk_level)}; border: 1px solid {getSeverityColor(cookie.risk_level)}40">
															{cookie.risk_level.toUpperCase()}
														</span>
													</td>
													<td>
														<div class="flags-cell">
															<span class="flag {cookie.http_only ? 'good' : 'bad'}">H</span>
															<span class="flag {cookie.secure ? 'good' : 'bad'}">S</span>
															<span class="flag {cookie.same_site ? 'good' : 'warn'}">SS</span>
														</div>
													</td>
													<td class="mono">{cookie.domain || '-'}</td>
													<td>
														<span class="samesite-badge">{cookie.same_site || 'None'}</span>
													</td>
													<td>
														{#if cookie.is_session}
															<span class="session-badge">{$tr('cookieAnalyzer.sessionCookie')}</span>
														{:else}
															<span class="expiry-text">{cookie.expires || '-'}</span>
														{/if}
													</td>
												</tr>
											{/each}
										</tbody>
									</table>
								</div>
							{:else}
								<div class="empty-state">
									<div class="empty-icon">🍪</div>
									<p>{$tr('cookieAnalyzer.noMatchingResults')}</p>
								</div>
							{/if}

						{:else if activeResultTab === 'compliance'}
							<div class="compliance-grid">
								<div class="compliance-card {result.compliance_report.gdpr_compliant ? 'pass' : 'fail'}">
									<div class="compliance-header">
										<span class="compliance-icon">{result.compliance_report.gdpr_compliant ? '✅' : '❌'}</span>
										<span class="compliance-name">GDPR</span>
									</div>
									<div class="compliance-status">{result.compliance_report.gdpr_compliant ? $tr('cookieAnalyzer.compliant') : $tr('cookieAnalyzer.nonCompliant')}</div>
									{#if result.compliance_report.gdpr_issues.length > 0}
										<div class="compliance-issues">
											{#each result.compliance_report.gdpr_issues as issue}
												<div class="compliance-issue-item">• {issue}</div>
											{/each}
										</div>
									{/if}
								</div>
								<div class="compliance-card {result.compliance_report.pci_dss_compliant ? 'pass' : 'fail'}">
									<div class="compliance-header">
										<span class="compliance-icon">{result.compliance_report.pci_dss_compliant ? '✅' : '❌'}</span>
										<span class="compliance-name">PCI DSS</span>
									</div>
									<div class="compliance-status">{result.compliance_report.pci_dss_compliant ? $tr('cookieAnalyzer.compliant') : $tr('cookieAnalyzer.nonCompliant')}</div>
									{#if result.compliance_report.pci_dss_issues.length > 0}
										<div class="compliance-issues">
											{#each result.compliance_report.pci_dss_issues as issue}
												<div class="compliance-issue-item">• {issue}</div>
											{/each}
										</div>
									{/if}
								</div>
								<div class="compliance-card {result.compliance_report.owasp_compliant ? 'pass' : 'fail'}">
									<div class="compliance-header">
										<span class="compliance-icon">{result.compliance_report.owasp_compliant ? '✅' : '❌'}</span>
										<span class="compliance-name">OWASP</span>
									</div>
									<div class="compliance-status">{result.compliance_report.owasp_compliant ? $tr('cookieAnalyzer.compliant') : $tr('cookieAnalyzer.nonCompliant')}</div>
									{#if result.compliance_report.owasp_issues.length > 0}
										<div class="compliance-issues">
											{#each result.compliance_report.owasp_issues as issue}
												<div class="compliance-issue-item">• {issue}</div>
											{/each}
										</div>
									{/if}
								</div>
							</div>
							<div class="compliance-score-section">
								<span class="compliance-score-label">{$tr('cookieAnalyzer.overallComplianceScore')}</span>
								<span class="compliance-score-value" style="color: {result.compliance_report.overall_compliance_score >= 80 ? '#22c55e' : result.compliance_report.overall_compliance_score >= 50 ? '#eab308' : '#ef4444'}">{result.compliance_report.overall_compliance_score}/100</span>
							</div>

						{:else if activeResultTab === 'headers'}
							<div class="headers-grid">
								{#each [
									{ name: 'Strict-Transport-Security', present: result.response_headers.has_strict_transport, icon: '🔒' },
									{ name: 'X-Content-Type-Options', present: result.response_headers.has_x_content_type_options, icon: '🛡️' },
									{ name: 'X-Frame-Options', present: result.response_headers.has_x_frame_options, icon: '🖼️' },
									{ name: 'Content-Security-Policy', present: result.response_headers.has_csp, icon: '📋' },
								] as header}
									<div class="header-card {header.present ? 'present' : 'missing'}">
										<div class="header-status">{header.present ? '✅' : '❌'}</div>
										<div class="header-name">{header.icon} {header.name}</div>
										<div class="header-label">{header.present ? $tr('cookieAnalyzer.present') : $tr('cookieAnalyzer.missing')}</div>
									</div>
								{/each}
							</div>
							<div class="headers-score-section">
								<span class="headers-score-label">{$tr('cookieAnalyzer.securityHeadersScore')}</span>
								<span class="headers-score-value" style="color: {result.response_headers.security_headers_score >= 75 ? '#22c55e' : result.response_headers.security_headers_score >= 50 ? '#eab308' : '#ef4444'}">{result.response_headers.security_headers_score}%</span>
							</div>
							{#if result.response_headers.server_header || result.response_headers.x_powered_by}
								<div class="info-section">
									<h3 class="subsection-title">ℹ️ {$tr('cookieAnalyzer.serverInfo')}</h3>
									{#if result.response_headers.server_header}
										<div class="info-row"><span class="info-label">Server:</span> <code>{result.response_headers.server_header}</code></div>
									{/if}
									{#if result.response_headers.x_powered_by}
										<div class="info-row"><span class="info-label">X-Powered-By:</span> <code>{result.response_headers.x_powered_by}</code></div>
									{/if}
								</div>
							{/if}
						{/if}

					{:else}
						<div class="empty-state">
							<div class="empty-icon">🍪</div>
							<p>{$tr('cookieAnalyzer.emptyState')}</p>
						</div>
					{/if}
				</div>
			</div>
		</div>
	{:else if activeMainTab === 'history'}
		<div class="section-card">
			<ToolHistory toolType="cookie_analyzer" toolName={$tr('cookieAnalyzer.title')} bind:this={historyComponent} />
		</div>
	{:else if activeMainTab === 'help'}
		<div class="section-card">
			<ToolHelp toolType="cookie_analyzer" />
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

	.target-chip:hover:not(.active) { border-color: rgba(148, 163, 184, 0.3); }

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

	.btn-primary:disabled { opacity: 0.5; cursor: not-allowed; transform: none; box-shadow: none; }

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

	.btn-secondary:hover:not(:disabled) { background: rgba(148, 163, 184, 0.2); color: #e2e8f0; }
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

	.score-badge {
		display: flex;
		flex-direction: column;
		align-items: center;
		padding: 0.5rem 1rem;
		border-radius: 0.5rem;
		border: 1px solid;
	}

	.score-grade {
		font-size: 1.5rem;
		font-weight: 700;
		line-height: 1;
	}

	.score-number {
		font-size: 0.65rem;
		opacity: 0.8;
		margin-top: 0.2rem;
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

	.btn-export:hover:not(:disabled) { background: rgba(34, 197, 94, 0.2); border-color: rgba(34, 197, 94, 0.5); }
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

	.result-tab:hover:not(.active) { border-color: rgba(168, 85, 247, 0.3); color: #c4b5fd; }

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

	.severity-label { font-size: 0.7rem; color: #94a3b8; }
	.severity-count { font-size: 1.2rem; font-weight: 700; }

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
	.category-name { flex: 1; font-size: 0.8rem; color: #e2e8f0; font-weight: 500; }
	.category-count { font-size: 1rem; font-weight: 700; color: #a855f7; }

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

	.top-issues-list {
		display: flex;
		flex-direction: column;
		gap: 0.35rem;
	}

	.top-issue-item {
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

	.top-issue-item:hover {
		background: rgba(168, 85, 247, 0.05);
		border-color: rgba(168, 85, 247, 0.15);
	}

	.severity-dot {
		width: 8px;
		height: 8px;
		border-radius: 50%;
		flex-shrink: 0;
	}

	.issue-type-label {
		font-size: 0.78rem;
		color: #cbd5e1;
		white-space: nowrap;
	}

	.issue-cookie-mini {
		font-size: 0.72rem;
		color: #94a3b8;
		flex: 1;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
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

	.filter-btn:hover:not(.active) { border-color: rgba(148, 163, 184, 0.3); }

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

	.search-input:focus { outline: none; border-color: #a855f7; }
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

	.issue-type-cell { font-weight: 500; color: #e2e8f0; font-size: 0.78rem; }
	.cookie-name-cell { font-weight: 500; color: #e2e8f0; font-size: 0.78rem; display: flex; align-items: center; gap: 0.3rem; }

	.third-party-tag {
		font-size: 0.6rem;
		padding: 0.1rem 0.3rem;
		border-radius: 0.2rem;
		background: rgba(59, 130, 246, 0.15);
		color: #3b82f6;
		font-weight: 600;
	}

	.issue-desc-cell { max-width: 300px; }
	.desc-text { font-size: 0.75rem; color: #cbd5e1; margin-bottom: 0.2rem; }
	.rec-text { font-size: 0.7rem; color: #22c55e; }

	.cwe-badge {
		display: inline-block;
		padding: 0.1rem 0.35rem;
		border-radius: 0.2rem;
		background: rgba(168, 85, 247, 0.1);
		color: #a855f7;
		font-size: 0.68rem;
		font-family: 'SF Mono', 'Fira Code', monospace;
	}

	.flags-cell {
		display: flex;
		gap: 0.2rem;
	}

	.flag {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		width: 1.4rem;
		height: 1.1rem;
		border-radius: 0.2rem;
		font-size: 0.6rem;
		font-weight: 700;
	}

	.flag.good { background: rgba(34, 197, 94, 0.15); color: #22c55e; }
	.flag.bad { background: rgba(239, 68, 68, 0.15); color: #ef4444; }
	.flag.warn { background: rgba(234, 179, 8, 0.15); color: #eab308; }

	.samesite-badge {
		display: inline-block;
		padding: 0.1rem 0.35rem;
		border-radius: 0.2rem;
		background: rgba(148, 163, 184, 0.1);
		font-size: 0.7rem;
		color: #94a3b8;
	}

	.session-badge {
		display: inline-block;
		padding: 0.1rem 0.35rem;
		border-radius: 0.2rem;
		background: rgba(234, 179, 8, 0.1);
		color: #eab308;
		font-size: 0.7rem;
	}

	.expiry-text { font-size: 0.72rem; color: #94a3b8; }

	.compliance-grid {
		display: grid;
		grid-template-columns: repeat(3, 1fr);
		gap: 0.75rem;
		margin-bottom: 1rem;
	}

	.compliance-card {
		padding: 1rem;
		border-radius: 0.5rem;
		border: 1px solid;
	}

	.compliance-card.pass {
		border-color: rgba(34, 197, 94, 0.3);
		background: rgba(34, 197, 94, 0.05);
	}

	.compliance-card.fail {
		border-color: rgba(239, 68, 68, 0.3);
		background: rgba(239, 68, 68, 0.05);
	}

	.compliance-header {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		margin-bottom: 0.5rem;
	}

	.compliance-icon { font-size: 1.2rem; }
	.compliance-name { font-size: 1rem; font-weight: 600; color: #f1f5f9; }

	.compliance-status {
		font-size: 0.8rem;
		margin-bottom: 0.5rem;
	}

	.compliance-card.pass .compliance-status { color: #22c55e; }
	.compliance-card.fail .compliance-status { color: #ef4444; }

	.compliance-issues {
		display: flex;
		flex-direction: column;
		gap: 0.25rem;
	}

	.compliance-issue-item {
		font-size: 0.72rem;
		color: #94a3b8;
		line-height: 1.4;
	}

	.compliance-score-section {
		display: flex;
		align-items: center;
		justify-content: center;
		gap: 1rem;
		padding: 1rem;
		background: rgba(15, 23, 42, 0.4);
		border-radius: 0.5rem;
		border: 1px solid rgba(148, 163, 184, 0.08);
	}

	.compliance-score-label { font-size: 0.9rem; color: #94a3b8; }
	.compliance-score-value { font-size: 1.5rem; font-weight: 700; }

	.headers-grid {
		display: grid;
		grid-template-columns: repeat(2, 1fr);
		gap: 0.5rem;
		margin-bottom: 1rem;
	}

	.header-card {
		padding: 0.75rem;
		border-radius: 0.5rem;
		border: 1px solid;
		display: flex;
		align-items: center;
		gap: 0.75rem;
	}

	.header-card.present {
		border-color: rgba(34, 197, 94, 0.3);
		background: rgba(34, 197, 94, 0.05);
	}

	.header-card.missing {
		border-color: rgba(239, 68, 68, 0.3);
		background: rgba(239, 68, 68, 0.05);
	}

	.header-status { font-size: 1.2rem; }
	.header-name { font-size: 0.8rem; font-weight: 500; color: #e2e8f0; }
	.header-label { font-size: 0.7rem; color: #94a3b8; }

	.header-card.present .header-label { color: #22c55e; }
	.header-card.missing .header-label { color: #ef4444; }

	.headers-score-section {
		display: flex;
		align-items: center;
		justify-content: center;
		gap: 1rem;
		padding: 1rem;
		background: rgba(15, 23, 42, 0.4);
		border-radius: 0.5rem;
		border: 1px solid rgba(148, 163, 184, 0.08);
		margin-bottom: 1rem;
	}

	.headers-score-label { font-size: 0.9rem; color: #94a3b8; }
	.headers-score-value { font-size: 1.5rem; font-weight: 700; }

	.info-section {
		padding: 0.75rem;
		background: rgba(15, 23, 42, 0.4);
		border-radius: 0.5rem;
		border: 1px solid rgba(148, 163, 184, 0.08);
	}

	.info-row {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		font-size: 0.8rem;
		color: #cbd5e1;
		margin-bottom: 0.3rem;
	}

	.info-label { color: #94a3b8; font-weight: 500; }
	.info-row code { font-family: 'SF Mono', 'Fira Code', monospace; font-size: 0.75rem; color: #a855f7; }

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
		.content-grid { grid-template-columns: 1fr; }
		.overview-grid { grid-template-columns: repeat(2, 1fr); }
		.severity-grid { grid-template-columns: repeat(3, 1fr); }
		.category-grid { grid-template-columns: repeat(2, 1fr); }
		.compliance-grid { grid-template-columns: 1fr; }
		.headers-grid { grid-template-columns: 1fr; }
	}
</style>
