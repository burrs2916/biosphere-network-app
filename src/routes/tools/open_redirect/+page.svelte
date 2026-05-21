<script lang="ts">
	import { tr } from '$lib/i18n';
	import ToolHistory from '$lib/components/ToolHistory.svelte';
	import ToolHelp from '$lib/components/ToolHelp.svelte';

	interface OpenRedirectVuln {
		parameter: string;
		payload: string;
		payload_type: string;
		severity: string;
		redirect_to: string;
		http_status: number | null;
		confidence: number;
		description: string;
		detail: string;
		recommendation: string;
		is_redirect_chain: boolean;
		is_body_based: boolean;
	}

	interface OpenRedirectResult {
		url: string;
		is_vulnerable: boolean;
		severity: string;
		security_score: number;
		vulnerabilities: OpenRedirectVuln[];
		tests_performed: number;
		scan_duration_ms: number;
		summary: string;
	}

	let url = $state('');
	let timeout = $state(15);
	let threads = $state(5);
	let scanLevel = $state('moderate');
	let customParams = $state('');
	let customPayloads = $state('');
	let followRedirects = $state(false);
	let analyzeBody = $state(false);
	let result: OpenRedirectResult | null = $state(null);
	let error = $state('');
	let processing = $state(false);
	let activeMainTab = $state('analyze');
	let activeResultTab = $state('overview');
	let searchQuery = $state('');
	let severityFilter = $state('all');
	let exportFormat = $state('json');

	const TOOL_NAME = 'open_redirect';
	let historyComponent = $state<ToolHistory>();

	function getScanLevelLabel(level: string): string {
		const labels: Record<string, string> = {
			basic: $tr('openRedirect.levelBasic'),
			moderate: $tr('openRedirect.levelModerate'),
			aggressive: $tr('openRedirect.levelAggressive')
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

	function getFilteredVulns() {
		return result?.vulnerabilities.filter(v => {
			if (severityFilter !== 'all' && v.severity !== severityFilter) return false;
			if (searchQuery) {
				const q = searchQuery.toLowerCase();
				return v.parameter.toLowerCase().includes(q) ||
					v.payload.toLowerCase().includes(q) ||
					v.description.toLowerCase().includes(q) ||
					v.redirect_to.toLowerCase().includes(q);
			}
			return true;
		}) || [];
	}

	function getPayloadTypeChartData() {
		if (!result || !result.vulnerabilities.length) return [];
		const types = [...new Set(result.vulnerabilities.map(v => v.payload_type))];
		const maxCount = Math.max(...types.map(t => result!.vulnerabilities.filter(v => v.payload_type === t).length));
		return types.map(t => ({
			payload_type: t,
			count: result!.vulnerabilities.filter(v => v.payload_type === t).length,
			percent: maxCount > 0 ? (result!.vulnerabilities.filter(v => v.payload_type === t).length / maxCount) * 100 : 0
		}));
	}

	async function check() {
		if (!url.trim()) {
			error = $tr('openRedirect.urlRequired');
			return;
		}
		processing = true;
		error = '';
		result = null;
		activeResultTab = 'overview';

		try {
			const { invoke } = await import('@tauri-apps/api/core');
			const test_params = customParams.trim()
				? customParams.split(/[,，\n;]+/).map(p => p.trim()).filter(p => p.length > 0)
				: [];
			const test_payloads = customPayloads.trim()
				? customPayloads.split(/[,，\n;]+/).map(p => p.trim()).filter(p => p.length > 0)
				: [];

			result = await invoke<OpenRedirectResult>('check_open_redirect_command', {
				config: {
					url: url.trim(),
					timeout,
					threads,
					scan_level: scanLevel,
					test_params,
					test_payloads,
					follow_redirects: followRedirects,
					analyze_body: analyzeBody
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
				defaultPath: `open_redirect_${Date.now()}.${exportFormat}`,
				filters: [{ name: exportFormat.toUpperCase(), extensions: [exportFormat] }]
			});
			if (!path) return;

			let content: string;
			if (exportFormat === 'json') {
				content = JSON.stringify(result, null, 2);
			} else {
				const headers = ['Parameter', 'Payload', 'Payload Type', 'Severity', 'Redirect To', 'HTTP Status', 'Confidence', 'Description', 'Recommendation'];
				const rows = result.vulnerabilities.map(v =>
					[v.parameter, v.payload, v.payload_type, v.severity, v.redirect_to, (v.http_status || 0).toString(), v.confidence.toString(), v.description, v.recommendation]
				);
				content = [headers, ...rows].map(r => r.map(c => `"${c.replace(/"/g, '""')}"`).join(',')).join('\n');
			}
			await writeTextFile(path as string, content);
		} catch {}
	}

	function clearAll() {
		url = '';
		customParams = '';
		customPayloads = '';
		result = null;
		error = '';
		scanLevel = 'moderate';
		followRedirects = false;
		analyzeBody = false;
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
			<h1 class="page-title">↪️ {$tr('openRedirect.title')}</h1>
			<p class="page-subtitle">{$tr('openRedirect.subtitle')}</p>
		</div>
	</div>

	<div class="tabs">
		<button class="tab-btn {activeMainTab === 'analyze' ? 'active' : ''}" onclick={() => activeMainTab = 'analyze'}>
			<span class="tab-icon">🔍</span> {$tr('openRedirect.check')}
		</button>
		<button class="tab-btn {activeMainTab === 'history' ? 'active' : ''}" onclick={() => activeMainTab = 'history'}>
			<span class="tab-icon">📋</span> {$tr('openRedirect.history')}
		</button>
		<button class="tab-btn {activeMainTab === 'help' ? 'active' : ''}" onclick={() => activeMainTab = 'help'}>
			<span class="tab-icon">📖</span> {$tr('openRedirect.help')}
		</button>
	</div>

	{#if activeMainTab === 'analyze'}
		<div class="content-grid">
			<div class="input-section">
				<div class="section-card">
					<h2 class="section-title">{$tr('openRedirect.configTitle')}</h2>
					<p class="section-desc">{$tr('openRedirect.configDesc')}</p>

					<div class="form-group">
						<label class="form-label">{$tr('openRedirect.targetUrl')}</label>
						<input type="text" bind:value={url} placeholder="https://example.com/page?param=value" class="form-input" disabled={processing} onkeydown={(e) => e.key === 'Enter' && check()} />
					</div>

					<div class="form-group">
						<label class="form-label">{$tr('openRedirect.scanLevel')}</label>
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
							<label class="form-label">⏱️ {$tr('openRedirect.timeout')}</label>
							<input type="number" bind:value={timeout} class="form-input" min="5" max="60" disabled={processing} />
						</div>
						<div class="form-group">
							<label class="form-label">🔀 {$tr('openRedirect.threads')}</label>
							<input type="number" bind:value={threads} class="form-input" min="1" max="20" disabled={processing} />
						</div>
					</div>

					<div class="form-group">
						<label class="form-label">{$tr('openRedirect.testOptions')}</label>
						<div class="target-grid">
							<label class="target-chip {followRedirects ? 'active' : ''}">
								<input type="checkbox" bind:checked={followRedirects} disabled={processing} />
								<span>🔗 {$tr('openRedirect.followRedirects')}</span>
							</label>
							<label class="target-chip {analyzeBody ? 'active' : ''}">
								<input type="checkbox" bind:checked={analyzeBody} disabled={processing} />
								<span>📄 {$tr('openRedirect.analyzeBody')}</span>
							</label>
						</div>
					</div>

					<div class="form-group">
						<label class="form-label">🎯 {$tr('openRedirect.customParams')}</label>
						<textarea bind:value={customParams} placeholder="url&#10;redirect&#10;next" class="form-input" style="height: 50px; resize: vertical;" disabled={processing}></textarea>
					</div>

					<div class="form-group">
						<label class="form-label">💣 {$tr('openRedirect.customPayloads')}</label>
						<textarea bind:value={customPayloads} placeholder="https://evil.com&#10;//evil.com" class="form-input" style="height: 50px; resize: vertical;" disabled={processing}></textarea>
					</div>

					<div class="button-group">
						<button class="btn-primary" onclick={check} disabled={processing || !url.trim()}>
							{#if processing}<span class="spinner"></span>{$tr('openRedirect.checking')}{:else}↪️ {$tr('openRedirect.startCheck')}{/if}
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
								<h2 class="section-title" style="margin-bottom:0">↪️ {result.url}</h2>
							</div>
							<div class="header-actions">
								<div class="score-badge" style="border-color: {getScoreColor(result.security_score)}40; background: {getScoreColor(result.security_score)}15">
									<span class="score-value" style="color: {getScoreColor(result.security_score)}">{Math.round(result.security_score)}</span>
									<span class="score-label" style="color: {getScoreColor(result.security_score)}">/100</span>
								</div>
								<div class="resource-score-badge">
									<span class="score-value">{result.vulnerabilities.length}</span>
									<span class="score-label">{$tr('openRedirect.vulnsFound')}</span>
								</div>
								<select bind:value={exportFormat} class="export-select">
									<option value="json">JSON</option>
									<option value="csv">CSV</option>
								</select>
								<button class="btn-export" onclick={exportResult}>
									📤 {$tr('openRedirect.export')}
								</button>
							</div>
						</div>

						<div class="summary-bar" style="background: {result.is_vulnerable ? 'rgba(239,68,68,0.08)' : 'rgba(34,197,94,0.08)'}; border-color: {result.is_vulnerable ? 'rgba(239,68,68,0.15)' : 'rgba(34,197,94,0.15)'}">
							{#if result.is_vulnerable}⚠️{:else}✅{/if} {result.summary}
						</div>

						<div class="result-tabs">
							<button class="result-tab {activeResultTab === 'overview' ? 'active' : ''}" onclick={() => activeResultTab = 'overview'}>
								📊 {$tr('openRedirect.tabOverview')}
							</button>
							<button class="result-tab {activeResultTab === 'vulnerabilities' ? 'active' : ''}" onclick={() => activeResultTab = 'vulnerabilities'}>
								🔴 {$tr('openRedirect.tabVulnerabilities')} ({result.vulnerabilities.length})
							</button>
							<button class="result-tab {activeResultTab === 'payloads' ? 'active' : ''}" onclick={() => activeResultTab = 'payloads'}>
								💣 {$tr('openRedirect.tabPayloads')}
							</button>
						</div>

						{#if activeResultTab === 'overview'}
							<div class="overview-grid">
								<div class="overview-stat">
									<span class="stat-label">{$tr('openRedirect.testsPerformed')}</span>
									<span class="stat-value">{result.tests_performed}</span>
								</div>
								<div class="overview-stat">
									<span class="stat-label">🔴 {$tr('openRedirect.criticalIssues')}</span>
									<span class="stat-value" style="color: {result.vulnerabilities.filter(v => v.severity === 'critical').length > 0 ? '#ef4444' : '#64748b'}">{result.vulnerabilities.filter(v => v.severity === 'critical').length}</span>
								</div>
								<div class="overview-stat">
									<span class="stat-label">🟠 {$tr('openRedirect.highIssues')}</span>
									<span class="stat-value" style="color: {result.vulnerabilities.filter(v => v.severity === 'high').length > 0 ? '#f97316' : '#64748b'}">{result.vulnerabilities.filter(v => v.severity === 'high').length}</span>
								</div>
								<div class="overview-stat">
									<span class="stat-label">🟡 {$tr('openRedirect.mediumIssues')}</span>
									<span class="stat-value" style="color: {result.vulnerabilities.filter(v => v.severity === 'medium').length > 0 ? '#f59e0b' : '#64748b'}">{result.vulnerabilities.filter(v => v.severity === 'medium').length}</span>
								</div>
								<div class="overview-stat">
									<span class="stat-label">⏱️ {$tr('openRedirect.scanDuration')}</span>
									<span class="stat-value">{formatDuration(result.scan_duration_ms)}</span>
								</div>
								<div class="overview-stat">
									<span class="stat-label">🛡️ {$tr('openRedirect.securityScore')}</span>
									<span class="stat-value" style="color: {getScoreColor(result.security_score)}">{Math.round(result.security_score)}</span>
								</div>
							</div>

							{#if result.vulnerabilities.length > 0}
								<div class="category-chart">
									<h3 class="subsection-title">{$tr('openRedirect.payloadType')}</h3>
									<div class="chart-bars">
										{#each getPayloadTypeChartData() as data}
											<div class="chart-row">
												<span class="chart-label">{data.payload_type}</span>
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

						{#if activeResultTab === 'vulnerabilities'}
							{#if result.vulnerabilities.length > 0}
								<div class="filter-bar">
									<input type="text" bind:value={searchQuery} placeholder="{$tr('openRedirect.searchVulns')}..." class="filter-input" />
									<select bind:value={severityFilter} class="filter-select">
										<option value="all">{$tr('openRedirect.allSeverities')}</option>
										<option value="critical">🔴 Critical</option>
										<option value="high">🟠 High</option>
										<option value="medium">🟡 Medium</option>
										<option value="low">🟢 Low</option>
									</select>
								</div>

								<div class="vuln-list">
									{#each getFilteredVulns() as vuln}
										<div class="vuln-card">
											<div class="vuln-header">
												<div class="vuln-header-left">
													<span class="severity-badge" style="background: {getSeverityBg(vuln.severity)}; color: {getSeverityColor(vuln.severity)}">
														{vuln.severity.toUpperCase()}
													</span>
													<span class="param-badge">📝 {vuln.parameter}</span>
													<span class="type-badge">{vuln.payload_type}</span>
													{#if vuln.is_body_based}<span class="body-badge">📄</span>{/if}
													{#if vuln.is_redirect_chain}<span class="chain-badge">🔗</span>{/if}
												</div>
												<span class="confidence-badge">
													{$tr('openRedirect.confidence')}: {Math.round(vuln.confidence * 100)}%
												</span>
											</div>
											<div class="vuln-body">
												<div class="vuln-row">
													<span class="row-label">Payload:</span>
													<code class="row-value">{vuln.payload}</code>
												</div>
												<div class="vuln-row">
													<span class="row-label">{$tr('openRedirect.httpStatus')}:</span>
													<span class="row-value">{vuln.http_status || 'N/A'}</span>
												</div>
												<div class="vuln-row">
													<span class="row-label">↪️:</span>
													<code class="row-value redirect-to">{vuln.redirect_to}</code>
												</div>
												<p class="vuln-desc">{vuln.description}</p>
												<p class="vuln-detail">{vuln.detail}</p>
												<p class="vuln-rec">💡 {vuln.recommendation}</p>
											</div>
										</div>
									{/each}
								</div>
							{:else}
								<div class="safe-state">
									<span class="safe-icon">✅</span>
									<span class="safe-text">{$tr('openRedirect.noVulns')}</span>
								</div>
							{/if}
						{/if}

						{#if activeResultTab === 'payloads'}
							{#if result.vulnerabilities.length > 0}
								<div class="payload-grid">
									{#each [...new Set(result.vulnerabilities.map(v => v.payload_type))] as ptype}
										<div class="payload-category">
											<h3 class="category-title">{ptype}</h3>
											<div class="payload-list">
												{#each result.vulnerabilities.filter(v => v.payload_type === ptype) as vuln}
													<div class="payload-item">
														<code class="payload-code">{vuln.payload}</code>
														<span class="payload-severity" style="color: {getSeverityColor(vuln.severity)}">{vuln.severity}</span>
														<span class="payload-param">→ {vuln.parameter}</span>
													</div>
												{/each}
											</div>
										</div>
									{/each}
								</div>
							{:else}
								<div class="empty-state">{$tr('openRedirect.noVulns')}</div>
							{/if}
						{/if}
					{:else if processing}
						<div class="processing-state">
							<span class="processing-icon pulse">↪️</span>
							<span class="processing-text">{$tr('openRedirect.checking')}</span>
							<span class="processing-hint">{$tr('openRedirect.checkHint')}</span>
						</div>
					{:else}
						<div class="empty-state-main">
							<span class="empty-icon">↪️</span>
							<span class="empty-text">{$tr('openRedirect.emptyHint')}</span>
						</div>
					{/if}
				</div>
			</div>
		</div>
	{:else if activeMainTab === 'history'}
		<div class="section-card"><ToolHistory toolType={TOOL_NAME} toolName={$tr('openRedirect.title')} bind:this={historyComponent} /></div>
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

	.overview-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 0.75rem; margin-bottom: 1rem; }
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

	.vuln-list { display: flex; flex-direction: column; gap: 0.75rem; }
	.vuln-card { background: rgba(15, 23, 42, 0.4); border: 1px solid rgba(148, 163, 184, 0.08); border-radius: 0.5rem; padding: 0.75rem; transition: border-color 0.2s; }
	.vuln-card:hover { border-color: rgba(168, 85, 247, 0.3); }
	.vuln-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem; }
	.vuln-header-left { display: flex; align-items: center; gap: 0.4rem; flex-wrap: wrap; }
	.severity-badge { padding: 0.15rem 0.5rem; border-radius: 0.3rem; font-size: 0.7rem; font-weight: 700; }
	.param-badge { padding: 0.15rem 0.4rem; border-radius: 0.3rem; background: rgba(59, 130, 246, 0.15); color: #93c5fd; font-size: 0.7rem; }
	.type-badge { padding: 0.15rem 0.4rem; border-radius: 0.3rem; background: rgba(168, 85, 247, 0.15); color: #c4b5fd; font-size: 0.7rem; }
	.body-badge { padding: 0.15rem 0.4rem; border-radius: 0.3rem; background: rgba(34, 197, 94, 0.15); font-size: 0.7rem; }
	.chain-badge { padding: 0.15rem 0.4rem; border-radius: 0.3rem; background: rgba(249, 115, 22, 0.15); font-size: 0.7rem; }
	.confidence-badge { font-size: 0.75rem; color: #a855f7; font-weight: 600; }
	.vuln-body { display: flex; flex-direction: column; gap: 0.25rem; }
	.vuln-row { display: flex; align-items: baseline; gap: 0.4rem; font-size: 0.8rem; }
	.row-label { color: #64748b; flex-shrink: 0; }
	.row-value { color: #e2e8f0; }
	.row-value.redirect-to { background: rgba(239, 68, 68, 0.1); padding: 0.1rem 0.3rem; border-radius: 0.2rem; font-size: 0.75rem; word-break: break-all; }
	.vuln-desc { font-size: 0.85rem; color: #e2e8f0; margin: 0.25rem 0 0; }
	.vuln-detail { font-size: 0.8rem; color: #94a3b8; margin: 0; }
	.vuln-rec { font-size: 0.8rem; color: #22c55e; margin: 0; }

	.payload-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 1rem; }
	.payload-category { background: rgba(15, 23, 42, 0.4); border: 1px solid rgba(148, 163, 184, 0.08); border-radius: 0.5rem; padding: 0.75rem; }
	.category-title { font-size: 0.85rem; font-weight: 600; color: #c4b5fd; margin: 0 0 0.5rem; }
	.payload-list { display: flex; flex-direction: column; gap: 0.35rem; }
	.payload-item { display: flex; align-items: center; gap: 0.5rem; padding: 0.35rem 0.5rem; background: rgba(15, 23, 42, 0.6); border-radius: 0.3rem; font-size: 0.75rem; }
	.payload-code { color: #e2e8f0; flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
	.payload-severity { font-weight: 600; }
	.payload-param { color: #94a3b8; }

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
	}
</style>
