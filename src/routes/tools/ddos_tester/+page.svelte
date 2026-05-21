<script lang="ts">
	import { tr } from '$lib/i18n';
	import ToolHistory from '$lib/components/ToolHistory.svelte';
	import ToolHelp from '$lib/components/ToolHelp.svelte';

	interface DdosFinding {
		severity: string;
		category: string;
		description: string;
		recommendation: string;
	}

	interface ResponseTimePercentiles {
		p50: number;
		p75: number;
		p90: number;
		p95: number;
		p99: number;
		min: number;
		max: number;
	}

	interface DdosTesterResult {
		success: boolean;
		target: string;
		attack_type: string;
		total_requests: number;
		successful_requests: number;
		failed_requests: number;
		duration_secs: number;
		requests_per_second: number;
		connections_opened: number;
		connections_maintained: number;
		target_response_time_ms: number[];
		response_status_codes: Record<string, number>;
		response_time_percentiles: ResponseTimePercentiles;
		findings: DdosFinding[];
		summary: string;
	}

	let target = $state('');
	let port = $state(80);
	let attackType = $state('slowloris');
	let durationSecs = $state(10);
	let concurrentConnections = $state(100);
	let requestsPerSecond = $state(50);
	let timeout = $state(5);
	let useHttps = $state(false);
	let result: DdosTesterResult | null = $state(null);
	let error = $state('');
	let processing = $state(false);
	let activeMainTab = $state('analyze');
	let activeResultTab = $state('overview');
	let exportFormat = $state('json');
	let exporting = $state(false);

	let historyComponent: ToolHistory = $state(null!);

	let avgResponseTime = $derived.by(() => {
		if (!result || result.target_response_time_ms.length === 0) return 0;
		return Math.round(result.target_response_time_ms.reduce((a: number, b: number) => a + b, 0) / result.target_response_time_ms.length);
	});

	let successRate = $derived.by(() => {
		if (!result || result.total_requests === 0) return '0';
		return ((result.successful_requests / result.total_requests) * 100).toFixed(1);
	});

	let maxResponseTime = $derived.by(() => {
		if (!result || result.target_response_time_ms.length === 0) return 1;
		return Math.max(...result.target_response_time_ms, 1);
	});

	let statusCodeEntries = $derived.by(() => {
		if (!result || !result.response_status_codes) return [];
		return Object.entries(result.response_status_codes).sort((a, b) => b[1] - a[1]);
	});

	let maxStatusCodeCount = $derived.by(() => {
		if (statusCodeEntries.length === 0) return 1;
		return Math.max(...statusCodeEntries.map(([, count]) => count), 1);
	});

	let highFindings = $derived.by(() => {
		if (!result) return [];
		return result.findings.filter(f => f.severity === 'high');
	});

	let mediumFindings = $derived.by(() => {
		if (!result) return [];
		return result.findings.filter(f => f.severity === 'medium');
	});

	let lowFindings = $derived.by(() => {
		if (!result) return [];
		return result.findings.filter(f => f.severity === 'low' || f.severity === 'info');
	});

	function getAttackTypes() {
		return [
			{ value: 'slowloris', icon: '🐢', label: $tr('ddosTester.attackTypes.slowloris'), desc: $tr('ddosTester.attackTypes.slowlorisDesc') },
			{ value: 'http_flood', icon: '🌊', label: $tr('ddosTester.attackTypes.httpFlood'), desc: $tr('ddosTester.attackTypes.httpFloodDesc') },
			{ value: 'slow_post', icon: '📮', label: $tr('ddosTester.attackTypes.slowPost'), desc: $tr('ddosTester.attackTypes.slowPostDesc') },
			{ value: 'tcp_connect', icon: '🔌', label: $tr('ddosTester.attackTypes.tcpConnect'), desc: $tr('ddosTester.attackTypes.tcpConnectDesc') },
		];
	}

	async function startTest() {
		if (!target.trim()) {
			error = $tr('ddosTester.target');
			return;
		}
		processing = true;
		error = '';
		result = null;
		activeResultTab = 'overview';
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			result = await invoke<DdosTesterResult>('test_ddos_command', {
				config: {
					target: target.trim(),
					port,
					attack_type: attackType,
					duration_secs: durationSecs,
					concurrent_connections: concurrentConnections,
					requests_per_second: requestsPerSecond,
					timeout,
					use_https: useHttps,
				}
			});
			if (result && historyComponent) {
				await historyComponent.saveHistory(target.trim(), JSON.stringify(result), result.summary, 'completed');
			}
		} catch (e: any) {
			error = e.toString();
			if (historyComponent) {
				await historyComponent.saveHistory(target.trim(), JSON.stringify({ error: e.toString() }), undefined, 'failed');
			}
		} finally {
			processing = false;
		}
	}

	function clearAll() {
		target = '';
		result = null;
		error = '';
		activeResultTab = 'overview';
	}

	function getSeverityColor(severity: string): string {
		switch (severity) {
			case 'high': return '#ef4444';
			case 'medium': return '#f59e0b';
			case 'low': return '#3b82f6';
			default: return '#6b7280';
		}
	}

	function getSeverityBg(severity: string): string {
		switch (severity) {
			case 'high': return 'rgba(239,68,68,0.15)';
			case 'medium': return 'rgba(245,158,11,0.15)';
			case 'low': return 'rgba(59,130,246,0.15)';
			default: return 'rgba(107,114,128,0.15)';
		}
	}

	function getStatusCodeColor(code: string): string {
		if (code === 'timeout') return '#ef4444';
		const num = parseInt(code);
		if (num >= 200 && num < 300) return '#22c55e';
		if (num >= 300 && num < 400) return '#3b82f6';
		if (num >= 400 && num < 500) return '#f59e0b';
		if (num >= 500) return '#ef4444';
		return '#94a3b8';
	}

	function getPercentileBarWidth(value: number): string {
		if (maxResponseTime === 0) return '0%';
		return Math.min((value / maxResponseTime) * 100, 100) + '%';
	}

	async function exportResult() {
		if (!result) return;
		exporting = true;
		try {
			const { open } = await import('@tauri-apps/plugin-dialog');
			const savePath = await open({
				directory: true,
				multiple: false,
			});
			if (!savePath) {
				exporting = false;
				return;
			}
			const ext = exportFormat === 'csv' ? 'csv' : 'json';
			const fileName = `stress-test-${new Date().toISOString().slice(0, 10)}.${ext}`;
			let content: string;
			if (exportFormat === 'csv') {
				const rows = [
					['Metric', 'Value'],
					['Target', result.target],
					['Attack Type', result.attack_type],
					['Total Requests', result.total_requests.toString()],
					['Successful Requests', result.successful_requests.toString()],
					['Failed Requests', result.failed_requests.toString()],
					['Duration (s)', result.duration_secs.toFixed(1)],
					['RPS', result.requests_per_second.toFixed(1)],
					['Avg Response (ms)', avgResponseTime.toString()],
					['Success Rate (%)', successRate],
					['Connections Opened', result.connections_opened.toString()],
					['Connections Maintained', result.connections_maintained.toString()],
					['P50 (ms)', result.response_time_percentiles?.p50?.toString() ?? 'N/A'],
					['P90 (ms)', result.response_time_percentiles?.p90?.toString() ?? 'N/A'],
					['P95 (ms)', result.response_time_percentiles?.p95?.toString() ?? 'N/A'],
					['P99 (ms)', result.response_time_percentiles?.p99?.toString() ?? 'N/A'],
				];
				if (result.findings.length > 0) {
					rows.push([]);
					rows.push(['Findings']);
					rows.push(['Severity', 'Category', 'Description', 'Recommendation']);
					for (const f of result.findings) {
						rows.push([f.severity, f.category, f.description, f.recommendation]);
					}
				}
				content = rows.map(r => r.map(c => `"${c}"`).join(',')).join('\n');
			} else {
				content = JSON.stringify(result, null, 2);
			}
			const { writeTextFile } = await import('@tauri-apps/plugin-fs');
			await writeTextFile(`${savePath}/${fileName}`, content);
		} catch (e: any) {
			console.error('Export failed:', e);
		} finally {
			exporting = false;
		}
	}

	function handleKeydown(e: KeyboardEvent) {
		if (e.key === 'Enter' && !processing && target.trim()) {
			startTest();
		}
	}
</script>

<svelte:window onkeydown={handleKeydown} />

<div class="nd-page">
	<div class="page-header">
		<div class="header-left">
			<a href="/" class="back-link">{$tr('common.backToHome')}</a>
			<h1 class="page-title">⚡ {$tr('ddosTester.title')}</h1>
			<p class="page-subtitle">{$tr('ddosTester.subtitle')}</p>
		</div>
	</div>

	<div class="warning-banner">
		⚠️ {$tr('ddosTester.warning')}
	</div>

	<div class="tabs">
		<button class="tab-btn {activeMainTab === 'analyze' ? 'active' : ''}" onclick={() => activeMainTab = 'analyze'}>
			<span class="tab-icon">⚡</span> {$tr('ddosTester.test')}
		</button>
		<button class="tab-btn {activeMainTab === 'history' ? 'active' : ''}" onclick={() => activeMainTab = 'history'}>
			<span class="tab-icon">📋</span> {$tr('ddosTester.history')}
		</button>
		<button class="tab-btn {activeMainTab === 'help' ? 'active' : ''}" onclick={() => activeMainTab = 'help'}>
			<span class="tab-icon">📖</span> {$tr('ddosTester.help')}
		</button>
	</div>

	{#if activeMainTab === 'analyze'}
		<div class="content-grid">
			<div class="input-section">
				<div class="section-card">
					<h2 class="section-title">{$tr('ddosTester.configTitle')}</h2>
					<p class="section-desc">{$tr('ddosTester.configDesc')}</p>

					<div class="form-group">
						<label class="form-label" for="ddos-target">{$tr('ddosTester.target')}</label>
						<input id="ddos-target" type="text" bind:value={target} placeholder={$tr('ddosTester.targetPlaceholder')} class="form-input" disabled={processing} />
					</div>

					<div class="form-row">
						<div class="form-group">
							<label class="form-label" for="ddos-port">{$tr('ddosTester.port')}</label>
							<input id="ddos-port" type="number" bind:value={port} class="form-input" min="1" max="65535" disabled={processing} />
						</div>
						<div class="form-group">
							<label class="form-label" for="ddos-attack-type">{$tr('ddosTester.attackType')}</label>
							<select id="ddos-attack-type" bind:value={attackType} class="form-input" disabled={processing}>
								{#each getAttackTypes() as at}
									<option value={at.value}>{at.icon} {at.label}</option>
								{/each}
							</select>
						</div>
					</div>

					{#if getAttackTypes().find(a => a.value === attackType)}
						<div class="attack-desc">
							{getAttackTypes().find(a => a.value === attackType)?.desc}
						</div>
					{/if}

					<div class="form-row">
						<div class="form-group">
							<label class="form-label" for="ddos-duration">{$tr('ddosTester.duration')}</label>
							<input id="ddos-duration" type="number" bind:value={durationSecs} class="form-input" min="1" max="120" disabled={processing} />
						</div>
						<div class="form-group">
							<label class="form-label" for="ddos-concurrent">{$tr('ddosTester.concurrentConnections')}</label>
							<input id="ddos-concurrent" type="number" bind:value={concurrentConnections} class="form-input" min="1" max="1000" disabled={processing} />
						</div>
					</div>

					{#if attackType === 'http_flood' || attackType === 'tcp_connect'}
						<div class="form-group">
							<label class="form-label" for="ddos-rps">{$tr('ddosTester.requestsPerSecond')}</label>
							<input id="ddos-rps" type="number" bind:value={requestsPerSecond} class="form-input" min="1" max="2000" disabled={processing} />
						</div>
					{/if}

					<div class="form-row">
						<div class="form-group">
							<label class="form-label" for="ddos-timeout">{$tr('ddosTester.timeout')}</label>
							<input id="ddos-timeout" type="number" bind:value={timeout} class="form-input" min="1" max="30" disabled={processing} />
						</div>
						<div class="form-group">
							<label class="form-label">{$tr('ddosTester.useHttps')}</label>
							<div class="toggle-wrapper">
								<button class="toggle-btn {useHttps ? 'active' : ''}" onclick={() => useHttps = !useHttps} disabled={processing}>
									{useHttps ? '🔒 HTTPS' : '🔓 HTTP'}
								</button>
							</div>
						</div>
					</div>

					<div class="button-group">
						<button class="btn-primary" onclick={startTest} disabled={processing || !target.trim()}>
							{#if processing}
								<span class="spinner"></span> {$tr('ddosTester.testing')}
							{:else}
								⚡ {$tr('ddosTester.start')}
							{/if}
						</button>
						<button class="btn-secondary" onclick={clearAll} disabled={processing}>
							🗑️ {$tr('ddosTester.clear')}
						</button>
					</div>
				</div>
			</div>

			<div class="result-section">
				<div class="section-card">
					<div class="result-header">
						<h2 class="section-title">{$tr('ddosTester.result.title')}</h2>
						{#if result}
							<div class="export-group">
								<select bind:value={exportFormat} class="export-select">
									<option value="json">JSON</option>
									<option value="csv">CSV</option>
								</select>
								<button class="btn-export" onclick={exportResult} disabled={exporting}>
									{#if exporting}
										<span class="spinner-sm"></span> {$tr('ddosTester.result.exporting')}
									{:else}
										📥 {$tr('ddosTester.result.export')}
									{/if}
								</button>
							</div>
						{/if}
					</div>

					{#if error}
						<div class="error-card">
							<div class="error-icon">⚠️</div>
							<div class="error-text">{error}</div>
						</div>
					{:else if result}
						<div class="summary-bar">{result.summary}</div>

						<div class="result-tabs">
							<button class="result-tab {activeResultTab === 'overview' ? 'active' : ''}" onclick={() => activeResultTab = 'overview'}>
								📊 {$tr('ddosTester.result.summary')}
							</button>
							<button class="result-tab {activeResultTab === 'percentiles' ? 'active' : ''}" onclick={() => activeResultTab = 'percentiles'}>
								⏱️ {$tr('ddosTester.result.percentiles')}
							</button>
							<button class="result-tab {activeResultTab === 'statusCodes' ? 'active' : ''}" onclick={() => activeResultTab = 'statusCodes'}>
								📡 {$tr('ddosTester.result.statusCodes')}
							</button>
							<button class="result-tab {activeResultTab === 'findings' ? 'active' : ''}" onclick={() => activeResultTab = 'findings'}>
								🔍 {$tr('ddosTester.result.findings')}
								{#if result.findings.length > 0}
									<span class="badge">{result.findings.length}</span>
								{/if}
							</button>
						</div>

						{#if activeResultTab === 'overview'}
							<div class="overview-grid">
								<div class="overview-stat">
									<div class="stat-label">{$tr('ddosTester.result.totalRequests')}</div>
									<div class="stat-value">{result.total_requests}</div>
								</div>
								<div class="overview-stat">
									<div class="stat-label">{$tr('ddosTester.result.successful')}</div>
									<div class="stat-value stat-success">{result.successful_requests}</div>
								</div>
								<div class="overview-stat">
									<div class="stat-label">{$tr('ddosTester.result.failed')}</div>
									<div class="stat-value stat-fail">{result.failed_requests}</div>
								</div>
								<div class="overview-stat">
									<div class="stat-label">{$tr('ddosTester.result.rps')}</div>
									<div class="stat-value">{result.requests_per_second.toFixed(1)}</div>
								</div>
								<div class="overview-stat">
									<div class="stat-label">{$tr('ddosTester.result.avgResponse')}</div>
									<div class="stat-value">{avgResponseTime}ms</div>
								</div>
								<div class="overview-stat">
									<div class="stat-label">{$tr('ddosTester.result.successRate')}</div>
									<div class="stat-value" style="color: {parseFloat(successRate) > 80 ? '#22c55e' : parseFloat(successRate) > 50 ? '#f59e0b' : '#ef4444'}">{successRate}%</div>
								</div>
								<div class="overview-stat">
									<div class="stat-label">{$tr('ddosTester.result.connectionsOpened')}</div>
									<div class="stat-value">{result.connections_opened}</div>
								</div>
								<div class="overview-stat">
									<div class="stat-label">{$tr('ddosTester.result.connectionsMaintained')}</div>
									<div class="stat-value">{result.connections_maintained}</div>
								</div>
							</div>

							{#if result.response_time_percentiles}
								<div class="mini-percentiles">
									<div class="mini-p-item">
										<span class="mini-p-label">P50</span>
										<span class="mini-p-value">{result.response_time_percentiles.p50}ms</span>
									</div>
									<div class="mini-p-item">
										<span class="mini-p-label">P90</span>
										<span class="mini-p-value">{result.response_time_percentiles.p90}ms</span>
									</div>
									<div class="mini-p-item">
										<span class="mini-p-label">P95</span>
										<span class="mini-p-value">{result.response_time_percentiles.p95}ms</span>
									</div>
									<div class="mini-p-item">
										<span class="mini-p-label">P99</span>
										<span class="mini-p-value">{result.response_time_percentiles.p99}ms</span>
									</div>
								</div>
							{/if}

							{#if result.findings.length > 0}
								<div class="findings-summary">
									{#if highFindings.length > 0}
										<span class="finding-count high">{highFindings.length} High</span>
									{/if}
									{#if mediumFindings.length > 0}
										<span class="finding-count medium">{mediumFindings.length} Medium</span>
									{/if}
									{#if lowFindings.length > 0}
										<span class="finding-count low">{lowFindings.length} Info</span>
									{/if}
								</div>
							{/if}
						{:else if activeResultTab === 'percentiles'}
							{#if result.response_time_percentiles}
								<div class="percentiles-chart">
									<div class="percentile-row">
										<span class="p-label">{$tr('ddosTester.result.min')}</span>
										<div class="p-bar-track">
											<div class="p-bar" style="width: {getPercentileBarWidth(result.response_time_percentiles.min)}; background: #22c55e;"></div>
										</div>
										<span class="p-value">{result.response_time_percentiles.min}ms</span>
									</div>
									<div class="percentile-row">
										<span class="p-label">{$tr('ddosTester.result.p50')}</span>
										<div class="p-bar-track">
											<div class="p-bar" style="width: {getPercentileBarWidth(result.response_time_percentiles.p50)}; background: #3b82f6;"></div>
										</div>
										<span class="p-value">{result.response_time_percentiles.p50}ms</span>
									</div>
									<div class="percentile-row">
										<span class="p-label">{$tr('ddosTester.result.p75')}</span>
										<div class="p-bar-track">
											<div class="p-bar" style="width: {getPercentileBarWidth(result.response_time_percentiles.p75)}; background: #8b5cf6;"></div>
										</div>
										<span class="p-value">{result.response_time_percentiles.p75}ms</span>
									</div>
									<div class="percentile-row">
										<span class="p-label">{$tr('ddosTester.result.p90')}</span>
										<div class="p-bar-track">
											<div class="p-bar" style="width: {getPercentileBarWidth(result.response_time_percentiles.p90)}; background: #f59e0b;"></div>
										</div>
										<span class="p-value">{result.response_time_percentiles.p90}ms</span>
									</div>
									<div class="percentile-row">
										<span class="p-label">{$tr('ddosTester.result.p95')}</span>
										<div class="p-bar-track">
											<div class="p-bar" style="width: {getPercentileBarWidth(result.response_time_percentiles.p95)}; background: #f97316;"></div>
										</div>
										<span class="p-value">{result.response_time_percentiles.p95}ms</span>
									</div>
									<div class="percentile-row">
										<span class="p-label">{$tr('ddosTester.result.p99')}</span>
										<div class="p-bar-track">
											<div class="p-bar" style="width: {getPercentileBarWidth(result.response_time_percentiles.p99)}; background: #ef4444;"></div>
										</div>
										<span class="p-value">{result.response_time_percentiles.p99}ms</span>
									</div>
									<div class="percentile-row">
										<span class="p-label">{$tr('ddosTester.result.max')}</span>
										<div class="p-bar-track">
											<div class="p-bar" style="width: 100%; background: #dc2626;"></div>
										</div>
										<span class="p-value">{result.response_time_percentiles.max}ms</span>
									</div>
								</div>
							{:else}
								<div class="empty-state">
									<div class="empty-icon">⏱️</div>
									<p>{$tr('ddosTester.result.noResults')}</p>
								</div>
							{/if}
						{:else if activeResultTab === 'statusCodes'}
							{#if statusCodeEntries.length > 0}
								<div class="status-codes-chart">
									{#each statusCodeEntries as [code, count]}
										<div class="status-row">
											<span class="status-code" style="color: {getStatusCodeColor(code)}">{code}</span>
											<div class="status-bar-track">
												<div class="status-bar" style="width: {(count / maxStatusCodeCount) * 100}%; background: {getStatusCodeColor(code)};"></div>
											</div>
											<span class="status-count">{count}</span>
										</div>
									{/each}
								</div>
							{:else}
								<div class="empty-state">
									<div class="empty-icon">📡</div>
									<p>{$tr('ddosTester.result.noResults')}</p>
								</div>
							{/if}
						{:else if activeResultTab === 'findings'}
							{#if result.findings.length > 0}
								<div class="findings-list">
									{#each result.findings as finding}
										<div class="finding-card" style="border-left-color: {getSeverityColor(finding.severity)}; background: {getSeverityBg(finding.severity)}">
											<div class="finding-header">
												<span class="finding-severity" style="background: {getSeverityColor(finding.severity)}">{finding.severity.toUpperCase()}</span>
												<span class="finding-category">{finding.category}</span>
											</div>
											<p class="finding-desc">{finding.description}</p>
											<p class="finding-rec">💡 {finding.recommendation}</p>
										</div>
									{/each}
								</div>
							{:else}
								<div class="empty-state">
									<div class="empty-icon">✅</div>
									<p>{$tr('ddosTester.result.noResults')}</p>
								</div>
							{/if}
						{/if}
					{:else if processing}
						<div class="processing-state">
							<div class="processing-spinner"></div>
							<p>{$tr('ddosTester.testing')}</p>
							<p class="processing-detail">{attackType.toUpperCase()} → {target}:{port}</p>
						</div>
					{:else}
						<div class="empty-state">
							<div class="empty-icon">⚡</div>
							<p>{$tr('ddosTester.result.noResults')}</p>
						</div>
					{/if}
				</div>
			</div>
		</div>
	{:else if activeMainTab === 'history'}
		<div class="section-card">
			<ToolHistory toolType="ddos_tester" toolName={$tr('ddosTester.title')} bind:this={historyComponent} />
		</div>
	{:else if activeMainTab === 'help'}
		<div class="section-card">
			<ToolHelp toolType="ddos_tester" />
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

	.warning-banner {
		padding: 0.75rem 1rem;
		background: rgba(245, 158, 11, 0.1);
		border: 1px solid rgba(245, 158, 11, 0.25);
		border-radius: 0.5rem;
		margin-bottom: 1.25rem;
		font-size: 0.8rem;
		color: #fbbf24;
		line-height: 1.5;
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

	.attack-desc {
		padding: 0.5rem 0.75rem;
		background: rgba(168, 85, 247, 0.08);
		border: 1px solid rgba(168, 85, 247, 0.15);
		border-radius: 0.4rem;
		font-size: 0.75rem;
		color: #c4b5fd;
		margin-bottom: 0.75rem;
		line-height: 1.5;
	}

	.toggle-wrapper {
		display: flex;
		align-items: center;
		height: 100%;
	}

	.toggle-btn {
		padding: 0.55rem 0.75rem;
		border-radius: 0.5rem;
		border: 1px solid rgba(148, 163, 184, 0.15);
		background: rgba(15, 23, 42, 0.8);
		color: #94a3b8;
		cursor: pointer;
		font-size: 0.85rem;
		transition: all 0.2s;
		width: 100%;
		text-align: center;
	}

	.toggle-btn.active {
		background: rgba(168, 85, 247, 0.15);
		border-color: rgba(168, 85, 247, 0.4);
		color: #c4b5fd;
	}

	.toggle-btn:hover:not(:disabled) {
		border-color: rgba(168, 85, 247, 0.3);
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

	.spinner-sm {
		display: inline-block;
		width: 0.75rem;
		height: 0.75rem;
		border: 2px solid rgba(255, 255, 255, 0.3);
		border-top-color: white;
		border-radius: 50%;
		animation: spin 0.6s linear infinite;
	}

	@keyframes spin { to { transform: rotate(360deg); } }

	.result-header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		margin-bottom: 0.75rem;
	}

	.export-group {
		display: flex;
		gap: 0.4rem;
		align-items: center;
	}

	.export-select {
		padding: 0.35rem 0.5rem;
		border-radius: 0.4rem;
		border: 1px solid rgba(148, 163, 184, 0.15);
		background: rgba(15, 23, 42, 0.6);
		color: #f1f5f9;
		font-size: 0.8rem;
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
		display: flex;
		align-items: center;
		gap: 0.3rem;
	}

	.btn-export:hover:not(:disabled) {
		background: rgba(168, 85, 247, 0.2);
		border-color: rgba(168, 85, 247, 0.5);
	}

	.btn-export:disabled { opacity: 0.5; cursor: not-allowed; }

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
		display: flex;
		align-items: center;
		gap: 0.3rem;
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

	.badge {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		min-width: 1.2rem;
		height: 1.2rem;
		padding: 0 0.3rem;
		border-radius: 0.6rem;
		background: rgba(239, 68, 68, 0.8);
		color: white;
		font-size: 0.65rem;
		font-weight: 700;
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
		margin-bottom: 0.25rem;
	}

	.stat-value {
		font-size: 1.25rem;
		font-weight: 700;
		color: #f1f5f9;
	}

	.stat-success { color: #22c55e !important; }
	.stat-fail { color: #ef4444 !important; }

	.mini-percentiles {
		display: flex;
		gap: 0.5rem;
		flex-wrap: wrap;
		margin-bottom: 1rem;
	}

	.mini-p-item {
		display: flex;
		align-items: center;
		gap: 0.3rem;
		padding: 0.3rem 0.6rem;
		background: rgba(15, 23, 42, 0.4);
		border: 1px solid rgba(148, 163, 184, 0.08);
		border-radius: 0.4rem;
	}

	.mini-p-label {
		font-size: 0.7rem;
		color: #94a3b8;
		font-weight: 600;
	}

	.mini-p-value {
		font-size: 0.8rem;
		color: #f1f5f9;
		font-weight: 700;
		font-family: 'SF Mono', 'Fira Code', monospace;
	}

	.findings-summary {
		display: flex;
		gap: 0.4rem;
		flex-wrap: wrap;
	}

	.finding-count {
		padding: 0.25rem 0.6rem;
		border-radius: 0.3rem;
		font-size: 0.75rem;
		font-weight: 600;
	}

	.finding-count.high { background: rgba(239, 68, 68, 0.15); color: #fca5a5; }
	.finding-count.medium { background: rgba(245, 158, 11, 0.15); color: #fbbf24; }
	.finding-count.low { background: rgba(59, 130, 246, 0.15); color: #93c5fd; }

	.percentiles-chart {
		display: flex;
		flex-direction: column;
		gap: 0.75rem;
	}

	.percentile-row {
		display: flex;
		align-items: center;
		gap: 0.75rem;
	}

	.p-label {
		width: 3rem;
		font-size: 0.8rem;
		color: #94a3b8;
		font-weight: 600;
		text-align: right;
	}

	.p-bar-track {
		flex: 1;
		height: 1.5rem;
		background: rgba(15, 23, 42, 0.6);
		border-radius: 0.4rem;
		overflow: hidden;
	}

	.p-bar {
		height: 100%;
		border-radius: 0.4rem;
		transition: width 0.5s ease;
		min-width: 2px;
		opacity: 0.8;
	}

	.p-value {
		width: 5rem;
		font-size: 0.8rem;
		color: #f1f5f9;
		font-weight: 600;
		font-family: 'SF Mono', 'Fira Code', monospace;
	}

	.status-codes-chart {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
	}

	.status-row {
		display: flex;
		align-items: center;
		gap: 0.75rem;
	}

	.status-code {
		width: 4rem;
		font-size: 0.85rem;
		font-weight: 700;
		font-family: 'SF Mono', 'Fira Code', monospace;
		text-align: right;
	}

	.status-bar-track {
		flex: 1;
		height: 1.5rem;
		background: rgba(15, 23, 42, 0.6);
		border-radius: 0.4rem;
		overflow: hidden;
	}

	.status-bar {
		height: 100%;
		border-radius: 0.4rem;
		transition: width 0.5s ease;
		min-width: 2px;
		opacity: 0.7;
	}

	.status-count {
		width: 4rem;
		font-size: 0.8rem;
		color: #f1f5f9;
		font-weight: 600;
		font-family: 'SF Mono', 'Fira Code', monospace;
	}

	.findings-list {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
	}

	.finding-card {
		padding: 0.75rem 1rem;
		border-radius: 0.5rem;
		border-left: 3px solid;
	}

	.finding-header {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		margin-bottom: 0.4rem;
	}

	.finding-severity {
		padding: 0.15rem 0.5rem;
		border-radius: 0.25rem;
		color: white;
		font-size: 0.7rem;
		font-weight: 700;
		letter-spacing: 0.05em;
	}

	.finding-category {
		font-weight: 600;
		font-size: 0.85rem;
		color: #e2e8f0;
		text-transform: capitalize;
	}

	.finding-desc {
		font-size: 0.8rem;
		color: #cbd5e1;
		margin: 0 0 0.3rem;
		line-height: 1.5;
	}

	.finding-rec {
		font-size: 0.75rem;
		color: #94a3b8;
		margin: 0;
		line-height: 1.5;
	}

	.empty-state {
		text-align: center;
		padding: 3rem 1rem;
		color: #94a3b8;
	}

	.empty-icon {
		font-size: 3rem;
		margin-bottom: 0.75rem;
		opacity: 0.5;
	}

	.empty-state p {
		font-size: 0.85rem;
		margin: 0;
	}

	.processing-state {
		text-align: center;
		padding: 3rem 1rem;
		color: #94a3b8;
	}

	.processing-spinner {
		display: inline-block;
		width: 2.5rem;
		height: 2.5rem;
		border: 3px solid rgba(168, 85, 247, 0.2);
		border-top-color: #a855f7;
		border-radius: 50%;
		animation: spin 0.8s linear infinite;
		margin-bottom: 1rem;
	}

	.processing-state p {
		font-size: 0.9rem;
		margin: 0.25rem 0;
	}

	.processing-detail {
		font-size: 0.8rem;
		color: #64748b;
		font-family: 'SF Mono', 'Fira Code', monospace;
	}

	@media (max-width: 900px) {
		.content-grid {
			grid-template-columns: 1fr;
		}
		.overview-grid {
			grid-template-columns: repeat(2, 1fr);
		}
	}

	@media (max-width: 600px) {
		.overview-grid {
			grid-template-columns: 1fr 1fr;
		}
		.form-row {
			grid-template-columns: 1fr;
		}
	}
</style>
