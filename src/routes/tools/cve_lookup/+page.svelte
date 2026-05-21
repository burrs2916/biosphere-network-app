<script lang="ts">
	import { tr } from '$lib/i18n';
	import ToolHistory from '$lib/components/ToolHistory.svelte';
	import ToolHelp from '$lib/components/ToolHelp.svelte';

	interface CveReference {
		url: string;
		source: string | null;
		tags: string[];
	}

	interface AffectedProduct {
		vendor: string;
		product: string;
		versions: string[];
		cpe: string;
	}

	interface ExploitabilityInfo {
		has_exploit: boolean;
		exploit_available: boolean;
		exploit_sources: string[];
		epss_score: number | null;
		epss_percentile: number | null;
	}

	interface PatchInfo {
		url: string;
		source: string | null;
		description: string | null;
	}

	interface CveEntry {
		cve_id: string;
		description: string;
		severity: string | null;
		cvss_score: number | null;
		cvss_version: string | null;
		cvss_vector: string | null;
		published_date: string | null;
		last_modified: string | null;
		url: string;
		cwe_ids: string[];
		references: CveReference[];
		affected_products: AffectedProduct[];
		exploitability: ExploitabilityInfo | null;
		patches: PatchInfo[];
		source: string;
	}

	interface SeverityStats {
		critical: number;
		high: number;
		medium: number;
		low: number;
		none: number;
	}

	interface CvssDistribution {
		range_9_10: number;
		range_7_9: number;
		range_4_7: number;
		range_0_4: number;
		unknown: number;
	}

	interface CveQueryResult {
		query: string;
		vulnerabilities: CveEntry[];
		total_results: number;
		summary: string;
		scan_duration_ms: number;
		severity_stats: SeverityStats;
		cvss_distribution: CvssDistribution;
	}

	let query = $state('');
	let activeMainTab = $state('analyze');
	let activeResultTab = $state('overview');
	let historyComponent: ToolHistory = $state(null!);
	let limit = $state(20);
	let severityFilter = $state('');
	let cvssMin = $state<number | null>(null);
	let cvssMax = $state<number | null>(null);
	let hasExploit = $state(false);
	let showAdvanced = $state(false);
	let result: CveQueryResult | null = $state(null);
	let error = $state('');
	let processing = $state(false);
	let searchQuery = $state('');
	let selectedCve: CveEntry | null = $state(null);
	let exportFormat = $state('json');
	let severityLinkFilter = $state('all');
	let copiedId = $state('');

	const TOOL_NAME = 'cve_lookup';

	function getSeverityColor(sev: string | null): string {
		if (!sev) return '#94a3b8';
		const s = sev.toUpperCase();
		if (s === 'CRITICAL') return '#ef4444';
		if (s === 'HIGH') return '#f97316';
		if (s === 'MEDIUM') return '#eab308';
		if (s === 'LOW') return '#22c55e';
		return '#94a3b8';
	}

	function getCvssColor(score: number | null): string {
		if (score === null) return '#94a3b8';
		if (score >= 9.0) return '#ef4444';
		if (score >= 7.0) return '#f97316';
		if (score >= 4.0) return '#eab308';
		return '#22c55e';
	}

	function formatDate(dateStr: string | null): string {
		if (!dateStr) return '-';
		return dateStr.split('T')[0];
	}

	function getFilteredVulnerabilities(): CveEntry[] {
		if (!result) return [];
		let filtered = result.vulnerabilities;

		if (severityLinkFilter !== 'all') {
			filtered = filtered.filter(v => {
				if (severityLinkFilter === 'critical') return v.severity?.toUpperCase() === 'CRITICAL';
				if (severityLinkFilter === 'high') return v.severity?.toUpperCase() === 'HIGH';
				if (severityLinkFilter === 'medium') return v.severity?.toUpperCase() === 'MEDIUM';
				if (severityLinkFilter === 'low') return v.severity?.toUpperCase() === 'LOW';
				if (severityLinkFilter === 'exploit') return v.exploitability?.has_exploit === true;
				return true;
			});
		}

		if (searchQuery.trim()) {
			const q = searchQuery.toLowerCase();
			filtered = filtered.filter(v =>
				v.cve_id.toLowerCase().includes(q) ||
				v.description.toLowerCase().includes(q) ||
				v.cwe_ids.some(c => c.toLowerCase().includes(q))
			);
		}

		return filtered;
	}

	function getCvssBarWidth(count: number, total: number): string {
		if (total === 0) return '0%';
		return `${(count / total) * 100}%`;
	}

	async function lookup() {
		if (!query.trim()) {
			error = $tr('cveLookup.error.emptyInput');
			return;
		}
		processing = true;
		error = '';
		result = null;
		selectedCve = null;
		activeResultTab = 'overview';
		severityLinkFilter = 'all';
		searchQuery = '';

		try {
			const { invoke } = await import('@tauri-apps/api/core');
			result = await invoke<CveQueryResult>('lookup_cve_command', {
				config: {
					query: query.trim(),
					limit,
					severity_filter: severityFilter || null,
					cvss_min: cvssMin,
					cvss_max: cvssMax,
					pub_date_start: null,
					pub_date_end: null,
					mod_date_start: null,
					mod_date_end: null,
					cpe_name: null,
					cwe_id: null,
					has_exploit: hasExploit || null,
					is_vulnerable: null,
				}
			});

			if (result && historyComponent) {
				await historyComponent.saveHistory(query.trim(), JSON.stringify(result), result.summary, 'completed');
			}
		} catch (e: any) {
			error = e.toString();
			if (historyComponent) {
				await historyComponent.saveHistory(query.trim(), JSON.stringify({ error: e.toString() }), `Error: ${e.toString()}`, 'error');
			}
		} finally {
			processing = false;
		}
	}

	function clearAll() {
		query = '';
		result = null;
		error = '';
		selectedCve = null;
		severityFilter = '';
		cvssMin = null;
		cvssMax = null;
		hasExploit = false;
		showAdvanced = false;
		severityLinkFilter = 'all';
		searchQuery = '';
	}

	function exportResult() {
		if (!result) return;

		let content: string;
		let filename: string;

		if (exportFormat === 'json') {
			content = JSON.stringify(result, null, 2);
			filename = `cve_${query.replace(/[^a-zA-Z0-9]/g, '_')}.json`;
		} else {
			const headers = ['CVE ID', 'Severity', 'CVSS Score', 'Description', 'Published', 'URL'];
			const rows = result.vulnerabilities.map(v => [
				v.cve_id,
				v.severity || '',
				v.cvss_score?.toString() || '',
				v.description.replace(/"/g, '""'),
				formatDate(v.published_date),
				v.url
			]);
			content = [headers.join(','), ...rows.map(r => r.map(c => `"${c}"`).join(','))].join('\n');
			filename = `cve_${query.replace(/[^a-zA-Z0-9]/g, '_')}.csv`;
		}

		const blob = new Blob([content], { type: exportFormat === 'json' ? 'application/json' : 'text/csv' });
		const url = URL.createObjectURL(blob);
		const a = document.createElement('a');
		a.href = url;
		a.download = filename;
		a.click();
		URL.revokeObjectURL(url);
	}

	function selectCve(cve: CveEntry) {
		selectedCve = cve;
		activeResultTab = 'details';
	}

	async function copyToClipboard(text: string) {
		try {
			await navigator.clipboard.writeText(text);
			copiedId = text;
			setTimeout(() => { copiedId = ''; }, 1500);
		} catch { }
	}

	function quickSearch(keyword: string) {
		query = keyword;
		lookup();
	}
</script>

<div class="nd-page">
	<div class="page-header">
		<div class="header-left">
			<a href="/" class="back-link">{$tr('common.backToHome')}</a>
			<h1 class="page-title">🛡️ {$tr('cveLookup.title')}</h1>
			<p class="page-subtitle">{$tr('cveLookup.subtitle')}</p>
		</div>
	</div>

	<div class="tabs">
		<button class="tab-btn {activeMainTab === 'analyze' ? 'active' : ''}" on:click={() => activeMainTab = 'analyze'}>
			<span class="tab-icon">🔍</span> {$tr('cveLookup.tabSearch')}
		</button>
		<button class="tab-btn {activeMainTab === 'history' ? 'active' : ''}" on:click={() => activeMainTab = 'history'}>
			<span class="tab-icon">📋</span> {$tr('cveLookup.tabHistory')}
		</button>
		<button class="tab-btn {activeMainTab === 'help' ? 'active' : ''}" on:click={() => activeMainTab = 'help'}>
			<span class="tab-icon">📖</span> {$tr('cveLookup.tabHelp')}
		</button>
	</div>

	{#if activeMainTab === 'analyze'}
		<div class="content-grid">
			<div class="input-section">
				<div class="section-card">
					<h2 class="section-title">{$tr('cveLookup.configTitle')}</h2>
					<p class="section-desc">{$tr('cveLookup.configDesc')}</p>

					<div class="form-group">
						<label class="form-label">{$tr('cveLookup.queryLabel')}</label>
						<input type="text" bind:value={query} placeholder="CVE-2024-1234 or keyword" class="form-input" disabled={processing} on:keydown={(e) => e.key === 'Enter' && lookup()} />
					</div>

					<div class="form-group">
						<label class="form-label">{$tr('cveLookup.quickSearch')}</label>
						<div class="quick-grid">
							<button class="quick-btn" on:click={() => quickSearch('CVE-2024')} disabled={processing}>CVE-2024</button>
							<button class="quick-btn" on:click={() => quickSearch('CVE-2025')} disabled={processing}>CVE-2025</button>
							<button class="quick-btn" on:click={() => quickSearch('log4j')} disabled={processing}>Log4j</button>
							<button class="quick-btn" on:click={() => quickSearch('openssl')} disabled={processing}>OpenSSL</button>
							<button class="quick-btn" on:click={() => quickSearch('apache')} disabled={processing}>Apache</button>
							<button class="quick-btn" on:click={() => quickSearch('nginx')} disabled={processing}>Nginx</button>
						</div>
					</div>

					<div class="form-row">
						<div class="form-group">
							<label class="form-label">📊 {$tr('cveLookup.resultLimit')}</label>
							<input type="number" bind:value={limit} class="form-input" min="1" max="100" disabled={processing} />
						</div>
						<div class="form-group">
							<label class="form-label">⚠️ {$tr('cveLookup.severityFilter')}</label>
							<select bind:value={severityFilter} class="form-input" disabled={processing}>
								<option value="">{$tr('cveLookup.allSeverities')}</option>
								<option value="CRITICAL">🔴 CRITICAL</option>
								<option value="HIGH">🟠 HIGH</option>
								<option value="MEDIUM">🟡 MEDIUM</option>
								<option value="LOW">🟢 LOW</option>
							</select>
						</div>
					</div>

					<div class="form-group">
						<button class="toggle-btn" on:click={() => showAdvanced = !showAdvanced}>
							<span class="toggle-arrow">{showAdvanced ? '▼' : '▶'}</span> {$tr('cveLookup.advancedOptions')}
						</button>
					</div>

					{#if showAdvanced}
						<div class="advanced-section">
							<div class="form-row">
								<div class="form-group">
									<label class="form-label">📈 {$tr('cveLookup.cvssMin')}</label>
									<input type="number" bind:value={cvssMin} class="form-input" min="0" max="10" step="0.1" disabled={processing} />
								</div>
								<div class="form-group">
									<label class="form-label">📉 {$tr('cveLookup.cvssMax')}</label>
									<input type="number" bind:value={cvssMax} class="form-input" min="0" max="10" step="0.1" disabled={processing} />
								</div>
							</div>

							<div class="form-group">
								<label class="target-chip {hasExploit ? 'active' : ''}">
									<input type="checkbox" bind:checked={hasExploit} disabled={processing} />
									<span>💥 {$tr('cveLookup.onlyWithExploit')}</span>
								</label>
							</div>
						</div>
					{/if}

					<div class="button-group">
						<button class="btn-primary" on:click={lookup} disabled={processing || !query.trim()}>
							{#if processing}<span class="spinner"></span>{$tr('cveLookup.searching')}{:else}🔍 {$tr('cveLookup.search')}{/if}
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
							<div class="result-query">
								<h2 class="section-title" style="margin-bottom:0">🛡️ {result.query}</h2>
								<span class="duration-badge">⏱️ {result.scan_duration_ms}ms</span>
							</div>
							<div class="header-actions">
								<select bind:value={exportFormat} class="export-select">
									<option value="json">JSON</option>
									<option value="csv">CSV</option>
								</select>
								<button class="btn-export" on:click={exportResult}>
									📤 {$tr('cveLookup.export')}
								</button>
							</div>
						</div>

						<div class="summary-bar">{result.summary}</div>

						<div class="result-tabs">
							<button class="result-tab {activeResultTab === 'overview' ? 'active' : ''}" on:click={() => activeResultTab = 'overview'}>
								📊 {$tr('cveLookup.tabOverview')}
							</button>
							<button class="result-tab {activeResultTab === 'list' ? 'active' : ''}" on:click={() => activeResultTab = 'list'}>
								📋 {$tr('cveLookup.tabList')} ({result.vulnerabilities.length})
							</button>
							{#if selectedCve}
								<button class="result-tab {activeResultTab === 'details' ? 'active' : ''}" on:click={() => activeResultTab = 'details'}>
									📄 {$tr('cveLookup.tabDetails')}
								</button>
							{/if}
						</div>

						{#if activeResultTab === 'overview'}
							<div class="overview-grid">
								<div class="overview-stat">
									<span class="stat-label">{$tr('cveLookup.totalResults')}</span>
									<span class="stat-value">{result.total_results}</span>
								</div>
								<div class="overview-stat">
									<span class="stat-label">🔴 Critical</span>
									<span class="stat-value" style="color: #ef4444">{result.severity_stats.critical}</span>
								</div>
								<div class="overview-stat">
									<span class="stat-label">🟠 High</span>
									<span class="stat-value" style="color: #f97316">{result.severity_stats.high}</span>
								</div>
								<div class="overview-stat">
									<span class="stat-label">🟡 Medium</span>
									<span class="stat-value" style="color: #eab308">{result.severity_stats.medium}</span>
								</div>
								<div class="overview-stat">
									<span class="stat-label">🟢 Low</span>
									<span class="stat-value" style="color: #22c55e">{result.severity_stats.low}</span>
								</div>
							</div>

							{#if result.vulnerabilities.length > 0}
								<h3 class="subsection-title">📊 {$tr('cveLookup.cvssDistribution')}</h3>
								<div class="cvss-bars">
									<div class="cvss-bar-item">
										<div class="cvss-bar-label">9.0 - 10.0</div>
										<div class="cvss-bar-wrapper">
											<div class="cvss-bar" style="width: {getCvssBarWidth(result.cvss_distribution.range_9_10, result.vulnerabilities.length)}; background: #ef4444;"></div>
										</div>
										<div class="cvss-bar-count">{result.cvss_distribution.range_9_10}</div>
									</div>
									<div class="cvss-bar-item">
										<div class="cvss-bar-label">7.0 - 8.9</div>
										<div class="cvss-bar-wrapper">
											<div class="cvss-bar" style="width: {getCvssBarWidth(result.cvss_distribution.range_7_9, result.vulnerabilities.length)}; background: #f97316;"></div>
										</div>
										<div class="cvss-bar-count">{result.cvss_distribution.range_7_9}</div>
									</div>
									<div class="cvss-bar-item">
										<div class="cvss-bar-label">4.0 - 6.9</div>
										<div class="cvss-bar-wrapper">
											<div class="cvss-bar" style="width: {getCvssBarWidth(result.cvss_distribution.range_4_7, result.vulnerabilities.length)}; background: #eab308;"></div>
										</div>
										<div class="cvss-bar-count">{result.cvss_distribution.range_4_7}</div>
									</div>
									<div class="cvss-bar-item">
										<div class="cvss-bar-label">0.0 - 3.9</div>
										<div class="cvss-bar-wrapper">
											<div class="cvss-bar" style="width: {getCvssBarWidth(result.cvss_distribution.range_0_4, result.vulnerabilities.length)}; background: #22c55e;"></div>
										</div>
										<div class="cvss-bar-count">{result.cvss_distribution.range_0_4}</div>
									</div>
								</div>

								<h3 class="subsection-title">🔥 {$tr('cveLookup.topVulnerabilities')}</h3>
								<div class="top-vulns">
									{#each result.vulnerabilities.slice(0, 5) as vuln}
										<div class="vuln-card" on:click={() => selectCve(vuln)}>
											<div class="vuln-header">
												<span class="vuln-id">{vuln.cve_id}</span>
												<button class="copy-btn" on:click|stopPropagation={() => copyToClipboard(vuln.cve_id)} title="Copy">
													{copiedId === vuln.cve_id ? '✅' : '📋'}
												</button>
												{#if vuln.severity}
													<span class="severity-badge" style="color: {getSeverityColor(vuln.severity)}; border-color: {getSeverityColor(vuln.severity)}40; background: {getSeverityColor(vuln.severity)}15">
														{vuln.severity}
														{#if vuln.cvss_score}
															({vuln.cvss_score.toFixed(1)})
														{/if}
													</span>
												{/if}
											</div>
											<p class="vuln-desc">{vuln.description.slice(0, 150)}{vuln.description.length > 150 ? '...' : ''}</p>
											<div class="vuln-footer">
												{#if vuln.exploitability?.has_exploit}
													<span class="exploit-tag">💥 {$tr('cveLookup.exploitAvailable')}</span>
												{/if}
												<span class="date-tag">📅 {formatDate(vuln.published_date)}</span>
												{#if vuln.affected_products.length > 0}
													<span class="date-tag">📦 {vuln.affected_products.length} {$tr('cveLookup.products')}</span>
												{/if}
											</div>
										</div>
									{/each}
								</div>
							{/if}

						{:else if activeResultTab === 'list'}
							<div class="filter-bar">
								<button class="filter-btn {severityLinkFilter === 'all' ? 'active' : ''}" on:click={() => severityLinkFilter = 'all'}>
									{$tr('cveLookup.allSeverities')} ({result.vulnerabilities.length})
								</button>
								<button class="filter-btn {severityLinkFilter === 'critical' ? 'active' : ''}" on:click={() => severityLinkFilter = 'critical'}>
									🔴 Critical ({result.vulnerabilities.filter(v => v.severity?.toUpperCase() === 'CRITICAL').length})
								</button>
								<button class="filter-btn {severityLinkFilter === 'high' ? 'active' : ''}" on:click={() => severityLinkFilter = 'high'}>
									🟠 High ({result.vulnerabilities.filter(v => v.severity?.toUpperCase() === 'HIGH').length})
								</button>
								<button class="filter-btn {severityLinkFilter === 'medium' ? 'active' : ''}" on:click={() => severityLinkFilter = 'medium'}>
									🟡 Medium ({result.vulnerabilities.filter(v => v.severity?.toUpperCase() === 'MEDIUM').length})
								</button>
								<button class="filter-btn {severityLinkFilter === 'low' ? 'active' : ''}" on:click={() => severityLinkFilter = 'low'}>
									🟢 Low ({result.vulnerabilities.filter(v => v.severity?.toUpperCase() === 'LOW').length})
								</button>
								<button class="filter-btn {severityLinkFilter === 'exploit' ? 'active' : ''}" on:click={() => severityLinkFilter = 'exploit'}>
									💥 {$tr('cveLookup.exploitAvailable')} ({result.vulnerabilities.filter(v => v.exploitability?.has_exploit).length})
								</button>
							</div>

							<div class="search-bar">
								<input type="text" bind:value={searchQuery} placeholder="{$tr('cveLookup.searchPlaceholder')}" class="search-input" />
							</div>

							{#if getFilteredVulnerabilities().length > 0}
								<div class="cve-list">
									{#each getFilteredVulnerabilities() as entry}
										<div class="cve-item" on:click={() => selectCve(entry)}>
											<div class="cve-header">
												<a href={entry.url} target="_blank" class="cve-id" on:click|stopPropagation>{entry.cve_id}</a>
												<button class="copy-btn" on:click|stopPropagation={() => copyToClipboard(entry.cve_id)} title="Copy">
													{copiedId === entry.cve_id ? '✅' : '📋'}
												</button>
												{#if entry.severity}
													<span class="severity-badge" style="color: {getSeverityColor(entry.severity)}; border-color: {getSeverityColor(entry.severity)}40; background: {getSeverityColor(entry.severity)}15">
														{entry.severity}
														{#if entry.cvss_score}
															({entry.cvss_score.toFixed(1)})
														{/if}
													</span>
												{/if}
												{#if entry.exploitability?.has_exploit}
													<span class="exploit-badge">💥</span>
												{/if}
											</div>
											<p class="cve-desc">{entry.description}</p>
											<div class="cve-meta">
												{#if entry.cwe_ids.length > 0}
													<span class="meta-tag">CWE: {entry.cwe_ids.slice(0, 2).join(', ')}{entry.cwe_ids.length > 2 ? '...' : ''}</span>
												{/if}
												{#if entry.published_date}
													<span class="meta-tag">📅 {formatDate(entry.published_date)}</span>
												{/if}
												{#if entry.affected_products.length > 0}
													<span class="meta-tag">📦 {entry.affected_products.length} {$tr('cveLookup.products')}</span>
												{/if}
												{#if entry.patches.length > 0}
													<span class="meta-tag">🔧 {entry.patches.length} {$tr('cveLookup.patches')}</span>
												{/if}
											</div>
										</div>
									{/each}
								</div>
							{:else}
								<div class="empty-state">
									<div class="empty-icon">🔍</div>
									<p>{$tr('cveLookup.noMatchingResults')}</p>
								</div>
							{/if}

						{:else if activeResultTab === 'details' && selectedCve}
							<div class="details-content">
								<div class="detail-header">
									<a href={selectedCve.url} target="_blank" class="detail-cve-id">{selectedCve.cve_id}</a>
									<button class="copy-btn" on:click={() => copyToClipboard(selectedCve!.cve_id)} title="Copy">
									{copiedId === selectedCve!.cve_id ? '✅' : '📋'}
								</button>
									{#if selectedCve.severity}
										<span class="severity-badge large" style="color: {getSeverityColor(selectedCve.severity)}; border-color: {getSeverityColor(selectedCve.severity)}40; background: {getSeverityColor(selectedCve.severity)}15">
											{selectedCve.severity}
											{#if selectedCve.cvss_score}
												({selectedCve.cvss_score.toFixed(1)})
											{/if}
										</span>
									{/if}
								</div>

								<div class="detail-section">
									<h3 class="detail-section-title">📝 {$tr('cveLookup.description')}</h3>
									<p class="detail-text">{selectedCve.description}</p>
								</div>

								<div class="detail-grid">
									<div class="detail-item">
										<span class="detail-label">📅 {$tr('cveLookup.publishedDate')}</span>
										<span class="detail-value">{formatDate(selectedCve.published_date)}</span>
									</div>
									<div class="detail-item">
										<span class="detail-label">🔄 {$tr('cveLookup.modifiedDate')}</span>
										<span class="detail-value">{formatDate(selectedCve.last_modified)}</span>
									</div>
									{#if selectedCve.cvss_version}
										<div class="detail-item">
											<span class="detail-label">📊 CVSS Version</span>
											<span class="detail-value">{selectedCve.cvss_version}</span>
										</div>
									{/if}
									{#if selectedCve.cvss_score}
										<div class="detail-item">
											<span class="detail-label">📊 CVSS Score</span>
											<span class="detail-value" style="color: {getCvssColor(selectedCve.cvss_score)}; font-weight: 700">{selectedCve.cvss_score.toFixed(1)}</span>
										</div>
									{/if}
									{#if selectedCve.cvss_vector}
										<div class="detail-item full-width">
											<span class="detail-label">🎯 CVSS Vector</span>
											<span class="detail-value mono">{selectedCve.cvss_vector}</span>
										</div>
									{/if}
								</div>

								{#if selectedCve.cwe_ids.length > 0}
									<div class="detail-section">
										<h3 class="detail-section-title">🏷️ CWE IDs</h3>
										<div class="cwe-tags">
											{#each selectedCve.cwe_ids as cwe}
												<a href="https://cwe.mitre.org/data/definitions/{cwe.replace('CWE-', '')}.html" target="_blank" class="cwe-tag" on:click|stopPropagation>
													{cwe}
												</a>
											{/each}
										</div>
									</div>
								{/if}

								{#if selectedCve.affected_products.length > 0}
									<div class="detail-section">
										<h3 class="detail-section-title">📦 {$tr('cveLookup.affectedProducts')} ({selectedCve.affected_products.length})</h3>
										<div class="products-list">
											{#each selectedCve.affected_products.slice(0, 10) as product}
												<div class="product-item">
													<span class="product-vendor">{product.vendor}</span>
													<span class="product-name">{product.product}</span>
													<span class="product-versions">{product.versions.join(', ')}</span>
												</div>
											{/each}
											{#if selectedCve.affected_products.length > 10}
												<div class="more-products">+{selectedCve.affected_products.length - 10} {$tr('cveLookup.moreProducts')}</div>
											{/if}
										</div>
									</div>
								{/if}

								{#if selectedCve.exploitability}
									<div class="detail-section exploit-section">
										<h3 class="detail-section-title">💥 {$tr('cveLookup.exploitInfo')}</h3>
										<div class="exploit-info">
											<div class="exploit-stat">
												<span class="exploit-label">{$tr('cveLookup.exploitAvailable')}</span>
												<span class="exploit-value {selectedCve.exploitability.exploit_available ? 'danger' : ''}">
													{selectedCve.exploitability.exploit_available ? '✅ ' + $tr('cveLookup.yes') : '❌ ' + $tr('cveLookup.no')}
												</span>
											</div>
											{#if selectedCve.exploitability.exploit_sources.length > 0}
												<div class="exploit-sources">
													<span class="exploit-label">{$tr('cveLookup.sources')}:</span>
													{#each selectedCve.exploitability.exploit_sources as source}
														<span class="source-tag">{source}</span>
													{/each}
												</div>
											{/if}
										</div>
									</div>
								{/if}

								{#if selectedCve.patches.length > 0}
									<div class="detail-section">
										<h3 class="detail-section-title">🔧 {$tr('cveLookup.patches')} ({selectedCve.patches.length})</h3>
										<div class="patches-list">
											{#each selectedCve.patches.slice(0, 5) as patch}
												<a href={patch.url} target="_blank" class="patch-link">
													<span class="patch-icon">🔧</span>
													<span class="patch-url">{patch.url}</span>
												</a>
											{/each}
										</div>
									</div>
								{/if}

								{#if selectedCve.references.length > 0}
									<div class="detail-section">
										<h3 class="detail-section-title">🔗 {$tr('cveLookup.references')} ({selectedCve.references.length})</h3>
										<div class="references-list">
											{#each selectedCve.references.slice(0, 10) as ref}
												<div class="reference-item">
													<a href={ref.url} target="_blank" class="ref-link">{ref.url}</a>
													{#if ref.tags.length > 0}
														<div class="ref-tags">
															{#each ref.tags.slice(0, 3) as tag}
																<span class="ref-tag">{tag}</span>
															{/each}
														</div>
													{/if}
												</div>
											{/each}
											{#if selectedCve.references.length > 10}
												<div class="more-refs">+{selectedCve.references.length - 10} {$tr('cveLookup.moreRefs')}</div>
											{/if}
										</div>
									</div>
								{/if}
							</div>
						{/if}
					{:else if processing}
						<div class="processing-state">
							<div class="spinner-large"></div>
							<p>{$tr('cveLookup.searching')}</p>
						</div>
					{:else}
						<div class="empty-state">
							<div class="empty-icon">🛡️</div>
							<p>{$tr('cveLookup.emptyState')}</p>
						</div>
					{/if}
				</div>
			</div>
		</div>
	{:else if activeMainTab === 'history'}
		<div class="section-card">
			<ToolHistory toolType={TOOL_NAME} toolName={$tr('cveLookup.title')} bind:this={historyComponent} />
		</div>
	{:else if activeMainTab === 'help'}
		<div class="section-card">
			<ToolHelp toolType={TOOL_NAME} />
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

	.quick-grid {
		display: grid;
		grid-template-columns: repeat(3, 1fr);
		gap: 0.35rem;
	}

	.quick-btn {
		padding: 0.35rem 0.5rem;
		border: 1px solid rgba(148, 163, 184, 0.15);
		border-radius: 0.4rem;
		background: rgba(15, 23, 42, 0.6);
		color: #94a3b8;
		cursor: pointer;
		font-size: 0.72rem;
		transition: all 0.2s;
		text-align: center;
	}

	.quick-btn:hover:not(:disabled) {
		border-color: rgba(168, 85, 247, 0.3);
		color: #c4b5fd;
		background: rgba(168, 85, 247, 0.08);
	}

	.quick-btn:disabled { opacity: 0.5; cursor: not-allowed; }

	.toggle-btn {
		background: transparent;
		border: none;
		color: #94a3b8;
		cursor: pointer;
		font-size: 0.8rem;
		padding: 0.4rem 0;
		display: flex;
		align-items: center;
		gap: 0.4rem;
		transition: color 0.2s;
	}

	.toggle-btn:hover { color: #c4b5fd; }
	.toggle-arrow { font-size: 0.7rem; }

	.advanced-section {
		padding-top: 0.75rem;
		border-top: 1px solid rgba(148, 163, 184, 0.1);
		margin-top: 0.5rem;
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

	.spinner-large {
		width: 40px;
		height: 40px;
		border: 3px solid rgba(148, 163, 184, 0.15);
		border-top-color: #a855f7;
		border-radius: 50%;
		animation: spin 0.8s linear infinite;
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

	.result-query {
		display: flex;
		align-items: center;
		gap: 0.75rem;
	}

	.duration-badge {
		font-size: 0.7rem;
		color: #94a3b8;
		background: rgba(15, 23, 42, 0.6);
		padding: 0.2rem 0.5rem;
		border-radius: 0.3rem;
		border: 1px solid rgba(148, 163, 184, 0.1);
	}

	.header-actions {
		display: flex;
		gap: 0.5rem;
		align-items: center;
	}

	.export-select {
		padding: 0.35rem 0.5rem;
		border-radius: 0.4rem;
		border: 1px solid rgba(148, 163, 184, 0.15);
		background: rgba(15, 23, 42, 0.6);
		color: #f1f5f9;
		font-size: 0.78rem;
	}

	.btn-export {
		padding: 0.4rem 0.75rem;
		border-radius: 0.4rem;
		border: 1px solid rgba(148, 163, 184, 0.15);
		background: rgba(15, 23, 42, 0.4);
		color: #94a3b8;
		cursor: pointer;
		font-size: 0.8rem;
		transition: all 0.2s;
	}

	.btn-export:hover { border-color: rgba(168, 85, 247, 0.3); color: #c4b5fd; }

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
		grid-template-columns: repeat(5, 1fr);
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

	.subsection-title {
		font-size: 0.9rem;
		font-weight: 600;
		color: #e2e8f0;
		margin: 1rem 0 0.5rem;
	}

	.cvss-bars {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
		margin-bottom: 1rem;
	}

	.cvss-bar-item {
		display: flex;
		align-items: center;
		gap: 0.75rem;
	}

	.cvss-bar-label {
		width: 70px;
		font-size: 0.75rem;
		color: #94a3b8;
		text-align: right;
	}

	.cvss-bar-wrapper {
		flex: 1;
		height: 18px;
		background: rgba(15, 23, 42, 0.6);
		border-radius: 0.3rem;
		overflow: hidden;
		border: 1px solid rgba(148, 163, 184, 0.06);
	}

	.cvss-bar {
		height: 100%;
		border-radius: 0.3rem;
		transition: width 0.3s ease;
		min-width: 0;
	}

	.cvss-bar-count {
		width: 30px;
		text-align: right;
		font-size: 0.8rem;
		color: #cbd5e1;
		font-weight: 600;
	}

	.top-vulns {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
	}

	.vuln-card {
		padding: 0.75rem;
		background: rgba(15, 23, 42, 0.4);
		border: 1px solid rgba(148, 163, 184, 0.08);
		border-radius: 0.5rem;
		cursor: pointer;
		transition: all 0.2s;
	}

	.vuln-card:hover { border-color: rgba(168, 85, 247, 0.3); background: rgba(168, 85, 247, 0.05); }

	.vuln-header {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		margin-bottom: 0.4rem;
	}

	.vuln-id {
		font-weight: 700;
		color: #a855f7;
		font-family: 'SF Mono', 'Fira Code', monospace;
		font-size: 0.88rem;
	}

	.copy-btn {
		background: transparent;
		border: none;
		cursor: pointer;
		font-size: 0.75rem;
		padding: 0.1rem 0.2rem;
		opacity: 0.6;
		transition: opacity 0.2s;
	}

	.copy-btn:hover { opacity: 1; }

	.severity-badge {
		display: inline-block;
		padding: 0.15rem 0.4rem;
		border-radius: 0.25rem;
		font-size: 0.7rem;
		font-weight: 600;
		border: 1px solid;
	}

	.severity-badge.large {
		padding: 0.3rem 0.6rem;
		font-size: 0.82rem;
	}

	.vuln-desc {
		font-size: 0.8rem;
		color: #94a3b8;
		line-height: 1.4;
		margin: 0;
	}

	.vuln-footer {
		display: flex;
		gap: 0.75rem;
		margin-top: 0.4rem;
	}

	.exploit-tag {
		font-size: 0.72rem;
		color: #ef4444;
		background: rgba(239, 68, 68, 0.1);
		padding: 0.1rem 0.4rem;
		border-radius: 0.25rem;
		border: 1px solid rgba(239, 68, 68, 0.2);
	}

	.date-tag {
		font-size: 0.72rem;
		color: #64748b;
	}

	.filter-bar {
		display: flex;
		gap: 0.3rem;
		margin-bottom: 0.75rem;
		flex-wrap: wrap;
	}

	.filter-btn {
		padding: 0.35rem 0.6rem;
		border-radius: 0.3rem;
		border: 1px solid rgba(148, 163, 184, 0.15);
		background: rgba(15, 23, 42, 0.4);
		color: #94a3b8;
		cursor: pointer;
		font-size: 0.72rem;
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

	.cve-list {
		max-height: 600px;
		overflow-y: auto;
	}

	.cve-item {
		padding: 0.75rem;
		border-bottom: 1px solid rgba(148, 163, 184, 0.06);
		cursor: pointer;
		transition: background 0.2s;
	}

	.cve-item:hover { background: rgba(168, 85, 247, 0.05); }

	.cve-header {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		margin-bottom: 0.35rem;
	}

	.cve-id {
		font-weight: 700;
		color: #a855f7;
		text-decoration: none;
		font-family: 'SF Mono', 'Fira Code', monospace;
		font-size: 0.85rem;
	}

	.cve-id:hover { text-decoration: underline; }

	.exploit-badge { font-size: 0.85rem; }

	.cve-desc {
		font-size: 0.8rem;
		line-height: 1.4;
		color: #94a3b8;
		margin: 0 0 0.35rem;
	}

	.cve-meta {
		display: flex;
		gap: 0.5rem;
		flex-wrap: wrap;
	}

	.meta-tag {
		font-size: 0.7rem;
		color: #94a3b8;
		background: rgba(15, 23, 42, 0.6);
		padding: 0.1rem 0.4rem;
		border-radius: 0.25rem;
		border: 1px solid rgba(148, 163, 184, 0.08);
	}

	.detail-header {
		display: flex;
		align-items: center;
		gap: 0.75rem;
		margin-bottom: 1.25rem;
		padding-bottom: 1rem;
		border-bottom: 1px solid rgba(148, 163, 184, 0.1);
	}

	.detail-cve-id {
		font-size: 1.2rem;
		font-weight: 700;
		color: #a855f7;
		text-decoration: none;
		font-family: 'SF Mono', 'Fira Code', monospace;
	}

	.detail-cve-id:hover { text-decoration: underline; }

	.detail-section { margin-bottom: 1.25rem; }

	.detail-section-title {
		font-size: 0.88rem;
		font-weight: 600;
		margin: 0 0 0.5rem;
		color: #e2e8f0;
	}

	.detail-text {
		font-size: 0.85rem;
		line-height: 1.6;
		color: #cbd5e1;
	}

	.detail-grid {
		display: grid;
		grid-template-columns: repeat(2, 1fr);
		gap: 0.75rem;
		margin-bottom: 1.25rem;
	}

	.detail-item {
		padding: 0.75rem;
		background: rgba(15, 23, 42, 0.4);
		border: 1px solid rgba(148, 163, 184, 0.08);
		border-radius: 0.5rem;
	}

	.detail-item.full-width { grid-column: span 2; }

	.detail-label {
		display: block;
		font-size: 0.7rem;
		color: #94a3b8;
		margin-bottom: 0.2rem;
		text-transform: uppercase;
		letter-spacing: 0.05em;
	}

	.detail-value {
		font-size: 0.85rem;
		color: #f1f5f9;
	}

	.mono {
		font-family: 'SF Mono', 'Fira Code', monospace;
		font-size: 0.78rem;
		word-break: break-all;
	}

	.cwe-tags {
		display: flex;
		flex-wrap: wrap;
		gap: 0.4rem;
	}

	.cwe-tag {
		padding: 0.3rem 0.6rem;
		background: rgba(168, 85, 247, 0.1);
		border: 1px solid rgba(168, 85, 247, 0.2);
		border-radius: 0.4rem;
		font-size: 0.8rem;
		color: #c4b5fd;
		text-decoration: none;
		font-family: 'SF Mono', 'Fira Code', monospace;
		transition: all 0.2s;
	}

	.cwe-tag:hover { background: rgba(168, 85, 247, 0.2); color: #e9d5ff; }

	.products-list {
		display: flex;
		flex-direction: column;
		gap: 0.4rem;
	}

	.product-item {
		display: flex;
		gap: 0.75rem;
		padding: 0.5rem 0.6rem;
		background: rgba(15, 23, 42, 0.4);
		border: 1px solid rgba(148, 163, 184, 0.06);
		border-radius: 0.4rem;
		font-size: 0.8rem;
	}

	.product-vendor { color: #94a3b8; min-width: 90px; }
	.product-name { font-weight: 500; color: #f1f5f9; flex: 1; }
	.product-versions { color: #94a3b8; }

	.more-products {
		font-size: 0.75rem;
		color: #64748b;
		text-align: center;
		padding: 0.5rem;
	}

	.exploit-section {
		background: rgba(239, 68, 68, 0.06);
		border: 1px solid rgba(239, 68, 68, 0.15);
		border-radius: 0.5rem;
		padding: 0.75rem;
	}

	.exploit-info {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
	}

	.exploit-stat {
		display: flex;
		justify-content: space-between;
		align-items: center;
	}

	.exploit-label { font-size: 0.8rem; color: #94a3b8; }
	.exploit-value { font-size: 0.8rem; color: #cbd5e1; }
	.exploit-value.danger { color: #ef4444; font-weight: 700; }

	.exploit-sources {
		display: flex;
		flex-wrap: wrap;
		gap: 0.4rem;
		align-items: center;
	}

	.source-tag {
		font-size: 0.7rem;
		padding: 0.15rem 0.4rem;
		background: rgba(239, 68, 68, 0.1);
		border: 1px solid rgba(239, 68, 68, 0.2);
		border-radius: 0.25rem;
		color: #fca5a5;
	}

	.patches-list {
		display: flex;
		flex-direction: column;
		gap: 0.4rem;
	}

	.patch-link {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		padding: 0.5rem 0.6rem;
		background: rgba(15, 23, 42, 0.4);
		border: 1px solid rgba(148, 163, 184, 0.06);
		border-radius: 0.4rem;
		text-decoration: none;
		color: #cbd5e1;
		transition: all 0.2s;
	}

	.patch-link:hover { border-color: rgba(168, 85, 247, 0.3); color: #c4b5fd; }
	.patch-icon { font-size: 0.85rem; }
	.patch-url { font-size: 0.75rem; word-break: break-all; font-family: 'SF Mono', 'Fira Code', monospace; }

	.references-list {
		display: flex;
		flex-direction: column;
		gap: 0.4rem;
	}

	.reference-item {
		padding: 0.5rem 0.6rem;
		background: rgba(15, 23, 42, 0.4);
		border: 1px solid rgba(148, 163, 184, 0.06);
		border-radius: 0.4rem;
	}

	.ref-link {
		font-size: 0.75rem;
		color: #a855f7;
		text-decoration: none;
		word-break: break-all;
		font-family: 'SF Mono', 'Fira Code', monospace;
	}

	.ref-link:hover { color: #c4b5fd; text-decoration: underline; }

	.ref-tags {
		display: flex;
		flex-wrap: wrap;
		gap: 0.3rem;
		margin-top: 0.3rem;
	}

	.ref-tag {
		font-size: 0.65rem;
		padding: 0.1rem 0.3rem;
		background: rgba(148, 163, 184, 0.1);
		border-radius: 0.2rem;
		color: #94a3b8;
	}

	.more-refs {
		font-size: 0.75rem;
		color: #64748b;
		text-align: center;
		padding: 0.5rem;
	}

	.processing-state {
		display: flex;
		flex-direction: column;
		align-items: center;
		justify-content: center;
		padding: 4rem;
		gap: 1rem;
	}

	.processing-state p { color: #94a3b8; font-size: 0.9rem; }

	.empty-state {
		text-align: center;
		padding: 4rem;
	}

	.empty-icon {
		font-size: 3.5rem;
		margin-bottom: 1rem;
		opacity: 0.4;
	}

	.empty-state p { color: #64748b; font-size: 0.9rem; }
</style>
