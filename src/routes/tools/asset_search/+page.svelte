<script lang="ts">
	import { tr } from '$lib/i18n';
	import ToolHistory from '$lib/components/ToolHistory.svelte';
	import ToolHelp from '$lib/components/ToolHelp.svelte';

	interface DiscoveredAsset {
		ip: string;
		port: number;
		protocol: string;
		service: string;
		version: string | null;
		hostname: string | null;
		os: string | null;
		country: string | null;
		city: string | null;
		org: string | null;
		last_seen: string | null;
		vulnerabilities: string[];
		banner: string | null;
		tags: string[];
	}

	interface SearchStatistics {
		total_hosts: number;
		open_ports: Record<string, number>;
		top_services: [string, number][];
		top_countries: [string, number][];
		vulnerable_hosts: number;
	}

	interface AssetSecurityFinding {
		severity: string;
		category: string;
		description: string;
		affected_asset: string;
		recommendation: string;
	}

	interface AssetSearchResult {
		success: boolean;
		query: string;
		engine: string;
		total_results: number;
		assets: DiscoveredAsset[];
		statistics: SearchStatistics;
		security_findings: AssetSecurityFinding[];
		summary: string;
	}

	let query = $state('');
	let searchEngine = $state('shodan');
	let maxResults = $state(50);
	let searchType = $state('host');
	let timeout = $state(30);
	let result: AssetSearchResult | null = $state(null);
	let error = $state('');
	let processing = $state(false);
	let activeMainTab = $state('search');
	let activeResultTab = $state('assets');
	let historyComponent: ToolHistory;

	async function search() {
		if (!query.trim()) { error = $tr('assetSearch.error.queryRequired'); return; }
		processing = true; error = ''; result = null;
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			result = await invoke<AssetSearchResult>('search_assets_command', {
				config: {
					query: query.trim(),
					search_engine: searchEngine,
					api_key: null,
					max_results: maxResults,
					search_type: searchType,
					timeout
				}
			});
			if (result && historyComponent) {
				await historyComponent.saveHistory(query.trim(), JSON.stringify(result), result.summary, 'completed');
			}
		} catch (e: any) {
			error = e.toString();
			if (historyComponent) {
				await historyComponent.saveHistory(query.trim(), '', error, 'failed');
			}
		} finally {
			processing = false;
		}
	}

	function clearAll() { query = ''; result = null; error = ''; }

	function getSeverityColor(s: string): string {
		switch (s) { case 'critical': return '#dc2626'; case 'high': return '#ef4444'; case 'medium': return '#f59e0b'; case 'low': return '#3b82f6'; default: return '#6b7280'; }
	}

	function translateSeverity(s: string): string {
		const key = `assetSearch.severity.${s}`;
		const val = $tr(key);
		return val !== key ? val : s;
	}
</script>

<div class="nd-page">
	<div class="page-header">
		<div class="header-left">
			<a href="/" class="back-link">{$tr('common.backToHome')}</a>
			<h1 class="page-title">🔍 {$tr('assetSearch.title')}</h1>
			<p class="page-subtitle">{$tr('assetSearch.subtitle')}</p>
		</div>
	</div>

	<div class="tabs">
		<button class="tab-btn {activeMainTab === 'search' ? 'active' : ''}" onclick={() => activeMainTab = 'search'}>
			<span class="tab-icon">🔍</span> {$tr('assetSearch.search')}
		</button>
		<button class="tab-btn {activeMainTab === 'history' ? 'active' : ''}" onclick={() => activeMainTab = 'history'}>
			<span class="tab-icon">📋</span> {$tr('assetSearch.history')}
		</button>
		<button class="tab-btn {activeMainTab === 'help' ? 'active' : ''}" onclick={() => activeMainTab = 'help'}>
			<span class="tab-icon">📖</span> {$tr('assetSearch.help')}
		</button>
	</div>

	{#if activeMainTab === 'search'}
		<div class="content-grid">
			<div class="input-section">
				<div class="section-card">
					<h2 class="section-title">{$tr('assetSearch.config.title')}</h2>
					<p class="section-desc">{$tr('assetSearch.config.desc')}</p>

					<div class="form-group">
						<label class="form-label">{$tr('assetSearch.config.query')}</label>
						<input type="text" bind:value={query} placeholder="IP / Domain / Keywords" class="form-input" disabled={processing} />
					</div>

					<div class="form-group">
						<label class="form-label">{$tr('assetSearch.config.engine')}</label>
						<select bind:value={searchEngine} class="form-input" disabled={processing}>
							<option value="shodan">Shodan</option>
							<option value="censys">Censys</option>
							<option value="fofa">FOFA</option>
							<option value="zoomeye">ZoomEye</option>
						</select>
					</div>

					<div class="form-group">
						<label class="form-label">{$tr('assetSearch.config.searchType')}</label>
						<select bind:value={searchType} class="form-input" disabled={processing}>
							<option value="host">{$tr('assetSearch.config.typeHost')}</option>
							<option value="domain">{$tr('assetSearch.config.typeDomain')}</option>
							<option value="service">{$tr('assetSearch.config.typeService')}</option>
							<option value="vuln">{$tr('assetSearch.config.typeVuln')}</option>
						</select>
					</div>

					<div class="form-group">
						<label class="form-label">{$tr('assetSearch.config.maxResults')}</label>
						<input type="number" bind:value={maxResults} min="1" max="500" class="form-input" disabled={processing} />
					</div>

					<div class="form-group">
						<label class="form-label">{$tr('assetSearch.config.timeout')}</label>
						<input type="number" bind:value={timeout} min="5" max="120" class="form-input" disabled={processing} />
					</div>

					<div class="button-group">
						<button class="btn-primary" onclick={search} disabled={processing || !query.trim()}>
							{#if processing}<span class="spinner"></span> {$tr('assetSearch.searching')}{:else}🔍 {$tr('assetSearch.startSearch')}{/if}
						</button>
						<button class="btn-secondary" onclick={clearAll} disabled={processing}>🗑️</button>
					</div>
				</div>
			</div>

			<div class="result-section">
				<div class="section-card">
					<h2 class="section-title">{$tr('assetSearch.result.title')}</h2>
					{#if error}
						<div class="error-card"><div class="error-icon">⚠️</div><div class="error-text">{error}</div></div>
					{:else if result}
						<div class="summary-banner">
							<div class="summary-info">
								<span class="engine-badge">{result.engine.toUpperCase()}</span>
								<span class="query-text">{result.query}</span>
							</div>
							<div class="summary-badges">
								<span class="summary-badge purple">{result.total_results} {$tr('assetSearch.result.assets')}</span>
								<span class="summary-badge red">{result.security_findings.filter(f => f.severity === 'high').length} {$tr('assetSearch.result.highRisk')}</span>
							</div>
						</div>

						<div class="result-tabs">
							<button class="result-tab {activeResultTab === 'assets' ? 'active' : ''}" onclick={() => activeResultTab = 'assets'}>🌐 {$tr('assetSearch.tabs.assets')} ({result.assets.length})</button>
							<button class="result-tab {activeResultTab === 'stats' ? 'active' : ''}" onclick={() => activeResultTab = 'stats'}>📊 {$tr('assetSearch.tabs.stats')}</button>
							<button class="result-tab {activeResultTab === 'findings' ? 'active' : ''}" onclick={() => activeResultTab = 'findings'}>🛡️ {$tr('assetSearch.tabs.findings')} ({result.security_findings.length})</button>
						</div>

						{#if activeResultTab === 'assets'}
							<div class="items-list">
								{#each result.assets as asset}
									<div class="item-card" style="border-left-color: {asset.vulnerabilities.length > 0 ? '#ef4444' : '#a855f7'}">
										<div class="item-header">
											<span class="asset-endpoint">{asset.ip}:{asset.port}</span>
											<span class="protocol-badge">{asset.protocol}</span>
											<span class="service-name">{asset.service}</span>
											{#if asset.vulnerabilities.length > 0}
												<span class="vuln-badge">{asset.vulnerabilities.length} CVE</span>
											{/if}
										</div>
										<div class="asset-meta">
											{#if asset.version}<span>{$tr('assetSearch.asset.version')}: {asset.version}</span>{/if}
											{#if asset.hostname}<span>{$tr('assetSearch.asset.hostname')}: {asset.hostname}</span>{/if}
											{#if asset.os}<span>{$tr('assetSearch.asset.os')}: {asset.os}</span>{/if}
											{#if asset.country}<span>{$tr('assetSearch.asset.location')}: {asset.city || ''}{asset.city && asset.country ? ', ' : ''}{asset.country}</span>{/if}
											{#if asset.org}<span>{$tr('assetSearch.asset.org')}: {asset.org}</span>{/if}
											{#if asset.last_seen}<span>{$tr('assetSearch.asset.lastSeen')}: {asset.last_seen}</span>{/if}
										</div>
										{#if asset.vulnerabilities.length > 0}
											<div class="tag-list">
												{#each asset.vulnerabilities as vuln}
													<span class="vuln-tag">{vuln}</span>
												{/each}
											</div>
										{/if}
										{#if asset.tags.length > 0}
											<div class="tag-list">
												{#each asset.tags as tag}
													<span class="info-tag">{tag}</span>
												{/each}
											</div>
										{/if}
									</div>
								{/each}
								{#if result.assets.length === 0}
									<div class="empty-item">{$tr('assetSearch.status.noAssets')}</div>
								{/if}
							</div>
						{:else if activeResultTab === 'stats'}
							<div class="stats-grid">
								<div class="stat-card" style="border-color: rgba(168, 85, 247, 0.3);">
									<span class="stat-label">🌐 {$tr('assetSearch.stats.totalHosts')}</span>
									<span class="stat-value" style="color: #c4b5fd;">{result.statistics.total_hosts}</span>
								</div>
								<div class="stat-card" style="border-color: rgba(239, 68, 68, 0.3);">
									<span class="stat-label">⚠️ {$tr('assetSearch.stats.vulnerableHosts')}</span>
									<span class="stat-value" style="color: #fca5a5;">{result.statistics.vulnerable_hosts}</span>
								</div>
								<div class="stat-card" style="border-color: rgba(34, 197, 94, 0.3);">
									<span class="stat-label">🔌 {$tr('assetSearch.stats.portTypes')}</span>
									<span class="stat-value" style="color: #86efac;">{Object.keys(result.statistics.open_ports).length}</span>
								</div>
								<div class="stat-card" style="border-color: rgba(245, 158, 11, 0.3);">
									<span class="stat-label">🛡️ {$tr('assetSearch.stats.findings')}</span>
									<span class="stat-value" style="color: #fcd34d;">{result.security_findings.length}</span>
								</div>
							</div>

							{#if result.statistics.top_services.length > 0}
								<div class="detail-card">
									<h3 class="subsection-title">🔧 {$tr('assetSearch.stats.topServices')}</h3>
									<div class="bar-list">
										{#each result.statistics.top_services as [svc, count]}
											<div class="bar-row">
												<span class="bar-label">{svc}</span>
												<div class="bar-track">
													<div class="bar-fill purple" style="width: {Math.min(100, (count / result.statistics.total_hosts) * 100)}%"></div>
												</div>
												<span class="bar-count">{count}</span>
											</div>
										{/each}
									</div>
								</div>
							{/if}

							{#if result.statistics.top_countries.length > 0}
								<div class="detail-card">
									<h3 class="subsection-title">🌍 {$tr('assetSearch.stats.countryDist')}</h3>
									<div class="bar-list">
										{#each result.statistics.top_countries as [country, count]}
											<div class="bar-row">
												<span class="bar-label">{country}</span>
												<div class="bar-track">
													<div class="bar-fill green" style="width: {Math.min(100, (count / result.statistics.total_hosts) * 100)}%"></div>
												</div>
												<span class="bar-count">{count}</span>
											</div>
										{/each}
									</div>
								</div>
							{/if}
						{:else if activeResultTab === 'findings'}
							<div class="items-list">
								{#each result.security_findings as finding}
									<div class="item-card" style="border-left-color: {getSeverityColor(finding.severity)}">
										<div class="item-header">
											<span class="severity-badge" style="background: {getSeverityColor(finding.severity)}">{translateSeverity(finding.severity)}</span>
											<span class="item-title">{finding.category}</span>
										</div>
										<p class="item-desc">{finding.description}</p>
										<p class="item-meta">{$tr('assetSearch.finding.affected')}: {finding.affected_asset}</p>
										{#if finding.recommendation}
											<p class="item-rec">💡 {finding.recommendation}</p>
										{/if}
									</div>
								{/each}
								{#if result.security_findings.length === 0}
									<div class="empty-item">{$tr('assetSearch.status.noFindings')}</div>
								{/if}
							</div>
						{/if}
					{:else}
						<div class="empty-state">
							<div class="empty-icon">🔍</div>
							<p>{$tr('assetSearch.result.noResults')}</p>
						</div>
					{/if}
				</div>
			</div>
		</div>
	{:else if activeMainTab === 'history'}
		<div class="section-card"><ToolHistory toolType="asset_search" toolName={$tr('assetSearch.title')} bind:this={historyComponent} /></div>
	{:else if activeMainTab === 'help'}
		<div class="section-card"><ToolHelp toolType="asset_search" /></div>
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
	.input-section { position: sticky; top: 1.5rem; align-self: start; max-height: calc(100vh - 3rem); overflow-y: auto; }
	.result-section { min-width: 0; }

	.section-card { background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(168, 85, 247, 0.15); border-radius: 0.75rem; padding: 1.25rem; }
	.section-title { font-size: 1rem; font-weight: 600; color: #f1f5f9; margin: 0 0 1rem; }
	.section-desc { font-size: 0.8rem; color: #94a3b8; margin: 0.25rem 0 0; }

	.form-group { margin-bottom: 0.75rem; }
	.form-label { display: block; font-size: 0.75rem; color: #94a3b8; margin-bottom: 0.3rem; font-weight: 500; text-transform: uppercase; letter-spacing: 0.05em; }
	.form-input { width: 100%; padding: 0.55rem 0.75rem; border-radius: 0.5rem; border: 1px solid rgba(148, 163, 184, 0.15); background: rgba(15, 23, 42, 0.8); color: #f1f5f9; font-size: 0.85rem; box-sizing: border-box; transition: border-color 0.2s; }
	.form-input:focus { outline: none; border-color: #a855f7; box-shadow: 0 0 0 2px rgba(168, 85, 247, 0.15); }
	.form-input::placeholder { color: #475569; }

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

	.summary-banner { display: flex; align-items: center; justify-content: space-between; padding: 0.75rem 1rem; background: rgba(15, 23, 42, 0.4); border: 1px solid rgba(148, 163, 184, 0.08); border-radius: 0.75rem; margin-bottom: 1rem; }
	.summary-info { display: flex; align-items: center; gap: 0.75rem; }
	.engine-badge { padding: 0.2rem 0.6rem; background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%); border-radius: 0.3rem; font-size: 0.7rem; font-weight: 700; color: white; letter-spacing: 0.05em; }
	.query-text { font-size: 0.85rem; color: #f1f5f9; font-weight: 500; }
	.summary-badges { display: flex; gap: 0.5rem; }
	.summary-badge { padding: 0.25rem 0.6rem; border-radius: 0.4rem; font-size: 0.75rem; font-weight: 600; }
	.summary-badge.purple { background: rgba(168, 85, 247, 0.15); color: #c4b5fd; border: 1px solid rgba(168, 85, 247, 0.3); }
	.summary-badge.red { background: rgba(239, 68, 68, 0.15); color: #fca5a5; border: 1px solid rgba(239, 68, 68, 0.3); }

	.result-tabs { display: flex; gap: 0.25rem; margin-bottom: 1rem; flex-wrap: wrap; }
	.result-tab { padding: 0.4rem 0.75rem; border-radius: 0.4rem; border: 1px solid rgba(148, 163, 184, 0.15); background: rgba(15, 23, 42, 0.4); color: #94a3b8; cursor: pointer; font-size: 0.8rem; transition: all 0.2s; }
	.result-tab.active { background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%); color: white; border-color: transparent; font-weight: 600; }
	.result-tab:hover:not(.active) { border-color: rgba(168, 85, 247, 0.3); color: #c4b5fd; }

	.items-list { display: flex; flex-direction: column; gap: 0.5rem; }
	.item-card { padding: 0.75rem; background: rgba(15, 23, 42, 0.4); border: 1px solid rgba(148, 163, 184, 0.08); border-radius: 0.5rem; border-left: 3px solid; }
	.item-header { display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.3rem; flex-wrap: wrap; }
	.item-title { font-weight: 600; font-size: 0.85rem; color: #f1f5f9; }
	.item-desc { font-size: 0.8rem; color: #94a3b8; margin-top: 0.3rem; }
	.item-meta { font-size: 0.75rem; color: #94a3b8; margin-top: 0.2rem; }
	.item-rec { font-size: 0.8rem; color: #86efac; margin-top: 0.3rem; }

	.asset-endpoint { font-family: 'SF Mono', 'Fira Code', monospace; font-weight: 600; font-size: 0.85rem; color: #c4b5fd; }
	.protocol-badge { padding: 0.1rem 0.4rem; background: rgba(148, 163, 184, 0.15); border-radius: 0.25rem; font-size: 0.7rem; color: #94a3b8; text-transform: uppercase; }
	.service-name { font-size: 0.85rem; font-weight: 500; color: #f1f5f9; }
	.vuln-badge { padding: 0.1rem 0.4rem; background: rgba(239, 68, 68, 0.15); border: 1px solid rgba(239, 68, 68, 0.3); border-radius: 0.25rem; font-size: 0.7rem; color: #fca5a5; font-weight: 600; }
	.asset-meta { display: grid; grid-template-columns: repeat(2, 1fr); gap: 0.15rem 0.5rem; font-size: 0.75rem; color: #94a3b8; margin-top: 0.3rem; }

	.severity-badge { padding: 0.15rem 0.5rem; border-radius: 0.3rem; color: white; font-size: 0.7rem; font-weight: 600; text-transform: uppercase; }

	.tag-list { display: flex; flex-wrap: wrap; gap: 0.25rem; margin-top: 0.3rem; }
	.vuln-tag { padding: 0.1rem 0.4rem; background: rgba(239, 68, 68, 0.1); color: #fca5a5; border-radius: 0.2rem; font-size: 0.7rem; }
	.info-tag { padding: 0.1rem 0.4rem; background: rgba(168, 85, 247, 0.1); color: #c4b5fd; border-radius: 0.2rem; font-size: 0.7rem; }

	.stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 0.75rem; margin-bottom: 1rem; }
	.stat-card { display: flex; flex-direction: column; align-items: center; padding: 0.75rem; background: rgba(15, 23, 42, 0.4); border: 1px solid rgba(148, 163, 184, 0.08); border-radius: 0.5rem; border-top: 2px solid; }
	.stat-label { font-size: 0.7rem; color: #94a3b8; margin-bottom: 0.25rem; }
	.stat-value { font-size: 1.25rem; font-weight: 700; }

	.detail-card { background: rgba(15, 23, 42, 0.4); border: 1px solid rgba(148, 163, 184, 0.08); border-radius: 0.5rem; padding: 0.75rem; margin-bottom: 0.75rem; }
	.subsection-title { font-size: 0.9rem; font-weight: 600; color: #e2e8f0; margin: 0 0 0.5rem; }

	.bar-list { display: flex; flex-direction: column; gap: 0.4rem; }
	.bar-row { display: flex; align-items: center; gap: 0.5rem; }
	.bar-label { font-size: 0.8rem; color: #94a3b8; width: 8rem; flex-shrink: 0; }
	.bar-track { flex: 1; background: rgba(15, 23, 42, 0.8); border-radius: 0.25rem; height: 1rem; overflow: hidden; }
	.bar-fill { height: 100%; border-radius: 0.25rem; transition: width 0.3s; }
	.bar-fill.purple { background: linear-gradient(90deg, #a855f7, #6366f1); }
	.bar-fill.green { background: linear-gradient(90deg, #22c55e, #16a34a); }
	.bar-count { font-size: 0.75rem; color: #94a3b8; width: 2rem; text-align: right; }

	.empty-item { text-align: center; padding: 1.5rem; color: #94a3b8; font-size: 0.85rem; }
	.empty-state { text-align: center; padding: 2.5rem 1rem; color: #94a3b8; }
	.empty-icon { font-size: 2.5rem; margin-bottom: 0.75rem; }
	.empty-state p { font-size: 0.85rem; margin: 0; }

	.input-section::-webkit-scrollbar { width: 4px; }
	.input-section::-webkit-scrollbar-track { background: transparent; }
	.input-section::-webkit-scrollbar-thumb { background: rgba(168, 85, 247, 0.3); border-radius: 2px; }
	.items-list::-webkit-scrollbar { width: 4px; }
	.items-list::-webkit-scrollbar-track { background: transparent; }
	.items-list::-webkit-scrollbar-thumb { background: rgba(168, 85, 247, 0.3); border-radius: 2px; }

	@media (max-width: 768px) {
		.content-grid { grid-template-columns: 1fr; }
		.input-section { position: static; max-height: none; }
		.stats-grid { grid-template-columns: repeat(2, 1fr); }
		.summary-banner { flex-direction: column; align-items: flex-start; gap: 0.5rem; }
		.asset-meta { grid-template-columns: 1fr; }
	}
	@media (max-width: 480px) {
		.nd-page { padding: 0.75rem; }
		.stats-grid { grid-template-columns: 1fr; }
		.tabs { flex-wrap: wrap; }
		.tab-btn { font-size: 0.8rem; padding: 0.5rem 0.75rem; }
		.result-tabs { gap: 0.15rem; }
		.result-tab { font-size: 0.75rem; padding: 0.3rem 0.5rem; }
	}
</style>
