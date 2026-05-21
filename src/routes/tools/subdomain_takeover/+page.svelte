<script lang="ts">
	import { tr } from '$lib/i18n';
	import ToolHistory from '$lib/components/ToolHistory.svelte';
	import ToolHelp from '$lib/components/ToolHelp.svelte';

	interface TakeoverEntry {
		subdomain: string;
		cname: string | null;
		is_vulnerable: boolean;
		is_potentially_vulnerable: boolean;
		service: string | null;
		service_category: string | null;
		evidence: string;
		fingerprint: string | null;
		confidence: number;
		http_status: number | null;
		http_title: string | null;
		response_time_ms: number | null;
		ip_addresses: string[];
	}

	interface ServiceDistribution {
		service: string;
		category: string;
		count: number;
		vulnerable_count: number;
	}

	interface TakeoverResult {
		domain: string;
		checked_subdomains: number;
		vulnerable: TakeoverEntry[];
		potentially_vulnerable: TakeoverEntry[];
		safe: TakeoverEntry[];
		errors: TakeoverEntry[];
		scan_duration_ms: number;
		summary: string;
		service_distribution: ServiceDistribution[];
	}

	let domain = $state('');
	let activeMainTab = $state('analyze');
	let historyComponent: ToolHistory;
	let subdomains = $state('');
	let timeout = $state(10);
	let threads = $state(10);
	let scanMode = $state('normal');
	let checkCname = $state(true);
	let checkHttp = $state(true);
	let checkDnsDangling = $state(true);
	let result: TakeoverResult | null = $state(null);
	let error = $state('');
	let processing = $state(false);
	let activeResultTab = $state('overview');
	let searchQuery = $state('');
	let filterCategory = $state('all');
	let exportFormat = $state('json');
	let exporting = $state(false);
	let progressDots = $state(0);
	let progressTimer: ReturnType<typeof setInterval> | null = null;

	$effect(() => {
		if (processing) {
			progressDots = 0;
			progressTimer = setInterval(() => {
				progressDots = (progressDots + 1) % 4;
			}, 500);
		} else {
			if (progressTimer) { clearInterval(progressTimer); progressTimer = null; }
		}
		return () => { if (progressTimer) { clearInterval(progressTimer); progressTimer = null; } };
	});

	function getScanModeLabel(mode: string): string {
		switch (mode) {
			case 'quick': return $tr('subdomainTakeover.modeQuick');
			case 'normal': return $tr('subdomainTakeover.modeNormal');
			case 'deep': return $tr('subdomainTakeover.modeDeep');
			default: return mode;
		}
	}

	function getScanModeDesc(mode: string): string {
		switch (mode) {
			case 'quick': return $tr('subdomainTakeover.modeQuickDesc');
			case 'normal': return $tr('subdomainTakeover.modeNormalDesc');
			case 'deep': return $tr('subdomainTakeover.modeDeepDesc');
			default: return '';
		}
	}

	function applyScanMode(mode: string) {
		scanMode = mode;
	}

	function getCategoryColor(cat: string): string {
		const colors: Record<string, string> = {
			'Hosting': '#3b82f6',
			'Cloud': '#8b5cf6',
			'CDN': '#06b6d4',
			'SaaS': '#f59e0b',
			'CMS': '#10b981',
			'Commerce': '#ec4899',
			'Payment': '#ef4444',
		};
		return colors[cat] || '#94a3b8';
	}

	function getConfidenceColor(conf: number): string {
		if (conf >= 0.9) return '#ef4444';
		if (conf >= 0.7) return '#f59e0b';
		if (conf >= 0.5) return '#eab308';
		return '#94a3b8';
	}

	function getConfidenceLabel(conf: number): string {
		if (conf >= 0.9) return $tr('subdomainTakeover.confidenceHigh');
		if (conf >= 0.7) return $tr('subdomainTakeover.confidenceMedium');
		if (conf >= 0.5) return $tr('subdomainTakeover.confidenceLow');
		return $tr('subdomainTakeover.confidenceUnknown');
	}

	function getFilteredVulnerable(): TakeoverEntry[] {
		if (!result) return [];
		return result.vulnerable.filter((e: TakeoverEntry) => {
			if (filterCategory !== 'all' && e.service_category !== filterCategory) return false;
			if (searchQuery && !e.subdomain.toLowerCase().includes(searchQuery.toLowerCase()) && !(e.cname || '').toLowerCase().includes(searchQuery.toLowerCase()) && !(e.service || '').toLowerCase().includes(searchQuery.toLowerCase())) return false;
			return true;
		});
	}

	function getFilteredPotentiallyVulnerable(): TakeoverEntry[] {
		if (!result) return [];
		return result.potentially_vulnerable.filter((e: TakeoverEntry) => {
			if (filterCategory !== 'all' && e.service_category !== filterCategory) return false;
			if (searchQuery && !e.subdomain.toLowerCase().includes(searchQuery.toLowerCase()) && !(e.cname || '').toLowerCase().includes(searchQuery.toLowerCase())) return false;
			return true;
		});
	}

	function getSubdomainCount(): number {
		const customList = subdomains ? subdomains.split(/[\n,;]+/).map((s: string) => s.trim()).filter((s: string) => s) : [];
		if (customList.length > 0) return customList.length;
		switch (scanMode) {
			case 'quick': return 16;
			case 'deep': return 180;
			default: return 48;
		}
	}

	function getCategories(): string[] {
		if (!result) return [];
		const cats = new Set<string>();
		for (const e of result.vulnerable) { if (e.service_category) cats.add(e.service_category); }
		for (const e of result.potentially_vulnerable) { if (e.service_category) cats.add(e.service_category); }
		return Array.from(cats);
	}

	function formatDuration(ms: number): string {
		if (ms < 1000) return `${ms}ms`;
		return `${(ms / 1000).toFixed(1)}s`;
	}

	async function importSubdomainsFromFile() {
		try {
			const { open } = await import('@tauri-apps/plugin-dialog');
			const selected = await open({
				multiple: false,
				filters: [{ name: 'Text', extensions: ['txt', 'csv', 'list'] }],
			});
			if (!selected) return;
			const filePath = typeof selected === 'string' ? selected : (selected as any).path || String(selected);
			const { readTextFile } = await import('@tauri-apps/plugin-fs');
			const content = await readTextFile(filePath);
			const lines = content.split(/[\r\n,;]+/).map(s => s.trim()).filter(s => s && !s.startsWith('#'));
			if (lines.length > 0) {
				const existing = subdomains ? subdomains.split(/[\n,;]+/).map(s => s.trim()).filter(s => s) : [];
				const merged = [...new Set([...existing, ...lines])];
				subdomains = merged.join('\n');
			}
		} catch (e: any) {
			console.error('Import failed:', e);
		}
	}

	async function check() {
		if (!domain.trim()) { error = $tr('subdomainTakeover.errors.domainRequired'); return; }
		if (!checkCname && !checkHttp && !checkDnsDangling) { error = $tr('subdomainTakeover.errors.noOptionSelected'); return; }
		processing = true; error = ''; result = null; activeResultTab = 'overview';
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			const subList = subdomains ? subdomains.split(/[\n,;]+/).map((s: string) => s.trim()).filter((s: string) => s) : [];
			result = await invoke<TakeoverResult>('check_subdomain_takeover_command', {
				config: {
					domain: domain.trim(),
					timeout,
					threads,
					scan_mode: scanMode,
					check_cname: checkCname,
					check_http: checkHttp,
					check_dns_dangling: checkDnsDangling,
					subdomains: subList,
				}
			});
			if (result && historyComponent) {
				await historyComponent.saveHistory(domain.trim(), JSON.stringify(result), result.summary, 'completed');
			}
		} catch (e: any) { error = e.toString(); }
		finally { processing = false; }
	}

	async function exportResult() {
		if (!result) return;
		exporting = true;
		try {
			const { save } = await import('@tauri-apps/plugin-dialog');
			const savePath = await save({
				defaultPath: `takeover-result-${new Date().toISOString().slice(0, 10)}.${exportFormat}`,
				filters: [{ name: exportFormat.toUpperCase(), extensions: [exportFormat] }],
			});
			if (!savePath) { exporting = false; return; }
			const content = exportFormat === 'json'
				? JSON.stringify(result, null, 2)
				: convertToCsv(result);
			const { writeTextFile } = await import('@tauri-apps/plugin-fs');
			await writeTextFile(savePath as string, content);
		} catch (e: any) {
			console.error('Export failed:', e);
		} finally { exporting = false; }
	}

	function convertToCsv(data: TakeoverResult): string {
		const headers = ['Subdomain', 'CNAME', 'Vulnerable', 'Potentially Vulnerable', 'Service', 'Category', 'Confidence', 'HTTP Status', 'Fingerprint', 'Evidence'];
		const rows: string[][] = [];
		for (const e of [...data.vulnerable, ...data.potentially_vulnerable, ...data.safe]) {
			rows.push([
				e.subdomain, e.cname || '', String(e.is_vulnerable), String(e.is_potentially_vulnerable),
				e.service || '', e.service_category || '', String(e.confidence),
				e.http_status ? String(e.http_status) : '', e.fingerprint || '', e.evidence,
			]);
		}
		return [headers, ...rows].map(r => r.map(c => `"${c.replace(/"/g, '""')}"`).join(',')).join('\n');
	}

	function clearAll() {
		domain = ''; subdomains = ''; result = null; error = '';
		searchQuery = ''; filterCategory = 'all'; activeResultTab = 'overview';
	}
</script>

<div class="nd-page">
	<div class="page-header">
		<div class="header-left">
			<a href="/" class="back-link">{$tr('common.backToHome')}</a>
			<h1 class="page-title">🔓 {$tr('subdomainTakeover.title')}</h1>
			<p class="page-subtitle">{$tr('subdomainTakeover.subtitle')}</p>
		</div>
	</div>

	<div class="tabs">
		<button class="tab-btn {activeMainTab === 'analyze' ? 'active' : ''}" onclick={() => activeMainTab = 'analyze'}>
			<span class="tab-icon">🔍</span> {$tr('subdomainTakeover.check')}
		</button>
		<button class="tab-btn {activeMainTab === 'history' ? 'active' : ''}" onclick={() => activeMainTab = 'history'}>
			<span class="tab-icon">📋</span> {$tr('subdomainTakeover.history')}
		</button>
		<button class="tab-btn {activeMainTab === 'help' ? 'active' : ''}" onclick={() => activeMainTab = 'help'}>
			<span class="tab-icon">📖</span> {$tr('subdomainTakeover.help')}
		</button>
	</div>

	{#if activeMainTab === 'analyze'}
		<div class="content-grid">
			<div class="input-section">
				<div class="section-card">
					<h2 class="section-title">{$tr('subdomainTakeover.configTitle')}</h2>
					<p class="section-desc">{$tr('subdomainTakeover.configDesc')}</p>

					<div class="form-group">
						<label class="form-label">{$tr('subdomainTakeover.targetDomain')}</label>
						<input type="text" bind:value={domain} placeholder="example.com" class="form-input" disabled={processing} onkeydown={(e) => e.key === 'Enter' && check()} />
					</div>

					<div class="form-group">
						<label class="form-label">{$tr('subdomainTakeover.scanMode')}</label>
						<div class="mode-grid">
							{#each ['quick', 'normal', 'deep'] as mode}
								<button class="mode-btn {scanMode === mode ? 'active' : ''}" onclick={() => applyScanMode(mode)} disabled={processing}>
									<span class="mode-name">{getScanModeLabel(mode)}</span>
									<span class="mode-desc">{getScanModeDesc(mode)}</span>
								</button>
							{/each}
						</div>
						<div class="subdomain-count-hint">
							{$tr('subdomainTakeover.subdomainCount', { count: getSubdomainCount() })}
						</div>
					</div>

					<div class="form-row">
						<div class="form-group">
							<label class="form-label">{$tr('subdomainTakeover.timeout')}</label>
							<input type="number" bind:value={timeout} class="form-input" min="5" max="60" disabled={processing} />
						</div>
						<div class="form-group">
							<label class="form-label">{$tr('subdomainTakeover.threads')}</label>
							<input type="number" bind:value={threads} class="form-input" min="1" max="50" disabled={processing} />
						</div>
					</div>

					<div class="form-group">
						<label class="form-label">{$tr('subdomainTakeover.detectionOptions')}</label>
						<div class="target-grid">
							<label class="target-chip {checkCname ? 'active' : ''}">
								<input type="checkbox" bind:checked={checkCname} disabled={processing} />
								<span>🔗 {$tr('subdomainTakeover.checkCname')}</span>
							</label>
							<label class="target-chip {checkHttp ? 'active' : ''}">
								<input type="checkbox" bind:checked={checkHttp} disabled={processing} />
								<span>🌐 {$tr('subdomainTakeover.checkHttp')}</span>
							</label>
							<label class="target-chip {checkDnsDangling ? 'active' : ''}">
								<input type="checkbox" bind:checked={checkDnsDangling} disabled={processing} />
								<span>⚠️ {$tr('subdomainTakeover.checkDnsDangling')}</span>
							</label>
						</div>
					</div>

					<div class="form-group">
						<label class="form-label">{$tr('subdomainTakeover.customSubdomains')}</label>
						<div class="textarea-with-actions">
							<textarea bind:value={subdomains} placeholder={$tr('subdomainTakeover.subdomainsPlaceholder')} class="form-textarea" rows="3" disabled={processing}></textarea>
							<button class="btn-import" onclick={importSubdomainsFromFile} disabled={processing} title={$tr('subdomainTakeover.importFromFile')}>
								📁
							</button>
						</div>
					</div>

					<div class="button-group">
						<button class="btn-primary" onclick={check} disabled={processing || !domain.trim() || (!checkCname && !checkHttp && !checkDnsDangling)}>
							{#if processing}<span class="spinner"></span>{$tr('subdomainTakeover.checking')}{:else}🔓 {$tr('subdomainTakeover.startCheck')}{/if}
						</button>
						<button class="btn-secondary" onclick={clearAll} disabled={processing}>🗑️</button>
					</div>
				</div>
			</div>

			<div class="result-section">
				<div class="section-card">
					{#if processing}
						<div class="progress-state">
							<div class="progress-icon-ring">
								<span class="progress-icon">🔍</span>
							</div>
							<div class="progress-text">
								{$tr('subdomainTakeover.checking')}{'.'.repeat(progressDots)}
							</div>
							<div class="progress-sub">
								{$tr('subdomainTakeover.scanningSubdomains', { domain: domain.trim(), mode: getScanModeLabel(scanMode) })}
							</div>
							<div class="progress-bar-track">
								<div class="progress-bar-fill"></div>
							</div>
						</div>
					{:else if error}
						<div class="error-card">
							<span class="error-icon">⚠️</span>
							<span class="error-text">{error}</span>
						</div>
					{:else if result}
						<div class="result-header">
							<div class="result-domain">
								<h2 class="section-title" style="margin-bottom:0">🔓 {result.domain}</h2>
							</div>
							<div class="header-actions">
								<div class="resource-score-badge">
									<span class="score-value">{result.vulnerable.length}</span>
									<span class="score-label">{$tr('subdomainTakeover.vulnerable')}</span>
								</div>
								<select bind:value={exportFormat} class="export-select" disabled={exporting}>
									<option value="json">JSON</option>
									<option value="csv">CSV</option>
								</select>
								<button class="btn-export" onclick={exportResult} disabled={exporting || !result}>
									{#if exporting}<span class="spinner-sm"></span>{:else}📤{/if}
									{$tr('subdomainTakeover.export')}
								</button>
							</div>
						</div>

						<div class="summary-bar">
							{result.summary} | {$tr('subdomainTakeover.scanDuration')}: {formatDuration(result.scan_duration_ms)}
						</div>

						<div class="result-tabs">
							<button class="result-tab {activeResultTab === 'overview' ? 'active' : ''}" onclick={() => activeResultTab = 'overview'}>
								<span>📊</span> {$tr('subdomainTakeover.tabOverview')}
							</button>
							<button class="result-tab {activeResultTab === 'vulnerable' ? 'active' : ''}" onclick={() => activeResultTab = 'vulnerable'}>
								<span>🔓</span> {$tr('subdomainTakeover.tabVulnerable')} ({result.vulnerable.length})
							</button>
							<button class="result-tab {activeResultTab === 'potential' ? 'active' : ''}" onclick={() => activeResultTab = 'potential'}>
								<span>⚠️</span> {$tr('subdomainTakeover.tabPotential')} ({result.potentially_vulnerable.length})
							</button>
							<button class="result-tab {activeResultTab === 'safe' ? 'active' : ''}" onclick={() => activeResultTab = 'safe'}>
								<span>✅</span> {$tr('subdomainTakeover.tabSafe')} ({result.safe.length})
							</button>
							{#if result.errors && result.errors.length > 0}
								<button class="result-tab {activeResultTab === 'errors' ? 'active' : ''}" onclick={() => activeResultTab = 'errors'}>
									<span>❌</span> {$tr('subdomainTakeover.tabErrors')} ({result.errors.length})
								</button>
							{/if}
						</div>

						{#if activeResultTab === 'overview'}
							<div class="overview-grid" style="grid-template-columns: repeat(5, 1fr);">
								<div class="overview-stat">
									<span class="stat-label">{$tr('subdomainTakeover.checked')}</span>
									<span class="stat-value">{result.checked_subdomains}</span>
								</div>
								<div class="overview-stat" style="border-color: rgba(239,68,68,0.3)">
									<span class="stat-label">{$tr('subdomainTakeover.vulnerable')}</span>
									<span class="stat-value" style="color:#ef4444">{result.vulnerable.length}</span>
								</div>
								<div class="overview-stat" style="border-color: rgba(245,158,11,0.3)">
									<span class="stat-label">{$tr('subdomainTakeover.potentiallyVulnerable')}</span>
									<span class="stat-value" style="color:#f59e0b">{result.potentially_vulnerable.length}</span>
								</div>
								<div class="overview-stat" style="border-color: rgba(34,197,94,0.3)">
									<span class="stat-label">{$tr('subdomainTakeover.safe')}</span>
									<span class="stat-value" style="color:#22c55e">{result.safe.length}</span>
								</div>
								<div class="overview-stat" style="border-color: rgba(148,163,184,0.3); cursor: pointer;" onclick={() => { if (result?.errors?.length) activeResultTab = 'errors'; }}>
									<span class="stat-label">❌ {$tr('subdomainTakeover.tabErrors')}</span>
									<span class="stat-value" style="color:#94a3b8">{result.errors?.length ?? 0}</span>
								</div>
							</div>

							{#if result.service_distribution.length > 0}
								<div class="subsection-title">{$tr('subdomainTakeover.serviceDistribution')}</div>
								<div class="distribution-grid">
									{#each result.service_distribution as dist}
										<div class="distribution-item">
											<div class="dist-header">
												<span class="dist-service" style="color: {getCategoryColor(dist.category)}">{dist.service}</span>
												<span class="dist-category" style="background: {getCategoryColor(dist.category)}20; color: {getCategoryColor(dist.category)}">{dist.category}</span>
											</div>
											<div class="dist-stats">
												<span class="dist-count">{dist.count} {$tr('subdomainTakeover.total')}</span>
												{#if dist.vulnerable_count > 0}
													<span class="dist-vuln">{dist.vulnerable_count} {$tr('subdomainTakeover.vulnerable')}</span>
												{/if}
											</div>
										</div>
									{/each}
								</div>
							{/if}

							{#if result.vulnerable.length > 0}
								<div class="subsection-title">🔓 {$tr('subdomainTakeover.topVulnerable')}</div>
								<div class="vuln-list">
									{#each result.vulnerable.slice(0, 5) as entry}
										<div class="takeover-item vulnerable">
											<div class="item-header">
												<span class="item-subdomain">🔓 {entry.subdomain}</span>
												{#if entry.service}<span class="service-badge" style="background: {getCategoryColor(entry.service_category || '')}20; color: {getCategoryColor(entry.service_category || '')}">{entry.service}</span>{/if}
												<span class="confidence-badge" style="color: {getConfidenceColor(entry.confidence)}">{(entry.confidence * 100).toFixed(0)}%</span>
											</div>
											{#if entry.cname}<div class="item-detail">CNAME: <span class="mono">{entry.cname}</span></div>{/if}
											<div class="item-meta">
												{#if entry.http_status}<span class="meta-tag">HTTP {entry.http_status}</span>{/if}
												{#if entry.response_time_ms != null}<span class="meta-tag">⏱ {entry.response_time_ms}ms</span>{/if}
											</div>
											<div class="item-detail">{entry.evidence}</div>
										</div>
									{/each}
								</div>
							{/if}

						{:else if activeResultTab === 'vulnerable'}
							<div class="filter-bar">
								<select bind:value={filterCategory} class="filter-select">
									<option value="all">{$tr('subdomainTakeover.allCategories')}</option>
									{#each getCategories() as cat}
										<option value={cat}>{cat}</option>
									{/each}
								</select>
								<input type="text" bind:value={searchQuery} placeholder={$tr('subdomainTakeover.searchPlaceholder')} class="search-input" />
							</div>

							{#if getFilteredVulnerable().length > 0}
								<div class="vuln-list">
									{#each getFilteredVulnerable() as entry}
										<div class="takeover-item vulnerable">
											<div class="item-header">
												<span class="item-subdomain">🔓 {entry.subdomain}</span>
												{#if entry.service}<span class="service-badge" style="background: {getCategoryColor(entry.service_category || '')}20; color: {getCategoryColor(entry.service_category || '')}">{entry.service}</span>{/if}
												<span class="confidence-badge" style="color: {getConfidenceColor(entry.confidence)}">{getConfidenceLabel(entry.confidence)} ({(entry.confidence * 100).toFixed(0)}%)</span>
											</div>
											{#if entry.cname}<div class="item-detail">CNAME: <span class="mono">{entry.cname}</span></div>{/if}
											{#if entry.ip_addresses.length > 0}<div class="item-detail">IP: <span class="mono">{entry.ip_addresses.join(', ')}</span></div>{/if}
											<div class="item-meta">
												{#if entry.http_status}<span class="meta-tag" style="color: {entry.http_status >= 400 ? '#ef4444' : '#22c55e'}">HTTP {entry.http_status}</span>{/if}
												{#if entry.response_time_ms != null}<span class="meta-tag">⏱ {entry.response_time_ms}ms</span>{/if}
												{#if entry.http_title}<span class="meta-tag">📄 {entry.http_title}</span>{/if}
											</div>
											{#if entry.fingerprint}<div class="item-detail">{$tr('subdomainTakeover.fingerprint')}: <span class="mono">{entry.fingerprint}</span></div>{/if}
											<div class="item-detail">{entry.evidence}</div>
										</div>
									{/each}
								</div>
							{:else}
								<div class="empty-state">
									<div class="empty-icon">✅</div>
									<p>{$tr('subdomainTakeover.noVulnerable')}</p>
								</div>
							{/if}

						{:else if activeResultTab === 'potential'}
							<div class="filter-bar">
								<select bind:value={filterCategory} class="filter-select">
									<option value="all">{$tr('subdomainTakeover.allCategories')}</option>
									{#each getCategories() as cat}
										<option value={cat}>{cat}</option>
									{/each}
								</select>
								<input type="text" bind:value={searchQuery} placeholder={$tr('subdomainTakeover.searchPlaceholder')} class="search-input" />
							</div>

							{#if getFilteredPotentiallyVulnerable().length > 0}
								<div class="vuln-list">
									{#each getFilteredPotentiallyVulnerable() as entry}
										<div class="takeover-item potential">
											<div class="item-header">
												<span class="item-subdomain">⚠️ {entry.subdomain}</span>
												{#if entry.service}<span class="service-badge" style="background: {getCategoryColor(entry.service_category || '')}20; color: {getCategoryColor(entry.service_category || '')}">{entry.service}</span>{/if}
												<span class="confidence-badge" style="color: {getConfidenceColor(entry.confidence)}">{(entry.confidence * 100).toFixed(0)}%</span>
											</div>
											{#if entry.cname}<div class="item-detail">CNAME: <span class="mono">{entry.cname}</span></div>{/if}
											<div class="item-meta">
												{#if entry.http_status}<span class="meta-tag" style="color: #f59e0b">HTTP {entry.http_status}</span>{/if}
												{#if entry.response_time_ms != null}<span class="meta-tag">⏱ {entry.response_time_ms}ms</span>{/if}
											</div>
											<div class="item-detail">{entry.evidence}</div>
										</div>
									{/each}
								</div>
							{:else}
								<div class="empty-state">
									<div class="empty-icon">✅</div>
									<p>{$tr('subdomainTakeover.noPotential')}</p>
								</div>
							{/if}

						{:else if activeResultTab === 'safe'}
							<div class="search-bar">
								<input type="text" bind:value={searchQuery} placeholder={$tr('subdomainTakeover.searchPlaceholder')} class="search-input" />
							</div>
							<div class="safe-list">
								{#each result.safe.filter((e: TakeoverEntry) => !searchQuery || e.subdomain.toLowerCase().includes(searchQuery.toLowerCase())).slice(0, 50) as entry}
									<div class="takeover-item safe">
										<span class="safe-name">✅ {entry.subdomain}</span>
										{#if entry.cname}<span class="safe-cname">CNAME: {entry.cname}</span>{/if}
										<span class="safe-status">{entry.evidence}</span>
									</div>
								{/each}
								{#if result.safe.length > 50}
									<div class="more-link">+{result.safe.length - 50} {$tr('subdomainTakeover.more')}</div>
								{/if}
							</div>

						{:else if activeResultTab === 'errors'}
							<div class="search-bar">
								<input type="text" bind:value={searchQuery} placeholder={$tr('subdomainTakeover.searchPlaceholder')} class="search-input" />
							</div>
							<div class="vuln-list">
								{#each (result.errors || []).filter((e: TakeoverEntry) => !searchQuery || e.subdomain.toLowerCase().includes(searchQuery.toLowerCase())) as entry}
									<div class="takeover-item error-item">
										<div class="item-header">
											<span class="item-subdomain">❌ {entry.subdomain}</span>
										</div>
										<div class="item-detail">{entry.evidence}</div>
									</div>
								{/each}
								{#if !result.errors || result.errors.length === 0}
									<div class="empty-state">
										<div class="empty-icon">✅</div>
										<p>{$tr('subdomainTakeover.noErrors')}</p>
									</div>
								{/if}
							</div>
						{/if}
					{:else}
						<div class="empty-state">
							<div class="empty-icon">🔓</div>
							<p>{$tr('subdomainTakeover.noResults')}</p>
						</div>
					{/if}
				</div>
			</div>
		</div>
	{:else if activeMainTab === 'history'}
		<div class="section-card">
			<ToolHistory toolType="subdomain_takeover" toolName={$tr('subdomainTakeover.title')} bind:this={historyComponent} />
		</div>
	{:else if activeMainTab === 'help'}
		<div class="section-card">
			<ToolHelp toolType="subdomain_takeover" />
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

	.form-input, .form-textarea {
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

	.form-input:focus, .form-textarea:focus {
		outline: none;
		border-color: #a855f7;
		box-shadow: 0 0 0 2px rgba(168, 85, 247, 0.15);
	}

	.form-input::placeholder, .form-textarea::placeholder { color: #475569; }
	.form-textarea { resize: vertical; font-family: monospace; font-size: 0.8rem; }

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

	.mode-name { display: block; font-size: 0.8rem; font-weight: 600; }
	.mode-desc { display: block; font-size: 0.65rem; opacity: 0.7; margin-top: 0.1rem; }

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

	.textarea-with-actions {
		position: relative;
	}

	.textarea-with-actions .form-textarea {
		padding-right: 2.5rem;
	}

	.btn-import {
		position: absolute;
		right: 0.5rem;
		bottom: 0.5rem;
		padding: 0.3rem 0.5rem;
		border-radius: 0.3rem;
		border: 1px solid rgba(168, 85, 247, 0.3);
		background: rgba(168, 85, 247, 0.1);
		color: #c4b5fd;
		cursor: pointer;
		font-size: 0.85rem;
		transition: all 0.2s;
		z-index: 1;
	}

	.btn-import:hover:not(:disabled) { background: rgba(168, 85, 247, 0.2); }
	.btn-import:disabled { opacity: 0.5; cursor: not-allowed; }

	.progress-state {
		display: flex;
		flex-direction: column;
		align-items: center;
		justify-content: center;
		padding: 3rem 1rem;
		text-align: center;
	}

	.progress-icon-ring {
		width: 4rem;
		height: 4rem;
		border-radius: 50%;
		border: 2px solid rgba(168, 85, 247, 0.3);
		display: flex;
		align-items: center;
		justify-content: center;
		margin-bottom: 1rem;
		animation: pulse-ring 1.5s ease-in-out infinite;
	}

	.progress-icon { font-size: 1.5rem; }

	@keyframes pulse-ring {
		0%, 100% { border-color: rgba(168, 85, 247, 0.3); transform: scale(1); }
		50% { border-color: rgba(168, 85, 247, 0.7); transform: scale(1.05); }
	}

	.progress-text {
		font-size: 1rem;
		font-weight: 600;
		color: #f1f5f9;
		margin-bottom: 0.4rem;
	}

	.progress-sub {
		font-size: 0.8rem;
		color: #94a3b8;
		margin-bottom: 1rem;
	}

	.progress-bar-track {
		width: 60%;
		max-width: 300px;
		height: 4px;
		background: rgba(148, 163, 184, 0.15);
		border-radius: 2px;
		overflow: hidden;
	}

	.progress-bar-fill {
		height: 100%;
		width: 30%;
		background: linear-gradient(90deg, #a855f7, #6366f1);
		border-radius: 2px;
		animation: progress-slide 1.5s ease-in-out infinite;
	}

	@keyframes progress-slide {
		0% { transform: translateX(-100%); }
		100% { transform: translateX(400%); }
	}

	.btn-view-errors {
		padding: 0.2rem 0.5rem;
		border-radius: 0.3rem;
		border: 1px solid rgba(168, 85, 247, 0.3);
		background: rgba(168, 85, 247, 0.1);
		color: #c4b5fd;
		cursor: pointer;
		font-size: 0.7rem;
		transition: all 0.2s;
	}

	.btn-view-errors:hover { background: rgba(168, 85, 247, 0.2); }

	.takeover-item.error-item {
		background: rgba(148, 163, 184, 0.04);
		border-color: rgba(148, 163, 184, 0.15);
	}

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
		border: 1px solid rgba(239, 68, 68, 0.3);
		background: rgba(239, 68, 68, 0.1);
	}

	.score-value {
		font-size: 1.5rem;
		font-weight: 700;
		color: #ef4444;
		line-height: 1;
	}

	.score-label {
		font-size: 0.65rem;
		color: #ef4444;
		opacity: 0.8;
		margin-top: 0.2rem;
	}

	.export-select {
		padding: 0.4rem 0.6rem;
		border-radius: 0.4rem;
		border: 1px solid rgba(148, 163, 184, 0.15);
		background: rgba(15, 23, 42, 0.6);
		color: #f1f5f9;
		font-size: 0.8rem;
	}

	.btn-export {
		padding: 0.4rem 0.75rem;
		border-radius: 0.4rem;
		border: 1px solid rgba(168, 85, 247, 0.3);
		background: rgba(168, 85, 247, 0.1);
		color: #c4b5fd;
		cursor: pointer;
		font-size: 0.8rem;
		display: flex;
		align-items: center;
		gap: 0.3rem;
		transition: all 0.2s;
	}

	.btn-export:hover:not(:disabled) { background: rgba(168, 85, 247, 0.2); }
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

	.subsection-title {
		font-size: 0.9rem;
		font-weight: 600;
		color: #e2e8f0;
		margin: 1rem 0 0.5rem;
	}

	.distribution-grid {
		display: grid;
		grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
		gap: 0.5rem;
		margin-bottom: 1rem;
	}

	.distribution-item {
		padding: 0.6rem 0.75rem;
		background: rgba(15, 23, 42, 0.4);
		border: 1px solid rgba(148, 163, 184, 0.08);
		border-radius: 0.5rem;
	}

	.dist-header {
		display: flex;
		align-items: center;
		justify-content: space-between;
		margin-bottom: 0.3rem;
	}

	.dist-service {
		font-size: 0.85rem;
		font-weight: 600;
	}

	.dist-category {
		font-size: 0.65rem;
		padding: 0.1rem 0.4rem;
		border-radius: 0.2rem;
		font-weight: 500;
	}

	.dist-stats {
		display: flex;
		gap: 0.75rem;
		font-size: 0.75rem;
		color: #94a3b8;
	}

	.dist-vuln { color: #ef4444; }

	.vuln-list {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
	}

	.takeover-item {
		padding: 0.75rem;
		border-radius: 0.5rem;
		border: 1px solid;
	}

	.takeover-item.vulnerable {
		background: rgba(239, 68, 68, 0.06);
		border-color: rgba(239, 68, 68, 0.2);
	}

	.takeover-item.potential {
		background: rgba(245, 158, 11, 0.06);
		border-color: rgba(245, 158, 11, 0.2);
	}

	.takeover-item.safe {
		background: rgba(15, 23, 42, 0.3);
		border-color: rgba(148, 163, 184, 0.08);
		display: flex;
		align-items: center;
		gap: 0.5rem;
		flex-wrap: wrap;
		padding: 0.5rem 0.75rem;
		font-size: 0.8rem;
	}

	.item-header {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		margin-bottom: 0.4rem;
		flex-wrap: wrap;
	}

	.item-subdomain {
		font-weight: 600;
		font-size: 0.9rem;
		color: #f1f5f9;
	}

	.service-badge {
		padding: 0.15rem 0.5rem;
		border-radius: 0.25rem;
		font-size: 0.7rem;
		font-weight: 600;
	}

	.confidence-badge {
		font-size: 0.7rem;
		font-weight: 600;
		padding: 0.1rem 0.4rem;
		border-radius: 0.2rem;
		background: rgba(15, 23, 42, 0.6);
	}

	.item-detail {
		font-size: 0.8rem;
		color: #94a3b8;
		margin-top: 0.2rem;
	}

	.item-meta {
		display: flex;
		gap: 0.5rem;
		flex-wrap: wrap;
		margin-top: 0.25rem;
	}

	.meta-tag {
		font-size: 0.72rem;
		color: #94a3b8;
		background: rgba(15, 23, 42, 0.6);
		padding: 0.1rem 0.4rem;
		border-radius: 0.2rem;
		border: 1px solid rgba(148, 163, 184, 0.1);
	}

	.subdomain-count-hint {
		font-size: 0.72rem;
		color: #64748b;
		margin-top: 0.35rem;
	}

	.mono {
		font-family: 'SF Mono', 'Fira Code', monospace;
		font-size: 0.78rem;
		color: #c4b5fd;
	}

	.status-badge {
		font-weight: 600;
		font-family: 'SF Mono', 'Fira Code', monospace;
		font-size: 0.78rem;
	}

	.filter-bar {
		display: flex;
		gap: 0.5rem;
		margin-bottom: 0.75rem;
		flex-wrap: wrap;
	}

	.filter-select {
		padding: 0.4rem 0.6rem;
		border-radius: 0.4rem;
		border: 1px solid rgba(148, 163, 184, 0.15);
		background: rgba(15, 23, 42, 0.6);
		color: #f1f5f9;
		font-size: 0.8rem;
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

	.safe-list {
		max-height: 400px;
		overflow-y: auto;
		display: flex;
		flex-direction: column;
		gap: 0.3rem;
	}

	.safe-name { color: #cbd5e1; font-weight: 500; }
	.safe-cname { color: #94a3b8; font-size: 0.75rem; }
	.safe-status { color: #64748b; font-size: 0.75rem; }

	.more-link {
		padding: 0.4rem 0.6rem;
		color: #a855f7;
		cursor: pointer;
		font-size: 0.8rem;
		text-align: center;
	}

	.empty-state {
		text-align: center;
		padding: 3rem;
		color: #94a3b8;
	}

	.empty-icon {
		font-size: 3rem;
		margin-bottom: 0.75rem;
		opacity: 0.5;
	}

	@media (max-width: 768px) {
		.content-grid {
			grid-template-columns: 1fr;
		}
		.overview-grid {
			grid-template-columns: repeat(2, 1fr) !important;
		}
		.mode-grid {
			grid-template-columns: 1fr;
		}
	}
</style>
