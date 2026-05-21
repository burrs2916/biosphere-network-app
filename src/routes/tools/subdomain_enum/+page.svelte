<script lang="ts">
	import { tr } from '$lib/i18n';
	import ToolHistory from '$lib/components/ToolHistory.svelte';
	import ToolHelp from '$lib/components/ToolHelp.svelte';

	interface SubdomainEntry {
		subdomain: string;
		ip_addresses: string[];
		ipv6_addresses: string[];
		source: string;
		is_alive: boolean;
		category: string;
		http_status: number | null;
		http_title: string | null;
		response_time_ms: number | null;
	}

	interface SubdomainCategory {
		name: string;
		count: number;
		subdomains: string[];
	}

	interface SubdomainResult {
		domain: string;
		subdomains: SubdomainEntry[];
		total_found: number;
		alive_count: number;
		dead_count: number;
		scan_duration_ms: number;
		sources_used: string[];
		summary: string;
		categories: SubdomainCategory[];
	}

	let domain = $state('');
	let activeMainTab = $state('analyze');
	let historyComponent: ToolHistory = $state(null!);
	let timeout = $state(15);
	let threads = $state(50);
	let scanMode = $state('normal');
	let useCt = $state(true);
	let useBruteforce = $state(true);
	let useHttpProbe = $state(false);
	let checkAlive = $state(true);
	let result: SubdomainResult | null = $state(null);
	let error = $state('');
	let processing = $state(false);
	let activeResultTab = $state('overview');
	let searchQuery = $state('');
	let filterCategory = $state('all');
	let filterAlive = $state(false);
	let exportFormat = $state('json');
	let exporting = $state(false);
	let showTargetSelector = $state(false);
	let targetList: any[] = $state([]);
	let selectedTargets: any[] = $state([]);
	let selectedTargetIds: number[] = $state([]);
	let targetSearchQuery = $state('');
	let loadingTargets = $state(false);

	function getScanModeLabel(mode: string): string {
		switch (mode) {
			case 'quick': return $tr('subdomainEnum.modeQuick');
			case 'normal': return $tr('subdomainEnum.modeNormal');
			case 'deep': return $tr('subdomainEnum.modeDeep');
			default: return mode;
		}
	}

	function getScanModeDesc(mode: string): string {
		switch (mode) {
			case 'quick': return $tr('subdomainEnum.modeQuickDesc');
			case 'normal': return $tr('subdomainEnum.modeNormalDesc');
			case 'deep': return $tr('subdomainEnum.modeDeepDesc');
			default: return '';
		}
	}

	function applyScanMode(mode: string) {
		scanMode = mode;
	}

	function getFilteredSubdomains(): SubdomainEntry[] {
		if (!result) return [];
		return result.subdomains.filter((s: SubdomainEntry) => {
			if (filterAlive && !s.is_alive) return false;
			if (filterCategory !== 'all' && s.category !== filterCategory) return false;
			if (searchQuery && !s.subdomain.toLowerCase().includes(searchQuery.toLowerCase()) && !s.ip_addresses.join(',').includes(searchQuery)) return false;
			return true;
		});
	}

	function getAliveCount(): number {
		return result ? result.alive_count : 0;
	}

	function getDeadCount(): number {
		return result ? result.dead_count : 0;
	}

	function getCategoryColor(cat: string): string {
		const colors: Record<string, string> = {
			'Web': '#3b82f6',
			'Mail': '#f59e0b',
			'DNS': '#8b5cf6',
			'CDN/Static': '#06b6d4',
			'API': '#10b981',
			'Development': '#f97316',
			'Production': '#ef4444',
			'Database': '#ec4899',
			'Admin': '#a855f7',
			'Security/Auth': '#6366f1',
			'DevOps': '#14b8a6',
			'Monitoring': '#84cc16',
			'Storage': '#0ea5e9',
			'Commerce': '#d946ef',
			'Content': '#22d3ee',
			'Internal': '#fb923c',
			'Infrastructure': '#64748b',
			'Other': '#94a3b8',
		};
		return colors[cat] || '#94a3b8';
	}

	async function enumerate() {
		if (!domain.trim()) { error = $tr('subdomainEnum.errors.domainRequired'); return; }
		processing = true; error = ''; result = null;
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			result = await invoke<SubdomainResult>('enumerate_subdomains_command', {
				config: {
					domain: domain.trim(),
					timeout,
					threads,
					scan_mode: scanMode,
					use_certificate_transparency: useCt,
					use_dns_bruteforce: useBruteforce,
					use_http_probe: useHttpProbe,
					check_alive: checkAlive,
					wordlist: []
				},
				targetId: selectedTargetIds.length > 0 ? selectedTargetIds[0] : null
			});
		} catch (e: any) { error = e.toString(); }
		finally { processing = false; }
	}

	async function exportResult() {
		if (!result) return;
		exporting = true;
		try {
			const { save } = await import('@tauri-apps/plugin-dialog');
			const { writeTextFile } = await import('@tauri-apps/plugin-fs');
			const filePath = await save({
				defaultPath: `subdomain_enum_${new Date().toISOString().slice(0, 10)}.${exportFormat}`,
				filters: [{ name: exportFormat.toUpperCase(), extensions: [exportFormat] }]
			});
			if (filePath) {
				let content: string;
				if (exportFormat === 'json') {
					content = JSON.stringify(result, null, 2);
				} else {
					const headers = ['Subdomain', 'IP Addresses', 'IPv6', 'Source', 'Alive', 'Category', 'HTTP Status', 'Title', 'Response Time(ms)'];
					const rows = result.subdomains.map((s: SubdomainEntry) => [
						s.subdomain, s.ip_addresses.join(';'), s.ipv6_addresses.join(';'),
						s.source, s.is_alive ? 'Yes' : 'No', s.category,
						s.http_status?.toString() || '', s.http_title || '',
						s.response_time_ms?.toString() || ''
					]);
					content = [headers, ...rows].map(r => r.map(c => `"${c.replace(/"/g, '""')}"`).join(',')).join('\n');
				}
				await writeTextFile(filePath, content);
			}
		} catch (e) {
			console.error('Export failed:', e);
		} finally {
			exporting = false;
		}
	}

	function clearAll() {
		domain = ''; result = null; error = '';
		searchQuery = ''; filterCategory = 'all'; filterAlive = false;
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
			domain = domain ? `${domain}\n${targetValues}` : targetValues;
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
			<h1 class="page-title">🌐 {$tr('subdomainEnum.title')}</h1>
			<p class="page-subtitle">{$tr('subdomainEnum.subtitle')}</p>
		</div>
	</div>

	<div class="tabs">
		<button class="tab-btn {activeMainTab === 'analyze' ? 'active' : ''}" onclick={() => activeMainTab = 'analyze'}>
			<span class="tab-icon">🔍</span> {$tr('subdomainEnum.enumerate')}
		</button>
		<button class="tab-btn {activeMainTab === 'history' ? 'active' : ''}" onclick={() => activeMainTab = 'history'}>
			<span class="tab-icon">📋</span> {$tr('subdomainEnum.history')}
		</button>
		<button class="tab-btn {activeMainTab === 'help' ? 'active' : ''}" onclick={() => activeMainTab = 'help'}>
			<span class="tab-icon">📖</span> {$tr('subdomainEnum.help')}
		</button>
	</div>

	{#if activeMainTab === 'analyze'}
		<div class="content-grid">
			<div class="input-section">
				<div class="section-card">
					<h2 class="section-title">{$tr('subdomainEnum.configTitle')}</h2>
					<p class="section-desc">{$tr('subdomainEnum.configDesc')}</p>

					<div class="form-group">
						<label class="form-label">{$tr('subdomainEnum.targetDomain')}</label>
						<div class="input-with-action">
							<input type="text" bind:value={domain} placeholder="example.com" class="form-input" disabled={processing} onkeydown={(e) => e.key === 'Enter' && enumerate()} />
							<button type="button" class="action-btn" onclick={openTargetSelectorModal} disabled={processing} title={$tr('common.selectTarget')}>
								🎯
							</button>
						</div>
					</div>

					<div class="form-group">
						<label class="form-label">{$tr('subdomainEnum.scanMode')}</label>
						<div class="mode-grid">
							{#each ['quick', 'normal', 'deep'] as mode}
								<button class="mode-btn {scanMode === mode ? 'active' : ''}" onclick={() => applyScanMode(mode)} disabled={processing}>
									<span class="mode-name">{getScanModeLabel(mode)}</span>
									<span class="mode-desc">{getScanModeDesc(mode)}</span>
								</button>
							{/each}
						</div>
					</div>

					<div class="form-row">
						<div class="form-group">
							<label class="form-label">{$tr('subdomainEnum.timeout')}</label>
							<input type="number" bind:value={timeout} class="form-input" min="5" max="60" disabled={processing} />
						</div>
						<div class="form-group">
							<label class="form-label">{$tr('subdomainEnum.threads')}</label>
							<input type="number" bind:value={threads} class="form-input" min="1" max="200" disabled={processing} />
						</div>
					</div>

					<div class="form-group">
						<label class="form-label">{$tr('subdomainEnum.detectionOptions')}</label>
						<div class="target-grid">
							<label class="target-chip {useCt ? 'active' : ''}">
								<input type="checkbox" bind:checked={useCt} disabled={processing} />
								<span>📜 {$tr('subdomainEnum.ctLogs')}</span>
							</label>
							<label class="target-chip {useBruteforce ? 'active' : ''}">
								<input type="checkbox" bind:checked={useBruteforce} disabled={processing} />
								<span>🔨 {$tr('subdomainEnum.dnsBruteforce')}</span>
							</label>
							<label class="target-chip {useHttpProbe ? 'active' : ''}">
								<input type="checkbox" bind:checked={useHttpProbe} disabled={processing} />
								<span>🌐 {$tr('subdomainEnum.httpProbe')}</span>
							</label>
							<label class="target-chip {checkAlive ? 'active' : ''}">
								<input type="checkbox" bind:checked={checkAlive} disabled={processing} />
								<span>💚 {$tr('subdomainEnum.checkAlive')}</span>
							</label>
						</div>
					</div>

					<div class="button-group">
						<button class="btn-primary" onclick={enumerate} disabled={processing || !domain.trim()}>
							{#if processing}<span class="spinner"></span>{:else}🌐{/if}
							{#if processing}{$tr('subdomainEnum.enumerating')}{:else}{$tr('subdomainEnum.enumerate')}{/if}
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
								<h2 class="section-title" style="margin-bottom:0">🌐 {result.domain}</h2>
							</div>
							<div class="header-actions">
								<div class="resource-score-badge">
									<span class="score-value">{result.total_found}</span>
									<span class="score-label">{$tr('subdomainEnum.subdomainsFound')}</span>
								</div>
								<select bind:value={exportFormat} class="export-select" disabled={exporting}>
									<option value="json">JSON</option>
									<option value="csv">CSV</option>
								</select>
								<button class="btn-export" onclick={exportResult} disabled={exporting || !result}>
									{#if exporting}<span class="spinner-sm"></span>{:else}📤{/if}
									{$tr('subdomainEnum.export')}
								</button>
							</div>
						</div>

						<div class="summary-bar">
							{result.summary} | {$tr('subdomainEnum.sources')}: {result.sources_used.join(', ')}
						</div>

						<div class="result-tabs">
							<button class="result-tab {activeResultTab === 'overview' ? 'active' : ''}" onclick={() => activeResultTab = 'overview'}>
								<span>📊</span> {$tr('subdomainEnum.tabOverview')}
							</button>
							<button class="result-tab {activeResultTab === 'subdomains' ? 'active' : ''}" onclick={() => activeResultTab = 'subdomains'}>
								<span>🌐</span> {$tr('subdomainEnum.tabSubdomains')}
							</button>
							<button class="result-tab {activeResultTab === 'categories' ? 'active' : ''}" onclick={() => activeResultTab = 'categories'}>
								<span>🏷️</span> {$tr('subdomainEnum.tabCategories')}
							</button>
						</div>

						{#if activeResultTab === 'overview'}
							<div class="overview-grid">
								<div class="overview-stat">
									<span class="stat-label">🌐 {$tr('subdomainEnum.totalFound')}</span>
									<span class="stat-value" style="color: #a855f7">{result.total_found}</span>
								</div>
								<div class="overview-stat">
									<span class="stat-label">💚 {$tr('subdomainEnum.alive')}</span>
									<span class="stat-value" style="color: {getAliveCount() > 0 ? '#22c55e' : '#64748b'}">{getAliveCount()}</span>
								</div>
								<div class="overview-stat">
									<span class="stat-label">🔴 {$tr('subdomainEnum.dead')}</span>
									<span class="stat-value" style="color: {getDeadCount() > 0 ? '#ef4444' : '#64748b'}">{getDeadCount()}</span>
								</div>
								<div class="overview-stat">
									<span class="stat-label">⏱️ {$tr('subdomainEnum.scanDuration')}</span>
									<span class="stat-value" style="color: #3b82f6">{(result.scan_duration_ms / 1000).toFixed(1)}s</span>
								</div>
							</div>

							{#if result.categories.length > 0}
								<h3 class="subsection-title">{$tr('subdomainEnum.categoryDistribution')}</h3>
								<div class="category-grid">
									{#each result.categories as cat}
										<div class="category-card" onclick={() => { filterCategory = cat.name; activeResultTab = 'subdomains'; }}>
											<div class="category-header">
												<span class="category-dot" style="background: {getCategoryColor(cat.name)}"></span>
												<span class="category-name">{cat.name}</span>
											</div>
											<span class="category-count">{cat.count}</span>
										</div>
									{/each}
								</div>
							{/if}

							{#if result.subdomains.filter((s: SubdomainEntry) => s.is_alive).length > 0}
								<h3 class="subsection-title">{$tr('subdomainEnum.topAliveSubdomains')}</h3>
								<div class="top-list">
									{#each result.subdomains.filter((s: SubdomainEntry) => s.is_alive).slice(0, 10) as entry}
										<div class="top-item">
											<span class="top-status alive">🟢</span>
											<span class="top-name">{entry.subdomain}</span>
											<span class="top-ip">{entry.ip_addresses[0] || '-'}</span>
											<span class="top-category" style="color: {getCategoryColor(entry.category)}">{entry.category}</span>
										</div>
									{/each}
								</div>
							{/if}

						{:else if activeResultTab === 'subdomains'}
							<div class="filter-bar">
								<div class="filter-left">
									<label class="target-chip {filterAlive ? 'active' : ''}" style="cursor:pointer">
										<input type="checkbox" bind:checked={filterAlive} />
										<span>💚 {$tr('subdomainEnum.aliveOnly')}</span>
									</label>
									<select bind:value={filterCategory} class="filter-select">
										<option value="all">{$tr('subdomainEnum.allCategories')}</option>
										{#each result.categories as cat}
											<option value={cat.name}>{cat.name} ({cat.count})</option>
										{/each}
									</select>
								</div>
								<div class="filter-right">
									<input type="text" bind:value={searchQuery} placeholder="{$tr('subdomainEnum.searchPlaceholder')}" class="search-input" />
									<span class="result-count">{getFilteredSubdomains().length}/{result.subdomains.length}</span>
								</div>
							</div>

							{#if getFilteredSubdomains().length > 0}
								<div class="subdomain-list">
									{#each getFilteredSubdomains() as entry}
										<div class="subdomain-item" class:alive={entry.is_alive} class:dead={!entry.is_alive}>
											<div class="subdomain-header">
												<span class="subdomain-status">{entry.is_alive ? '🟢' : '🔴'}</span>
												<span class="subdomain-name">{entry.subdomain}</span>
												<span class="category-badge" style="background: {getCategoryColor(entry.category)}20; color: {getCategoryColor(entry.category)}; border: 1px solid {getCategoryColor(entry.category)}40">{entry.category}</span>
												<span class="source-badge">{entry.source}</span>
											</div>
											<div class="subdomain-details">
												<span class="ip-list">IP: {entry.ip_addresses.join(', ') || '-'}</span>
												{#if entry.ipv6_addresses.length > 0}
													<span class="ipv6-list">IPv6: {entry.ipv6_addresses.join(', ')}</span>
												{/if}
												{#if entry.http_status}
													<span class="http-info">HTTP {entry.http_status} {entry.response_time_ms ? `(${entry.response_time_ms}ms)` : ''}</span>
												{/if}
												{#if entry.http_title}
													<span class="http-title">"{entry.http_title}"</span>
												{/if}
											</div>
										</div>
									{/each}
								</div>
							{:else}
								<div class="empty-state">
									<div class="empty-icon">🔍</div>
									<p>{$tr('subdomainEnum.noSubdomainsFound')}</p>
								</div>
							{/if}

						{:else if activeResultTab === 'categories'}
							{#if result.categories.length > 0}
								<div class="categories-detail">
									{#each result.categories as cat}
										<div class="category-detail-card">
											<div class="category-detail-header">
												<span class="category-dot" style="background: {getCategoryColor(cat.name)}"></span>
												<span class="category-detail-name">{cat.name}</span>
												<span class="category-detail-count">{cat.count} {$tr('subdomainEnum.subdomainsFound')}</span>
											</div>
											<div class="category-subdomains">
												{#each cat.subdomains as sub}
													<span class="subdomain-chip" style="border-color: {getCategoryColor(cat.name)}40">{sub}</span>
												{/each}
											</div>
										</div>
									{/each}
								</div>
							{:else}
								<div class="empty-state">
									<div class="empty-icon">🏷️</div>
									<p>{$tr('subdomainEnum.noCategories')}</p>
								</div>
							{/if}
						{/if}
					{:else}
						<div class="empty-state">
							<div class="empty-icon">🌐</div>
							<p>{$tr('subdomainEnum.noResults')}</p>
						</div>
					{/if}
				</div>
			</div>
		</div>
	{:else if activeMainTab === 'history'}
		<div class="section-card">
			<ToolHistory toolType="subdomain_enum" toolName={$tr('subdomainEnum.title')} bind:this={historyComponent} />
		</div>
	{:else if activeMainTab === 'help'}
		<div class="section-card">
			<ToolHelp toolType="subdomain_enum" />
		</div>
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

	.subsection-title {
		font-size: 0.9rem;
		font-weight: 600;
		color: #e2e8f0;
		margin: 1rem 0 0.5rem;
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

	.mode-name { display: block; font-size: 0.8rem; font-weight: 500; }
	.mode-desc { display: block; font-size: 0.65rem; opacity: 0.7; margin-top: 2px; }

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

	.btn-export:hover:not(:disabled) {
		background: rgba(168, 85, 247, 0.2);
		border-color: rgba(168, 85, 247, 0.5);
	}

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
		font-size: 1.5rem;
		font-weight: 700;
		line-height: 1;
	}

	.category-grid {
		display: grid;
		grid-template-columns: repeat(auto-fill, minmax(120px, 1fr));
		gap: 0.5rem;
		margin-bottom: 1rem;
	}

	.category-card {
		display: flex;
		flex-direction: column;
		align-items: center;
		padding: 0.6rem;
		background: rgba(15, 23, 42, 0.4);
		border: 1px solid rgba(148, 163, 184, 0.08);
		border-radius: 0.5rem;
		cursor: pointer;
		transition: all 0.2s;
	}

	.category-card:hover {
		border-color: rgba(168, 85, 247, 0.3);
		background: rgba(168, 85, 247, 0.05);
	}

	.category-header {
		display: flex;
		align-items: center;
		gap: 0.3rem;
	}

	.category-dot {
		width: 0.5rem;
		height: 0.5rem;
		border-radius: 50%;
	}

	.category-name {
		font-size: 0.75rem;
		color: #e2e8f0;
	}

	.category-count {
		font-size: 1.2rem;
		font-weight: 700;
		color: #a855f7;
		margin-top: 0.25rem;
	}

	.top-list {
		display: flex;
		flex-direction: column;
		gap: 0.35rem;
	}

	.top-item {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		padding: 0.4rem 0.6rem;
		background: rgba(15, 23, 42, 0.4);
		border-radius: 0.4rem;
		border: 1px solid rgba(148, 163, 184, 0.08);
		font-size: 0.8rem;
	}

	.top-status { font-size: 0.7rem; }
	.top-name { flex: 1; color: #f1f5f9; font-family: monospace; font-size: 0.8rem; }
	.top-ip { color: #94a3b8; font-family: monospace; font-size: 0.75rem; }
	.top-category { font-size: 0.7rem; }

	.filter-bar {
		display: flex;
		justify-content: space-between;
		align-items: center;
		margin-bottom: 0.75rem;
		flex-wrap: wrap;
		gap: 0.5rem;
	}

	.filter-left {
		display: flex;
		align-items: center;
		gap: 0.5rem;
	}

	.filter-right {
		display: flex;
		align-items: center;
		gap: 0.5rem;
	}

	.filter-select {
		padding: 0.35rem 0.5rem;
		border-radius: 0.4rem;
		border: 1px solid rgba(148, 163, 184, 0.15);
		background: rgba(15, 23, 42, 0.6);
		color: #f1f5f9;
		font-size: 0.75rem;
	}

	.search-input {
		padding: 0.35rem 0.6rem;
		border-radius: 0.4rem;
		border: 1px solid rgba(148, 163, 184, 0.15);
		background: rgba(15, 23, 42, 0.6);
		color: #f1f5f9;
		font-size: 0.8rem;
		width: 180px;
		box-sizing: border-box;
	}

	.search-input:focus {
		outline: none;
		border-color: #a855f7;
	}

	.result-count {
		font-size: 0.75rem;
		color: #94a3b8;
	}

	.subdomain-list {
		max-height: 600px;
		overflow-y: auto;
	}

	.subdomain-item {
		padding: 0.6rem 0.75rem;
		border-bottom: 1px solid rgba(148, 163, 184, 0.08);
		transition: background 0.2s;
	}

	.subdomain-item:hover {
		background: rgba(168, 85, 247, 0.05);
	}

	.subdomain-item.alive {
		border-left: 3px solid #22c55e;
	}

	.subdomain-item.dead {
		border-left: 3px solid #ef4444;
	}

	.subdomain-header {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		flex-wrap: wrap;
	}

	.subdomain-status { font-size: 0.75rem; }

	.subdomain-name {
		font-weight: 600;
		font-size: 0.85rem;
		color: #f1f5f9;
		font-family: monospace;
	}

	.category-badge {
		font-size: 0.65rem;
		padding: 0.15rem 0.4rem;
		border-radius: 0.25rem;
		font-weight: 500;
	}

	.source-badge {
		font-size: 0.65rem;
		padding: 0.15rem 0.4rem;
		border-radius: 0.25rem;
		background: rgba(148, 163, 184, 0.1);
		color: #94a3b8;
	}

	.subdomain-details {
		display: flex;
		gap: 0.75rem;
		margin-top: 0.3rem;
		flex-wrap: wrap;
		font-size: 0.75rem;
	}

	.ip-list { color: #94a3b8; font-family: monospace; }
	.ipv6-list { color: #64748b; font-family: monospace; }
	.http-info { color: #3b82f6; font-family: monospace; }
	.http-title { color: #94a3b8; font-style: italic; }

	.categories-detail {
		display: flex;
		flex-direction: column;
		gap: 0.75rem;
	}

	.category-detail-card {
		background: rgba(15, 23, 42, 0.4);
		border: 1px solid rgba(148, 163, 184, 0.08);
		border-radius: 0.5rem;
		padding: 0.75rem;
	}

	.category-detail-header {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		margin-bottom: 0.5rem;
	}

	.category-detail-name {
		font-weight: 600;
		color: #e2e8f0;
		font-size: 0.9rem;
	}

	.category-detail-count {
		font-size: 0.75rem;
		color: #94a3b8;
	}

	.category-subdomains {
		display: flex;
		flex-wrap: wrap;
		gap: 0.35rem;
	}

	.subdomain-chip {
		font-size: 0.7rem;
		padding: 0.2rem 0.5rem;
		border: 1px solid rgba(148, 163, 184, 0.15);
		border-radius: 0.3rem;
		background: rgba(15, 23, 42, 0.6);
		color: #c4b5fd;
		font-family: monospace;
	}

	.empty-state {
		text-align: center;
		padding: 3rem;
		color: #94a3b8;
	}

	.empty-icon { font-size: 3rem; margin-bottom: 0.75rem; }

	@media (max-width: 768px) {
		.content-grid {
			grid-template-columns: 1fr;
		}
		.overview-grid {
			grid-template-columns: repeat(2, 1fr);
		}
	}

	.input-with-action { display: flex; gap: 0.5rem; }
	.input-with-action .form-input { flex: 1; }
	.action-btn { padding: 0.5rem 0.75rem; border: 1px solid rgba(168, 85, 247, 0.3); border-radius: 0.5rem; background: rgba(168, 85, 247, 0.1); color: #c4b5fd; cursor: pointer; font-size: 1rem; transition: all 0.2s; white-space: nowrap; }
	.action-btn:hover:not(:disabled) { background: rgba(168, 85, 247, 0.2); border-color: rgba(168, 85, 247, 0.5); }
	.action-btn:disabled { opacity: 0.5; cursor: not-allowed; }

	.modal-overlay { position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0, 0, 0, 0.6); display: flex; align-items: center; justify-content: center; z-index: 1000; }
	.modal-content { background: #1e293b; border: 1px solid rgba(168, 85, 247, 0.2); border-radius: 0.75rem; width: 90%; max-width: 500px; max-height: 80vh; display: flex; flex-direction: column; }
	.modal-header { display: flex; justify-content: space-between; align-items: center; padding: 1rem 1.25rem; border-bottom: 1px solid rgba(148, 163, 184, 0.1); }
	.modal-header h3 { margin: 0; color: #f1f5f9; font-size: 1rem; }
	.modal-close { background: none; border: none; color: #94a3b8; cursor: pointer; font-size: 1.2rem; }
	.modal-body { padding: 1rem 1.25rem; overflow-y: auto; flex: 1; }
	.modal-footer { display: flex; justify-content: flex-end; align-items: center; gap: 0.75rem; padding: 0.75rem 1.25rem; border-top: 1px solid rgba(148, 163, 184, 0.1); }
	.selected-count { flex: 1; color: #94a3b8; font-size: 0.8rem; }
	.target-list { max-height: 300px; overflow-y: auto; display: flex; flex-direction: column; gap: 0.25rem; }
	.target-select-item { display: flex; align-items: center; gap: 0.5rem; padding: 0.5rem 0.75rem; border-radius: 0.4rem; cursor: pointer; transition: background 0.2s; color: #cbd5e1; font-size: 0.85rem; }
	.target-select-item:hover { background: rgba(168, 85, 247, 0.08); }
	.target-select-item.selected { background: rgba(168, 85, 247, 0.15); border: 1px solid rgba(168, 85, 247, 0.3); }
	.target-select-item input[type="checkbox"] { accent-color: #a855f7; }
	.loading-state, .empty-state { text-align: center; padding: 2rem; color: #94a3b8; }
	.spinner { display: inline-block; width: 1rem; height: 1rem; border: 2px solid rgba(168, 85, 247, 0.2); border-top-color: #a855f7; border-radius: 50%; animation: spin 0.8s linear infinite; }
	@keyframes spin { to { transform: rotate(360deg); } }
	.btn-primary-sm { padding: 0.4rem 1rem; border: none; border-radius: 0.4rem; background: linear-gradient(135deg, #a855f7, #6366f1); color: white; cursor: pointer; font-size: 0.8rem; font-weight: 600; }
	.btn-primary-sm:disabled { opacity: 0.5; cursor: not-allowed; }
	.btn-secondary { padding: 0.4rem 1rem; border: 1px solid rgba(148, 163, 184, 0.2); border-radius: 0.4rem; background: transparent; color: #94a3b8; cursor: pointer; font-size: 0.8rem; }
</style>
