<script lang="ts">
	import { tr } from '$lib/i18n';
	import ToolHistory from '$lib/components/ToolHistory.svelte';
	import ToolHelp from '$lib/components/ToolHelp.svelte';

	interface SocialAccount {
		platform: string;
		url: string;
		username: string;
		is_verified: boolean;
		bio: string | null;
		followers: number | null;
		profile_picture: string | null;
		category: string;
		risk_level: string;
	}

	interface SocialFinderStats {
		total_checked: number;
		found_count: number;
		not_found_count: number;
		categories: Record<string, number>;
		high_risk_count: number;
	}

	interface SocialFinding {
		severity: string;
		category: string;
		description: string;
		recommendation: string;
	}

	interface SocialFinderResult {
		success: boolean;
		username: string;
		found_accounts: SocialAccount[];
		not_found_platforms: string[];
		statistics: SocialFinderStats;
		security_findings: SocialFinding[];
		summary: string;
	}

	interface PlatformInfo {
		name: string;
		category: string;
		check_method: string;
	}

	interface PlatformSelectItem {
		name: string;
		category: string;
		check_method: string;
		selected: boolean;
	}

	let username = $state('');
	let mode = $state('fast');
	let timeout = $state(15);
	let result: SocialFinderResult | null = $state(null);
	let error = $state('');
	let processing = $state(false);
	let activeMainTab = $state('search');
	let activeResultTab = $state('found');
	let filterCategory = $state('');

	let selectedPlatforms: string[] = $state([]);
	let availablePlatforms: PlatformInfo[] = $state([]);

	let showTargetSelector = $state(false);
	let platformSelectList: PlatformSelectItem[] = $state([]);
	let loadingPlatforms = $state(false);
	let platformSearchQuery = $state('');
	let categoryFilter = $state('');
	let selectedTargetIds: number[] = $state([]);
	let selectedTargets: any[] = $state([]);
	let targetList: any[] = $state([]);
	let targetSearchQuery = $state('');
	let loadingTargets = $state(false);
	let showTargetManagerSelector = $state(false);

	let historyComponent: ToolHistory;

	let filteredPlatformSelectList = $derived(
		platformSelectList.filter(p => {
			const matchesSearch = !platformSearchQuery ||
				p.name.toLowerCase().includes(platformSearchQuery.toLowerCase()) ||
				p.category.toLowerCase().includes(platformSearchQuery.toLowerCase());
			const matchesCategory = !categoryFilter || p.category === categoryFilter;
			return matchesSearch && matchesCategory;
		})
	);

	let platformCategories = $derived(
		[...new Set(availablePlatforms.map(p => p.category))].sort()
	);

	let selectedCount = $derived(
		platformSelectList.filter(p => p.selected).length
	);

	let filteredAccounts = $derived(
		result
			? (filterCategory ? (result as SocialFinderResult).found_accounts.filter((a: SocialAccount) => a.category === filterCategory) : (result as SocialFinderResult).found_accounts)
			: [] as SocialAccount[]
	);

	let categories = $derived(
		result ? Object.keys((result as SocialFinderResult).statistics.categories) : [] as string[]
	);

	async function loadPlatforms() {
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			availablePlatforms = await invoke<PlatformInfo[]>('list_social_platforms_command');
		} catch (e) {
			console.error('Failed to load platforms:', e);
		}
	}

	async function openTargetSelector() {
		showTargetSelector = true;
		await loadPlatformSelectList();
	}

	async function loadPlatformSelectList() {
		loadingPlatforms = true;
		try {
			if (availablePlatforms.length === 0) {
				await loadPlatforms();
			}
			platformSelectList = availablePlatforms.map(p => ({
				name: p.name,
				category: p.category,
				check_method: p.check_method,
				selected: selectedPlatforms.includes(p.name),
			}));
			platformSearchQuery = '';
			categoryFilter = '';
		} catch (e) {
			console.error('Failed to load platform list:', e);
			platformSelectList = [];
		} finally {
			loadingPlatforms = false;
		}
	}

	function togglePlatformSelection(p: PlatformSelectItem) {
		p.selected = !p.selected;
		platformSelectList = [...platformSelectList];
	}

	function selectAllPlatforms() {
		platformSelectList = platformSelectList.map(p => ({ ...p, selected: true }));
	}

	function deselectAllPlatforms() {
		platformSelectList = platformSelectList.map(p => ({ ...p, selected: false }));
	}

	function confirmPlatformSelection() {
		const newlySelected = platformSelectList.filter(p => p.selected).map(p => p.name);
		selectedPlatforms = newlySelected;
		showTargetSelector = false;
		platformSelectList = [];
	}

	function removePlatform(name: string) {
		selectedPlatforms = selectedPlatforms.filter(p => p !== name);
	}

	function clearPlatforms() {
		selectedPlatforms = [];
	}

	async function search() {
		if (!username.trim()) { error = $tr('socialFinder.error.usernameRequired'); return; }
		if (selectedPlatforms.length === 0) { error = $tr('socialFinder.error.platformRequired'); return; }
		processing = true; error = ''; result = null;
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			result = await invoke<SocialFinderResult>('find_social_command', {
				config: {
					username: username.trim(),
					check_platforms: selectedPlatforms,
					timeout,
					mode,
				},
				targetId: selectedTargetIds.length > 0 ? selectedTargetIds[0] : null,
			});
			if (result && historyComponent) {
				await historyComponent.saveHistory(username.trim(), JSON.stringify(result), result.summary, 'completed');
			}
		} catch (e: any) {
			error = e.toString();
			if (historyComponent) {
				await historyComponent.saveHistory(username.trim(), '', error, 'failed');
			}
		} finally {
			processing = false;
		}
	}

	function clearAll() { username = ''; result = null; error = ''; selectedPlatforms = []; }

	async function openTargetSelectorModal() {
		showTargetManagerSelector = true;
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
			username = username ? `${username}\n${targetValues}` : targetValues;
			selectedTargetIds = selectedTargets.map((t: any) => t.id).filter((id: number | null): id is number => id !== null);
		}
		showTargetManagerSelector = false;
		selectedTargets = [];
	}

	function getSeverityColor(s: string): string {
		switch (s) { case 'critical': return '#dc2626'; case 'high': return '#ef4444'; case 'medium': return '#f59e0b'; case 'low': return '#3b82f6'; default: return '#6b7280'; }
	}

	function translateSeverity(s: string): string {
		const key = `socialFinder.severity.${s}`;
		const val = $tr(key);
		return val !== key ? val : s;
	}

	function translateCategory(c: string): string {
		const key = `socialFinder.category.${c}`;
		const val = $tr(key);
		return val !== key ? val : c;
	}

	function translateRiskLevel(r: string): string {
		const key = `socialFinder.riskLevel.${r}`;
		const val = $tr(key);
		return val !== key ? val : r;
	}

	loadPlatforms();
</script>

<div class="nd-page">
	<div class="page-header">
		<div class="header-left">
			<a href="/" class="back-link">{$tr('common.backToHome')}</a>
			<h1 class="page-title">👤 {$tr('socialFinder.title')}</h1>
			<p class="page-subtitle">{$tr('socialFinder.subtitle')}</p>
		</div>
	</div>

	<div class="tabs">
		<button class="tab-btn {activeMainTab === 'search' ? 'active' : ''}" onclick={() => activeMainTab = 'search'}>
			<span class="tab-icon">🔍</span> {$tr('socialFinder.find')}
		</button>
		<button class="tab-btn {activeMainTab === 'history' ? 'active' : ''}" onclick={() => activeMainTab = 'history'}>
			<span class="tab-icon">📋</span> {$tr('socialFinder.history')}
		</button>
		<button class="tab-btn {activeMainTab === 'help' ? 'active' : ''}" onclick={() => activeMainTab = 'help'}>
			<span class="tab-icon">📖</span> {$tr('socialFinder.help')}
		</button>
	</div>

	{#if activeMainTab === 'search'}
		<div class="content-grid">
			<div class="input-section">
				<div class="section-card">
					<h2 class="section-title">{$tr('socialFinder.config.title')}</h2>
					<p class="section-desc">{$tr('socialFinder.config.desc')}</p>

					<div class="form-group">
						<label class="form-label">{$tr('socialFinder.config.username')}</label>
						<div class="input-with-action">
							<input type="text" bind:value={username} placeholder="e.g. johndoe" class="form-input" disabled={processing} onkeydown={(e) => e.key === 'Enter' && search()} />
							<button type="button" class="action-btn" onclick={openTargetSelectorModal} disabled={processing} title={$tr('common.selectTarget')}>
								🎯
							</button>
						</div>
					</div>

					<div class="form-group">
						<label class="form-label">{$tr('socialFinder.config.mode')}</label>
						<select bind:value={mode} class="form-input" disabled={processing}>
							<option value="fast">{$tr('socialFinder.config.fastMode')}</option>
							<option value="deep">{$tr('socialFinder.config.deepMode')}</option>
						</select>
					</div>

					<div class="form-group">
						<label class="form-label">{$tr('socialFinder.config.timeout')}</label>
						<input type="number" bind:value={timeout} min="5" max="120" class="form-input" disabled={processing} />
					</div>

					<div class="button-group">
						<button class="btn-primary" onclick={search} disabled={processing || selectedPlatforms.length === 0}>
							{#if processing}<span class="spinner"></span> {$tr('socialFinder.finding')}{:else}🔍 {$tr('socialFinder.startFind')}{/if}
						</button>
						<button class="btn-secondary" onclick={clearAll} disabled={processing}>🗑️</button>
					</div>
				</div>

				<div class="section-card" style="margin-top: 0.75rem">
					<div class="platform-header">
						<h2 class="section-title" style="margin-bottom:0">{$tr('socialFinder.config.platforms')}</h2>
						<span class="platform-count">{selectedPlatforms.length}</span>
					</div>

					<div class="platform-actions">
						<button class="btn-select" onclick={openTargetSelector} disabled={processing}>
							🎯 {$tr('socialFinder.config.selectTargets')}
						</button>
						{#if selectedPlatforms.length > 0}
							<button class="btn-clear-sm" onclick={clearPlatforms}>{$tr('socialFinder.config.clearAll')}</button>
						{/if}
					</div>

					{#if selectedPlatforms.length === 0}
						<div class="empty-platforms">
							<div class="empty-platforms-icon">🎯</div>
							<p>{$tr('socialFinder.config.noPlatforms')}</p>
						</div>
					{:else}
						<div class="platform-list">
							{#each selectedPlatforms as platform}
								<div class="platform-item">
									<span class="platform-name">{platform}</span>
									<button class="platform-remove" onclick={() => removePlatform(platform)}>✕</button>
								</div>
							{/each}
						</div>
					{/if}
				</div>
			</div>

			<div class="result-section">
				<div class="section-card">
					<h2 class="section-title">{$tr('socialFinder.result.title')}</h2>
					{#if error}
						<div class="error-card"><div class="error-icon">⚠️</div><div class="error-text">{error}</div></div>
					{:else if result}
						<div class="summary-banner">
							<div class="summary-info">
								<span class="domain-badge">{$tr('socialFinder.username')}</span>
								<span class="query-text">{result.username}</span>
							</div>
							<div class="summary-badges">
								<span class="summary-badge purple">{result.statistics.found_count} {$tr('socialFinder.result.found')}</span>
								<span class="summary-badge gray">{result.statistics.not_found_count} {$tr('socialFinder.result.notFound')}</span>
								{#if result.statistics.high_risk_count > 0}
									<span class="summary-badge red">{result.statistics.high_risk_count} {$tr('socialFinder.result.highRisk')}</span>
								{/if}
							</div>
						</div>

						<div class="stats-grid">
							<div class="stat-card">
								<div class="stat-value purple">{result.statistics.total_checked}</div>
								<div class="stat-label">{$tr('socialFinder.result.checkedPlatforms')}</div>
							</div>
							<div class="stat-card">
								<div class="stat-value green">{result.statistics.found_count}</div>
								<div class="stat-label">{$tr('socialFinder.result.foundAccounts')}</div>
							</div>
							<div class="stat-card">
								<div class="stat-value gray">{result.statistics.not_found_count}</div>
								<div class="stat-label">{$tr('socialFinder.result.notFoundPlatforms')}</div>
							</div>
							<div class="stat-card">
								<div class="stat-value red">{result.statistics.high_risk_count}</div>
								<div class="stat-label">{$tr('socialFinder.result.highRiskAccounts')}</div>
							</div>
						</div>

						<div class="result-tabs">
							<button class="result-tab {activeResultTab === 'found' ? 'active' : ''}" onclick={() => activeResultTab = 'found'}>✅ {$tr('socialFinder.tabs.found')} ({result.found_accounts.length})</button>
							<button class="result-tab {activeResultTab === 'notfound' ? 'active' : ''}" onclick={() => activeResultTab = 'notfound'}>❌ {$tr('socialFinder.tabs.notFound')} ({result.not_found_platforms.length})</button>
							<button class="result-tab {activeResultTab === 'findings' ? 'active' : ''}" onclick={() => activeResultTab = 'findings'}>🛡️ {$tr('socialFinder.tabs.findings')} ({result.security_findings.length})</button>
						</div>

						{#if activeResultTab === 'found'}
							<div class="filter-bar">
								<button class="filter-btn {filterCategory === '' ? 'active' : ''}" onclick={() => filterCategory = ''}>{$tr('socialFinder.filter.all')}</button>
								{#each categories as cat}
									<button class="filter-btn {filterCategory === cat ? 'active' : ''}" onclick={() => filterCategory = cat}>
										{translateCategory(cat)} ({result.statistics.categories[cat]})
									</button>
								{/each}
							</div>
							<div class="items-list">
								{#each filteredAccounts as account}
									<div class="item-card" style="border-left-color: {account.risk_level === 'high' ? '#ef4444' : account.risk_level === 'medium' ? '#f59e0b' : '#22c55e'}">
										<div class="item-header">
											<div class="account-info">
												<a href={account.url} target="_blank" class="platform-link">{account.platform}</a>
												{#if account.is_verified}
													<span class="verified-badge">✓</span>
												{/if}
												<span class="risk-badge risk-{account.risk_level}">{translateRiskLevel(account.risk_level)}</span>
											</div>
											<span class="category-tag">{translateCategory(account.category)}</span>
										</div>
										<div class="account-details">
											<span class="account-url">{account.url}</span>
											{#if account.followers}
												<span class="account-followers">{$tr('socialFinder.result.followers')}: {account.followers.toLocaleString()}</span>
											{/if}
										</div>
										{#if account.bio}
											<div class="account-bio">{account.bio}</div>
										{/if}
									</div>
								{/each}
								{#if filteredAccounts.length === 0}
									<div class="empty-item">{$tr('socialFinder.status.noAccounts')}</div>
								{/if}
							</div>
						{:else if activeResultTab === 'notfound'}
							<div class="not-found-grid">
								{#each result.not_found_platforms as platform}
									<span class="not-found-tag">{platform}</span>
								{/each}
							</div>
						{:else if activeResultTab === 'findings'}
							<div class="items-list">
								{#each result.security_findings as finding}
									<div class="item-card" style="border-left-color: {getSeverityColor(finding.severity)}">
										<div class="item-header">
											<span class="severity-badge" style="background: {getSeverityColor(finding.severity)}">{translateSeverity(finding.severity)}</span>
											<span class="item-title">{finding.category}</span>
										</div>
										<p class="item-desc">{finding.description}</p>
										{#if finding.recommendation}
											<p class="item-rec">💡 {finding.recommendation}</p>
										{/if}
									</div>
								{/each}
								{#if result.security_findings.length === 0}
									<div class="empty-item">{$tr('socialFinder.status.noFindings')}</div>
								{/if}
							</div>
						{/if}
					{:else}
						<div class="empty-state">
							<div class="empty-icon">👤</div>
							<p>{$tr('socialFinder.result.noResults')}</p>
						</div>
					{/if}
				</div>
			</div>
		</div>
	{:else if activeMainTab === 'history'}
		<div class="section-card"><ToolHistory toolType="social_finder" toolName={$tr('socialFinder.title')} bind:this={historyComponent} /></div>
	{:else if activeMainTab === 'help'}
		<div class="section-card"><ToolHelp toolType="social_finder" /></div>
	{/if}
</div>

{#if showTargetSelector}
	<div class="modal-overlay" role="button" tabindex="-1" onclick={() => showTargetSelector = false} onkeydown={(e) => e.key === 'Escape' && (showTargetSelector = false)}>
		<div class="modal-content" role="dialog" aria-modal="true" tabindex="-1" onclick={(e) => e.stopPropagation()} onkeydown={(e) => e.stopPropagation()}>
			<div class="modal-header">
				<h2>🎯 {$tr('socialFinder.modal.selectPlatforms')}</h2>
				<button class="modal-close" onclick={() => showTargetSelector = false}>✕</button>
			</div>

			<div class="modal-body">
				<div class="platform-search-row">
					<input type="text" bind:value={platformSearchQuery} placeholder={$tr('socialFinder.modal.searchPlaceholder')} class="platform-search-input" />
					<button class="btn-select-all" onclick={selectAllPlatforms}>{$tr('socialFinder.modal.selectAll')}</button>
					<button class="btn-deselect-all" onclick={deselectAllPlatforms}>{$tr('socialFinder.modal.deselectAll')}</button>
				</div>

				{#if platformCategories.length > 1}
					<div class="category-filter-bar">
						<button class="cat-filter-btn {categoryFilter === '' ? 'active' : ''}" onclick={() => categoryFilter = ''}>{$tr('socialFinder.filter.all')}</button>
						{#each platformCategories as cat}
							<button class="cat-filter-btn {categoryFilter === cat ? 'active' : ''}" onclick={() => categoryFilter = cat}>
								{translateCategory(cat)}
							</button>
						{/each}
					</div>
				{/if}

				{#if loadingPlatforms}
					<div class="loading-message">
						<div class="spinner"></div>
						{$tr('socialFinder.modal.loading')}
					</div>
				{:else if filteredPlatformSelectList.length === 0}
					<div class="empty-message">
						{#if platformSearchQuery}
							{$tr('socialFinder.modal.noMatch')}
						{:else}
							{$tr('socialFinder.modal.noTargets')}
						{/if}
					</div>
				{:else}
					<div class="platform-grid">
						{#each filteredPlatformSelectList as p (p.name)}
							<div
								class="platform-select-item {p.selected ? 'selected' : ''}"
								onclick={() => togglePlatformSelection(p)}
								onkeydown={(e) => e.key === 'Enter' && togglePlatformSelection(p)}
								role="button"
								tabindex="0"
							>
								<div class="platform-select-info">
									<div class="platform-select-name">{p.name}</div>
									<div class="platform-select-meta">
										<span class="platform-select-cat">{translateCategory(p.category)}</span>
										<span class="platform-select-method">{p.check_method}</span>
									</div>
								</div>
								<div class="platform-select-check">
									{#if p.selected}✓{/if}
								</div>
							</div>
						{/each}
					</div>
				{/if}
			</div>

			<div class="modal-footer">
				<div class="selection-info">
					{$tr('socialFinder.modal.selectedCount', { count: selectedCount })}
				</div>
				<div class="modal-actions">
					<button class="btn-cancel" onclick={() => showTargetSelector = false}>
						{$tr('socialFinder.modal.cancel')}
					</button>
					<button class="btn-confirm" onclick={confirmPlatformSelection} disabled={selectedCount === 0}>
						{$tr('socialFinder.modal.confirm')}
					</button>
				</div>
			</div>
		</div>
	</div>
{/if}

{#if showTargetManagerSelector}
	<div class="modal-overlay" onclick={() => showTargetManagerSelector = false}>
		<div class="modal-content" onclick={(e) => e.stopPropagation()}>
			<div class="modal-header">
				<h3>🎯 {$tr('common.selectTarget')}</h3>
				<button class="modal-close" onclick={() => showTargetManagerSelector = false}>✕</button>
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
				<button class="btn-secondary" onclick={() => showTargetManagerSelector = false}>{$tr('common.cancel')}</button>
				<button class="btn-primary-sm" onclick={confirmTargetSelection} disabled={selectedTargets.length === 0}>{$tr('common.confirm')}</button>
			</div>
		</div>
	</div>
{/if}

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

	.platform-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.75rem; }
	.platform-count { padding: 0.15rem 0.5rem; background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%); border-radius: 0.3rem; font-size: 0.7rem; font-weight: 700; color: white; }
	.platform-actions { display: flex; gap: 0.5rem; margin-bottom: 0.75rem; }
	.btn-select { flex: 1; background: rgba(168, 85, 247, 0.15); color: #c4b5fd; border: 1px solid rgba(168, 85, 247, 0.3); padding: 0.5rem 0.75rem; border-radius: 0.5rem; cursor: pointer; font-size: 0.85rem; transition: all 0.2s; }
	.btn-select:hover:not(:disabled) { background: rgba(168, 85, 247, 0.25); }
	.btn-select:disabled { opacity: 0.5; cursor: not-allowed; }
	.btn-clear-sm { background: rgba(148, 163, 184, 0.1); color: #94a3b8; border: 1px solid rgba(148, 163, 184, 0.15); padding: 0.5rem 0.75rem; border-radius: 0.5rem; cursor: pointer; font-size: 0.8rem; transition: all 0.2s; }
	.btn-clear-sm:hover { background: rgba(148, 163, 184, 0.2); color: #e2e8f0; }

	.empty-platforms { text-align: center; padding: 1.5rem; color: #94a3b8; }
	.empty-platforms-icon { font-size: 1.5rem; margin-bottom: 0.5rem; }
	.empty-platforms p { font-size: 0.8rem; margin: 0; }

	.platform-list { max-height: 300px; overflow-y: auto; display: flex; flex-direction: column; gap: 0.25rem; }
	.platform-item { display: flex; align-items: center; justify-content: space-between; padding: 0.4rem 0.5rem; border-radius: 0.4rem; transition: background 0.2s; }
	.platform-item:hover { background: rgba(168, 85, 247, 0.08); }
	.platform-name { font-size: 0.85rem; color: #cbd5e1; }
	.platform-remove { background: none; border: none; color: #64748b; cursor: pointer; font-size: 0.75rem; padding: 0.15rem 0.3rem; border-radius: 0.2rem; transition: all 0.2s; opacity: 0; }
	.platform-item:hover .platform-remove { opacity: 1; }
	.platform-remove:hover { color: #ef4444; background: rgba(239, 68, 68, 0.1); }

	.spinner { display: inline-block; width: 1rem; height: 1rem; border: 2px solid rgba(255, 255, 255, 0.3); border-top-color: white; border-radius: 50%; animation: spin 0.6s linear infinite; }
	@keyframes spin { to { transform: rotate(360deg); } }

	.error-card { display: flex; align-items: center; gap: 0.75rem; padding: 1rem; background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.2); border-radius: 0.5rem; }
	.error-icon { font-size: 1.25rem; }
	.error-text { color: #fca5a5; font-size: 0.85rem; }

	.summary-banner { display: flex; align-items: center; justify-content: space-between; padding: 0.75rem 1rem; background: rgba(15, 23, 42, 0.4); border: 1px solid rgba(148, 163, 184, 0.08); border-radius: 0.75rem; margin-bottom: 1rem; }
	.summary-info { display: flex; align-items: center; gap: 0.75rem; }
	.domain-badge { padding: 0.2rem 0.6rem; background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%); border-radius: 0.3rem; font-size: 0.7rem; font-weight: 700; color: white; letter-spacing: 0.05em; }
	.query-text { font-size: 0.85rem; color: #f1f5f9; font-weight: 500; font-family: 'SF Mono', 'Fira Code', monospace; }
	.summary-badges { display: flex; gap: 0.5rem; }
	.summary-badge { padding: 0.25rem 0.6rem; border-radius: 0.4rem; font-size: 0.75rem; font-weight: 600; }
	.summary-badge.purple { background: rgba(168, 85, 247, 0.15); color: #c4b5fd; border: 1px solid rgba(168, 85, 247, 0.3); }
	.summary-badge.gray { background: rgba(148, 163, 184, 0.15); color: #94a3b8; border: 1px solid rgba(148, 163, 184, 0.3); }
	.summary-badge.red { background: rgba(239, 68, 68, 0.15); color: #fca5a5; border: 1px solid rgba(239, 68, 68, 0.3); }

	.stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 0.75rem; margin-bottom: 1rem; }
	.stat-card { background: rgba(15, 23, 42, 0.4); border: 1px solid rgba(148, 163, 184, 0.08); border-radius: 0.5rem; padding: 0.75rem; text-align: center; }
	.stat-value { font-size: 1.25rem; font-weight: 700; }
	.stat-value.purple { color: #c4b5fd; }
	.stat-value.green { color: #86efac; }
	.stat-value.gray { color: #94a3b8; }
	.stat-value.red { color: #fca5a5; }
	.stat-label { font-size: 0.7rem; color: #64748b; margin-top: 0.2rem; }

	.result-tabs { display: flex; gap: 0.25rem; margin-bottom: 1rem; flex-wrap: wrap; }
	.result-tab { padding: 0.4rem 0.75rem; border-radius: 0.4rem; border: 1px solid rgba(148, 163, 184, 0.15); background: rgba(15, 23, 42, 0.4); color: #94a3b8; cursor: pointer; font-size: 0.8rem; transition: all 0.2s; }
	.result-tab.active { background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%); color: white; border-color: transparent; font-weight: 600; }
	.result-tab:hover:not(.active) { border-color: rgba(168, 85, 247, 0.3); color: #c4b5fd; }

	.filter-bar { display: flex; gap: 0.25rem; margin-bottom: 0.75rem; flex-wrap: wrap; }
	.filter-btn { padding: 0.3rem 0.6rem; border-radius: 0.3rem; border: 1px solid rgba(148, 163, 184, 0.15); background: rgba(15, 23, 42, 0.4); color: #94a3b8; cursor: pointer; font-size: 0.75rem; transition: all 0.2s; }
	.filter-btn.active { background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%); color: white; border-color: transparent; font-weight: 600; }
	.filter-btn:hover:not(.active) { border-color: rgba(168, 85, 247, 0.3); color: #c4b5fd; }

	.items-list { display: flex; flex-direction: column; gap: 0.5rem; }
	.item-card { padding: 0.75rem; background: rgba(15, 23, 42, 0.4); border: 1px solid rgba(148, 163, 184, 0.08); border-radius: 0.5rem; border-left: 3px solid; }
	.item-header { display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.3rem; flex-wrap: wrap; }
	.item-title { font-weight: 600; font-size: 0.85rem; color: #f1f5f9; }
	.item-desc { font-size: 0.8rem; color: #94a3b8; margin-top: 0.3rem; }
	.item-rec { font-size: 0.8rem; color: #86efac; margin-top: 0.3rem; }

	.account-info { display: flex; align-items: center; gap: 0.5rem; }
	.platform-link { font-weight: 600; font-size: 0.9rem; color: #c4b5fd; text-decoration: none; }
	.platform-link:hover { text-decoration: underline; color: #a855f7; }
	.verified-badge { color: #3b82f6; font-weight: 700; font-size: 0.85rem; }
	.risk-badge { padding: 0.15rem 0.5rem; border-radius: 0.3rem; font-size: 0.7rem; font-weight: 600; }
	.risk-high { background: rgba(239, 68, 68, 0.15); color: #fca5a5; }
	.risk-medium { background: rgba(245, 158, 11, 0.15); color: #fbbf24; }
	.risk-low { background: rgba(34, 197, 94, 0.15); color: #86efac; }
	.category-tag { margin-left: auto; padding: 0.15rem 0.5rem; background: rgba(168, 85, 247, 0.1); color: #c4b5fd; border-radius: 0.3rem; font-size: 0.7rem; }

	.account-details { display: flex; gap: 1rem; font-size: 0.8rem; color: #94a3b8; margin-top: 0.3rem; flex-wrap: wrap; }
	.account-url { font-family: 'SF Mono', 'Fira Code', monospace; font-size: 0.75rem; color: #64748b; }
	.account-followers { color: #94a3b8; }
	.account-bio { font-size: 0.8rem; color: #cbd5e1; margin-top: 0.3rem; padding-top: 0.3rem; border-top: 1px solid rgba(148, 163, 184, 0.08); }

	.severity-badge { padding: 0.15rem 0.5rem; border-radius: 0.3rem; color: white; font-size: 0.7rem; font-weight: 600; text-transform: uppercase; }

	.not-found-grid { display: flex; flex-wrap: wrap; gap: 0.4rem; }
	.not-found-tag { padding: 0.3rem 0.6rem; background: rgba(15, 23, 42, 0.4); border: 1px solid rgba(148, 163, 184, 0.08); border-radius: 0.4rem; font-size: 0.8rem; color: #64748b; }

	.empty-item { text-align: center; padding: 1.5rem; color: #94a3b8; font-size: 0.85rem; }
	.empty-state { text-align: center; padding: 2.5rem 1rem; color: #94a3b8; }
	.empty-icon { font-size: 2.5rem; margin-bottom: 0.75rem; }
	.empty-state p { font-size: 0.85rem; margin: 0; }

	.modal-overlay { position: fixed; inset: 0; background: rgba(0, 0, 0, 0.7); display: flex; align-items: center; justify-content: center; z-index: 1000; backdrop-filter: blur(4px); }
	.modal-content { background: #1e293b; border: 1px solid rgba(168, 85, 247, 0.2); border-radius: 1rem; width: 90%; max-width: 700px; max-height: 80vh; overflow: hidden; animation: modalFadeIn 0.2s ease-out; }
	@keyframes modalFadeIn { from { opacity: 0; transform: scale(0.95); } to { opacity: 1; transform: scale(1); } }
	.modal-header { display: flex; align-items: center; justify-content: space-between; padding: 1.25rem 1.5rem; border-bottom: 1px solid rgba(168, 85, 247, 0.15); background: rgba(0, 0, 0, 0.2); }
	.modal-header h2 { margin: 0; font-size: 1.1rem; color: #e5e7eb; }
	.modal-close { background: none; border: none; color: #9ca3af; cursor: pointer; font-size: 1.2rem; padding: 0.25rem; }
	.modal-close:hover { color: #e5e7eb; }
	.modal-body { padding: 1.5rem; max-height: calc(80vh - 200px); overflow-y: auto; }
	.platform-search-row { display: flex; gap: 0.5rem; margin-bottom: 0.75rem; }
	.platform-search-input { flex: 1; padding: 0.6rem 0.75rem; background: rgba(255, 255, 255, 0.05); border: 1px solid rgba(168, 85, 247, 0.2); border-radius: 0.5rem; color: #e5e7eb; font-size: 0.85rem; box-sizing: border-box; }
	.platform-search-input:focus { outline: none; border-color: #a855f7; background: rgba(255, 255, 255, 0.08); }
	.btn-select-all, .btn-deselect-all { padding: 0.5rem 0.75rem; border-radius: 0.4rem; font-size: 0.75rem; cursor: pointer; transition: all 0.2s; white-space: nowrap; }
	.btn-select-all { background: rgba(168, 85, 247, 0.15); border: 1px solid rgba(168, 85, 247, 0.3); color: #c4b5fd; }
	.btn-select-all:hover { background: rgba(168, 85, 247, 0.25); }
	.btn-deselect-all { background: rgba(148, 163, 184, 0.1); border: 1px solid rgba(148, 163, 184, 0.2); color: #94a3b8; }
	.btn-deselect-all:hover { background: rgba(148, 163, 184, 0.2); }
	.category-filter-bar { display: flex; gap: 0.25rem; margin-bottom: 0.75rem; flex-wrap: wrap; }
	.cat-filter-btn { padding: 0.25rem 0.5rem; border-radius: 0.3rem; border: 1px solid rgba(148, 163, 184, 0.15); background: rgba(15, 23, 42, 0.4); color: #94a3b8; cursor: pointer; font-size: 0.7rem; transition: all 0.2s; }
	.cat-filter-btn.active { background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%); color: white; border-color: transparent; font-weight: 600; }
	.cat-filter-btn:hover:not(.active) { border-color: rgba(168, 85, 247, 0.3); color: #c4b5fd; }
	.platform-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 0.4rem; }
	.platform-select-item { display: flex; align-items: center; justify-content: space-between; padding: 0.6rem 0.75rem; background: rgba(255, 255, 255, 0.03); border: 1px solid rgba(148, 163, 184, 0.1); border-radius: 0.4rem; cursor: pointer; transition: all 0.2s; }
	.platform-select-item:hover { background: rgba(168, 85, 247, 0.08); border-color: rgba(168, 85, 247, 0.3); }
	.platform-select-item.selected { background: rgba(168, 85, 247, 0.12); border-color: #a855f7; }
	.platform-select-info { flex: 1; min-width: 0; }
	.platform-select-name { font-size: 0.85rem; font-weight: 600; color: #e5e7eb; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
	.platform-select-meta { display: flex; gap: 0.4rem; margin-top: 0.15rem; }
	.platform-select-cat { font-size: 0.65rem; color: #c4b5fd; background: rgba(168, 85, 247, 0.1); padding: 0.1rem 0.35rem; border-radius: 0.2rem; }
	.platform-select-method { font-size: 0.65rem; color: #64748b; }
	.platform-select-check { width: 1.5rem; height: 1.5rem; display: flex; align-items: center; justify-content: center; background: rgba(168, 85, 247, 0.15); border-radius: 0.3rem; color: #a855f7; font-size: 0.9rem; font-weight: bold; flex-shrink: 0; }
	.modal-footer { display: flex; align-items: center; justify-content: space-between; padding: 1rem 1.5rem; border-top: 1px solid rgba(168, 85, 247, 0.15); background: rgba(0, 0, 0, 0.2); }
	.selection-info { font-size: 0.9rem; color: #9ca3af; }
	.modal-actions { display: flex; gap: 0.75rem; }
	.btn-cancel, .btn-confirm { padding: 0.5rem 1.25rem; border-radius: 0.5rem; font-size: 0.875rem; font-weight: 500; cursor: pointer; transition: all 0.2s; }
	.btn-cancel { background: rgba(255, 255, 255, 0.1); border: 1px solid rgba(255, 255, 255, 0.2); color: #e5e7eb; }
	.btn-cancel:hover { background: rgba(255, 255, 255, 0.15); }
	.btn-confirm { background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%); border: none; color: white; }
	.btn-confirm:hover:not(:disabled) { box-shadow: 0 4px 15px rgba(168, 85, 247, 0.4); }
	.btn-confirm:disabled { opacity: 0.5; cursor: not-allowed; }
	.loading-message, .empty-message { text-align: center; padding: 2rem; color: #9ca3af; }

	.input-section::-webkit-scrollbar { width: 4px; }
	.input-section::-webkit-scrollbar-track { background: transparent; }
	.input-section::-webkit-scrollbar-thumb { background: rgba(168, 85, 247, 0.3); border-radius: 2px; }
	.platform-list::-webkit-scrollbar { width: 4px; }
	.platform-list::-webkit-scrollbar-track { background: transparent; }
	.platform-list::-webkit-scrollbar-thumb { background: rgba(168, 85, 247, 0.3); border-radius: 2px; }
	.items-list::-webkit-scrollbar { width: 4px; }
	.items-list::-webkit-scrollbar-track { background: transparent; }
	.items-list::-webkit-scrollbar-thumb { background: rgba(168, 85, 247, 0.3); border-radius: 2px; }

	@media (max-width: 768px) {
		.content-grid { grid-template-columns: 1fr; }
		.input-section { position: static; max-height: none; }
		.stats-grid { grid-template-columns: repeat(2, 1fr); }
		.summary-banner { flex-direction: column; align-items: flex-start; gap: 0.5rem; }
	}

	.input-with-action { display: flex; gap: 0.5rem; }
	.input-with-action .form-input { flex: 1; }
	.action-btn { padding: 0.5rem 0.75rem; border: 1px solid rgba(168, 85, 247, 0.3); border-radius: 0.5rem; background: rgba(168, 85, 247, 0.1); color: #c4b5fd; cursor: pointer; font-size: 1rem; transition: all 0.2s; white-space: nowrap; }
	.action-btn:hover:not(:disabled) { background: rgba(168, 85, 247, 0.2); border-color: rgba(168, 85, 247, 0.5); }
	.action-btn:disabled { opacity: 0.5; cursor: not-allowed; }

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
