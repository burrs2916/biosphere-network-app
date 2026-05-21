<script lang="ts">
	import { tr } from '$lib/i18n';
	import ToolHistory from '$lib/components/ToolHistory.svelte';
	import ToolHelp from '$lib/components/ToolHelp.svelte';

	interface AdminPath {
		url: string;
		path: string;
		status_code: number;
		content_length: number | null;
		title: string | null;
		redirect_url: string | null;
		is_likely_admin: boolean;
		category: string;
		has_login_form: boolean;
		response_time_ms: number;
		confidence: number;
	}

	interface WafDetection {
		detected: boolean;
		waf_name: string | null;
		evidence: string[];
	}

	interface PathCategory {
		name: string;
		count: number;
		paths: string[];
	}

	interface AdminFinderResult {
		url: string;
		found_paths: AdminPath[];
		paths_tested: number;
		scan_duration_ms: number;
		summary: string;
		waf_detected: WafDetection | null;
		categories: PathCategory[];
	}

	let url = $state('');
	let activeMainTab = $state('analyze');
	let historyComponent: ToolHistory = $state(null!);
	let timeout = $state(15);
	let concurrent = $state(10);
	let scanMode = $state('normal');
	let followRedirects = $state(true);
	let randomizeUa = $state(true);
	let detectLoginForms = $state(true);
	let detectWaf = $state(true);
	let result: AdminFinderResult | null = $state(null);
	let error = $state('');
	let processing = $state(false);
	let activeResultTab = $state('overview');
	let filterAdmin = $state(false);
	let searchQuery = $state('');
	let exportFormat = $state('json');
	let exporting = $state(false);

	function getFilteredPaths(): AdminPath[] {
		if (!result) return [];
		return result.found_paths.filter((p: AdminPath) => {
			if (filterAdmin && !p.is_likely_admin) return false;
			if (searchQuery && !p.path.toLowerCase().includes(searchQuery.toLowerCase()) && !p.url.toLowerCase().includes(searchQuery.toLowerCase())) return false;
			return true;
		});
	}

	function getLikelyAdminCount(): number {
		return result ? result.found_paths.filter((p: AdminPath) => p.is_likely_admin).length : 0;
	}

	function getLoginFormCount(): number {
		return result ? result.found_paths.filter((p: AdminPath) => p.has_login_form).length : 0;
	}

	function getScanModeLabel(mode: string): string {
		switch (mode) {
			case 'quick': return $tr('adminFinder.modeQuick');
			case 'normal': return $tr('adminFinder.modeNormal');
			case 'deep': return $tr('adminFinder.modeDeep');
			default: return mode;
		}
	}

	function getScanModeDesc(mode: string): string {
		switch (mode) {
			case 'quick': return $tr('adminFinder.modeQuickDesc');
			case 'normal': return $tr('adminFinder.modeNormalDesc');
			case 'deep': return $tr('adminFinder.modeDeepDesc');
			default: return '';
		}
	}

	function applyScanMode(mode: string) {
		scanMode = mode;
		switch (mode) {
			case 'quick': concurrent = 15; timeout = 10; break;
			case 'normal': concurrent = 10; timeout = 15; break;
			case 'deep': concurrent = 5; timeout = 20; break;
		}
	}

	function getStatusColor(code: number): string {
		if (code >= 200 && code < 300) return '#22c55e';
		if (code >= 300 && code < 400) return '#3b82f6';
		if (code >= 400 && code < 500) return '#f59e0b';
		return '#ef4444';
	}

	function getConfidenceColor(conf: number): string {
		if (conf >= 0.8) return '#22c55e';
		if (conf >= 0.6) return '#3b82f6';
		if (conf >= 0.4) return '#f59e0b';
		return '#94a3b8';
	}

	function getCategoryColor(cat: string): string {
		const colors: Record<string, string> = {
			'Admin': '#a855f7',
			'Login': '#3b82f6',
			'Panel': '#6366f1',
			'Database': '#ef4444',
			'WordPress': '#22c55e',
			'API': '#f59e0b',
			'DevOps': '#06b6d4',
			'Sensitive': '#ef4444',
			'Service': '#8b5cf6',
			'Business': '#14b8a6',
			'CMS': '#ec4899',
			'Debug': '#94a3b8',
			'Other': '#64748b',
		};
		return colors[cat] || '#64748b';
	}

	function formatDuration(ms: number): string {
		if (ms < 1000) return `${ms}ms`;
		return `${(ms / 1000).toFixed(1)}s`;
	}

	function formatSize(bytes: number): string {
		if (bytes < 1024) return `${bytes}B`;
		if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)}KB`;
		return `${(bytes / (1024 * 1024)).toFixed(1)}MB`;
	}

	async function find() {
		if (!url.trim()) { error = $tr('adminFinder.errors.urlRequired'); return; }
		processing = true; error = ''; result = null;
		activeResultTab = 'overview';
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			result = await invoke<AdminFinderResult>('find_admin_command', {
				config: {
					url: url.trim(),
					timeout,
					concurrent,
					wordlist: [],
					scan_mode: scanMode,
					follow_redirects: followRedirects,
					randomize_ua: randomizeUa,
					detect_login_forms: detectLoginForms,
					detect_waf: detectWaf,
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
		} finally {
			processing = false;
		}
	}

	function clearAll() {
		url = ''; result = null; error = ''; filterAdmin = false; searchQuery = '';
	}

	async function exportResult() {
		if (!result) return;
		exporting = true;
		try {
			const { save } = await import('@tauri-apps/plugin-dialog');
			const { writeTextFile } = await import('@tauri-apps/plugin-fs');
			const filePath = await save({
				defaultPath: `admin_finder_${new Date().toISOString().slice(0, 10)}.${exportFormat}`,
				filters: [{ name: exportFormat.toUpperCase(), extensions: [exportFormat] }]
			});
			if (filePath) {
				let content: string;
				if (exportFormat === 'json') {
					content = JSON.stringify(result, null, 2);
				} else {
					const headers = ['URL', 'Path', 'Status', 'Content Length', 'Title', 'Category', 'Login Form', 'Confidence', 'Likely Admin'];
					const rows = result.found_paths.map((p: AdminPath) => [
						p.url, p.path, p.status_code.toString(),
						p.content_length?.toString() || '', p.title || '',
						p.category, p.has_login_form ? 'Yes' : 'No',
						p.confidence.toFixed(2), p.is_likely_admin ? 'Yes' : 'No'
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
</script>

<div class="nd-page">
	<div class="page-header">
		<div class="header-left">
			<a href="/" class="back-link">{$tr('common.backToHome')}</a>
			<h1 class="page-title">🔐 {$tr('adminFinder.title')}</h1>
			<p class="page-subtitle">{$tr('adminFinder.subtitle')}</p>
		</div>
	</div>

	<div class="tabs">
		<button class="tab-btn {activeMainTab === 'analyze' ? 'active' : ''}" onclick={() => activeMainTab = 'analyze'}>
			<span class="tab-icon">🔍</span> {$tr('adminFinder.scan')}
		</button>
		<button class="tab-btn {activeMainTab === 'history' ? 'active' : ''}" onclick={() => activeMainTab = 'history'}>
			<span class="tab-icon">📋</span> {$tr('adminFinder.history')}
		</button>
		<button class="tab-btn {activeMainTab === 'help' ? 'active' : ''}" onclick={() => activeMainTab = 'help'}>
			<span class="tab-icon">📖</span> {$tr('adminFinder.help')}
		</button>
	</div>

	{#if activeMainTab === 'analyze'}
		<div class="content-grid">
			<div class="input-section">
				<div class="section-card">
					<h2 class="section-title">{$tr('adminFinder.configTitle')}</h2>
					<p class="section-desc">{$tr('adminFinder.configDesc')}</p>

					<div class="form-group">
						<label class="form-label">{$tr('adminFinder.targetUrl')}</label>
						<input type="text" bind:value={url} placeholder="https://example.com" class="form-input" disabled={processing} onkeydown={(e) => e.key === 'Enter' && find()} />
					</div>

					<div class="form-group">
						<label class="form-label">{$tr('adminFinder.scanMode')}</label>
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
							<label class="form-label">{$tr('adminFinder.timeout')}</label>
							<input type="number" bind:value={timeout} class="form-input" min="5" max="60" disabled={processing} />
						</div>
						<div class="form-group">
							<label class="form-label">{$tr('adminFinder.concurrent')}</label>
							<input type="number" bind:value={concurrent} class="form-input" min="1" max="30" disabled={processing} />
						</div>
					</div>

					<div class="form-group">
						<label class="form-label">{$tr('adminFinder.detectionOptions')}</label>
						<div class="chip-grid">
							<label class="target-chip {followRedirects ? 'active' : ''}">
								<input type="checkbox" bind:checked={followRedirects} />
								<span>↪️ {$tr('adminFinder.followRedirects')}</span>
							</label>
							<label class="target-chip {randomizeUa ? 'active' : ''}">
								<input type="checkbox" bind:checked={randomizeUa} />
								<span>🎲 {$tr('adminFinder.randomUa')}</span>
							</label>
							<label class="target-chip {detectLoginForms ? 'active' : ''}">
								<input type="checkbox" bind:checked={detectLoginForms} />
								<span>🔐 {$tr('adminFinder.detectLoginForms')}</span>
							</label>
							<label class="target-chip {detectWaf ? 'active' : ''}">
								<input type="checkbox" bind:checked={detectWaf} />
								<span>🛡️ {$tr('adminFinder.detectWaf')}</span>
							</label>
						</div>
					</div>

					<div class="button-group">
						<button class="btn-primary" onclick={find} disabled={processing || !url.trim()}>
							{#if processing}<span class="spinner-sm"></span>{:else}🔍{/if}
							{processing ? $tr('adminFinder.scanning') : $tr('adminFinder.scan')}
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
								<h2 class="section-title" style="margin-bottom:0">🔐 {result.url}</h2>
							</div>
							<div class="header-actions">
								<div class="resource-score-badge">
									<span class="score-value">{result.found_paths.length}</span>
									<span class="score-label">{$tr('adminFinder.pathsFound')}</span>
								</div>
								<select bind:value={exportFormat} class="export-select" disabled={exporting}>
									<option value="json">JSON</option>
									<option value="csv">CSV</option>
								</select>
								<button class="btn-export" onclick={exportResult} disabled={exporting || !result}>
									{#if exporting}<span class="spinner-sm"></span>{:else}📤{/if}
									{$tr('adminFinder.export')}
								</button>
							</div>
						</div>

						{#if result.waf_detected && result.waf_detected.detected}
							<div class="waf-warning">
								<span class="waf-icon">🛡️</span>
								<div class="waf-info">
									<span class="waf-name">{$tr('adminFinder.wafDetected')}: {result.waf_detected.waf_name || 'Unknown'}</span>
									<span class="waf-evidence">{result.waf_detected.evidence.join(', ')}</span>
								</div>
							</div>
						{/if}

						<div class="result-tabs">
							<button class="result-tab {activeResultTab === 'overview' ? 'active' : ''}" onclick={() => activeResultTab = 'overview'}>
								<span>📊</span> {$tr('adminFinder.tabOverview')}
							</button>
							<button class="result-tab {activeResultTab === 'paths' ? 'active' : ''}" onclick={() => activeResultTab = 'paths'}>
								<span>📂</span> {$tr('adminFinder.tabPaths')}
							</button>
							<button class="result-tab {activeResultTab === 'categories' ? 'active' : ''}" onclick={() => activeResultTab = 'categories'}>
								<span>🏷️</span> {$tr('adminFinder.tabCategories')}
							</button>
						</div>

						{#if activeResultTab === 'overview'}
							<div class="overview-grid">
								<div class="overview-stat">
									<span class="stat-label">{$tr('adminFinder.pathsTested')}</span>
									<span class="stat-value">{result.paths_tested}</span>
								</div>
								<div class="overview-stat">
									<span class="stat-label">📂 {$tr('adminFinder.pathsFound')}</span>
									<span class="stat-value" style="color: {result.found_paths.length > 0 ? '#a855f7' : '#64748b'}">{result.found_paths.length}</span>
								</div>
								<div class="overview-stat">
									<span class="stat-label">🔐 {$tr('adminFinder.likelyAdmin')}</span>
									<span class="stat-value" style="color: {getLikelyAdminCount() > 0 ? '#22c55e' : '#64748b'}">{getLikelyAdminCount()}</span>
								</div>
								<div class="overview-stat">
									<span class="stat-label">🔑 {$tr('adminFinder.loginForms')}</span>
									<span class="stat-value" style="color: {getLoginFormCount() > 0 ? '#3b82f6' : '#64748b'}">{getLoginFormCount()}</span>
								</div>
								<div class="overview-stat">
									<span class="stat-label">⏱️ {$tr('adminFinder.scanDuration')}</span>
									<span class="stat-value" style="color: #f59e0b">{formatDuration(result.scan_duration_ms)}</span>
								</div>
								<div class="overview-stat">
									<span class="stat-label">🛡️ WAF</span>
									<span class="stat-value" style="color: {result.waf_detected?.detected ? '#ef4444' : '#22c55e'}">{result.waf_detected?.detected ? $tr('adminFinder.wafYes') : $tr('adminFinder.wafNo')}</span>
								</div>
							</div>

							{#if result.categories && result.categories.length > 0}
								<h3 class="subsection-title">🏷️ {$tr('adminFinder.categoryDistribution')}</h3>
								<div class="category-grid">
									{#each result.categories.slice(0, 12) as cat}
										<div class="category-chip" style="border-color: {getCategoryColor(cat.name)}40; background: {getCategoryColor(cat.name)}10">
											<span class="cat-name" style="color: {getCategoryColor(cat.name)}">{cat.name}</span>
											<span class="cat-count">{cat.count}</span>
										</div>
									{/each}
								</div>
							{/if}

							{#if result.found_paths.filter(p => p.is_likely_admin).length > 0}
								<h3 class="subsection-title">🔐 {$tr('adminFinder.topLikelyAdmin')}</h3>
								<div class="path-list">
									{#each result.found_paths.filter(p => p.is_likely_admin).slice(0, 10) as path}
										<div class="path-item admin">
											<div class="path-header">
												<span class="path-status" style="color: {getStatusColor(path.status_code)}">{path.status_code}</span>
												<span class="path-url">{path.path}</span>
												<span class="confidence-badge" style="background: {getConfidenceColor(path.confidence)}20; color: {getConfidenceColor(path.confidence)}">
													{Math.round(path.confidence * 100)}%
												</span>
												{#if path.has_login_form}<span class="login-badge">🔑</span>{/if}
											</div>
											{#if path.title}<div class="path-meta">📄 {path.title}</div>{/if}
											<div class="path-meta">
												<span class="cat-tag" style="background: {getCategoryColor(path.category)}20; color: {getCategoryColor(path.category)}">{path.category}</span>
												{#if path.content_length}<span>{formatSize(path.content_length)}</span>{/if}
												<span>{path.response_time_ms}ms</span>
											</div>
										</div>
									{/each}
								</div>
							{/if}

						{:else if activeResultTab === 'paths'}
							<div class="filter-bar">
								<div class="filter-left">
									<label class="target-chip {filterAdmin ? 'active' : ''}" onclick={() => filterAdmin = !filterAdmin}>
										<input type="checkbox" bind:checked={filterAdmin} />
										<span>🔐 {$tr('adminFinder.filterAdmin')}</span>
									</label>
								</div>
								<div class="filter-right">
									<input type="text" bind:value={searchQuery} placeholder="{$tr('adminFinder.searchPaths')}" class="search-input" />
									<span class="result-count">{getFilteredPaths().length}/{result.found_paths.length}</span>
								</div>
							</div>

							{#if getFilteredPaths().length > 0}
								<div class="path-list">
									{#each getFilteredPaths() as path}
										<div class="path-item" class:admin={path.is_likely_admin}>
											<div class="path-header">
												<span class="path-status" style="color: {getStatusColor(path.status_code)}">{path.status_code}</span>
												<span class="path-url">{path.path}</span>
												<span class="confidence-badge" style="background: {getConfidenceColor(path.confidence)}20; color: {getConfidenceColor(path.confidence)}">
													{Math.round(path.confidence * 100)}%
												</span>
												{#if path.is_likely_admin}<span class="admin-badge">🔐</span>{/if}
												{#if path.has_login_form}<span class="login-badge">🔑</span>{/if}
											</div>
											{#if path.title}<div class="path-meta">📄 {path.title}</div>{/if}
											{#if path.redirect_url}<div class="path-meta redirect">↪️ → {path.redirect_url}</div>{/if}
											<div class="path-meta">
												<span class="cat-tag" style="background: {getCategoryColor(path.category)}20; color: {getCategoryColor(path.category)}">{path.category}</span>
												{#if path.content_length}<span>{formatSize(path.content_length)}</span>{/if}
												<span>{path.response_time_ms}ms</span>
											</div>
										</div>
									{/each}
								</div>
							{:else}
								<div class="empty-result">{$tr('adminFinder.noPathsFound')}</div>
							{/if}

						{:else if activeResultTab === 'categories'}
							{#if result.categories && result.categories.length > 0}
								<div class="categories-detail">
									{#each result.categories.sort((a, b) => b.count - a.count) as cat}
										<div class="category-section">
											<div class="category-header" style="border-left: 3px solid {getCategoryColor(cat.name)}">
												<span class="cat-name" style="color: {getCategoryColor(cat.name)}">{cat.name}</span>
												<span class="cat-count-badge">{cat.count}</span>
											</div>
											<div class="category-paths">
												{#each cat.paths as p}
													<span class="cat-path-tag">{p}</span>
												{/each}
											</div>
										</div>
									{/each}
								</div>
							{:else}
								<div class="empty-result">{$tr('adminFinder.noCategories')}</div>
							{/if}
						{/if}

					{:else}
						<div class="empty-state">
							<div class="empty-icon">🔐</div>
							<p>{$tr('adminFinder.noResults')}</p>
						</div>
					{/if}
				</div>
			</div>
		</div>
	{:else if activeMainTab === 'history'}
		<div class="section-card">
			<ToolHistory toolType="admin_finder" toolName={$tr('adminFinder.title')} bind:this={historyComponent} />
		</div>
	{:else if activeMainTab === 'help'}
		<div class="section-card">
			<ToolHelp toolType="admin_finder" />
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
		font-size: 0.8rem;
		font-weight: 500;
		color: #94a3b8;
		margin-bottom: 0.35rem;
	}

	.form-input {
		width: 100%;
		padding: 0.5rem 0.75rem;
		border: 1px solid rgba(148, 163, 184, 0.15);
		border-radius: 0.5rem;
		background: rgba(15, 23, 42, 0.8);
		color: #f1f5f9;
		font-size: 0.85rem;
		box-sizing: border-box;
		transition: border-color 0.2s;
	}

	.form-input:focus {
		outline: none;
		border-color: rgba(168, 85, 247, 0.5);
		box-shadow: 0 0 0 2px rgba(168, 85, 247, 0.1);
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
		display: flex;
		flex-direction: column;
		align-items: center;
		padding: 0.5rem 0.35rem;
		border: 1px solid rgba(148, 163, 184, 0.15);
		border-radius: 0.5rem;
		background: rgba(15, 23, 42, 0.6);
		cursor: pointer;
		transition: all 0.2s;
	}

	.mode-btn.active {
		border-color: rgba(168, 85, 247, 0.5);
		background: rgba(168, 85, 247, 0.1);
	}

	.mode-btn:hover:not(.active) {
		border-color: rgba(148, 163, 184, 0.3);
	}

	.mode-name {
		font-size: 0.8rem;
		font-weight: 600;
		color: #f1f5f9;
	}

	.mode-desc {
		font-size: 0.65rem;
		color: #94a3b8;
		margin-top: 0.15rem;
	}

	.mode-btn.active .mode-name { color: #c4b5fd; }

	.chip-grid {
		display: flex;
		flex-wrap: wrap;
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

	.spinner-sm {
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
		padding: 0.75rem 1rem;
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
		margin-bottom: 1rem;
		flex-wrap: wrap;
		gap: 0.5rem;
	}

	.result-domain { display: flex; align-items: center; gap: 0.5rem; }

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
		padding: 0.35rem 0.75rem;
		background: rgba(168, 85, 247, 0.1);
		border: 1px solid rgba(168, 85, 247, 0.2);
		border-radius: 0.5rem;
	}

	.score-value { font-size: 1.1rem; font-weight: 700; color: #a855f7; }
	.score-label { font-size: 0.65rem; color: #94a3b8; }

	.export-select {
		padding: 0.35rem 0.5rem;
		border: 1px solid rgba(148, 163, 184, 0.15);
		border-radius: 0.4rem;
		background: rgba(15, 23, 42, 0.8);
		color: #f1f5f9;
		font-size: 0.8rem;
	}

	.btn-export {
		display: flex;
		align-items: center;
		gap: 0.3rem;
		padding: 0.4rem 0.75rem;
		border: 1px solid rgba(148, 163, 184, 0.15);
		border-radius: 0.4rem;
		background: rgba(15, 23, 42, 0.6);
		color: #94a3b8;
		cursor: pointer;
		font-size: 0.8rem;
		transition: all 0.2s;
	}

	.btn-export:hover:not(:disabled) {
		background: rgba(148, 163, 184, 0.2);
		color: #e2e8f0;
	}

	.btn-export:disabled { opacity: 0.5; cursor: not-allowed; }

	.waf-warning {
		display: flex;
		align-items: center;
		gap: 0.75rem;
		padding: 0.75rem 1rem;
		background: rgba(239, 68, 68, 0.1);
		border: 1px solid rgba(239, 68, 68, 0.2);
		border-radius: 0.5rem;
		margin-bottom: 1rem;
	}

	.waf-icon { font-size: 1.25rem; }
	.waf-info { display: flex; flex-direction: column; gap: 0.15rem; }
	.waf-name { color: #fca5a5; font-weight: 600; font-size: 0.85rem; }
	.waf-evidence { color: #94a3b8; font-size: 0.75rem; }

	.result-tabs {
		display: flex;
		gap: 0.2rem;
		margin-bottom: 1rem;
		background: rgba(15, 23, 42, 0.4);
		border: 1px solid rgba(148, 163, 184, 0.1);
		border-radius: 0.5rem;
		padding: 0.2rem;
		overflow-x: auto;
	}

	.result-tab {
		padding: 0.4rem 0.75rem;
		border: none;
		border-radius: 0.35rem;
		background: transparent;
		cursor: pointer;
		font-size: 0.78rem;
		color: #94a3b8;
		transition: all 0.2s;
		white-space: nowrap;
		display: flex;
		align-items: center;
		gap: 0.25rem;
	}

	.result-tab.active {
		background: rgba(168, 85, 247, 0.15);
		color: #c4b5fd;
		font-weight: 600;
	}

	.result-tab:hover:not(.active) { background: rgba(148, 163, 184, 0.1); }

	.overview-grid {
		display: grid;
		grid-template-columns: repeat(3, 1fr);
		gap: 0.75rem;
		margin-bottom: 1.25rem;
	}

	.overview-stat {
		display: flex;
		flex-direction: column;
		align-items: center;
		padding: 0.75rem;
		background: rgba(15, 23, 42, 0.5);
		border: 1px solid rgba(148, 163, 184, 0.1);
		border-radius: 0.5rem;
	}

	.stat-label { font-size: 0.75rem; color: #94a3b8; margin-bottom: 0.25rem; }
	.stat-value { font-size: 1.25rem; font-weight: 700; color: #f1f5f9; }

	.subsection-title {
		font-size: 0.9rem;
		font-weight: 600;
		color: #f1f5f9;
		margin: 1rem 0 0.5rem;
	}

	.category-grid {
		display: flex;
		flex-wrap: wrap;
		gap: 0.35rem;
		margin-bottom: 1rem;
	}

	.category-chip {
		display: flex;
		align-items: center;
		gap: 0.35rem;
		padding: 0.3rem 0.6rem;
		border: 1px solid;
		border-radius: 0.4rem;
		font-size: 0.75rem;
	}

	.cat-name { font-weight: 600; }
	.cat-count { color: #94a3b8; }

	.path-list {
		display: flex;
		flex-direction: column;
		gap: 0.4rem;
	}

	.path-item {
		padding: 0.6rem 0.75rem;
		background: rgba(15, 23, 42, 0.5);
		border: 1px solid rgba(148, 163, 184, 0.1);
		border-radius: 0.5rem;
		transition: border-color 0.2s;
	}

	.path-item.admin {
		border-color: rgba(168, 85, 247, 0.3);
		background: rgba(168, 85, 247, 0.05);
	}

	.path-header {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		flex-wrap: wrap;
	}

	.path-status {
		font-weight: 700;
		font-size: 0.85rem;
		min-width: 2rem;
		font-family: monospace;
	}

	.path-url {
		font-size: 0.85rem;
		color: #e2e8f0;
		flex: 1;
		word-break: break-all;
		min-width: 0;
	}

	.confidence-badge {
		padding: 0.1rem 0.4rem;
		border-radius: 0.3rem;
		font-size: 0.7rem;
		font-weight: 600;
	}

	.admin-badge {
		font-size: 0.75rem;
	}

	.login-badge {
		font-size: 0.75rem;
	}

	.path-meta {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		margin-top: 0.25rem;
		font-size: 0.75rem;
		color: #94a3b8;
		flex-wrap: wrap;
	}

	.path-meta.redirect { color: #60a5fa; }

	.cat-tag {
		padding: 0.1rem 0.35rem;
		border-radius: 0.25rem;
		font-size: 0.7rem;
		font-weight: 600;
	}

	.filter-bar {
		display: flex;
		justify-content: space-between;
		align-items: center;
		margin-bottom: 0.75rem;
		flex-wrap: wrap;
		gap: 0.5rem;
	}

	.filter-left { display: flex; gap: 0.5rem; align-items: center; }

	.filter-right {
		display: flex;
		align-items: center;
		gap: 0.5rem;
	}

	.search-input {
		padding: 0.35rem 0.6rem;
		border: 1px solid rgba(148, 163, 184, 0.15);
		border-radius: 0.4rem;
		background: rgba(15, 23, 42, 0.8);
		color: #f1f5f9;
		font-size: 0.8rem;
		width: 180px;
	}

	.search-input:focus {
		outline: none;
		border-color: rgba(168, 85, 247, 0.5);
	}

	.result-count { font-size: 0.75rem; color: #64748b; }

	.categories-detail {
		display: flex;
		flex-direction: column;
		gap: 0.75rem;
	}

	.category-section {
		padding: 0.75rem;
		background: rgba(15, 23, 42, 0.4);
		border: 1px solid rgba(148, 163, 184, 0.1);
		border-radius: 0.5rem;
	}

	.category-header {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		padding-left: 0.5rem;
		margin-bottom: 0.5rem;
	}

	.cat-count-badge {
		padding: 0.1rem 0.4rem;
		background: rgba(168, 85, 247, 0.15);
		color: #c4b5fd;
		border-radius: 0.3rem;
		font-size: 0.7rem;
		font-weight: 600;
	}

	.category-paths {
		display: flex;
		flex-wrap: wrap;
		gap: 0.3rem;
	}

	.cat-path-tag {
		padding: 0.2rem 0.45rem;
		background: rgba(15, 23, 42, 0.6);
		border: 1px solid rgba(148, 163, 184, 0.1);
		border-radius: 0.3rem;
		font-size: 0.72rem;
		color: #cbd5e1;
	}

	.empty-result {
		text-align: center;
		padding: 2rem;
		color: #64748b;
		font-size: 0.9rem;
	}

	.empty-state {
		text-align: center;
		padding: 3rem 1rem;
		color: #64748b;
	}

	.empty-icon { font-size: 3rem; margin-bottom: 0.75rem; }

	@media (max-width: 900px) {
		.content-grid {
			grid-template-columns: 1fr;
		}
		.overview-grid {
			grid-template-columns: repeat(2, 1fr);
		}
	}
</style>
