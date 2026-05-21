<script lang="ts">
	import { tr, t } from '$lib/i18n';
	import ToolHistory from '$lib/components/ToolHistory.svelte';
	import ToolHelp from '$lib/components/ToolHelp.svelte';
	import { listen } from '@tauri-apps/api/event';

	interface PlatformResult {
		platform: string;
		url: string;
		found: boolean;
		status_code: number | null;
		error: string | null;
		error_type: string | null;
		category: string;
		response_time_ms: number | null;
		page_title: string | null;
		is_captcha: boolean;
		is_censored: boolean;
		retry_count: number;
	}

	interface CategorySummary {
		category: string;
		total: number;
		found: number;
	}

	interface BatchUsernameResult {
		username: string;
		found_count: number;
		total_checked: number;
		digital_footprint_score: number;
		risk_level: string;
		found_on: PlatformResult[];
	}

	interface UsernameOsintResult {
		username: string;
		found_on: PlatformResult[];
		not_found_on: PlatformResult[];
		errors: PlatformResult[];
		total_found: number;
		total_checked: number;
		total_errors: number;
		digital_footprint_score: number;
		risk_level: string;
		category_summary: CategorySummary[];
		summary: string;
		permutations: string[];
		batch_results: BatchUsernameResult[];
	}

	interface OsintProgress {
		checked: number;
		total: number;
		found: number;
		errors: number;
		current_platform: string;
		username: string;
	}

	interface OsintPlatform {
		id: number | null;
		name: string;
		display_name: string | null;
		category: string;
		url_template: string;
		error_type: string;
		error_codes: string | null;
		error_messages: string | null;
		error_url: string | null;
		regex_check: string | null;
		request_method: string;
		headers: string | null;
		payload: string | null;
		is_active: boolean;
		is_built_in: boolean;
		priority: number;
		notes: string | null;
		source: string;
		created_at: string;
		updated_at: string;
	}

	let username = $state('');
	let additionalUsernames = $state('');
	let activeMainTab = $state('check');
	let historyComponent: ToolHistory;
	let selectedCategories = $state<string[]>([]);
	let result: UsernameOsintResult | null = $state(null);
	let error = $state('');
	let processing = $state(false);
	let activeResultTab = $state('overview');
	let platforms: OsintPlatform[] = $state([]);
	let platformCount = $state(0);
	let platformCategories: string[] = $state([]);
	let showAddPlatform = $state(false);
	let newPlatform: Partial<OsintPlatform> = $state({
		name: '', display_name: '', category: 'social', url_template: 'https://example.com/{}',
		error_type: 'status_code', error_codes: '[404]', request_method: 'GET'
	});
	let platformFilterCategory = $state('');
	let savingToTarget = $state(false);
	let editingPlatform: OsintPlatform | null = $state(null);
	let showEditPlatform = $state(false);
	let showImportSherlock = $state(false);
	let sherlockJsonText = $state('');
	let sherlockImporting = $state(false);
	let maigretImporting = $state(false);
	let maigretImportStats: { total_parsed: number; total_platforms: number; imported: number; updated: number; failed: number; skipped_no_url: number } | null = $state(null);
	let platformSearchQuery = $state('');
	let showInactivePlatforms = $state(false);
	let generatePermutations = $state(false);
	let retries = $state(1);
	let concurrentLimit = $state(15);
	let timeout = $state(10);
	let showAdvanced = $state(false);
	let progress: OsintProgress | null = $state(null);
	let liveResults: PlatformResult[] = $state([]);
	let showExportMenu = $state(false);

	const categories = [
		{ id: 'social', icon: '💬' },
		{ id: 'developer', icon: '💻' },
		{ id: 'gaming', icon: '🎮' },
		{ id: 'creative', icon: '🎨' },
		{ id: 'music', icon: '🎵' },
		{ id: 'security', icon: '🔒' },
		{ id: 'finance', icon: '💰' },
		{ id: 'dating', icon: '❤️' },
		{ id: 'forum', icon: '📝' },
		{ id: 'other', icon: '📌' },
	];

	async function loadPlatforms() {
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			platforms = await invoke<OsintPlatform[]>('get_osint_platforms_command', {
				category: platformFilterCategory || null,
				activeOnly: !showInactivePlatforms
			});
			platformCount = await invoke<number>('count_osint_platforms_command');
			platformCategories = await invoke<string[]>('get_osint_platform_categories_command');
		} catch (e) { console.error('Failed to load platforms:', e); }
	}

	function getFilteredPlatforms(): OsintPlatform[] {
		if (!platformSearchQuery.trim()) return platforms;
		const q = platformSearchQuery.toLowerCase();
		return platforms.filter(p =>
			p.name.toLowerCase().includes(q) ||
			(p.display_name && p.display_name.toLowerCase().includes(q)) ||
			p.url_template.toLowerCase().includes(q)
		);
	}

	function toggleCategory(cat: string) {
		if (selectedCategories.includes(cat)) {
			selectedCategories = selectedCategories.filter(c => c !== cat);
		} else {
			selectedCategories = [...selectedCategories, cat];
		}
	}

	function handleKeydown(e: KeyboardEvent) {
		if (e.key === 'Enter' && !processing && username.trim()) {
			checkUsername();
		}
	}

	async function checkUsername() {
		if (!username.trim()) { error = t('usernameOsint.error.emptyInput'); return; }
		processing = true; error = ''; result = null; progress = null; liveResults = [];

		const usernames = additionalUsernames.trim()
			? additionalUsernames.trim().split(/[\s,]+/).filter((u: string) => u.trim())
			: [];

		const unlistenProgress = await listen<OsintProgress>('osint-progress', (event) => {
			progress = event.payload;
		});

		const unlistenResult = await listen<PlatformResult>('osint-platform-result', (event) => {
			liveResults = [...liveResults, event.payload];
		});

		try {
			const { invoke } = await import('@tauri-apps/api/core');
			result = await invoke<UsernameOsintResult>('check_username_osint_command', {
				config: {
					username: username.trim(),
					timeout: timeout,
					platforms: [],
					categories: selectedCategories,
					check_all: selectedCategories.length === 0,
					retries: retries,
					concurrent_limit: concurrentLimit,
					generate_permutations: generatePermutations,
					usernames: usernames,
					recursive_search: false,
					max_recursive_depth: 2,
					tags: [],
					exclude_tags: [],
					top_sites: 500,
					use_disabled_sites: false,
					id_type: 'username',
					cookie_jar: null,
					proxy_url: null,
				}
			});
		} catch (e: any) { error = e.toString(); }
		finally { processing = false; unlistenProgress(); unlistenResult(); }
	}

	async function saveToTarget() {
		if (!result) return;
		const r = result;
		savingToTarget = true;
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			const createResult = await invoke<{ success: boolean; target_id: number | null; message: string }>('target_manager', {
				action: 'create',
				name: r.username,
				targetType: 'Username',
				targetValue: r.username,
				description: t('usernameOsint.saveTarget.desc', { found: r.total_found, total: r.total_checked, score: Math.round(r.digital_footprint_score), risk: t(`usernameOsint.riskLevels.${r.risk_level}`) }),
				tags: 'osint,' + r.risk_level,
				location: null,
				organization: null,
			});
			if (!createResult.success || !createResult.target_id) {
				error = createResult.message || 'Failed to create target';
				return;
			}
			const targetId = createResult.target_id;
			const scanResults = r.found_on.map(p => ({
				target_id: targetId,
				username: r.username,
				platform_name: p.platform,
				platform_url: p.url,
				found: true,
				status_code: p.status_code,
				error_message: null,
				category: p.category,
				response_time_ms: p.response_time_ms,
				scanned_at: new Date().toISOString(),
			}));
			await invoke('save_osint_scan_results_command', { results: scanResults });
			error = '';
		} catch (e: any) {
			error = e.toString();
		} finally {
			savingToTarget = false;
		}
	}

	async function addPlatform() {
		if (!newPlatform.name || !newPlatform.url_template) return;
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			await invoke('create_osint_platform_command', {
				platform: {
					id: null,
					name: newPlatform.name,
					display_name: newPlatform.display_name || null,
					category: newPlatform.category || 'other',
					url_template: newPlatform.url_template,
					error_type: newPlatform.error_type || 'status_code',
					error_codes: newPlatform.error_codes || '[404]',
					error_messages: null,
					error_url: null,
					regex_check: null,
					request_method: newPlatform.request_method || 'GET',
					headers: null,
					payload: null,
					is_active: true,
					is_built_in: false,
					priority: 0,
					notes: null,
					source: 'custom',
					created_at: new Date().toISOString(),
					updated_at: new Date().toISOString(),
				}
			});
			showAddPlatform = false;
			newPlatform = { name: '', display_name: '', category: 'social', url_template: 'https://example.com/{}', error_type: 'status_code', error_codes: '[404]', request_method: 'GET' };
			await loadPlatforms();
		} catch (e: any) { console.error('Failed to add platform:', e); }
	}

	async function deletePlatform(name: string) {
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			await invoke('delete_osint_platform_command', { name });
			await loadPlatforms();
		} catch (e: any) { console.error('Failed to delete platform:', e); }
	}

	async function togglePlatformActive(platform: OsintPlatform) {
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			const updated = { ...platform, is_active: !platform.is_active, updated_at: new Date().toISOString() };
			await invoke('update_osint_platform_command', { platform: updated });
			await loadPlatforms();
		} catch (e: any) { console.error('Failed to toggle platform:', e); }
	}

	function startEditPlatform(platform: OsintPlatform) {
		editingPlatform = { ...platform };
		showEditPlatform = true;
	}

	async function saveEditPlatform() {
		if (!editingPlatform) return;
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			const updated = { ...editingPlatform, updated_at: new Date().toISOString() };
			await invoke('update_osint_platform_command', { platform: updated });
			showEditPlatform = false;
			editingPlatform = null;
			await loadPlatforms();
		} catch (e: any) { console.error('Failed to update platform:', e); }
	}

	async function handleSherlockImport() {
		if (!sherlockJsonText.trim()) return;
		sherlockImporting = true;
		try {
			await importSherlockJson(sherlockJsonText);
			sherlockJsonText = '';
			showImportSherlock = false;
		} finally {
			sherlockImporting = false;
		}
	}

	async function handleSherlockFileImport() {
		try {
			const { open } = await import('@tauri-apps/plugin-dialog');
			const path = await open({
				filters: [{ name: 'JSON', extensions: ['json'] }],
				multiple: false,
			});
			if (path && typeof path === 'string') {
				const { readTextFile } = await import('@tauri-apps/plugin-fs');
				const content = await readTextFile(path);
				sherlockJsonText = content;
			}
		} catch (e) { console.error('File open failed:', e); }
	}

	async function handleMaigretImport() {
		maigretImporting = true;
		maigretImportStats = null;
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			maigretImportStats = await invoke('import_maigret_data_command');
			await loadPlatforms();
		} catch (e: any) {
			error = e.toString();
		} finally {
			maigretImporting = false;
		}
	}

	async function importSherlockJson(jsonStr: string) {
		try {
			const data = JSON.parse(jsonStr);
			const { invoke } = await import('@tauri-apps/api/core');
			const platforms: Partial<OsintPlatform>[] = [];
			for (const [name, info] of Object.entries(data)) {
				const p = info as any;
				platforms.push({
					id: null,
					name,
					display_name: p.username_unavailable || name,
					category: mapSherlockCategory(p.tags),
					url_template: p.url || '',
					error_type: p.error_type === 'status_code' ? 'status_code' : p.error_type === 'message' ? 'message' : 'status_code',
					error_codes: p.error_code ? `[${p.error_code}]` : '[404]',
					error_messages: p.error_msg ? JSON.stringify([p.error_msg]) : null,
					error_url: p.error_url || null,
					regex_check: p.regex_check || null,
					request_method: (p.request_method || 'GET').toUpperCase(),
					headers: null,
					payload: null,
					is_active: true,
					is_built_in: false,
					priority: 0,
					notes: null,
					source: 'sherlock',
					created_at: new Date().toISOString(),
					updated_at: new Date().toISOString(),
				});
			}
			await invoke('batch_import_osint_platforms_command', { platforms });
			await loadPlatforms();
		} catch (e: any) { console.error('Import failed:', e); }
	}

	function mapSherlockCategory(tags: string[] | undefined): string {
		if (!tags) return 'other';
		const t = tags.map(x => x.toLowerCase());
		if (t.some(x => ['social', 'photo', 'video', 'blog', 'news', 'dating'].includes(x))) return 'social';
		if (t.some(x => ['tech', 'coding', 'developer'].includes(x))) return 'developer';
		if (t.some(x => ['gaming'].includes(x))) return 'gaming';
		if (t.some(x => ['music', 'audio'].includes(x))) return 'music';
		if (t.some(x => ['art', 'design'].includes(x))) return 'creative';
		if (t.some(x => ['security', 'hacking'].includes(x))) return 'security';
		return 'other';
	}

	function downloadBlob(blob: Blob, filename: string) {
		const url = URL.createObjectURL(blob);
		const a = document.createElement('a');
		a.href = url;
		a.download = filename;
		document.body.appendChild(a);
		a.click();
		document.body.removeChild(a);
		URL.revokeObjectURL(url);
	}

	function exportJSON() {
		if (!result) return;
		const blob = new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' });
		downloadBlob(blob, `osint_${result.username}_${new Date().toISOString().slice(0,10)}.json`);
		showExportMenu = false;
	}

	function exportCSV() {
		if (!result) return;
		const headers = [
			t('usernameOsint.export.colPlatform'),
			t('usernameOsint.export.colUrl'),
			t('usernameOsint.export.colFound'),
			t('usernameOsint.export.colStatusCode'),
			t('usernameOsint.export.colCategory'),
			t('usernameOsint.export.colErrorType'),
			t('usernameOsint.export.colPageTitle'),
			t('usernameOsint.export.colResponseTime'),
			t('usernameOsint.export.colIsCaptcha'),
			t('usernameOsint.export.colIsCensored'),
			t('usernameOsint.export.colRetryCount'),
		];
		const rows = [...result.found_on, ...result.not_found_on, ...result.errors].map(p => [
			p.platform, p.url, p.found ? t('usernameOsint.export.yes') : t('usernameOsint.export.no'), p.status_code ?? '',
			p.category, p.error_type ?? '', p.page_title ?? '',
			p.response_time_ms ?? '', p.is_captcha ? t('usernameOsint.export.yes') : '', p.is_censored ? t('usernameOsint.export.yes') : '', p.retry_count
		]);
		const csvContent = [headers, ...rows].map(row =>
			row.map(cell => `"${String(cell).replace(/"/g, '""')}"`).join(',')
		).join('\n');
		const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8' });
		downloadBlob(blob, `osint_${result.username}_${new Date().toISOString().slice(0,10)}.csv`);
		showExportMenu = false;
	}

	function exportMarkdown() {
		if (!result) return;
		let md = `# ${t('usernameOsint.export.reportTitle')}: ${result.username}\n\n`;
		md += `**${t('usernameOsint.export.scanDate')}:** ${new Date().toISOString()}\n\n`;
		md += `## ${t('usernameOsint.export.summary')}\n\n`;
		md += `- **${t('usernameOsint.export.totalChecked')}:** ${result.total_checked}\n`;
		md += `- **${t('usernameOsint.export.found')}:** ${result.total_found}\n`;
		md += `- **${t('usernameOsint.export.notFound')}:** ${result.total_checked - result.total_found - result.total_errors}\n`;
		md += `- **${t('usernameOsint.export.errors')}:** ${result.total_errors}\n`;
		md += `- **${t('usernameOsint.export.footprintScore')}:** ${Math.round(result.digital_footprint_score)}/100\n`;
		md += `- **${t('usernameOsint.export.riskLevel')}:** ${result.risk_level}\n\n`;

		if (result.permutations.length > 0) {
			md += `## ${t('usernameOsint.export.variantsChecked')}\n\n`;
			md += result.permutations.map(p => `- \`${p}\``).join('\n') + '\n\n';
		}

		if (result.batch_results.length > 1) {
			md += `## ${t('usernameOsint.export.batchResults')}\n\n`;
			md += `| ${t('usernameOsint.export.colPlatform')} | ${t('usernameOsint.export.colFound2')} | ${t('usernameOsint.export.colChecked')} | ${t('usernameOsint.export.colScore')} | ${t('usernameOsint.export.colRisk')} |\n|---|---|---|---|---|\n`;
			result.batch_results.forEach(b => {
				md += `| ${b.username} | ${b.found_count} | ${b.total_checked} | ${Math.round(b.digital_footprint_score)} | ${b.risk_level} |\n`;
			});
			md += '\n';
		}

		md += `## ${t('usernameOsint.export.categorySummary')}\n\n`;
		md += `| ${t('usernameOsint.platforms.category')} | ${t('usernameOsint.export.colFound2')} | ${t('usernameOsint.export.colTotal')} | ${t('usernameOsint.export.colRatio')} |\n|---|---|---|---|\n`;
		result.category_summary.forEach(cs => {
			md += `| ${cs.category} | ${cs.found} | ${cs.total} | ${cs.total > 0 ? Math.round(cs.found / cs.total * 100) : 0}% |\n`;
		});
		md += '\n';

		if (result.found_on.length > 0) {
			md += `## ${t('usernameOsint.export.foundPlatforms')}\n\n`;
			md += `| ${t('usernameOsint.export.colPlatform')} | ${t('usernameOsint.export.colUrl')} | ${t('usernameOsint.export.colStatus')} | ${t('usernameOsint.export.colCategory')} | ${t('usernameOsint.export.colTitle')} | ${t('usernameOsint.export.colTime')} |\n|---|---|---|---|---|---|\n`;
			result.found_on.forEach(p => {
				md += `| ${p.platform} | ${p.url} | ${p.status_code ?? '-'} | ${p.category} | ${p.page_title ?? '-'} | ${p.response_time_ms ? p.response_time_ms + 'ms' : '-'} |\n`;
			});
			md += '\n';
		}

		if (result.errors.length > 0) {
			md += `## ${t('usernameOsint.export.errorPlatforms')}\n\n`;
			md += `| ${t('usernameOsint.export.colPlatform')} | ${t('usernameOsint.export.colError')} | ${t('usernameOsint.export.colErrorType')} | ${t('usernameOsint.export.colCategory')} |\n|---|---|---|---|\n`;
			result.errors.forEach(p => {
				md += `| ${p.platform} | ${p.error ?? t('usernameOsint.result.unknownError')} | ${p.error_type ?? '-'} | ${p.category} |\n`;
			});
			md += '\n';
		}

		const blob = new Blob([md], { type: 'text/markdown;charset=utf-8' });
		downloadBlob(blob, `osint_${result.username}_${new Date().toISOString().slice(0,10)}.md`);
		showExportMenu = false;
	}

	function getErrorTypeIcon(errorType: string | null): string {
		if (!errorType) return '';
		switch (errorType) {
			case 'captcha': return '🤖';
			case 'censored': return '🚫';
			case 'timeout': return '⏱️';
			case 'connection': return '🔌';
			case 'ssl': return '🔒';
			case 'network': return '📡';
			case 'empty_response': return '📭';
			default: return '⚠️';
		}
	}

	function getErrorTypeLabel(errorType: string | null): string {
		if (!errorType) return '';
		const key = `usernameOsint.errorTypes.${errorType}`;
		const label = t(key);
		return label === key ? errorType : label;
	}

	function clearAll() {
		username = '';
		additionalUsernames = '';
		result = null;
		error = '';
		selectedCategories = [];
		activeResultTab = 'overview';
		progress = null;
		generatePermutations = false;
	}

	function getRiskColor(level: string): string {
		switch (level) {
			case 'critical': return '#ef4444';
			case 'high': return '#f87171';
			case 'medium': return '#facc15';
			case 'low': return '#a3e635';
			case 'minimal': return '#10b981';
			default: return '#94a3b8';
		}
	}

	function getRiskLabel(level: string): string {
		const key = `usernameOsint.riskLevels.${level}`;
		const label = t(key);
		return label === key ? level : label;
	}

	function getCategoryIcon(cat: string): string {
		const found = categories.find(c => c.id === cat);
		return found ? found.icon : '📌';
	}

	function getCategoryLabel(cat: string): string {
		return t(`usernameOsint.categories.${cat}`);
	}

	$effect(() => {
		if (activeMainTab === 'platforms') {
			loadPlatforms();
		}
	});
</script>

<svelte:window onkeydown={handleKeydown} />

<div class="nd-page">
	<div class="page-header">
		<div class="header-left">
			<a href="/" class="back-link">{$tr('common.backToHome')}</a>
			<h1 class="page-title">👤 {$tr('usernameOsint.title')}</h1>
			<p class="page-subtitle">{$tr('usernameOsint.subtitle')}</p>
		</div>
	</div>

	<div class="tabs">
		<button class="tab-btn {activeMainTab === 'check' ? 'active' : ''}" onclick={() => activeMainTab = 'check'}>
			<span class="tab-icon">🔍</span> {$tr('usernameOsint.tabs.check')}
		</button>
		<button class="tab-btn {activeMainTab === 'platforms' ? 'active' : ''}" onclick={() => activeMainTab = 'platforms'}>
			<span class="tab-icon">🌐</span> {$tr('usernameOsint.tabs.platforms')} ({platformCount})
		</button>
		<button class="tab-btn {activeMainTab === 'history' ? 'active' : ''}" onclick={() => activeMainTab = 'history'}>
			<span class="tab-icon">📋</span> {$tr('usernameOsint.tabs.history')}
		</button>
		<button class="tab-btn {activeMainTab === 'help' ? 'active' : ''}" onclick={() => activeMainTab = 'help'}>
			<span class="tab-icon">📖</span> {$tr('usernameOsint.tabs.help')}
		</button>
	</div>

	{#if activeMainTab === 'check'}
		<div class="content-grid">
			<div class="input-section">
				<div class="section-card">
					<h2 class="section-title">{$tr('usernameOsint.config.title')}</h2>
					<p class="section-desc">{$tr('usernameOsint.config.desc')}</p>

					<div class="form-group">
						<label class="form-label">{$tr('usernameOsint.config.username')}</label>
						<input type="text" bind:value={username} placeholder="johndoe" class="form-input" disabled={processing} />
					</div>

					<div class="form-group">
						<label class="form-label">{$tr('usernameOsint.config.additionalUsernames')} <span class="form-hint-inline">({$tr('usernameOsint.config.additionalUsernamesHint')})</span></label>
						<textarea bind:value={additionalUsernames} placeholder={$tr('usernameOsint.config.additionalUsernamesPlaceholder')} class="form-input" style="min-height:60px; resize:vertical;" disabled={processing}></textarea>
					</div>

					<div class="form-group">
						<label class="toggle-label">
							<input type="checkbox" bind:checked={generatePermutations} disabled={processing} />
							<span>{$tr('usernameOsint.config.generatePermutations')}</span>
						</label>
						<p class="form-hint">{$tr('usernameOsint.config.generatePermutationsHint')}</p>
					</div>

					<div class="form-group">
						<label class="form-label">{$tr('usernameOsint.config.categoryFilter')}</label>
						<div class="chip-group">
							{#each categories as cat}
								<button class="target-chip {selectedCategories.includes(cat.id) ? 'active' : ''}" onclick={() => toggleCategory(cat.id)} disabled={processing}>
									<span>{cat.icon} {getCategoryLabel(cat.id)}</span>
								</button>
							{/each}
						</div>
						<p class="form-hint">{$tr('usernameOsint.config.categoryHint')}</p>
					</div>

					<div class="form-group">
						<button class="toggle-advanced-btn" onclick={() => showAdvanced = !showAdvanced}>
							{showAdvanced ? '▼' : '▶'} {$tr('usernameOsint.config.advancedSettings')}
						</button>
						{#if showAdvanced}
							<div class="advanced-settings">
								<div class="form-row">
									<div class="form-group" style="flex:1">
										<label class="form-label">{$tr('usernameOsint.config.timeout')}</label>
										<input type="number" bind:value={timeout} min={3} max={60} class="form-input" disabled={processing} />
									</div>
									<div class="form-group" style="flex:1">
										<label class="form-label">{$tr('usernameOsint.config.retries')}</label>
										<input type="number" bind:value={retries} min={0} max={5} class="form-input" disabled={processing} />
									</div>
									<div class="form-group" style="flex:1">
										<label class="form-label">{$tr('usernameOsint.config.concurrency')}</label>
										<input type="number" bind:value={concurrentLimit} min={1} max={50} class="form-input" disabled={processing} />
									</div>
								</div>
							</div>
						{/if}
					</div>

					<div class="btn-group">
						<button class="action-btn" onclick={checkUsername} disabled={processing || !username.trim()}>
							{processing ? $tr('usernameOsint.buttons.checking') : $tr('usernameOsint.buttons.check')}
						</button>
						<button class="clear-btn" onclick={clearAll} disabled={processing}>
							{$tr('usernameOsint.buttons.clear')}
						</button>
					</div>
				</div>

				<div class="section-card">
					<h3 class="section-title" style="font-size: 0.85rem;">{$tr('usernameOsint.examples.title')}</h3>
					<div class="examples-list">
						<button class="example-item" onclick={() => { username = 'johndoe'; }}>
							<span class="example-name">johndoe</span>
							<span class="example-desc">{$tr('usernameOsint.examples.common')}</span>
						</button>
						<button class="example-item" onclick={() => { username = 'torvalds'; }}>
							<span class="example-name">torvalds</span>
							<span class="example-desc">{$tr('usernameOsint.examples.developer')}</span>
						</button>
						<button class="example-item" onclick={() => { username = 'nasa'; }}>
							<span class="example-name">nasa</span>
							<span class="example-desc">{$tr('usernameOsint.examples.org')}</span>
						</button>
					</div>
				</div>
			</div>

			<div class="result-section">
				{#if processing && progress}
					<div class="section-card">
						<div class="progress-info">
							<div class="progress-header">
								<span class="progress-label">🔍 {$tr('usernameOsint.progress.scanning')} {progress.username}</span>
								<span class="progress-count">{progress.checked}/{progress.total}</span>
							</div>
							<div class="progress-bar-lg">
								<div class="progress-fill-lg" style="width: {progress.total > 0 ? (progress.checked / progress.total * 100) : 0}%;"></div>
							</div>
							<div class="progress-stats">
								<span style="color:#10b981">✅ {$tr('usernameOsint.progress.found')} {progress.found}</span>
								<span style="color:#94a3b8">❌ {$tr('usernameOsint.progress.checked')} {progress.checked - progress.found - progress.errors}</span>
								<span style="color:#ef4444">⚠️ {$tr('usernameOsint.progress.errors')} {progress.errors}</span>
							</div>
							<div class="progress-current">
								<span class="current-platform">→ {$tr('usernameOsint.progress.currentPlatform')}: {progress.current_platform}</span>
							</div>
						</div>
					</div>

					{#if liveResults.length > 0}
						<div class="section-card">
							<h3 class="section-title" style="font-size: 0.85rem;">
								📡 {$tr('usernameOsint.progress.liveResults')} ({liveResults.length})
							</h3>
							<div class="live-results-table">
								<div class="live-table-header">
									<span class="live-col-platform">{$tr('usernameOsint.export.colPlatform')}</span>
									<span class="live-col-status">{$tr('usernameOsint.export.colStatus')}</span>
									<span class="live-col-result">{$tr('usernameOsint.export.colResult')}</span>
									<span class="live-col-time">{$tr('usernameOsint.export.colTime')}</span>
									<span class="live-col-info">{$tr('usernameOsint.export.colInfo')}</span>
								</div>
								<div class="live-table-body">
									{#each liveResults as r}
										<div class="live-table-row {r.found ? 'found' : r.error ? 'error' : 'not-found'}">
											<span class="live-col-platform">
												<span class="live-cat-icon">{getCategoryIcon(r.category)}</span>
												<span class="live-platform-name">{r.platform}</span>
											</span>
											<span class="live-col-status">
												{#if r.status_code}
													<span class="status-badge {r.status_code >= 200 && r.status_code < 300 ? 'ok' : r.status_code >= 400 ? 'err' : 'warn'}">{r.status_code}</span>
												{:else}
													<span class="status-badge err">---</span>
												{/if}
											</span>
											<span class="live-col-result">
												{#if r.found}
													<span class="result-tag found">✅</span>
												{:else if r.error}
													<span class="result-tag error">⚠️</span>
												{:else}
													<span class="result-tag not-found">❌</span>
												{/if}
											</span>
											<span class="live-col-time">
												{#if r.response_time_ms}
													<span class="time-badge">{r.response_time_ms}ms</span>
												{/if}
											</span>
											<span class="live-col-info">
												{#if r.is_captcha}
													<span class="captcha-badge">🤖</span>
												{/if}
												{#if r.is_censored}
													<span class="censored-badge">🚫</span>
												{/if}
												{#if r.retry_count > 0}
													<span class="retry-badge">🔄×{r.retry_count}</span>
												{/if}
												{#if r.error_type}
													<span class="error-type-badge {r.error_type}">{getErrorTypeLabel(r.error_type)}</span>
												{/if}
												{#if r.page_title}
													<span class="live-page-title" title={r.page_title}>{r.page_title}</span>
												{/if}
											</span>
										</div>
									{/each}
								</div>
							</div>
						</div>
					{/if}
				{/if}

				{#if error}
					<div class="section-card">
						<div class="error-banner">
							<span class="error-icon">⚠️</span>
							<span class="error-text">{error}</span>
						</div>
					</div>
				{:else if result}
					<div class="section-card">
						<div class="result-summary" style="background: {result.digital_footprint_score >= 60 ? 'rgba(239,68,68,0.1)' : result.digital_footprint_score >= 30 ? 'rgba(250,204,21,0.1)' : 'rgba(16,185,129,0.1)'}; border-left: 3px solid {getRiskColor(result.risk_level)};">
							{result.summary}
						</div>

						<div class="stat-grid">
							<div class="stat-card">
								<div class="stat-value" style="color: #a855f7">{result.total_checked}</div>
								<div class="stat-label">{$tr('usernameOsint.result.checked')}</div>
							</div>
							<div class="stat-card">
								<div class="stat-value" style="color: #10b981">{result.total_found}</div>
								<div class="stat-label">{$tr('usernameOsint.result.found')}</div>
							</div>
							<div class="stat-card">
								<div class="stat-value" style="color: #94a3b8">{result.total_checked - result.total_found - result.total_errors}</div>
								<div class="stat-label">{$tr('usernameOsint.result.notFound')}</div>
							</div>
							<div class="stat-card">
								<div class="stat-value" style="color: {getRiskColor(result.risk_level)}">{Math.round(result.digital_footprint_score)}</div>
								<div class="stat-label">{$tr('usernameOsint.result.footprintScore')}</div>
							</div>
						</div>

						{#if result.category_summary.length > 0}
							<div class="category-bar">
								{#each result.category_summary as cs}
									<div class="category-bar-item" style="flex: {cs.total}; background: {cs.found > 0 ? 'rgba(168,85,247,0.3)' : 'rgba(148,163,184,0.1)'};">
										<span class="cat-bar-label">{getCategoryIcon(cs.category)} {cs.found}/{cs.total}</span>
									</div>
								{/each}
							</div>
						{/if}

						<div class="action-bar">
							<button class="save-target-btn" onclick={saveToTarget} disabled={savingToTarget}>
								{savingToTarget ? '⏳' : '💾'} {$tr('usernameOsint.buttons.saveToTarget')}
							</button>
							<div class="export-wrapper">
								<button class="export-btn" onclick={() => showExportMenu = !showExportMenu}>
									📤 {$tr('usernameOsint.buttons.export')}
								</button>
								{#if showExportMenu}
									<div class="export-menu">
										<button class="export-option" onclick={exportJSON}>📋 {$tr('usernameOsint.export.json')}</button>
										<button class="export-option" onclick={exportCSV}>📊 {$tr('usernameOsint.export.csv')}</button>
										<button class="export-option" onclick={exportMarkdown}>📝 {$tr('usernameOsint.export.markdown')}</button>
									</div>
								{/if}
							</div>
						</div>

						{#if result.permutations.length > 0}
							<div class="permutations-section">
								<span class="perm-label">🔄 {$tr('usernameOsint.result.variantsChecked')} ({result.permutations.length}):</span>
								<div class="perm-list">
									{#each result.permutations as perm}
										<span class="perm-chip">{perm}</span>
									{/each}
								</div>
							</div>
						{/if}

						<div class="sub-tabs">
							<button class="sub-tab {activeResultTab === 'overview' ? 'active' : ''}" onclick={() => activeResultTab = 'overview'}>
								{$tr('usernameOsint.result.tabOverview')}
							</button>
							<button class="sub-tab {activeResultTab === 'found' ? 'active' : ''}" onclick={() => activeResultTab = 'found'}>
								✅ {$tr('usernameOsint.result.foundOn')} ({result.found_on.length})
							</button>
							<button class="sub-tab {activeResultTab === 'notfound' ? 'active' : ''}" onclick={() => activeResultTab = 'notfound'}>
								❌ {$tr('usernameOsint.result.notFoundOn')} ({result.not_found_on.length})
							</button>
							{#if result.errors.length > 0}
								<button class="sub-tab {activeResultTab === 'errors' ? 'active' : ''}" onclick={() => activeResultTab = 'errors'}>
									⚠️ {$tr('usernameOsint.result.errors')} ({result.errors.length})
								</button>
							{/if}
							{#if result.batch_results.length > 1}
								<button class="sub-tab {activeResultTab === 'batch' ? 'active' : ''}" onclick={() => activeResultTab = 'batch'}>
									👥 {$tr('usernameOsint.result.tabBatch')} ({result.batch_results.length})
								</button>
							{/if}
						</div>

						{#if activeResultTab === 'overview'}
							<div class="category-overview">
								{#each result.category_summary as cs}
									<div class="category-card">
										<div class="category-header">
											<span class="category-icon">{getCategoryIcon(cs.category)}</span>
											<span class="category-name">{getCategoryLabel(cs.category)}</span>
											<span class="category-count">{cs.found}/{cs.total}</span>
										</div>
										<div class="category-progress">
											<div class="progress-bar">
												<div class="progress-fill" style="width: {cs.total > 0 ? (cs.found / cs.total * 100) : 0}%;"></div>
											</div>
										</div>
										<div class="category-platforms">
											{#each result.found_on.filter((p: PlatformResult) => p.category === cs.category) as p}
												<a href={p.url} target="_blank" class="mini-platform found">{p.platform}</a>
											{/each}
											{#each result.not_found_on.filter((p: PlatformResult) => p.category === cs.category) as p}
												<span class="mini-platform not-found">{p.platform}</span>
											{/each}
										</div>
									</div>
								{/each}
							</div>
						{:else if activeResultTab === 'found'}
							<div class="platform-list">
								{#each result.found_on as p}
									<a href={p.url} target="_blank" class="platform-item found">
										<div class="platform-left">
											<span class="platform-icon">{getCategoryIcon(p.category)}</span>
											<div class="platform-info">
												<span class="platform-name">{p.platform}</span>
												<span class="platform-url">{p.url}</span>
												{#if p.page_title}
													<span class="platform-title">📄 {p.page_title}</span>
												{/if}
											</div>
										</div>
										<div class="platform-right">
											{#if p.status_code}
												<span class="status-badge ok">{p.status_code}</span>
											{/if}
											{#if p.response_time_ms}
												<span class="time-badge">{p.response_time_ms}ms</span>
											{/if}
											{#if p.retry_count > 0}
												<span class="retry-badge">🔄 ×{p.retry_count}</span>
											{/if}
										</div>
									</a>
								{/each}
							</div>
						{:else if activeResultTab === 'notfound'}
							<div class="platform-list">
								{#each result.not_found_on as p}
									<div class="platform-item not-found">
										<div class="platform-left">
											<span class="platform-icon">{getCategoryIcon(p.category)}</span>
											<div class="platform-info">
												<span class="platform-name">{p.platform}</span>
												<span class="platform-url">{p.url}</span>
											</div>
										</div>
										<div class="platform-right">
											{#if p.status_code}
												<span class="status-badge err">{p.status_code}</span>
											{/if}
										</div>
									</div>
								{/each}
							</div>
						{:else if activeResultTab === 'errors'}
							<div class="platform-list">
								{#each result.errors as p}
									<div class="platform-item error">
										<div class="platform-left">
											<span class="platform-icon">{getCategoryIcon(p.category)}</span>
											<div class="platform-info">
												<span class="platform-name">{p.platform}</span>
												<span class="platform-error">{p.error || $tr('usernameOsint.result.unknownError')}</span>
												{#if p.error_type}
													<span class="error-type-badge {p.error_type}">
														{getErrorTypeIcon(p.error_type)} {getErrorTypeLabel(p.error_type)}
													</span>
												{/if}
											</div>
										</div>
										<div class="platform-right">
											{#if p.is_captcha}
												<span class="captcha-badge">🤖 {$tr('usernameOsint.errorTypes.captcha')}</span>
											{/if}
											{#if p.is_censored}
												<span class="censored-badge">🚫 {$tr('usernameOsint.errorTypes.censored')}</span>
											{/if}
											{#if p.retry_count > 0}
												<span class="retry-badge">🔄 ×{p.retry_count}</span>
											{/if}
										</div>
									</div>
								{/each}
							</div>
						{:else if activeResultTab === 'batch'}
							<div class="batch-results">
								{#each result.batch_results as br}
									<div class="batch-card">
										<div class="batch-header">
											<span class="batch-username">{br.username}</span>
											<span class="batch-risk" style="color: {getRiskColor(br.risk_level)}">{getRiskLabel(br.risk_level).toUpperCase()}</span>
										</div>
										<div class="batch-stats">
											<span>✅ {br.found_count} {$tr('usernameOsint.result.batchFound')}</span>
											<span>📊 {br.total_checked} {$tr('usernameOsint.result.batchChecked')}</span>
											<span>🎯 {$tr('usernameOsint.result.batchScore')}: {Math.round(br.digital_footprint_score)}</span>
										</div>
										<div class="progress-bar" style="margin-top:0.5rem">
											<div class="progress-fill" style="width: {br.total_checked > 0 ? (br.found_count / br.total_checked * 100) : 0}%; background: {getRiskColor(br.risk_level)};"></div>
										</div>
										{#if br.found_on.length > 0}
											<div class="batch-platforms">
												{#each br.found_on.slice(0, 8) as p}
													<a href={p.url} target="_blank" class="mini-platform found">{p.platform}</a>
												{/each}
												{#if br.found_on.length > 8}
													<span class="mini-platform more">+{br.found_on.length - 8}</span>
												{/if}
											</div>
										{/if}
									</div>
								{/each}
							</div>
						{/if}
					</div>
				{:else}
					<div class="section-card">
						<div class="empty-state">
							<div class="empty-icon">👤</div>
							<p>{$tr('usernameOsint.result.empty')}</p>
							<p class="empty-sub">{$tr('usernameOsint.result.emptySub')}</p>
						</div>
					</div>
				{/if}
			</div>
		</div>
	{:else if activeMainTab === 'platforms'}
		<div class="section-card">
			<div class="platform-header">
				<h2 class="section-title">{$tr('usernameOsint.platforms.title')}</h2>
				<div class="platform-actions">
					<button class="action-btn small" onclick={handleMaigretImport} disabled={maigretImporting}>
						{maigretImporting ? '⏳' : '🚀'} {$tr('usernameOsint.platforms.importMaigret')}
					</button>
					<button class="action-btn small" onclick={() => showImportSherlock = !showImportSherlock}>
						📥 {$tr('usernameOsint.platforms.importSherlock')}
					</button>
					<button class="action-btn small" onclick={() => showAddPlatform = !showAddPlatform}>
						{showAddPlatform ? '✕' : '+ '} {$tr('usernameOsint.platforms.add')}
					</button>
				</div>
			</div>

			{#if showImportSherlock}
				<div class="add-platform-form">
					<h3 class="section-title" style="font-size: 0.9rem;">📥 {$tr('usernameOsint.platforms.importSherlockTitle')}</h3>
					<p class="section-desc">{$tr('usernameOsint.platforms.importSherlockDesc')}</p>
					<div class="form-group">
						<div class="form-row">
							<button class="clear-btn small" onclick={handleSherlockFileImport}>📂 {$tr('usernameOsint.platforms.loadFile')}</button>
							<a href="https://github.com/sherlock-project/sherlock/blob/master/sherlock/resources/data.json" target="_blank" class="clear-btn small" style="text-decoration:none; display:inline-flex; align-items:center;">🔗 {$tr('usernameOsint.platforms.getDataJson')}</a>
						</div>
					</div>
					<div class="form-group">
						<label class="form-label">{$tr('usernameOsint.platforms.jsonContent')}</label>
						<textarea bind:value={sherlockJsonText} placeholder={$tr('usernameOsint.platforms.pasteJsonPlaceholder')} class="form-input" style="min-height:120px; font-family:monospace; font-size:0.75rem; resize:vertical;"></textarea>
					</div>
					<div class="btn-group">
						<button class="action-btn small" onclick={handleSherlockImport} disabled={sherlockImporting || !sherlockJsonText.trim()}>
							{sherlockImporting ? `⏳ ${$tr('usernameOsint.platforms.importing')}` : `📥 ${$tr('usernameOsint.platforms.import')}`}
						</button>
						<button class="clear-btn" onclick={() => { showImportSherlock = false; sherlockJsonText = ''; }}>{$tr('usernameOsint.buttons.clear')}</button>
					</div>
				</div>
			{/if}

			{#if maigretImportStats}
				<div class="add-platform-form" style="background: #f0fdf4; border-color: #22c55e;">
					<h3 class="section-title" style="font-size: 0.9rem; color: #16a34a;">✅ {$tr('usernameOsint.platforms.maigretImportSuccess')}</h3>
					<div class="import-stats-grid">
						<div class="import-stat">
							<span class="import-stat-value">{maigretImportStats.total_parsed}</span>
							<span class="import-stat-label">{$tr('usernameOsint.platforms.parsed')}</span>
						</div>
						<div class="import-stat">
							<span class="import-stat-value" style="color:#22c55e;">{maigretImportStats.imported}</span>
							<span class="import-stat-label">{$tr('usernameOsint.platforms.imported')}</span>
						</div>
						<div class="import-stat">
							<span class="import-stat-value" style="color:#f59e0b;">{maigretImportStats.updated}</span>
							<span class="import-stat-label">{$tr('usernameOsint.platforms.updated')}</span>
						</div>
						<div class="import-stat">
							<span class="import-stat-value" style="color:#ef4444;">{maigretImportStats.failed}</span>
							<span class="import-stat-label">{$tr('usernameOsint.platforms.failed')}</span>
						</div>
						<div class="import-stat">
							<span class="import-stat-value" style="color:#94a3b8;">{maigretImportStats.skipped_no_url}</span>
							<span class="import-stat-label">{$tr('usernameOsint.platforms.skipped')}</span>
						</div>
					</div>
					<button class="clear-btn" style="margin-top: 0.75rem;" onclick={() => maigretImportStats = null}>✕ {$tr('usernameOsint.buttons.close')}</button>
				</div>
			{/if}

			{#if showEditPlatform && editingPlatform}
				<div class="add-platform-form">
					<h3 class="section-title" style="font-size: 0.9rem;">✏️ {$tr('usernameOsint.platforms.editPlatform')}: {editingPlatform.display_name || editingPlatform.name}</h3>
					<div class="form-row">
						<div class="form-group">
							<label class="form-label">{$tr('usernameOsint.platforms.displayName')}</label>
							<input type="text" bind:value={editingPlatform.display_name} class="form-input" />
						</div>
						<div class="form-group">
							<label class="form-label">{$tr('usernameOsint.platforms.category')}</label>
							<select bind:value={editingPlatform.category} class="form-input">
								{#each categories as cat}
									<option value={cat.id}>{cat.icon} {getCategoryLabel(cat.id)}</option>
								{/each}
								<option value="other">📌 {$tr('usernameOsint.categories.other')}</option>
							</select>
						</div>
						<div class="form-group">
							<label class="form-label">{$tr('usernameOsint.platforms.active')}</label>
							<select bind:value={editingPlatform.is_active} class="form-input">
								<option value={true}>{$tr('usernameOsint.platforms.activeStatus')}</option>
								<option value={false}>{$tr('usernameOsint.platforms.inactiveStatus')}</option>
							</select>
						</div>
					</div>
					<div class="form-row">
						<div class="form-group" style="flex:2">
							<label class="form-label">{$tr('usernameOsint.platforms.urlTemplate')}</label>
							<input type="text" bind:value={editingPlatform.url_template} class="form-input" />
						</div>
						<div class="form-group">
							<label class="form-label">{$tr('usernameOsint.platforms.errorType')}</label>
							<select bind:value={editingPlatform.error_type} class="form-input">
								<option value="status_code">{$tr('usernameOsint.platforms.detection.statusCode')}</option>
								<option value="message">{$tr('usernameOsint.platforms.detection.message')}</option>
								<option value="redirect">{$tr('usernameOsint.platforms.detection.redirect')}</option>
								<option value="regex">{$tr('usernameOsint.platforms.detection.regex')}</option>
							</select>
						</div>
						<div class="form-group">
							<label class="form-label">{$tr('usernameOsint.platforms.requestMethod')}</label>
							<select bind:value={editingPlatform.request_method} class="form-input">
								<option value="GET">{$tr('usernameOsint.platforms.method.GET')}</option>
								<option value="POST">{$tr('usernameOsint.platforms.method.POST')}</option>
								<option value="HEAD">{$tr('usernameOsint.platforms.method.HEAD')}</option>
							</select>
						</div>
					</div>
					<div class="form-row">
						<div class="form-group">
							<label class="form-label">{$tr('usernameOsint.platforms.errorCodes')}</label>
							<input type="text" bind:value={editingPlatform.error_codes} class="form-input" placeholder='[404]' />
						</div>
						<div class="form-group">
							<label class="form-label">{$tr('usernameOsint.platforms.errorMessages')}</label>
							<input type="text" bind:value={editingPlatform.error_messages} class="form-input" placeholder={$tr('usernameOsint.platforms.errorMessagesPlaceholder')} />
						</div>
						<div class="form-group">
							<label class="form-label">{$tr('usernameOsint.platforms.regexCheck')}</label>
							<input type="text" bind:value={editingPlatform.regex_check} class="form-input" placeholder="pattern" />
						</div>
					</div>
					<div class="form-row">
						<div class="form-group" style="flex:2">
							<label class="form-label">{$tr('usernameOsint.platforms.notes')}</label>
							<input type="text" bind:value={editingPlatform.notes} class="form-input" />
						</div>
						<div class="form-group">
							<label class="form-label">{$tr('usernameOsint.platforms.priority')}</label>
							<input type="number" bind:value={editingPlatform.priority} class="form-input" />
						</div>
					</div>
					<div class="btn-group">
						<button class="action-btn small" onclick={saveEditPlatform}>{$tr('usernameOsint.platforms.save')}</button>
						<button class="clear-btn" onclick={() => { showEditPlatform = false; editingPlatform = null; }}>{$tr('usernameOsint.buttons.cancel')}</button>
					</div>
				</div>
			{/if}

			{#if showAddPlatform}
				<div class="add-platform-form">
					<div class="form-row">
						<div class="form-group">
							<label class="form-label">{$tr('usernameOsint.platforms.name')} *</label>
							<input type="text" bind:value={newPlatform.name} placeholder={$tr('usernameOsint.platforms.namePlaceholder')} class="form-input" />
						</div>
						<div class="form-group">
							<label class="form-label">{$tr('usernameOsint.platforms.displayName')}</label>
							<input type="text" bind:value={newPlatform.display_name} placeholder={$tr('usernameOsint.platforms.displayNamePlaceholder')} class="form-input" />
						</div>
						<div class="form-group">
							<label class="form-label">{$tr('usernameOsint.platforms.category')}</label>
							<select bind:value={newPlatform.category} class="form-input">
								{#each categories as cat}
									<option value={cat.id}>{cat.icon} {getCategoryLabel(cat.id)}</option>
								{/each}
								<option value="other">📌 {$tr('usernameOsint.categories.other')}</option>
							</select>
						</div>
					</div>
					<div class="form-row">
						<div class="form-group" style="flex:2">
							<label class="form-label">{$tr('usernameOsint.platforms.urlTemplate')} * ({$tr('usernameOsint.platforms.urlTemplateHint')})</label>
							<input type="text" bind:value={newPlatform.url_template} placeholder={"https://example.com/{}"} class="form-input" />
						</div>
						<div class="form-group">
							<label class="form-label">{$tr('usernameOsint.platforms.errorType')}</label>
							<select bind:value={newPlatform.error_type} class="form-input">
								<option value="status_code">{$tr('usernameOsint.platforms.detection.statusCode')}</option>
								<option value="message">{$tr('usernameOsint.platforms.detection.message')}</option>
								<option value="redirect">{$tr('usernameOsint.platforms.detection.redirect')}</option>
								<option value="regex">{$tr('usernameOsint.platforms.detection.regex')}</option>
							</select>
						</div>
						<div class="form-group">
							<label class="form-label">{$tr('usernameOsint.platforms.requestMethod')}</label>
							<select bind:value={newPlatform.request_method} class="form-input">
								<option value="GET">{$tr('usernameOsint.platforms.method.GET')}</option>
								<option value="POST">{$tr('usernameOsint.platforms.method.POST')}</option>
								<option value="HEAD">{$tr('usernameOsint.platforms.method.HEAD')}</option>
							</select>
						</div>
					</div>
				<div class="btn-group">
					<button class="action-btn small" onclick={addPlatform} disabled={!newPlatform.name || !newPlatform.url_template}>
						{$tr('usernameOsint.platforms.save')}
					</button>
					<button class="clear-btn" onclick={() => showAddPlatform = false}>{$tr('usernameOsint.buttons.clear')}</button>
				</div>
			</div>
		{/if}

		<div class="platform-filter">
			<div class="filter-row">
				<div class="form-group" style="flex:1; margin-bottom:0">
					<input type="text" bind:value={platformSearchQuery} placeholder={$tr('usernameOsint.platforms.searchPlatforms')} class="form-input" />
					</div>
					<label class="toggle-label">
						<input type="checkbox" bind:checked={showInactivePlatforms} onchange={loadPlatforms} />
						<span>{$tr('usernameOsint.platforms.showInactive')}</span>
					</label>
				</div>
				<div class="chip-group" style="margin-top:0.5rem">
					<button class="target-chip {!platformFilterCategory ? 'active' : ''}" onclick={() => { platformFilterCategory = ''; loadPlatforms(); }}>
						{$tr('usernameOsint.platforms.all')} ({platformCount})
					</button>
					{#each platformCategories as cat}
						<button class="target-chip {platformFilterCategory === cat ? 'active' : ''}" onclick={() => { platformFilterCategory = cat; loadPlatforms(); }}>
							{getCategoryIcon(cat)} {getCategoryLabel(cat)}
						</button>
					{/each}
				</div>
			</div>

			<div class="platform-table">
				<div class="table-header">
					<span class="col-name">{$tr('usernameOsint.platforms.name')}</span>
					<span class="col-category">{$tr('usernameOsint.platforms.category')}</span>
					<span class="col-url">{$tr('usernameOsint.platforms.urlTemplate')}</span>
					<span class="col-detect">{$tr('usernameOsint.platforms.errorType')}</span>
					<span class="col-source">{$tr('usernameOsint.platforms.source')}</span>
					<span class="col-actions">{$tr('usernameOsint.platforms.actions')}</span>
				</div>
				{#each getFilteredPlatforms() as p}
					<div class="table-row" class:inactive-row={!p.is_active}>
						<span class="col-name">
							{#if p.display_name}
								<strong>{p.display_name}</strong>
								<br/><small style="color:#64748b">{p.name}</small>
							{:else}
								<strong>{p.name}</strong>
							{/if}
						</span>
						<span class="col-category">{getCategoryIcon(p.category)} {getCategoryLabel(p.category)}</span>
						<span class="col-url"><code>{p.url_template}</code></span>
						<span class="col-detect">
							<span class="detect-badge">{p.error_type}</span>
							{#if p.request_method !== 'GET'}<span class="detect-badge method">{p.request_method}</span>{/if}
						</span>
						<span class="col-source">
							<span class="source-badge {p.source}">{p.source === 'custom' ? $tr('usernameOsint.platforms.custom') : p.source === 'sherlock' ? 'Sherlock' : p.source}</span>
							{#if p.is_built_in}<span class="source-badge builtin">{$tr('usernameOsint.platforms.builtin')}</span>{/if}
						</span>
						<span class="col-actions">
							<button class="icon-btn" onclick={() => startEditPlatform(p)} title={$tr('usernameOsint.platforms.edit')}>✏️</button>
							<button class="icon-btn" onclick={() => togglePlatformActive(p)} title={p.is_active ? $tr('usernameOsint.platforms.deactivate') : $tr('usernameOsint.platforms.activate')}>{p.is_active ? '🟢' : '🔴'}</button>
							{#if !p.is_built_in}
								<button class="delete-btn" onclick={() => deletePlatform(p.name)} title={$tr('usernameOsint.platforms.delete')}>🗑️</button>
							{/if}
						</span>
					</div>
				{/each}
			</div>
		</div>
	{:else if activeMainTab === 'history'}
		<div class="section-card">
			<ToolHistory toolType="username_osint" toolName={$tr('usernameOsint.title')} bind:this={historyComponent} />
		</div>
	{:else if activeMainTab === 'help'}
		<div class="section-card">
			<ToolHelp toolType="username_osint" />
		</div>
	{/if}
</div>

<style>
	.nd-page { padding: 1.25rem; max-width: 1200px; margin: 0 auto; }
	.page-header { margin-bottom: 1.25rem; }
	.header-left { display: flex; flex-direction: column; }
	.back-link { color: #94a3b8; text-decoration: none; font-size: 0.8rem; margin-bottom: 0.25rem; }
	.back-link:hover { color: #c4b5fd; }
	.page-title { font-size: 1.4rem; font-weight: 700; margin: 0.25rem 0; color: #e2e8f0; }
	.page-subtitle { color: #94a3b8; font-size: 0.85rem; margin: 0; }

	.tabs { display: flex; gap: 0.25rem; margin-bottom: 1rem; background: rgba(15, 23, 42, 0.6); border-radius: 0.625rem; padding: 0.25rem; border: 1px solid rgba(148, 163, 184, 0.1); }
	.tab-btn { flex: 1; padding: 0.5rem 1rem; border: none; border-radius: 0.5rem; background: transparent; cursor: pointer; font-size: 0.85rem; color: #94a3b8; transition: all 0.2s; display: flex; align-items: center; justify-content: center; gap: 0.35rem; }
	.tab-btn.active { background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%); color: white; box-shadow: 0 2px 8px rgba(168, 85, 247, 0.3); }
	.tab-btn:hover:not(.active) { background: rgba(148, 163, 184, 0.1); color: #e2e8f0; }
	.tab-icon { font-size: 0.9rem; }

	.content-grid { display: grid; grid-template-columns: 380px 1fr; gap: 1rem; }
	.input-section { display: flex; flex-direction: column; gap: 1rem; }
	.result-section { min-width: 0; }

	.section-card { background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(148, 163, 184, 0.1); border-radius: 0.75rem; padding: 1.25rem; }
	.section-title { font-size: 1rem; font-weight: 600; margin: 0 0 0.75rem; color: #e2e8f0; }
	.section-desc { font-size: 0.8rem; color: #94a3b8; margin: 0 0 0.75rem; }

	.form-group { margin-bottom: 0.75rem; }
	.form-label { display: block; font-size: 0.8rem; color: #94a3b8; margin-bottom: 0.35rem; font-weight: 500; }
	.form-input { width: 100%; padding: 0.5rem 0.75rem; border-radius: 0.5rem; border: 1px solid rgba(148, 163, 184, 0.15); background: rgba(15, 23, 42, 0.8); color: #e2e8f0; font-size: 0.85rem; box-sizing: border-box; }
	.form-input:focus { outline: none; border-color: rgba(168, 85, 247, 0.4); box-shadow: 0 0 0 2px rgba(168, 85, 247, 0.1); }
	.form-input::placeholder { color: #64748b; }
	.form-hint { font-size: 0.7rem; color: #64748b; margin: 0.25rem 0 0; }

	.chip-group { display: flex; flex-wrap: wrap; gap: 0.35rem; }
	.target-chip { display: flex; align-items: center; gap: 0.25rem; padding: 0.25rem 0.5rem; border: 1px solid rgba(148, 163, 184, 0.15); border-radius: 0.4rem; background: rgba(15, 23, 42, 0.6); cursor: pointer; font-size: 0.75rem; color: #94a3b8; transition: all 0.2s; }
	.target-chip.active { border-color: rgba(168, 85, 247, 0.4); background: rgba(168, 85, 247, 0.1); color: #c4b5fd; }
	.target-chip:hover:not(.active) { border-color: rgba(148, 163, 184, 0.3); }

	.btn-group { display: flex; gap: 0.5rem; margin-top: 0.5rem; }
	.action-btn { flex: 1; padding: 0.6rem 1rem; border: none; border-radius: 0.5rem; background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%); color: white; font-size: 0.85rem; font-weight: 600; cursor: pointer; transition: all 0.2s; }
	.action-btn:hover:not(:disabled) { box-shadow: 0 4px 12px rgba(168, 85, 247, 0.4); }
	.action-btn:disabled { opacity: 0.5; cursor: not-allowed; }
	.action-btn.small { flex: unset; padding: 0.4rem 0.75rem; font-size: 0.8rem; }
	.clear-btn { padding: 0.6rem 1rem; border: 1px solid rgba(148, 163, 184, 0.2); border-radius: 0.5rem; background: rgba(15, 23, 42, 0.6); color: #94a3b8; font-size: 0.85rem; font-weight: 500; cursor: pointer; transition: all 0.2s; }
	.clear-btn:hover:not(:disabled) { border-color: rgba(168, 85, 247, 0.3); color: #c4b5fd; }
	.clear-btn:disabled { opacity: 0.5; cursor: not-allowed; }

	.save-target-btn { padding: 0.4rem 0.75rem; border: 1px solid rgba(16, 185, 129, 0.3); border-radius: 0.4rem; background: rgba(16, 185, 129, 0.1); color: #10b981; font-size: 0.8rem; cursor: pointer; transition: all 0.2s; }
	.save-target-btn:hover:not(:disabled) { background: rgba(16, 185, 129, 0.2); }
	.save-target-btn:disabled { opacity: 0.5; cursor: not-allowed; }

	.action-bar { display: flex; justify-content: flex-end; margin-bottom: 0.75rem; }

	.examples-list { display: flex; flex-direction: column; gap: 0.35rem; }
	.example-item { display: flex; justify-content: space-between; align-items: center; padding: 0.4rem 0.6rem; border: 1px solid rgba(148, 163, 184, 0.1); border-radius: 0.4rem; background: rgba(15, 23, 42, 0.4); cursor: pointer; transition: all 0.2s; }
	.example-item:hover { border-color: rgba(168, 85, 247, 0.3); background: rgba(168, 85, 247, 0.05); }
	.example-name { font-size: 0.8rem; color: #e2e8f0; font-family: 'SF Mono', 'Fira Code', monospace; }
	.example-desc { font-size: 0.7rem; color: #94a3b8; }

	.result-summary { padding: 0.75rem 1rem; border-radius: 0.5rem; margin-bottom: 0.75rem; font-size: 0.85rem; color: #e2e8f0; }

	.stat-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 0.5rem; margin-bottom: 0.75rem; }
	.stat-card { background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(148, 163, 184, 0.1); border-radius: 0.5rem; padding: 0.6rem; text-align: center; }
	.stat-value { font-size: 1.25rem; font-weight: 700; }
	.stat-label { font-size: 0.7rem; color: #94a3b8; margin-top: 0.15rem; }

	.category-bar { display: flex; border-radius: 0.4rem; overflow: hidden; margin-bottom: 0.75rem; height: 1.5rem; }
	.category-bar-item { display: flex; align-items: center; justify-content: center; min-width: 2rem; }
	.cat-bar-label { font-size: 0.65rem; color: #e2e8f0; white-space: nowrap; }

	.sub-tabs { display: flex; gap: 0.2rem; margin-bottom: 0.75rem; background: rgba(15, 23, 42, 0.6); border-radius: 0.5rem; padding: 0.2rem; flex-wrap: wrap; }
	.sub-tab { padding: 0.35rem 0.75rem; border: none; border-radius: 0.375rem; background: transparent; cursor: pointer; font-size: 0.8rem; color: #94a3b8; transition: all 0.2s; white-space: nowrap; }
	.sub-tab.active { background: rgba(168, 85, 247, 0.2); color: #c4b5fd; }
	.sub-tab:hover:not(.active) { color: #e2e8f0; }

	.category-overview { display: flex; flex-direction: column; gap: 0.5rem; }
	.category-card { background: rgba(15, 23, 42, 0.4); border: 1px solid rgba(148, 163, 184, 0.1); border-radius: 0.5rem; padding: 0.75rem; }
	.category-header { display: flex; align-items: center; gap: 0.35rem; margin-bottom: 0.35rem; }
	.category-icon { font-size: 0.9rem; }
	.category-name { font-size: 0.85rem; font-weight: 500; color: #e2e8f0; flex: 1; }
	.category-count { font-size: 0.8rem; color: #c4b5fd; font-weight: 600; }
	.category-progress { margin-bottom: 0.5rem; }
	.progress-bar { height: 0.25rem; background: rgba(148, 163, 184, 0.1); border-radius: 0.125rem; overflow: hidden; }
	.progress-fill { height: 100%; background: linear-gradient(90deg, #a855f7, #6366f1); border-radius: 0.125rem; transition: width 0.3s; }
	.category-platforms { display: flex; flex-wrap: wrap; gap: 0.25rem; }
	.mini-platform { padding: 0.1rem 0.35rem; border-radius: 0.25rem; font-size: 0.65rem; text-decoration: none; }
	.mini-platform.found { background: rgba(16, 185, 129, 0.15); color: #10b981; border: 1px solid rgba(16, 185, 129, 0.2); }
	.mini-platform.found:hover { background: rgba(16, 185, 129, 0.25); }
	.mini-platform.not-found { background: rgba(148, 163, 184, 0.08); color: #64748b; border: 1px solid rgba(148, 163, 184, 0.1); }

	.platform-list { display: flex; flex-direction: column; gap: 0.25rem; max-height: 500px; overflow-y: auto; }
	.platform-item { display: flex; align-items: center; justify-content: space-between; padding: 0.5rem 0.75rem; border-radius: 0.4rem; transition: all 0.2s; text-decoration: none; color: inherit; }
	.platform-item.found { background: rgba(16, 185, 129, 0.08); border: 1px solid rgba(16, 185, 129, 0.15); }
	.platform-item.found:hover { background: rgba(16, 185, 129, 0.15); }
	.platform-item.not-found { background: rgba(148, 163, 184, 0.05); border: 1px solid rgba(148, 163, 184, 0.1); }
	.platform-item.error { background: rgba(239, 68, 68, 0.08); border: 1px solid rgba(239, 68, 68, 0.15); }
	.platform-left { display: flex; align-items: center; gap: 0.5rem; min-width: 0; flex: 1; }
	.platform-icon { font-size: 1rem; }
	.platform-info { min-width: 0; }
	.platform-name { font-size: 0.85rem; color: #e2e8f0; display: block; }
	.platform-url { font-size: 0.7rem; color: #64748b; display: block; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 400px; }
	.platform-error { font-size: 0.7rem; color: #ef4444; display: block; }
	.platform-right { display: flex; align-items: center; gap: 0.35rem; }
	.status-badge { padding: 0.1rem 0.4rem; border-radius: 0.25rem; font-size: 0.7rem; font-weight: 600; }
	.status-badge.ok { background: rgba(16, 185, 129, 0.15); color: #10b981; }
	.status-badge.err { background: rgba(239, 68, 68, 0.15); color: #ef4444; }
	.time-badge { font-size: 0.65rem; color: #64748b; }

	.error-banner { display: flex; align-items: center; gap: 0.5rem; padding: 0.75rem 1rem; background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.2); border-radius: 0.5rem; }
	.error-icon { font-size: 1.1rem; }
	.error-text { font-size: 0.85rem; color: #ef4444; }

	.empty-state { text-align: center; padding: 2rem 1rem; }
	.empty-icon { font-size: 2.5rem; margin-bottom: 0.75rem; }
	.empty-state p { color: #94a3b8; font-size: 0.9rem; margin: 0.25rem 0; }
	.empty-sub { font-size: 0.8rem !important; color: #64748b !important; }

	.platform-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem; }
	.platform-actions { display: flex; gap: 0.5rem; }

	.add-platform-form { background: rgba(15, 23, 42, 0.8); border: 1px solid rgba(168, 85, 247, 0.2); border-radius: 0.5rem; padding: 1rem; margin-bottom: 1rem; }
	.import-stats-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 0.75rem; margin-top: 0.75rem; }
	.import-stat { text-align: center; padding: 0.5rem; background: rgba(255,255,255,0.05); border-radius: 0.4rem; }
	.import-stat-value { display: block; font-size: 1.5rem; font-weight: 700; color: #e2e8f0; }
	.import-stat-label { display: block; font-size: 0.7rem; color: #94a3b8; margin-top: 0.2rem; text-transform: uppercase; }
	.form-row { display: flex; gap: 0.75rem; margin-bottom: 0.5rem; }
	.form-row .form-group { flex: 1; }

	.platform-filter { margin-bottom: 1rem; }

	.platform-table { width: 100%; }
	.table-header { display: grid; grid-template-columns: 2fr 1fr 3fr 1.5fr 1fr 0.5fr; gap: 0.5rem; padding: 0.5rem 0.75rem; background: rgba(15, 23, 42, 0.8); border-radius: 0.4rem 0.4rem 0 0; font-size: 0.75rem; color: #94a3b8; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; border: 1px solid rgba(148, 163, 184, 0.1); border-bottom: none; }
	.table-row { display: grid; grid-template-columns: 2fr 1fr 3fr 1.5fr 1fr 0.5fr; gap: 0.5rem; padding: 0.5rem 0.75rem; border: 1px solid rgba(148, 163, 184, 0.08); border-top: none; font-size: 0.8rem; align-items: center; transition: background 0.2s; }
	.table-row:hover { background: rgba(148, 163, 184, 0.05); }
	.table-row:last-child { border-radius: 0 0 0.4rem 0.4rem; }
	.col-url code { font-size: 0.7rem; color: #94a3b8; background: rgba(15, 23, 42, 0.6); padding: 0.1rem 0.3rem; border-radius: 0.2rem; }

	.detect-badge { display: inline-block; padding: 0.1rem 0.35rem; border-radius: 0.2rem; font-size: 0.65rem; background: rgba(168, 85, 247, 0.15); color: #c4b5fd; margin-right: 0.2rem; }
	.detect-badge.method { background: rgba(59, 130, 246, 0.15); color: #93c5fd; }
	.source-badge { display: inline-block; padding: 0.1rem 0.35rem; border-radius: 0.2rem; font-size: 0.65rem; background: rgba(148, 163, 184, 0.1); color: #94a3b8; margin-right: 0.2rem; }
	.source-badge.sherlock { background: rgba(59, 130, 246, 0.15); color: #93c5fd; }
	.source-badge.custom { background: rgba(16, 185, 129, 0.15); color: #10b981; }
	.source-badge.builtin { background: rgba(168, 85, 247, 0.15); color: #c4b5fd; }

	.delete-btn { background: none; border: none; cursor: pointer; font-size: 0.85rem; padding: 0.2rem; opacity: 0.6; transition: opacity 0.2s; }
	.delete-btn:hover { opacity: 1; }

	.icon-btn { background: none; border: none; cursor: pointer; font-size: 0.8rem; padding: 0.15rem; opacity: 0.7; transition: opacity 0.2s; }
	.icon-btn:hover { opacity: 1; }

	.inactive-row { opacity: 0.5; }

	.filter-row { display: flex; align-items: center; gap: 0.75rem; }

	.toggle-label { display: flex; align-items: center; gap: 0.35rem; font-size: 0.8rem; color: #94a3b8; cursor: pointer; white-space: nowrap; }
	.toggle-label input[type="checkbox"] { accent-color: #a855f7; }

	.clear-btn.small { padding: 0.35rem 0.6rem; font-size: 0.75rem; }

	.form-hint-inline { font-size: 0.7rem; color: #64748b; font-weight: 400; }

	.toggle-advanced-btn { background: none; border: 1px solid rgba(148, 163, 184, 0.15); border-radius: 0.4rem; color: #94a3b8; font-size: 0.8rem; padding: 0.3rem 0.6rem; cursor: pointer; transition: all 0.2s; width: 100%; text-align: left; }
	.toggle-advanced-btn:hover { border-color: rgba(168, 85, 247, 0.3); color: #c4b5fd; }
	.advanced-settings { margin-top: 0.5rem; padding: 0.75rem; background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(148, 163, 184, 0.1); border-radius: 0.5rem; }

	.progress-info { padding: 0.5rem 0; }
	.progress-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem; }
	.progress-label { font-size: 0.85rem; color: #e2e8f0; font-weight: 600; }
	.progress-count { font-size: 0.8rem; color: #c4b5fd; font-weight: 500; }
	.progress-bar-lg { height: 0.5rem; background: rgba(148, 163, 184, 0.1); border-radius: 0.25rem; overflow: hidden; margin-bottom: 0.5rem; }
	.progress-fill-lg { height: 100%; background: linear-gradient(90deg, #a855f7, #6366f1); border-radius: 0.25rem; transition: width 0.3s ease; }
	.progress-stats { display: flex; gap: 1rem; font-size: 0.8rem; margin-bottom: 0.35rem; }
	.progress-current { font-size: 0.75rem; color: #64748b; }
	.current-platform { color: #94a3b8; }

	.export-wrapper { position: relative; }
	.export-btn { padding: 0.4rem 0.75rem; border: 1px solid rgba(168, 85, 247, 0.3); border-radius: 0.4rem; background: rgba(168, 85, 247, 0.1); color: #c4b5fd; font-size: 0.8rem; cursor: pointer; transition: all 0.2s; }
	.export-btn:hover { background: rgba(168, 85, 247, 0.2); }
	.export-menu { position: absolute; top: 100%; right: 0; margin-top: 0.25rem; background: rgba(15, 23, 42, 0.95); border: 1px solid rgba(148, 163, 184, 0.2); border-radius: 0.5rem; padding: 0.25rem; z-index: 10; min-width: 120px; box-shadow: 0 4px 12px rgba(0,0,0,0.3); }
	.export-option { display: block; width: 100%; padding: 0.4rem 0.6rem; border: none; border-radius: 0.375rem; background: transparent; color: #e2e8f0; font-size: 0.8rem; cursor: pointer; text-align: left; transition: all 0.15s; }
	.export-option:hover { background: rgba(168, 85, 247, 0.15); }

	.permutations-section { margin-bottom: 0.75rem; padding: 0.6rem; background: rgba(15, 23, 42, 0.4); border: 1px solid rgba(148, 163, 184, 0.1); border-radius: 0.5rem; }
	.perm-label { font-size: 0.75rem; color: #94a3b8; display: block; margin-bottom: 0.35rem; }
	.perm-list { display: flex; flex-wrap: wrap; gap: 0.25rem; }
	.perm-chip { padding: 0.15rem 0.4rem; border-radius: 0.25rem; font-size: 0.7rem; background: rgba(168, 85, 247, 0.1); color: #c4b5fd; border: 1px solid rgba(168, 85, 247, 0.15); font-family: 'SF Mono', 'Fira Code', monospace; }

	.platform-title { font-size: 0.7rem; color: #94a3b8; display: block; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 400px; }
	.retry-badge { font-size: 0.65rem; color: #f59e0b; background: rgba(245, 158, 11, 0.1); padding: 0.1rem 0.3rem; border-radius: 0.2rem; }

	.error-type-badge { display: inline-block; padding: 0.1rem 0.35rem; border-radius: 0.2rem; font-size: 0.65rem; margin-top: 0.15rem; }
	.error-type-badge.captcha { background: rgba(245, 158, 11, 0.15); color: #f59e0b; }
	.error-type-badge.censored { background: rgba(239, 68, 68, 0.15); color: #ef4444; }
	.error-type-badge.timeout { background: rgba(59, 130, 246, 0.15); color: #93c5fd; }
	.error-type-badge.connection { background: rgba(168, 85, 247, 0.15); color: #c4b5fd; }
	.error-type-badge.ssl { background: rgba(236, 72, 153, 0.15); color: #f472b6; }
	.error-type-badge.network { background: rgba(148, 163, 184, 0.15); color: #94a3b8; }
	.error-type-badge.empty_response { background: rgba(34, 211, 238, 0.15); color: #22d3ee; }

	.captcha-badge { font-size: 0.65rem; color: #f59e0b; background: rgba(245, 158, 11, 0.1); padding: 0.1rem 0.3rem; border-radius: 0.2rem; }
	.censored-badge { font-size: 0.65rem; color: #ef4444; background: rgba(239, 68, 68, 0.1); padding: 0.1rem 0.3rem; border-radius: 0.2rem; }

	.batch-results { display: flex; flex-direction: column; gap: 0.5rem; }
	.batch-card { background: rgba(15, 23, 42, 0.4); border: 1px solid rgba(148, 163, 184, 0.1); border-radius: 0.5rem; padding: 0.75rem; }
	.batch-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.35rem; }
	.batch-username { font-size: 0.9rem; font-weight: 600; color: #e2e8f0; font-family: 'SF Mono', 'Fira Code', monospace; }
	.batch-risk { font-size: 0.75rem; font-weight: 600; text-transform: uppercase; }
	.batch-stats { display: flex; gap: 1rem; font-size: 0.75rem; color: #94a3b8; }
	.batch-platforms { display: flex; flex-wrap: wrap; gap: 0.25rem; margin-top: 0.5rem; }
	.mini-platform.more { background: rgba(148, 163, 184, 0.1); color: #94a3b8; border: 1px solid rgba(148, 163, 184, 0.15); }

	.live-results-table { width: 100%; font-size: 0.75rem; }
	.live-table-header { display: grid; grid-template-columns: 2fr 0.8fr 0.6fr 0.8fr 2fr; gap: 0.35rem; padding: 0.4rem 0.6rem; background: rgba(15, 23, 42, 0.8); border-radius: 0.35rem 0.35rem 0 0; font-size: 0.7rem; color: #94a3b8; font-weight: 600; text-transform: uppercase; letter-spacing: 0.04em; border: 1px solid rgba(148, 163, 184, 0.1); border-bottom: none; }
	.live-table-body { max-height: 350px; overflow-y: auto; }
	.live-table-row { display: grid; grid-template-columns: 2fr 0.8fr 0.6fr 0.8fr 2fr; gap: 0.35rem; padding: 0.35rem 0.6rem; border: 1px solid rgba(148, 163, 184, 0.06); border-top: none; align-items: center; transition: background 0.15s; }
	.live-table-row.found { background: rgba(16, 185, 129, 0.06); }
	.live-table-row.error { background: rgba(239, 68, 68, 0.06); }
	.live-table-row.not-found { background: rgba(148, 163, 184, 0.03); }
	.live-table-row:last-child { border-radius: 0 0 0.35rem 0.35rem; }
	.live-col-platform { display: flex; align-items: center; gap: 0.3rem; min-width: 0; }
	.live-cat-icon { font-size: 0.75rem; flex-shrink: 0; }
	.live-platform-name { font-size: 0.78rem; color: #e2e8f0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
	.live-col-status { text-align: center; }
	.live-col-result { text-align: center; }
	.result-tag { font-size: 0.75rem; }
	.result-tag.found { color: #10b981; }
	.result-tag.error { color: #ef4444; }
	.result-tag.not-found { color: #64748b; }
	.live-col-time { text-align: center; }
	.live-col-info { display: flex; align-items: center; gap: 0.2rem; flex-wrap: wrap; min-width: 0; }
	.live-page-title { font-size: 0.65rem; color: #64748b; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 150px; }
	.status-badge.warn { background: rgba(245, 158, 11, 0.15); color: #f59e0b; }

	@media (max-width: 900px) {
		.content-grid { grid-template-columns: 1fr; }
		.table-header, .table-row { grid-template-columns: 2fr 1fr 2fr 1fr 0.5fr; }
		.col-url { display: none; }
		.stat-grid { grid-template-columns: repeat(2, 1fr); }
	}
</style>
