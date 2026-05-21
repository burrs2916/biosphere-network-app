<script lang="ts">
	import { tr } from '$lib/i18n';
	import { open } from '@tauri-apps/plugin-dialog';
	import { readFile } from '@tauri-apps/plugin-fs';
	import ToolHistory from '$lib/components/ToolHistory.svelte';
	import ToolHelp from '$lib/components/ToolHelp.svelte';

	interface WafIndicator {
		indicator_type: string;
		category: string;
		description: string;
		value: string;
		confidence: number;
		severity: string;
	}

	interface BlockedPayload {
		payload: string;
		attack_type: string;
		status_code: number;
		blocked: boolean;
		block_method: string;
	}

	interface CookieIndicator {
		name: string;
		waf_name: string;
		confidence: number;
		description: string;
	}

	interface ResponseAnalysis {
		status_code: number;
		server_header: string | null;
		content_length: number | null;
		has_captcha: boolean;
		has_challenge_page: boolean;
		redirect_url: string | null;
		response_time_ms: number;
		content_type: string | null;
		x_powered_by: string | null;
		interesting_headers: string[];
	}

	interface BypassSuggestion {
		technique: string;
		description: string;
		difficulty: string;
		effectiveness: string;
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
		max_confidence: number;
	}

	interface WafDetectionResult {
		url: string;
		waf_detected: boolean;
		waf_name: string | null;
		confidence: number;
		grade: string;
		indicators: WafIndicator[];
		blocked_payloads: BlockedPayload[];
		cookie_indicators: CookieIndicator[];
		response_analysis: ResponseAnalysis;
		bypass_suggestions: BypassSuggestion[];
		severity_stats: SeverityStats;
		category_stats: CategoryStat[];
		summary: string;
		scan_duration_ms: number;
	}

	interface BatchWafDetectionResult {
		url: string;
		result: WafDetectionResult | null;
		error: string | null;
	}

	let url = $state('');
	let timeout = $state(15);
	let followRedirects = $state(true);
	let verifySsl = $state(false);
	let userAgent = $state('');
	let proxyUrl = $state('');
	let customHeaders = $state('');
	let maxConcurrentPayloads = $state(5);
	let checkCookies = $state(true);
	let checkResponseBehavior = $state(true);
	let aggressiveMode = $state(false);
	let result: WafDetectionResult | null = $state(null);
	let batchResults: BatchWafDetectionResult[] = $state([]);
	let error = $state('');
	let processing = $state(false);
	let activeMainTab = $state('detect');
	let activeTab = $state('single');
	let activeResultTab = $state('overview');
	let historyComponent: ToolHistory;
	let showTargetSelector = $state(false);
	let targetList: any[] = $state([]);
	let selectedTargets: any[] = $state([]);
	let selectedTargetIds: number[] = $state([]);
	let targetSearchQuery = $state('');
	let loadingTargets = $state(false);
	let showAdvancedConfig = $state(false);
	let currentPage = $state(1);
	let pageSize = 10;

	let totalPages = $derived(Math.ceil(batchResults.length / pageSize));
	let paginatedResults = $derived(batchResults.slice((currentPage - 1) * pageSize, currentPage * pageSize));
	let detectedCount = $derived(batchResults.filter(r => r.result?.waf_detected).length);
	let notDetectedCount = $derived(batchResults.filter(r => r.result && !r.result.waf_detected).length);
	let errorCount = $derived(batchResults.filter(r => r.error).length);
	let filteredTargets = $derived(
		targetList.filter((t: any) =>
			!targetSearchQuery ||
			t.name?.toLowerCase().includes(targetSearchQuery.toLowerCase()) ||
			t.target_value?.toLowerCase().includes(targetSearchQuery.toLowerCase())
		)
	);

	function getConfidenceColor(conf: number): string {
		if (conf >= 0.8) return '#ef4444';
		if (conf >= 0.6) return '#f97316';
		if (conf >= 0.4) return '#eab308';
		if (conf >= 0.2) return '#3b82f6';
		return '#22c55e';
	}

	function getConfidenceLabel(conf: number): string {
		if (conf >= 0.8) return $tr('wafDetector.result.veryHigh');
		if (conf >= 0.6) return $tr('wafDetector.result.high');
		if (conf >= 0.4) return $tr('wafDetector.result.medium');
		if (conf >= 0.2) return $tr('wafDetector.result.low');
		return $tr('wafDetector.result.veryLow');
	}

	function getGradeColor(grade: string): string {
		if (grade.startsWith('A')) return '#22c55e';
		if (grade.startsWith('B')) return '#3b82f6';
		if (grade.startsWith('C')) return '#eab308';
		if (grade === 'D') return '#f97316';
		if (grade === 'E') return '#ef4444';
		return '#64748b';
	}

	function getSeverityColor(severity: string): string {
		switch (severity) {
			case 'critical': return '#ef4444';
			case 'high': return '#f97316';
			case 'medium': return '#eab308';
			case 'low': return '#3b82f6';
			default: return '#64748b';
		}
	}

	function getDifficultyLabel(diff: string): string {
		switch (diff) {
			case 'low': return $tr('wafDetector.bypass.difficultyLow');
			case 'medium': return $tr('wafDetector.bypass.difficultyMedium');
			case 'high': return $tr('wafDetector.bypass.difficultyHigh');
			case 'very_high': return $tr('wafDetector.bypass.difficultyVeryHigh');
			default: return diff;
		}
	}

	function getEffectivenessLabel(eff: string): string {
		switch (eff) {
			case 'low': return $tr('wafDetector.bypass.effectivenessLow');
			case 'medium': return $tr('wafDetector.bypass.effectivenessMedium');
			case 'high': return $tr('wafDetector.bypass.effectivenessHigh');
			default: return eff;
		}
	}

	function buildConfig() {
		return {
			url: url.trim(),
			timeout,
			follow_redirects: followRedirects,
			verify_ssl: verifySsl,
			user_agent: userAgent || null,
			proxy_url: proxyUrl || null,
			custom_headers: customHeaders || null,
			max_concurrent_payloads: maxConcurrentPayloads,
			check_cookies: checkCookies,
			check_response_behavior: checkResponseBehavior,
			aggressive_mode: aggressiveMode,
		};
	}

	async function detectWaf() {
		if (!url.trim()) {
			error = $tr('wafDetector.error.emptyInput');
			return;
		}
		processing = true;
		error = '';
		result = null;
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			result = await invoke<WafDetectionResult>('detect_waf_command', { config: buildConfig(), targetId: selectedTargetIds.length > 0 ? selectedTargetIds[0] : null });
			if (result && historyComponent) {
				await historyComponent.saveHistory(result.url, JSON.stringify(result), result.summary, 'completed');
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

	async function batchDetect() {
		const urls = url.split(/[\n,;]+/).map(u => u.trim()).filter(u => u.length > 0);
		if (urls.length === 0) {
			error = $tr('wafDetector.error.emptyInput');
			return;
		}
		processing = true;
		error = '';
		batchResults = [];
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			for (const targetUrl of urls) {
				try {
					const config = buildConfig();
					config.url = targetUrl;
					const r = await invoke<WafDetectionResult>('detect_waf_command', { config });
					batchResults.push({ url: targetUrl, result: r, error: null });
					if (historyComponent) {
						await historyComponent.saveHistory(r.url, JSON.stringify(r), r.summary, 'completed');
					}
				} catch (e: any) {
					batchResults.push({ url: targetUrl, result: null, error: e.toString() });
				}
			}
		} catch (e: any) {
			error = e.toString();
		} finally {
			processing = false;
		}
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
			url = url ? `${url}\n${targetValues}` : targetValues;
			selectedTargetIds = selectedTargets.map((t: any) => t.id).filter((id: number | null): id is number => id !== null);
		}
		showTargetSelector = false;
		selectedTargets = [];
	}

	async function importUrls() {
		try {
			const selected = await open({ multiple: false, filters: [{ name: 'Text', extensions: ['txt', 'csv', 'list'] }] });
			if (selected) {
				const fileData = await readFile(selected as string);
				const content = new TextDecoder('utf-8').decode(fileData);
				const urls = content.split(/[\n,;]+/).map(u => u.trim()).filter(u => u.length > 0);
				if (urls.length > 0) {
					url = url ? `${url}\n${urls.join('\n')}` : urls.join('\n');
				}
			}
		} catch (e) {
			console.error('Import failed:', e);
		}
	}

	function clearAll() {
		url = '';
		timeout = 15;
		result = null;
		batchResults = [];
		error = '';
		activeResultTab = 'overview';
	}

	function switchTab(tab: string) {
		activeTab = tab;
		error = '';
		result = null;
		batchResults = [];
	}

	function handleKeydown(e: KeyboardEvent) {
		if (e.key === 'Enter' && !processing && url.trim()) {
			if (activeTab === 'single') detectWaf();
			else batchDetect();
		}
	}
</script>

<svelte:window onkeydown={handleKeydown} />

<div class="nd-page">
	<div class="page-header">
		<div class="header-left">
			<a href="/" class="back-link">{$tr('common.backToHome')}</a>
			<h1 class="page-title">🛡️ {$tr('wafDetector.title')}</h1>
			<p class="page-subtitle">{$tr('wafDetector.subtitle')}</p>
		</div>
	</div>

	<div class="tabs">
		<button class="tab-btn {activeMainTab === 'detect' ? 'active' : ''}" onclick={() => activeMainTab = 'detect'}>
			<span class="tab-icon">🔍</span> {$tr('wafDetector.tabs.detect')}
		</button>
		<button class="tab-btn {activeMainTab === 'history' ? 'active' : ''}" onclick={() => activeMainTab = 'history'}>
			<span class="tab-icon">📋</span> {$tr('wafDetector.tabs.history')}
		</button>
		<button class="tab-btn {activeMainTab === 'help' ? 'active' : ''}" onclick={() => activeMainTab = 'help'}>
			<span class="tab-icon">📖</span> {$tr('wafDetector.tabs.help')}
		</button>
	</div>

	{#if activeMainTab === 'detect'}
		<div class="content-grid">
			<div class="input-section">
				<div class="section-card">
					<h2 class="section-title">{$tr('wafDetector.input.title')}</h2>
					<p class="section-desc">{$tr('wafDetector.input.configDesc')}</p>

					<div class="sub-tabs">
						<button class="sub-tab-btn {activeTab === 'single' ? 'active' : ''}" onclick={() => switchTab('single')}>
							{$tr('wafDetector.tabs.single')}
						</button>
						<button class="sub-tab-btn {activeTab === 'batch' ? 'active' : ''}" onclick={() => switchTab('batch')}>
							{$tr('wafDetector.tabs.batch')}
						</button>
					</div>

					{#if activeTab === 'single'}
						<div class="form-group">
							<label class="form-label">{$tr('wafDetector.input.urlLabel')}</label>
							<input type="text" bind:value={url} placeholder={$tr('wafDetector.input.urlPlaceholder')} class="form-input" disabled={processing} />
						</div>
					{:else}
						<div class="form-group">
							<label class="form-label">{$tr('wafDetector.batch.inputLabel')}</label>
							<textarea bind:value={url} placeholder={$tr('wafDetector.batch.inputPlaceholder')} class="form-textarea" rows="6" disabled={processing}></textarea>
							<div class="textarea-actions">
								<button type="button" class="action-btn" onclick={openTargetSelectorModal} disabled={processing}>
									🎯 {$tr('wafDetector.batch.selectTarget')}
								</button>
								<button type="button" class="action-btn" onclick={importUrls} disabled={processing}>
									📥 {$tr('wafDetector.batch.import')}
								</button>
							</div>
						</div>
					{/if}

					<div class="form-row">
						<div class="form-group">
							<label class="form-label">{$tr('wafDetector.input.timeoutLabel')}</label>
							<input type="number" bind:value={timeout} placeholder="15" class="form-input" disabled={processing} min="5" max="60" />
						</div>
						<div class="form-group">
							<label class="form-label">{$tr('wafDetector.input.concurrentLabel')}</label>
							<input type="number" bind:value={maxConcurrentPayloads} placeholder="5" class="form-input" disabled={processing} min="1" max="20" />
						</div>
					</div>

					<div class="form-group">
						<label class="form-label">{$tr('wafDetector.input.detectionOptions')}</label>
						<div class="target-grid">
							<label class="target-chip {checkCookies ? 'active' : ''}">
								<input type="checkbox" bind:checked={checkCookies} disabled={processing} />
								<span>🍪 {$tr('wafDetector.input.checkCookies')}</span>
							</label>
							<label class="target-chip {checkResponseBehavior ? 'active' : ''}">
								<input type="checkbox" bind:checked={checkResponseBehavior} disabled={processing} />
								<span>🎯 {$tr('wafDetector.input.checkBehavior')}</span>
							</label>
							<label class="target-chip {followRedirects ? 'active' : ''}">
								<input type="checkbox" bind:checked={followRedirects} disabled={processing} />
								<span>↪️ {$tr('wafDetector.input.followRedirects')}</span>
							</label>
							<label class="target-chip {aggressiveMode ? 'active' : ''}">
								<input type="checkbox" bind:checked={aggressiveMode} disabled={processing} />
								<span>⚡ {$tr('wafDetector.input.aggressiveMode')}</span>
							</label>
						</div>
					</div>

					<div class="form-group">
						<button class="config-toggle" onclick={() => showAdvancedConfig = !showAdvancedConfig}>
							<span>{showAdvancedConfig ? '▼' : '▶'}</span>
							<span>{$tr('wafDetector.input.advancedConfig')}</span>
						</button>
					</div>

					{#if showAdvancedConfig}
						<div class="advanced-config">
							<div class="form-row">
								<div class="form-group">
									<label class="form-label">🌐 Proxy URL</label>
									<input type="text" bind:value={proxyUrl} placeholder="http://proxy:port" class="form-input" disabled={processing} />
								</div>
								<div class="form-group">
									<label class="form-label">🔑 User-Agent</label>
									<input type="text" bind:value={userAgent} placeholder={$tr('wafDetector.input.uaPlaceholder')} class="form-input" disabled={processing} />
								</div>
							</div>
							<div class="form-group">
								<label class="form-label">📋 {$tr('wafDetector.input.customHeaders')}</label>
								<input type="text" bind:value={customHeaders} placeholder="X-Custom: value, X-Api-Key: key" class="form-input" disabled={processing} />
							</div>
							<div class="form-group">
								<label class="target-chip {verifySsl ? 'active' : ''}">
									<input type="checkbox" bind:checked={verifySsl} disabled={processing} />
									<span>🔒 {$tr('wafDetector.input.verifySsl')}</span>
								</label>
							</div>
						</div>
					{/if}

					<div class="button-group">
						<button class="btn-primary" onclick={activeTab === 'single' ? detectWaf : batchDetect} disabled={processing || !url.trim()}>
							{#if processing}<span class="spinner"></span>{$tr('wafDetector.buttons.detecting')}{:else}🔍 {activeTab === 'single' ? $tr('wafDetector.buttons.detect') : $tr('wafDetector.batch.detectAll')}{/if}
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
					{:else if activeTab === 'single' && result}
						<div class="result-header">
							<div class="status-badge {result.waf_detected ? 'detected' : 'safe'}">
								{#if result.waf_detected}🛡️{:else}✅{/if}
								<span>{result.waf_detected ? $tr('wafDetector.result.detected') : $tr('wafDetector.result.notDetected')}</span>
							</div>
							{#if result.waf_detected}
								<div class="grade-badge" style="border-color: {getGradeColor(result.grade)}; color: {getGradeColor(result.grade)}">
									<span class="grade-label">{$tr('wafDetector.result.grade')}</span>
									<span class="grade-value">{result.grade}</span>
								</div>
							{/if}
						</div>

						{#if result.waf_detected && result.waf_name}
							<div class="waf-name-card">
								<span class="waf-name-label">{$tr('wafDetector.result.wafName')}</span>
								<span class="waf-name-value">{result.waf_name}</span>
								<span class="confidence-badge" style="background: {getConfidenceColor(result.confidence)}15; color: {getConfidenceColor(result.confidence)}; border: 1px solid {getConfidenceColor(result.confidence)}40">
									{getConfidenceLabel(result.confidence)} ({(result.confidence * 100).toFixed(0)}%)
								</span>
							</div>
						{/if}

						<div class="summary-bar">{result.summary}</div>

						<div class="result-tabs">
							<button class="result-tab {activeResultTab === 'overview' ? 'active' : ''}" onclick={() => activeResultTab = 'overview'}>
								📊 {$tr('wafDetector.result.tabOverview')}
							</button>
							<button class="result-tab {activeResultTab === 'indicators' ? 'active' : ''}" onclick={() => activeResultTab = 'indicators'}>
								🔍 {$tr('wafDetector.result.tabIndicators')} ({result.indicators.length})
							</button>
							<button class="result-tab {activeResultTab === 'payloads' ? 'active' : ''}" onclick={() => activeResultTab = 'payloads'}>
								🚫 {$tr('wafDetector.result.tabPayloads')} ({result.blocked_payloads.length})
							</button>
							{#if result.cookie_indicators.length > 0}
								<button class="result-tab {activeResultTab === 'cookies' ? 'active' : ''}" onclick={() => activeResultTab = 'cookies'}>
									🍪 {$tr('wafDetector.result.tabCookies')} ({result.cookie_indicators.length})
								</button>
							{/if}
							{#if result.bypass_suggestions.length > 0}
								<button class="result-tab {activeResultTab === 'bypass' ? 'active' : ''}" onclick={() => activeResultTab = 'bypass'}>
									🔓 {$tr('wafDetector.result.tabBypass')} ({result.bypass_suggestions.length})
								</button>
							{/if}
						</div>

						{#if activeResultTab === 'overview'}
							<div class="overview-grid">
								<div class="overview-stat">
									<span class="stat-icon">⏱️</span>
									<span class="stat-value">{result.scan_duration_ms}</span>
									<span class="stat-label">ms</span>
								</div>
								<div class="overview-stat">
									<span class="stat-icon">📡</span>
									<span class="stat-value">{result.response_analysis.status_code}</span>
									<span class="stat-label">{$tr('wafDetector.result.statusCode')}</span>
								</div>
								<div class="overview-stat">
									<span class="stat-icon">🔍</span>
									<span class="stat-value">{result.indicators.length}</span>
									<span class="stat-label">{$tr('wafDetector.result.indicatorsCount')}</span>
								</div>
								<div class="overview-stat">
									<span class="stat-icon">🚫</span>
									<span class="stat-value">{result.blocked_payloads.length}</span>
									<span class="stat-label">{$tr('wafDetector.result.blockedCount')}</span>
								</div>
							</div>

							<div class="detail-section">
								<h4 class="detail-title">📊 {$tr('wafDetector.result.responseInfo')}</h4>
								<div class="detail-row">
									<span class="detail-label">{$tr('wafDetector.result.statusCode')}</span>
									<span class="detail-value" style="color: {result.response_analysis.status_code >= 400 ? '#ef4444' : '#22c55e'}">{result.response_analysis.status_code}</span>
								</div>
								<div class="detail-row">
									<span class="detail-label">{$tr('wafDetector.result.server')}</span>
									<span class="detail-value mono">{result.response_analysis.server_header ?? '-'}</span>
								</div>
								{#if result.response_analysis.x_powered_by}
									<div class="detail-row">
										<span class="detail-label">X-Powered-By</span>
										<span class="detail-value mono">{result.response_analysis.x_powered_by}</span>
									</div>
								{/if}
								<div class="detail-row">
									<span class="detail-label">{$tr('wafDetector.result.responseTime')}</span>
									<span class="detail-value">{result.response_analysis.response_time_ms} ms</span>
								</div>
								{#if result.response_analysis.content_type}
									<div class="detail-row">
										<span class="detail-label">Content-Type</span>
										<span class="detail-value mono">{result.response_analysis.content_type}</span>
									</div>
								{/if}
								{#if result.response_analysis.has_captcha}
									<div class="detail-row warning">
										<span class="detail-label">CAPTCHA</span>
										<span class="detail-value">⚠️ {$tr('wafDetector.result.captchaDetected')}</span>
									</div>
								{/if}
								{#if result.response_analysis.has_challenge_page}
									<div class="detail-row warning">
										<span class="detail-label">{$tr('wafDetector.result.challengePage')}</span>
										<span class="detail-value">⚠️ {$tr('wafDetector.result.challengeDetected')}</span>
									</div>
								{/if}
								{#if result.response_analysis.redirect_url}
									<div class="detail-row">
										<span class="detail-label">{$tr('wafDetector.result.redirectUrl')}</span>
										<span class="detail-value mono">{result.response_analysis.redirect_url}</span>
									</div>
								{/if}
							</div>

							{#if result.severity_stats && (result.severity_stats.critical + result.severity_stats.high + result.severity_stats.medium + result.severity_stats.low + result.severity_stats.info) > 0}
								<div class="detail-section">
									<h4 class="detail-title">📊 {$tr('wafDetector.result.severityDistribution')}</h4>
									<div class="severity-bar">
										{#if result.severity_stats.critical > 0}
											<div class="severity-segment critical" style="flex: {result.severity_stats.critical}">
												<span class="severity-text">🔴 {result.severity_stats.critical}</span>
											</div>
										{/if}
										{#if result.severity_stats.high > 0}
											<div class="severity-segment high" style="flex: {result.severity_stats.high}">
												<span class="severity-text">🟠 {result.severity_stats.high}</span>
											</div>
										{/if}
										{#if result.severity_stats.medium > 0}
											<div class="severity-segment medium" style="flex: {result.severity_stats.medium}">
												<span class="severity-text">🟡 {result.severity_stats.medium}</span>
											</div>
										{/if}
										{#if result.severity_stats.low > 0}
											<div class="severity-segment low" style="flex: {result.severity_stats.low}">
												<span class="severity-text">🔵 {result.severity_stats.low}</span>
											</div>
										{/if}
										{#if result.severity_stats.info > 0}
											<div class="severity-segment info" style="flex: {result.severity_stats.info}">
												<span class="severity-text">⚪ {result.severity_stats.info}</span>
											</div>
										{/if}
									</div>
								</div>
							{/if}

							{#if result.response_analysis.interesting_headers.length > 0}
								<div class="detail-section">
									<h4 class="detail-title">🔑 {$tr('wafDetector.result.interestingHeaders')}</h4>
									{#each result.response_analysis.interesting_headers as header}
										<div class="detail-row">
											<span class="detail-value mono" style="font-size: 0.75rem">{header}</span>
										</div>
									{/each}
								</div>
							{/if}
						{:else if activeResultTab === 'indicators'}
							{#if result.indicators.length > 0}
								<div class="indicator-list">
									{#each result.indicators as indicator}
										<div class="indicator-item">
											<div class="indicator-header">
												<span class="indicator-type">{indicator.indicator_type}</span>
												<span class="indicator-severity" style="color: {getSeverityColor(indicator.severity)}">{indicator.severity.toUpperCase()}</span>
												<span class="indicator-confidence" style="color: {getConfidenceColor(indicator.confidence)}">
													{(indicator.confidence * 100).toFixed(0)}%
												</span>
											</div>
											<div class="indicator-desc">{indicator.description}</div>
											<div class="indicator-meta">
												<span class="indicator-category">{indicator.category}</span>
												<span class="indicator-value mono">{indicator.value}</span>
											</div>
										</div>
									{/each}
								</div>
							{:else}
								<div class="empty-state">
									<div class="empty-icon">🔍</div>
									<p>{$tr('wafDetector.result.noIndicators')}</p>
								</div>
							{/if}
						{:else if activeResultTab === 'payloads'}
							{#if result.blocked_payloads.length > 0}
								<div class="payload-list">
									{#each result.blocked_payloads as payload}
										<div class="payload-item {payload.blocked ? 'blocked' : 'passed'}">
											<div class="payload-header">
												<span class="payload-status">{payload.blocked ? '🚫' : '✅'}</span>
												<span class="payload-type">{payload.attack_type}</span>
												<span class="payload-method">{payload.block_method}</span>
											</div>
											<div class="payload-url mono">{payload.payload}</div>
											<div class="payload-meta">
												<span class="payload-status-code">HTTP {payload.status_code}</span>
											</div>
										</div>
									{/each}
								</div>
							{:else}
								<div class="empty-state">
									<div class="empty-icon">🚫</div>
									<p>{$tr('wafDetector.result.noBlockedPayloads')}</p>
								</div>
							{/if}
						{:else if activeResultTab === 'cookies'}
							{#if result.cookie_indicators.length > 0}
								<div class="cookie-list">
									{#each result.cookie_indicators as cookie}
										<div class="cookie-item">
											<div class="cookie-header">
												<span class="cookie-name">🍪 {cookie.name}</span>
												<span class="cookie-confidence" style="color: {getConfidenceColor(cookie.confidence)}">
													{(cookie.confidence * 100).toFixed(0)}%
												</span>
											</div>
											<div class="cookie-desc">{cookie.description}</div>
											<div class="cookie-waf">→ {cookie.waf_name}</div>
										</div>
									{/each}
								</div>
							{:else}
								<div class="empty-state">
									<div class="empty-icon">🍪</div>
									<p>{$tr('wafDetector.result.noCookieIndicators')}</p>
								</div>
							{/if}
						{:else if activeResultTab === 'bypass'}
							{#if result.bypass_suggestions.length > 0}
								<div class="bypass-list">
									{#each result.bypass_suggestions as suggestion}
										<div class="bypass-item">
											<div class="bypass-header">
												<span class="bypass-technique">🔓 {suggestion.technique}</span>
												<span class="bypass-difficulty difficulty-{suggestion.difficulty}">
													{getDifficultyLabel(suggestion.difficulty)}
												</span>
												<span class="bypass-effectiveness effectiveness-{suggestion.effectiveness}">
													{getEffectivenessLabel(suggestion.effectiveness)}
												</span>
											</div>
											<div class="bypass-desc">{suggestion.description}</div>
										</div>
									{/each}
								</div>
							{:else}
								<div class="empty-state">
									<div class="empty-icon">🔓</div>
									<p>{$tr('wafDetector.result.noBypassSuggestions')}</p>
								</div>
							{/if}
						{/if}
					{:else if activeTab === 'batch' && batchResults.length > 0}
						<div class="batch-stats">
							<div class="overview-stat">
								<span class="stat-icon">📊</span>
								<span class="stat-value">{batchResults.length}</span>
								<span class="stat-label">{$tr('wafDetector.batch.total')}</span>
							</div>
							<div class="overview-stat detected">
								<span class="stat-icon">🛡️</span>
								<span class="stat-value">{detectedCount}</span>
								<span class="stat-label">{$tr('wafDetector.batch.detected')}</span>
							</div>
							<div class="overview-stat safe">
								<span class="stat-icon">✅</span>
								<span class="stat-value">{notDetectedCount}</span>
								<span class="stat-label">{$tr('wafDetector.batch.notDetected')}</span>
							</div>
							{#if errorCount > 0}
								<div class="overview-stat err">
									<span class="stat-icon">❌</span>
									<span class="stat-value">{errorCount}</span>
									<span class="stat-label">{$tr('wafDetector.batch.error')}</span>
								</div>
							{/if}
						</div>
						<div class="batch-results">
							{#each paginatedResults as item}
								<div class="batch-item {item.result?.waf_detected ? 'detected' : 'safe'}">
									<div class="batch-item-header">
										<span class="batch-status">{item.result?.waf_detected ? '🛡️' : '✅'}</span>
										<span class="batch-url mono">{item.url}</span>
										{#if item.result}
											{#if item.result.waf_name}
												<span class="batch-waf-name">{item.result.waf_name}</span>
											{/if}
											<span class="batch-grade" style="color: {getGradeColor(item.result.grade)}">{item.result.grade}</span>
											<span class="batch-confidence" style="color: {getConfidenceColor(item.result.confidence)}">
												{(item.result.confidence * 100).toFixed(0)}%
											</span>
										{:else}
											<span class="batch-error-text">❌ {item.error}</span>
										{/if}
									</div>
								</div>
							{/each}
						</div>
						{#if totalPages > 1}
							<div class="pagination">
								<button class="page-btn" disabled={currentPage === 1} onclick={() => currentPage--}>←</button>
								<span class="page-info">{$tr('common.page')} {currentPage}/{totalPages}</span>
								<button class="page-btn" disabled={currentPage >= totalPages} onclick={() => currentPage++}>→</button>
							</div>
						{/if}
					{:else}
						<div class="empty-state">
							<div class="empty-icon">🛡️</div>
							<p>{$tr('wafDetector.result.empty')}</p>
							<p class="empty-hint">{$tr('wafDetector.result.hint')}</p>
						</div>
					{/if}
				</div>
			</div>
		</div>
	{:else if activeMainTab === 'history'}
		<div class="section-card">
			<ToolHistory toolType="waf_detector" toolName={$tr('wafDetector.title')} bind:this={historyComponent} />
		</div>
	{:else if activeMainTab === 'help'}
		<div class="section-card">
			<ToolHelp toolType="waf_detector" />
		</div>
	{/if}
</div>

{#if showTargetSelector}
	<div class="modal-overlay" onclick={() => showTargetSelector = false}>
		<div class="modal-content" onclick={(e) => e.stopPropagation()}>
			<div class="modal-header">
				<h3>🎯 {$tr('wafDetector.batch.targetSelector.title')}</h3>
				<button class="modal-close" onclick={() => showTargetSelector = false}>✕</button>
			</div>
			<div class="modal-body">
				<input type="text" bind:value={targetSearchQuery} placeholder={$tr('wafDetector.batch.targetSelector.searchPlaceholder')} class="form-input" />
				{#if loadingTargets}
					<div class="loading-state"><span class="spinner"></span> {$tr('wafDetector.batch.targetSelector.loading')}</div>
				{:else if filteredTargets.length === 0}
					<div class="empty-state"><p>{$tr('wafDetector.batch.targetSelector.noTargets')}</p></div>
				{:else}
					<div class="target-list">
						{#each filteredTargets as t}
							<label class="target-select-item {selectedTargets.some((st: any) => st.id === t.id) ? 'selected' : ''}">
								<input type="checkbox" checked={selectedTargets.some((st: any) => st.id === t.id)} onchange={() => toggleTargetSelection(t)} />
								<span>{t.name || t.target_value}</span>
							</label>
						{/each}
					</div>
				{/if}
			</div>
			<div class="modal-footer">
				<span class="selected-count">{$tr('wafDetector.batch.targetSelector.selectedCount', { count: selectedTargets.length })}</span>
				<button class="btn-secondary" onclick={() => showTargetSelector = false}>{$tr('common.cancel')}</button>
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
	.section-card { background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(168, 85, 247, 0.15); border-radius: 0.75rem; padding: 1.25rem; }
	.section-title { font-size: 1rem; font-weight: 600; color: #f1f5f9; margin: 0 0 0.5rem; }
	.section-desc { font-size: 0.8rem; color: #94a3b8; margin: 0 0 1rem; }

	.sub-tabs { display: flex; gap: 0.25rem; margin-bottom: 1rem; background: rgba(15, 23, 42, 0.4); border: 1px solid rgba(148, 163, 184, 0.1); border-radius: 0.5rem; padding: 0.2rem; }
	.sub-tab-btn { flex: 1; padding: 0.45rem 0.75rem; border: none; border-radius: 0.375rem; background: transparent; cursor: pointer; font-size: 0.8rem; color: #94a3b8; transition: all 0.2s; }
	.sub-tab-btn.active { background: rgba(168, 85, 247, 0.2); color: #c4b5fd; font-weight: 600; }
	.sub-tab-btn:hover:not(.active) { background: rgba(148, 163, 184, 0.1); }

	.form-group { margin-bottom: 0.75rem; }
	.form-label { display: block; font-size: 0.75rem; color: #94a3b8; margin-bottom: 0.3rem; font-weight: 500; text-transform: uppercase; letter-spacing: 0.05em; }
	.form-input { width: 100%; padding: 0.55rem 0.75rem; border-radius: 0.5rem; border: 1px solid rgba(148, 163, 184, 0.15); background: rgba(15, 23, 42, 0.8); color: #f1f5f9; font-size: 0.85rem; box-sizing: border-box; transition: border-color 0.2s; }
	.form-input:focus { outline: none; border-color: #a855f7; box-shadow: 0 0 0 2px rgba(168, 85, 247, 0.15); }
	.form-input::placeholder { color: #475569; }
	.form-textarea { width: 100%; padding: 0.55rem 0.75rem; border-radius: 0.5rem; border: 1px solid rgba(148, 163, 184, 0.15); background: rgba(15, 23, 42, 0.8); color: #f1f5f9; font-size: 0.85rem; box-sizing: border-box; transition: border-color 0.2s; resize: vertical; font-family: inherit; }
	.form-textarea:focus { outline: none; border-color: #a855f7; box-shadow: 0 0 0 2px rgba(168, 85, 247, 0.15); }
	.form-textarea::placeholder { color: #475569; }

	.textarea-actions { display: flex; gap: 0.5rem; margin-top: 0.5rem; }
	.action-btn { padding: 0.35rem 0.65rem; border-radius: 0.375rem; border: 1px solid rgba(148, 163, 184, 0.2); background: rgba(148, 163, 184, 0.1); color: #94a3b8; cursor: pointer; font-size: 0.75rem; transition: all 0.2s; }
	.action-btn:hover:not(:disabled) { background: rgba(148, 163, 184, 0.2); border-color: rgba(148, 163, 184, 0.3); }
	.action-btn:disabled { opacity: 0.5; cursor: not-allowed; }

	.form-row { display: grid; grid-template-columns: 1fr 1fr; gap: 0.75rem; }
	.target-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 0.35rem; }
	.target-chip { display: flex; align-items: center; gap: 0.4rem; padding: 0.4rem 0.65rem; border-radius: 0.375rem; border: 1px solid rgba(148, 163, 184, 0.15); cursor: pointer; font-size: 0.78rem; color: #94a3b8; transition: all 0.2s; }
	.target-chip.active { border-color: rgba(168, 85, 247, 0.4); background: rgba(168, 85, 247, 0.1); color: #c4b5fd; }
	.target-chip input[type="checkbox"] { accent-color: #a855f7; width: 0.8rem; height: 0.8rem; }
	.target-chip:hover:not(.active) { border-color: rgba(148, 163, 184, 0.3); }

	.config-toggle { display: flex; align-items: center; gap: 0.5rem; padding: 0.4rem 0; border: none; background: transparent; color: #94a3b8; cursor: pointer; font-size: 0.8rem; transition: color 0.2s; }
	.config-toggle:hover { color: #c4b5fd; }
	.advanced-config { padding: 0.75rem; border: 1px solid rgba(168, 85, 247, 0.15); border-radius: 0.5rem; background: rgba(15, 23, 42, 0.4); margin-bottom: 0.75rem; }

	.button-group { display: flex; gap: 0.5rem; margin-top: 1rem; }
	.btn-primary { flex: 1; background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%); color: white; font-weight: 600; padding: 0.65rem 1.25rem; border: none; border-radius: 0.5rem; cursor: pointer; transition: all 0.2s; display: flex; align-items: center; justify-content: center; gap: 0.5rem; font-size: 0.9rem; }
	.btn-primary:hover:not(:disabled) { box-shadow: 0 4px 15px rgba(168, 85, 247, 0.4); transform: translateY(-1px); }
	.btn-primary:disabled { opacity: 0.5; cursor: not-allowed; transform: none; box-shadow: none; }
	.btn-secondary { background: rgba(148, 163, 184, 0.1); color: #94a3b8; padding: 0.65rem 1rem; border: 1px solid rgba(148, 163, 184, 0.15); border-radius: 0.5rem; cursor: pointer; transition: all 0.2s; font-size: 0.9rem; }
	.btn-secondary:hover:not(:disabled) { background: rgba(148, 163, 184, 0.2); color: #e2e8f0; }
	.btn-secondary:disabled { opacity: 0.5; cursor: not-allowed; }
	.btn-primary-sm { background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%); color: white; font-weight: 600; padding: 0.45rem 1rem; border: none; border-radius: 0.5rem; cursor: pointer; font-size: 0.8rem; }
	.btn-primary-sm:disabled { opacity: 0.5; cursor: not-allowed; }

	.spinner { display: inline-block; width: 1rem; height: 1rem; border: 2px solid rgba(255, 255, 255, 0.3); border-top-color: white; border-radius: 50%; animation: spin 0.6s linear infinite; }
	@keyframes spin { to { transform: rotate(360deg); } }

	.error-card { display: flex; align-items: center; gap: 0.75rem; padding: 1rem; background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.2); border-radius: 0.5rem; }
	.error-icon { font-size: 1.25rem; }
	.error-text { color: #fca5a5; font-size: 0.85rem; }

	.result-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem; }
	.status-badge { display: flex; align-items: center; gap: 0.5rem; padding: 0.5rem 1rem; border-radius: 0.5rem; font-weight: 600; font-size: 0.9rem; }
	.status-badge.detected { background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.3); color: #fca5a5; }
	.status-badge.safe { background: rgba(34, 197, 94, 0.1); border: 1px solid rgba(34, 197, 94, 0.3); color: #86efac; }
	.grade-badge { display: flex; flex-direction: column; align-items: center; padding: 0.5rem 1rem; border-radius: 0.5rem; border: 2px solid; }
	.grade-label { font-size: 0.6rem; text-transform: uppercase; opacity: 0.8; }
	.grade-value { font-size: 1.5rem; font-weight: 700; line-height: 1; }

	.waf-name-card { display: flex; align-items: center; gap: 0.75rem; padding: 0.75rem 1rem; background: rgba(15, 23, 42, 0.4); border: 1px solid rgba(168, 85, 247, 0.2); border-radius: 0.5rem; margin-bottom: 0.75rem; }
	.waf-name-label { font-size: 0.75rem; color: #94a3b8; font-weight: 500; }
	.waf-name-value { font-size: 1rem; font-weight: 700; color: #f1f5f9; }
	.confidence-badge { padding: 0.25rem 0.65rem; border-radius: 0.375rem; font-size: 0.75rem; font-weight: 600; }

	.summary-bar { font-size: 0.8rem; color: #94a3b8; padding: 0.5rem 0.75rem; background: rgba(15, 23, 42, 0.4); border-radius: 0.4rem; margin-bottom: 1rem; border: 1px solid rgba(148, 163, 184, 0.08); }

	.result-tabs { display: flex; gap: 0.25rem; margin-bottom: 1rem; flex-wrap: wrap; }
	.result-tab { padding: 0.4rem 0.75rem; border-radius: 0.4rem; border: 1px solid rgba(148, 163, 184, 0.15); background: rgba(15, 23, 42, 0.4); color: #94a3b8; cursor: pointer; font-size: 0.8rem; transition: all 0.2s; }
	.result-tab.active { background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%); color: white; border-color: transparent; font-weight: 600; }
	.result-tab:hover:not(.active) { border-color: rgba(168, 85, 247, 0.3); color: #c4b5fd; }

	.overview-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 0.75rem; margin-bottom: 1rem; }
	.overview-stat { display: flex; flex-direction: column; align-items: center; padding: 0.75rem; background: rgba(15, 23, 42, 0.4); border: 1px solid rgba(148, 163, 184, 0.08); border-radius: 0.5rem; }
	.overview-stat.detected { border-color: rgba(239, 68, 68, 0.2); background: rgba(239, 68, 68, 0.05); }
	.overview-stat.safe { border-color: rgba(34, 197, 94, 0.2); background: rgba(34, 197, 94, 0.05); }
	.overview-stat.err { border-color: rgba(245, 158, 11, 0.2); background: rgba(245, 158, 11, 0.05); }
	.stat-icon { font-size: 1.1rem; margin-bottom: 0.25rem; }
	.stat-value { font-size: 1.1rem; font-weight: 700; color: #f1f5f9; }
	.stat-label { font-size: 0.7rem; color: #94a3b8; }

	.detail-section { display: flex; flex-direction: column; gap: 0.5rem; margin-bottom: 1rem; }
	.detail-title { font-size: 0.85rem; font-weight: 600; color: #f1f5f9; margin: 0 0 0.25rem; }
	.detail-row { display: flex; justify-content: space-between; align-items: flex-start; padding: 0.5rem 0.75rem; background: rgba(15, 23, 42, 0.4); border-radius: 0.4rem; border: 1px solid rgba(148, 163, 184, 0.06); }
	.detail-row.warning { background: rgba(245, 158, 11, 0.08); border-color: rgba(245, 158, 11, 0.2); }
	.detail-label { font-size: 0.75rem; color: #94a3b8; font-weight: 500; flex-shrink: 0; margin-right: 1rem; }
	.detail-value { font-size: 0.8rem; color: #e2e8f0; text-align: right; word-break: break-word; }
	.mono { font-family: 'SF Mono', 'Fira Code', monospace; font-size: 0.78rem; }

	.severity-bar { display: flex; gap: 2px; border-radius: 0.375rem; overflow: hidden; height: 28px; }
	.severity-segment { display: flex; align-items: center; justify-content: center; min-width: 40px; }
	.severity-segment.critical { background: rgba(239, 68, 68, 0.3); }
	.severity-segment.high { background: rgba(249, 115, 22, 0.3); }
	.severity-segment.medium { background: rgba(234, 179, 8, 0.3); }
	.severity-segment.low { background: rgba(59, 130, 246, 0.3); }
	.severity-segment.info { background: rgba(100, 116, 139, 0.3); }
	.severity-text { font-size: 0.7rem; white-space: nowrap; }

	.indicator-list { display: flex; flex-direction: column; gap: 0.4rem; }
	.indicator-item { padding: 0.6rem 0.75rem; background: rgba(15, 23, 42, 0.4); border: 1px solid rgba(148, 163, 184, 0.06); border-radius: 0.4rem; }
	.indicator-header { display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.25rem; }
	.indicator-type { padding: 0.15rem 0.4rem; border-radius: 0.25rem; background: rgba(168, 85, 247, 0.15); color: #c4b5fd; font-size: 0.7rem; font-weight: 600; }
	.indicator-severity { font-size: 0.7rem; font-weight: 700; }
	.indicator-confidence { font-size: 0.75rem; font-weight: 600; margin-left: auto; }
	.indicator-desc { font-size: 0.8rem; color: #e2e8f0; margin-bottom: 0.25rem; }
	.indicator-meta { display: flex; align-items: center; gap: 0.5rem; }
	.indicator-category { font-size: 0.7rem; color: #64748b; }
	.indicator-value { font-size: 0.7rem; color: #94a3b8; }

	.payload-list { display: flex; flex-direction: column; gap: 0.4rem; }
	.payload-item { padding: 0.6rem 0.75rem; background: rgba(15, 23, 42, 0.4); border: 1px solid rgba(148, 163, 184, 0.06); border-radius: 0.4rem; }
	.payload-item.blocked { border-left: 3px solid #ef4444; }
	.payload-item.passed { border-left: 3px solid #22c55e; }
	.payload-header { display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.25rem; }
	.payload-status { font-size: 0.85rem; }
	.payload-type { padding: 0.15rem 0.4rem; border-radius: 0.25rem; background: rgba(239, 68, 68, 0.15); color: #fca5a5; font-size: 0.7rem; font-weight: 600; }
	.payload-method { padding: 0.15rem 0.4rem; border-radius: 0.25rem; background: rgba(59, 130, 246, 0.15); color: #93c5fd; font-size: 0.7rem; }
	.payload-url { font-size: 0.78rem; color: #e2e8f0; margin-bottom: 0.25rem; word-break: break-all; }
	.payload-meta { display: flex; align-items: center; gap: 0.5rem; }
	.payload-status-code { font-size: 0.7rem; color: #64748b; }

	.cookie-list { display: flex; flex-direction: column; gap: 0.4rem; }
	.cookie-item { padding: 0.6rem 0.75rem; background: rgba(15, 23, 42, 0.4); border: 1px solid rgba(148, 163, 184, 0.06); border-radius: 0.4rem; border-left: 3px solid #f59e0b; }
	.cookie-header { display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.25rem; }
	.cookie-name { font-size: 0.85rem; font-weight: 600; color: #f1f5f9; }
	.cookie-confidence { font-size: 0.75rem; font-weight: 600; margin-left: auto; }
	.cookie-desc { font-size: 0.8rem; color: #94a3b8; margin-bottom: 0.15rem; }
	.cookie-waf { font-size: 0.75rem; color: #a855f7; }

	.bypass-list { display: flex; flex-direction: column; gap: 0.4rem; }
	.bypass-item { padding: 0.6rem 0.75rem; background: rgba(15, 23, 42, 0.4); border: 1px solid rgba(148, 163, 184, 0.06); border-radius: 0.4rem; border-left: 3px solid #22c55e; }
	.bypass-header { display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.25rem; flex-wrap: wrap; }
	.bypass-technique { font-size: 0.85rem; font-weight: 600; color: #f1f5f9; }
	.bypass-difficulty, .bypass-effectiveness { padding: 0.15rem 0.4rem; border-radius: 0.25rem; font-size: 0.65rem; font-weight: 600; }
	.difficulty-low { background: rgba(34, 197, 94, 0.15); color: #86efac; }
	.difficulty-medium { background: rgba(234, 179, 8, 0.15); color: #fde047; }
	.difficulty-high { background: rgba(249, 115, 22, 0.15); color: #fdba74; }
	.difficulty-very_high { background: rgba(239, 68, 68, 0.15); color: #fca5a5; }
	.effectiveness-low { background: rgba(148, 163, 184, 0.15); color: #94a3b8; }
	.effectiveness-medium { background: rgba(59, 130, 246, 0.15); color: #93c5fd; }
	.effectiveness-high { background: rgba(34, 197, 94, 0.15); color: #86efac; }
	.bypass-desc { font-size: 0.8rem; color: #94a3b8; line-height: 1.5; }

	.batch-stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 0.75rem; margin-bottom: 1rem; }
	.batch-results { display: flex; flex-direction: column; gap: 0.4rem; }
	.batch-item { padding: 0.5rem 0.75rem; border-radius: 0.4rem; border: 1px solid rgba(148, 163, 184, 0.06); background: rgba(15, 23, 42, 0.4); }
	.batch-item.detected { border-left: 3px solid #ef4444; }
	.batch-item.safe { border-left: 3px solid #22c55e; }
	.batch-item-header { display: flex; align-items: center; gap: 0.5rem; }
	.batch-status { font-size: 0.85rem; }
	.batch-url { flex: 1; font-size: 0.8rem; color: #e2e8f0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
	.batch-waf-name { padding: 0.15rem 0.4rem; border-radius: 0.25rem; background: rgba(168, 85, 247, 0.15); color: #c4b5fd; font-size: 0.7rem; font-weight: 600; }
	.batch-grade { font-size: 0.85rem; font-weight: 700; }
	.batch-confidence { font-size: 0.75rem; font-weight: 600; }
	.batch-error-text { font-size: 0.75rem; color: #fca5a5; }

	.pagination { display: flex; justify-content: center; align-items: center; gap: 0.75rem; margin-top: 1rem; padding-top: 0.75rem; border-top: 1px solid rgba(148, 163, 184, 0.08); }
	.page-btn { background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(148, 163, 184, 0.15); border-radius: 0.375rem; padding: 0.35rem 0.65rem; cursor: pointer; font-size: 0.85rem; color: #e2e8f0; }
	.page-btn:disabled { opacity: 0.4; cursor: not-allowed; }
	.page-info { font-size: 0.8rem; color: #94a3b8; }

	.empty-state { text-align: center; padding: 2.5rem 1rem; color: #94a3b8; }
	.empty-icon { font-size: 2.5rem; margin-bottom: 0.75rem; }
	.empty-state p { font-size: 0.85rem; margin: 0; }
	.empty-hint { font-size: 0.78rem; color: #64748b; margin-top: 0.25rem; }

	.modal-overlay { position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0, 0, 0, 0.5); display: flex; align-items: center; justify-content: center; z-index: 1000; }
	.modal-content { background: var(--bg-secondary, #1e293b); border-radius: 0.75rem; padding: 1.25rem; max-width: 500px; width: 90%; max-height: 80vh; display: flex; flex-direction: column; }
	.modal-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem; }
	.modal-header h3 { margin: 0; font-size: 1rem; color: #f1f5f9; }
	.modal-close { background: none; border: none; cursor: pointer; font-size: 1.2rem; color: #94a3b8; }
	.modal-body { flex: 1; overflow-y: auto; margin-bottom: 1rem; }
	.modal-footer { display: flex; align-items: center; gap: 0.75rem; justify-content: flex-end; }
	.selected-count { font-size: 0.8rem; color: #94a3b8; margin-right: auto; }

	.loading-state { display: flex; align-items: center; justify-content: center; gap: 0.5rem; padding: 2rem; color: #94a3b8; }
	.target-list { display: flex; flex-direction: column; gap: 0.35rem; max-height: 300px; overflow-y: auto; margin-top: 0.5rem; }
	.target-select-item { display: flex; align-items: center; gap: 0.5rem; padding: 0.4rem 0.65rem; border-radius: 0.375rem; border: 1px solid rgba(148, 163, 184, 0.1); cursor: pointer; font-size: 0.8rem; color: #94a3b8; transition: all 0.2s; }
	.target-select-item.selected { border-color: rgba(168, 85, 247, 0.4); background: rgba(168, 85, 247, 0.1); color: #c4b5fd; }
	.target-select-item input[type="checkbox"] { accent-color: #a855f7; }

	@media (max-width: 768px) {
		.content-grid { grid-template-columns: 1fr; }
		.overview-grid { grid-template-columns: repeat(2, 1fr); }
		.batch-stats { grid-template-columns: repeat(2, 1fr); }
		.target-grid { grid-template-columns: 1fr; }
	}
</style>
