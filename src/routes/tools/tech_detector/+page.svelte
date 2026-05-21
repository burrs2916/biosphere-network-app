<script lang="ts">
	import { tr, t } from '$lib/i18n';
	import ToolHistory from '$lib/components/ToolHistory.svelte';
	import ToolHelp from '$lib/components/ToolHelp.svelte';

	interface DetectedTech {
		name: string;
		category: string;
		confidence: number;
		version: string | null;
		detection_method: string;
		detail: string;
	}

	interface TechCategory {
		name: string;
		count: number;
		techs: string[];
	}

	interface SslInfo {
		subject: string | null;
		issuer: string | null;
		valid_from: string | null;
		valid_to: string | null;
		is_expired: boolean;
		protocol: string | null;
		cipher: string | null;
		san_domains: string[];
	}

	interface WafDetection {
		detected: boolean;
		waf_name: string | null;
		evidence: string[];
	}

	interface SecurityHeaderEntry {
		name: string;
		present: boolean;
		value: string | null;
		recommendation: string;
		severity: string;
	}

	interface SecurityHeaderResult {
		headers: SecurityHeaderEntry[];
		score: number;
		grade: string;
	}

	interface ResponseInfo {
		status_code: number;
		content_type: string | null;
		server: string | null;
		content_length: number | null;
		response_time_ms: number;
		redirect_url: string | null;
		ip_address: string | null;
	}

	interface TechDetectResult {
		url: string;
		technologies: DetectedTech[];
		categories: TechCategory[];
		summary: string;
		ssl_info: SslInfo | null;
		waf_detected: WafDetection | null;
		security_headers: SecurityHeaderResult | null;
		response_info: ResponseInfo;
		scan_duration_ms: number;
	}

	let url = $state('');
	let activeMainTab = $state('analyze');
	let historyComponent: ToolHistory;
	let timeout = $state(15);
	let scanMode = $state('normal');
	let followRedirects = $state(true);
	let randomizeUa = $state(true);
	let collectSslInfo = $state(true);
	let collectSecurityHeaders = $state(true);
	let detectJs = $state(true);
	let detectHeaders = $state(true);
	let detectCookies = $state(true);
	let detectHtml = $state(true);
	let detectCss = $state(true);
	let detectMeta = $state(true);
	let result: TechDetectResult | null = $state(null);
	let error = $state('');
	let processing = $state(false);
	let activeResultTab = $state('overview');
	let categoryFilter = $state('all');
	let searchQuery = $state('');

	async function detect() {
		if (!url.trim()) { error = t('techDetector.error.emptyInput'); return; }
		processing = true; error = ''; result = null;
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			result = await invoke<TechDetectResult>('detect_tech_command', {
				config: {
					url: url.trim(),
					timeout,
					detect_js: detectJs,
					detect_headers: detectHeaders,
					detect_cookies: detectCookies,
					detect_html: detectHtml,
					detect_css: detectCss,
					detect_meta: detectMeta,
					scan_mode: scanMode,
					follow_redirects: followRedirects,
					randomize_ua: randomizeUa,
					collect_ssl_info: collectSslInfo,
					collect_security_headers: collectSecurityHeaders,
				}
			});
			if (result && historyComponent) {
				await historyComponent.saveHistory(
					url.trim(),
					JSON.stringify(result),
					result.summary,
					'completed'
				);
			}
		} catch (e: any) {
			error = e.toString();
			if (historyComponent) {
				await historyComponent.saveHistory(url.trim(), JSON.stringify({ error: e.toString() }), undefined, 'failed');
			}
		} finally { processing = false; }
	}

	function clearAll() {
		url = ''; result = null; error = '';
		categoryFilter = 'all'; searchQuery = '';
	}

	function getConfidenceColor(c: number): string {
		if (c >= 0.9) return '#22c55e';
		if (c >= 0.7) return '#a855f7';
		if (c >= 0.5) return '#f59e0b';
		return '#ef4444';
	}

	function getConfidenceLabel(c: number): string {
		if (c >= 0.9) return t('techDetector.labels.high');
		if (c >= 0.7) return t('techDetector.labels.medium');
		if (c >= 0.5) return t('techDetector.labels.low');
		return t('techDetector.labels.weak');
	}

	function getCategoryIcon(cat: string): string {
		const icons: Record<string, string> = {
			'Web Server': '🖥️', 'Framework': '🏗️', 'Programming Language': '💻',
			'CMS': '📝', 'JavaScript Library': '📦', 'UI Framework': '🎨',
			'CDN': '🌐', 'Analytics': '📊', 'Advertising': '📢',
			'Cache': '⚡', 'Database': '🗄️', 'Hosting': '☁️',
			'Marketing': '📈', 'Miscellaneous': '🔧', 'Security': '🔒',
			'Payment': '💳', 'Customer Support': '🎧', 'E-commerce': '🛒',
			'Static Site Generator': '⚡', 'Website Builder': '🏗️',
			'Forum': '💬', 'Wiki': '📖', 'DevOps': '⚙️',
			'Monitoring': '📡', 'Build Tool': '🔨', 'PaaS': '☁️',
		};
		return icons[cat] || '🔧';
	}

	function getTechIcon(name: string): string {
		const lower = name.toLowerCase();
		if (lower.includes('react')) return '⚛️';
		if (lower.includes('vue')) return '💚';
		if (lower.includes('angular')) return '🔴';
		if (lower.includes('next')) return '▲';
		if (lower.includes('nuxt')) return '💚';
		if (lower.includes('svelte')) return '🔥';
		if (lower.includes('wordpress')) return '📝';
		if (lower.includes('bootstrap')) return '🅱️';
		if (lower.includes('tailwind')) return '🌊';
		if (lower.includes('cloudflare')) return '☁️';
		if (lower.includes('google')) return '🔍';
		if (lower.includes('stripe')) return '💳';
		if (lower.includes('paypal')) return '💰';
		if (lower.includes('nginx')) return '🖥️';
		if (lower.includes('apache')) return '🖥️';
		if (lower.includes('php')) return '🐘';
		if (lower.includes('django')) return '🐍';
		if (lower.includes('laravel')) return '🔴';
		if (lower.includes('shopify')) return '🛒';
		if (lower.includes('magento')) return '🛒';
		if (lower.includes('drupal')) return '💧';
		if (lower.includes('joomla')) return '🟧';
		if (lower.includes('firebase')) return '🔥';
		if (lower.includes('vercel')) return '▲';
		if (lower.includes('netlify')) return '🌐';
		if (lower.includes('astro')) return '🚀';
		if (lower.includes('gatsby')) return '💜';
		if (lower.includes('hugo')) return '🏗️';
		if (lower.includes('vite')) return '⚡';
		if (lower.includes('webpack')) return '📦';
		if (lower.includes('jquery')) return '📜';
		if (lower.includes('lodash')) return '📦';
		return '🔧';
	}

	function getMethodBadgeColor(method: string): string {
		const lower = method.toLowerCase();
		if (lower.includes('header')) return '#3b82f6';
		if (lower.includes('cookie')) return '#f59e0b';
		if (lower.includes('html')) return '#22c55e';
		if (lower.includes('javascript') || lower.includes('js')) return '#a855f7';
		if (lower.includes('css')) return '#ec4899';
		if (lower.includes('meta')) return '#06b6d4';
		if (lower.includes('script')) return '#8b5cf6';
		if (lower.includes('link')) return '#0ea5e9';
		return '#64748b';
	}

	function getSeverityColor(sev: string): string {
		if (sev === 'critical' || sev === 'high') return '#ef4444';
		if (sev === 'medium') return '#f97316';
		return '#eab308';
	}

	function getSecurityGradeColor(grade: string): string {
		if (grade === 'A+' || grade === 'A') return '#22c55e';
		if (grade === 'B') return '#3b82f6';
		if (grade === 'C') return '#f59e0b';
		if (grade === 'D') return '#f97316';
		return '#ef4444';
	}

	function formatDuration(ms: number): string {
		if (ms < 1000) return `${ms}ms`;
		return `${(ms / 1000).toFixed(1)}s`;
	}

	function formatSize(bytes: number | null): string {
		if (bytes === null) return '-';
		if (bytes < 1024) return `${bytes}B`;
		if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)}KB`;
		return `${(bytes / (1024 * 1024)).toFixed(1)}MB`;
	}

	function getFilteredTechs(): DetectedTech[] {
		if (!result) return [];
		let techs = result.technologies;
		if (categoryFilter !== 'all') {
			techs = techs.filter(t => t.category === categoryFilter);
		}
		if (searchQuery.trim()) {
			const q = searchQuery.toLowerCase();
			techs = techs.filter(t =>
				t.name.toLowerCase().includes(q) ||
				t.category.toLowerCase().includes(q) ||
				t.detection_method.toLowerCase().includes(q) ||
				t.detail.toLowerCase().includes(q)
			);
		}
		return techs;
	}

	function getUniqueCategories(): string[] {
		if (!result) return [];
		return [...new Set(result.technologies.map(t => t.category))];
	}

	function exportJSON() {
		if (!result) return;
		const blob = new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' });
		const a = document.createElement('a');
		a.href = URL.createObjectURL(blob);
		a.download = `techdetect_${new Date().toISOString().slice(0, 10)}.json`;
		a.click();
		URL.revokeObjectURL(a.href);
	}

	function exportCSV() {
		if (!result) return;
		const headers = ['Name', 'Category', 'Version', 'Confidence', 'Method', 'Detail'];
		const rows = result.technologies.map(t => [
			t.name, t.category, t.version || '',
			(t.confidence * 100).toFixed(0) + '%', t.detection_method, t.detail
		]);
		const csv = [headers.join(','), ...rows.map(r => r.map(c => `"${c}"`).join(','))].join('\n');
		const blob = new Blob([csv], { type: 'text/csv' });
		const a = document.createElement('a');
		a.href = URL.createObjectURL(blob);
		a.download = `techdetect_${new Date().toISOString().slice(0, 10)}.csv`;
		a.click();
		URL.revokeObjectURL(a.href);
	}
</script>

<div class="nd-page">
	<div class="page-header">
		<div class="header-left">
			<a href="/" class="back-link">{$tr('common.backToHome')}</a>
			<h1 class="page-title">🔬 {$tr('techDetector.title')}</h1>
			<p class="page-subtitle">{$tr('techDetector.subtitle')}</p>
		</div>
	</div>

	<div class="tabs">
		<button class="tab-btn {activeMainTab === 'analyze' ? 'active' : ''}" onclick={() => activeMainTab = 'analyze'}>
			<span class="tab-icon">🔍</span> {$tr('techDetector.detect')}
		</button>
		<button class="tab-btn {activeMainTab === 'history' ? 'active' : ''}" onclick={() => activeMainTab = 'history'}>
			<span class="tab-icon">📋</span> {$tr('techDetector.history')}
		</button>
		<button class="tab-btn {activeMainTab === 'help' ? 'active' : ''}" onclick={() => activeMainTab = 'help'}>
			<span class="tab-icon">📖</span> {$tr('techDetector.help')}
		</button>
	</div>

	{#if activeMainTab === 'analyze'}
		<div class="content-grid">
			<div class="input-section">
				<div class="section-card">
					<h2 class="section-title">{$tr('techDetector.configTitle')}</h2>
					<p class="section-desc">{$tr('techDetector.configDesc')}</p>

					<div class="form-group">
						<label class="form-label">{$tr('techDetector.targetUrl')}</label>
						<input type="text" bind:value={url} placeholder="https://example.com" class="form-input" disabled={processing} onkeydown={(e) => e.key === 'Enter' && detect()} />
					</div>

					<div class="form-row">
						<div class="form-group">
							<label class="form-label">{$tr('techDetector.timeout')}</label>
							<input type="number" bind:value={timeout} class="form-input" min="5" max="60" disabled={processing} />
						</div>
					</div>

					<div class="form-group">
						<label class="form-label">{$tr('techDetector.scanMode')}</label>
						<div class="target-grid">
							<label class="target-chip {scanMode === 'quick' ? 'active' : ''}">
								<input type="radio" name="scanMode" value="quick" bind:group={scanMode} disabled={processing} />
								<span>⚡ {$tr('techDetector.modeQuick')}</span>
							</label>
							<label class="target-chip {scanMode === 'normal' ? 'active' : ''}">
								<input type="radio" name="scanMode" value="normal" bind:group={scanMode} disabled={processing} />
								<span>⚖️ {$tr('techDetector.modeNormal')}</span>
							</label>
							<label class="target-chip {scanMode === 'deep' ? 'active' : ''}">
								<input type="radio" name="scanMode" value="deep" bind:group={scanMode} disabled={processing} />
								<span>🔬 {$tr('techDetector.modeDeep')}</span>
							</label>
						</div>
					</div>

					<div class="form-group">
						<label class="form-label">{$tr('techDetector.detectionMethods')}</label>
						<div class="target-grid">
							<label class="target-chip {detectHeaders ? 'active' : ''}">
								<input type="checkbox" bind:checked={detectHeaders} disabled={processing} />
								<span>📡 {$tr('techDetector.methods.httpHeader')}</span>
							</label>
							<label class="target-chip {detectCookies ? 'active' : ''}">
								<input type="checkbox" bind:checked={detectCookies} disabled={processing} />
								<span>🍪 {$tr('techDetector.methods.cookie')}</span>
							</label>
							<label class="target-chip {detectHtml ? 'active' : ''}">
								<input type="checkbox" bind:checked={detectHtml} disabled={processing} />
								<span>📄 {$tr('techDetector.methods.html')}</span>
							</label>
							<label class="target-chip {detectJs ? 'active' : ''}">
								<input type="checkbox" bind:checked={detectJs} disabled={processing} />
								<span>📜 {$tr('techDetector.methods.javascript')}</span>
							</label>
							<label class="target-chip {detectCss ? 'active' : ''}">
								<input type="checkbox" bind:checked={detectCss} disabled={processing} />
								<span>🎨 {$tr('techDetector.methods.css')}</span>
							</label>
							<label class="target-chip {detectMeta ? 'active' : ''}">
								<input type="checkbox" bind:checked={detectMeta} disabled={processing} />
								<span>🏷️ {$tr('techDetector.methods.metaTag')}</span>
							</label>
						</div>
					</div>

					<div class="checkbox-grid">
						<label class="target-chip {followRedirects ? 'active' : ''}">
							<input type="checkbox" bind:checked={followRedirects} disabled={processing} />
							<span>↪️ {$tr('techDetector.followRedirects')}</span>
						</label>
						<label class="target-chip {randomizeUa ? 'active' : ''}">
							<input type="checkbox" bind:checked={randomizeUa} disabled={processing} />
							<span>🎭 {$tr('techDetector.randomUa')}</span>
						</label>
						<label class="target-chip {collectSslInfo ? 'active' : ''}">
							<input type="checkbox" bind:checked={collectSslInfo} disabled={processing} />
							<span>🔒 {$tr('techDetector.collectSsl')}</span>
						</label>
						<label class="target-chip {collectSecurityHeaders ? 'active' : ''}">
							<input type="checkbox" bind:checked={collectSecurityHeaders} disabled={processing} />
							<span>🛡️ {$tr('techDetector.collectSecurityHeaders')}</span>
						</label>
					</div>

					<div class="button-group">
						<button class="btn-primary" onclick={detect} disabled={processing || !url.trim()}>
							{#if processing}<span class="spinner"></span>{$tr('techDetector.detecting')}{:else}🔬 {$tr('techDetector.startDetect')}{/if}
						</button>
						<button class="btn-secondary" onclick={clearAll} disabled={processing}>🗑️</button>
					</div>
				</div>
			</div>

			<div class="result-section">
				{#if error}
					<div class="section-card">
						<div class="error-card">
							<span class="error-icon">⚠️</span>
							<span class="error-text">{error}</span>
						</div>
					</div>
				{:else if result}
					<div class="section-card">
						<div class="result-header">
							<h2 class="section-title">{$tr('techDetector.resultTitle')}</h2>
							<div class="result-header-actions">
								<div class="result-score-badge">
									<span class="score-value">{result.technologies.length}</span>
									<span class="score-label">{$tr('techDetector.topTechs')}</span>
								</div>
								<div class="export-group">
									<button class="export-btn" onclick={exportJSON} title="JSON">📋 JSON</button>
									<button class="export-btn" onclick={exportCSV} title="CSV">📊 CSV</button>
								</div>
							</div>
						</div>

						<div class="summary-bar">
							{result.summary}
							<span class="duration-badge">⏱ {formatDuration(result.scan_duration_ms)}</span>
						</div>

						{#if result.waf_detected?.detected}
							<div class="waf-alert">
								<span class="waf-icon">🛡️</span>
								<div class="waf-info">
									<span class="waf-title">{$tr('techDetector.wafDetected')}: {result.waf_detected.waf_name}</span>
									{#if result.waf_detected.evidence.length > 0}
										<span class="waf-evidence">{result.waf_detected.evidence.join(' | ')}</span>
									{/if}
								</div>
							</div>
						{/if}

						{#if result.ssl_info}
							<div class="ssl-info-bar">
								<span class="ssl-icon">🔒</span>
								<div class="ssl-details">
									<span class="ssl-subject">{result.ssl_info.subject || '-'}</span>
									<span class="ssl-meta">
										{result.ssl_info.protocol || '-'} | {result.ssl_info.cipher || '-'}
										{#if result.ssl_info.is_expired}<span class="ssl-expired">⚠️ EXPIRED</span>{/if}
									</span>
								</div>
							</div>
						{/if}

						{#if result.security_headers}
							<div class="security-header-bar">
								<span class="sh-icon">🛡️</span>
								<div class="sh-details">
									<span class="sh-grade" style="color: {getSecurityGradeColor(result.security_headers.grade)}">
										{$tr('techDetector.securityGrade')}: {result.security_headers.grade} ({result.security_headers.score}/100)
									</span>
									<span class="sh-missing">
										{result.security_headers.headers.filter(h => !h.present).length} {$tr('techDetector.headersMissing')}
									</span>
								</div>
							</div>
						{/if}

						{#if result.categories.length > 0}
							<div class="tech-grid" style="margin-bottom: 1rem;">
								{#each result.categories as cat}
									<span class="tech-chip">
										<span class="tech-icon">{getCategoryIcon(cat.name)}</span>
										<span class="tech-name">{cat.name}</span>
										<span class="tech-count">{cat.count}</span>
									</span>
								{/each}
							</div>
						{/if}

						<div class="result-tabs">
							<button class="result-tab {activeResultTab === 'overview' ? 'active' : ''}" onclick={() => activeResultTab = 'overview'}>
								📊 {$tr('techDetector.overview')}
							</button>
							<button class="result-tab {activeResultTab === 'detail' ? 'active' : ''}" onclick={() => activeResultTab = 'detail'}>
								📋 {$tr('techDetector.detail')}
							</button>
							<button class="result-tab {activeResultTab === 'category' ? 'active' : ''}" onclick={() => activeResultTab = 'category'}>
								🗂️ {$tr('techDetector.byCategory')}
							</button>
							<button class="result-tab {activeResultTab === 'security' ? 'active' : ''}" onclick={() => activeResultTab = 'security'}>
								🛡️ {$tr('techDetector.security')}
							</button>
						</div>

						{#if activeResultTab === 'overview'}
							<div class="overview-grid">
								<div class="overview-stat">
									<span class="stat-icon">🔬</span>
									<span class="stat-value">{result.technologies.length}</span>
									<span class="stat-label">{$tr('techDetector.topTechs')}</span>
								</div>
								<div class="overview-stat">
									<span class="stat-icon">🗂️</span>
									<span class="stat-value">{result.categories.length}</span>
									<span class="stat-label">{$tr('techDetector.result.categories')}</span>
								</div>
								<div class="overview-stat">
									<span class="stat-icon">📡</span>
									<span class="stat-value">{result.response_info.status_code}</span>
									<span class="stat-label">HTTP {$tr('techDetector.labels.statusCode')}</span>
								</div>
								<div class="overview-stat">
									<span class="stat-icon">⏱</span>
									<span class="stat-value">{formatDuration(result.scan_duration_ms)}</span>
									<span class="stat-label">{$tr('techDetector.scanDuration')}</span>
								</div>
							</div>

							{#if result.response_info}
								<div class="response-info-bar">
									<div class="ri-item">
										<span class="ri-label">Server</span>
										<span class="ri-value">{result.response_info.server || '-'}</span>
									</div>
									<div class="ri-item">
										<span class="ri-label">IP</span>
										<span class="ri-value">{result.response_info.ip_address || '-'}</span>
									</div>
									<div class="ri-item">
										<span class="ri-label">Content-Type</span>
										<span class="ri-value">{result.response_info.content_type || '-'}</span>
									</div>
									<div class="ri-item">
										<span class="ri-label">Size</span>
										<span class="ri-value">{formatSize(result.response_info.content_length)}</span>
									</div>
								</div>
							{/if}

							<div class="subsection-title">{$tr('techDetector.topTechs')}</div>
							<div class="tech-grid">
								{#each result.technologies as tech}
									<span class="tech-chip">
										<span class="tech-icon">{getTechIcon(tech.name)}</span>
										<span class="tech-name">{tech.name}</span>
										{#if tech.version}
											<span class="tech-version-mini">v{tech.version}</span>
										{/if}
										<span class="confidence-mini" style="color: {getConfidenceColor(tech.confidence)}">
											{(tech.confidence * 100).toFixed(0)}%
										</span>
									</span>
								{/each}
							</div>
						{:else if activeResultTab === 'detail'}
							<div class="filter-bar">
								<button class="filter-btn {categoryFilter === 'all' ? 'active' : ''}" onclick={() => categoryFilter = 'all'}>
									{$tr('techDetector.overview')} ({result.technologies.length})
								</button>
								{#each getUniqueCategories() as cat}
									<button class="filter-btn {categoryFilter === cat ? 'active' : ''}" onclick={() => categoryFilter = cat}>
										{getCategoryIcon(cat)} {cat} ({result.technologies.filter(t => t.category === cat).length})
									</button>
								{/each}
							</div>

							<div class="search-bar">
								<input type="text" bind:value={searchQuery} placeholder="{$tr('techDetector.searchPlaceholder')}" class="search-input" />
							</div>

							<div class="links-table-wrapper">
								<table class="data-table">
									<thead>
										<tr>
											<th>{$tr('techDetector.labels.tech')}</th>
											<th>{$tr('techDetector.labels.category')}</th>
											<th>{$tr('techDetector.labels.version')}</th>
											<th>{$tr('techDetector.labels.confidence')}</th>
											<th>{$tr('techDetector.labels.method')}</th>
											<th>{$tr('techDetector.labels.detail')}</th>
										</tr>
									</thead>
									<tbody>
										{#each getFilteredTechs() as tech}
											<tr>
												<td>
													<span class="tech-name-cell">
														<span class="tech-icon">{getTechIcon(tech.name)}</span>
														{tech.name}
													</span>
												</td>
												<td>
													<span class="category-badge">{getCategoryIcon(tech.category)} {tech.category}</span>
												</td>
												<td>
													{#if tech.version}
														<span class="tech-version-mini">v{tech.version}</span>
													{:else}
														<span class="text-muted">-</span>
													{/if}
												</td>
												<td>
													<span class="confidence-badge" style="color: {getConfidenceColor(tech.confidence)}; border-color: {getConfidenceColor(tech.confidence)}40; background: {getConfidenceColor(tech.confidence)}15;">
														{(tech.confidence * 100).toFixed(0)}%
													</span>
												</td>
												<td>
													{#each tech.detection_method.split(', ') as method}
														<span class="method-badge" style="background: {getMethodBadgeColor(method)}15; color: {getMethodBadgeColor(method)}; border-color: {getMethodBadgeColor(method)}30;">
															{method}
														</span>
													{/each}
												</td>
												<td>
													<span class="detail-text" title={tech.detail}>{tech.detail}</span>
												</td>
											</tr>
										{/each}
									</tbody>
								</table>
							</div>
						{:else if activeResultTab === 'category'}
							{#each result.categories as cat}
								<div class="category-section">
									<div class="category-header">
										<span class="category-icon">{getCategoryIcon(cat.name)}</span>
										<span class="category-name">{cat.name}</span>
										<span class="category-count">{cat.count}</span>
									</div>
									<div class="category-techs">
										{#each result.technologies.filter(t => t.category === cat.name) as tech}
											<div class="category-tech-item">
												<div class="cti-left">
													<span class="tech-icon">{getTechIcon(tech.name)}</span>
													<span class="cti-name">{tech.name}</span>
													{#if tech.version}
														<span class="tech-version-mini">v{tech.version}</span>
													{/if}
												</div>
												<div class="cti-right">
													<span class="confidence-mini" style="color: {getConfidenceColor(tech.confidence)}">
														{(tech.confidence * 100).toFixed(0)}%
													</span>
													<span class="method-mini">{tech.detection_method}</span>
												</div>
											</div>
										{/each}
									</div>
								</div>
							{/each}
						{:else if activeResultTab === 'security'}
							{#if result.security_headers}
								<div class="security-overview">
									<div class="grade-display" style="border-color: {getSecurityGradeColor(result.security_headers.grade)}40; background: {getSecurityGradeColor(result.security_headers.grade)}10;">
										<span class="grade-letter" style="color: {getSecurityGradeColor(result.security_headers.grade)}">{result.security_headers.grade}</span>
										<span class="grade-score">{$tr('techDetector.securityScore')}: {result.security_headers.score}/100</span>
									</div>
								</div>

								<div class="security-headers-list">
									{#each result.security_headers.headers as header}
										<div class="sh-item" style="border-left: 3px solid {header.present ? '#22c55e' : getSeverityColor(header.severity)}">
											<div class="shi-header">
												<span class="shi-status">{header.present ? '✅' : '❌'}</span>
												<span class="shi-name">{header.name}</span>
												<span class="shi-severity" style="background: {getSeverityColor(header.severity)}20; color: {getSeverityColor(header.severity)}">{header.severity}</span>
											</div>
											{#if header.present && header.value}
												<div class="shi-value">{header.value}</div>
											{/if}
											{#if !header.present}
												<div class="shi-recommendation">💡 {header.recommendation}</div>
											{/if}
										</div>
									{/each}
								</div>
							{:else}
								<div class="empty-mini">{$tr('techDetector.noSecurityHeaders')}</div>
							{/if}

							{#if result.ssl_info}
								<div class="subsection-title">🔒 SSL/TLS {$tr('techDetector.info')}</div>
								<div class="ssl-detail-card">
									<div class="ssl-detail-row">
										<span class="ssl-detail-label">{$tr('techDetector.ssl.subject')}</span>
										<span class="ssl-detail-value">{result.ssl_info.subject || '-'}</span>
									</div>
									<div class="ssl-detail-row">
										<span class="ssl-detail-label">{$tr('techDetector.ssl.issuer')}</span>
										<span class="ssl-detail-value">{result.ssl_info.issuer || '-'}</span>
									</div>
									<div class="ssl-detail-row">
										<span class="ssl-detail-label">{$tr('techDetector.ssl.validFrom')}</span>
										<span class="ssl-detail-value">{result.ssl_info.valid_from || '-'}</span>
									</div>
									<div class="ssl-detail-row">
										<span class="ssl-detail-label">{$tr('techDetector.ssl.validTo')}</span>
										<span class="ssl-detail-value" style="color: {result.ssl_info.is_expired ? '#ef4444' : '#22c55e'}">{result.ssl_info.valid_to || '-'}{#if result.ssl_info.is_expired} ⚠️ EXPIRED{/if}</span>
									</div>
									<div class="ssl-detail-row">
										<span class="ssl-detail-label">{$tr('techDetector.ssl.protocol')}</span>
										<span class="ssl-detail-value">{result.ssl_info.protocol || '-'}</span>
									</div>
									<div class="ssl-detail-row">
										<span class="ssl-detail-label">{$tr('techDetector.ssl.cipher')}</span>
										<span class="ssl-detail-value">{result.ssl_info.cipher || '-'}</span>
									</div>
									{#if result.ssl_info.san_domains.length > 0}
										<div class="ssl-detail-row">
											<span class="ssl-detail-label">SAN</span>
											<span class="ssl-detail-value">{result.ssl_info.san_domains.join(', ')}</span>
										</div>
									{/if}
								</div>
							{/if}

							{#if result.waf_detected?.detected}
								<div class="subsection-title">🛡️ WAF {$tr('techDetector.info')}</div>
								<div class="waf-detail-card">
									<div class="waf-detail-row">
										<span class="waf-detail-label">{$tr('techDetector.waf.name')}</span>
										<span class="waf-detail-value">{result.waf_detected.waf_name || '-'}</span>
									</div>
									{#if result.waf_detected.evidence.length > 0}
										<div class="waf-detail-row">
											<span class="waf-detail-label">{$tr('techDetector.waf.evidence')}</span>
											<div class="waf-evidence-list">
												{#each result.waf_detected.evidence as ev}
													<span class="waf-evidence-chip">{ev}</span>
												{/each}
											</div>
										</div>
									{/if}
								</div>
							{/if}
						{/if}
					</div>
				{:else}
					<div class="section-card">
						<div class="empty-state">
							<div class="empty-icon">🔬</div>
							<p class="empty-text">{$tr('techDetector.emptyHint')}</p>
							<p class="empty-sub">{$tr('techDetector.emptySub')}</p>
						</div>
					</div>
				{/if}
			</div>
		</div>
	{:else if activeMainTab === 'history'}
		<div class="section-card">
			<ToolHistory toolType="tech_detector" toolName={$tr('techDetector.title')} bind:this={historyComponent} />
		</div>
	{:else if activeMainTab === 'help'}
		<div class="section-card">
			<ToolHelp toolType="tech_detector" />
		</div>
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
	.section-card { background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(168, 85, 247, 0.15); border-radius: 0.75rem; padding: 1.25rem; }
	.section-title { font-size: 1rem; font-weight: 600; color: #f1f5f9; margin: 0 0 1rem; }
	.section-desc { font-size: 0.8rem; color: #94a3b8; margin: 0.25rem 0 0; }
	.form-group { margin-bottom: 0.75rem; }
	.form-label { display: block; font-size: 0.75rem; color: #94a3b8; margin-bottom: 0.3rem; font-weight: 500; text-transform: uppercase; letter-spacing: 0.05em; }
	.form-input { width: 100%; padding: 0.55rem 0.75rem; border-radius: 0.5rem; border: 1px solid rgba(148, 163, 184, 0.15); background: rgba(15, 23, 42, 0.8); color: #f1f5f9; font-size: 0.85rem; box-sizing: border-box; transition: border-color 0.2s; }
	.form-input:focus { outline: none; border-color: #a855f7; box-shadow: 0 0 0 2px rgba(168, 85, 247, 0.15); }
	.form-input::placeholder { color: #475569; }
	.form-row { display: grid; grid-template-columns: 1fr 1fr; gap: 0.75rem; }
	.target-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 0.35rem; }
	.target-chip { display: flex; align-items: center; gap: 0.35rem; padding: 0.35rem 0.5rem; border: 1px solid rgba(148, 163, 184, 0.15); border-radius: 0.4rem; background: rgba(15, 23, 42, 0.6); cursor: pointer; font-size: 0.75rem; color: #94a3b8; transition: all 0.2s; }
	.target-chip.active { border-color: rgba(168, 85, 247, 0.4); background: rgba(168, 85, 247, 0.1); color: #c4b5fd; }
	.target-chip input[type="checkbox"], .target-chip input[type="radio"] { accent-color: #a855f7; width: 0.8rem; height: 0.8rem; }
	.target-chip:hover:not(.active) { border-color: rgba(148, 163, 184, 0.3); }
	.checkbox-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 0.35rem; margin-bottom: 0.75rem; }
	.button-group { display: flex; gap: 0.5rem; margin-top: 1rem; }
	.btn-primary { flex: 1; background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%); color: white; font-weight: 600; padding: 0.65rem 1.25rem; border: none; border-radius: 0.5rem; cursor: pointer; transition: all 0.2s; display: flex; align-items: center; justify-content: center; gap: 0.4rem; font-size: 0.85rem; }
	.btn-primary:hover:not(:disabled) { box-shadow: 0 4px 12px rgba(168, 85, 247, 0.4); transform: translateY(-1px); }
	.btn-primary:disabled { opacity: 0.5; cursor: not-allowed; }
	.btn-secondary { padding: 0.65rem 0.85rem; border: 1px solid rgba(148, 163, 184, 0.15); border-radius: 0.5rem; background: rgba(15, 23, 42, 0.6); color: #94a3b8; cursor: pointer; transition: all 0.2s; font-size: 0.85rem; }
	.btn-secondary:hover:not(:disabled) { border-color: rgba(239, 68, 68, 0.4); color: #f87171; }
	.spinner { width: 1rem; height: 1rem; border: 2px solid rgba(255,255,255,0.3); border-top-color: white; border-radius: 50%; animation: spin 0.6s linear infinite; display: inline-block; }
	@keyframes spin { to { transform: rotate(360deg); } }
	.error-card { display: flex; align-items: center; gap: 0.75rem; padding: 1rem; background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.2); border-radius: 0.5rem; }
	.error-icon { font-size: 1.5rem; }
	.error-text { color: #fca5a5; font-size: 0.85rem; word-break: break-all; }
	.result-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem; flex-wrap: wrap; gap: 0.5rem; }
	.result-header-actions { display: flex; align-items: center; gap: 0.5rem; }
	.result-score-badge { display: flex; flex-direction: column; align-items: center; padding: 0.5rem 1rem; border-radius: 0.5rem; border: 1px solid rgba(168, 85, 247, 0.3); background: rgba(168, 85, 247, 0.1); }
	.score-value { font-size: 1.5rem; font-weight: 700; color: #a855f7; line-height: 1; }
	.score-label { font-size: 0.65rem; color: #a855f7; opacity: 0.8; margin-top: 0.2rem; }
	.export-group { display: flex; gap: 0.3rem; }
	.export-btn { padding: 0.3rem 0.5rem; border-radius: 0.3rem; border: 1px solid rgba(148, 163, 184, 0.15); background: rgba(15, 23, 42, 0.4); color: #94a3b8; cursor: pointer; font-size: 0.7rem; transition: all 0.2s; }
	.export-btn:hover { border-color: rgba(168, 85, 247, 0.4); color: #c4b5fd; }
	.summary-bar { font-size: 0.8rem; color: #94a3b8; padding: 0.5rem 0.75rem; background: rgba(15, 23, 42, 0.4); border-radius: 0.4rem; margin-bottom: 1rem; border: 1px solid rgba(148, 163, 184, 0.08); display: flex; justify-content: space-between; align-items: center; }
	.duration-badge { font-size: 0.7rem; color: #a855f7; font-weight: 600; }
	.waf-alert { display: flex; align-items: center; gap: 0.75rem; padding: 0.75rem; background: rgba(245, 158, 11, 0.1); border: 1px solid rgba(245, 158, 11, 0.2); border-radius: 0.5rem; margin-bottom: 1rem; }
	.waf-icon { font-size: 1.5rem; }
	.waf-info { display: flex; flex-direction: column; gap: 0.15rem; }
	.waf-title { font-size: 0.85rem; font-weight: 600; color: #fbbf24; }
	.waf-evidence { font-size: 0.7rem; color: #d97706; }
	.ssl-info-bar { display: flex; align-items: center; gap: 0.75rem; padding: 0.6rem 0.75rem; background: rgba(34, 197, 94, 0.08); border: 1px solid rgba(34, 197, 94, 0.15); border-radius: 0.5rem; margin-bottom: 1rem; }
	.ssl-icon { font-size: 1.2rem; }
	.ssl-details { display: flex; flex-direction: column; gap: 0.1rem; min-width: 0; }
	.ssl-subject { font-size: 0.8rem; color: #86efac; font-weight: 500; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
	.ssl-meta { font-size: 0.7rem; color: #94a3b8; display: flex; align-items: center; gap: 0.5rem; }
	.ssl-expired { color: #ef4444; font-weight: 600; font-size: 0.65rem; }
	.security-header-bar { display: flex; align-items: center; gap: 0.75rem; padding: 0.6rem 0.75rem; background: rgba(59, 130, 246, 0.08); border: 1px solid rgba(59, 130, 246, 0.15); border-radius: 0.5rem; margin-bottom: 1rem; }
	.sh-icon { font-size: 1.2rem; }
	.sh-details { display: flex; flex-direction: column; gap: 0.1rem; }
	.sh-grade { font-size: 0.85rem; font-weight: 600; }
	.sh-missing { font-size: 0.7rem; color: #94a3b8; }
	.tech-grid { display: flex; flex-wrap: wrap; gap: 0.4rem; }
	.tech-chip { display: flex; align-items: center; gap: 0.3rem; padding: 0.35rem 0.6rem; background: rgba(168, 85, 247, 0.1); border: 1px solid rgba(168, 85, 247, 0.2); border-radius: 0.4rem; font-size: 0.75rem; color: #c4b5fd; }
	.tech-icon { font-size: 0.8rem; }
	.tech-name { font-size: 0.75rem; }
	.tech-count { font-size: 0.65rem; padding: 0.05rem 0.3rem; background: rgba(168, 85, 247, 0.2); border-radius: 0.2rem; font-weight: 600; }
	.tech-version-mini { font-size: 0.55rem; padding: 0.05rem 0.25rem; background: rgba(34, 197, 94, 0.15); color: #86efac; border-radius: 0.2rem; font-weight: 600; font-family: 'SF Mono', 'Fira Code', monospace; }
	.confidence-mini { font-size: 0.65rem; font-weight: 600; }
	.result-tabs { display: flex; gap: 0.25rem; margin-bottom: 1rem; flex-wrap: wrap; }
	.result-tab { padding: 0.4rem 0.75rem; border-radius: 0.4rem; border: 1px solid rgba(148, 163, 184, 0.15); background: rgba(15, 23, 42, 0.4); color: #94a3b8; cursor: pointer; font-size: 0.8rem; transition: all 0.2s; }
	.result-tab.active { background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%); color: white; border-color: transparent; font-weight: 600; }
	.result-tab:hover:not(.active) { border-color: rgba(168, 85, 247, 0.3); color: #c4b5fd; }
	.overview-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 0.75rem; margin-bottom: 1rem; }
	.overview-stat { display: flex; flex-direction: column; align-items: center; padding: 0.75rem; background: rgba(15, 23, 42, 0.4); border: 1px solid rgba(148, 163, 184, 0.08); border-radius: 0.5rem; }
	.stat-icon { font-size: 1.2rem; margin-bottom: 0.25rem; }
	.stat-value { font-size: 1.25rem; font-weight: 700; color: #f1f5f9; }
	.stat-label { font-size: 0.7rem; color: #94a3b8; margin-top: 0.15rem; }
	.response-info-bar { display: flex; flex-wrap: wrap; gap: 0.5rem; margin-bottom: 1rem; padding: 0.5rem 0.75rem; background: rgba(15, 23, 42, 0.4); border: 1px solid rgba(148, 163, 184, 0.08); border-radius: 0.4rem; }
	.ri-item { display: flex; align-items: center; gap: 0.3rem; font-size: 0.75rem; }
	.ri-label { color: #64748b; font-weight: 500; }
	.ri-value { color: #cbd5e1; font-family: 'SF Mono', 'Fira Code', monospace; }
	.subsection-title { font-size: 0.9rem; font-weight: 600; color: #e2e8f0; margin: 1rem 0 0.5rem; }
	.filter-bar { display: flex; gap: 0.3rem; margin-bottom: 0.75rem; flex-wrap: wrap; }
	.filter-btn { padding: 0.35rem 0.6rem; border-radius: 0.3rem; border: 1px solid rgba(148, 163, 184, 0.15); background: rgba(15, 23, 42, 0.4); color: #94a3b8; cursor: pointer; font-size: 0.75rem; transition: all 0.2s; }
	.filter-btn.active { background: rgba(168, 85, 247, 0.15); border-color: rgba(168, 85, 247, 0.4); color: #c4b5fd; }
	.filter-btn:hover:not(.active) { border-color: rgba(148, 163, 184, 0.3); }
	.search-bar { margin-bottom: 0.75rem; }
	.search-input { width: 100%; padding: 0.45rem 0.75rem; border-radius: 0.4rem; border: 1px solid rgba(148, 163, 184, 0.15); background: rgba(15, 23, 42, 0.6); color: #f1f5f9; font-size: 0.8rem; box-sizing: border-box; }
	.search-input:focus { outline: none; border-color: #a855f7; }
	.search-input::placeholder { color: #475569; }
	.links-table-wrapper { max-height: 500px; overflow-y: auto; border-radius: 0.5rem; border: 1px solid rgba(148, 163, 184, 0.08); }
	.data-table { width: 100%; border-collapse: collapse; font-size: 0.8rem; }
	.data-table th { text-align: left; padding: 0.5rem 0.6rem; background: rgba(15, 23, 42, 0.6); color: #94a3b8; font-weight: 500; font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.05em; border-bottom: 1px solid rgba(148, 163, 184, 0.1); position: sticky; top: 0; z-index: 1; }
	.data-table td { padding: 0.4rem 0.6rem; border-bottom: 1px solid rgba(148, 163, 184, 0.06); color: #cbd5e1; }
	.data-table tr:hover td { background: rgba(168, 85, 247, 0.05); }
	.tech-name-cell { display: flex; align-items: center; gap: 0.3rem; font-weight: 600; color: #f1f5f9; }
	.category-badge { display: inline-flex; align-items: center; gap: 0.25rem; font-size: 0.75rem; color: #94a3b8; }
	.confidence-badge { display: inline-block; padding: 0.15rem 0.4rem; border-radius: 0.25rem; font-size: 0.7rem; font-weight: 600; border: 1px solid; }
	.method-badge { display: inline-block; padding: 0.1rem 0.35rem; border-radius: 0.2rem; font-size: 0.65rem; border: 1px solid; margin-right: 0.2rem; }
	.detail-text { font-size: 0.75rem; color: #64748b; max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; display: block; }
	.text-muted { color: #475569; }
	.category-section { margin-bottom: 1rem; }
	.category-header { display: flex; align-items: center; gap: 0.5rem; padding: 0.5rem 0.75rem; background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(168, 85, 247, 0.15); border-radius: 0.5rem; margin-bottom: 0.5rem; }
	.category-icon { font-size: 1rem; }
	.category-name { font-weight: 600; font-size: 0.9rem; color: #e2e8f0; }
	.category-count { margin-left: auto; font-size: 0.75rem; padding: 0.1rem 0.4rem; background: rgba(168, 85, 247, 0.2); border-radius: 0.25rem; color: #c4b5fd; font-weight: 600; }
	.category-techs { display: flex; flex-direction: column; gap: 0.3rem; }
	.category-tech-item { display: flex; justify-content: space-between; align-items: center; padding: 0.4rem 0.6rem; background: rgba(15, 23, 42, 0.4); border-radius: 0.3rem; border: 1px solid rgba(148, 163, 184, 0.06); }
	.category-tech-item:hover { background: rgba(168, 85, 247, 0.05); }
	.cti-left { display: flex; align-items: center; gap: 0.35rem; }
	.cti-name { font-size: 0.85rem; font-weight: 500; color: #e2e8f0; }
	.cti-right { display: flex; align-items: center; gap: 0.5rem; }
	.method-mini { font-size: 0.7rem; color: #64748b; }
	.security-overview { display: flex; justify-content: center; margin-bottom: 1rem; }
	.grade-display { display: flex; flex-direction: column; align-items: center; padding: 1rem 2rem; border-radius: 0.75rem; border: 1px solid; }
	.grade-letter { font-size: 2.5rem; font-weight: 800; line-height: 1; }
	.grade-score { font-size: 0.8rem; color: #94a3b8; margin-top: 0.3rem; }
	.security-headers-list { display: flex; flex-direction: column; gap: 0.4rem; }
	.sh-item { padding: 0.5rem 0.75rem; background: rgba(15, 23, 42, 0.4); border-radius: 0.4rem; border: 1px solid rgba(148, 163, 184, 0.06); }
	.shi-header { display: flex; align-items: center; gap: 0.4rem; }
	.shi-status { font-size: 0.85rem; }
	.shi-name { font-size: 0.8rem; font-weight: 600; color: #e2e8f0; font-family: 'SF Mono', 'Fira Code', monospace; }
	.shi-severity { font-size: 0.6rem; padding: 0.05rem 0.3rem; border-radius: 0.15rem; font-weight: 600; margin-left: auto; }
	.shi-value { font-size: 0.7rem; color: #94a3b8; margin-top: 0.25rem; padding-left: 1.5rem; font-family: 'SF Mono', 'Fira Code', monospace; word-break: break-all; }
	.shi-recommendation { font-size: 0.7rem; color: #64748b; margin-top: 0.25rem; padding-left: 1.5rem; }
	.ssl-detail-card { background: rgba(15, 23, 42, 0.4); border: 1px solid rgba(148, 163, 184, 0.08); border-radius: 0.5rem; padding: 0.75rem; }
	.ssl-detail-row { display: flex; align-items: baseline; padding: 0.3rem 0; border-bottom: 1px solid rgba(148, 163, 184, 0.04); }
	.ssl-detail-row:last-child { border-bottom: none; }
	.ssl-detail-label { font-size: 0.75rem; color: #64748b; min-width: 80px; font-weight: 500; }
	.ssl-detail-value { font-size: 0.8rem; color: #cbd5e1; font-family: 'SF Mono', 'Fira Code', monospace; word-break: break-all; }
	.waf-detail-card { background: rgba(15, 23, 42, 0.4); border: 1px solid rgba(245, 158, 11, 0.15); border-radius: 0.5rem; padding: 0.75rem; }
	.waf-detail-row { display: flex; align-items: baseline; padding: 0.3rem 0; gap: 0.5rem; }
	.waf-detail-label { font-size: 0.75rem; color: #64748b; min-width: 80px; font-weight: 500; }
	.waf-detail-value { font-size: 0.8rem; color: #fbbf24; font-weight: 500; }
	.waf-evidence-list { display: flex; flex-wrap: wrap; gap: 0.3rem; }
	.waf-evidence-chip { font-size: 0.7rem; padding: 0.15rem 0.4rem; background: rgba(245, 158, 11, 0.1); border: 1px solid rgba(245, 158, 11, 0.2); border-radius: 0.2rem; color: #fbbf24; }
	.empty-mini { font-size: 0.85rem; color: #64748b; text-align: center; padding: 2rem; }
	.empty-state { text-align: center; padding: 3rem 1rem; }
	.empty-icon { font-size: 3rem; margin-bottom: 0.75rem; opacity: 0.5; }
	.empty-text { color: #94a3b8; font-size: 0.95rem; margin: 0 0 0.25rem; }
	.empty-sub { color: #64748b; font-size: 0.8rem; margin: 0; }
</style>
