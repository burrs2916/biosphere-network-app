<script lang="ts">
	import { tr } from '$lib/i18n';
	import ToolHistory from '$lib/components/ToolHistory.svelte';
	import ToolHelp from '$lib/components/ToolHelp.svelte';

	interface DomainAnalysis {
		domain: string; is_ip_based: boolean; is_suspicious_tld: boolean;
		suspicious_tld: string; domain_age_days: number | null; whois_protected: boolean;
		subdomain_count: number; has_dga_pattern: boolean; domain_length: number;
		has_hyphen: boolean; has_numbers: boolean; suspicious_patterns: string[];
	}
	interface SslAnalysis {
		has_ssl: boolean; is_valid: boolean; issuer: string;
		valid_from: string; valid_to: string; is_self_signed: boolean;
		is_free_ca: boolean; days_until_expiry: number; issues: string[];
	}
	interface ContentAnalysis {
		has_login_form: boolean; has_password_field: boolean; external_resources: number;
		suspicious_scripts: number; hidden_iframes: number; brand_impersonation: string[];
		suspicious_keywords: string[]; form_actions: string[]; page_title: string;
		has_mismatched_urls: boolean;
	}
	interface RedirectAnalysis {
		redirect_count: number; redirect_chain: string[]; has_shortener: boolean;
		final_url: string; issues: string[];
	}
	interface ReputationInfo {
		is_blacklisted: boolean; blacklist_sources: string[]; threat_score: number;
		reported_count: number; first_seen: string | null; tags: string[];
		is_new_domain: boolean;
	}
	interface PhishingIndicator {
		category: string; indicator: string; description: string;
		severity: string; confidence: number; mitre_id: string;
	}
	interface PhishingDetectorResult {
		success: boolean; url: string; is_phishing: boolean; phishing_score: number;
		risk_level: string; domain_analysis: DomainAnalysis; ssl_analysis: SslAnalysis;
		content_analysis: ContentAnalysis; redirect_analysis: RedirectAnalysis;
		reputation_info: ReputationInfo; indicators: PhishingIndicator[]; summary: string;
	}

	let url = $state('');
	let checkDomain = $state(true);
	let checkSsl = $state(true);
	let checkContent = $state(true);
	let checkRedirect = $state(true);
	let checkReputation = $state(true);
	let checkHomograph = $state(true);
	let checkTyposquatting = $state(false);
	let compareBrand = $state('');
	let result: PhishingDetectorResult | null = $state(null);
	let error = $state('');
	let processing = $state(false);
	let activeMainTab = $state('analyze');
	let activeResultTab = $state('indicators');
	let exportFormat = $state('json');
	let exporting = $state(false);
	let historyComponent: ToolHistory = $state(null!);

	let scoreColor = $derived.by(() => {
		if (!result) return '#6b7280';
		const s = result.phishing_score;
		if (s >= 0.8) return '#dc2626';
		if (s >= 0.6) return '#ef4444';
		if (s >= 0.4) return '#f59e0b';
		if (s >= 0.2) return '#3b82f6';
		return '#22c55e';
	});

	let scoreLabel = $derived.by(() => {
		if (!result) return '';
		const s = result.phishing_score;
		if (s >= 0.8) return $tr('phishingDetector.riskLevels.critical');
		if (s >= 0.6) return $tr('phishingDetector.riskLevels.high');
		if (s >= 0.4) return $tr('phishingDetector.riskLevels.medium');
		if (s >= 0.2) return $tr('phishingDetector.riskLevels.low');
		return $tr('phishingDetector.riskLevels.info');
	});

	async function detect() {
		if (!url.trim()) { error = $tr('phishingDetector.error.emptyUrl'); return; }
		processing = true; error = ''; result = null; activeResultTab = 'indicators';
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			result = await invoke<PhishingDetectorResult>('detect_phishing_command', {
				config: {
					url: url.trim(),
					check_domain: checkDomain,
					check_ssl: checkSsl,
					check_content: checkContent,
					check_redirect: checkRedirect,
					check_reputation: checkReputation,
					check_homograph: checkHomograph,
					check_typosquatting: checkTyposquatting,
					compare_brand: compareBrand.trim() || '',
					timeout: 15
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
		} finally { processing = false; }
	}

	function clearAll() { url = ''; compareBrand = ''; result = null; error = ''; }
	function getSeverityColor(s: string): string {
		switch (s) { case 'critical': return '#dc2626'; case 'high': return '#ef4444'; case 'medium': return '#f59e0b'; case 'low': return '#3b82f6'; default: return '#6b7280'; }
	}
	function formatSize(bytes: number): string {
		if (bytes < 1024) return bytes + ' B';
		if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
		return (bytes / 1048576).toFixed(1) + ' MB';
	}
	async function copyToClipboard(text: string) {
		try { await navigator.clipboard.writeText(text); } catch {}
	}
	async function exportResult() {
		if (!result) return;
		exporting = true;
		try {
			let content: string;
			let filename: string;
			if (exportFormat === 'csv') {
				const headers = ['Category', 'Indicator', 'Description', 'Severity', 'Confidence', 'MITRE ID'];
				const rows = result.indicators.map(i => [i.category, i.indicator, i.description, i.severity, i.confidence.toFixed(2), i.mitre_id]);
				content = [headers.join(','), ...rows.map(r => r.map(c => `"${c}"`).join(','))].join('\n');
				filename = 'phishing_detection.csv';
			} else {
				content = JSON.stringify(result, null, 2);
				filename = 'phishing_detection.json';
			}
			const blob = new Blob([content], { type: exportFormat === 'csv' ? 'text/csv' : 'application/json' });
			const a = document.createElement('a');
			a.href = URL.createObjectURL(blob);
			a.download = filename;
			a.click();
			URL.revokeObjectURL(a.href);
		} finally { exporting = false; }
	}
</script>

<div class="nd-page">
	<div class="page-header">
		<div class="header-left">
			<a href="/" class="back-link">{$tr('common.backToHome')}</a>
			<h1 class="page-title">🎣 {$tr('phishingDetector.title')}</h1>
			<p class="page-subtitle">{$tr('phishingDetector.subtitle')}</p>
		</div>
	</div>

	<div class="tabs">
		<button class="tab-btn {activeMainTab === 'analyze' ? 'active' : ''}" onclick={() => activeMainTab = 'analyze'}>
			<span class="tab-icon">🔍</span> {$tr('phishingDetector.detect')}
		</button>
		<button class="tab-btn {activeMainTab === 'history' ? 'active' : ''}" onclick={() => activeMainTab = 'history'}>
			<span class="tab-icon">📋</span> {$tr('common.history')}
		</button>
		<button class="tab-btn {activeMainTab === 'help' ? 'active' : ''}" onclick={() => activeMainTab = 'help'}>
			<span class="tab-icon">📖</span> {$tr('common.help')}
		</button>
	</div>

	{#if activeMainTab === 'analyze'}
		<div class="content-grid">
			<div class="input-section">
				<div class="section-card">
					<h2 class="section-title">{$tr('phishingDetector.configTitle')}</h2>
					<p class="section-desc">{$tr('phishingDetector.configDesc')}</p>

					<div class="form-group">
						<label class="form-label" for="pd-url">{$tr('phishingDetector.url')}</label>
						<input id="pd-url" type="text" bind:value={url} placeholder={$tr('phishingDetector.urlPlaceholder')} class="form-input" disabled={processing} />
					</div>

					<div class="form-group">
						<label class="form-label" for="pd-brand">{$tr('phishingDetector.compareBrand')}</label>
						<input id="pd-brand" type="text" bind:value={compareBrand} placeholder={$tr('phishingDetector.compareBrandPlaceholder')} class="form-input" disabled={processing} />
					</div>

					<div class="form-group">
						<label class="form-label">{$tr('phishingDetector.checkOptions')}</label>
						<div class="check-grid">
							<label class="check-chip {checkDomain ? 'active' : ''}">
								<input type="checkbox" bind:checked={checkDomain} disabled={processing} />
								🌐 {$tr('phishingDetector.checkDomain')}
							</label>
							<label class="check-chip {checkSsl ? 'active' : ''}">
								<input type="checkbox" bind:checked={checkSsl} disabled={processing} />
								🔒 {$tr('phishingDetector.checkSsl')}
							</label>
							<label class="check-chip {checkContent ? 'active' : ''}">
								<input type="checkbox" bind:checked={checkContent} disabled={processing} />
								📄 {$tr('phishingDetector.checkContent')}
							</label>
							<label class="check-chip {checkRedirect ? 'active' : ''}">
								<input type="checkbox" bind:checked={checkRedirect} disabled={processing} />
								🔄 {$tr('phishingDetector.checkRedirect')}
							</label>
							<label class="check-chip {checkReputation ? 'active' : ''}">
								<input type="checkbox" bind:checked={checkReputation} disabled={processing} />
								⭐ {$tr('phishingDetector.checkReputation')}
							</label>
							<label class="check-chip {checkHomograph ? 'active' : ''}">
								<input type="checkbox" bind:checked={checkHomograph} disabled={processing} />
								🔤 {$tr('phishingDetector.checkHomograph')}
							</label>
							<label class="check-chip {checkTyposquatting ? 'active' : ''}">
								<input type="checkbox" bind:checked={checkTyposquatting} disabled={processing} />
								✏️ {$tr('phishingDetector.checkTyposquatting')}
							</label>
						</div>
					</div>

					<div class="button-group">
						<button class="btn-primary" onclick={detect} disabled={processing || !url.trim()}>
							{#if processing}⏳ {$tr('phishingDetector.detecting')}{:else}🎣 {$tr('phishingDetector.detect')}{/if}
						</button>
						<button class="btn-secondary" onclick={clearAll} disabled={processing}>🗑️ {$tr('common.clear')}</button>
					</div>
				</div>
			</div>

			<div class="result-section">
				{#if error}
					<div class="section-card">
						<div class="error-banner">
							<span class="error-icon">⚠️</span>
							<span>{error}</span>
						</div>
					</div>
				{:else if result}
					<div class="section-card score-section">
						<div class="score-row">
							<div class="score-circle" style="border-color: {scoreColor}">
								<span class="score-number" style="color: {scoreColor}">{Math.round(result.phishing_score * 100)}</span>
								<span class="score-max">%</span>
							</div>
							<div class="score-details">
								<div class="score-level" style="color: {scoreColor}">{scoreLabel}</div>
								<div class="score-stats">
									<span class="stat-item">⚠️ {$tr('phishingDetector.indicators')}: {result.indicators.length}</span>
									<span class="stat-item">{result.is_phishing ? '🚨' : '✅'} {result.is_phishing ? $tr('phishingDetector.phishingSuspected') : $tr('phishingDetector.relativelySafe')}</span>
								</div>
								<div class="score-total">{result.summary}</div>
							</div>
							<div class="export-group">
								<select bind:value={exportFormat} class="export-select">
									<option value="json">JSON</option>
									<option value="csv">CSV</option>
								</select>
								<button class="btn-export" onclick={exportResult} disabled={exporting}>
									{#if exporting}⏳{:else}📥{/if} {$tr('phishingDetector.export')}
								</button>
							</div>
						</div>
					</div>

					{#if result.indicators.filter(i => i.severity === 'critical' || i.severity === 'high').length > 0}
						<div class="section-card warning-section">
							<h3 class="warning-title">🚨 {$tr('phishingDetector.criticalFindings')}</h3>
							<div class="warning-list">
								{#each result.indicators.filter(i => i.severity === 'critical' || i.severity === 'high') as ind}
									<div class="warning-item" style="border-left-color: {getSeverityColor(ind.severity)}">
										<span class="warning-severity" style="background: {getSeverityColor(ind.severity)}">{ind.severity.toUpperCase()}</span>
										<span class="warning-text">{ind.category}: {ind.indicator}</span>
									</div>
								{/each}
							</div>
						</div>
					{/if}

					<div class="section-card">
						<div class="result-tabs">
							<button class="result-tab {activeResultTab === 'indicators' ? 'active' : ''}" onclick={() => activeResultTab = 'indicators'}>
								⚠️ {$tr('phishingDetector.tabs.indicators')} ({result.indicators.length})
							</button>
							<button class="result-tab {activeResultTab === 'domain' ? 'active' : ''}" onclick={() => activeResultTab = 'domain'}>
								🌐 {$tr('phishingDetector.tabs.domain')}
							</button>
							<button class="result-tab {activeResultTab === 'ssl' ? 'active' : ''}" onclick={() => activeResultTab = 'ssl'}>
								🔒 {$tr('phishingDetector.tabs.ssl')}
							</button>
							<button class="result-tab {activeResultTab === 'content' ? 'active' : ''}" onclick={() => activeResultTab = 'content'}>
								📄 {$tr('phishingDetector.tabs.content')}
							</button>
							<button class="result-tab {activeResultTab === 'redirect' ? 'active' : ''}" onclick={() => activeResultTab = 'redirect'}>
								🔄 {$tr('phishingDetector.tabs.redirect')}
							</button>
							<button class="result-tab {activeResultTab === 'reputation' ? 'active' : ''}" onclick={() => activeResultTab = 'reputation'}>
								⭐ {$tr('phishingDetector.tabs.reputation')}
							</button>
						</div>

						{#if activeResultTab === 'indicators'}
							{#if result.indicators.length === 0}
								<div class="empty-tab">✅ {$tr('phishingDetector.noIndicators')}</div>
							{:else}
								<div class="items-list">
									{#each result.indicators as ind}
										<div class="item-card" style="border-left-color: {getSeverityColor(ind.severity)}">
											<div class="item-header">
												<span class="severity-badge" style="background: {getSeverityColor(ind.severity)}">{ind.severity.toUpperCase()}</span>
												<span class="item-title">{ind.category}: {ind.indicator}</span>
												{#if ind.mitre_id}
													<span class="mitre-tag">{ind.mitre_id}</span>
												{/if}
											</div>
											<p class="item-desc">{ind.description}</p>
											<div class="item-footer">
												<span class="confidence-bar">
													<span class="confidence-fill" style="width: {ind.confidence * 100}%; background: {getSeverityColor(ind.severity)}"></span>
												</span>
												<span class="confidence-text">{(ind.confidence * 100).toFixed(0)}%</span>
											</div>
										</div>
									{/each}
								</div>
							{/if}

						{:else if activeResultTab === 'domain'}
							<div class="info-grid">
								<div class="info-row">
									<span class="info-label">{$tr('phishingDetector.domain.domain')}</span>
									<span class="info-value mono">{result.domain_analysis.domain}</span>
								</div>
								<div class="info-row">
									<span class="info-label">{$tr('phishingDetector.domain.isIpBased')}</span>
									<span class="info-value" style="color: {result.domain_analysis.is_ip_based ? '#ef4444' : '#22c55e'}">{result.domain_analysis.is_ip_based ? '⚠️ ' + $tr('common.yes') : '✅ ' + $tr('common.no')}</span>
								</div>
								<div class="info-row">
									<span class="info-label">{$tr('phishingDetector.domain.isSuspiciousTld')}</span>
									<span class="info-value" style="color: {result.domain_analysis.is_suspicious_tld ? '#f59e0b' : '#22c55e'}">{result.domain_analysis.is_suspicious_tld ? '⚠️ ' + result.domain_analysis.suspicious_tld : '✅ ' + $tr('common.no')}</span>
								</div>
								<div class="info-row">
									<span class="info-label">{$tr('phishingDetector.domain.subdomainCount')}</span>
									<span class="info-value">{result.domain_analysis.subdomain_count}</span>
								</div>
								<div class="info-row">
									<span class="info-label">{$tr('phishingDetector.domain.domainLength')}</span>
									<span class="info-value">{result.domain_analysis.domain_length}</span>
								</div>
								<div class="info-row">
									<span class="info-label">{$tr('phishingDetector.domain.hasHyphen')}</span>
									<span class="info-value">{result.domain_analysis.has_hyphen ? $tr('common.yes') : $tr('common.no')}</span>
								</div>
								<div class="info-row">
									<span class="info-label">{$tr('phishingDetector.domain.hasNumbers')}</span>
									<span class="info-value">{result.domain_analysis.has_numbers ? $tr('common.yes') : $tr('common.no')}</span>
								</div>
								<div class="info-row">
									<span class="info-label">{$tr('phishingDetector.domain.hasDgaPattern')}</span>
									<span class="info-value" style="color: {result.domain_analysis.has_dga_pattern ? '#ef4444' : '#22c55e'}">{result.domain_analysis.has_dga_pattern ? '⚠️ ' + $tr('common.yes') : '✅ ' + $tr('common.no')}</span>
								</div>
								{#if result.domain_analysis.domain_age_days !== null}
									<div class="info-row">
										<span class="info-label">{$tr('phishingDetector.domain.domainAge')}</span>
										<span class="info-value">{result.domain_analysis.domain_age_days} {$tr('phishingDetector.domain.days')}</span>
									</div>
								{/if}
								{#if result.domain_analysis.suspicious_patterns.length > 0}
									<div class="info-row full-width">
										<span class="info-label">{$tr('phishingDetector.domain.suspiciousPatterns')}</span>
										<div class="tag-list">
											{#each result.domain_analysis.suspicious_patterns as p}
												<span class="tag warning">{p}</span>
											{/each}
										</div>
									</div>
								{/if}
							</div>

						{:else if activeResultTab === 'ssl'}
							<div class="info-grid">
								<div class="info-row">
									<span class="info-label">{$tr('phishingDetector.ssl.hasSsl')}</span>
									<span class="info-value" style="color: {result.ssl_analysis.has_ssl ? '#22c55e' : '#ef4444'}">{result.ssl_analysis.has_ssl ? '✅ HTTPS' : '❌ HTTP'}</span>
								</div>
								<div class="info-row">
									<span class="info-label">{$tr('phishingDetector.ssl.isValid')}</span>
									<span class="info-value" style="color: {result.ssl_analysis.is_valid ? '#22c55e' : '#ef4444'}">{result.ssl_analysis.is_valid ? '✅ ' + $tr('common.yes') : '❌ ' + $tr('common.no')}</span>
								</div>
								<div class="info-row">
									<span class="info-label">{$tr('phishingDetector.ssl.issuer')}</span>
									<span class="info-value">{result.ssl_analysis.issuer || '-'}</span>
								</div>
								<div class="info-row">
									<span class="info-label">{$tr('phishingDetector.ssl.isSelfSigned')}</span>
									<span class="info-value" style="color: {result.ssl_analysis.is_self_signed ? '#f59e0b' : '#22c55e'}">{result.ssl_analysis.is_self_signed ? '⚠️ ' + $tr('common.yes') : $tr('common.no')}</span>
								</div>
								<div class="info-row">
									<span class="info-label">{$tr('phishingDetector.ssl.isFreeCa')}</span>
									<span class="info-value">{result.ssl_analysis.is_free_ca ? $tr('common.yes') : $tr('common.no')}</span>
								</div>
								<div class="info-row">
									<span class="info-label">{$tr('phishingDetector.ssl.daysUntilExpiry')}</span>
									<span class="info-value">{result.ssl_analysis.days_until_expiry} {$tr('phishingDetector.domain.days')}</span>
								</div>
								{#if result.ssl_analysis.issues.length > 0}
									<div class="info-row full-width">
										<span class="info-label">{$tr('phishingDetector.ssl.issues')}</span>
										<div class="tag-list">
											{#each result.ssl_analysis.issues as issue}
												<span class="tag warning">{issue}</span>
											{/each}
										</div>
									</div>
								{/if}
							</div>

						{:else if activeResultTab === 'content'}
							<div class="info-grid">
								<div class="info-row">
									<span class="info-label">{$tr('phishingDetector.content.hasLoginForm')}</span>
									<span class="info-value" style="color: {result.content_analysis.has_login_form ? '#f59e0b' : '#22c55e'}">{result.content_analysis.has_login_form ? '⚠️ ' + $tr('common.yes') : '✅ ' + $tr('common.no')}</span>
								</div>
								<div class="info-row">
									<span class="info-label">{$tr('phishingDetector.content.hasPasswordField')}</span>
									<span class="info-value" style="color: {result.content_analysis.has_password_field ? '#f59e0b' : '#22c55e'}">{result.content_analysis.has_password_field ? '⚠️ ' + $tr('common.yes') : '✅ ' + $tr('common.no')}</span>
								</div>
								<div class="info-row">
									<span class="info-label">{$tr('phishingDetector.content.hasMismatchedUrls')}</span>
									<span class="info-value" style="color: {result.content_analysis.has_mismatched_urls ? '#ef4444' : '#22c55e'}">{result.content_analysis.has_mismatched_urls ? '🚨 ' + $tr('common.yes') : '✅ ' + $tr('common.no')}</span>
								</div>
								{#if result.content_analysis.brand_impersonation.length > 0}
									<div class="info-row full-width">
										<span class="info-label">{$tr('phishingDetector.content.brandImpersonation')}</span>
										<div class="tag-list">
											{#each result.content_analysis.brand_impersonation as b}
												<span class="tag danger">{b}</span>
											{/each}
										</div>
									</div>
								{/if}
								{#if result.content_analysis.suspicious_keywords.length > 0}
									<div class="info-row full-width">
										<span class="info-label">{$tr('phishingDetector.content.suspiciousKeywords')}</span>
										<div class="tag-list">
											{#each result.content_analysis.suspicious_keywords as k}
												<span class="tag warning">{k}</span>
											{/each}
										</div>
									</div>
								{/if}
							</div>

						{:else if activeResultTab === 'redirect'}
							<div class="info-grid">
								<div class="info-row">
									<span class="info-label">{$tr('phishingDetector.redirect.hasShortener')}</span>
									<span class="info-value" style="color: {result.redirect_analysis.has_shortener ? '#f59e0b' : '#22c55e'}">{result.redirect_analysis.has_shortener ? '⚠️ ' + $tr('common.yes') : '✅ ' + $tr('common.no')}</span>
								</div>
								<div class="info-row">
									<span class="info-label">{$tr('phishingDetector.redirect.redirectCount')}</span>
									<span class="info-value">{result.redirect_analysis.redirect_count}</span>
								</div>
								<div class="info-row">
									<span class="info-label">{$tr('phishingDetector.redirect.finalUrl')}</span>
									<span class="info-value mono">{result.redirect_analysis.final_url}</span>
								</div>
								{#if result.redirect_analysis.redirect_chain.length > 0}
									<div class="info-row full-width">
										<span class="info-label">{$tr('phishingDetector.redirect.chain')}</span>
										<div class="chain-list">
											{#each result.redirect_analysis.redirect_chain as step, i}
												<div class="chain-step">
													<span class="chain-num">{i + 1}</span>
													<span class="chain-url">{step}</span>
												</div>
											{/each}
										</div>
									</div>
								{/if}
								{#if result.redirect_analysis.issues.length > 0}
									<div class="info-row full-width">
										<span class="info-label">{$tr('phishingDetector.redirect.issues')}</span>
										<div class="tag-list">
											{#each result.redirect_analysis.issues as issue}
												<span class="tag warning">{issue}</span>
											{/each}
										</div>
									</div>
								{/if}
							</div>

						{:else if activeResultTab === 'reputation'}
							<div class="info-grid">
								<div class="info-row">
									<span class="info-label">{$tr('phishingDetector.reputation.isBlacklisted')}</span>
									<span class="info-value" style="color: {result.reputation_info.is_blacklisted ? '#ef4444' : '#22c55e'}">{result.reputation_info.is_blacklisted ? '🚨 ' + $tr('common.yes') : '✅ ' + $tr('common.no')}</span>
								</div>
								<div class="info-row">
									<span class="info-label">{$tr('phishingDetector.reputation.threatScore')}</span>
									<span class="info-value" style="color: {result.reputation_info.threat_score > 50 ? '#ef4444' : result.reputation_info.threat_score > 25 ? '#f59e0b' : '#22c55e'}">{result.reputation_info.threat_score.toFixed(1)}</span>
								</div>
								<div class="info-row">
									<span class="info-label">{$tr('phishingDetector.reputation.isNewDomain')}</span>
									<span class="info-value" style="color: {result.reputation_info.is_new_domain ? '#f59e0b' : '#22c55e'}">{result.reputation_info.is_new_domain ? '⚠️ ' + $tr('common.yes') : '✅ ' + $tr('common.no')}</span>
								</div>
								{#if result.reputation_info.blacklist_sources.length > 0}
									<div class="info-row full-width">
										<span class="info-label">{$tr('phishingDetector.reputation.blacklistSources')}</span>
										<div class="tag-list">
											{#each result.reputation_info.blacklist_sources as s}
												<span class="tag danger">{s}</span>
											{/each}
										</div>
									</div>
								{/if}
								{#if result.reputation_info.tags.length > 0}
									<div class="info-row full-width">
										<span class="info-label">{$tr('phishingDetector.reputation.tags')}</span>
										<div class="tag-list">
											{#each result.reputation_info.tags as t}
												<span class="tag">{t}</span>
											{/each}
										</div>
									</div>
								{/if}
							</div>
						{/if}
					</div>
				{:else}
					<div class="section-card">
						<div class="empty-state">
							<div class="empty-icon">🎣</div>
							<p>{$tr('phishingDetector.noResults')}</p>
						</div>
					</div>
				{/if}
			</div>
		</div>
	{:else if activeMainTab === 'history'}
		<div class="section-card">
			<ToolHistory toolType="phishing_detector" toolName={$tr('phishingDetector.title')} bind:this={historyComponent} />
		</div>
	{:else if activeMainTab === 'help'}
		<div class="section-card">
			<ToolHelp toolType="phishing_detector" />
		</div>
	{/if}
</div>

<style>
	.nd-page { padding: 20px; max-width: 1400px; margin: 0 auto; min-height: 100vh; }
	.page-header { margin-bottom: 20px; }
	.header-left { display: flex; flex-direction: column; gap: 4px; }
	.back-link { color: #94a3b8; text-decoration: none; font-size: 0.85rem; transition: color 0.2s; }
	.back-link:hover { color: #a855f7; }
	.page-title { font-size: 1.5rem; margin: 8px 0 4px; color: #f1f5f9; font-weight: 700; }
	.page-subtitle { color: #94a3b8; font-size: 0.9rem; margin: 0; }

	.tabs { display: flex; gap: 4px; margin-bottom: 16px; background: rgba(15, 23, 42, 0.6); border-radius: 12px; padding: 4px; border: 1px solid rgba(168, 85, 247, 0.1); }
	.tab-btn { flex: 1; padding: 10px 16px; border: none; border-radius: 8px; background: transparent; cursor: pointer; font-size: 0.9rem; color: #94a3b8; transition: all 0.2s; display: flex; align-items: center; justify-content: center; gap: 6px; }
	.tab-btn:hover { color: #e2e8f0; background: rgba(168, 85, 247, 0.1); }
	.tab-btn.active { background: linear-gradient(135deg, #a855f7, #7c3aed); color: white; box-shadow: 0 2px 8px rgba(168, 85, 247, 0.3); }
	.tab-icon { font-size: 1rem; }

	.content-grid { display: grid; grid-template-columns: 380px 1fr; gap: 20px; }
	@media (max-width: 900px) { .content-grid { grid-template-columns: 1fr; } }

	.section-card { background: rgba(15, 23, 42, 0.6); border-radius: 12px; padding: 20px; border: 1px solid rgba(148, 163, 184, 0.1); }
	.section-title { font-size: 1.1rem; margin: 0 0 4px; color: #f1f5f9; font-weight: 600; }
	.section-desc { font-size: 0.8rem; color: #64748b; margin: 0 0 16px; }

	.form-group { margin-bottom: 14px; }
	.form-label { display: block; font-size: 0.85rem; color: #94a3b8; margin-bottom: 6px; font-weight: 500; }
	.form-input { width: 100%; padding: 10px 12px; border-radius: 8px; border: 1px solid rgba(148, 163, 184, 0.2); background: rgba(15, 23, 42, 0.8); color: #f1f5f9; font-size: 0.9rem; box-sizing: border-box; transition: border-color 0.2s; }
	.form-input:focus { outline: none; border-color: #a855f7; }
	.form-input:disabled { opacity: 0.5; cursor: not-allowed; }
	.form-input::placeholder { color: #475569; }

	.check-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 6px; }
	.check-chip { display: flex; align-items: center; gap: 6px; padding: 8px 10px; border-radius: 8px; border: 1px solid rgba(148, 163, 184, 0.15); background: rgba(15, 23, 42, 0.5); cursor: pointer; font-size: 0.8rem; color: #94a3b8; transition: all 0.2s; }
	.check-chip:hover { border-color: rgba(168, 85, 247, 0.3); color: #e2e8f0; }
	.check-chip.active { border-color: rgba(168, 85, 247, 0.5); background: rgba(168, 85, 247, 0.1); color: #e2e8f0; }
	.check-chip input { display: none; }

	.button-group { display: flex; gap: 8px; margin-top: 16px; }
	.btn-primary { padding: 10px 20px; border-radius: 8px; border: none; background: linear-gradient(135deg, #a855f7, #7c3aed); color: white; cursor: pointer; font-size: 0.9rem; font-weight: 600; transition: all 0.2s; flex: 1; }
	.btn-primary:hover:not(:disabled) { box-shadow: 0 4px 12px rgba(168, 85, 247, 0.4); transform: translateY(-1px); }
	.btn-primary:disabled { opacity: 0.5; cursor: not-allowed; }
	.btn-secondary { padding: 10px 16px; border-radius: 8px; border: 1px solid rgba(148, 163, 184, 0.2); background: rgba(15, 23, 42, 0.5); color: #94a3b8; cursor: pointer; font-size: 0.9rem; transition: all 0.2s; }
	.btn-secondary:hover:not(:disabled) { border-color: rgba(148, 163, 184, 0.4); color: #e2e8f0; }
	.btn-secondary:disabled { opacity: 0.5; cursor: not-allowed; }

	.error-banner { display: flex; align-items: center; gap: 12px; padding: 14px; background: rgba(239, 68, 68, 0.1); border-radius: 8px; border: 1px solid rgba(239, 68, 68, 0.2); color: #fca5a5; }
	.error-icon { font-size: 1.3rem; }

	.score-section { margin-bottom: 12px; }
	.score-row { display: flex; align-items: center; gap: 16px; flex-wrap: wrap; }
	.score-circle { width: 80px; height: 80px; border-radius: 50%; border: 4px solid; display: flex; align-items: center; justify-content: center; flex-shrink: 0; }
	.score-number { font-size: 1.5rem; font-weight: 700; }
	.score-max { font-size: 0.8rem; color: #94a3b8; }
	.score-details { flex: 1; min-width: 200px; }
	.score-level { font-size: 1.1rem; font-weight: 700; margin-bottom: 4px; }
	.score-stats { display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 4px; }
	.stat-item { font-size: 0.8rem; color: #94a3b8; }
	.score-total { font-size: 0.75rem; color: #64748b; font-family: monospace; word-break: break-all; }
	.export-group { display: flex; gap: 4px; align-items: center; }
	.export-select { padding: 6px 8px; border-radius: 6px; border: 1px solid rgba(148, 163, 184, 0.2); background: rgba(15, 23, 42, 0.8); color: #94a3b8; font-size: 0.8rem; }
	.btn-export { padding: 6px 12px; border-radius: 6px; border: 1px solid rgba(168, 85, 247, 0.3); background: rgba(168, 85, 247, 0.1); color: #c4b5fd; cursor: pointer; font-size: 0.8rem; transition: all 0.2s; }
	.btn-export:hover:not(:disabled) { background: rgba(168, 85, 247, 0.2); }
	.btn-export:disabled { opacity: 0.5; cursor: not-allowed; }

	.warning-section { margin-bottom: 12px; border-color: rgba(239, 68, 68, 0.2); }
	.warning-title { font-size: 0.95rem; color: #fca5a5; margin: 0 0 10px; }
	.warning-list { display: flex; flex-direction: column; gap: 6px; }
	.warning-item { display: flex; align-items: center; gap: 8px; padding: 8px 12px; background: rgba(15, 23, 42, 0.5); border-radius: 6px; border-left: 3px solid; font-size: 0.85rem; }
	.warning-severity { padding: 2px 6px; border-radius: 4px; color: white; font-size: 0.65rem; font-weight: 700; }
	.warning-text { color: #e2e8f0; }

	.result-tabs { display: flex; gap: 4px; margin-bottom: 16px; flex-wrap: wrap; }
	.result-tab { padding: 7px 14px; border: 1px solid rgba(148, 163, 184, 0.15); border-radius: 8px; background: transparent; color: #94a3b8; cursor: pointer; font-size: 0.8rem; transition: all 0.2s; }
	.result-tab:hover { color: #e2e8f0; border-color: rgba(148, 163, 184, 0.3); }
	.result-tab.active { background: rgba(168, 85, 247, 0.15); color: #c4b5fd; border-color: rgba(168, 85, 247, 0.4); }

	.items-list { display: flex; flex-direction: column; gap: 8px; }
	.item-card { padding: 12px; background: rgba(15, 23, 42, 0.5); border-radius: 8px; border-left: 3px solid; }
	.item-header { display: flex; align-items: center; gap: 8px; margin-bottom: 6px; flex-wrap: wrap; }
	.severity-badge { padding: 2px 8px; border-radius: 4px; color: white; font-size: 0.65rem; font-weight: 700; }
	.item-title { font-weight: 600; font-size: 0.9rem; color: #e2e8f0; }
	.mitre-tag { padding: 2px 6px; border-radius: 4px; background: rgba(59, 130, 246, 0.2); color: #93c5fd; font-size: 0.7rem; font-family: monospace; }
	.item-desc { font-size: 0.85rem; color: #94a3b8; margin: 0 0 8px; }
	.item-footer { display: flex; align-items: center; gap: 8px; }
	.confidence-bar { flex: 1; height: 4px; background: rgba(148, 163, 184, 0.15); border-radius: 2px; overflow: hidden; }
	.confidence-fill { display: block; height: 100%; border-radius: 2px; transition: width 0.3s; }
	.confidence-text { font-size: 0.75rem; color: #64748b; min-width: 32px; }

	.info-grid { display: flex; flex-direction: column; gap: 8px; }
	.info-row { display: flex; gap: 12px; padding: 10px 12px; background: rgba(15, 23, 42, 0.5); border-radius: 8px; align-items: flex-start; }
	.info-row.full-width { flex-direction: column; gap: 6px; }
	.info-label { font-weight: 600; font-size: 0.85rem; color: #94a3b8; min-width: 120px; flex-shrink: 0; }
	.info-value { font-size: 0.85rem; color: #e2e8f0; }
	.info-value.mono { font-family: monospace; word-break: break-all; }

	.tag-list { display: flex; flex-wrap: wrap; gap: 6px; }
	.tag { padding: 3px 10px; border-radius: 6px; font-size: 0.75rem; background: rgba(148, 163, 184, 0.1); color: #94a3b8; border: 1px solid rgba(148, 163, 184, 0.15); }
	.tag.warning { background: rgba(245, 158, 11, 0.1); color: #fbbf24; border-color: rgba(245, 158, 11, 0.2); }
	.tag.danger { background: rgba(239, 68, 68, 0.1); color: #fca5a5; border-color: rgba(239, 68, 68, 0.2); }

	.chain-list { display: flex; flex-direction: column; gap: 4px; }
	.chain-step { display: flex; align-items: center; gap: 8px; padding: 6px 10px; background: rgba(15, 23, 42, 0.5); border-radius: 6px; }
	.chain-num { width: 22px; height: 22px; border-radius: 50%; background: rgba(168, 85, 247, 0.2); color: #c4b5fd; display: flex; align-items: center; justify-content: center; font-size: 0.7rem; font-weight: 700; flex-shrink: 0; }
	.chain-url { font-family: monospace; font-size: 0.8rem; color: #94a3b8; word-break: break-all; }

	.empty-tab { text-align: center; padding: 30px; color: #64748b; font-size: 0.9rem; }
	.empty-state { text-align: center; padding: 50px 20px; color: #64748b; }
	.empty-icon { font-size: 3rem; margin-bottom: 12px; }
</style>
