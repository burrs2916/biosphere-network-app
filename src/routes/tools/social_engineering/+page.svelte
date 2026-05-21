<script lang="ts">
	import { tr } from '$lib/i18n';
	import ToolHistory from '$lib/components/ToolHistory.svelte';
	import ToolHelp from '$lib/components/ToolHelp.svelte';

	interface TyposquattedDomain {
		domain: string;
		technique: string;
		is_registered: boolean;
		similarity_score: number;
		risk_level: string;
	}

	interface TyposquattingResult {
		original_domain: string;
		typosquatted_domains: TyposquattedDomain[];
		risk_level: string;
	}

	interface BrandImpersonation {
		brand: string;
		impersonation_type: string;
		indicators: string[];
		confidence: number;
		risk_level: string;
	}

	interface EmailPhishingIndicator {
		indicator_type: string;
		description: string;
		value: string;
		risk_level: string;
		recommendation: string;
	}

	interface SocialEngineeringFinding {
		severity: string;
		category: string;
		description: string;
		recommendation: string;
		mitre_technique: string | null;
	}

	interface SocialEngineeringResult {
		success: boolean;
		analysis_type: string;
		typosquatting: TyposquattingResult | null;
		brand_impersonations: BrandImpersonation[];
		email_indicators: EmailPhishingIndicator[];
		security_findings: SocialEngineeringFinding[];
		summary: string;
	}

	let targetUrl = $state('');
	let emailContent = $state('');
	let domain = $state('');
	let analysisType = $state('comprehensive');
	let checkTyposquatting = $state(true);
	let checkHomograph = $state(true);
	let checkBrandImpersonation = $state(true);
	let result: SocialEngineeringResult | null = $state(null);
	let error = $state('');
	let processing = $state(false);
	let activeMainTab = $state('analyze');
	let activeResultTab = $state('overview');

	let historyComponent: ToolHistory = $state(null as any);

	let highFindingCount = $derived(
		(result as SocialEngineeringResult | null)?.security_findings.filter((f: SocialEngineeringFinding) => f.severity === 'critical' || f.severity === 'high').length ?? 0
	);

	let typoCount = $derived(
		(result as SocialEngineeringResult | null)?.typosquatting?.typosquatted_domains.length ?? 0
	);

	let brandCount = $derived(
		(result as SocialEngineeringResult | null)?.brand_impersonations.length ?? 0
	);

	let indicatorCount = $derived(
		(result as SocialEngineeringResult | null)?.email_indicators.length ?? 0
	);

	function translateSeverity(sev: string): string {
		const key = `socialEngineering.severity.${sev}`;
		const val = $tr(key);
		return val === key ? sev : val;
	}

	function translateCategory(cat: string): string {
		const key = `socialEngineering.category.${cat}`;
		const val = $tr(key);
		return val === key ? cat : val;
	}

	function translateTechnique(tech: string): string {
		const key = `socialEngineering.technique.${tech}`;
		const val = $tr(key);
		return val === key ? tech : val;
	}

	function translateIndicatorType(t: string): string {
		const key = `socialEngineering.indicatorType.${t}`;
		const val = $tr(key);
		return val === key ? t : val;
	}

	async function analyze() {
		if (!targetUrl.trim() && !emailContent.trim() && !domain.trim()) {
			error = $tr('socialEngineering.error.noTarget');
			return;
		}
		processing = true;
		error = '';
		result = null;
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			result = await invoke<SocialEngineeringResult>('analyze_social_engineering_command', {
				config: {
					target_url: targetUrl.trim() || null,
					email_content: emailContent.trim() || null,
					domain: domain.trim() || null,
					analysis_type: analysisType,
					check_typosquatting: checkTyposquatting,
					check_homograph: checkHomograph,
					check_brand_impersonation: checkBrandImpersonation,
				}
			});
			if (result && historyComponent) {
				const inputSummary = domain.trim() || targetUrl.trim() || $tr('socialEngineering.emailContent');
				await historyComponent.saveHistory(inputSummary, JSON.stringify(result), result.summary, 'completed');
			}
		} catch (e: any) {
			error = e.toString();
			if (historyComponent) {
				await historyComponent.saveHistory($tr('socialEngineering.title'), '', error, 'failed');
			}
		} finally {
			processing = false;
		}
	}

	function clearAll() {
		targetUrl = '';
		emailContent = '';
		domain = '';
		analysisType = 'comprehensive';
		checkTyposquatting = true;
		checkHomograph = true;
		checkBrandImpersonation = true;
		result = null;
		error = '';
	}

	function getSeverityColor(severity: string): string {
		switch (severity) {
			case 'critical': return '#fca5a5';
			case 'high': return '#fdba74';
			case 'medium': return '#fbbf24';
			case 'low': return '#86efac';
			default: return '#94a3b8';
		}
	}

	function getSeverityBorder(severity: string): string {
		switch (severity) {
			case 'critical': return 'rgba(239, 68, 68, 0.5)';
			case 'high': return 'rgba(249, 115, 22, 0.5)';
			case 'medium': return 'rgba(245, 158, 11, 0.5)';
			case 'low': return 'rgba(34, 197, 94, 0.5)';
			default: return 'rgba(148, 163, 184, 0.3)';
		}
	}

	function getSeverityBg(severity: string): string {
		switch (severity) {
			case 'critical': return 'rgba(239, 68, 68, 0.1)';
			case 'high': return 'rgba(249, 115, 22, 0.1)';
			case 'medium': return 'rgba(245, 158, 11, 0.1)';
			case 'low': return 'rgba(34, 197, 94, 0.1)';
			default: return 'rgba(148, 163, 184, 0.1)';
		}
	}
</script>

<div class="nd-page">
	<div class="page-header">
		<div class="header-left">
			<a href="/" class="back-link">{$tr('common.backToHome')}</a>
			<h1 class="page-title">🎭 {$tr('socialEngineering.title')}</h1>
			<p class="page-subtitle">{$tr('socialEngineering.subtitle')}</p>
		</div>
	</div>

	<div class="tabs">
		<button class="tab-btn {activeMainTab === 'analyze' ? 'active' : ''}" onclick={() => activeMainTab = 'analyze'}>
			<span class="tab-icon">🔍</span> {$tr('socialEngineering.analyze')}
		</button>
		<button class="tab-btn {activeMainTab === 'history' ? 'active' : ''}" onclick={() => activeMainTab = 'history'}>
			<span class="tab-icon">📋</span> {$tr('socialEngineering.history')}
		</button>
		<button class="tab-btn {activeMainTab === 'help' ? 'active' : ''}" onclick={() => activeMainTab = 'help'}>
			<span class="tab-icon">📖</span> {$tr('socialEngineering.help')}
		</button>
	</div>

	{#if activeMainTab === 'analyze'}
		<div class="content-grid">
			<div class="input-section">
				<div class="section-card">
					<h2 class="section-title">{$tr('socialEngineering.config.title')}</h2>
					<p class="section-desc">{$tr('socialEngineering.config.desc')}</p>

					<div class="form-group">
						<label class="form-label">{$tr('socialEngineering.targetUrl')}</label>
						<input type="text" bind:value={targetUrl} placeholder="https://suspicious-site.com" class="form-input" disabled={processing} />
					</div>

					<div class="form-group">
						<label class="form-label">{$tr('socialEngineering.domain')}</label>
						<input type="text" bind:value={domain} placeholder="example.com" class="form-input" disabled={processing} />
					</div>

					<div class="form-group">
						<label class="form-label">{$tr('socialEngineering.emailContent')}</label>
						<textarea bind:value={emailContent} placeholder={$tr('socialEngineering.emailPlaceholder')} rows="4" class="form-input form-textarea" disabled={processing}></textarea>
					</div>

					<div class="form-group">
						<label class="form-label">{$tr('socialEngineering.analysisType')}</label>
						<select bind:value={analysisType} class="form-input" disabled={processing}>
							<option value="comprehensive">{$tr('socialEngineering.comprehensive')}</option>
							<option value="domain">{$tr('socialEngineering.domainAnalysis')}</option>
							<option value="email">{$tr('socialEngineering.emailAnalysis')}</option>
							<option value="url">{$tr('socialEngineering.urlAnalysis')}</option>
						</select>
					</div>

					<div class="checkbox-group">
						<label class="checkbox-label">
							<input type="checkbox" bind:checked={checkTyposquatting} />
							<span>{$tr('socialEngineering.checkTyposquatting')}</span>
						</label>
						<label class="checkbox-label">
							<input type="checkbox" bind:checked={checkHomograph} />
							<span>{$tr('socialEngineering.checkHomograph')}</span>
						</label>
						<label class="checkbox-label">
							<input type="checkbox" bind:checked={checkBrandImpersonation} />
							<span>{$tr('socialEngineering.checkBrandImpersonation')}</span>
						</label>
					</div>

					<div class="button-group">
						<button class="btn-primary" onclick={analyze} disabled={processing || (!targetUrl.trim() && !emailContent.trim() && !domain.trim())}>
							{#if processing}<span class="spinner"></span> {$tr('socialEngineering.analyzing')}{:else}🔍 {$tr('socialEngineering.analyze')}{/if}
						</button>
						<button class="btn-secondary" onclick={clearAll} disabled={processing}>🗑️</button>
					</div>
				</div>
			</div>

			<div class="result-section">
				<div class="section-card">
					<h2 class="section-title">{$tr('socialEngineering.result.title')}</h2>

					{#if error}
						<div class="error-card">
							<div class="error-icon">⚠️</div>
							<div class="error-text">{error}</div>
						</div>
					{:else if result}
						<div class="summary-banner">
							<div class="summary-info">
								<span class="domain-badge">{$tr('socialEngineering.title')}</span>
								<span class="query-text">{domain || targetUrl || $tr('socialEngineering.emailContent')}</span>
								<span class="status-badge {result.success ? 'success' : 'failed'}">{result.success ? $tr('socialEngineering.result.success') : $tr('socialEngineering.result.failed')}</span>
							</div>
							<div class="summary-badges">
								<span class="summary-badge purple">{typoCount} {$tr('socialEngineering.result.typosquatting')}</span>
								<span class="summary-badge red">{brandCount} {$tr('socialEngineering.result.brandImpersonations')}</span>
								{#if highFindingCount > 0}
									<span class="summary-badge orange">{highFindingCount} {$tr('socialEngineering.result.highFindings')}</span>
								{/if}
							</div>
						</div>

						<div class="stats-grid">
							<div class="stat-card">
								<div class="stat-value orange">{typoCount}</div>
								<div class="stat-label">{$tr('socialEngineering.result.typosquatting')}</div>
							</div>
							<div class="stat-card">
								<div class="stat-value red">{brandCount}</div>
								<div class="stat-label">{$tr('socialEngineering.result.brandImpersonations')}</div>
							</div>
							<div class="stat-card">
								<div class="stat-value yellow">{indicatorCount}</div>
								<div class="stat-label">{$tr('socialEngineering.result.emailIndicators')}</div>
							</div>
							<div class="stat-card">
								<div class="stat-value purple">{highFindingCount}</div>
								<div class="stat-label">{$tr('socialEngineering.result.highFindings')}</div>
							</div>
						</div>

						<div class="result-tabs">
							<button class="result-tab {activeResultTab === 'overview' ? 'active' : ''}" onclick={() => activeResultTab = 'overview'}>{$tr('socialEngineering.tabs.overview')}</button>
							{#if result.typosquatting}
								<button class="result-tab {activeResultTab === 'typosquatting' ? 'active' : ''}" onclick={() => activeResultTab = 'typosquatting'}>{$tr('socialEngineering.tabs.typosquatting')} ({result.typosquatting.typosquatted_domains.length})</button>
							{/if}
							<button class="result-tab {activeResultTab === 'brands' ? 'active' : ''}" onclick={() => activeResultTab = 'brands'}>{$tr('socialEngineering.tabs.brands')} ({result.brand_impersonations.length})</button>
							<button class="result-tab {activeResultTab === 'email' ? 'active' : ''}" onclick={() => activeResultTab = 'email'}>{$tr('socialEngineering.tabs.indicators')} ({result.email_indicators.length})</button>
							<button class="result-tab {activeResultTab === 'findings' ? 'active' : ''}" onclick={() => activeResultTab = 'findings'}>{$tr('socialEngineering.tabs.findings')} ({result.security_findings.length})</button>
						</div>

						{#if activeResultTab === 'overview'}
							<div class="items-list">
								{#if result.security_findings.length > 0}
									<div>
										<h3 class="item-section-title">{$tr('socialEngineering.result.securityFindings')} ({result.security_findings.length})</h3>
										<div class="detection-list">
											{#each result.security_findings as finding}
												<div class="detection-item">
													<div class="detection-header">
														<span class="detection-family">{translateCategory(finding.category)}</span>
														<span class="severity-badge" style="background: {getSeverityBorder(finding.severity)}; color: {getSeverityColor(finding.severity)};">{translateSeverity(finding.severity)}</span>
													</div>
													<p class="detection-desc">{finding.description}</p>
													<p class="detection-rec">💡 {$tr('socialEngineering.result.recommendation')}: {finding.recommendation}</p>
													{#if finding.mitre_technique}
														<span class="mitre-tag">MITRE: {finding.mitre_technique}</span>
													{/if}
												</div>
											{/each}
										</div>
									</div>
								{/if}

								{#if result.brand_impersonations.length > 0}
									<div>
										<h3 class="item-section-title">{$tr('socialEngineering.result.brandImpersonations')} ({result.brand_impersonations.length})</h3>
										<div class="tag-grid">
											{#each result.brand_impersonations as brand}
												<span class="tag-item red">
													{brand.brand} ({(brand.confidence * 100).toFixed(0)}%)
												</span>
											{/each}
										</div>
									</div>
								{/if}

								{#if result.email_indicators.length > 0}
									<div>
										<h3 class="item-section-title">{$tr('socialEngineering.result.emailIndicators')} ({result.email_indicators.length})</h3>
										<div class="detection-list">
											{#each result.email_indicators as ind}
												<div class="detection-card" style="border-left-color: {getSeverityBorder(ind.risk_level)}; background: {getSeverityBg(ind.risk_level)};">
													<div class="detection-header">
														<h4 class="detection-family">{translateIndicatorType(ind.indicator_type)}</h4>
														<span class="severity-badge large" style="background: {getSeverityBorder(ind.risk_level)}; color: {getSeverityColor(ind.risk_level)};">{translateSeverity(ind.risk_level)}</span>
													</div>
													<p class="detection-desc">{ind.description}</p>
													<p class="detection-rec">💡 {ind.recommendation}</p>
												</div>
											{/each}
										</div>
									</div>
								{/if}
							</div>
						{:else if activeResultTab === 'typosquatting' && result.typosquatting}
							<div class="typosquat-header">
								<span class="info-label">{$tr('socialEngineering.result.originalDomain')}</span>
								<span class="mono-text">{result.typosquatting.original_domain}</span>
								<span class="severity-badge" style="background: {getSeverityBorder(result.typosquatting.risk_level)}; color: {getSeverityColor(result.typosquatting.risk_level)};">{translateSeverity(result.typosquatting.risk_level)}</span>
							</div>
							<div class="table-wrapper">
								<table class="data-table">
									<thead>
										<tr>
											<th>{$tr('socialEngineering.table.domain')}</th>
											<th>{$tr('socialEngineering.table.technique')}</th>
											<th>{$tr('socialEngineering.table.similarity')}</th>
											<th>{$tr('socialEngineering.table.riskLevel')}</th>
										</tr>
									</thead>
									<tbody>
										{#each result.typosquatting.typosquatted_domains as ts}
											<tr>
												<td class="device-name mono-text">{ts.domain}</td>
												<td>{translateTechnique(ts.technique)}</td>
												<td>
													<div class="similarity-bar">
														<div class="similarity-fill" style="width: {ts.similarity_score * 100}%; background: {getSeverityBorder(ts.risk_level)};"></div>
														<span class="similarity-text">{(ts.similarity_score * 100).toFixed(0)}%</span>
													</div>
												</td>
												<td>
													<span class="severity-badge" style="background: {getSeverityBorder(ts.risk_level)}; color: {getSeverityColor(ts.risk_level)};">{translateSeverity(ts.risk_level)}</span>
												</td>
											</tr>
										{/each}
									</tbody>
								</table>
							</div>
						{:else if activeResultTab === 'brands'}
							{#if result.brand_impersonations.length > 0}
								<div class="detection-list">
									{#each result.brand_impersonations as brand}
										<div class="detection-card" style="border-left-color: {getSeverityBorder(brand.risk_level)}; background: {getSeverityBg(brand.risk_level)};">
											<div class="detection-header">
												<h4 class="detection-family">{brand.brand}</h4>
												<span class="severity-badge large" style="background: {getSeverityBorder(brand.risk_level)}; color: {getSeverityColor(brand.risk_level)};">{translateSeverity(brand.risk_level)}</span>
											</div>
											<div class="detection-meta">
												<span class="meta-item"><span class="meta-label">{$tr('socialEngineering.table.impersonationType')}:</span> {brand.impersonation_type}</span>
												<span class="meta-item"><span class="meta-label">{$tr('socialEngineering.table.confidence')}:</span> {(brand.confidence * 100).toFixed(0)}%</span>
											</div>
											{#if brand.indicators.length > 0}
												<div class="tag-grid" style="margin-top: 0.4rem;">
													{#each brand.indicators as ind}
														<span class="tag-item gray">{ind}</span>
													{/each}
												</div>
											{/if}
										</div>
									{/each}
								</div>
							{:else}
								<div class="empty-item">{$tr('socialEngineering.result.noBrands')}</div>
							{/if}
						{:else if activeResultTab === 'email'}
							{#if result.email_indicators.length > 0}
								<div class="detection-list">
									{#each result.email_indicators as ind}
										<div class="detection-card" style="border-left-color: {getSeverityBorder(ind.risk_level)}; background: {getSeverityBg(ind.risk_level)};">
											<div class="detection-header">
												<h4 class="detection-family">{translateIndicatorType(ind.indicator_type)}</h4>
												<span class="severity-badge large" style="background: {getSeverityBorder(ind.risk_level)}; color: {getSeverityColor(ind.risk_level)};">{translateSeverity(ind.risk_level)}</span>
											</div>
											<p class="detection-desc">{ind.description}</p>
											<div class="detection-meta">
												<span class="meta-item"><span class="meta-label">{$tr('socialEngineering.table.value')}:</span> <span class="mono-text">{ind.value}</span></span>
											</div>
											<p class="detection-rec">💡 {ind.recommendation}</p>
										</div>
									{/each}
								</div>
							{:else}
								<div class="empty-item">{$tr('socialEngineering.result.noIndicators')}</div>
							{/if}
						{:else if activeResultTab === 'findings'}
							{#if result.security_findings.length > 0}
								<div class="finding-list">
									{#each result.security_findings as finding}
										<div class="finding-card" style="border-left-color: {getSeverityBorder(finding.severity)}; background: {getSeverityBg(finding.severity)}; border-left: 3px solid;">
											<div class="finding-header">
												<span class="severity-badge" style="background: {getSeverityBorder(finding.severity)}; color: {getSeverityColor(finding.severity)};">{translateSeverity(finding.severity)}</span>
												<span class="finding-category">{translateCategory(finding.category)}</span>
											</div>
											<p class="finding-desc">{finding.description}</p>
											<p class="finding-rec">💡 {$tr('socialEngineering.result.recommendation')}: {finding.recommendation}</p>
											{#if finding.mitre_technique}
												<span class="mitre-tag">MITRE: {finding.mitre_technique}</span>
											{/if}
										</div>
									{/each}
								</div>
							{:else}
								<div class="empty-item">{$tr('socialEngineering.result.noFindings')}</div>
							{/if}
						{/if}
					{:else}
						<div class="empty-state">
							<div class="empty-icon">🎭</div>
							<p>{$tr('socialEngineering.result.noResults')}</p>
						</div>
					{/if}
				</div>
			</div>
		</div>
	{:else if activeMainTab === 'history'}
		<ToolHistory bind:this={historyComponent} toolType="social_engineering" toolName={$tr('socialEngineering.title')} />
	{:else if activeMainTab === 'help'}
		<ToolHelp toolType="social_engineering" />
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
	.form-input:disabled { opacity: 0.6; }
	.form-textarea { resize: vertical; min-height: 80px; font-family: inherit; }

	.checkbox-group { display: flex; flex-direction: column; gap: 0.5rem; margin: 0.75rem 0; }
	.checkbox-label { display: flex; align-items: center; gap: 0.5rem; font-size: 0.85rem; color: #cbd5e1; cursor: pointer; }
	.checkbox-label input[type="checkbox"] { accent-color: #a855f7; }

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

	.summary-banner { display: flex; align-items: center; justify-content: space-between; padding: 0.75rem 1rem; background: rgba(15, 23, 42, 0.4); border: 1px solid rgba(148, 163, 184, 0.08); border-radius: 0.75rem; margin-bottom: 1rem; flex-wrap: wrap; gap: 0.5rem; }
	.summary-info { display: flex; align-items: center; gap: 0.75rem; }
	.domain-badge { padding: 0.2rem 0.6rem; background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%); border-radius: 0.3rem; font-size: 0.7rem; font-weight: 700; color: white; letter-spacing: 0.05em; }
	.query-text { font-size: 0.85rem; color: #f1f5f9; font-weight: 500; font-family: 'SF Mono', 'Fira Code', monospace; }
	.status-badge { padding: 0.15rem 0.5rem; border-radius: 0.3rem; font-size: 0.7rem; font-weight: 600; }
	.status-badge.success { background: rgba(34, 197, 94, 0.15); color: #86efac; border: 1px solid rgba(34, 197, 94, 0.3); }
	.status-badge.failed { background: rgba(239, 68, 68, 0.15); color: #fca5a5; border: 1px solid rgba(239, 68, 68, 0.3); }
	.summary-badges { display: flex; gap: 0.5rem; flex-wrap: wrap; }
	.summary-badge { padding: 0.25rem 0.6rem; border-radius: 0.4rem; font-size: 0.75rem; font-weight: 600; }
	.summary-badge.purple { background: rgba(168, 85, 247, 0.15); color: #c4b5fd; border: 1px solid rgba(168, 85, 247, 0.3); }
	.summary-badge.red { background: rgba(239, 68, 68, 0.15); color: #fca5a5; border: 1px solid rgba(239, 68, 68, 0.3); }
	.summary-badge.orange { background: rgba(249, 115, 22, 0.15); color: #fdba74; border: 1px solid rgba(249, 115, 22, 0.3); }

	.stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 0.75rem; margin-bottom: 1rem; }
	.stat-card { background: rgba(15, 23, 42, 0.4); border: 1px solid rgba(148, 163, 184, 0.08); border-radius: 0.5rem; padding: 0.75rem; text-align: center; }
	.stat-value { font-size: 1.25rem; font-weight: 700; }
	.stat-value.purple { color: #c4b5fd; }
	.stat-value.orange { color: #fdba74; }
	.stat-value.red { color: #fca5a5; }
	.stat-value.yellow { color: #fbbf24; }
	.stat-label { font-size: 0.7rem; color: #64748b; margin-top: 0.2rem; }

	.result-tabs { display: flex; gap: 0.25rem; margin-bottom: 1rem; flex-wrap: wrap; }
	.result-tab { padding: 0.4rem 0.75rem; border-radius: 0.4rem; border: 1px solid rgba(148, 163, 184, 0.15); background: rgba(15, 23, 42, 0.4); color: #94a3b8; cursor: pointer; font-size: 0.8rem; transition: all 0.2s; }
	.result-tab.active { background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%); color: white; border-color: transparent; font-weight: 600; }
	.result-tab:hover:not(.active) { border-color: rgba(168, 85, 247, 0.3); color: #c4b5fd; }

	.items-list { display: flex; flex-direction: column; gap: 1rem; }
	.item-section-title { font-size: 0.85rem; font-weight: 600; color: #c4b5fd; margin: 0 0 0.5rem; }

	.tag-grid { display: flex; flex-wrap: wrap; gap: 0.4rem; }
	.tag-item { padding: 0.25rem 0.6rem; border-radius: 0.3rem; font-size: 0.75rem; font-weight: 500; }
	.tag-item.red { background: rgba(239, 68, 68, 0.15); color: #fca5a5; border: 1px solid rgba(239, 68, 68, 0.2); }
	.tag-item.gray { background: rgba(148, 163, 184, 0.15); color: #94a3b8; border: 1px solid rgba(148, 163, 184, 0.2); }

	.detection-list { display: flex; flex-direction: column; gap: 0.75rem; }
	.detection-item { padding: 0.75rem; background: rgba(15, 23, 42, 0.4); border: 1px solid rgba(148, 163, 184, 0.08); border-radius: 0.5rem; }
	.detection-card { padding: 0.75rem; background: rgba(15, 23, 42, 0.4); border: 1px solid rgba(168, 85, 247, 0.15); border-radius: 0.5rem; border-left: 3px solid rgba(168, 85, 247, 0.5); }
	.detection-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.4rem; flex-wrap: wrap; gap: 0.3rem; }
	.detection-family { font-weight: 600; color: #c4b5fd; font-size: 0.9rem; }
	.detection-desc { font-size: 0.85rem; color: #cbd5e1; margin: 0.3rem 0 0; }
	.detection-rec { font-size: 0.8rem; color: #86efac; margin: 0.3rem 0 0; }
	.detection-meta { display: flex; gap: 1rem; flex-wrap: wrap; font-size: 0.8rem; color: #94a3b8; margin-top: 0.3rem; }
	.meta-item { font-size: 0.85rem; color: #cbd5e1; }
	.meta-label { color: #94a3b8; margin-right: 0.3rem; }

	.severity-badge { padding: 0.15rem 0.5rem; border-radius: 0.3rem; font-size: 0.7rem; font-weight: 600; text-transform: uppercase; }
	.severity-badge.large { font-size: 0.8rem; padding: 0.2rem 0.6rem; }

	.mitre-tag { display: inline-block; margin-top: 0.3rem; padding: 0.15rem 0.5rem; border-radius: 0.2rem; font-size: 0.7rem; background: rgba(168, 85, 247, 0.15); color: #c4b5fd; border: 1px solid rgba(168, 85, 247, 0.3); }

	.typosquat-header { display: flex; align-items: center; gap: 0.75rem; margin-bottom: 1rem; padding: 0.75rem; background: rgba(15, 23, 42, 0.4); border: 1px solid rgba(148, 163, 184, 0.08); border-radius: 0.5rem; }

	.table-wrapper { overflow-x: auto; }
	.data-table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
	.data-table th { padding: 0.5rem 0.75rem; text-align: left; color: #94a3b8; font-weight: 500; border-bottom: 1px solid rgba(148, 163, 184, 0.15); font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; }
	.data-table td { padding: 0.5rem 0.75rem; border-bottom: 1px solid rgba(148, 163, 184, 0.08); color: #cbd5e1; }
	.data-table tr:hover td { background: rgba(168, 85, 247, 0.05); }
	.mono-text { font-family: 'SF Mono', 'Fira Code', monospace; font-size: 0.82rem; color: #93c5fd; }
	.device-name { font-weight: 500; color: #f1f5f9; }

	.similarity-bar { position: relative; width: 100%; height: 1.25rem; background: rgba(15, 23, 42, 0.6); border-radius: 0.25rem; overflow: hidden; }
	.similarity-fill { height: 100%; border-radius: 0.25rem; transition: width 0.3s; }
	.similarity-text { position: absolute; right: 0.4rem; top: 50%; transform: translateY(-50%); font-size: 0.7rem; color: #f1f5f9; font-weight: 600; }

	.finding-list { display: flex; flex-direction: column; gap: 0.5rem; }
	.finding-card { padding: 0.75rem; border-radius: 0.5rem; border-left: 3px solid; }
	.finding-header { display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.3rem; flex-wrap: wrap; }
	.finding-category { font-size: 0.85rem; font-weight: 500; color: #f1f5f9; }
	.finding-desc { font-size: 0.85rem; color: #cbd5e1; margin: 0.3rem 0; }
	.finding-rec { font-size: 0.8rem; color: #86efac; margin: 0.3rem 0 0; }

	.empty-state { text-align: center; padding: 2.5rem 1rem; color: #94a3b8; }
	.empty-icon { font-size: 2.5rem; margin-bottom: 0.75rem; }
	.empty-state p { font-size: 0.85rem; margin: 0; }
	.empty-item { text-align: center; padding: 1.5rem; color: #64748b; font-size: 0.85rem; }

	@media (max-width: 768px) {
		.content-grid { grid-template-columns: 1fr; }
		.input-section { position: static; max-height: none; }
		.stats-grid { grid-template-columns: repeat(2, 1fr); }
	}
</style>
