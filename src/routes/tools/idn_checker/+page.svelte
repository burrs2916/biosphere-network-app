<script lang="ts">
	import { tr, t } from '$lib/i18n';
	import ToolHistory from '$lib/components/ToolHistory.svelte';
	import ToolHelp from '$lib/components/ToolHelp.svelte';

	interface SuspiciousChar {
		position: number;
		char: string;
		unicode_codepoint: string;
		unicode_name: string;
		resembles: string;
		category: string;
		risk: string;
	}

	interface SimilarDomain {
		domain: string;
		similarity_type: string;
		punycode: string | null;
		risk_level: string;
	}

	interface CharSubstitution {
		original: string;
		replaced: string;
		position: number;
		category: string;
	}

	interface DomainVariant {
		domain: string;
		punycode: string;
		variant_type: string;
		substitutions: CharSubstitution[];
		is_registered: boolean | null;
		risk_level: string;
	}

	interface ScriptInfo {
		script: string;
		char_count: number;
		has_confusable: boolean;
	}

	interface ScriptAnalysis {
		scripts: ScriptInfo[];
		is_mixed_script: boolean;
		is_single_script: boolean;
		has_confusable: boolean;
		script_count: number;
		detail: string;
	}

	interface BrandMatch {
		brand: string;
		category: string;
		confidence: number;
		matched_positions: number[];
	}

	interface IdnCheckResult {
		original_domain: string;
		punycode_domain: string | null;
		is_idn: boolean;
		is_suspicious: boolean;
		risk_level: string;
		risk_score: number;
		suspicious_chars: SuspiciousChar[];
		similar_domains: SimilarDomain[];
		generated_variants: DomainVariant[];
		script_analysis: ScriptAnalysis;
		brand_match: BrandMatch | null;
		summary: string;
	}

	interface BatchIdnCheckResult {
		total: number;
		suspicious_count: number;
		safe_count: number;
		error_count: number;
		results: IdnCheckResult[];
		summary: string;
	}

	let domain = $state('');
	let generateVariants = $state(true);
	let checkDns = $state(true);
	let checkBrand = $state(true);
	let maxVariants = $state(50);
	let result: IdnCheckResult | null = $state(null);
	let batchResults: BatchIdnCheckResult | null = $state(null);
	let error = $state('');
	let processing = $state(false);
	let activeMainTab = $state('check');
	let activeTab = $state('single');
	let activeResultTab = $state('overview');
	let batchInput = $state('');
	let historyComponent: ToolHistory = $state(null!);

	function getRiskColor(level: string): string {
		switch (level) {
			case 'critical': return '#ef4444';
			case 'high': return '#f97316';
			case 'medium': return '#eab308';
			case 'low': return '#22c55e';
			case 'safe': return '#10b981';
			default: return '#6b7280';
		}
	}

	function getRiskBg(level: string): string {
		switch (level) {
			case 'critical': return 'rgba(239,68,68,0.15)';
			case 'high': return 'rgba(249,115,22,0.15)';
			case 'medium': return 'rgba(234,179,8,0.15)';
			case 'low': return 'rgba(34,197,94,0.15)';
			case 'safe': return 'rgba(16,185,129,0.15)';
			default: return 'rgba(107,114,128,0.15)';
		}
	}

	function getCategoryColor(category: string): string {
		switch (category) {
			case 'Cyrillic': return 'rgba(239,68,68,0.2)';
			case 'Greek': return 'rgba(59,130,246,0.2)';
			case 'Coptic': return 'rgba(249,115,22,0.2)';
			case 'Armenian': return 'rgba(168,85,247,0.2)';
			case 'Cherokee': return 'rgba(236,72,153,0.2)';
			case 'Latin Extended': return 'rgba(234,179,8,0.2)';
			case 'Enclosed': return 'rgba(107,114,128,0.2)';
			case 'CJK': return 'rgba(168,85,247,0.2)';
			default: return 'rgba(107,114,128,0.2)';
		}
	}

	function getCategoryTextColor(category: string): string {
		switch (category) {
			case 'Cyrillic': return '#f87171';
			case 'Greek': return '#60a5fa';
			case 'Coptic': return '#fb923c';
			case 'Armenian': return '#c084fc';
			case 'Cherokee': return '#f472b6';
			case 'Latin Extended': return '#facc15';
			case 'Enclosed': return '#9ca3af';
			case 'CJK': return '#c084fc';
			default: return '#9ca3af';
		}
	}

	async function checkDomain() {
		if (!domain.trim()) {
			error = t('idnChecker.error.emptyInput');
			return;
		}
		processing = true;
		error = '';
		result = null;
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			result = await invoke<IdnCheckResult>('idn_check_command', {
				config: {
					domain: domain.trim(),
					generate_variants: generateVariants,
					check_dns: checkDns,
					check_brand: checkBrand,
					max_variants: maxVariants,
				}
			});
			if (result && historyComponent) {
				await historyComponent.saveHistory(
					domain.trim(),
					JSON.stringify(result),
					result.summary,
					'completed'
				);
			}
		} catch (e: any) {
			error = e.toString();
			if (historyComponent) {
				await historyComponent.saveHistory(domain.trim(), '', error, 'failed');
			}
		} finally {
			processing = false;
		}
	}

	async function batchCheck() {
		const domains = batchInput.split('\n').map(d => d.trim()).filter(d => d.length > 0);
		if (domains.length === 0) {
			error = t('idnChecker.error.emptyInput');
			return;
		}
		processing = true;
		error = '';
		batchResults = null;
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			batchResults = await invoke<BatchIdnCheckResult>('idn_batch_check_command', {
				domains,
				config: {
					domain: '',
					generate_variants: generateVariants,
					check_dns: checkDns,
					check_brand: checkBrand,
					max_variants: maxVariants,
				}
			});
		} catch (e: any) {
			error = e.toString();
		} finally {
			processing = false;
		}
	}

	function loadFromHistory(data: string) {
		try {
			result = JSON.parse(data);
			if (result) {
				domain = result.original_domain || '';
			}
		} catch {}
	}

	function clearAll() {
		domain = '';
		batchInput = '';
		result = null;
		batchResults = null;
		error = '';
		activeResultTab = 'overview';
	}

	function handleKeydown(e: KeyboardEvent) {
		if (e.key === 'Enter' && !processing) {
			if (activeTab === 'single' && domain.trim()) {
				checkDomain();
			} else if (activeTab === 'batch' && batchInput.trim()) {
				batchCheck();
			}
		}
	}

	function getRegisteredCount(): number {
		if (!result) return 0;
		return result.generated_variants.filter((v: DomainVariant) => v.is_registered === true).length;
	}

	function getHighRiskChars(): number {
		if (!result) return 0;
		return result.suspicious_chars.filter((c: SuspiciousChar) => c.risk === 'high').length;
	}
</script>

<svelte:window onkeydown={handleKeydown} />

<div class="nd-page">
	<div class="page-header">
		<div class="header-left">
			<a href="/" class="back-link">{$tr('common.backToHome')}</a>
			<h1 class="page-title">🔤 {$tr('idnChecker.title')}</h1>
			<p class="page-subtitle">{$tr('idnChecker.subtitle')}</p>
		</div>
	</div>

	<div class="tabs">
		<button class="tab-btn {activeMainTab === 'check' ? 'active' : ''}" onclick={() => activeMainTab = 'check'}>
			<span class="tab-icon">🔍</span> {$tr('idnChecker.tabs.check')}
		</button>
		<button class="tab-btn {activeMainTab === 'history' ? 'active' : ''}" onclick={() => activeMainTab = 'history'}>
			<span class="tab-icon">📋</span> {$tr('idnChecker.tabs.history')}
		</button>
		<button class="tab-btn {activeMainTab === 'help' ? 'active' : ''}" onclick={() => activeMainTab = 'help'}>
			<span class="tab-icon">📖</span> {$tr('idnChecker.tabs.help')}
		</button>
	</div>

	{#if activeMainTab === 'check'}
		<div class="content-grid">
			<div class="input-section">
				<div class="section-card">
					<h2 class="section-title">{$tr('idnChecker.config.title')}</h2>
					<p class="section-desc">{$tr('idnChecker.config.desc')}</p>

					<div class="sub-tabs">
						<button class="sub-tab {activeTab === 'single' ? 'active' : ''}" onclick={() => activeTab = 'single'}>
							{$tr('idnChecker.tabs.single')}
						</button>
						<button class="sub-tab {activeTab === 'batch' ? 'active' : ''}" onclick={() => activeTab = 'batch'}>
							{$tr('idnChecker.tabs.batch')}
						</button>
					</div>

					{#if activeTab === 'single'}
						<div class="form-group">
							<label class="form-label">{$tr('idnChecker.config.domain')}</label>
							<input type="text" bind:value={domain} placeholder="example.com 或 pаypal.com" class="form-input" disabled={processing} />
							<p class="form-hint">{$tr('idnChecker.config.domainHint')}</p>
						</div>
					{:else}
						<div class="form-group">
							<label class="form-label">{$tr('idnChecker.config.batchDomains')}</label>
							<textarea bind:value={batchInput} placeholder="paypal.com&#10;gоogle.com&#10;аpple.com" class="form-textarea" rows="5" disabled={processing}></textarea>
							<p class="form-hint">{$tr('idnChecker.config.batchHint')}</p>
						</div>
					{/if}

					<div class="form-group">
						<label class="form-label">{$tr('idnChecker.config.options')}</label>
						<div class="target-grid">
							<label class="target-chip {generateVariants ? 'active' : ''}">
								<input type="checkbox" bind:checked={generateVariants} disabled={processing} />
								<span>🔀 {$tr('idnChecker.config.generateVariants')}</span>
							</label>
							<label class="target-chip {checkDns ? 'active' : ''}">
								<input type="checkbox" bind:checked={checkDns} disabled={processing} />
								<span>🌐 {$tr('idnChecker.config.checkDns')}</span>
							</label>
							<label class="target-chip {checkBrand ? 'active' : ''}">
								<input type="checkbox" bind:checked={checkBrand} disabled={processing} />
								<span>🏷️ {$tr('idnChecker.config.checkBrand')}</span>
							</label>
						</div>
					</div>

					{#if generateVariants}
						<div class="form-group">
							<label class="form-label">{$tr('idnChecker.config.maxVariants')}</label>
							<input type="number" bind:value={maxVariants} class="form-input" min="1" max="200" disabled={processing} />
						</div>
					{/if}

					{#if activeTab === 'single'}
						<div class="btn-group">
							<button class="action-btn" onclick={checkDomain} disabled={processing}>
								{processing ? $tr('idnChecker.buttons.checking') : $tr('idnChecker.buttons.check')}
							</button>
							<button class="clear-btn" onclick={clearAll} disabled={processing}>
								{$tr('idnChecker.buttons.clear')}
							</button>
						</div>
					{:else}
						<div class="btn-group">
							<button class="action-btn" onclick={batchCheck} disabled={processing}>
								{processing ? $tr('idnChecker.buttons.checking') : $tr('idnChecker.buttons.batchCheck')}
							</button>
							<button class="clear-btn" onclick={clearAll} disabled={processing}>
								{$tr('idnChecker.buttons.clear')}
							</button>
						</div>
					{/if}
				</div>

				<div class="section-card">
					<h3 class="section-title" style="font-size: 0.85rem;">{$tr('idnChecker.examples.title')}</h3>
					<div class="examples-list">
						<button class="example-item" onclick={() => { domain = 'pаypal.com'; activeTab = 'single'; }}>
							<span class="example-label">pаypal.com</span>
							<span class="example-desc">Cyrillic а → Latin a</span>
						</button>
						<button class="example-item" onclick={() => { domain = 'gоogle.com'; activeTab = 'single'; }}>
							<span class="example-label">gоogle.com</span>
							<span class="example-desc">Cyrillic о → Latin o</span>
						</button>
						<button class="example-item" onclick={() => { domain = 'аpple.com'; activeTab = 'single'; }}>
							<span class="example-label">аpple.com</span>
							<span class="example-desc">Cyrillic а → Latin a</span>
						</button>
						<button class="example-item" onclick={() => { domain = 'tеlegram.com'; activeTab = 'single'; }}>
							<span class="example-label">tеlegram.com</span>
							<span class="example-desc">Cyrillic е → Latin e</span>
						</button>
					</div>
				</div>
			</div>

			<div class="result-section">
				{#if error}
					<div class="error-banner">{error}</div>
				{/if}

				{#if activeTab === 'single' && result}
					<div class="section-card">
						<div class="result-summary" style="background: {getRiskBg(result.risk_level)}; border-left: 3px solid {getRiskColor(result.risk_level)};">
							{result.summary}
						</div>

						<div class="stat-grid">
							<button class="stat-card {activeResultTab === 'overview' ? 'active' : ''}" onclick={() => activeResultTab = 'overview'}>
								<div class="stat-value" style="color: {getRiskColor(result.risk_level)}">
									{result.risk_level.toUpperCase()}
								</div>
								<div class="stat-label">{$tr('idnChecker.result.riskLevel')}</div>
							</button>
							<button class="stat-card {activeResultTab === 'chars' ? 'active' : ''}" onclick={() => activeResultTab = 'chars'}>
								<div class="stat-value" style="color: #f87171">{result.suspicious_chars.length}</div>
								<div class="stat-label">{$tr('idnChecker.result.suspiciousChars')}</div>
							</button>
							<button class="stat-card {activeResultTab === 'variants' ? 'active' : ''}" onclick={() => activeResultTab = 'variants'}>
								<div class="stat-value" style="color: #a855f7">{result.generated_variants.length}</div>
								<div class="stat-label">{$tr('idnChecker.result.variants')}</div>
							</button>
							<button class="stat-card {activeResultTab === 'scripts' ? 'active' : ''}" onclick={() => activeResultTab = 'scripts'}>
								<div class="stat-value" style="color: {result.script_analysis.is_mixed_script ? '#f87171' : '#10b981'}">{result.script_analysis.script_count}</div>
								<div class="stat-label">{$tr('idnChecker.result.scripts')}</div>
							</button>
						</div>

						{#if activeResultTab === 'overview'}
							<div class="detail-section">
								<div class="detail-row">
									<span class="detail-label">{$tr('idnChecker.result.originalDomain')}</span>
									<div class="domain-display">
										{#each result.original_domain.split('') as char, i}
											{#if result.suspicious_chars.some(c => c.position === i)}
												<span class="highlighted-char">{char}</span>
											{:else}
												<span>{char}</span>
											{/if}
										{/each}
									</div>
								</div>

								{#if result.punycode_domain}
									<div class="detail-row">
										<span class="detail-label">{$tr('idnChecker.result.punycode')}</span>
										<span class="detail-value mono" style="color: #facc15">{result.punycode_domain}</span>
									</div>
								{/if}

								<div class="detail-row">
									<span class="detail-label">{$tr('idnChecker.result.riskScore')}</span>
									<div class="risk-bar-container">
										<div class="risk-bar" style="width: {result.risk_score * 100}%; background: {getRiskColor(result.risk_level)};"></div>
										<span class="risk-bar-label" style="color: {getRiskColor(result.risk_level)}">{(result.risk_score * 100).toFixed(0)}%</span>
									</div>
								</div>

								<div class="info-grid">
									<div class="info-item">
										<span class="info-label">{$tr('idnChecker.result.isIdn')}</span>
										<span class="info-value" style="color: {result.is_idn ? '#facc15' : '#10b981'}">{result.is_idn ? $tr('idnChecker.result.yes') : $tr('idnChecker.result.no')}</span>
									</div>
									<div class="info-item">
										<span class="info-label">{$tr('idnChecker.result.isSuspicious')}</span>
										<span class="info-value" style="color: {result.is_suspicious ? '#f87171' : '#10b981'}">{result.is_suspicious ? $tr('idnChecker.result.yes') : $tr('idnChecker.result.no')}</span>
									</div>
									<div class="info-item">
										<span class="info-label">{$tr('idnChecker.result.highRiskChars')}</span>
										<span class="info-value" style="color: {getHighRiskChars() > 0 ? '#f87171' : '#10b981'}">{getHighRiskChars()}</span>
									</div>
									<div class="info-item">
										<span class="info-label">{$tr('idnChecker.result.registeredVariants')}</span>
										<span class="info-value" style="color: {getRegisteredCount() > 0 ? '#f87171' : '#10b981'}">{getRegisteredCount()}</span>
									</div>
								</div>

								{#if result.brand_match}
									<div class="brand-alert">
										<div class="brand-header">
											<span class="brand-icon">⚠️</span>
											<span class="brand-title">{$tr('idnChecker.result.brandMatch')}</span>
										</div>
										<div class="brand-details">
											<span class="brand-name">{result.brand_match.brand}</span>
											<span class="brand-category">{result.brand_match.category}</span>
											<span class="brand-confidence">{(result.brand_match.confidence * 100).toFixed(0)}%</span>
										</div>
									</div>
								{/if}

								{#if result.similar_domains.length > 0}
									<div class="similar-section">
										<h4 class="sub-title">{$tr('idnChecker.result.similarDomains')}</h4>
										<div class="similar-list">
											{#each result.similar_domains as sd}
												<div class="similar-item">
													<span class="similar-domain mono">{sd.domain}</span>
													<span class="similar-type">{sd.similarity_type}</span>
													<span class="risk-badge" style="background: {getRiskBg(sd.risk_level)}; color: {getRiskColor(sd.risk_level)}">{sd.risk_level}</span>
												</div>
											{/each}
										</div>
									</div>
								{/if}
							</div>

						{:else if activeResultTab === 'chars'}
							{#if result.suspicious_chars.length > 0}
								<div class="chars-table">
									<div class="table-header">
										<span class="col-position">{$tr('idnChecker.result.position')}</span>
										<span class="col-char">{$tr('idnChecker.result.char')}</span>
										<span class="col-unicode">Unicode</span>
										<span class="col-name">{$tr('idnChecker.result.unicodeName')}</span>
										<span class="col-resembles">{$tr('idnChecker.result.resembles')}</span>
										<span class="col-category">{$tr('idnChecker.result.category')}</span>
										<span class="col-risk">{$tr('idnChecker.result.risk')}</span>
									</div>
									{#each result.suspicious_chars as sc}
										<div class="table-row">
											<span class="col-position">{sc.position}</span>
											<span class="col-char highlighted-char">{sc.char}</span>
											<span class="col-unicode mono" style="color: #60a5fa">{sc.unicode_codepoint}</span>
											<span class="col-name" style="color: #94a3b8; font-size: 0.75rem;">{sc.unicode_name}</span>
											<span class="col-resembles" style="color: #10b981; font-size: 1.1rem;">{sc.resembles}</span>
											<span class="col-category">
												<span class="category-badge" style="background: {getCategoryColor(sc.category)}; color: {getCategoryTextColor(sc.category)}">{sc.category}</span>
											</span>
											<span class="col-risk">
												<span class="risk-badge" style="background: {getRiskBg(sc.risk)}; color: {getRiskColor(sc.risk)}">{sc.risk}</span>
											</span>
										</div>
									{/each}
								</div>
							{:else}
								<div class="empty-state">{$tr('idnChecker.result.noSuspiciousChars')}</div>
							{/if}

						{:else if activeResultTab === 'variants'}
							{#if result.generated_variants.length > 0}
								<div class="variants-header">
									<span class="variants-count">{$tr('idnChecker.result.variantsCount').replace('{count}', result.generated_variants.length.toString())}</span>
									<span class="variants-registered" style="color: {getRegisteredCount() > 0 ? '#f87171' : '#10b981'}">
										{$tr('idnChecker.result.registeredCount').replace('{count}', getRegisteredCount().toString())}
									</span>
								</div>
								<div class="variants-list">
									{#each result.generated_variants as v}
										<div class="variant-item">
											<div class="variant-main">
												<span class="variant-domain mono">{v.domain}</span>
												<span class="risk-badge" style="background: {getRiskBg(v.risk_level)}; color: {getRiskColor(v.risk_level)}">{v.risk_level}</span>
												{#if v.is_registered === true}
													<span class="registered-badge">🌐 {$tr('idnChecker.result.registered')}</span>
												{:else if v.is_registered === false}
													<span class="unregistered-badge">{$tr('idnChecker.result.unregistered')}</span>
												{/if}
											</div>
											<div class="variant-punycode mono">{v.punycode}</div>
											<div class="variant-subs">
												{#each v.substitutions as sub}
													<span class="sub-badge">
														{sub.original}→{sub.replaced} <span style="color: {getCategoryTextColor(sub.category)}">({sub.category})</span>
													</span>
												{/each}
											</div>
										</div>
									{/each}
								</div>
							{:else}
								<div class="empty-state">{$tr('idnChecker.result.noVariants')}</div>
							{/if}

						{:else if activeResultTab === 'scripts'}
							<div class="scripts-section">
								<div class="script-alert" style="background: {result.script_analysis.is_mixed_script ? 'rgba(239,68,68,0.1)' : 'rgba(16,185,129,0.1)'}; border-left: 3px solid {result.script_analysis.is_mixed_script ? '#ef4444' : '#10b981'}">
									{result.script_analysis.detail}
								</div>

								<div class="scripts-grid">
									{#each result.script_analysis.scripts as si}
										<div class="script-card" style="border-color: {si.has_confusable ? 'rgba(239,68,68,0.4)' : 'rgba(148,163,184,0.15)'}">
											<div class="script-name">{si.script}</div>
											<div class="script-count">{si.char_count} {$tr('idnChecker.result.chars')}</div>
											{#if si.has_confusable}
												<div class="script-warning">⚠️ {$tr('idnChecker.result.hasConfusable')}</div>
											{/if}
										</div>
									{/each}
								</div>
							</div>
						{/if}
					</div>

				{:else if activeTab === 'batch' && batchResults}
					<div class="section-card">
						<div class="result-summary" style="background: {batchResults.suspicious_count > 0 ? 'rgba(239,68,68,0.1)' : 'rgba(16,185,129,0.1)'}; border-left: 3px solid {batchResults.suspicious_count > 0 ? '#ef4444' : '#10b981'};">
							{batchResults.summary}
						</div>

						<div class="stat-grid" style="grid-template-columns: repeat(4, 1fr);">
							<div class="stat-card">
								<div class="stat-value" style="color: #a855f7">{batchResults.total}</div>
								<div class="stat-label">{$tr('idnChecker.result.total')}</div>
							</div>
							<div class="stat-card">
								<div class="stat-value" style="color: #f87171">{batchResults.suspicious_count}</div>
								<div class="stat-label">{$tr('idnChecker.result.suspiciousCount')}</div>
							</div>
							<div class="stat-card">
								<div class="stat-value" style="color: #10b981">{batchResults.safe_count}</div>
								<div class="stat-label">{$tr('idnChecker.result.safeCount')}</div>
							</div>
							<div class="stat-card">
								<div class="stat-value" style="color: #facc15">{batchResults.error_count}</div>
								<div class="stat-label">{$tr('idnChecker.result.errorCount')}</div>
							</div>
						</div>

						<div class="batch-list">
							{#each batchResults.results as r}
								<div class="batch-item" style="border-left: 3px solid {getRiskColor(r.risk_level)}">
									<div class="batch-domain">
										<span class="mono">{r.original_domain}</span>
										<span class="risk-badge" style="background: {getRiskBg(r.risk_level)}; color: {getRiskColor(r.risk_level)}">{r.risk_level}</span>
									</div>
									<div class="batch-summary">{r.summary}</div>
								</div>
							{/each}
						</div>
					</div>

				{:else if !result && !batchResults && !error}
					<div class="section-card">
						<div class="empty-state">
							<div class="empty-icon">🔤</div>
							<div class="empty-text">{$tr('idnChecker.result.empty')}</div>
							<div class="empty-sub">{$tr('idnChecker.result.emptySub')}</div>
						</div>
					</div>
				{/if}
			</div>
		</div>

	{:else if activeMainTab === 'history'}
		<div class="section-card">
			<ToolHistory toolType="idn_checker" toolName={$tr('idnChecker.title')} bind:this={historyComponent} />
		</div>

	{:else if activeMainTab === 'help'}
		<div class="section-card">
			<ToolHelp toolType="idn_checker" />
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

	.sub-tabs {
		display: flex;
		gap: 0.25rem;
		margin-bottom: 1rem;
		background: rgba(15, 23, 42, 0.8);
		border-radius: 0.5rem;
		padding: 0.2rem;
	}

	.sub-tab {
		flex: 1;
		padding: 0.4rem 0.75rem;
		border: none;
		border-radius: 0.375rem;
		background: transparent;
		cursor: pointer;
		font-size: 0.8rem;
		color: #94a3b8;
		transition: all 0.2s;
	}
	.sub-tab.active {
		background: rgba(168, 85, 247, 0.2);
		color: #c4b5fd;
		font-weight: 600;
	}
	.sub-tab:hover:not(.active) { color: #c4b5fd; }

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

	.form-textarea {
		width: 100%;
		padding: 0.55rem 0.75rem;
		border-radius: 0.5rem;
		border: 1px solid rgba(148, 163, 184, 0.15);
		background: rgba(15, 23, 42, 0.8);
		color: #f1f5f9;
		font-size: 0.85rem;
		box-sizing: border-box;
		transition: border-color 0.2s;
		resize: vertical;
		font-family: inherit;
	}
	.form-textarea:focus {
		outline: none;
		border-color: #a855f7;
		box-shadow: 0 0 0 2px rgba(168, 85, 247, 0.15);
	}
	.form-textarea::placeholder { color: #475569; }

	.form-hint {
		font-size: 0.7rem;
		color: #64748b;
		margin: 0.25rem 0 0;
	}

	.target-grid {
		display: grid;
		grid-template-columns: 1fr;
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

	.btn-group {
		display: flex;
		gap: 0.5rem;
		margin-top: 0.5rem;
	}

	.action-btn {
		flex: 1;
		padding: 0.6rem 1rem;
		border: none;
		border-radius: 0.5rem;
		background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%);
		color: white;
		font-size: 0.85rem;
		font-weight: 600;
		cursor: pointer;
		transition: all 0.2s;
	}
	.action-btn:hover:not(:disabled) { box-shadow: 0 4px 12px rgba(168, 85, 247, 0.4); }
	.action-btn:disabled { opacity: 0.5; cursor: not-allowed; }

	.clear-btn {
		padding: 0.6rem 1rem;
		border: 1px solid rgba(148, 163, 184, 0.2);
		border-radius: 0.5rem;
		background: rgba(15, 23, 42, 0.6);
		color: #94a3b8;
		font-size: 0.85rem;
		font-weight: 500;
		cursor: pointer;
		transition: all 0.2s;
	}
	.clear-btn:hover:not(:disabled) { border-color: rgba(168, 85, 247, 0.3); color: #c4b5fd; }
	.clear-btn:disabled { opacity: 0.5; cursor: not-allowed; }

	.examples-list {
		display: flex;
		flex-direction: column;
		gap: 0.35rem;
	}

	.example-item {
		display: flex;
		justify-content: space-between;
		align-items: center;
		padding: 0.4rem 0.6rem;
		border: 1px solid rgba(148, 163, 184, 0.1);
		border-radius: 0.375rem;
		background: rgba(15, 23, 42, 0.4);
		cursor: pointer;
		font-size: 0.75rem;
		color: #94a3b8;
		transition: all 0.2s;
		text-align: left;
	}
	.example-item:hover { border-color: rgba(168, 85, 247, 0.3); color: #c4b5fd; }
	.example-label { font-family: monospace; color: #c4b5fd; }
	.example-desc { color: #64748b; font-size: 0.7rem; }

	.error-banner {
		background: rgba(239, 68, 68, 0.1);
		border: 1px solid rgba(239, 68, 68, 0.2);
		border-radius: 0.5rem;
		padding: 0.75rem 1rem;
		color: #fca5a5;
		font-size: 0.85rem;
		margin-bottom: 1rem;
	}

	.result-summary {
		padding: 0.75rem 1rem;
		border-radius: 0.5rem;
		font-size: 0.85rem;
		margin-bottom: 1rem;
		color: #e2e8f0;
		line-height: 1.5;
	}

	.stat-grid {
		display: grid;
		grid-template-columns: repeat(4, 1fr);
		gap: 0.5rem;
		margin-bottom: 1rem;
	}

	.stat-card {
		background: rgba(15, 23, 42, 0.8);
		border: 1px solid rgba(148, 163, 184, 0.15);
		border-radius: 0.5rem;
		padding: 0.6rem;
		text-align: center;
		cursor: pointer;
		transition: all 0.2s;
	}
	.stat-card.active { border-color: rgba(168, 85, 247, 0.4); background: rgba(168, 85, 247, 0.1); }
	.stat-card:hover:not(.active) { border-color: rgba(168, 85, 247, 0.2); }

	.stat-value {
		font-size: 1.1rem;
		font-weight: 700;
	}
	.stat-label {
		font-size: 0.65rem;
		color: #94a3b8;
		margin-top: 0.2rem;
		text-transform: uppercase;
		letter-spacing: 0.05em;
	}

	.detail-section {
		display: flex;
		flex-direction: column;
		gap: 0.75rem;
	}

	.detail-row {
		display: flex;
		flex-direction: column;
		gap: 0.25rem;
	}
	.detail-label {
		font-size: 0.75rem;
		color: #94a3b8;
		font-weight: 500;
		text-transform: uppercase;
		letter-spacing: 0.05em;
	}
	.detail-value { font-size: 0.85rem; color: #f1f5f9; }
	.mono { font-family: 'SF Mono', 'Fira Code', monospace; }

	.domain-display {
		background: rgba(15, 23, 42, 0.8);
		border-radius: 0.5rem;
		padding: 0.6rem 0.75rem;
		font-family: 'SF Mono', 'Fira Code', monospace;
		font-size: 1.1rem;
		word-break: break-all;
	}
	.highlighted-char {
		color: #f87171;
		background: rgba(239, 68, 68, 0.2);
		padding: 0 0.15rem;
		border-radius: 0.2rem;
	}

	.risk-bar-container {
		position: relative;
		height: 1.5rem;
		background: rgba(15, 23, 42, 0.8);
		border-radius: 0.375rem;
		overflow: hidden;
	}
	.risk-bar {
		height: 100%;
		border-radius: 0.375rem;
		transition: width 0.5s ease;
	}
	.risk-bar-label {
		position: absolute;
		right: 0.5rem;
		top: 50%;
		transform: translateY(-50%);
		font-size: 0.75rem;
		font-weight: 600;
	}

	.info-grid {
		display: grid;
		grid-template-columns: repeat(2, 1fr);
		gap: 0.5rem;
	}
	.info-item {
		background: rgba(15, 23, 42, 0.8);
		border-radius: 0.5rem;
		padding: 0.5rem 0.75rem;
		display: flex;
		justify-content: space-between;
		align-items: center;
	}
	.info-label { font-size: 0.75rem; color: #94a3b8; }
	.info-value { font-size: 0.85rem; font-weight: 600; }

	.brand-alert {
		background: rgba(239, 68, 68, 0.1);
		border: 1px solid rgba(239, 68, 68, 0.2);
		border-radius: 0.5rem;
		padding: 0.75rem;
	}
	.brand-header {
		display: flex;
		align-items: center;
		gap: 0.4rem;
		margin-bottom: 0.5rem;
	}
	.brand-icon { font-size: 1rem; }
	.brand-title { font-size: 0.85rem; font-weight: 600; color: #fca5a5; }
	.brand-details {
		display: flex;
		gap: 0.75rem;
		align-items: center;
	}
	.brand-name { font-weight: 700; color: #f87171; font-size: 1rem; }
	.brand-category {
		font-size: 0.75rem;
		padding: 0.15rem 0.5rem;
		border-radius: 0.375rem;
		background: rgba(168, 85, 247, 0.2);
		color: #c4b5fd;
	}
	.brand-confidence {
		font-size: 0.75rem;
		color: #facc15;
	}

	.similar-section { margin-top: 0.5rem; }
	.sub-title {
		font-size: 0.85rem;
		font-weight: 600;
		color: #f1f5f9;
		margin: 0 0 0.5rem;
	}
	.similar-list {
		display: flex;
		flex-direction: column;
		gap: 0.35rem;
	}
	.similar-item {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		padding: 0.4rem 0.6rem;
		background: rgba(15, 23, 42, 0.6);
		border: 1px solid rgba(148, 163, 184, 0.1);
		border-radius: 0.375rem;
		font-size: 0.8rem;
	}
	.similar-domain { color: #60a5fa; flex: 1; }
	.similar-type { color: #94a3b8; font-size: 0.7rem; }

	.risk-badge {
		font-size: 0.65rem;
		padding: 0.15rem 0.4rem;
		border-radius: 0.25rem;
		font-weight: 600;
		text-transform: uppercase;
	}

	.chars-table {
		display: flex;
		flex-direction: column;
	}
	.table-header {
		display: grid;
		grid-template-columns: 50px 40px 80px 1fr 40px 100px 60px;
		gap: 0.5rem;
		padding: 0.5rem 0.75rem;
		border-bottom: 1px solid rgba(148, 163, 184, 0.15);
		font-size: 0.7rem;
		color: #64748b;
		text-transform: uppercase;
		letter-spacing: 0.05em;
	}
	.table-row {
		display: grid;
		grid-template-columns: 50px 40px 80px 1fr 40px 100px 60px;
		gap: 0.5rem;
		padding: 0.5rem 0.75rem;
		border-bottom: 1px solid rgba(148, 163, 184, 0.05);
		align-items: center;
		font-size: 0.8rem;
	}

	.category-badge {
		font-size: 0.65rem;
		padding: 0.15rem 0.4rem;
		border-radius: 0.25rem;
	}

	.variants-header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		margin-bottom: 0.75rem;
		font-size: 0.8rem;
		color: #94a3b8;
	}
	.variants-list {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
		max-height: 500px;
		overflow-y: auto;
	}
	.variant-item {
		background: rgba(15, 23, 42, 0.6);
		border: 1px solid rgba(148, 163, 184, 0.1);
		border-radius: 0.5rem;
		padding: 0.6rem 0.75rem;
	}
	.variant-main {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		margin-bottom: 0.25rem;
	}
	.variant-domain { color: #60a5fa; flex: 1; font-size: 0.85rem; }
	.variant-punycode {
		font-size: 0.7rem;
		color: #facc15;
		margin-bottom: 0.25rem;
	}
	.variant-subs {
		display: flex;
		flex-wrap: wrap;
		gap: 0.25rem;
	}
	.sub-badge {
		font-size: 0.65rem;
		padding: 0.1rem 0.35rem;
		border-radius: 0.25rem;
		background: rgba(15, 23, 42, 0.8);
		color: #94a3b8;
	}
	.registered-badge {
		font-size: 0.65rem;
		padding: 0.1rem 0.35rem;
		border-radius: 0.25rem;
		background: rgba(239, 68, 68, 0.2);
		color: #f87171;
	}
	.unregistered-badge {
		font-size: 0.65rem;
		padding: 0.1rem 0.35rem;
		border-radius: 0.25rem;
		background: rgba(16, 185, 129, 0.15);
		color: #6ee7b7;
	}

	.scripts-section {
		display: flex;
		flex-direction: column;
		gap: 0.75rem;
	}
	.script-alert {
		padding: 0.6rem 0.75rem;
		border-radius: 0.375rem;
		font-size: 0.8rem;
		color: #e2e8f0;
	}
	.scripts-grid {
		display: grid;
		grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
		gap: 0.5rem;
	}
	.script-card {
		background: rgba(15, 23, 42, 0.6);
		border: 1px solid rgba(148, 163, 184, 0.15);
		border-radius: 0.5rem;
		padding: 0.6rem;
		text-align: center;
	}
	.script-name { font-weight: 600; color: #f1f5f9; font-size: 0.85rem; }
	.script-count { font-size: 0.75rem; color: #94a3b8; margin-top: 0.15rem; }
	.script-warning { font-size: 0.65rem; color: #f87171; margin-top: 0.25rem; }

	.batch-list {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
	}
	.batch-item {
		background: rgba(15, 23, 42, 0.6);
		border-radius: 0.5rem;
		padding: 0.6rem 0.75rem;
	}
	.batch-domain {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		margin-bottom: 0.25rem;
	}
	.batch-summary { font-size: 0.75rem; color: #94a3b8; }

	.empty-state {
		text-align: center;
		padding: 3rem 1rem;
	}
	.empty-icon { font-size: 3rem; margin-bottom: 1rem; }
	.empty-text { font-size: 1rem; color: #94a3b8; margin-bottom: 0.5rem; }
	.empty-sub { font-size: 0.8rem; color: #64748b; }

	@media (max-width: 768px) {
		.content-grid {
			grid-template-columns: 1fr;
		}
		.stat-grid {
			grid-template-columns: repeat(2, 1fr);
		}
		.table-header, .table-row {
			grid-template-columns: 40px 35px 70px 1fr 35px 80px 50px;
			font-size: 0.7rem;
		}
	}
</style>
