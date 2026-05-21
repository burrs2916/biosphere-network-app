<script lang="ts">
	import { tr } from '$lib/i18n';
	import ToolHistory from '$lib/components/ToolHistory.svelte';
	import ToolHelp from '$lib/components/ToolHelp.svelte';

	interface CloudFinding {
		severity: string;
		category: string;
		resource: string;
		description: string;
		recommendation: string;
		compliance: string[];
	}

	interface CloudAuditResult {
		success: boolean;
		provider: string;
		region: string;
		findings: CloudFinding[];
		checks_performed: number;
		iam_findings: CloudFinding[];
		storage_findings: CloudFinding[];
		network_findings: CloudFinding[];
		logging_findings: CloudFinding[];
		encryption_findings: CloudFinding[];
		compute_findings: CloudFinding[];
		summary: string;
	}

	let provider = $state('aws');
	let region = $state('us-east-1');
	let accessKey = $state('');
	let secretKey = $state('');
	let checkIam = $state(true);
	let checkS3 = $state(true);
	let checkNetwork = $state(true);
	let checkLogging = $state(true);
	let checkEncryption = $state(true);
	let checkCompute = $state(true);
	let result: CloudAuditResult | null = $state(null as CloudAuditResult | null);
	let error = $state('');
	let processing = $state(false);
	let activeMainTab = $state('analyze');
	let activeResultTab = $state('overview');
	let severityFilter = $state('all');
	let categoryFilter = $state('all');
	let historyComponent: ToolHistory = $state(null!);

	let criticalCount = $derived(result?.findings.filter(f => f.severity === 'critical').length ?? 0);
	let highCount = $derived(result?.findings.filter(f => f.severity === 'high').length ?? 0);
	let mediumCount = $derived(result?.findings.filter(f => f.severity === 'medium').length ?? 0);
	let lowCount = $derived(result?.findings.filter(f => f.severity === 'low').length ?? 0);
	let infoCount = $derived(result?.findings.filter(f => f.severity === 'info').length ?? 0);

	let filteredFindings = $derived(() => {
		if (!result) return [];
		let findings = result.findings;
		if (severityFilter !== 'all') {
			findings = findings.filter(f => f.severity === severityFilter);
		}
		if (categoryFilter !== 'all') {
			findings = findings.filter(f => f.category === categoryFilter);
		}
		return findings;
	});

	let categories = $derived(() => {
		if (!result) return [];
		const cats = new Set(result.findings.map(f => f.category));
		return Array.from(cats);
	});

	async function audit() {
		processing = true;
		error = '';
		result = null;
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			result = await invoke<CloudAuditResult>('audit_cloud_command', {
				config: {
					provider,
					region: region.trim(),
					access_key: accessKey.trim(),
					secret_key: secretKey.trim(),
					check_iam: checkIam,
					check_storage: checkS3,
					check_network: checkNetwork,
					check_logging: checkLogging,
					check_encryption: checkEncryption,
					check_compute: checkCompute,
					timeout: 30
				}
			});
			if (result && historyComponent) {
				await historyComponent.saveHistory(
					`${provider} (${region})`,
					JSON.stringify(result),
					result.summary,
					'completed'
				);
			}
		} catch (e: any) {
			error = e.toString();
			if (historyComponent) {
				await historyComponent.saveHistory(provider, JSON.stringify({ error: e.toString() }), undefined, 'failed');
			}
		} finally {
			processing = false;
		}
	}

	function clearAll() {
		accessKey = '';
		secretKey = '';
		result = null;
		error = '';
		severityFilter = 'all';
		categoryFilter = 'all';
		activeResultTab = 'overview';
	}

	function getSeverityColor(severity: string): string {
		switch (severity) {
			case 'critical': return '#dc2626';
			case 'high': return '#f97316';
			case 'medium': return '#eab308';
			case 'low': return '#22c55e';
			case 'info': return '#3b82f6';
			default: return '#6b7280';
		}
	}

	function getSeverityBg(severity: string): string {
		switch (severity) {
			case 'critical': return 'rgba(220, 38, 38, 0.15)';
			case 'high': return 'rgba(249, 115, 22, 0.15)';
			case 'medium': return 'rgba(234, 179, 8, 0.15)';
			case 'low': return 'rgba(34, 197, 94, 0.15)';
			case 'info': return 'rgba(59, 130, 246, 0.15)';
			default: return 'rgba(107, 114, 128, 0.15)';
		}
	}

	function getSeverityLabel(severity: string): string {
		switch (severity) {
			case 'critical': return $tr('cloudAudit.severity.critical');
			case 'high': return $tr('cloudAudit.severity.high');
			case 'medium': return $tr('cloudAudit.severity.medium');
			case 'low': return $tr('cloudAudit.severity.low');
			case 'info': return $tr('cloudAudit.severity.info');
			default: return severity;
		}
	}

	function getCategoryIcon(category: string): string {
		switch (category) {
			case 'IAM': return '👤';
			case '存储': case 'Storage': return '💾';
			case '网络': case 'Network': return '🌐';
			case '日志': case 'Logging': return '📋';
			case '加密': case 'Encryption': return '🔐';
			case '计算': case 'Compute': return '🖥️';
			default: return '📦';
		}
	}

	function getProviderIcon(p: string): string {
		switch (p) {
			case 'aws': return '🟠';
			case 'azure': return '🔵';
			case 'gcp': return '🟡';
			case 'aliyun': return '🟢';
			default: return '☁️';
		}
	}

	function getProviderLabel(p: string): string {
		switch (p) {
			case 'aws': return 'AWS';
			case 'azure': return 'Azure';
			case 'gcp': return 'GCP';
			case 'aliyun': return $tr('cloudAudit.providerAliyun');
			default: return p;
		}
	}

	function getCategoryFindings(category: string): CloudFinding[] {
		if (!result) return [];
		switch (category) {
			case 'iam': return result.iam_findings;
			case 'storage': return result.storage_findings;
			case 'network': return result.network_findings;
			case 'logging': return result.logging_findings;
			case 'encryption': return result.encryption_findings;
			case 'compute': return result.compute_findings;
			default: return [];
		}
	}

	function getCategoryCount(category: string): number {
		return getCategoryFindings(category).length;
	}

	function exportResult() {
		if (!result) return;
		const blob = new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' });
		const url = URL.createObjectURL(blob);
		const a = document.createElement('a');
		a.href = url;
		a.download = `cloud-audit-${result.provider}-${result.region}-${Date.now()}.json`;
		a.click();
		URL.revokeObjectURL(url);
	}

	function exportFindingsCsv() {
		if (!result || result.findings.length === 0) return;
		const headers = ['Severity', 'Category', 'Resource', 'Description', 'Recommendation', 'Compliance'];
		const rows = result.findings.map(f => [
			f.severity,
			f.category,
			f.resource,
			f.description,
			f.recommendation,
			f.compliance.join('; ')
		]);
		const csv = [headers.join(','), ...rows.map(r => r.map(c => `"${c.replace(/"/g, '""')}"`).join(','))].join('\n');
		const blob = new Blob([csv], { type: 'text/csv' });
		const url = URL.createObjectURL(blob);
		const a = document.createElement('a');
		a.href = url;
		a.download = `cloud-audit-${result.provider}-${result.region}-${Date.now()}.csv`;
		a.click();
		URL.revokeObjectURL(url);
	}
</script>

<div class="nd-page">
	<div class="page-header">
		<div class="header-left">
			<a href="/" class="back-link">{$tr('common.backToHome')}</a>
			<h1 class="page-title">☁️ {$tr('cloudAudit.title')}</h1>
			<p class="page-subtitle">{$tr('cloudAudit.subtitle')}</p>
		</div>
	</div>

	<div class="tabs">
		<button class="tab-btn {activeMainTab === 'analyze' ? 'active' : ''}" onclick={() => activeMainTab = 'analyze'}>
			<span class="tab-icon">🔍</span> {$tr('cloudAudit.mainTabs.audit')}
		</button>
		<button class="tab-btn {activeMainTab === 'history' ? 'active' : ''}" onclick={() => activeMainTab = 'history'}>
			<span class="tab-icon">📋</span> {$tr('cloudAudit.mainTabs.history')}
		</button>
		<button class="tab-btn {activeMainTab === 'help' ? 'active' : ''}" onclick={() => activeMainTab = 'help'}>
			<span class="tab-icon">📖</span> {$tr('cloudAudit.mainTabs.help')}
		</button>
	</div>

	{#if activeMainTab === 'analyze'}
		<div class="content-grid">
			<div class="input-section">
				<div class="section-card">
					<h2 class="section-title">{$tr('cloudAudit.config.title')}</h2>

					<div class="form-group">
						<label class="form-label">☁️ {$tr('cloudAudit.config.provider')}</label>
						<div class="provider-grid">
							<button class="provider-btn {provider === 'aws' ? 'active' : ''}" onclick={() => provider = 'aws'} disabled={processing}>
								<span class="provider-icon">🟠</span>
								<span class="provider-name">AWS</span>
							</button>
							<button class="provider-btn {provider === 'azure' ? 'active' : ''}" onclick={() => provider = 'azure'} disabled={processing}>
								<span class="provider-icon">🔵</span>
								<span class="provider-name">Azure</span>
							</button>
							<button class="provider-btn {provider === 'gcp' ? 'active' : ''}" onclick={() => provider = 'gcp'} disabled={processing}>
								<span class="provider-icon">🟡</span>
								<span class="provider-name">GCP</span>
							</button>
							<button class="provider-btn {provider === 'aliyun' ? 'active' : ''}" onclick={() => provider = 'aliyun'} disabled={processing}>
								<span class="provider-icon">🟢</span>
								<span class="provider-name">{$tr('cloudAudit.providerAliyun')}</span>
							</button>
						</div>
					</div>

					<div class="form-group">
						<label class="form-label">🌍 {$tr('cloudAudit.config.region')}</label>
						<input type="text" bind:value={region} placeholder="us-east-1" class="form-input" disabled={processing} />
					</div>

					<div class="form-group">
						<label class="form-label">🔑 {$tr('cloudAudit.config.accessKey')}</label>
						<input type="password" bind:value={accessKey} placeholder="AKIA..." class="form-input" disabled={processing} />
					</div>

					<div class="form-group">
						<label class="form-label">🔒 {$tr('cloudAudit.config.secretKey')}</label>
						<input type="password" bind:value={secretKey} placeholder="wJalrXU..." class="form-input" disabled={processing} />
					</div>

					<div class="form-group">
						<label class="form-label">✅ {$tr('cloudAudit.config.checkTypes')}</label>
						<div class="check-grid">
							<label class="check-label">
								<input type="checkbox" bind:checked={checkIam} disabled={processing} />
								<span>👤 IAM</span>
							</label>
							<label class="check-label">
								<input type="checkbox" bind:checked={checkS3} disabled={processing} />
								<span>💾 {$tr('cloudAudit.check.storage')}</span>
							</label>
							<label class="check-label">
								<input type="checkbox" bind:checked={checkNetwork} disabled={processing} />
								<span>🌐 {$tr('cloudAudit.check.network')}</span>
							</label>
							<label class="check-label">
								<input type="checkbox" bind:checked={checkLogging} disabled={processing} />
								<span>📋 {$tr('cloudAudit.check.logging')}</span>
							</label>
							<label class="check-label">
								<input type="checkbox" bind:checked={checkEncryption} disabled={processing} />
								<span>🔐 {$tr('cloudAudit.check.encryption')}</span>
							</label>
							<label class="check-label">
								<input type="checkbox" bind:checked={checkCompute} disabled={processing} />
								<span>🖥️ {$tr('cloudAudit.check.compute')}</span>
							</label>
						</div>
					</div>

					{#if !accessKey && !secretKey}
						<div class="info-card">
							<div class="info-icon">💡</div>
							<div class="info-text">
								<strong>{$tr('cloudAudit.info.cliMode')}</strong>
								<p>{$tr('cloudAudit.info.cliModeDesc')}</p>
							</div>
						</div>
					{/if}

					<div class="button-group">
						<button class="btn btn-primary" onclick={audit} disabled={processing}>
							{#if processing}⏳ {$tr('cloudAudit.scanning')}{:else}☁️ {$tr('cloudAudit.scan')}{/if}
						</button>
						<button class="btn btn-secondary" onclick={clearAll} disabled={processing}>
							🗑️ {$tr('cloudAudit.clear')}
						</button>
					</div>
				</div>
			</div>

			<div class="result-section">
				<div class="section-card">
					<h2 class="section-title">{$tr('cloudAudit.result.title')}</h2>

					{#if error}
						<div class="error-card">
							<div class="error-icon">⚠️</div>
							<div class="error-content"><p>{error}</p></div>
						</div>
					{:else if result}
						<div class="result-summary">
							<span class="provider-badge">{getProviderIcon(result.provider)} {getProviderLabel(result.provider)}</span>
							<span class="region-badge">🌍 {result.region}</span>
							<span class="checks-badge">🔍 {$tr('cloudAudit.stats.checks')}: {result.checks_performed}</span>
						</div>

						<div class="severity-stats">
							<button class="severity-stat {severityFilter === 'all' ? 'active' : ''}" onclick={() => severityFilter = 'all'}>
								<span class="stat-number">{result.findings.length}</span>
								<span class="stat-label">{$tr('cloudAudit.stats.total')}</span>
							</button>
							<button class="severity-stat critical {severityFilter === 'critical' ? 'active' : ''}" onclick={() => severityFilter = severityFilter === 'critical' ? 'all' : 'critical'}>
								<span class="stat-number">{criticalCount}</span>
								<span class="stat-label">{$tr('cloudAudit.severity.critical')}</span>
							</button>
							<button class="severity-stat high {severityFilter === 'high' ? 'active' : ''}" onclick={() => severityFilter = severityFilter === 'high' ? 'all' : 'high'}>
								<span class="stat-number">{highCount}</span>
								<span class="stat-label">{$tr('cloudAudit.severity.high')}</span>
							</button>
							<button class="severity-stat medium {severityFilter === 'medium' ? 'active' : ''}" onclick={() => severityFilter = severityFilter === 'medium' ? 'all' : 'medium'}>
								<span class="stat-number">{mediumCount}</span>
								<span class="stat-label">{$tr('cloudAudit.severity.medium')}</span>
							</button>
							<button class="severity-stat low {severityFilter === 'low' ? 'active' : ''}" onclick={() => severityFilter = severityFilter === 'low' ? 'all' : 'low'}>
								<span class="stat-number">{lowCount}</span>
								<span class="stat-label">{$tr('cloudAudit.severity.low')}</span>
							</button>
							<button class="severity-stat info {severityFilter === 'info' ? 'active' : ''}" onclick={() => severityFilter = severityFilter === 'info' ? 'all' : 'info'}>
								<span class="stat-number">{infoCount}</span>
								<span class="stat-label">{$tr('cloudAudit.severity.info')}</span>
							</button>
						</div>

						<div class="result-toolbar">
							<div class="result-tabs">
								<button class="result-tab-btn {activeResultTab === 'overview' ? 'active' : ''}" onclick={() => activeResultTab = 'overview'}>
									📊 {$tr('cloudAudit.resultTabs.overview')}
								</button>
								<button class="result-tab-btn {activeResultTab === 'byCategory' ? 'active' : ''}" onclick={() => activeResultTab = 'byCategory'}>
									📂 {$tr('cloudAudit.resultTabs.byCategory')}
								</button>
								<button class="result-tab-btn {activeResultTab === 'all' ? 'active' : ''}" onclick={() => activeResultTab = 'all'}>
									📋 {$tr('cloudAudit.resultTabs.allFindings')}
								</button>
							</div>
							<div class="toolbar-actions">
								<select bind:value={categoryFilter} class="filter-select">
									<option value="all">{$tr('cloudAudit.filter.allCategories')}</option>
									{#each categories() as cat}
										<option value={cat}>{getCategoryIcon(cat)} {cat}</option>
									{/each}
								</select>
								<button class="btn-icon" onclick={exportResult} title="Export JSON">📥 JSON</button>
								<button class="btn-icon" onclick={exportFindingsCsv} title="Export CSV">📊 CSV</button>
							</div>
						</div>

						{#if activeResultTab === 'overview'}
							<div class="category-overview">
								{#each ['iam', 'storage', 'network', 'logging', 'encryption', 'compute'] as cat}
									{@const count = getCategoryCount(cat)}
									{@const catFindings = getCategoryFindings(cat)}
									{@const catCritical = catFindings.filter(f => f.severity === 'critical').length}
									{@const catHigh = catFindings.filter(f => f.severity === 'high').length}
									<button class="category-card" onclick={() => { categoryFilter = cat === 'iam' ? 'IAM' : cat === 'storage' ? '存储' : cat === 'network' ? '网络' : cat === 'logging' ? '日志' : cat === 'encryption' ? '加密' : '计算'; activeResultTab = 'all'; }}>
										<div class="category-header">
											<span class="category-icon">{getCategoryIcon(cat === 'iam' ? 'IAM' : cat === 'storage' ? '存储' : cat === 'network' ? '网络' : cat === 'logging' ? '日志' : cat === 'encryption' ? '加密' : '计算')}</span>
											<span class="category-name">{$tr(`cloudAudit.category.${cat}`)}</span>
										</div>
										<div class="category-count">{count} {$tr('cloudAudit.stats.findings')}</div>
										{#if catCritical > 0 || catHigh > 0}
											<div class="category-alert">
												{#if catCritical > 0}<span class="mini-badge critical">{catCritical} C</span>{/if}
												{#if catHigh > 0}<span class="mini-badge high">{catHigh} H</span>{/if}
											</div>
										{/if}
									</button>
								{/each}
							</div>
						{:else if activeResultTab === 'byCategory'}
							<div class="category-details">
								{#each ['iam', 'storage', 'network', 'logging', 'encryption', 'compute'] as cat}
									{@const catFindings = getCategoryFindings(cat)}
									{#if catFindings.length > 0}
										<details class="category-group" open>
											<summary class="category-summary">
												<span>{getCategoryIcon(cat === 'iam' ? 'IAM' : cat === 'storage' ? '存储' : cat === 'network' ? '网络' : cat === 'logging' ? '日志' : cat === 'encryption' ? '加密' : '计算')} {$tr(`cloudAudit.category.${cat}`)}</span>
												<span class="category-badge">{catFindings.length}</span>
											</summary>
											<div class="finding-list">
												{#each catFindings as finding, i}
													{@render findingCard(finding, i)}
												{/each}
											</div>
										</details>
									{/if}
								{/each}
							</div>
						{:else}
							{#if filteredFindings().length > 0}
								<div class="finding-list">
									{#each filteredFindings() as finding, i}
										{@render findingCard(finding, i)}
									{/each}
								</div>
							{:else}
								<div class="empty-state">
									<div class="empty-icon">🔍</div>
									<p>{$tr('cloudAudit.result.noMatching')}</p>
								</div>
							{/if}
						{/if}
					{:else}
						<div class="empty-state">
							<div class="empty-icon">☁️</div>
							<p>{$tr('cloudAudit.result.noResults')}</p>
						</div>
					{/if}
				</div>
			</div>
		</div>
	{:else if activeMainTab === 'history'}
		<div class="section-card">
			<ToolHistory toolType="cloud_audit" toolName={$tr('cloudAudit.title')} bind:this={historyComponent} />
		</div>
	{:else if activeMainTab === 'help'}
		<div class="section-card">
			<ToolHelp toolType="cloud_audit" />
		</div>
	{/if}
</div>

{#snippet findingCard(finding: CloudFinding, i: number)}
	<div class="finding-card" style="border-left-color: {getSeverityColor(finding.severity)}">
		<div class="finding-header">
			<span class="finding-index">#{i + 1}</span>
			<span class="finding-category">{getCategoryIcon(finding.category)} {finding.category}</span>
			<span class="finding-severity" style="background: {getSeverityBg(finding.severity)}; color: {getSeverityColor(finding.severity)}">
				{getSeverityLabel(finding.severity)}
			</span>
		</div>
		<div class="finding-resource">📦 {finding.resource}</div>
		<div class="finding-desc">{finding.description}</div>
		<div class="finding-rec">💡 {finding.recommendation}</div>
		{#if finding.compliance.length > 0}
			<div class="finding-compliance">
				{#each finding.compliance as std}
					<span class="compliance-badge">{std}</span>
				{/each}
			</div>
		{/if}
	</div>
{/snippet}

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

	.form-group { margin-bottom: 0.75rem; }

	.form-label {
		display: block;
		font-size: 0.8rem;
		color: #94a3b8;
		margin-bottom: 0.35rem;
		font-weight: 500;
	}

	.form-input {
		width: 100%;
		padding: 0.5rem 0.75rem;
		border-radius: 0.5rem;
		border: 1px solid rgba(168, 85, 247, 0.2);
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

	.provider-grid {
		display: grid;
		grid-template-columns: 1fr 1fr;
		gap: 0.5rem;
	}

	.provider-btn {
		display: flex;
		align-items: center;
		justify-content: center;
		gap: 0.4rem;
		padding: 0.5rem;
		border-radius: 0.5rem;
		border: 1px solid rgba(168, 85, 247, 0.2);
		background: rgba(15, 23, 42, 0.6);
		color: #94a3b8;
		cursor: pointer;
		font-size: 0.8rem;
		transition: all 0.2s;
	}

	.provider-btn.active {
		border-color: #a855f7;
		background: rgba(168, 85, 247, 0.15);
		color: #f1f5f9;
	}

	.provider-btn:hover:not(.active) {
		border-color: rgba(168, 85, 247, 0.4);
		background: rgba(168, 85, 247, 0.08);
	}

	.provider-icon { font-size: 0.9rem; }
	.provider-name { font-weight: 500; }

	.check-grid {
		display: grid;
		grid-template-columns: 1fr 1fr;
		gap: 0.4rem;
	}

	.check-label {
		display: flex;
		align-items: center;
		gap: 0.4rem;
		font-size: 0.8rem;
		color: #cbd5e1;
		cursor: pointer;
		padding: 0.35rem 0.5rem;
		border-radius: 0.4rem;
		transition: background 0.2s;
	}

	.check-label:hover { background: rgba(168, 85, 247, 0.08); }

	.check-label input[type="checkbox"] {
		accent-color: #a855f7;
	}

	.info-card {
		display: flex;
		align-items: flex-start;
		gap: 0.75rem;
		padding: 0.75rem;
		background: rgba(59, 130, 246, 0.1);
		border: 1px solid rgba(59, 130, 246, 0.2);
		border-radius: 0.5rem;
		margin-bottom: 0.75rem;
	}

	.info-icon { font-size: 1.2rem; flex-shrink: 0; }

	.info-text {
		font-size: 0.8rem;
		color: #93c5fd;
	}

	.info-text strong { color: #60a5fa; }
	.info-text p { margin: 0.2rem 0 0; }

	.button-group {
		display: flex;
		gap: 0.5rem;
	}

	.btn {
		padding: 0.5rem 1rem;
		border-radius: 0.5rem;
		border: none;
		cursor: pointer;
		font-size: 0.85rem;
		transition: all 0.2s;
	}

	.btn-primary {
		background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%);
		color: white;
		font-weight: 500;
	}

	.btn-primary:hover:not(:disabled) {
		box-shadow: 0 2px 8px rgba(168, 85, 247, 0.4);
		transform: translateY(-1px);
	}

	.btn-primary:disabled { opacity: 0.5; cursor: not-allowed; }

	.btn-secondary {
		background: rgba(15, 23, 42, 0.8);
		color: #94a3b8;
		border: 1px solid rgba(168, 85, 247, 0.2);
	}

	.btn-secondary:hover:not(:disabled) {
		border-color: rgba(168, 85, 247, 0.4);
		color: #c4b5fd;
	}

	.btn-icon {
		padding: 0.3rem 0.6rem;
		border-radius: 0.4rem;
		border: 1px solid rgba(168, 85, 247, 0.2);
		background: rgba(15, 23, 42, 0.6);
		color: #94a3b8;
		cursor: pointer;
		font-size: 0.75rem;
		transition: all 0.2s;
	}

	.btn-icon:hover {
		border-color: #a855f7;
		color: #c4b5fd;
	}

	.error-card {
		display: flex;
		align-items: center;
		gap: 0.75rem;
		padding: 0.75rem;
		background: rgba(239, 68, 68, 0.1);
		border: 1px solid rgba(239, 68, 68, 0.2);
		border-radius: 0.5rem;
	}

	.error-icon { font-size: 1.2rem; }
	.error-content { color: #fca5a5; font-size: 0.85rem; }

	.result-summary {
		display: flex;
		align-items: center;
		gap: 0.75rem;
		padding: 0.75rem;
		border-radius: 0.5rem;
		margin-bottom: 1rem;
		background: rgba(168, 85, 247, 0.1);
		border: 1px solid rgba(168, 85, 247, 0.2);
		flex-wrap: wrap;
	}

	.provider-badge, .region-badge, .checks-badge {
		padding: 0.25rem 0.6rem;
		border-radius: 1rem;
		font-size: 0.8rem;
		background: rgba(15, 23, 42, 0.6);
		border: 1px solid rgba(168, 85, 247, 0.2);
		color: #c4b5fd;
	}

	.severity-stats {
		display: grid;
		grid-template-columns: repeat(6, 1fr);
		gap: 0.5rem;
		margin-bottom: 1rem;
	}

	.severity-stat {
		display: flex;
		flex-direction: column;
		align-items: center;
		padding: 0.5rem;
		border-radius: 0.5rem;
		border: 1px solid rgba(168, 85, 247, 0.15);
		background: rgba(15, 23, 42, 0.4);
		cursor: pointer;
		transition: all 0.2s;
	}

	.severity-stat:hover { border-color: rgba(168, 85, 247, 0.4); }
	.severity-stat.active { border-color: #a855f7; background: rgba(168, 85, 247, 0.15); }

	.severity-stat.critical .stat-number { color: #dc2626; }
	.severity-stat.high .stat-number { color: #f97316; }
	.severity-stat.medium .stat-number { color: #eab308; }
	.severity-stat.low .stat-number { color: #22c55e; }
	.severity-stat.info .stat-number { color: #3b82f6; }

	.stat-number {
		font-size: 1.2rem;
		font-weight: 700;
		color: #f1f5f9;
	}

	.stat-label {
		font-size: 0.65rem;
		color: #94a3b8;
		margin-top: 0.15rem;
	}

	.result-toolbar {
		display: flex;
		justify-content: space-between;
		align-items: center;
		margin-bottom: 1rem;
		gap: 0.5rem;
		flex-wrap: wrap;
	}

	.result-tabs {
		display: flex;
		gap: 0.25rem;
		background: rgba(15, 23, 42, 0.6);
		border: 1px solid rgba(168, 85, 247, 0.15);
		border-radius: 0.5rem;
		padding: 0.2rem;
	}

	.result-tab-btn {
		padding: 0.35rem 0.7rem;
		border: none;
		border-radius: 0.35rem;
		background: transparent;
		cursor: pointer;
		font-size: 0.75rem;
		color: #94a3b8;
		transition: all 0.2s;
	}

	.result-tab-btn.active {
		background: rgba(168, 85, 247, 0.2);
		color: #c4b5fd;
		font-weight: 500;
	}

	.result-tab-btn:hover:not(.active) { color: #c4b5fd; }

	.toolbar-actions {
		display: flex;
		gap: 0.4rem;
		align-items: center;
	}

	.filter-select {
		padding: 0.3rem 0.5rem;
		border-radius: 0.4rem;
		border: 1px solid rgba(168, 85, 247, 0.2);
		background: rgba(15, 23, 42, 0.8);
		color: #c4b5fd;
		font-size: 0.75rem;
	}

	.category-overview {
		display: grid;
		grid-template-columns: repeat(3, 1fr);
		gap: 0.75rem;
	}

	.category-card {
		display: flex;
		flex-direction: column;
		gap: 0.4rem;
		padding: 0.75rem;
		border-radius: 0.5rem;
		border: 1px solid rgba(168, 85, 247, 0.15);
		background: rgba(15, 23, 42, 0.4);
		cursor: pointer;
		transition: all 0.2s;
		text-align: left;
		color: inherit;
	}

	.category-card:hover {
		border-color: rgba(168, 85, 247, 0.4);
		background: rgba(168, 85, 247, 0.08);
	}

	.category-header {
		display: flex;
		align-items: center;
		gap: 0.4rem;
	}

	.category-icon { font-size: 1rem; }
	.category-name { font-size: 0.85rem; font-weight: 500; color: #f1f5f9; }
	.category-count { font-size: 0.75rem; color: #94a3b8; }

	.category-alert {
		display: flex;
		gap: 0.3rem;
	}

	.mini-badge {
		padding: 0.1rem 0.35rem;
		border-radius: 0.25rem;
		font-size: 0.65rem;
		font-weight: 600;
	}

	.mini-badge.critical { background: rgba(220, 38, 38, 0.2); color: #fca5a5; }
	.mini-badge.high { background: rgba(249, 115, 22, 0.2); color: #fdba74; }

	.category-details {
		display: flex;
		flex-direction: column;
		gap: 0.75rem;
	}

	.category-group {
		border: 1px solid rgba(168, 85, 247, 0.15);
		border-radius: 0.5rem;
		overflow: hidden;
	}

	.category-summary {
		display: flex;
		justify-content: space-between;
		align-items: center;
		padding: 0.6rem 0.75rem;
		background: rgba(15, 23, 42, 0.6);
		cursor: pointer;
		font-size: 0.85rem;
		color: #f1f5f9;
		font-weight: 500;
	}

	.category-badge {
		padding: 0.15rem 0.5rem;
		border-radius: 1rem;
		background: rgba(168, 85, 247, 0.2);
		color: #c4b5fd;
		font-size: 0.75rem;
	}

	.finding-list {
		display: flex;
		flex-direction: column;
		gap: 0.6rem;
	}

	.finding-card {
		padding: 0.75rem;
		background: rgba(15, 23, 42, 0.4);
		border-radius: 0.5rem;
		border-left: 3px solid;
		transition: background 0.2s;
	}

	.finding-card:hover { background: rgba(15, 23, 42, 0.6); }

	.finding-header {
		display: flex;
		gap: 0.5rem;
		align-items: center;
		margin-bottom: 0.4rem;
		flex-wrap: wrap;
	}

	.finding-index {
		font-weight: 600;
		font-size: 0.8rem;
		color: #94a3b8;
	}

	.finding-category {
		padding: 0.1rem 0.5rem;
		background: rgba(168, 85, 247, 0.15);
		border-radius: 0.25rem;
		font-size: 0.7rem;
		color: #c4b5fd;
	}

	.finding-severity {
		padding: 0.1rem 0.5rem;
		border-radius: 0.25rem;
		font-size: 0.7rem;
		font-weight: 600;
	}

	.finding-resource {
		font-family: 'SF Mono', 'Fira Code', monospace;
		font-size: 0.8rem;
		color: #e2e8f0;
		margin-bottom: 0.3rem;
	}

	.finding-desc {
		font-size: 0.8rem;
		color: #94a3b8;
		margin-bottom: 0.3rem;
	}

	.finding-rec {
		font-size: 0.8rem;
		color: #86efac;
	}

	.finding-compliance {
		display: flex;
		gap: 0.3rem;
		flex-wrap: wrap;
		margin-top: 0.4rem;
	}

	.compliance-badge {
		padding: 0.1rem 0.4rem;
		border-radius: 0.25rem;
		background: rgba(99, 102, 241, 0.15);
		color: #a5b4fc;
		font-size: 0.65rem;
		border: 1px solid rgba(99, 102, 241, 0.2);
	}

	.empty-state {
		text-align: center;
		padding: 3rem;
		color: #94a3b8;
	}

	.empty-icon {
		font-size: 3rem;
		margin-bottom: 0.75rem;
	}

	@media (max-width: 900px) {
		.content-grid {
			grid-template-columns: 1fr;
		}
		.severity-stats {
			grid-template-columns: repeat(3, 1fr);
		}
		.category-overview {
			grid-template-columns: repeat(2, 1fr);
		}
	}
</style>
