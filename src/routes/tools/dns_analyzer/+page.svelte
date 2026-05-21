<script lang="ts">
	import { tr } from '$lib/i18n';
	import { onMount } from 'svelte';
	import ToolHistory from '$lib/components/ToolHistory.svelte';
	import ToolHelp from '$lib/components/ToolHelp.svelte';

	interface DnsRecord {
		record_type: string;
		name: string;
		value: string;
		ttl: number;
		priority: number | null;
	}

	interface DnssecDetails {
		enabled: boolean;
		key_tags: number[];
		algorithms: string[];
		digest_types: string[];
	}

	interface ZoneTransferDetails {
		tested_nameservers: string[];
		vulnerable_nameservers: string[];
		transferred_records: DnsRecord[];
	}

	interface DnsSecurityIssue {
		severity: string;
		category: string;
		description: string;
		recommendation: string;
	}

	interface DnsAnalyzerResult {
		success: boolean;
		domain: string;
		nameservers: string[];
		dnssec_enabled: boolean;
		dnssec_details: DnssecDetails;
		zone_transfer_possible: boolean;
		zone_transfer_details: ZoneTransferDetails;
		records: DnsRecord[];
		security_issues: DnsSecurityIssue[];
		summary: string;
	}

	let domain = $state('');
	let nameserver = $state('');
	let checkDnssec = $state(true);
	let checkZoneTransfer = $state(true);
	let timeout = $state(5);
	let result: DnsAnalyzerResult | null = $state(null);
	let error = $state('');
	let processing = $state(false);
	let activeMainTab = $state('analyze');
	let activeResultTab = $state('overview');
	let recordFilter = $state('all');
	let historyComponent: ToolHistory = $state(null!);

	function getFilteredRecords(): DnsRecord[] {
		if (!result) return [];
		if (recordFilter === 'all') return result.records;
		return result.records.filter(r => r.record_type === recordFilter);
	}

	function getRecordTypes(): string[] {
		if (!result) return [];
		const types = new Set(result.records.map(r => r.record_type));
		return Array.from(types).sort();
	}

	function getSeverityColor(severity: string): string {
		switch (severity) {
			case 'high': return '#ef4444';
			case 'medium': return '#f59e0b';
			case 'low': return '#3b82f6';
			case 'info': return '#6b7280';
			default: return '#6b7280';
		}
	}

	function getSeverityLabel(severity: string): string {
		switch (severity) {
			case 'high': return $tr('dnsAnalyzer.severityHigh');
			case 'medium': return $tr('dnsAnalyzer.severityMedium');
			case 'low': return $tr('dnsAnalyzer.severityLow');
			case 'info': return $tr('dnsAnalyzer.severityInfo');
			default: return severity;
		}
	}

	function getRecordTypeColor(type: string): string {
		switch (type) {
			case 'A': return '#3b82f6';
			case 'AAAA': return '#8b5cf6';
			case 'MX': return '#f59e0b';
			case 'NS': return '#22c55e';
			case 'TXT': return '#06b6d4';
			case 'SOA': return '#f97316';
			case 'CNAME': return '#ec4899';
			case 'DS': return '#ef4444';
			case 'DNSKEY': return '#a855f7';
			case 'SRV': return '#14b8a6';
			case 'PTR': return '#64748b';
			default: return '#94a3b8';
		}
	}

	function getSecurityScore(): number {
		if (!result) return 0;
		let score = 100;
		for (const issue of result.security_issues) {
			switch (issue.severity) {
			case 'high': score -= 25; break;
			case 'medium': score -= 15; break;
			case 'low': score -= 5; break;
			}
		}
		if (result.dnssec_enabled) score = Math.min(score + 10, 100);
		return Math.max(score, 0);
	}

	function getSecurityScoreColor(score: number): string {
		if (score >= 80) return '#22c55e';
		if (score >= 60) return '#eab308';
		if (score >= 40) return '#f97316';
		return '#ef4444';
	}

	function getSecurityScoreLabel(score: number): string {
		if (score >= 80) return $tr('dnsAnalyzer.riskLow');
		if (score >= 60) return $tr('dnsAnalyzer.riskMedium');
		if (score >= 40) return $tr('dnsAnalyzer.riskHigh');
		return $tr('dnsAnalyzer.riskCritical');
	}

	async function analyze() {
		if (!domain.trim()) { error = $tr('dnsAnalyzer.domainRequired'); return; }
		processing = true; error = ''; result = null;
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			result = await invoke<DnsAnalyzerResult>('analyze_dns_command', {
				config: {
					domain: domain.trim(),
					nameserver: nameserver.trim() || null,
					check_dnssec: checkDnssec,
					check_zone_transfer: checkZoneTransfer,
					record_types: ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'SRV', 'PTR'],
					timeout
				}
			});
			if (result && historyComponent) {
				await historyComponent.saveHistory(domain.trim(), JSON.stringify(result), result.summary, 'completed');
			}
		} catch (e: any) {
			error = e.toString();
			if (historyComponent) {
				await historyComponent.saveHistory(domain.trim(), JSON.stringify({ error: e.toString() }), undefined, 'failed');
			}
		} finally { processing = false; }
	}

	function clearAll() {
		domain = '';
		nameserver = '';
		result = null;
		error = '';
		recordFilter = 'all';
		activeResultTab = 'overview';
	}

	function handleKeydown(e: KeyboardEvent) {
		if (e.key === 'Enter' && !processing && domain.trim()) {
			analyze();
		}
	}
</script>

<svelte:window onkeydown={handleKeydown} />

<div class="nd-page">
	<div class="page-header">
		<div class="header-left">
			<a href="/" class="back-link">{$tr('common.backToHome')}</a>
			<h1 class="page-title">🛡️ {$tr('dnsAnalyzer.title')}</h1>
			<p class="page-subtitle">{$tr('dnsAnalyzer.subtitle')}</p>
		</div>
	</div>

	<div class="tabs">
		<button class="tab-btn {activeMainTab === 'analyze' ? 'active' : ''}" onclick={() => activeMainTab = 'analyze'}>
			<span class="tab-icon">🔍</span> {$tr('dnsAnalyzer.analyze')}
		</button>
		<button class="tab-btn {activeMainTab === 'history' ? 'active' : ''}" onclick={() => activeMainTab = 'history'}>
			<span class="tab-icon">📋</span> {$tr('dnsAnalyzer.history')}
		</button>
		<button class="tab-btn {activeMainTab === 'help' ? 'active' : ''}" onclick={() => activeMainTab = 'help'}>
			<span class="tab-icon">📖</span> {$tr('dnsAnalyzer.help')}
		</button>
	</div>

	{#if activeMainTab === 'analyze'}
		<div class="content-grid">
			<div class="input-section">
				<div class="section-card">
					<h2 class="section-title">{$tr('dnsAnalyzer.configTitle')}</h2>
					<p class="section-desc">{$tr('dnsAnalyzer.configDesc')}</p>

					<div class="form-group">
						<label class="form-label">{$tr('dnsAnalyzer.domain')}</label>
						<input type="text" bind:value={domain} placeholder="example.com" class="form-input" disabled={processing} />
					</div>
					<div class="form-group">
						<label class="form-label">{$tr('dnsAnalyzer.nameserver')}</label>
						<input type="text" bind:value={nameserver} placeholder="8.8.8.8" class="form-input" disabled={processing} />
					</div>
					<div class="form-group">
						<label class="form-label">{$tr('dnsAnalyzer.timeout')}</label>
						<input type="number" bind:value={timeout} class="form-input" min="1" max="30" disabled={processing} />
					</div>
					<div class="form-group">
						<label class="checkbox-label">
							<input type="checkbox" bind:checked={checkDnssec} disabled={processing} />
							<span>{$tr('dnsAnalyzer.checkDnssec')}</span>
						</label>
					</div>
					<div class="form-group">
						<label class="checkbox-label">
							<input type="checkbox" bind:checked={checkZoneTransfer} disabled={processing} />
							<span>{$tr('dnsAnalyzer.checkZoneTransfer')}</span>
						</label>
					</div>
					<div class="button-group">
						<button class="btn-primary" onclick={analyze} disabled={processing || !domain.trim()}>
							{#if processing}<span class="spinner"></span>{$tr('dnsAnalyzer.analyzing')}{:else}🔍 {$tr('dnsAnalyzer.startAnalyze')}{/if}
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
								<h2 class="section-title" style="margin-bottom:0">🛡️ {result.domain}</h2>
							</div>
							<div class="security-score-badge" style="border-color: {getSecurityScoreColor(getSecurityScore())}40; background: {getSecurityScoreColor(getSecurityScore())}10">
								<span class="score-value" style="color: {getSecurityScoreColor(getSecurityScore())}">{getSecurityScore()}</span>
								<span class="score-label" style="color: {getSecurityScoreColor(getSecurityScore())}">{getSecurityScoreLabel(getSecurityScore())}</span>
							</div>
						</div>

						<div class="summary-bar">{result.summary}</div>

						<div class="result-tabs">
							<button class="result-tab {activeResultTab === 'overview' ? 'active' : ''}" onclick={() => activeResultTab = 'overview'}>
								📊 {$tr('dnsAnalyzer.tabOverview')}
							</button>
							<button class="result-tab {activeResultTab === 'records' ? 'active' : ''}" onclick={() => activeResultTab = 'records'}>
								📋 {$tr('dnsAnalyzer.tabRecords')} ({result.records.length})
							</button>
							<button class="result-tab {activeResultTab === 'security' ? 'active' : ''}" onclick={() => activeResultTab = 'security'}>
								🔒 {$tr('dnsAnalyzer.tabSecurity')} ({result.security_issues.length})
							</button>
							<button class="result-tab {activeResultTab === 'dnssec' ? 'active' : ''}" onclick={() => activeResultTab = 'dnssec'}>
								🛡️ DNSSEC
							</button>
							<button class="result-tab {activeResultTab === 'zone' ? 'active' : ''}" onclick={() => activeResultTab = 'zone'}>
								🔄 {$tr('dnsAnalyzer.tabZone')}
							</button>
						</div>

						{#if activeResultTab === 'overview'}
							<div class="overview-grid">
								<div class="overview-stat">
									<span class="stat-label">{$tr('dnsAnalyzer.totalRecords')}</span>
									<span class="stat-value">{result.records.length}</span>
								</div>
								<div class="overview-stat">
									<span class="stat-label">{$tr('dnsAnalyzer.nameservers')}</span>
									<span class="stat-value">{result.nameservers.length}</span>
								</div>
								<div class="overview-stat">
									<span class="stat-label">DNSSEC</span>
									<span class="stat-value" style="color: {result.dnssec_enabled ? '#22c55e' : '#ef4444'}">
										{result.dnssec_enabled ? '✅ ' + $tr('dnsAnalyzer.enabled') : '❌ ' + $tr('dnsAnalyzer.disabled')}
									</span>
								</div>
								<div class="overview-stat">
									<span class="stat-label">{$tr('dnsAnalyzer.zoneTransfer')}</span>
									<span class="stat-value" style="color: {result.zone_transfer_possible ? '#ef4444' : '#22c55e'}">
										{result.zone_transfer_possible ? '⚠️ ' + $tr('dnsAnalyzer.vulnerable') : '✅ ' + $tr('dnsAnalyzer.secure')}
									</span>
								</div>
								<div class="overview-stat">
									<span class="stat-label">{$tr('dnsAnalyzer.securityIssues')}</span>
									<span class="stat-value" style="color: {result.security_issues.length > 0 ? '#f59e0b' : '#22c55e'}">{result.security_issues.length}</span>
								</div>
								<div class="overview-stat">
									<span class="stat-label">{$tr('dnsAnalyzer.highIssues')}</span>
									<span class="stat-value" style="color: {result.security_issues.filter(i => i.severity === 'high').length > 0 ? '#ef4444' : '#22c55e'}">
										{result.security_issues.filter(i => i.severity === 'high').length}
									</span>
								</div>
							</div>

							{#if result.security_issues.length > 0}
								<h3 class="subsection-title">⚠️ {$tr('dnsAnalyzer.keyFindings')}</h3>
								<div class="findings-list">
									{#each result.security_issues.slice(0, 3) as issue}
										<div class="finding-item" style="border-left-color: {getSeverityColor(issue.severity)}">
											<span class="finding-severity" style="background: {getSeverityColor(issue.severity)}15; color: {getSeverityColor(issue.severity)}; border: 1px solid {getSeverityColor(issue.severity)}30">
												{getSeverityLabel(issue.severity)}
											</span>
											<span class="finding-category">{issue.category}</span>
											<span class="finding-desc">{issue.description}</span>
										</div>
									{/each}
									{#if result.security_issues.length > 3}
										<div class="finding-more" onclick={() => activeResultTab = 'security'}>
											{$tr('dnsAnalyzer.viewAllIssues')} ({result.security_issues.length}) →
										</div>
									{/if}
								</div>
							{/if}

							{#if result.records.length > 0}
								<h3 class="subsection-title">📋 {$tr('dnsAnalyzer.recordSummary')}</h3>
								<div class="record-type-grid">
									{#each getRecordTypes() as type}
										<div class="record-type-chip" style="border-color: {getRecordTypeColor(type)}40; background: {getRecordTypeColor(type)}10">
											<span class="type-label" style="color: {getRecordTypeColor(type)}">{type}</span>
											<span class="type-count">{result.records.filter(r => r.record_type === type).length}</span>
										</div>
									{/each}
								</div>
							{/if}

						{:else if activeResultTab === 'records'}
							<div class="filter-bar">
								<button class="filter-btn {recordFilter === 'all' ? 'active' : ''}" onclick={() => recordFilter = 'all'}>
									{$tr('dnsAnalyzer.allTypes')} ({result.records.length})
								</button>
								{#each getRecordTypes() as type}
									<button class="filter-btn {recordFilter === type ? 'active' : ''}" onclick={() => recordFilter = type}>
										<span style="color: {getRecordTypeColor(type)}">{type}</span>
										({result.records.filter(r => r.record_type === type).length})
									</button>
								{/each}
							</div>

							{#if getFilteredRecords().length > 0}
								<div class="records-table-wrapper">
									<table class="data-table">
										<thead>
											<tr>
												<th>{$tr('dnsAnalyzer.colType')}</th>
												<th>{$tr('dnsAnalyzer.colName')}</th>
												<th>{$tr('dnsAnalyzer.colValue')}</th>
												<th>{$tr('dnsAnalyzer.colTTL')}</th>
												<th>{$tr('dnsAnalyzer.colPriority')}</th>
											</tr>
										</thead>
										<tbody>
											{#each getFilteredRecords() as record}
												<tr>
													<td>
														<span class="record-type-badge" style="color: {getRecordTypeColor(record.record_type)}; border-color: {getRecordTypeColor(record.record_type)}40; background: {getRecordTypeColor(record.record_type)}15">
															{record.record_type}
														</span>
													</td>
													<td class="mono">{record.name}</td>
													<td class="mono record-value">{record.value}</td>
													<td class="mono">{record.ttl}s</td>
													<td>{#if record.priority !== null}{record.priority}{:else}-{/if}</td>
												</tr>
											{/each}
										</tbody>
									</table>
								</div>
							{:else}
								<div class="empty-state">
									<div class="empty-icon">📋</div>
									<p>{$tr('dnsAnalyzer.noRecords')}</p>
								</div>
							{/if}

						{:else if activeResultTab === 'security'}
							{#if result.security_issues.length > 0}
								<div class="security-summary-bar">
									<span class="security-stat danger">🔴 {$tr('dnsAnalyzer.highIssues')}: {result.security_issues.filter(i => i.severity === 'high').length}</span>
									<span class="security-stat warning">🟡 {$tr('dnsAnalyzer.mediumIssues')}: {result.security_issues.filter(i => i.severity === 'medium').length}</span>
									<span class="security-stat info">🔵 {$tr('dnsAnalyzer.lowIssues')}: {result.security_issues.filter(i => i.severity === 'low').length}</span>
								</div>
								<div class="issues-list">
									{#each result.security_issues as issue}
										<div class="issue-card" style="border-left-color: {getSeverityColor(issue.severity)}">
											<div class="issue-header">
												<span class="issue-severity" style="background: {getSeverityColor(issue.severity)}; color: white">{getSeverityLabel(issue.severity)}</span>
												<span class="issue-category">{issue.category}</span>
											</div>
											<p class="issue-desc">{issue.description}</p>
											<p class="issue-rec">💡 {issue.recommendation}</p>
										</div>
									{/each}
								</div>
							{:else}
								<div class="empty-state safe">
									<div class="empty-icon">✅</div>
									<p>{$tr('dnsAnalyzer.noSecurityIssues')}</p>
								</div>
							{/if}

						{:else if activeResultTab === 'dnssec'}
							<div class="detail-section">
								<div class="detail-row">
									<span class="detail-label">DNSSEC {$tr('dnsAnalyzer.status')}</span>
									<span class="detail-value" style="color: {result.dnssec_enabled ? '#22c55e' : '#ef4444'}">
										{result.dnssec_enabled ? '✅ ' + $tr('dnsAnalyzer.enabled') : '❌ ' + $tr('dnsAnalyzer.disabled')}
									</span>
								</div>
								{#if result.dnssec_enabled}
									{#if result.dnssec_details.key_tags.length > 0 && result.dnssec_details.key_tags[0] !== 0}
										<div class="detail-row">
											<span class="detail-label">{$tr('dnsAnalyzer.keyTags')}</span>
											<span class="detail-value mono">{result.dnssec_details.key_tags.join(', ')}</span>
										</div>
									{/if}
									{#if result.dnssec_details.algorithms.length > 0 && result.dnssec_details.algorithms[0] !== '未检测到'}
										<div class="detail-row">
											<span class="detail-label">{$tr('dnsAnalyzer.signAlgorithms')}</span>
											<span class="detail-value">{result.dnssec_details.algorithms.join(', ')}</span>
										</div>
									{/if}
									{#if result.dnssec_details.digest_types.length > 0 && result.dnssec_details.digest_types[0] !== '未检测到'}
										<div class="detail-row">
											<span class="detail-label">{$tr('dnsAnalyzer.digestTypes')}</span>
											<span class="detail-value">{result.dnssec_details.digest_types.join(', ')}</span>
										</div>
									{/if}
								{:else}
									<div class="dnssec-warning">
										<span class="warning-icon">⚠️</span>
										<span class="warning-text">{$tr('dnsAnalyzer.dnssecWarning')}</span>
									</div>
								{/if}
							</div>

						{:else if activeResultTab === 'zone'}
							<div class="detail-section">
								<div class="detail-row">
									<span class="detail-label">{$tr('dnsAnalyzer.zoneTransferRisk')}</span>
									<span class="detail-value" style="color: {result.zone_transfer_possible ? '#ef4444' : '#22c55e'}">
										{result.zone_transfer_possible ? '⚠️ ' + $tr('dnsAnalyzer.vulnerable') : '✅ ' + $tr('dnsAnalyzer.secure')}
									</span>
								</div>
								<div class="detail-row">
									<span class="detail-label">{$tr('dnsAnalyzer.testedNS')}</span>
									<span class="detail-value mono">{result.zone_transfer_details.tested_nameservers.join(', ') || $tr('dnsAnalyzer.none')}</span>
								</div>
								{#if result.zone_transfer_details.vulnerable_nameservers.length > 0}
									<div class="detail-row danger">
										<span class="detail-label">{$tr('dnsAnalyzer.vulnerableNS')}</span>
										<span class="detail-value mono" style="color: #ef4444">{result.zone_transfer_details.vulnerable_nameservers.join(', ')}</span>
									</div>
								{/if}
								{#if result.zone_transfer_details.transferred_records.length > 0}
									<h3 class="subsection-title">📋 {$tr('dnsAnalyzer.transferredRecords')}</h3>
									<div class="records-table-wrapper">
										<table class="data-table">
											<thead>
												<tr>
													<th>{$tr('dnsAnalyzer.colType')}</th>
													<th>{$tr('dnsAnalyzer.colName')}</th>
													<th>{$tr('dnsAnalyzer.colValue')}</th>
												</tr>
											</thead>
											<tbody>
												{#each result.zone_transfer_details.transferred_records as record}
													<tr>
														<td><span class="record-type-badge" style="color: {getRecordTypeColor(record.record_type)}; border-color: {getRecordTypeColor(record.record_type)}40; background: {getRecordTypeColor(record.record_type)}15">{record.record_type}</span></td>
														<td class="mono">{record.name}</td>
														<td class="mono">{record.value}</td>
													</tr>
												{/each}
											</tbody>
										</table>
									</div>
								{/if}
								{#if result.zone_transfer_possible}
									<div class="dnssec-warning">
										<span class="warning-icon">⚠️</span>
										<span class="warning-text">{$tr('dnsAnalyzer.zoneWarning')}</span>
									</div>
								{/if}
							</div>
						{/if}
					{:else}
						<div class="empty-state">
							<div class="empty-icon">🛡️</div>
							<p>{$tr('dnsAnalyzer.noResults')}</p>
						</div>
					{/if}
				</div>
			</div>
		</div>
	{:else if activeMainTab === 'history'}
		<div class="section-card">
			<ToolHistory toolType="dns_analyzer" toolName={$tr('dnsAnalyzer.title')} bind:this={historyComponent} />
		</div>
	{:else if activeMainTab === 'help'}
		<div class="section-card">
			<ToolHelp toolType="dns_analyzer" />
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
		grid-template-columns: 320px 1fr;
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

	.checkbox-label {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		cursor: pointer;
		font-size: 0.825rem;
		color: #cbd5e1;
	}

	.checkbox-label input[type="checkbox"] {
		accent-color: #a855f7;
		width: 0.9rem;
		height: 0.9rem;
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

	.btn-primary:disabled { opacity: 0.5; cursor: not-allowed; transform: none; box-shadow: none; }

	.btn-secondary {
		background: rgba(15, 23, 42, 0.8);
		color: #94a3b8;
		border: 1px solid rgba(148, 163, 184, 0.15);
		padding: 0.65rem 1rem;
		border-radius: 0.5rem;
		cursor: pointer;
		transition: all 0.2s;
		font-size: 0.9rem;
	}

	.btn-secondary:hover:not(:disabled) { border-color: rgba(168, 85, 247, 0.3); color: #c4b5fd; }
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

	.error-icon { font-size: 1.2rem; }
	.error-text { color: #ef4444; font-size: 0.85rem; }

	.result-header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		margin-bottom: 0.75rem;
	}

	.security-score-badge {
		display: flex;
		flex-direction: column;
		align-items: center;
		padding: 0.5rem 1rem;
		border-radius: 0.5rem;
		border: 1px solid;
	}

	.score-value {
		font-size: 1.5rem;
		font-weight: 700;
		line-height: 1;
	}

	.score-label {
		font-size: 0.7rem;
		font-weight: 600;
		margin-top: 0.2rem;
	}

	.summary-bar {
		padding: 0.75rem 1rem;
		background: rgba(15, 23, 42, 0.5);
		border: 1px solid rgba(148, 163, 184, 0.08);
		border-radius: 0.5rem;
		font-size: 0.8rem;
		color: #94a3b8;
		margin-bottom: 1rem;
	}

	.result-tabs {
		display: flex;
		gap: 0.25rem;
		margin-bottom: 1rem;
		flex-wrap: wrap;
	}

	.result-tab {
		padding: 0.4rem 0.75rem;
		border: 1px solid rgba(148, 163, 184, 0.15);
		border-radius: 0.375rem;
		background: transparent;
		color: #94a3b8;
		cursor: pointer;
		font-size: 0.8rem;
		transition: all 0.2s;
	}

	.result-tab.active {
		background: rgba(168, 85, 247, 0.2);
		color: #c4b5fd;
		border-color: rgba(168, 85, 247, 0.3);
		font-weight: 600;
	}

	.result-tab:hover:not(.active) { background: rgba(168, 85, 247, 0.08); }

	.overview-grid {
		display: grid;
		grid-template-columns: repeat(3, 1fr);
		gap: 0.75rem;
		margin-bottom: 1.25rem;
	}

	.overview-stat {
		padding: 0.75rem;
		background: rgba(15, 23, 42, 0.5);
		border: 1px solid rgba(148, 163, 184, 0.08);
		border-radius: 0.5rem;
		display: flex;
		flex-direction: column;
		gap: 0.25rem;
	}

	.stat-label {
		font-size: 0.7rem;
		color: #94a3b8;
		text-transform: uppercase;
		letter-spacing: 0.05em;
	}

	.stat-value {
		font-size: 0.9rem;
		font-weight: 600;
		color: #f1f5f9;
	}

	.subsection-title {
		font-size: 0.9rem;
		font-weight: 600;
		color: #f1f5f9;
		margin: 1.25rem 0 0.75rem;
	}

	.findings-list {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
	}

	.finding-item {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		padding: 0.5rem 0.75rem;
		background: rgba(15, 23, 42, 0.5);
		border: 1px solid rgba(148, 163, 184, 0.08);
		border-left: 3px solid;
		border-radius: 0.375rem;
		font-size: 0.8rem;
		flex-wrap: wrap;
	}

	.finding-severity {
		padding: 0.1rem 0.4rem;
		border-radius: 0.25rem;
		font-size: 0.65rem;
		font-weight: 600;
	}

	.finding-category {
		font-weight: 600;
		color: #f1f5f9;
	}

	.finding-desc {
		color: #94a3b8;
		flex: 1;
	}

	.finding-more {
		text-align: center;
		padding: 0.5rem;
		color: #a855f7;
		font-size: 0.8rem;
		cursor: pointer;
		transition: color 0.2s;
	}

	.finding-more:hover { color: #c4b5fd; }

	.record-type-grid {
		display: flex;
		flex-wrap: wrap;
		gap: 0.5rem;
	}

	.record-type-chip {
		display: flex;
		align-items: center;
		gap: 0.4rem;
		padding: 0.35rem 0.65rem;
		border: 1px solid;
		border-radius: 0.375rem;
	}

	.type-label {
		font-weight: 600;
		font-size: 0.8rem;
	}

	.type-count {
		font-size: 0.7rem;
		color: #94a3b8;
	}

	.filter-bar {
		display: flex;
		gap: 0.25rem;
		margin-bottom: 0.75rem;
		background: rgba(15, 23, 42, 0.6);
		border-radius: 0.5rem;
		padding: 0.2rem;
		overflow-x: auto;
		flex-wrap: wrap;
	}

	.filter-btn {
		padding: 0.35rem 0.65rem;
		border: none;
		border-radius: 0.375rem;
		background: transparent;
		cursor: pointer;
		font-size: 0.75rem;
		color: #94a3b8;
		transition: all 0.2s;
		white-space: nowrap;
	}

	.filter-btn.active {
		background: rgba(168, 85, 247, 0.2);
		color: #c4b5fd;
		font-weight: 600;
	}

	.filter-btn:hover:not(.active) { background: rgba(168, 85, 247, 0.08); }

	.records-table-wrapper {
		overflow-x: auto;
		border-radius: 0.5rem;
		border: 1px solid rgba(148, 163, 184, 0.08);
	}

	.data-table {
		width: 100%;
		border-collapse: collapse;
		font-size: 0.8rem;
	}

	.data-table th {
		padding: 0.5rem 0.75rem;
		text-align: left;
		font-size: 0.7rem;
		color: #94a3b8;
		text-transform: uppercase;
		letter-spacing: 0.05em;
		border-bottom: 1px solid rgba(148, 163, 184, 0.1);
		background: rgba(15, 23, 42, 0.5);
		white-space: nowrap;
	}

	.data-table td {
		padding: 0.45rem 0.75rem;
		border-bottom: 1px solid rgba(148, 163, 184, 0.05);
		color: #cbd5e1;
	}

	.data-table tr:hover { background: rgba(168, 85, 247, 0.03); }

	.mono {
		font-family: 'SF Mono', 'Fira Code', 'Cascadia Code', monospace;
		font-size: 0.78rem;
	}

	.record-value {
		word-break: break-all;
		max-width: 300px;
	}

	.record-type-badge {
		padding: 0.1rem 0.5rem;
		border-radius: 0.25rem;
		font-weight: 600;
		font-size: 0.7rem;
		border: 1px solid;
		display: inline-block;
		min-width: 2.5rem;
		text-align: center;
	}

	.security-summary-bar {
		display: flex;
		gap: 1.5rem;
		margin-bottom: 1rem;
		padding: 0.75rem;
		background: rgba(15, 23, 42, 0.5);
		border-radius: 0.5rem;
		border: 1px solid rgba(148, 163, 184, 0.08);
	}

	.security-stat {
		font-size: 0.85rem;
		font-weight: 600;
	}

	.security-stat.danger { color: #ef4444; }
	.security-stat.warning { color: #f59e0b; }
	.security-stat.info { color: #3b82f6; }

	.issues-list {
		display: flex;
		flex-direction: column;
		gap: 0.625rem;
	}

	.issue-card {
		padding: 0.875rem;
		background: rgba(15, 23, 42, 0.5);
		border: 1px solid rgba(148, 163, 184, 0.08);
		border-left: 3px solid;
		border-radius: 0.5rem;
	}

	.issue-header {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		margin-bottom: 0.5rem;
	}

	.issue-severity {
		padding: 0.15rem 0.5rem;
		border-radius: 0.25rem;
		font-size: 0.65rem;
		font-weight: 600;
		text-transform: uppercase;
	}

	.issue-category {
		font-weight: 600;
		font-size: 0.85rem;
		color: #f1f5f9;
	}

	.issue-desc {
		font-size: 0.8rem;
		color: #cbd5e1;
		margin: 0.25rem 0;
	}

	.issue-rec {
		font-size: 0.75rem;
		color: #94a3b8;
		margin: 0.25rem 0 0;
	}

	.detail-section {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
	}

	.detail-row {
		display: flex;
		justify-content: space-between;
		align-items: center;
		padding: 0.6rem 0.875rem;
		background: rgba(15, 23, 42, 0.5);
		border: 1px solid rgba(148, 163, 184, 0.08);
		border-radius: 0.375rem;
	}

	.detail-row.danger {
		background: rgba(239, 68, 68, 0.05);
		border-color: rgba(239, 68, 68, 0.15);
	}

	.detail-label {
		font-size: 0.8rem;
		font-weight: 600;
		color: #94a3b8;
	}

	.detail-value {
		font-size: 0.85rem;
		color: #f1f5f9;
	}

	.dnssec-warning {
		display: flex;
		align-items: flex-start;
		gap: 0.5rem;
		padding: 0.75rem 1rem;
		background: rgba(245, 158, 11, 0.08);
		border: 1px solid rgba(245, 158, 11, 0.2);
		border-radius: 0.5rem;
		margin-top: 0.75rem;
	}

	.warning-icon { font-size: 1rem; flex-shrink: 0; }

	.warning-text {
		font-size: 0.8rem;
		color: #f59e0b;
		line-height: 1.5;
	}

	.empty-state {
		text-align: center;
		padding: 3rem 1rem;
		color: #94a3b8;
	}

	.empty-state p { margin: 0; font-size: 0.9rem; }
	.empty-state.safe p { color: #22c55e; }
	.empty-icon { font-size: 2.5rem; margin-bottom: 0.75rem; }

	@media (max-width: 768px) {
		.nd-page { padding: 1rem; }
		.content-grid { grid-template-columns: 1fr; }
		.overview-grid { grid-template-columns: repeat(2, 1fr); }
		.page-header { flex-direction: column; align-items: flex-start; gap: 0.75rem; }
		.tabs { overflow-x: auto; }
		.filter-bar { flex-wrap: wrap; }
		.result-tabs { flex-wrap: wrap; }
	}
</style>
