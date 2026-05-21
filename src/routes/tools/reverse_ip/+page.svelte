<script lang="ts">
	import { tr } from '$lib/i18n';
	import ToolHistory from '$lib/components/ToolHistory.svelte';
	import ToolHelp from '$lib/components/ToolHelp.svelte';

	interface ReverseDomain {
		domain: string;
		first_seen: string | null;
		last_seen: string | null;
		record_type: string;
		is_active: boolean;
		is_subdomain: boolean;
	}

	interface DnsHistoryEntry {
		domain: string;
		ip: string;
		record_type: string;
		first_seen: string;
		last_seen: string;
	}

	interface RelatedIp {
		ip: string;
		relationship: string;
		domains: string[];
		asn: string | null;
		org: string | null;
	}

	interface ReverseIpFinding {
		severity: string;
		category: string;
		description: string;
		recommendation: string;
	}

	interface ReverseIpResult {
		success: boolean;
		ip: string;
		domains: ReverseDomain[];
		dns_history: DnsHistoryEntry[];
		related_ips: RelatedIp[];
		security_findings: ReverseIpFinding[];
		summary: string;
	}

	let ip = $state('');
	let includeDnsHistory = $state(true);
	let includeSubdomains = $state(true);
	let timeout = $state(30);
	let result: ReverseIpResult | null = $state(null);
	let error = $state('');
	let processing = $state(false);
	let activeMainTab = $state('lookup');
	let activeResultTab = $state('domains');
	let historyComponent: ToolHistory;

	async function lookup() {
		if (!ip.trim()) { error = $tr('reverseIp.error.ipRequired'); return; }
		processing = true; error = ''; result = null;
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			result = await invoke<ReverseIpResult>('reverse_ip_lookup_command', {
				config: {
					ip: ip.trim(),
					timeout,
					include_dns_history: includeDnsHistory,
					include_subdomains: includeSubdomains,
				}
			});
			if (result && historyComponent) {
				await historyComponent.saveHistory(ip.trim(), JSON.stringify(result), result.summary, 'completed');
			}
		} catch (e: any) {
			error = e.toString();
			if (historyComponent) {
				await historyComponent.saveHistory(ip.trim(), '', error, 'failed');
			}
		} finally {
			processing = false;
		}
	}

	function clearAll() { ip = ''; result = null; error = ''; }

	function getSeverityColor(s: string): string {
		switch (s) { case 'critical': return '#dc2626'; case 'high': return '#ef4444'; case 'medium': return '#f59e0b'; case 'low': return '#3b82f6'; default: return '#6b7280'; }
	}

	function translateSeverity(s: string): string {
		const key = `reverseIp.severity.${s}`;
		const val = $tr(key);
		return val !== key ? val : s;
	}
</script>

<div class="nd-page">
	<div class="page-header">
		<div class="header-left">
			<a href="/" class="back-link">{$tr('common.backToHome')}</a>
			<h1 class="page-title">🔄 {$tr('reverseIp.title')}</h1>
			<p class="page-subtitle">{$tr('reverseIp.subtitle')}</p>
		</div>
	</div>

	<div class="tabs">
		<button class="tab-btn {activeMainTab === 'lookup' ? 'active' : ''}" onclick={() => activeMainTab = 'lookup'}>
			<span class="tab-icon">🔄</span> {$tr('reverseIp.lookup')}
		</button>
		<button class="tab-btn {activeMainTab === 'history' ? 'active' : ''}" onclick={() => activeMainTab = 'history'}>
			<span class="tab-icon">📋</span> {$tr('reverseIp.history')}
		</button>
		<button class="tab-btn {activeMainTab === 'help' ? 'active' : ''}" onclick={() => activeMainTab = 'help'}>
			<span class="tab-icon">📖</span> {$tr('reverseIp.help')}
		</button>
	</div>

	{#if activeMainTab === 'lookup'}
		<div class="content-grid">
			<div class="input-section">
				<div class="section-card">
					<h2 class="section-title">{$tr('reverseIp.config.title')}</h2>
					<p class="section-desc">{$tr('reverseIp.config.desc')}</p>

					<div class="form-group">
						<label class="form-label">{$tr('reverseIp.config.ip')}</label>
						<input type="text" bind:value={ip} placeholder="e.g. 104.21.50.100" class="form-input" disabled={processing} />
					</div>

					<div class="checkbox-group">
						<label class="checkbox-label">
							<input type="checkbox" bind:checked={includeDnsHistory} disabled={processing} />
							<span class="checkbox-text">{$tr('reverseIp.config.includeDnsHistory')}</span>
						</label>
					</div>

					<div class="checkbox-group">
						<label class="checkbox-label">
							<input type="checkbox" bind:checked={includeSubdomains} disabled={processing} />
							<span class="checkbox-text">{$tr('reverseIp.config.includeSubdomains')}</span>
						</label>
					</div>

					<div class="form-group">
						<label class="form-label">{$tr('reverseIp.config.timeout')}</label>
						<input type="number" bind:value={timeout} min="5" max="120" class="form-input" disabled={processing} />
					</div>

					<div class="button-group">
						<button class="btn-primary" onclick={lookup} disabled={processing || !ip.trim()}>
							{#if processing}<span class="spinner"></span> {$tr('reverseIp.looking')}{:else}🔄 {$tr('reverseIp.startLookup')}{/if}
						</button>
						<button class="btn-secondary" onclick={clearAll} disabled={processing}>🗑️</button>
					</div>
				</div>
			</div>

			<div class="result-section">
				<div class="section-card">
					<h2 class="section-title">{$tr('reverseIp.result.title')}</h2>
					{#if error}
						<div class="error-card"><div class="error-icon">⚠️</div><div class="error-text">{error}</div></div>
					{:else if result}
						<div class="summary-banner">
							<div class="summary-info">
								<span class="ip-badge">IP</span>
								<span class="query-text">{result.ip}</span>
							</div>
							<div class="summary-badges">
								<span class="summary-badge purple">{result.domains.length} {$tr('reverseIp.result.domains')}</span>
								<span class="summary-badge green">{result.domains.filter(d => d.is_active).length} {$tr('reverseIp.result.active')}</span>
							</div>
						</div>

						<div class="result-tabs">
							<button class="result-tab {activeResultTab === 'domains' ? 'active' : ''}" onclick={() => activeResultTab = 'domains'}>🌐 {$tr('reverseIp.tabs.domains')} ({result.domains.length})</button>
							<button class="result-tab {activeResultTab === 'history' ? 'active' : ''}" onclick={() => activeResultTab = 'history'}>📜 {$tr('reverseIp.tabs.dnsHistory')} ({result.dns_history.length})</button>
							<button class="result-tab {activeResultTab === 'related' ? 'active' : ''}" onclick={() => activeResultTab = 'related'}>🔗 {$tr('reverseIp.tabs.relatedIps')} ({result.related_ips.length})</button>
							<button class="result-tab {activeResultTab === 'findings' ? 'active' : ''}" onclick={() => activeResultTab = 'findings'}>🛡️ {$tr('reverseIp.tabs.findings')} ({result.security_findings.length})</button>
						</div>

						{#if activeResultTab === 'domains'}
							<div class="items-list">
								{#each result.domains as domain}
									<div class="item-card" style="border-left-color: {domain.is_active ? '#a855f7' : '#475569'}">
										<div class="item-header">
											<span class="domain-name">{domain.domain}</span>
											<span class="record-badge">{domain.record_type}</span>
											{#if domain.is_subdomain}
												<span class="subdomain-badge">{$tr('reverseIp.domain.subdomain')}</span>
											{/if}
											<div class="status-area">
												{#if domain.is_active}
													<span class="active-badge">{$tr('reverseIp.domain.active')}</span>
												{:else}
													<span class="inactive-badge">{$tr('reverseIp.domain.inactive')}</span>
												{/if}
												{#if domain.last_seen}
													<span class="date-text">{domain.last_seen}</span>
												{/if}
											</div>
										</div>
										{#if domain.first_seen || domain.last_seen}
											<div class="domain-meta">
												{#if domain.first_seen}<span>{$tr('reverseIp.domain.firstSeen')}: {domain.first_seen}</span>{/if}
											</div>
										{/if}
									</div>
								{/each}
								{#if result.domains.length === 0}
									<div class="empty-item">{$tr('reverseIp.status.noDomains')}</div>
								{/if}
							</div>
						{:else if activeResultTab === 'history'}
							{#if result.dns_history.length > 0}
								<div class="table-wrap">
									<table class="data-table">
										<thead>
											<tr>
												<th>{$tr('reverseIp.dnsHistory.domain')}</th>
												<th>{$tr('reverseIp.dnsHistory.ip')}</th>
												<th>{$tr('reverseIp.dnsHistory.type')}</th>
												<th>{$tr('reverseIp.dnsHistory.firstSeen')}</th>
												<th>{$tr('reverseIp.dnsHistory.lastSeen')}</th>
											</tr>
										</thead>
										<tbody>
											{#each result.dns_history as entry}
												<tr>
													<td class="mono">{entry.domain}</td>
													<td class="mono">{entry.ip}</td>
													<td><span class="record-badge">{entry.record_type}</span></td>
													<td class="muted">{entry.first_seen}</td>
													<td class="muted">{entry.last_seen}</td>
												</tr>
											{/each}
										</tbody>
									</table>
								</div>
							{:else}
								<div class="empty-item">{$tr('reverseIp.status.noDnsHistory')}</div>
							{/if}
						{:else if activeResultTab === 'related'}
							<div class="items-list">
								{#each result.related_ips as rel}
									<div class="item-card" style="border-left-color: #22c55e">
										<div class="item-header">
											<span class="domain-name">{rel.ip}</span>
											<span class="relationship-badge">{rel.relationship}</span>
										</div>
										<div class="related-meta">
											{#if rel.asn}<span>ASN: {rel.asn}</span>{/if}
											{#if rel.org}<span>{$tr('reverseIp.related.org')}: {rel.org}</span>{/if}
										</div>
										{#if rel.domains.length > 0}
											<div class="tag-list">
												{#each rel.domains as d}
													<span class="info-tag">{d}</span>
												{/each}
											</div>
										{/if}
									</div>
								{/each}
								{#if result.related_ips.length === 0}
									<div class="empty-item">{$tr('reverseIp.status.noRelatedIps')}</div>
								{/if}
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
									<div class="empty-item">{$tr('reverseIp.status.noFindings')}</div>
								{/if}
							</div>
						{/if}
					{:else}
						<div class="empty-state">
							<div class="empty-icon">🔄</div>
							<p>{$tr('reverseIp.result.noResults')}</p>
						</div>
					{/if}
				</div>
			</div>
		</div>
	{:else if activeMainTab === 'history'}
		<div class="section-card"><ToolHistory toolType="reverse_ip" toolName={$tr('reverseIp.title')} bind:this={historyComponent} /></div>
	{:else if activeMainTab === 'help'}
		<div class="section-card"><ToolHelp toolType="reverse_ip" /></div>
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

	.checkbox-group { margin-bottom: 0.6rem; }
	.checkbox-label { display: flex; align-items: center; gap: 0.5rem; cursor: pointer; }
	.checkbox-text { font-size: 0.85rem; color: #cbd5e1; }

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

	.summary-banner { display: flex; align-items: center; justify-content: space-between; padding: 0.75rem 1rem; background: rgba(15, 23, 42, 0.4); border: 1px solid rgba(148, 163, 184, 0.08); border-radius: 0.75rem; margin-bottom: 1rem; }
	.summary-info { display: flex; align-items: center; gap: 0.75rem; }
	.ip-badge { padding: 0.2rem 0.6rem; background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%); border-radius: 0.3rem; font-size: 0.7rem; font-weight: 700; color: white; letter-spacing: 0.05em; }
	.query-text { font-size: 0.85rem; color: #f1f5f9; font-weight: 500; font-family: 'SF Mono', 'Fira Code', monospace; }
	.summary-badges { display: flex; gap: 0.5rem; }
	.summary-badge { padding: 0.25rem 0.6rem; border-radius: 0.4rem; font-size: 0.75rem; font-weight: 600; }
	.summary-badge.purple { background: rgba(168, 85, 247, 0.15); color: #c4b5fd; border: 1px solid rgba(168, 85, 247, 0.3); }
	.summary-badge.green { background: rgba(34, 197, 94, 0.15); color: #86efac; border: 1px solid rgba(34, 197, 94, 0.3); }

	.result-tabs { display: flex; gap: 0.25rem; margin-bottom: 1rem; flex-wrap: wrap; }
	.result-tab { padding: 0.4rem 0.75rem; border-radius: 0.4rem; border: 1px solid rgba(148, 163, 184, 0.15); background: rgba(15, 23, 42, 0.4); color: #94a3b8; cursor: pointer; font-size: 0.8rem; transition: all 0.2s; }
	.result-tab.active { background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%); color: white; border-color: transparent; font-weight: 600; }
	.result-tab:hover:not(.active) { border-color: rgba(168, 85, 247, 0.3); color: #c4b5fd; }

	.items-list { display: flex; flex-direction: column; gap: 0.5rem; }
	.item-card { padding: 0.75rem; background: rgba(15, 23, 42, 0.4); border: 1px solid rgba(148, 163, 184, 0.08); border-radius: 0.5rem; border-left: 3px solid; }
	.item-header { display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.3rem; flex-wrap: wrap; }
	.item-title { font-weight: 600; font-size: 0.85rem; color: #f1f5f9; }
	.item-desc { font-size: 0.8rem; color: #94a3b8; margin-top: 0.3rem; }
	.item-rec { font-size: 0.8rem; color: #86efac; margin-top: 0.3rem; }

	.domain-name { font-family: 'SF Mono', 'Fira Code', monospace; font-weight: 600; font-size: 0.85rem; color: #c4b5fd; }
	.record-badge { padding: 0.1rem 0.4rem; background: rgba(148, 163, 184, 0.15); border-radius: 0.25rem; font-size: 0.7rem; color: #94a3b8; text-transform: uppercase; }
	.subdomain-badge { padding: 0.1rem 0.4rem; background: rgba(168, 85, 247, 0.15); color: #c4b5fd; border-radius: 0.25rem; font-size: 0.7rem; }
	.active-badge { padding: 0.1rem 0.4rem; background: rgba(34, 197, 94, 0.15); color: #86efac; border-radius: 0.25rem; font-size: 0.7rem; font-weight: 600; }
	.inactive-badge { padding: 0.1rem 0.4rem; background: rgba(148, 163, 184, 0.1); color: #64748b; border-radius: 0.25rem; font-size: 0.7rem; }
	.date-text { font-size: 0.7rem; color: #64748b; }
	.status-area { margin-left: auto; display: flex; align-items: center; gap: 0.5rem; }
	.domain-meta { font-size: 0.75rem; color: #94a3b8; margin-top: 0.2rem; }

	.relationship-badge { padding: 0.1rem 0.4rem; background: rgba(34, 197, 94, 0.15); color: #86efac; border-radius: 0.25rem; font-size: 0.7rem; }
	.related-meta { display: flex; gap: 1rem; font-size: 0.75rem; color: #94a3b8; margin-top: 0.3rem; }

	.severity-badge { padding: 0.15rem 0.5rem; border-radius: 0.3rem; color: white; font-size: 0.7rem; font-weight: 600; text-transform: uppercase; }

	.tag-list { display: flex; flex-wrap: wrap; gap: 0.25rem; margin-top: 0.3rem; }
	.info-tag { padding: 0.1rem 0.4rem; background: rgba(168, 85, 247, 0.1); color: #c4b5fd; border-radius: 0.2rem; font-size: 0.7rem; }

	.table-wrap { overflow-x: auto; }
	.data-table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
	.data-table th { text-align: left; padding: 0.5rem 0.75rem; color: #94a3b8; border-bottom: 1px solid rgba(148, 163, 184, 0.15); font-weight: 500; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; }
	.data-table td { padding: 0.5rem 0.75rem; border-bottom: 1px solid rgba(148, 163, 184, 0.08); color: #e2e8f0; }
	.data-table .mono { font-family: 'SF Mono', 'Fira Code', monospace; color: #c4b5fd; }
	.data-table .muted { color: #94a3b8; }

	.empty-item { text-align: center; padding: 1.5rem; color: #94a3b8; font-size: 0.85rem; }
	.empty-state { text-align: center; padding: 2.5rem 1rem; color: #94a3b8; }
	.empty-icon { font-size: 2.5rem; margin-bottom: 0.75rem; }
	.empty-state p { font-size: 0.85rem; margin: 0; }

	.input-section::-webkit-scrollbar { width: 4px; }
	.input-section::-webkit-scrollbar-track { background: transparent; }
	.input-section::-webkit-scrollbar-thumb { background: rgba(168, 85, 247, 0.3); border-radius: 2px; }
	.items-list::-webkit-scrollbar { width: 4px; }
	.items-list::-webkit-scrollbar-track { background: transparent; }
	.items-list::-webkit-scrollbar-thumb { background: rgba(168, 85, 247, 0.3); border-radius: 2px; }

	@media (max-width: 768px) {
		.content-grid { grid-template-columns: 1fr; }
		.input-section { position: static; max-height: none; }
		.summary-banner { flex-direction: column; align-items: flex-start; gap: 0.5rem; }
		.status-area { margin-left: 0; }
		.item-header { flex-wrap: wrap; }
	}
	@media (max-width: 480px) {
		.nd-page { padding: 0.75rem; }
		.tabs { flex-wrap: wrap; }
		.tab-btn { font-size: 0.8rem; padding: 0.5rem 0.75rem; }
		.result-tabs { gap: 0.15rem; }
		.result-tab { font-size: 0.75rem; padding: 0.3rem 0.5rem; }
	}
</style>
