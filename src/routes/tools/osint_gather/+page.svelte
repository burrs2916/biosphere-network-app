<script lang="ts">
	import { tr } from '$lib/i18n';
	import ToolHistory from '$lib/components/ToolHistory.svelte';
	import ToolHelp from '$lib/components/ToolHelp.svelte';

	interface OsintEmail {
		address: string;
		source: string;
		is_valid: boolean;
		breach_count: number | null;
	}

	interface OsintSubdomain {
		subdomain: string;
		ip: string | null;
		is_active: boolean;
		source: string;
	}

	interface OsintIpInfo {
		ip: string;
		hostname: string | null;
		country: string | null;
		org: string | null;
		asn: string | null;
		source: string;
	}

	interface OsintUrl {
		url: string;
		title: string | null;
		source: string;
	}

	interface OsintDnsRecord {
		record_type: string;
		name: string;
		value: string;
		ttl: number;
	}

	interface OsintMetadata {
		key: string;
		value: string;
		source: string;
	}

	interface OsintFinding {
		severity: string;
		category: string;
		description: string;
		recommendation: string;
	}

	interface OsintGatherResult {
		success: boolean;
		target: string;
		emails: OsintEmail[];
		subdomains: OsintSubdomain[];
		ip_addresses: OsintIpInfo[];
		urls: OsintUrl[];
		dns_records: OsintDnsRecord[];
		metadata: OsintMetadata[];
		security_findings: OsintFinding[];
		summary: string;
	}

	let target = $state('');
	let checkEmail = $state(true);
	let checkSubdomain = $state(true);
	let checkIp = $state(true);
	let checkUrl = $state(true);
	let checkDns = $state(true);
	let maxResults = $state(100);
	let timeout = $state(30);
	let result: OsintGatherResult | null = $state(null);
	let error = $state('');
	let processing = $state(false);
	let activeMainTab = $state('gather');
	let activeResultTab = $state('overview');

	let historyComponent: ToolHistory;

	let totalData = $derived(
		result
			? (result as OsintGatherResult).emails.length + (result as OsintGatherResult).subdomains.length + (result as OsintGatherResult).ip_addresses.length + (result as OsintGatherResult).urls.length + (result as OsintGatherResult).dns_records.length
			: 0
	);

	function translateCategory(cat: string): string {
		const key = `osintGather.category.${cat}`;
		const val = $tr(key);
		return val === key ? cat : val;
	}

	function translateSeverity(sev: string): string {
		const key = `osintGather.severity.${sev}`;
		const val = $tr(key);
		return val === key ? sev : val;
	}

	async function gather() {
		if (!target.trim()) {
			error = $tr('osintGather.error.targetRequired');
			return;
		}
		processing = true;
		error = '';
		result = null;
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			const sources: string[] = [];
			if (checkEmail) sources.push('email');
			if (checkSubdomain) sources.push('subdomain');
			if (checkIp) sources.push('ip');
			if (checkUrl) sources.push('url');
			if (checkDns) sources.push('dns');

			result = await invoke<OsintGatherResult>('gather_osint_command', {
				config: {
					target: target.trim(),
					search_engines: ['google', 'bing'],
					data_sources: sources,
					max_results: maxResults,
					timeout,
				}
			});
			if (result && historyComponent) {
				await historyComponent.saveHistory(target.trim(), JSON.stringify(result), result.summary, 'completed');
			}
		} catch (e: any) {
			error = e.toString();
			if (historyComponent) {
				await historyComponent.saveHistory(target.trim(), '', error, 'failed');
			}
		} finally {
			processing = false;
		}
	}

	function clearAll() {
		target = '';
		result = null;
		error = '';
		checkEmail = true;
		checkSubdomain = true;
		checkIp = true;
		checkUrl = true;
		checkDns = true;
		maxResults = 100;
		timeout = 30;
	}

	function getSeverityColor(severity: string): string {
		switch (severity) {
			case 'high': return '#fca5a5';
			case 'medium': return '#fbbf24';
			case 'low': return '#86efac';
			default: return '#94a3b8';
		}
	}

	function getSeverityBorder(severity: string): string {
		switch (severity) {
			case 'high': return 'rgba(239, 68, 68, 0.5)';
			case 'medium': return 'rgba(245, 158, 11, 0.5)';
			case 'low': return 'rgba(34, 197, 94, 0.5)';
			default: return 'rgba(148, 163, 184, 0.3)';
		}
	}

	function getSeverityBg(severity: string): string {
		switch (severity) {
			case 'high': return 'rgba(239, 68, 68, 0.1)';
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
			<h1 class="page-title">🕵️ {$tr('osintGather.title')}</h1>
			<p class="page-subtitle">{$tr('osintGather.subtitle')}</p>
		</div>
	</div>

	<div class="tabs">
		<button class="tab-btn {activeMainTab === 'gather' ? 'active' : ''}" onclick={() => activeMainTab = 'gather'}>
			<span class="tab-icon">🔍</span> {$tr('osintGather.gather')}
		</button>
		<button class="tab-btn {activeMainTab === 'history' ? 'active' : ''}" onclick={() => activeMainTab = 'history'}>
			<span class="tab-icon">📋</span> {$tr('osintGather.history')}
		</button>
		<button class="tab-btn {activeMainTab === 'help' ? 'active' : ''}" onclick={() => activeMainTab = 'help'}>
			<span class="tab-icon">📖</span> {$tr('osintGather.help')}
		</button>
	</div>

	{#if activeMainTab === 'gather'}
		<div class="content-grid">
			<div class="input-section">
				<div class="section-card">
					<h2 class="section-title">{$tr('osintGather.config.title')}</h2>
					<p class="section-desc">{$tr('osintGather.config.desc')}</p>

					<div class="form-group">
						<label class="form-label">{$tr('osintGather.config.target')}</label>
						<input type="text" bind:value={target} placeholder={$tr('osintGather.config.targetPlaceholder')} class="form-input" disabled={processing} onkeydown={(e) => e.key === 'Enter' && gather()} />
					</div>

					<div class="form-group">
						<label class="form-label">{$tr('osintGather.config.dataSources')}</label>
						<div class="checkbox-group">
							<label class="checkbox-item">
								<input type="checkbox" bind:checked={checkEmail} disabled={processing} />
								<span>{$tr('osintGather.config.email')}</span>
							</label>
							<label class="checkbox-item">
								<input type="checkbox" bind:checked={checkSubdomain} disabled={processing} />
								<span>{$tr('osintGather.config.subdomain')}</span>
							</label>
							<label class="checkbox-item">
								<input type="checkbox" bind:checked={checkIp} disabled={processing} />
								<span>{$tr('osintGather.config.ip')}</span>
							</label>
							<label class="checkbox-item">
								<input type="checkbox" bind:checked={checkUrl} disabled={processing} />
								<span>{$tr('osintGather.config.url')}</span>
							</label>
							<label class="checkbox-item">
								<input type="checkbox" bind:checked={checkDns} disabled={processing} />
								<span>{$tr('osintGather.config.dns')}</span>
							</label>
						</div>
					</div>

					<div class="form-group">
						<label class="form-label">{$tr('osintGather.config.maxResults')}</label>
						<input type="number" bind:value={maxResults} min="10" max="1000" class="form-input" disabled={processing} />
					</div>

					<div class="form-group">
						<label class="form-label">{$tr('osintGather.config.timeout')}</label>
						<input type="number" bind:value={timeout} min="10" max="120" class="form-input" disabled={processing} />
					</div>

					<div class="button-group">
						<button class="btn-primary" onclick={gather} disabled={processing}>
							{#if processing}<span class="spinner"></span> {$tr('osintGather.gathering')}{:else}🔍 {$tr('osintGather.startGather')}{/if}
						</button>
						<button class="btn-secondary" onclick={clearAll} disabled={processing}>🗑️</button>
					</div>
				</div>
			</div>

			<div class="result-section">
				<div class="section-card">
					<h2 class="section-title">{$tr('osintGather.result.title')}</h2>

					{#if error}
						<div class="error-card">
							<div class="error-icon">⚠️</div>
							<div class="error-text">{error}</div>
						</div>
					{:else if result}
						<div class="summary-banner">
							<div class="summary-info">
								<span class="domain-badge">{$tr('osintGather.target')}</span>
								<span class="query-text">{(result as OsintGatherResult).target}</span>
							</div>
							<div class="summary-badges">
								<span class="summary-badge purple">{(result as OsintGatherResult).emails.length} {$tr('osintGather.result.emails')}</span>
								<span class="summary-badge purple">{(result as OsintGatherResult).subdomains.length} {$tr('osintGather.result.subdomains')}</span>
								<span class="summary-badge gray">{(result as OsintGatherResult).dns_records.length} {$tr('osintGather.result.dns')}</span>
								{#if (result as OsintGatherResult).security_findings.length > 0}
									<span class="summary-badge red">{(result as OsintGatherResult).security_findings.length} {$tr('osintGather.result.findings')}</span>
								{/if}
							</div>
						</div>

						<div class="stats-grid">
							<div class="stat-card">
								<div class="stat-value purple">{totalData}</div>
								<div class="stat-label">{$tr('osintGather.result.totalData')}</div>
							</div>
							<div class="stat-card">
								<div class="stat-value green">{(result as OsintGatherResult).emails.length}</div>
								<div class="stat-label">{$tr('osintGather.result.emails')}</div>
							</div>
							<div class="stat-card">
								<div class="stat-value purple">{(result as OsintGatherResult).subdomains.length}</div>
								<div class="stat-label">{$tr('osintGather.result.subdomains')}</div>
							</div>
							<div class="stat-card">
								<div class="stat-value red">{(result as OsintGatherResult).security_findings.length}</div>
								<div class="stat-label">{$tr('osintGather.result.findings')}</div>
							</div>
						</div>

						<div class="result-tabs">
							<button class="result-tab {activeResultTab === 'overview' ? 'active' : ''}" onclick={() => activeResultTab = 'overview'}>{$tr('osintGather.tabs.overview')}</button>
							<button class="result-tab {activeResultTab === 'emails' ? 'active' : ''}" onclick={() => activeResultTab = 'emails'}>{$tr('osintGather.tabs.emails')}</button>
							<button class="result-tab {activeResultTab === 'subdomains' ? 'active' : ''}" onclick={() => activeResultTab = 'subdomains'}>{$tr('osintGather.tabs.subdomains')}</button>
							<button class="result-tab {activeResultTab === 'ips' ? 'active' : ''}" onclick={() => activeResultTab = 'ips'}>{$tr('osintGather.tabs.ips')}</button>
							<button class="result-tab {activeResultTab === 'urls' ? 'active' : ''}" onclick={() => activeResultTab = 'urls'}>{$tr('osintGather.tabs.urls')}</button>
							<button class="result-tab {activeResultTab === 'dns' ? 'active' : ''}" onclick={() => activeResultTab = 'dns'}>{$tr('osintGather.tabs.dns')}</button>
							<button class="result-tab {activeResultTab === 'findings' ? 'active' : ''}" onclick={() => activeResultTab = 'findings'}>{$tr('osintGather.tabs.findings')}</button>
						</div>

						{#if activeResultTab === 'overview'}
							<div class="items-list">
								{#if (result as OsintGatherResult).emails.length > 0}
									<div>
										<h3 class="item-section-title">{$tr('osintGather.result.emails')} ({(result as OsintGatherResult).emails.length})</h3>
										<div class="tag-grid">
											{#each (result as OsintGatherResult).emails as email}
												<span class="tag-item green">
													{email.address}
													{#if email.breach_count}
														<span class="breach-tag">({email.breach_count} {$tr('osintGather.result.breachCount')})</span>
													{/if}
												</span>
											{/each}
										</div>
									</div>
								{/if}
								{#if (result as OsintGatherResult).subdomains.length > 0}
									<div>
										<h3 class="item-section-title">{$tr('osintGather.result.subdomains')} ({(result as OsintGatherResult).subdomains.length})</h3>
										<div class="tag-grid">
											{#each (result as OsintGatherResult).subdomains as sub}
												<span class="tag-item purple">
													{sub.subdomain}
													{#if !sub.is_active}<span class="inactive-tag">({$tr('osintGather.result.inactive')})</span>{/if}
												</span>
											{/each}
										</div>
									</div>
								{/if}
								{#if (result as OsintGatherResult).urls.length > 0}
									<div>
										<h3 class="item-section-title">{$tr('osintGather.result.urls')} ({(result as OsintGatherResult).urls.length})</h3>
										<div class="url-list">
											{#each (result as OsintGatherResult).urls as url_item}
												<div class="url-item">
													<span class="url-link">{url_item.url}</span>
													{#if url_item.title}<span class="url-title">- {url_item.title}</span>{/if}
												</div>
											{/each}
										</div>
									</div>
								{/if}
							</div>
						{:else if activeResultTab === 'emails'}
							{#if (result as OsintGatherResult).emails.length > 0}
								<div class="table-wrap">
									<table class="data-table">
										<thead>
											<tr>
												<th>{$tr('osintGather.config.email')}</th>
												<th>{$tr('osintGather.result.source')}</th>
												<th>{$tr('osintGather.result.valid')}</th>
												<th>{$tr('osintGather.result.breachTimes')}</th>
											</tr>
										</thead>
										<tbody>
											{#each (result as OsintGatherResult).emails as email}
												<tr>
													<td class="mono green">{email.address}</td>
													<td class="muted">{email.source}</td>
													<td>{email.is_valid ? '✓' : '✗'}</td>
													<td>{email.breach_count ?? '-'}</td>
												</tr>
											{/each}
										</tbody>
									</table>
								</div>
							{:else}
								<div class="empty-item">{$tr('osintGather.result.emails')}: 0</div>
							{/if}
						{:else if activeResultTab === 'subdomains'}
							{#if (result as OsintGatherResult).subdomains.length > 0}
								<div class="table-wrap">
									<table class="data-table">
										<thead>
											<tr>
												<th>{$tr('osintGather.config.subdomain')}</th>
												<th>IP</th>
												<th>{$tr('osintGather.result.active')}</th>
												<th>{$tr('osintGather.result.source')}</th>
											</tr>
										</thead>
										<tbody>
											{#each (result as OsintGatherResult).subdomains as sub}
												<tr>
													<td class="mono purple">{sub.subdomain}</td>
													<td class="mono">{sub.ip || '-'}</td>
													<td>{#if sub.is_active}<span class="status-active">{$tr('osintGather.result.active')}</span>{:else}<span class="status-inactive">{$tr('osintGather.result.inactive')}</span>{/if}</td>
													<td class="muted">{sub.source}</td>
												</tr>
											{/each}
										</tbody>
									</table>
								</div>
							{:else}
								<div class="empty-item">{$tr('osintGather.result.subdomains')}: 0</div>
							{/if}
						{:else if activeResultTab === 'ips'}
							{#if (result as OsintGatherResult).ip_addresses.length > 0}
								<div class="items-list">
									{#each (result as OsintGatherResult).ip_addresses as ip_info}
										<div class="ip-card">
											<div class="ip-header">
												<span class="ip-address">{ip_info.ip}</span>
												<span class="ip-source">{$tr('osintGather.result.source')}: {ip_info.source}</span>
											</div>
											<div class="ip-details">
												{#if ip_info.hostname}<span>{$tr('osintGather.result.hostname')}: {ip_info.hostname}</span>{/if}
												{#if ip_info.country}<span>{$tr('osintGather.result.country')}: {ip_info.country}</span>{/if}
												{#if ip_info.org}<span>{$tr('osintGather.result.org')}: {ip_info.org}</span>{/if}
												{#if ip_info.asn}<span>ASN: {ip_info.asn}</span>{/if}
											</div>
										</div>
									{/each}
								</div>
							{:else}
								<div class="empty-item">IP: 0</div>
							{/if}
						{:else if activeResultTab === 'urls'}
							{#if (result as OsintGatherResult).urls.length > 0}
								<div class="items-list">
									{#each (result as OsintGatherResult).urls as url_item}
										<div class="url-card">
											<div class="url-link-main">{url_item.url}</div>
											{#if url_item.title}<div class="url-title-sub">{url_item.title}</div>{/if}
											<div class="url-source">{$tr('osintGather.result.source')}: {url_item.source}</div>
										</div>
									{/each}
								</div>
							{:else}
								<div class="empty-item">URL: 0</div>
							{/if}
						{:else if activeResultTab === 'dns'}
							{#if (result as OsintGatherResult).dns_records.length > 0}
								<div class="table-wrap">
									<table class="data-table">
										<thead>
											<tr>
												<th>Type</th>
												<th>Name</th>
												<th>Value</th>
												<th>TTL</th>
											</tr>
										</thead>
										<tbody>
											{#each (result as OsintGatherResult).dns_records as record}
												<tr>
													<td><span class="dns-type">{record.record_type}</span></td>
													<td class="mono">{record.name}</td>
													<td class="mono dns-value">{record.value}</td>
													<td>{record.ttl}</td>
												</tr>
											{/each}
										</tbody>
									</table>
								</div>
							{:else}
								<div class="empty-item">DNS: 0</div>
							{/if}
						{:else if activeResultTab === 'findings'}
							{#if (result as OsintGatherResult).security_findings.length > 0}
								<div class="items-list">
									{#each (result as OsintGatherResult).security_findings as finding}
										<div class="finding-card" style="border-left-color: {getSeverityBorder(finding.severity)}; background: {getSeverityBg(finding.severity)};">
											<div class="finding-header">
												<span class="severity-badge" style="background: {getSeverityBorder(finding.severity)}; color: {getSeverityColor(finding.severity)};">{translateSeverity(finding.severity)}</span>
												<span class="finding-category">{translateCategory(finding.category)}</span>
											</div>
											<p class="finding-desc">{finding.description}</p>
											<p class="finding-rec">{$tr('osintGather.result.recommendation')}: {finding.recommendation}</p>
										</div>
									{/each}
								</div>
							{:else}
								<div class="empty-item">{$tr('osintGather.result.findings')}: 0</div>
							{/if}
						{/if}
					{:else}
						<div class="empty-state">
							<div class="empty-icon">🕵️</div>
							<p>{$tr('osintGather.result.noResults')}</p>
						</div>
					{/if}
				</div>
			</div>
		</div>
	{:else if activeMainTab === 'history'}
		<ToolHistory bind:this={historyComponent} toolType="osint_gather" toolName={$tr('osintGather.title')} />
	{:else if activeMainTab === 'help'}
		<ToolHelp toolType="osint_gather" />
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

	.checkbox-group { display: flex; flex-direction: column; gap: 0.4rem; }
	.checkbox-item { display: flex; align-items: center; gap: 0.5rem; cursor: pointer; font-size: 0.85rem; color: #cbd5e1; }
	.checkbox-item input[type="checkbox"] { accent-color: #a855f7; }
	.checkbox-item:has(input:disabled) { opacity: 0.6; }

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
	.domain-badge { padding: 0.2rem 0.6rem; background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%); border-radius: 0.3rem; font-size: 0.7rem; font-weight: 700; color: white; letter-spacing: 0.05em; }
	.query-text { font-size: 0.85rem; color: #f1f5f9; font-weight: 500; font-family: 'SF Mono', 'Fira Code', monospace; }
	.summary-badges { display: flex; gap: 0.5rem; flex-wrap: wrap; }
	.summary-badge { padding: 0.25rem 0.6rem; border-radius: 0.4rem; font-size: 0.75rem; font-weight: 600; }
	.summary-badge.purple { background: rgba(168, 85, 247, 0.15); color: #c4b5fd; border: 1px solid rgba(168, 85, 247, 0.3); }
	.summary-badge.gray { background: rgba(148, 163, 184, 0.15); color: #94a3b8; border: 1px solid rgba(148, 163, 184, 0.3); }
	.summary-badge.red { background: rgba(239, 68, 68, 0.15); color: #fca5a5; border: 1px solid rgba(239, 68, 68, 0.3); }

	.stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 0.75rem; margin-bottom: 1rem; }
	.stat-card { background: rgba(15, 23, 42, 0.4); border: 1px solid rgba(148, 163, 184, 0.08); border-radius: 0.5rem; padding: 0.75rem; text-align: center; }
	.stat-value { font-size: 1.25rem; font-weight: 700; }
	.stat-value.purple { color: #c4b5fd; }
	.stat-value.green { color: #86efac; }
	.stat-value.red { color: #fca5a5; }
	.stat-label { font-size: 0.7rem; color: #64748b; margin-top: 0.2rem; }

	.result-tabs { display: flex; gap: 0.25rem; margin-bottom: 1rem; flex-wrap: wrap; }
	.result-tab { padding: 0.4rem 0.75rem; border-radius: 0.4rem; border: 1px solid rgba(148, 163, 184, 0.15); background: rgba(15, 23, 42, 0.4); color: #94a3b8; cursor: pointer; font-size: 0.8rem; transition: all 0.2s; }
	.result-tab.active { background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%); color: white; border-color: transparent; font-weight: 600; }
	.result-tab:hover:not(.active) { border-color: rgba(168, 85, 247, 0.3); color: #c4b5fd; }

	.items-list { display: flex; flex-direction: column; gap: 0.5rem; }
	.item-section-title { font-size: 0.85rem; font-weight: 600; color: #cbd5e1; margin: 0.75rem 0 0.5rem; }
	.item-section-title:first-child { margin-top: 0; }

	.tag-grid { display: flex; flex-wrap: wrap; gap: 0.4rem; }
	.tag-item { padding: 0.3rem 0.6rem; border-radius: 0.4rem; font-size: 0.8rem; font-family: 'SF Mono', 'Fira Code', monospace; }
	.tag-item.green { background: rgba(34, 197, 94, 0.1); color: #86efac; border: 1px solid rgba(34, 197, 94, 0.2); }
	.tag-item.purple { background: rgba(168, 85, 247, 0.1); color: #c4b5fd; border: 1px solid rgba(168, 85, 247, 0.2); }
	.breach-tag { color: #fca5a5; margin-left: 0.25rem; font-size: 0.7rem; }
	.inactive-tag { color: #64748b; margin-left: 0.25rem; font-size: 0.7rem; }

	.url-list { display: flex; flex-direction: column; gap: 0.25rem; }
	.url-item { font-size: 0.8rem; padding: 0.2rem 0; }
	.url-link { color: #c4b5fd; }
	.url-title { color: #94a3b8; margin-left: 0.5rem; }

	.table-wrap { overflow-x: auto; }
	.data-table { width: 100%; font-size: 0.85rem; border-collapse: collapse; }
	.data-table thead tr { color: #94a3b8; border-bottom: 1px solid rgba(168, 85, 247, 0.15); }
	.data-table th { text-align: left; padding: 0.5rem 0.75rem; font-weight: 500; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; }
	.data-table td { padding: 0.5rem 0.75rem; border-bottom: 1px solid rgba(148, 163, 184, 0.08); color: #cbd5e1; }
	.data-table tbody tr:hover { background: rgba(168, 85, 247, 0.05); }
	.mono { font-family: 'SF Mono', 'Fira Code', monospace; font-size: 0.8rem; }
	.mono.green { color: #86efac; }
	.mono.purple { color: #c4b5fd; }
	.muted { color: #64748b; }

	.status-active { color: #86efac; font-size: 0.8rem; }
	.status-inactive { color: #64748b; font-size: 0.8rem; }

	.ip-card { padding: 0.75rem; background: rgba(15, 23, 42, 0.4); border: 1px solid rgba(148, 163, 184, 0.08); border-radius: 0.5rem; border-left: 3px solid rgba(245, 158, 11, 0.5); }
	.ip-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.3rem; }
	.ip-address { font-family: 'SF Mono', 'Fira Code', monospace; font-weight: 600; color: #fbbf24; font-size: 0.9rem; }
	.ip-source { font-size: 0.75rem; color: #64748b; }
	.ip-details { display: grid; grid-template-columns: 1fr 1fr; gap: 0.25rem; font-size: 0.8rem; color: #94a3b8; }

	.url-card { padding: 0.75rem; background: rgba(15, 23, 42, 0.4); border: 1px solid rgba(148, 163, 184, 0.08); border-radius: 0.5rem; border-left: 3px solid rgba(168, 85, 247, 0.5); }
	.url-link-main { font-family: 'SF Mono', 'Fira Code', monospace; font-size: 0.85rem; color: #c4b5fd; word-break: break-all; }
	.url-title-sub { font-size: 0.8rem; color: #cbd5e1; margin-top: 0.2rem; }
	.url-source { font-size: 0.7rem; color: #64748b; margin-top: 0.2rem; }

	.dns-type { padding: 0.15rem 0.4rem; background: rgba(168, 85, 247, 0.15); color: #c4b5fd; border-radius: 0.2rem; font-size: 0.75rem; font-weight: 600; }
	.dns-value { max-width: 300px; word-break: break-all; font-size: 0.75rem; }

	.finding-card { padding: 0.75rem; border-radius: 0.5rem; border-left: 3px solid; }
	.finding-header { display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.3rem; }
	.severity-badge { padding: 0.15rem 0.5rem; border-radius: 0.3rem; font-size: 0.7rem; font-weight: 600; text-transform: uppercase; }
	.finding-category { font-size: 0.85rem; font-weight: 500; color: #f1f5f9; }
	.finding-desc { font-size: 0.85rem; color: #cbd5e1; margin: 0.3rem 0; }
	.finding-rec { font-size: 0.8rem; color: #86efac; margin: 0.3rem 0 0; }

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
		.stats-grid { grid-template-columns: repeat(2, 1fr); }
		.summary-banner { flex-direction: column; align-items: flex-start; gap: 0.5rem; }
	}
</style>
