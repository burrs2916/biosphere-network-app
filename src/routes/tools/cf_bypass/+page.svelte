<script lang="ts">
	import { tr } from '$lib/i18n';
	import ToolHistory from '$lib/components/ToolHistory.svelte';
	import ToolHelp from '$lib/components/ToolHelp.svelte';

	interface OriginIp {
		ip: string;
		source: string;
		confidence: string;
		is_verified: boolean;
	}

	interface BypassMethod {
		method: string;
		description: string;
		result: string;
		success: boolean;
	}

	interface DnsHistoryRecord {
		domain: string;
		ip: string;
		record_type: string;
		first_seen: string;
		last_seen: string;
		provider: string;
	}

	interface SubdomainRecord {
		subdomain: string;
		ip: string;
		is_cf_protected: boolean;
		service: string | null;
	}

	interface SslCertificateInfo {
		issuer: string;
		subject: string;
		serial: string;
		not_before: string;
		not_after: string;
		san_domains: string[];
		possible_origin: string | null;
	}

	interface CfBypassFinding {
		severity: string;
		category: string;
		description: string;
		recommendation: string;
	}

	interface CfBypassResult {
		success: boolean;
		domain: string;
		is_behind_cf: boolean;
		cf_ips: string[];
		origin_ips: OriginIp[];
		methods: BypassMethod[];
		dns_history: DnsHistoryRecord[];
		subdomain_ips: SubdomainRecord[];
		ssl_info: SslCertificateInfo | null;
		security_findings: CfBypassFinding[];
		summary: string;
	}

	let domain = $state('');
	let checkDnsHistory = $state(true);
	let checkSubdomains = $state(true);
	let checkSslCerts = $state(true);
	let checkMailHeaders = $state(true);
	let timeout = $state(30);
	let result: CfBypassResult | null = $state(null);
	let error = $state('');
	let processing = $state(false);
	let activeMainTab = $state('bypass');
	let activeResultTab = $state('origin');

	let historyComponent: ToolHistory;

	async function bypass() {
		if (!domain.trim()) { error = $tr('cfBypass.error.domainRequired'); return; }
		processing = true; error = ''; result = null;
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			result = await invoke<CfBypassResult>('cf_bypass_command', {
				config: {
					domain: domain.trim(),
					timeout,
					check_dns_history: checkDnsHistory,
					check_subdomains: checkSubdomains,
					check_ssl_certs: checkSslCerts,
					check_mail_headers: checkMailHeaders,
				}
			});
			if (result && historyComponent) {
				await historyComponent.saveHistory(domain.trim(), JSON.stringify(result), result.summary, 'completed');
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

	function clearAll() { domain = ''; result = null; error = ''; }

	function getSeverityColor(s: string): string {
		switch (s) { case 'critical': return '#dc2626'; case 'high': return '#ef4444'; case 'medium': return '#f59e0b'; case 'low': return '#3b82f6'; default: return '#6b7280'; }
	}

	function translateSeverity(s: string): string {
		const key = `cfBypass.severity.${s}`;
		const val = $tr(key);
		return val !== key ? val : s;
	}

	function translateConfidence(s: string): string {
		const key = `cfBypass.confidence.${s}`;
		const val = $tr(key);
		return val !== key ? val : s;
	}
</script>

<div class="nd-page">
	<div class="page-header">
		<div class="header-left">
			<a href="/" class="back-link">{$tr('common.backToHome')}</a>
			<h1 class="page-title">☁️ {$tr('cfBypass.title')}</h1>
			<p class="page-subtitle">{$tr('cfBypass.subtitle')}</p>
		</div>
	</div>

	<div class="tabs">
		<button class="tab-btn {activeMainTab === 'bypass' ? 'active' : ''}" onclick={() => activeMainTab = 'bypass'}>
			<span class="tab-icon">☁️</span> {$tr('cfBypass.bypass')}
		</button>
		<button class="tab-btn {activeMainTab === 'history' ? 'active' : ''}" onclick={() => activeMainTab = 'history'}>
			<span class="tab-icon">📋</span> {$tr('cfBypass.history')}
		</button>
		<button class="tab-btn {activeMainTab === 'help' ? 'active' : ''}" onclick={() => activeMainTab = 'help'}>
			<span class="tab-icon">📖</span> {$tr('cfBypass.help')}
		</button>
	</div>

	{#if activeMainTab === 'bypass'}
		<div class="content-grid">
			<div class="input-section">
				<div class="section-card">
					<h2 class="section-title">{$tr('cfBypass.config.title')}</h2>
					<p class="section-desc">{$tr('cfBypass.config.desc')}</p>

					<div class="form-group">
						<label class="form-label">{$tr('cfBypass.config.domain')}</label>
						<input type="text" bind:value={domain} placeholder="e.g. example.com" class="form-input" disabled={processing} />
					</div>

					<div class="checkbox-group">
						<label class="checkbox-label">
							<input type="checkbox" bind:checked={checkDnsHistory} disabled={processing} />
							<span class="checkbox-text">{$tr('cfBypass.config.checkDnsHistory')}</span>
						</label>
					</div>

					<div class="checkbox-group">
						<label class="checkbox-label">
							<input type="checkbox" bind:checked={checkSubdomains} disabled={processing} />
							<span class="checkbox-text">{$tr('cfBypass.config.checkSubdomains')}</span>
						</label>
					</div>

					<div class="checkbox-group">
						<label class="checkbox-label">
							<input type="checkbox" bind:checked={checkSslCerts} disabled={processing} />
							<span class="checkbox-text">{$tr('cfBypass.config.checkSslCerts')}</span>
						</label>
					</div>

					<div class="checkbox-group">
						<label class="checkbox-label">
							<input type="checkbox" bind:checked={checkMailHeaders} disabled={processing} />
							<span class="checkbox-text">{$tr('cfBypass.config.checkMailHeaders')}</span>
						</label>
					</div>

					<div class="form-group">
						<label class="form-label">{$tr('cfBypass.config.timeout')}</label>
						<input type="number" bind:value={timeout} min="5" max="120" class="form-input" disabled={processing} />
					</div>

					<div class="button-group">
						<button class="btn-primary" onclick={bypass} disabled={processing || !domain.trim()}>
							{#if processing}<span class="spinner"></span> {$tr('cfBypass.bypassing')}{:else}☁️ {$tr('cfBypass.startBypass')}{/if}
						</button>
						<button class="btn-secondary" onclick={clearAll} disabled={processing}>🗑️</button>
					</div>
				</div>
			</div>

			<div class="result-section">
				<div class="section-card">
					<h2 class="section-title">{$tr('cfBypass.result.title')}</h2>
					{#if error}
						<div class="error-card"><div class="error-icon">⚠️</div><div class="error-text">{error}</div></div>
					{:else if result}
						<div class="summary-banner">
							<div class="summary-info">
								<span class="domain-badge">{$tr('cfBypass.domain')}</span>
								<span class="query-text">{result.domain}</span>
							</div>
							<div class="summary-badges">
								{#if result.is_behind_cf}
									<span class="summary-badge orange">{$tr('cfBypass.status.cfEnabled')}</span>
								{:else}
									<span class="summary-badge green">{$tr('cfBypass.status.cfNotDetected')}</span>
								{/if}
								{#if result.origin_ips.length > 0}
									<span class="summary-badge red">{result.origin_ips.length} {$tr('cfBypass.result.originIps')}</span>
								{/if}
							</div>
						</div>

						<div class="result-tabs">
							<button class="result-tab {activeResultTab === 'origin' ? 'active' : ''}" onclick={() => activeResultTab = 'origin'}>🔍 {$tr('cfBypass.tabs.origin')} ({result.origin_ips.length})</button>
							<button class="result-tab {activeResultTab === 'methods' ? 'active' : ''}" onclick={() => activeResultTab = 'methods'}>🛠️ {$tr('cfBypass.tabs.methods')}</button>
							<button class="result-tab {activeResultTab === 'dns' ? 'active' : ''}" onclick={() => activeResultTab = 'dns'}>📜 {$tr('cfBypass.tabs.dnsHistory')} ({result.dns_history.length})</button>
							<button class="result-tab {activeResultTab === 'subdomains' ? 'active' : ''}" onclick={() => activeResultTab = 'subdomains'}>🌐 {$tr('cfBypass.tabs.subdomains')} ({result.subdomain_ips.length})</button>
							<button class="result-tab {activeResultTab === 'ssl' ? 'active' : ''}" onclick={() => activeResultTab = 'ssl'}>🔒 {$tr('cfBypass.tabs.ssl')}</button>
							<button class="result-tab {activeResultTab === 'findings' ? 'active' : ''}" onclick={() => activeResultTab = 'findings'}>🛡️ {$tr('cfBypass.tabs.findings')} ({result.security_findings.length})</button>
						</div>

						{#if activeResultTab === 'origin'}
							<div class="items-list">
								{#if result.cf_ips.length > 0}
									<div class="cf-ips-section">
										<h3 class="sub-title">CloudFlare IP</h3>
										<div class="tag-list">
											{#each result.cf_ips as cfip}
												<span class="cf-ip-tag">{cfip}</span>
											{/each}
										</div>
									</div>
								{/if}

								<h3 class="sub-title">{$tr('cfBypass.result.possibleOrigin')}</h3>
								{#each result.origin_ips as origin}
									<div class="item-card" style="border-left-color: #ef4444">
										<div class="item-header">
											<span class="ip-name">{origin.ip}</span>
											<div class="status-area">
												<span class="confidence-badge confidence-{origin.confidence}">{translateConfidence(origin.confidence)}</span>
												{#if origin.is_verified}
													<span class="verified-badge">✓</span>
												{/if}
											</div>
										</div>
										<div class="origin-source">{$tr('cfBypass.result.source')}: {origin.source}</div>
									</div>
								{/each}
								{#if result.origin_ips.length === 0}
									<div class="empty-item">{$tr('cfBypass.status.noOriginIps')}</div>
								{/if}
							</div>
						{:else if activeResultTab === 'methods'}
							<div class="items-list">
								{#each result.methods as method}
									<div class="item-card" style="border-left-color: {method.success ? '#22c55e' : '#475569'}">
										<div class="item-header">
											<span class="item-title">{method.method}</span>
											{#if method.success}
												<span class="success-badge">{$tr('cfBypass.result.success')}</span>
											{:else}
												<span class="fail-badge">{$tr('cfBypass.result.notFound')}</span>
											{/if}
										</div>
										<p class="item-desc">{method.description}</p>
										<p class="item-result">{method.result}</p>
									</div>
								{/each}
							</div>
						{:else if activeResultTab === 'dns'}
							{#if result.dns_history.length > 0}
								<div class="table-wrap">
									<table class="data-table">
										<thead>
											<tr>
												<th>{$tr('cfBypass.dnsHistory.domain')}</th>
												<th>{$tr('cfBypass.dnsHistory.ip')}</th>
												<th>{$tr('cfBypass.dnsHistory.type')}</th>
												<th>{$tr('cfBypass.dnsHistory.firstSeen')}</th>
												<th>{$tr('cfBypass.dnsHistory.lastSeen')}</th>
												<th>{$tr('cfBypass.dnsHistory.provider')}</th>
											</tr>
										</thead>
										<tbody>
											{#each result.dns_history as entry}
												<tr>
													<td class="mono">{entry.domain}</td>
													<td class="mono ip-red">{entry.ip}</td>
													<td><span class="record-badge">{entry.record_type}</span></td>
													<td class="muted">{entry.first_seen}</td>
													<td class="muted">{entry.last_seen}</td>
													<td class="muted">{entry.provider}</td>
												</tr>
											{/each}
										</tbody>
									</table>
								</div>
							{:else}
								<div class="empty-item">{$tr('cfBypass.status.noDnsHistory')}</div>
							{/if}
						{:else if activeResultTab === 'subdomains'}
							<div class="items-list">
								{#each result.subdomain_ips as sub}
									<div class="item-card" style="border-left-color: {sub.is_cf_protected ? '#22c55e' : '#ef4444'}">
										<div class="item-header">
											<span class="domain-name">{sub.subdomain}</span>
											<span class="arrow">→</span>
											<span class="ip-name">{sub.ip}</span>
											{#if sub.service}
												<span class="service-badge">{sub.service}</span>
											{/if}
											<div class="status-area">
												{#if sub.is_cf_protected}
													<span class="cf-protected-badge">{$tr('cfBypass.subdomain.cfProtected')}</span>
												{:else}
													<span class="cf-unprotected-badge">{$tr('cfBypass.subdomain.unprotected')}</span>
												{/if}
											</div>
										</div>
									</div>
								{/each}
								{#if result.subdomain_ips.length === 0}
									<div class="empty-item">{$tr('cfBypass.status.noSubdomains')}</div>
								{/if}
							</div>
						{:else if activeResultTab === 'ssl'}
							{#if result.ssl_info}
								<div class="ssl-card">
									<div class="ssl-grid">
										<div class="ssl-field">
											<span class="ssl-label">{$tr('cfBypass.ssl.issuer')}</span>
											<p class="ssl-value">{result.ssl_info.issuer}</p>
										</div>
										<div class="ssl-field">
											<span class="ssl-label">{$tr('cfBypass.ssl.subject')}</span>
											<p class="ssl-value">{result.ssl_info.subject}</p>
										</div>
										<div class="ssl-field">
											<span class="ssl-label">{$tr('cfBypass.ssl.validity')}</span>
											<p class="ssl-value">{result.ssl_info.not_before} → {result.ssl_info.not_after}</p>
										</div>
										<div class="ssl-field">
											<span class="ssl-label">{$tr('cfBypass.ssl.serial')}</span>
											<p class="ssl-value mono">{result.ssl_info.serial}</p>
										</div>
									</div>
									<div class="ssl-field" style="margin-top: 0.75rem">
										<span class="ssl-label">{$tr('cfBypass.ssl.sanDomains')}</span>
										<div class="tag-list" style="margin-top: 0.3rem">
											{#each result.ssl_info.san_domains as d}
												<span class="info-tag">{d}</span>
											{/each}
										</div>
									</div>
									{#if result.ssl_info.possible_origin}
										<div class="origin-hint">
											<span class="origin-hint-label">{$tr('cfBypass.ssl.possibleOrigin')}</span>
											<span class="origin-hint-ip">{result.ssl_info.possible_origin}</span>
										</div>
									{/if}
								</div>
							{:else}
								<div class="empty-item">{$tr('cfBypass.status.noSslInfo')}</div>
							{/if}
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
									<div class="empty-item">{$tr('cfBypass.status.noFindings')}</div>
								{/if}
							</div>
						{/if}
					{:else}
						<div class="empty-state">
							<div class="empty-icon">☁️</div>
							<p>{$tr('cfBypass.result.noResults')}</p>
						</div>
					{/if}
				</div>
			</div>
		</div>
	{:else if activeMainTab === 'history'}
		<div class="section-card"><ToolHistory toolType="cf_bypass" toolName={$tr('cfBypass.title')} bind:this={historyComponent} /></div>
	{:else if activeMainTab === 'help'}
		<div class="section-card"><ToolHelp toolType="cf_bypass" /></div>
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
	.domain-badge { padding: 0.2rem 0.6rem; background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%); border-radius: 0.3rem; font-size: 0.7rem; font-weight: 700; color: white; letter-spacing: 0.05em; }
	.query-text { font-size: 0.85rem; color: #f1f5f9; font-weight: 500; font-family: 'SF Mono', 'Fira Code', monospace; }
	.summary-badges { display: flex; gap: 0.5rem; }
	.summary-badge { padding: 0.25rem 0.6rem; border-radius: 0.4rem; font-size: 0.75rem; font-weight: 600; }
	.summary-badge.orange { background: rgba(249, 115, 22, 0.15); color: #fb923c; border: 1px solid rgba(249, 115, 22, 0.3); }
	.summary-badge.green { background: rgba(34, 197, 94, 0.15); color: #86efac; border: 1px solid rgba(34, 197, 94, 0.3); }
	.summary-badge.red { background: rgba(239, 68, 68, 0.15); color: #fca5a5; border: 1px solid rgba(239, 68, 68, 0.3); }

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
	.item-result { font-size: 0.8rem; color: #cbd5e1; margin-top: 0.2rem; }

	.domain-name { font-family: 'SF Mono', 'Fira Code', monospace; font-weight: 600; font-size: 0.85rem; color: #c4b5fd; }
	.ip-name { font-family: 'SF Mono', 'Fira Code', monospace; font-weight: 600; font-size: 0.9rem; color: #fca5a5; }
	.arrow { color: #64748b; font-size: 0.8rem; }
	.record-badge { padding: 0.1rem 0.4rem; background: rgba(148, 163, 184, 0.15); border-radius: 0.25rem; font-size: 0.7rem; color: #94a3b8; text-transform: uppercase; }
	.service-badge { padding: 0.1rem 0.4rem; background: rgba(168, 85, 247, 0.15); color: #c4b5fd; border-radius: 0.25rem; font-size: 0.7rem; }
	.status-area { margin-left: auto; display: flex; align-items: center; gap: 0.5rem; }

	.confidence-badge { padding: 0.15rem 0.5rem; border-radius: 0.3rem; font-size: 0.7rem; font-weight: 600; }
	.confidence-high { background: rgba(34, 197, 94, 0.15); color: #86efac; }
	.confidence-medium { background: rgba(245, 158, 11, 0.15); color: #fbbf24; }
	.confidence-low { background: rgba(239, 68, 68, 0.15); color: #fca5a5; }
	.verified-badge { color: #22c55e; font-weight: 700; font-size: 0.85rem; }
	.origin-source { font-size: 0.75rem; color: #94a3b8; margin-top: 0.2rem; }

	.success-badge { padding: 0.1rem 0.4rem; background: rgba(34, 197, 94, 0.15); color: #86efac; border-radius: 0.25rem; font-size: 0.7rem; font-weight: 600; }
	.fail-badge { padding: 0.1rem 0.4rem; background: rgba(148, 163, 184, 0.1); color: #64748b; border-radius: 0.25rem; font-size: 0.7rem; }
	.cf-protected-badge { padding: 0.1rem 0.4rem; background: rgba(34, 197, 94, 0.15); color: #86efac; border-radius: 0.25rem; font-size: 0.7rem; font-weight: 600; }
	.cf-unprotected-badge { padding: 0.1rem 0.4rem; background: rgba(239, 68, 68, 0.15); color: #fca5a5; border-radius: 0.25rem; font-size: 0.7rem; font-weight: 600; }

	.cf-ips-section { margin-bottom: 1rem; padding-bottom: 0.75rem; border-bottom: 1px solid rgba(148, 163, 184, 0.1); }
	.sub-title { font-size: 0.85rem; font-weight: 600; color: #94a3b8; margin: 0 0 0.5rem; }
	.cf-ip-tag { padding: 0.2rem 0.5rem; background: rgba(249, 115, 22, 0.1); color: #fb923c; border: 1px solid rgba(249, 115, 22, 0.2); border-radius: 0.3rem; font-size: 0.8rem; font-family: 'SF Mono', 'Fira Code', monospace; }

	.severity-badge { padding: 0.15rem 0.5rem; border-radius: 0.3rem; color: white; font-size: 0.7rem; font-weight: 600; text-transform: uppercase; }

	.tag-list { display: flex; flex-wrap: wrap; gap: 0.25rem; }
	.info-tag { padding: 0.1rem 0.4rem; background: rgba(168, 85, 247, 0.1); color: #c4b5fd; border-radius: 0.2rem; font-size: 0.7rem; }

	.ssl-card { background: rgba(15, 23, 42, 0.4); border: 1px solid rgba(148, 163, 184, 0.08); border-radius: 0.5rem; padding: 1rem; }
	.ssl-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 0.75rem; }
	.ssl-label { font-size: 0.7rem; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.05em; }
	.ssl-value { font-size: 0.85rem; color: #e2e8f0; margin: 0.2rem 0 0; }
	.origin-hint { margin-top: 0.75rem; padding: 0.5rem 0.75rem; background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.2); border-radius: 0.4rem; display: flex; align-items: center; gap: 0.5rem; }
	.origin-hint-label { font-size: 0.8rem; color: #fca5a5; }
	.origin-hint-ip { font-family: 'SF Mono', 'Fira Code', monospace; font-size: 0.85rem; color: #fca5a5; font-weight: 600; }

	.table-wrap { overflow-x: auto; }
	.data-table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
	.data-table th { text-align: left; padding: 0.5rem 0.75rem; color: #94a3b8; border-bottom: 1px solid rgba(148, 163, 184, 0.15); font-weight: 500; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; }
	.data-table td { padding: 0.5rem 0.75rem; border-bottom: 1px solid rgba(148, 163, 184, 0.08); color: #e2e8f0; }
	.data-table .mono { font-family: 'SF Mono', 'Fira Code', monospace; color: #c4b5fd; }
	.data-table .ip-red { color: #fca5a5; }
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
		.ssl-grid { grid-template-columns: 1fr; }
	}
	@media (max-width: 480px) {
		.nd-page { padding: 0.75rem; }
		.tabs { flex-wrap: wrap; }
		.tab-btn { font-size: 0.8rem; padding: 0.5rem 0.75rem; }
		.result-tabs { gap: 0.15rem; }
		.result-tab { font-size: 0.75rem; padding: 0.3rem 0.5rem; }
	}
</style>
