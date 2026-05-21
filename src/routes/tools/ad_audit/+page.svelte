<script lang="ts">
	import { tr } from '$lib/i18n';
	import ToolHistory from '$lib/components/ToolHistory.svelte';
	import ToolHelp from '$lib/components/ToolHelp.svelte';

	interface SmbShare { name: string; path: string; comment: string; readable: boolean; writable: boolean; risk_level: string; }
	interface CertTemplate { name: string; enabled: boolean; enrollment_allowed: boolean; authentication_enabled: boolean; vulnerable: boolean; reason: string; }
	interface TrustRelationship { trusted_domain: string; trust_type: string; trust_direction: string; transitive: boolean; sid_filtering: boolean; }
	interface GpoEntry { name: string; guid: string; status: string; applies_to: string; suspicious: boolean; reason: string; }
	interface AclEntry { object: string; principal: string; permission: string; risk_level: string; }
	interface AdIssue { category: string; severity: string; title: string; description: string; recommendation: string; mitre_attack: string | null; }
	interface KerberosInfo { pre_auth_not_required: string[]; as_rep_roastable: string[]; kerberoastable: string[]; weak_encryption: string[]; delegation_accounts: string[]; unconstrained_delegation: string[]; issues: AdIssue[]; }
	interface LdapInfo { domain_name: string; domain_sid: string; functional_level: string; users_count: number; groups_count: number; computers_count: number; admin_count: number; disabled_accounts: number; password_not_required: string[]; password_never_expires: string[]; anonymous_bind: boolean; ldap_signing: boolean; channel_binding: boolean; issues: AdIssue[]; }
	interface SmbInfo { shares: SmbShare[]; signing_required: boolean; smb_version: string; null_sessions: boolean; issues: AdIssue[]; }
	interface DnsInfo { zones: string[]; dynamic_updates: boolean; zone_transfer_possible: boolean; records_count: number; wpad_record: boolean; issues: AdIssue[]; }
	interface CertInfo { templates: CertTemplate[]; vulnerable_templates: string[]; esc1_vulnerable: string[]; esc8_vulnerable: boolean; issues: AdIssue[]; }
	interface TrustInfo { trust_relationships: TrustRelationship[]; issues: AdIssue[]; }
	interface GpoInfo { gpo_count: number; gpos: GpoEntry[]; unlinked_gpos: number; password_in_gpo: boolean; issues: AdIssue[]; }
	interface AclInfo { excessive_permissions: AclEntry[]; dcsync_possible: boolean; issues: AdIssue[]; }
	interface AdAuditResult { success: boolean; domain: string; kerberos_info: KerberosInfo; ldap_info: LdapInfo; smb_info: SmbInfo; dns_info: DnsInfo; cert_info: CertInfo; trust_info: TrustInfo; gpo_info: GpoInfo; acl_info: AclInfo; all_issues: AdIssue[]; total_issues: number; critical_issues: number; high_issues: number; summary: string; }

	let domain = $state('');
	let domainController = $state('');
	let username = $state('');
	let password = $state('');
	let checkKerberos = $state(true);
	let checkLdap = $state(true);
	let checkSmb = $state(true);
	let checkDns = $state(true);
	let checkCerts = $state(true);
	let checkTrust = $state(true);
	let checkGpo = $state(true);
	let checkAcl = $state(true);
	let checkDelegation = $state(true);
	let timeout = $state(60);
	let result: AdAuditResult | null = $state(null);
	let error = $state('');
	let processing = $state(false);
	let activeMainTab = $state('analyze');
	let activeResultTab = $state('overview');
	let historyComponent: ToolHistory = $state(null!);

	async function audit() {
		if (!domain.trim()) { error = $tr('adAudit.error.domainRequired'); return; }
		processing = true; error = ''; result = null;
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			result = await invoke<AdAuditResult>('audit_ad_command', {
				config: { domain: domain.trim(), domain_controller: domainController.trim() || null, username: username.trim() || null, password: password.trim() || null, check_kerberos: checkKerberos, check_ldap: checkLdap, check_smb: checkSmb, check_dns: checkDns, check_certs: checkCerts, check_trusts: checkTrust, check_gpo: checkGpo, check_acl: checkAcl, check_delegation: checkDelegation, timeout }
			});
			if (result && historyComponent) { await historyComponent.saveHistory(domain.trim(), JSON.stringify(result), result.summary, 'completed'); }
		} catch (e: any) {
			error = e.toString();
			if (historyComponent) { await historyComponent.saveHistory(domain.trim(), JSON.stringify({ error: e.toString() }), undefined, 'failed'); }
		} finally { processing = false; }
	}

	function clearAll() { domain = ''; domainController = ''; username = ''; password = ''; result = null; error = ''; activeResultTab = 'overview'; }

	function getSeverityColor(s: string): string {
		switch (s) { case 'critical': return '#dc2626'; case 'high': return '#ef4444'; case 'medium': return '#f59e0b'; case 'low': return '#3b82f6'; default: return '#6b7280'; }
	}

	function getRiskColor(risk: string): string {
		switch (risk) { case 'critical': case 'high': return '#ef4444'; case 'medium': return '#f59e0b'; case 'low': return '#22c55e'; default: return '#94a3b8'; }
	}

	function statusIcon(ok: boolean): string { return ok ? '✅' : '❌'; }
	function warnIcon(ok: boolean): string { return ok ? '⚠️' : '✅'; }

	function translateSeverity(s: string): string {
		const key = `adAudit.severity.${s}`;
		const translated = $tr(key);
		return translated === key ? s.toUpperCase() : translated;
	}

	function translateCategory(c: string): string {
		const map: Record<string, string> = {
			'Kerberos': 'adAudit.kerberos.title',
			'LDAP': 'adAudit.ldap.title',
			'SMB': 'adAudit.smb.title',
			'DNS': 'adAudit.dns.title',
			'Certificate': 'adAudit.certs.title',
			'Trust': 'adAudit.trust.title',
			'GPO': 'adAudit.gpo.title',
			'ACL': 'adAudit.acl.title',
		};
		const key = map[c];
		if (!key) return c;
		const translated = $tr(key);
		return translated === key ? c : translated;
	}

	function translateRiskLevel(r: string): string {
		const key = `adAudit.severity.${r}`;
		const translated = $tr(key);
		return translated === key ? r : translated;
	}

	function handleKeydown(e: KeyboardEvent) { if (e.key === 'Enter' && !processing && domain.trim()) { audit(); } }
</script>

<svelte:window on:keydown={handleKeydown} />

<div class="nd-page">
	<div class="page-header">
		<div class="header-left">
			<a href="/" class="back-link">{$tr('common.backToHome')}</a>
			<h1 class="page-title">🏢 {$tr('adAudit.title')}</h1>
			<p class="page-subtitle">{$tr('adAudit.subtitle')}</p>
		</div>
	</div>

	<div class="tabs">
		<button class="tab-btn {activeMainTab === 'analyze' ? 'active' : ''}" onclick={() => activeMainTab = 'analyze'}><span class="tab-icon">🔍</span> {$tr('adAudit.audit')}</button>
		<button class="tab-btn {activeMainTab === 'history' ? 'active' : ''}" onclick={() => activeMainTab = 'history'}><span class="tab-icon">📋</span> {$tr('adAudit.history')}</button>
		<button class="tab-btn {activeMainTab === 'help' ? 'active' : ''}" onclick={() => activeMainTab = 'help'}><span class="tab-icon">📖</span> {$tr('adAudit.help')}</button>
	</div>

	{#if activeMainTab === 'analyze'}
		<div class="content-grid">
			<div class="input-section">
				<div class="section-card">
					<h2 class="section-title">{$tr('adAudit.config.title')}</h2>
					<p class="section-desc">{$tr('adAudit.config.desc')}</p>
					<div class="form-group">
						<label class="form-label">{$tr('adAudit.config.domain')} *</label>
						<input type="text" bind:value={domain} placeholder="corp.local" class="form-input" disabled={processing} />
					</div>
					<div class="form-group">
						<label class="form-label">{$tr('adAudit.config.domainController')}</label>
						<input type="text" bind:value={domainController} placeholder="dc01.corp.local" class="form-input" disabled={processing} />
					</div>
					<div class="form-row">
						<div class="form-group">
							<label class="form-label">{$tr('adAudit.config.username')}</label>
							<input type="text" bind:value={username} placeholder="domain\\user" class="form-input" disabled={processing} />
						</div>
						<div class="form-group">
							<label class="form-label">{$tr('adAudit.config.password')}</label>
							<input type="password" bind:value={password} placeholder="••••••••" class="form-input" disabled={processing} />
						</div>
					</div>
					<div class="form-group">
						<label class="form-label">{$tr('adAudit.config.checkItems')}</label>
						<div class="target-grid">
							<label class="target-chip {checkKerberos ? 'active' : ''}"><input type="checkbox" bind:checked={checkKerberos} disabled={processing} /><span>🎫 {$tr('adAudit.kerberos.title')}</span></label>
							<label class="target-chip {checkLdap ? 'active' : ''}"><input type="checkbox" bind:checked={checkLdap} disabled={processing} /><span>📋 {$tr('adAudit.ldap.title')}</span></label>
							<label class="target-chip {checkSmb ? 'active' : ''}"><input type="checkbox" bind:checked={checkSmb} disabled={processing} /><span>📁 {$tr('adAudit.smb.title')}</span></label>
							<label class="target-chip {checkDns ? 'active' : ''}"><input type="checkbox" bind:checked={checkDns} disabled={processing} /><span>🌐 {$tr('adAudit.dns.title')}</span></label>
							<label class="target-chip {checkCerts ? 'active' : ''}"><input type="checkbox" bind:checked={checkCerts} disabled={processing} /><span>📜 {$tr('adAudit.config.certs')}</span></label>
							<label class="target-chip {checkTrust ? 'active' : ''}"><input type="checkbox" bind:checked={checkTrust} disabled={processing} /><span>🤝 {$tr('adAudit.config.trust')}</span></label>
							<label class="target-chip {checkGpo ? 'active' : ''}"><input type="checkbox" bind:checked={checkGpo} disabled={processing} /><span>📝 {$tr('adAudit.gpo.title')}</span></label>
							<label class="target-chip {checkAcl ? 'active' : ''}"><input type="checkbox" bind:checked={checkAcl} disabled={processing} /><span>🔐 {$tr('adAudit.acl.title')}</span></label>
							<label class="target-chip {checkDelegation ? 'active' : ''}"><input type="checkbox" bind:checked={checkDelegation} disabled={processing} /><span>🔄 {$tr('adAudit.config.delegation')}</span></label>
						</div>
					</div>
					<div class="form-row">
						<div class="form-group">
							<label class="form-label">⏱️ {$tr('adAudit.config.timeout')} (s)</label>
							<input type="number" bind:value={timeout} class="form-input" min="10" max="300" disabled={processing} />
						</div>
					</div>
					<div class="button-group">
						<button class="btn-primary" onclick={audit} disabled={processing || !domain.trim()}>
							{#if processing}<span class="spinner"></span>{$tr('adAudit.auditing')}{:else}🏢 {$tr('adAudit.startAudit')}{/if}
						</button>
						<button class="btn-secondary" onclick={clearAll} disabled={processing}>🗑️</button>
					</div>
				</div>
			</div>

			<div class="result-section">
				<div class="section-card">
					{#if error}
						<div class="error-card"><span class="error-icon">⚠️</span><span class="error-text">{error}</span></div>
					{:else if result}
						<div class="result-header">
							<h2 class="section-title" style="margin:0">{$tr('adAudit.result.title')}</h2>
							<div class="result-stats">
								<span class="stat-chip critical">🔴 {result.critical_issues} {$tr('adAudit.result.critical')}</span>
								<span class="stat-chip high">🟠 {result.high_issues} {$tr('adAudit.result.high')}</span>
								<span class="stat-chip total">📊 {result.total_issues} {$tr('adAudit.result.total')}</span>
							</div>
						</div>
						<div class="summary-bar">{result.summary}</div>

						{#if result.critical_issues > 0}
							<div class="critical-alert">
								<div class="critical-alert-header">🚨 {$tr('adAudit.result.criticalFindings')}</div>
								<div class="critical-list">
									{#each result.all_issues.filter(i => i.severity === 'critical') as issue}
										<div class="critical-item">
											<span class="critical-category">{translateCategory(issue.category)}</span>
											<span class="critical-title">{issue.title}</span>
											{#if issue.mitre_attack}<span class="mitre-badge">{issue.mitre_attack}</span>{/if}
										</div>
									{/each}
								</div>
							</div>
						{/if}

						<div class="result-tabs">
							<button class="result-tab {activeResultTab === 'overview' ? 'active' : ''}" onclick={() => activeResultTab = 'overview'}>📊 {$tr('adAudit.tabs.overview')}</button>
							<button class="result-tab {activeResultTab === 'issues' ? 'active' : ''}" onclick={() => activeResultTab = 'issues'}>⚠️ {$tr('adAudit.tabs.issues')} ({result.all_issues.length})</button>
							<button class="result-tab {activeResultTab === 'kerberos' ? 'active' : ''}" onclick={() => activeResultTab = 'kerberos'}>🎫 {$tr('adAudit.kerberos.title')}</button>
							<button class="result-tab {activeResultTab === 'ldap' ? 'active' : ''}" onclick={() => activeResultTab = 'ldap'}>📋 {$tr('adAudit.ldap.title')}</button>
							<button class="result-tab {activeResultTab === 'smb' ? 'active' : ''}" onclick={() => activeResultTab = 'smb'}>📁 {$tr('adAudit.smb.title')}</button>
							<button class="result-tab {activeResultTab === 'dns' ? 'active' : ''}" onclick={() => activeResultTab = 'dns'}>🌐 {$tr('adAudit.dns.title')}</button>
							<button class="result-tab {activeResultTab === 'certs' ? 'active' : ''}" onclick={() => activeResultTab = 'certs'}>📜 {$tr('adAudit.certs.title')}</button>
							<button class="result-tab {activeResultTab === 'trust' ? 'active' : ''}" onclick={() => activeResultTab = 'trust'}>🤝 {$tr('adAudit.trust.title')}</button>
							<button class="result-tab {activeResultTab === 'gpo' ? 'active' : ''}" onclick={() => activeResultTab = 'gpo'}>📝 {$tr('adAudit.gpo.title')}</button>
							<button class="result-tab {activeResultTab === 'acl' ? 'active' : ''}" onclick={() => activeResultTab = 'acl'}>🔐 {$tr('adAudit.acl.title')}</button>
						</div>

						{#if activeResultTab === 'overview'}
							<div class="overview-grid">
								<div class="overview-stat"><span class="stat-icon">🌐</span><span class="stat-value">{result.domain}</span><span class="stat-label">{$tr('adAudit.overview.domain')}</span></div>
								<div class="overview-stat"><span class="stat-icon">👥</span><span class="stat-value">{result.ldap_info.users_count}</span><span class="stat-label">{$tr('adAudit.overview.users')}</span></div>
								<div class="overview-stat"><span class="stat-icon">🖥️</span><span class="stat-value">{result.ldap_info.computers_count}</span><span class="stat-label">{$tr('adAudit.overview.computers')}</span></div>
								<div class="overview-stat"><span class="stat-icon">📊</span><span class="stat-value" style="color: {result.total_issues > 0 ? '#ef4444' : '#22c55e'}">{result.total_issues}</span><span class="stat-label">{$tr('adAudit.overview.totalIssues')}</span></div>
							</div>
							<div class="info-grid">
								<div class="info-card">
									<h3 class="info-card-title">🎫 {$tr('adAudit.kerberos.title')}</h3>
									<div class="info-row"><span class="info-label">{$tr('adAudit.kerberos.preAuthDisabled')}</span><span class="info-value" style="color: {result.kerberos_info.pre_auth_not_required.length > 0 ? '#ef4444' : '#22c55e'}">{result.kerberos_info.pre_auth_not_required.length}</span></div>
									<div class="info-row"><span class="info-label">{$tr('adAudit.kerberos.asRepRoastable')}</span><span class="info-value" style="color: {result.kerberos_info.as_rep_roastable.length > 0 ? '#ef4444' : '#22c55e'}">{result.kerberos_info.as_rep_roastable.length}</span></div>
									<div class="info-row"><span class="info-label">{$tr('adAudit.kerberos.kerberoastable')}</span><span class="info-value" style="color: {result.kerberos_info.kerberoastable.length > 0 ? '#ef4444' : '#22c55e'}">{result.kerberos_info.kerberoastable.length}</span></div>
									<div class="info-row"><span class="info-label">{$tr('adAudit.kerberos.unconstrainedDelegation')}</span><span class="info-value" style="color: {result.kerberos_info.unconstrained_delegation.length > 0 ? '#ef4444' : '#22c55e'}">{result.kerberos_info.unconstrained_delegation.length}</span></div>
								</div>
								<div class="info-card">
									<h3 class="info-card-title">📋 {$tr('adAudit.ldap.title')}</h3>
									<div class="info-row"><span class="info-label">{$tr('adAudit.ldap.anonymousBind')}</span><span class="info-value">{statusIcon(!result.ldap_info.anonymous_bind)} {result.ldap_info.anonymous_bind ? $tr('adAudit.status.allowed') : $tr('adAudit.status.disabled')}</span></div>
									<div class="info-row"><span class="info-label">{$tr('adAudit.ldap.signing')}</span><span class="info-value">{statusIcon(result.ldap_info.ldap_signing)} {result.ldap_info.ldap_signing ? $tr('adAudit.status.enabled') : $tr('adAudit.status.disabled')}</span></div>
									<div class="info-row"><span class="info-label">{$tr('adAudit.ldap.channelBinding')}</span><span class="info-value">{statusIcon(result.ldap_info.channel_binding)} {result.ldap_info.channel_binding ? $tr('adAudit.status.enabled') : $tr('adAudit.status.disabled')}</span></div>
									<div class="info-row"><span class="info-label">{$tr('adAudit.ldap.functionalLevel')}</span><span class="info-value">{result.ldap_info.functional_level || '-'}</span></div>
								</div>
								<div class="info-card">
									<h3 class="info-card-title">📁 {$tr('adAudit.smb.title')}</h3>
									<div class="info-row"><span class="info-label">{$tr('adAudit.smb.signingRequired')}</span><span class="info-value">{statusIcon(result.smb_info.signing_required)} {result.smb_info.signing_required ? $tr('adAudit.status.yes') : $tr('adAudit.status.no')}</span></div>
									<div class="info-row"><span class="info-label">{$tr('adAudit.smb.nullSessions')}</span><span class="info-value">{warnIcon(!result.smb_info.null_sessions)} {result.smb_info.null_sessions ? $tr('adAudit.status.allowed') : $tr('adAudit.status.disabled')}</span></div>
									<div class="info-row"><span class="info-label">{$tr('adAudit.smb.version')}</span><span class="info-value">{result.smb_info.smb_version || '-'}</span></div>
									<div class="info-row"><span class="info-label">{$tr('adAudit.smb.shares')}</span><span class="info-value">{result.smb_info.shares.length}</span></div>
								</div>
								<div class="info-card">
									<h3 class="info-card-title">🌐 {$tr('adAudit.dns.title')}</h3>
									<div class="info-row"><span class="info-label">{$tr('adAudit.dns.zoneTransfer')}</span><span class="info-value">{warnIcon(!result.dns_info.zone_transfer_possible)} {result.dns_info.zone_transfer_possible ? $tr('adAudit.status.vulnerable') : $tr('adAudit.status.secure')}</span></div>
									<div class="info-row"><span class="info-label">{$tr('adAudit.dns.dynamicUpdates')}</span><span class="info-value">{warnIcon(!result.dns_info.dynamic_updates)} {result.dns_info.dynamic_updates ? $tr('adAudit.status.enabled') : $tr('adAudit.status.disabled')}</span></div>
									<div class="info-row"><span class="info-label">{$tr('adAudit.dns.wpadRecord')}</span><span class="info-value">{warnIcon(!result.dns_info.wpad_record)} {result.dns_info.wpad_record ? $tr('adAudit.status.found') : $tr('adAudit.status.notFound')}</span></div>
									<div class="info-row"><span class="info-label">{$tr('adAudit.dns.zones')}</span><span class="info-value">{result.dns_info.zones.length}</span></div>
								</div>
							</div>

						{:else if activeResultTab === 'issues'}
							<div class="items-list">
								{#each result.all_issues as issue}
									<div class="item-card" style="border-left-color: {getSeverityColor(issue.severity)}">
										<div class="item-header">
											<span class="severity-badge" style="background: {getSeverityColor(issue.severity)}; color: white">{translateSeverity(issue.severity)}</span>
											<span class="item-title">{issue.title}</span>
											<span class="category-badge">{translateCategory(issue.category)}</span>
											{#if issue.mitre_attack}<span class="mitre-badge">{issue.mitre_attack}</span>{/if}
										</div>
										<p class="item-desc">{issue.description}</p>
										<p class="item-rec">💡 {issue.recommendation}</p>
									</div>
								{/each}
							</div>

						{:else if activeResultTab === 'kerberos'}
							<div class="detail-section">
								<div class="detail-grid">
									<div class="detail-stat"><span class="detail-label">{$tr('adAudit.kerberos.preAuthDisabled')}</span><span class="detail-value" style="color: {result.kerberos_info.pre_auth_not_required.length > 0 ? '#ef4444' : '#22c55e'}">{result.kerberos_info.pre_auth_not_required.length}</span></div>
									<div class="detail-stat"><span class="detail-label">{$tr('adAudit.kerberos.asRepRoastable')}</span><span class="detail-value" style="color: {result.kerberos_info.as_rep_roastable.length > 0 ? '#ef4444' : '#22c55e'}">{result.kerberos_info.as_rep_roastable.length}</span></div>
									<div class="detail-stat"><span class="detail-label">{$tr('adAudit.kerberos.kerberoastable')}</span><span class="detail-value" style="color: {result.kerberos_info.kerberoastable.length > 0 ? '#ef4444' : '#22c55e'}">{result.kerberos_info.kerberoastable.length}</span></div>
									<div class="detail-stat"><span class="detail-label">{$tr('adAudit.kerberos.weakEncryption')}</span><span class="detail-value" style="color: {result.kerberos_info.weak_encryption.length > 0 ? '#ef4444' : '#22c55e'}">{result.kerberos_info.weak_encryption.length}</span></div>
									<div class="detail-stat"><span class="detail-label">{$tr('adAudit.kerberos.constrainedDelegation')}</span><span class="detail-value" style="color: {result.kerberos_info.delegation_accounts.length > 0 ? '#f59e0b' : '#22c55e'}">{result.kerberos_info.delegation_accounts.length}</span></div>
									<div class="detail-stat"><span class="detail-label">{$tr('adAudit.kerberos.unconstrainedDelegation')}</span><span class="detail-value" style="color: {result.kerberos_info.unconstrained_delegation.length > 0 ? '#ef4444' : '#22c55e'}">{result.kerberos_info.unconstrained_delegation.length}</span></div>
								</div>
								{#if result.kerberos_info.pre_auth_not_required.length > 0}
									<div class="account-list"><h4 class="account-list-title">{$tr('adAudit.kerberos.preAuthDisabledAccounts')}</h4>{#each result.kerberos_info.pre_auth_not_required as account}<span class="account-tag">{account}</span>{/each}</div>
								{/if}
								{#if result.kerberos_info.as_rep_roastable.length > 0}
									<div class="account-list"><h4 class="account-list-title">{$tr('adAudit.kerberos.asRepRoastableAccounts')}</h4>{#each result.kerberos_info.as_rep_roastable as account}<span class="account-tag">{account}</span>{/each}</div>
								{/if}
								{#if result.kerberos_info.kerberoastable.length > 0}
									<div class="account-list"><h4 class="account-list-title">{$tr('adAudit.kerberos.kerberoastableAccounts')}</h4>{#each result.kerberos_info.kerberoastable as account}<span class="account-tag">{account}</span>{/each}</div>
								{/if}
								{#if result.kerberos_info.unconstrained_delegation.length > 0}
									<div class="account-list"><h4 class="account-list-title">{$tr('adAudit.kerberos.unconstrainedDelegationAccounts')}</h4>{#each result.kerberos_info.unconstrained_delegation as account}<span class="account-tag critical">{account}</span>{/each}</div>
								{/if}
								{#if result.kerberos_info.issues.length > 0}
									<h4 class="sub-section-title">⚠️ {$tr('adAudit.kerberos.issues')}</h4>
									{#each result.kerberos_info.issues as issue}
										<div class="item-card" style="border-left-color: {getSeverityColor(issue.severity)}"><div class="item-header"><span class="severity-badge" style="background: {getSeverityColor(issue.severity)}; color: white">{translateSeverity(issue.severity)}</span><span class="item-title">{issue.title}</span>{#if issue.mitre_attack}<span class="mitre-badge">{issue.mitre_attack}</span>{/if}</div><p class="item-desc">{issue.description}</p><p class="item-rec">💡 {issue.recommendation}</p></div>
									{/each}
								{/if}
							</div>

						{:else if activeResultTab === 'ldap'}
							<div class="detail-section">
								<div class="detail-grid">
									<div class="detail-stat"><span class="detail-label">{$tr('adAudit.ldap.domainName')}</span><span class="detail-value">{result.ldap_info.domain_name || '-'}</span></div>
									<div class="detail-stat"><span class="detail-label">{$tr('adAudit.ldap.functionalLevel')}</span><span class="detail-value">{result.ldap_info.functional_level || '-'}</span></div>
									<div class="detail-stat"><span class="detail-label">{$tr('adAudit.ldap.usersCount')}</span><span class="detail-value">{result.ldap_info.users_count}</span></div>
									<div class="detail-stat"><span class="detail-label">{$tr('adAudit.ldap.groupsCount')}</span><span class="detail-value">{result.ldap_info.groups_count}</span></div>
									<div class="detail-stat"><span class="detail-label">{$tr('adAudit.ldap.computersCount')}</span><span class="detail-value">{result.ldap_info.computers_count}</span></div>
									<div class="detail-stat"><span class="detail-label">{$tr('adAudit.ldap.adminCount')}</span><span class="detail-value">{result.ldap_info.admin_count}</span></div>
								</div>
								<div class="security-checks">
									<h4 class="sub-section-title">🔒 {$tr('adAudit.ldap.securityChecks')}</h4>
									<div class="check-grid">
										<div class="check-item {result.ldap_info.anonymous_bind ? 'danger' : 'safe'}"><span class="check-icon">{statusIcon(!result.ldap_info.anonymous_bind)}</span><span class="check-label">{$tr('adAudit.ldap.anonymousBind')}</span><span class="check-status">{result.ldap_info.anonymous_bind ? $tr('adAudit.status.allowed') : $tr('adAudit.status.disabled')}</span></div>
										<div class="check-item {result.ldap_info.ldap_signing ? 'safe' : 'danger'}"><span class="check-icon">{statusIcon(result.ldap_info.ldap_signing)}</span><span class="check-label">{$tr('adAudit.ldap.signing')}</span><span class="check-status">{result.ldap_info.ldap_signing ? $tr('adAudit.status.enabled') : $tr('adAudit.status.disabled')}</span></div>
										<div class="check-item {result.ldap_info.channel_binding ? 'safe' : 'danger'}"><span class="check-icon">{statusIcon(result.ldap_info.channel_binding)}</span><span class="check-label">{$tr('adAudit.ldap.channelBinding')}</span><span class="check-status">{result.ldap_info.channel_binding ? $tr('adAudit.status.enabled') : $tr('adAudit.status.disabled')}</span></div>
									</div>
								</div>
								{#if result.ldap_info.password_not_required.length > 0}
									<div class="account-list"><h4 class="account-list-title">🔑 {$tr('adAudit.ldap.passwordNotRequired')}</h4>{#each result.ldap_info.password_not_required as account}<span class="account-tag">{account}</span>{/each}</div>
								{/if}
								{#if result.ldap_info.password_never_expires.length > 0}
									<div class="account-list"><h4 class="account-list-title">⏰ {$tr('adAudit.ldap.passwordNeverExpires')}</h4>{#each result.ldap_info.password_never_expires as account}<span class="account-tag">{account}</span>{/each}</div>
								{/if}
								{#if result.ldap_info.issues.length > 0}
									<h4 class="sub-section-title">⚠️ {$tr('adAudit.ldap.issues')}</h4>
									{#each result.ldap_info.issues as issue}
										<div class="item-card" style="border-left-color: {getSeverityColor(issue.severity)}"><div class="item-header"><span class="severity-badge" style="background: {getSeverityColor(issue.severity)}; color: white">{translateSeverity(issue.severity)}</span><span class="item-title">{issue.title}</span>{#if issue.mitre_attack}<span class="mitre-badge">{issue.mitre_attack}</span>{/if}</div><p class="item-desc">{issue.description}</p><p class="item-rec">💡 {issue.recommendation}</p></div>
									{/each}
								{/if}
							</div>

						{:else if activeResultTab === 'smb'}
							<div class="detail-section">
								<div class="detail-grid">
									<div class="detail-stat"><span class="detail-label">{$tr('adAudit.smb.signingRequired')}</span><span class="detail-value">{statusIcon(result.smb_info.signing_required)} {result.smb_info.signing_required ? $tr('adAudit.status.yes') : $tr('adAudit.status.no')}</span></div>
									<div class="detail-stat"><span class="detail-label">{$tr('adAudit.smb.nullSessions')}</span><span class="detail-value">{warnIcon(!result.smb_info.null_sessions)} {result.smb_info.null_sessions ? $tr('adAudit.status.allowed') : $tr('adAudit.status.disabled')}</span></div>
									<div class="detail-stat"><span class="detail-label">{$tr('adAudit.smb.version')}</span><span class="detail-value">{result.smb_info.smb_version || '-'}</span></div>
									<div class="detail-stat"><span class="detail-label">{$tr('adAudit.smb.shares')}</span><span class="detail-value">{result.smb_info.shares.length}</span></div>
								</div>
								{#if result.smb_info.shares.length > 0}
									<h4 class="sub-section-title">📁 {$tr('adAudit.smb.shareList')}</h4>
									<div class="share-table">
										<div class="share-header"><span>{$tr('adAudit.smb.shareName')}</span><span>{$tr('adAudit.smb.sharePath')}</span><span>{$tr('adAudit.smb.shareRisk')}</span></div>
										{#each result.smb_info.shares as share}
											<div class="share-row"><span class="share-name">{share.name}</span><span class="share-path">{share.path || '-'}</span><span class="share-risk" style="color: {getRiskColor(share.risk_level)}">{translateRiskLevel(share.risk_level)}</span></div>
										{/each}
									</div>
								{/if}
								{#if result.smb_info.issues.length > 0}
									<h4 class="sub-section-title">⚠️ {$tr('adAudit.smb.issues')}</h4>
									{#each result.smb_info.issues as issue}
										<div class="item-card" style="border-left-color: {getSeverityColor(issue.severity)}"><div class="item-header"><span class="severity-badge" style="background: {getSeverityColor(issue.severity)}; color: white">{translateSeverity(issue.severity)}</span><span class="item-title">{issue.title}</span>{#if issue.mitre_attack}<span class="mitre-badge">{issue.mitre_attack}</span>{/if}</div><p class="item-desc">{issue.description}</p><p class="item-rec">💡 {issue.recommendation}</p></div>
									{/each}
								{/if}
							</div>

						{:else if activeResultTab === 'dns'}
							<div class="detail-section">
								<div class="detail-grid">
									<div class="detail-stat"><span class="detail-label">{$tr('adAudit.dns.zoneTransfer')}</span><span class="detail-value">{warnIcon(!result.dns_info.zone_transfer_possible)} {result.dns_info.zone_transfer_possible ? $tr('adAudit.status.vulnerable') : $tr('adAudit.status.secure')}</span></div>
									<div class="detail-stat"><span class="detail-label">{$tr('adAudit.dns.dynamicUpdates')}</span><span class="detail-value">{warnIcon(!result.dns_info.dynamic_updates)} {result.dns_info.dynamic_updates ? $tr('adAudit.status.enabled') : $tr('adAudit.status.disabled')}</span></div>
									<div class="detail-stat"><span class="detail-label">{$tr('adAudit.dns.wpadRecord')}</span><span class="detail-value">{warnIcon(!result.dns_info.wpad_record)} {result.dns_info.wpad_record ? $tr('adAudit.status.found') : $tr('adAudit.status.notFound')}</span></div>
									<div class="detail-stat"><span class="detail-label">{$tr('adAudit.dns.recordsCount')}</span><span class="detail-value">{result.dns_info.records_count}</span></div>
								</div>
								{#if result.dns_info.zones.length > 0}
									<div class="account-list"><h4 class="account-list-title">🌐 {$tr('adAudit.dns.zones')}</h4>{#each result.dns_info.zones as zone}<span class="account-tag">{zone}</span>{/each}</div>
								{/if}
								{#if result.dns_info.issues.length > 0}
									<h4 class="sub-section-title">⚠️ {$tr('adAudit.dns.issues')}</h4>
									{#each result.dns_info.issues as issue}
										<div class="item-card" style="border-left-color: {getSeverityColor(issue.severity)}"><div class="item-header"><span class="severity-badge" style="background: {getSeverityColor(issue.severity)}; color: white">{translateSeverity(issue.severity)}</span><span class="item-title">{issue.title}</span>{#if issue.mitre_attack}<span class="mitre-badge">{issue.mitre_attack}</span>{/if}</div><p class="item-desc">{issue.description}</p><p class="item-rec">💡 {issue.recommendation}</p></div>
									{/each}
								{/if}
							</div>

						{:else if activeResultTab === 'certs'}
							<div class="detail-section">
								<div class="detail-grid">
									<div class="detail-stat"><span class="detail-label">{$tr('adAudit.certs.templateVulns')}</span><span class="detail-value" style="color: {result.cert_info.vulnerable_templates.length > 0 ? '#ef4444' : '#22c55e'}">{result.cert_info.vulnerable_templates.length}</span></div>
									<div class="detail-stat"><span class="detail-label">{$tr('adAudit.certs.esc1Vulnerable')}</span><span class="detail-value" style="color: {result.cert_info.esc1_vulnerable.length > 0 ? '#ef4444' : '#22c55e'}">{result.cert_info.esc1_vulnerable.length}</span></div>
									<div class="detail-stat"><span class="detail-label">{$tr('adAudit.certs.esc8Vulnerable')}</span><span class="detail-value">{warnIcon(!result.cert_info.esc8_vulnerable)} {result.cert_info.esc8_vulnerable ? $tr('adAudit.status.vulnerable') : $tr('adAudit.status.secure')}</span></div>
									<div class="detail-stat"><span class="detail-label">{$tr('adAudit.certs.templates')}</span><span class="detail-value">{result.cert_info.templates.length}</span></div>
								</div>
								{#if result.cert_info.esc1_vulnerable.length > 0}
									<div class="account-list"><h4 class="account-list-title">🚨 {$tr('adAudit.certs.esc1Vulnerable')}</h4>{#each result.cert_info.esc1_vulnerable as tmpl}<span class="account-tag critical">{tmpl}</span>{/each}</div>
								{/if}
								{#if result.cert_info.templates.length > 0}
									<h4 class="sub-section-title">📜 {$tr('adAudit.certs.templateList')}</h4>
									<div class="share-table">
										<div class="share-header"><span>{$tr('adAudit.certs.templateName')}</span><span>{$tr('adAudit.certs.status')}</span><span>{$tr('adAudit.certs.risk')}</span></div>
										{#each result.cert_info.templates as tmpl}
											<div class="share-row"><span class="share-name">{tmpl.name}</span><span>{tmpl.enabled ? '✅' : '❌'}</span><span class="share-risk" style="color: {tmpl.vulnerable ? '#ef4444' : '#22c55e'}">{tmpl.vulnerable ? $tr('adAudit.certs.vulnerable') : $tr('adAudit.status.secure')}</span></div>
										{/each}
									</div>
								{/if}
								{#if result.cert_info.issues.length > 0}
									<h4 class="sub-section-title">⚠️ {$tr('adAudit.certs.issues')}</h4>
									{#each result.cert_info.issues as issue}
										<div class="item-card" style="border-left-color: {getSeverityColor(issue.severity)}"><div class="item-header"><span class="severity-badge" style="background: {getSeverityColor(issue.severity)}; color: white">{translateSeverity(issue.severity)}</span><span class="item-title">{issue.title}</span>{#if issue.mitre_attack}<span class="mitre-badge">{issue.mitre_attack}</span>{/if}</div><p class="item-desc">{issue.description}</p><p class="item-rec">💡 {issue.recommendation}</p></div>
									{/each}
								{/if}
							</div>

						{:else if activeResultTab === 'trust'}
							<div class="detail-section">
								{#if result.trust_info.trust_relationships.length > 0}
									<h4 class="sub-section-title">🤝 {$tr('adAudit.trust.relationships')}</h4>
									<div class="share-table">
										<div class="share-header"><span>{$tr('adAudit.trust.domain')}</span><span>{$tr('adAudit.trust.type')}</span><span>{$tr('adAudit.trust.direction')}</span><span>{$tr('adAudit.trust.sidFiltering')}</span></div>
										{#each result.trust_info.trust_relationships as trust}
											<div class="share-row"><span class="share-name">{trust.trusted_domain}</span><span>{trust.trust_type}</span><span>{trust.trust_direction}</span><span style="color: {trust.sid_filtering ? '#22c55e' : '#ef4444'}">{trust.sid_filtering ? '✅' : '❌'}</span></div>
										{/each}
									</div>
								{:else}
									<div class="empty-detail">{$tr('adAudit.trust.noTrusts')}</div>
								{/if}
								{#if result.trust_info.issues.length > 0}
									<h4 class="sub-section-title">⚠️ {$tr('adAudit.trust.issues')}</h4>
									{#each result.trust_info.issues as issue}
										<div class="item-card" style="border-left-color: {getSeverityColor(issue.severity)}"><div class="item-header"><span class="severity-badge" style="background: {getSeverityColor(issue.severity)}; color: white">{translateSeverity(issue.severity)}</span><span class="item-title">{issue.title}</span>{#if issue.mitre_attack}<span class="mitre-badge">{issue.mitre_attack}</span>{/if}</div><p class="item-desc">{issue.description}</p><p class="item-rec">💡 {issue.recommendation}</p></div>
									{/each}
								{/if}
							</div>

						{:else if activeResultTab === 'gpo'}
							<div class="detail-section">
								<div class="detail-grid">
									<div class="detail-stat"><span class="detail-label">{$tr('adAudit.gpo.totalGpos')}</span><span class="detail-value">{result.gpo_info.gpo_count}</span></div>
									<div class="detail-stat"><span class="detail-label">{$tr('adAudit.gpo.unlinkedGpos')}</span><span class="detail-value" style="color: {result.gpo_info.unlinked_gpos > 0 ? '#f59e0b' : '#22c55e'}">{result.gpo_info.unlinked_gpos}</span></div>
									<div class="detail-stat"><span class="detail-label">{$tr('adAudit.gpo.passwordInGpo')}</span><span class="detail-value">{warnIcon(!result.gpo_info.password_in_gpo)} {result.gpo_info.password_in_gpo ? $tr('adAudit.status.found') : $tr('adAudit.status.notFound')}</span></div>
								</div>
								{#if result.gpo_info.gpos.length > 0}
									<h4 class="sub-section-title">📝 {$tr('adAudit.gpo.gpoList')}</h4>
									{#each result.gpo_info.gpos as gpo}
										<div class="item-card" style="border-left-color: {gpo.suspicious ? '#ef4444' : 'rgba(148, 163, 184, 0.15)'}"><div class="item-header"><span class="item-title">{gpo.name}</span>{#if gpo.suspicious}<span class="severity-badge" style="background: #ef4444; color: white">⚠️</span>{/if}</div><p class="item-desc">{gpo.reason || gpo.status}</p></div>
									{/each}
								{/if}
								{#if result.gpo_info.issues.length > 0}
									<h4 class="sub-section-title">⚠️ {$tr('adAudit.gpo.issues')}</h4>
									{#each result.gpo_info.issues as issue}
										<div class="item-card" style="border-left-color: {getSeverityColor(issue.severity)}"><div class="item-header"><span class="severity-badge" style="background: {getSeverityColor(issue.severity)}; color: white">{translateSeverity(issue.severity)}</span><span class="item-title">{issue.title}</span>{#if issue.mitre_attack}<span class="mitre-badge">{issue.mitre_attack}</span>{/if}</div><p class="item-desc">{issue.description}</p><p class="item-rec">💡 {issue.recommendation}</p></div>
									{/each}
								{/if}
							</div>

						{:else if activeResultTab === 'acl'}
							<div class="detail-section">
								<div class="detail-grid">
									<div class="detail-stat"><span class="detail-label">{$tr('adAudit.acl.excessivePermissions')}</span><span class="detail-value" style="color: {result.acl_info.excessive_permissions.length > 0 ? '#ef4444' : '#22c55e'}">{result.acl_info.excessive_permissions.length}</span></div>
									<div class="detail-stat"><span class="detail-label">{$tr('adAudit.acl.dcsyncPossible')}</span><span class="detail-value">{warnIcon(!result.acl_info.dcsync_possible)} {result.acl_info.dcsync_possible ? $tr('adAudit.status.vulnerable') : $tr('adAudit.status.secure')}</span></div>
								</div>
								{#if result.acl_info.excessive_permissions.length > 0}
									<h4 class="sub-section-title">🔐 {$tr('adAudit.acl.excessivePermissionsList')}</h4>
									<div class="share-table">
										<div class="share-header"><span>{$tr('adAudit.acl.object')}</span><span>{$tr('adAudit.acl.principal')}</span><span>{$tr('adAudit.acl.permission')}</span><span>{$tr('adAudit.acl.risk')}</span></div>
										{#each result.acl_info.excessive_permissions as entry}
											<div class="share-row"><span class="share-name">{entry.object}</span><span>{entry.principal}</span><span>{entry.permission}</span><span class="share-risk" style="color: {getRiskColor(entry.risk_level)}">{translateRiskLevel(entry.risk_level)}</span></div>
										{/each}
									</div>
								{/if}
								{#if result.acl_info.issues.length > 0}
									<h4 class="sub-section-title">⚠️ {$tr('adAudit.acl.issues')}</h4>
									{#each result.acl_info.issues as issue}
										<div class="item-card" style="border-left-color: {getSeverityColor(issue.severity)}"><div class="item-header"><span class="severity-badge" style="background: {getSeverityColor(issue.severity)}; color: white">{translateSeverity(issue.severity)}</span><span class="item-title">{issue.title}</span>{#if issue.mitre_attack}<span class="mitre-badge">{issue.mitre_attack}</span>{/if}</div><p class="item-desc">{issue.description}</p><p class="item-rec">💡 {issue.recommendation}</p></div>
									{/each}
								{/if}
							</div>
						{/if}
					{:else}
						<div class="empty-state"><div class="empty-icon">🏢</div><p>{$tr('adAudit.result.noResults')}</p></div>
					{/if}
				</div>
			</div>
		</div>
	{:else if activeMainTab === 'history'}
		<div class="section-card"><ToolHistory toolType="ad_audit" toolName={$tr('adAudit.title')} bind:this={historyComponent} /></div>
	{:else if activeMainTab === 'help'}
		<div class="section-card"><ToolHelp toolType="ad_audit" /></div>
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
	.target-chip input[type="checkbox"] { accent-color: #a855f7; width: 0.8rem; height: 0.8rem; }
	.target-chip:hover:not(.active) { border-color: rgba(148, 163, 184, 0.3); }
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
	.result-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem; flex-wrap: wrap; gap: 0.5rem; }
	.result-stats { display: flex; gap: 0.5rem; flex-wrap: wrap; }
	.stat-chip { padding: 0.25rem 0.6rem; border-radius: 0.4rem; font-size: 0.75rem; font-weight: 600; }
	.stat-chip.critical { background: rgba(220, 38, 38, 0.15); color: #fca5a5; }
	.stat-chip.high { background: rgba(239, 68, 68, 0.15); color: #fca5a5; }
	.stat-chip.total { background: rgba(168, 85, 247, 0.15); color: #c4b5fd; }
	.summary-bar { font-size: 0.8rem; color: #94a3b8; padding: 0.5rem 0.75rem; background: rgba(15, 23, 42, 0.4); border-radius: 0.4rem; margin-bottom: 1rem; border: 1px solid rgba(148, 163, 184, 0.08); }
	.critical-alert { padding: 0.75rem; background: rgba(220, 38, 38, 0.1); border: 1px solid rgba(220, 38, 38, 0.3); border-radius: 0.5rem; margin-bottom: 1rem; }
	.critical-alert-header { font-size: 0.85rem; font-weight: 600; color: #fca5a5; margin-bottom: 0.5rem; }
	.critical-list { display: flex; flex-direction: column; gap: 0.35rem; }
	.critical-item { display: flex; align-items: center; gap: 0.5rem; font-size: 0.8rem; color: #fca5a5; }
	.critical-category { padding: 0.1rem 0.4rem; background: rgba(220, 38, 38, 0.2); border-radius: 0.25rem; font-size: 0.7rem; font-weight: 600; }
	.critical-title { flex: 1; }
	.mitre-badge { padding: 0.1rem 0.4rem; background: rgba(99, 102, 241, 0.2); border-radius: 0.25rem; font-size: 0.7rem; color: #a5b4fc; font-weight: 600; white-space: nowrap; }
	.result-tabs { display: flex; gap: 0.25rem; margin-bottom: 1rem; flex-wrap: wrap; }
	.result-tab { padding: 0.4rem 0.75rem; border-radius: 0.4rem; border: 1px solid rgba(148, 163, 184, 0.15); background: rgba(15, 23, 42, 0.4); color: #94a3b8; cursor: pointer; font-size: 0.8rem; transition: all 0.2s; }
	.result-tab.active { background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%); color: white; border-color: transparent; font-weight: 600; }
	.result-tab:hover:not(.active) { border-color: rgba(168, 85, 247, 0.3); color: #c4b5fd; }
	.overview-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 0.75rem; margin-bottom: 1rem; }
	.overview-stat { display: flex; flex-direction: column; align-items: center; padding: 0.75rem; background: rgba(15, 23, 42, 0.4); border: 1px solid rgba(148, 163, 184, 0.08); border-radius: 0.5rem; }
	.stat-icon { font-size: 1.2rem; margin-bottom: 0.25rem; }
	.stat-value { font-size: 1.1rem; font-weight: 700; color: #f1f5f9; word-break: break-all; text-align: center; }
	.stat-label { font-size: 0.7rem; color: #94a3b8; margin-top: 0.2rem; }
	.info-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 0.75rem; }
	.info-card { background: rgba(15, 23, 42, 0.4); border: 1px solid rgba(148, 163, 184, 0.08); border-radius: 0.5rem; padding: 0.75rem; }
	.info-card-title { font-size: 0.85rem; font-weight: 600; color: #f1f5f9; margin: 0 0 0.5rem; }
	.info-row { display: flex; justify-content: space-between; align-items: center; padding: 0.25rem 0; font-size: 0.8rem; }
	.info-label { color: #94a3b8; font-weight: 500; }
	.info-value { color: #f1f5f9; font-weight: 500; }
	.detail-section { display: flex; flex-direction: column; gap: 1rem; }
	.detail-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 0.5rem; }
	.detail-stat { display: flex; flex-direction: column; padding: 0.5rem 0.75rem; background: rgba(15, 23, 42, 0.4); border: 1px solid rgba(148, 163, 184, 0.08); border-radius: 0.4rem; }
	.detail-label { font-size: 0.7rem; color: #94a3b8; margin-bottom: 0.15rem; }
	.detail-value { font-size: 0.85rem; font-weight: 600; color: #f1f5f9; }
	.sub-section-title { font-size: 0.85rem; font-weight: 600; color: #f1f5f9; margin: 0.5rem 0 0.5rem; }
	.security-checks { margin-top: 0.5rem; }
	.check-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 0.5rem; }
	.check-item { display: flex; align-items: center; gap: 0.4rem; padding: 0.5rem 0.75rem; border-radius: 0.4rem; font-size: 0.8rem; border: 1px solid; }
	.check-item.safe { background: rgba(34, 197, 94, 0.08); border-color: rgba(34, 197, 94, 0.2); color: #86efac; }
	.check-item.danger { background: rgba(239, 68, 68, 0.08); border-color: rgba(239, 68, 68, 0.2); color: #fca5a5; }
	.check-icon { font-size: 0.9rem; }
	.check-label { flex: 1; font-weight: 500; }
	.check-status { font-weight: 600; }
	.account-list { margin-top: 0.75rem; }
	.account-list-title { font-size: 0.8rem; font-weight: 600; color: #f1f5f9; margin: 0 0 0.5rem; }
	.account-tag { display: inline-block; padding: 0.2rem 0.5rem; margin: 0.15rem; border-radius: 0.3rem; font-size: 0.75rem; background: rgba(168, 85, 247, 0.1); border: 1px solid rgba(168, 85, 247, 0.2); color: #c4b5fd; }
	.account-tag.critical { background: rgba(220, 38, 38, 0.1); border-color: rgba(220, 38, 38, 0.3); color: #fca5a5; }
	.items-list { display: flex; flex-direction: column; gap: 0.5rem; max-height: 600px; overflow-y: auto; }
	.item-card { padding: 0.75rem; background: rgba(15, 23, 42, 0.4); border: 1px solid rgba(148, 163, 184, 0.08); border-radius: 0.5rem; border-left: 3px solid; }
	.item-header { display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap; margin-bottom: 0.35rem; }
	.severity-badge { padding: 0.15rem 0.4rem; border-radius: 0.25rem; font-size: 0.7rem; font-weight: 600; }
	.item-title { font-size: 0.85rem; font-weight: 600; color: #f1f5f9; flex: 1; }
	.category-badge { padding: 0.1rem 0.4rem; background: rgba(148, 163, 184, 0.15); border-radius: 0.25rem; font-size: 0.7rem; color: #94a3b8; font-weight: 500; }
	.item-desc { font-size: 0.8rem; color: #94a3b8; margin: 0.25rem 0 0; line-height: 1.4; }
	.item-rec { font-size: 0.78rem; color: #86efac; margin: 0.25rem 0 0; line-height: 1.4; }
	.share-table { display: flex; flex-direction: column; gap: 0.2rem; }
	.share-header { display: grid; grid-template-columns: 2fr 2fr 1fr; gap: 0.5rem; padding: 0.4rem 0.6rem; background: rgba(15, 23, 42, 0.6); border-radius: 0.3rem; font-size: 0.7rem; color: #94a3b8; font-weight: 500; text-transform: uppercase; letter-spacing: 0.05em; }
	.share-row { display: grid; grid-template-columns: 2fr 2fr 1fr; gap: 0.5rem; padding: 0.35rem 0.6rem; border-radius: 0.3rem; font-size: 0.8rem; color: #cbd5e1; border-bottom: 1px solid rgba(148, 163, 184, 0.06); }
	.share-row:hover { background: rgba(168, 85, 247, 0.05); }
	.share-name { font-weight: 500; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
	.share-path { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: #94a3b8; font-size: 0.75rem; }
	.share-risk { font-weight: 600; font-size: 0.75rem; }
	.empty-detail { text-align: center; padding: 2rem; color: #64748b; font-size: 0.85rem; }
	.empty-state { text-align: center; padding: 2.5rem 1rem; color: #94a3b8; }
	.empty-icon { font-size: 2.5rem; margin-bottom: 0.75rem; }
	.input-section { position: sticky; top: 1.5rem; align-self: start; max-height: calc(100vh - 3rem); overflow-y: auto; }
	.result-section { min-width: 0; }
	.empty-state p { font-size: 0.85rem; margin: 0; }
	.result-section::-webkit-scrollbar { width: 4px; }
	.result-section::-webkit-scrollbar-track { background: transparent; }
	.result-section::-webkit-scrollbar-thumb { background: rgba(168, 85, 247, 0.3); border-radius: 2px; }
	.input-section::-webkit-scrollbar { width: 4px; }
	.input-section::-webkit-scrollbar-track { background: transparent; }
	.input-section::-webkit-scrollbar-thumb { background: rgba(168, 85, 247, 0.3); border-radius: 2px; }
	.items-list::-webkit-scrollbar { width: 4px; }
	.items-list::-webkit-scrollbar-track { background: transparent; }
	.items-list::-webkit-scrollbar-thumb { background: rgba(168, 85, 247, 0.3); border-radius: 2px; }

	@media (max-width: 768px) {
		.content-grid { grid-template-columns: 1fr; }
		.input-section { position: static; max-height: none; }
		.overview-grid { grid-template-columns: repeat(2, 1fr); }
		.target-grid { grid-template-columns: repeat(2, 1fr); }
		.detail-grid { grid-template-columns: repeat(2, 1fr); }
		.check-grid { grid-template-columns: 1fr; }
		.share-header, .share-row { grid-template-columns: 1fr 1fr; }
		.info-grid { grid-template-columns: 1fr; }
		.form-row { grid-template-columns: 1fr; }
		.result-header { flex-direction: column; align-items: flex-start; }
	}

	@media (max-width: 480px) {
		.nd-page { padding: 0.75rem; }
		.overview-grid { grid-template-columns: 1fr; }
		.target-grid { grid-template-columns: 1fr; }
		.detail-grid { grid-template-columns: 1fr; }
		.tabs { flex-wrap: wrap; }
		.tab-btn { font-size: 0.8rem; padding: 0.5rem 0.75rem; }
		.result-tabs { gap: 0.15rem; }
		.result-tab { font-size: 0.75rem; padding: 0.3rem 0.5rem; }
	}
</style>
