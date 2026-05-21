<script lang="ts">
	import { tr } from '$lib/i18n';
	import ToolHistory from '$lib/components/ToolHistory.svelte';
	import ToolHelp from '$lib/components/ToolHelp.svelte';

	interface PermissionInfo { name: string; risk_level: string; description: string; is_dangerous: boolean; category: string; }
	interface ApiSecurityIssue { endpoint: string; method: string; issue_type: string; severity: string; description: string; recommendation: string; }
	interface DataStorageIssue { location: string; data_type: string; is_encrypted: boolean; risk_level: string; description: string; }
	interface CryptoIssue { algorithm: string; usage: string; key_size: number | null; issue: string; severity: string; recommendation: string; }
	interface NetworkIssue { url: string; protocol: string; issue_type: string; severity: string; description: string; }
	interface CodeQualityIssue { category: string; description: string; severity: string; file: string; line: number | null; }
	interface TamperingProtection { root_detection: boolean; jailbreak_detection: boolean; integrity_check: boolean; anti_debug: boolean; anti_tamper: boolean; emulator_detection: boolean; repackaging_detection: boolean; score: number; }
	interface PrivacyIssue { data_collected: string; purpose: string; is_necessary: boolean; risk_level: string; regulation: string; }

	interface MobileSecurityResult {
		success: boolean; app_path: string; platform: string; app_name: string; package_name: string;
		version: string; min_sdk: string; target_sdk: string;
		permissions: PermissionInfo[]; api_issues: ApiSecurityIssue[];
		storage_issues: DataStorageIssue[]; crypto_issues: CryptoIssue[];
		network_issues: NetworkIssue[]; code_issues: CodeQualityIssue[];
		tampering_protection: TamperingProtection; privacy_issues: PrivacyIssue[];
		security_score: number; total_issues: number; critical_issues: number; summary: string;
	}

	let appPath = $state('');
	let platform = $state('android');
	let checkPermissions = $state(true);
	let checkApi = $state(true);
	let checkStorage = $state(true);
	let checkCrypto = $state(true);
	let checkNetwork = $state(true);
	let checkTampering = $state(true);
	let checkDebugging = $state(true);
	let checkPrivacy = $state(true);
	let checkCodeQuality = $state(true);
	let result: MobileSecurityResult | null = $state(null);
	let error = $state('');
	let processing = $state(false);
	let activeMainTab = $state('analyze');
	let activeResultTab = $state('overview');
	let historyComponent: ToolHistory = $state(null!);

	async function analyze() {
		if (!appPath.trim()) { error = $tr('mobileSecurity.error.appPathRequired'); return; }
		processing = true; error = ''; result = null;
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			result = await invoke<MobileSecurityResult>('analyze_mobile_security_command', {
				config: {
					app_path: appPath.trim(), platform,
					check_permissions: checkPermissions, check_api_security: checkApi,
					check_data_storage: checkStorage, check_cryptography: checkCrypto,
					check_network: checkNetwork, check_tampering: checkTampering,
					check_debugging: checkDebugging, check_privacy: checkPrivacy,
					check_code_quality: checkCodeQuality
				}
			});
			if (result && historyComponent) {
				await historyComponent.saveHistory(appPath.trim(), JSON.stringify(result), result.summary, 'completed');
			}
		} catch (e: any) {
			error = e.toString();
			if (historyComponent) { await historyComponent.saveHistory(appPath.trim(), JSON.stringify({ error: e.toString() }), undefined, 'failed'); }
		} finally { processing = false; }
	}

	function clearAll() { appPath = ''; result = null; error = ''; }

	function getSeverityColor(s: string): string {
		switch (s) { case 'critical': return '#dc2626'; case 'high': return '#ef4444'; case 'medium': return '#f59e0b'; case 'low': return '#3b82f6'; default: return '#6b7280'; }
	}

	function translateSeverity(s: string): string {
		const key = `mobileSecurity.severity.${s}`;
		const val = $tr(key);
		return val !== key ? val : s;
	}

	function getScoreColor(score: number): string {
		if (score >= 0.7) return '#22c55e';
		if (score >= 0.4) return '#f59e0b';
		return '#ef4444';
	}
</script>

<div class="nd-page">
	<div class="page-header">
		<div class="header-left">
			<a href="/" class="back-link">{$tr('common.backToHome')}</a>
			<h1 class="page-title">📱 {$tr('mobileSecurity.title')}</h1>
			<p class="page-subtitle">{$tr('mobileSecurity.subtitle')}</p>
		</div>
	</div>

	<div class="tabs">
		<button class="tab-btn {activeMainTab === 'analyze' ? 'active' : ''}" onclick={() => activeMainTab = 'analyze'}>
			<span class="tab-icon">🔍</span> {$tr('mobileSecurity.analyze')}
		</button>
		<button class="tab-btn {activeMainTab === 'history' ? 'active' : ''}" onclick={() => activeMainTab = 'history'}>
			<span class="tab-icon">📋</span> {$tr('mobileSecurity.history')}
		</button>
		<button class="tab-btn {activeMainTab === 'help' ? 'active' : ''}" onclick={() => activeMainTab = 'help'}>
			<span class="tab-icon">📖</span> {$tr('mobileSecurity.help')}
		</button>
	</div>

	{#if activeMainTab === 'analyze'}
		<div class="content-grid">
			<div class="input-section">
				<div class="section-card">
					<h2 class="section-title">{$tr('mobileSecurity.config.title')}</h2>
					<p class="section-desc">{$tr('mobileSecurity.config.desc')}</p>

					<div class="form-group">
						<label class="form-label">{$tr('mobileSecurity.config.appPath')}</label>
						<input type="text" bind:value={appPath} placeholder="/path/to/app.apk or .ipa" class="form-input" disabled={processing} />
					</div>
					<div class="form-group">
						<label class="form-label">{$tr('mobileSecurity.config.platform')}</label>
						<select bind:value={platform} class="form-input" disabled={processing}>
							<option value="android">Android</option>
							<option value="ios">iOS</option>
						</select>
					</div>

					<div class="form-group">
						<label class="form-label">{$tr('mobileSecurity.config.checkItems')}</label>
						<div class="target-grid">
							<label class="target-chip {checkPermissions ? 'active' : ''}"><input type="checkbox" bind:checked={checkPermissions} disabled={processing} /><span>{$tr('mobileSecurity.config.permissions')}</span></label>
							<label class="target-chip {checkApi ? 'active' : ''}"><input type="checkbox" bind:checked={checkApi} disabled={processing} /><span>{$tr('mobileSecurity.config.apiSecurity')}</span></label>
							<label class="target-chip {checkStorage ? 'active' : ''}"><input type="checkbox" bind:checked={checkStorage} disabled={processing} /><span>{$tr('mobileSecurity.config.dataStorage')}</span></label>
							<label class="target-chip {checkCrypto ? 'active' : ''}"><input type="checkbox" bind:checked={checkCrypto} disabled={processing} /><span>{$tr('mobileSecurity.config.crypto')}</span></label>
							<label class="target-chip {checkNetwork ? 'active' : ''}"><input type="checkbox" bind:checked={checkNetwork} disabled={processing} /><span>{$tr('mobileSecurity.config.network')}</span></label>
							<label class="target-chip {checkTampering ? 'active' : ''}"><input type="checkbox" bind:checked={checkTampering} disabled={processing} /><span>{$tr('mobileSecurity.config.tampering')}</span></label>
							<label class="target-chip {checkDebugging ? 'active' : ''}"><input type="checkbox" bind:checked={checkDebugging} disabled={processing} /><span>{$tr('mobileSecurity.config.debugging')}</span></label>
							<label class="target-chip {checkPrivacy ? 'active' : ''}"><input type="checkbox" bind:checked={checkPrivacy} disabled={processing} /><span>{$tr('mobileSecurity.config.privacy')}</span></label>
							<label class="target-chip {checkCodeQuality ? 'active' : ''}"><input type="checkbox" bind:checked={checkCodeQuality} disabled={processing} /><span>{$tr('mobileSecurity.config.codeQuality')}</span></label>
						</div>
					</div>

					<div class="button-group">
						<button class="btn-primary" onclick={analyze} disabled={processing || !appPath.trim()}>
							{#if processing}<span class="spinner"></span> {$tr('mobileSecurity.analyzing')}{:else}📱 {$tr('mobileSecurity.startAnalyze')}{/if}
						</button>
						<button class="btn-secondary" onclick={clearAll} disabled={processing}>🗑️</button>
					</div>
				</div>
			</div>

			<div class="result-section">
				<div class="section-card">
					<h2 class="section-title">{$tr('mobileSecurity.result.title')}</h2>
					{#if error}
						<div class="error-card"><div class="error-icon">⚠️</div><div class="error-text">{error}</div></div>
					{:else if result}
						<div class="score-banner">
							<div class="score-circle" style="border-color: {getScoreColor(result.security_score)}">
								<span class="score-value" style="color: {getScoreColor(result.security_score)}">{(result.security_score * 100).toFixed(0)}</span>
								<span class="score-unit">{$tr('mobileSecurity.result.scoreUnit')}</span>
							</div>
							<div class="score-info">
								<span class="app-name">{result.app_name}</span>
								<span class="score-meta">{result.package_name} | {result.platform} v{result.version}</span>
								{#if result.min_sdk || result.target_sdk}
									<span class="score-meta">SDK: {result.min_sdk || 'N/A'} → {result.target_sdk || 'N/A'}</span>
								{/if}
							</div>
							<div class="issue-badges">
								<span class="issue-badge critical">{result.critical_issues} {$tr('mobileSecurity.result.critical')}</span>
								<span class="issue-badge high">{result.total_issues} {$tr('mobileSecurity.result.total')}</span>
							</div>
						</div>

						<div class="result-tabs">
							<button class="result-tab {activeResultTab === 'overview' ? 'active' : ''}" onclick={() => activeResultTab = 'overview'}>📊 {$tr('mobileSecurity.tabs.overview')}</button>
							<button class="result-tab {activeResultTab === 'permissions' ? 'active' : ''}" onclick={() => activeResultTab = 'permissions'}>🔑 {$tr('mobileSecurity.tabs.permissions')} ({result.permissions.length})</button>
							<button class="result-tab {activeResultTab === 'api' ? 'active' : ''}" onclick={() => activeResultTab = 'api'}>🔌 {$tr('mobileSecurity.tabs.api')} ({result.api_issues.length})</button>
							<button class="result-tab {activeResultTab === 'storage' ? 'active' : ''}" onclick={() => activeResultTab = 'storage'}>💾 {$tr('mobileSecurity.tabs.storage')} ({result.storage_issues.length})</button>
							<button class="result-tab {activeResultTab === 'crypto' ? 'active' : ''}" onclick={() => activeResultTab = 'crypto'}>🔐 {$tr('mobileSecurity.tabs.crypto')} ({result.crypto_issues.length})</button>
							<button class="result-tab {activeResultTab === 'network' ? 'active' : ''}" onclick={() => activeResultTab = 'network'}>🌐 {$tr('mobileSecurity.tabs.network')} ({result.network_issues.length})</button>
							<button class="result-tab {activeResultTab === 'code' ? 'active' : ''}" onclick={() => activeResultTab = 'code'}>📝 {$tr('mobileSecurity.tabs.code')} ({result.code_issues.length})</button>
							<button class="result-tab {activeResultTab === 'privacy' ? 'active' : ''}" onclick={() => activeResultTab = 'privacy'}>👁️ {$tr('mobileSecurity.tabs.privacy')} ({result.privacy_issues.length})</button>
						</div>

						{#if activeResultTab === 'overview'}
							<div class="overview-grid">
								<div class="overview-stat" style="border-color: rgba(168, 85, 247, 0.3);">
									<span class="stat-label">🔑 {$tr('mobileSecurity.overview.totalPermissions')}</span>
									<span class="stat-value">{result.permissions.length}</span>
									<span class="stat-sub">{result.permissions.filter(p => p.is_dangerous).length} {$tr('mobileSecurity.overview.dangerous')}</span>
								</div>
								<div class="overview-stat" style="border-color: rgba(239, 68, 68, 0.3);">
									<span class="stat-label">⚠️ {$tr('mobileSecurity.overview.totalIssues')}</span>
									<span class="stat-value" style="color: {result.total_issues > 0 ? '#fca5a5' : '#86efac'}">{result.total_issues}</span>
									<span class="stat-sub">{result.critical_issues} {$tr('mobileSecurity.overview.criticalIssues')}</span>
								</div>
								<div class="overview-stat" style="border-color: rgba(34, 197, 94, 0.3);">
									<span class="stat-label">🛡️ {$tr('mobileSecurity.overview.protectionScore')}</span>
									<span class="stat-value" style="color: {getScoreColor(result.tampering_protection.score)}">{(result.tampering_protection.score * 100).toFixed(0)}%</span>
									<span class="stat-sub">{$tr('mobileSecurity.overview.outOf7')}</span>
								</div>
								<div class="overview-stat" style="border-color: rgba(59, 130, 246, 0.3);">
									<span class="stat-label">📊 {$tr('mobileSecurity.overview.securityScore')}</span>
									<span class="stat-value" style="color: {getScoreColor(result.security_score)}">{(result.security_score * 100).toFixed(0)}</span>
									<span class="stat-sub">{$tr('mobileSecurity.result.scoreUnit')}</span>
								</div>
							</div>

							<div class="detail-grid">
								<div class="detail-card">
									<h3 class="subsection-title">🛡️ {$tr('mobileSecurity.overview.protectionChecks')}</h3>
									<div class="check-list">
										<div class="check-row"><span class="check-label">Root {$tr('mobileSecurity.overview.detection')}</span><span class="check-value">{result.tampering_protection.root_detection ? '✅' : '❌'}</span></div>
										<div class="check-row"><span class="check-label">Jailbreak {$tr('mobileSecurity.overview.detection')}</span><span class="check-value">{result.tampering_protection.jailbreak_detection ? '✅' : '❌'}</span></div>
										<div class="check-row"><span class="check-label">{$tr('mobileSecurity.overview.integrityCheck')}</span><span class="check-value">{result.tampering_protection.integrity_check ? '✅' : '❌'}</span></div>
										<div class="check-row"><span class="check-label">{$tr('mobileSecurity.overview.antiDebug')}</span><span class="check-value">{result.tampering_protection.anti_debug ? '✅' : '❌'}</span></div>
										<div class="check-row"><span class="check-label">{$tr('mobileSecurity.overview.antiTamper')}</span><span class="check-value">{result.tampering_protection.anti_tamper ? '✅' : '❌'}</span></div>
										<div class="check-row"><span class="check-label">{$tr('mobileSecurity.overview.emulatorDetection')}</span><span class="check-value">{result.tampering_protection.emulator_detection ? '✅' : '❌'}</span></div>
										<div class="check-row"><span class="check-label">{$tr('mobileSecurity.overview.repackagingDetection')}</span><span class="check-value">{result.tampering_protection.repackaging_detection ? '✅' : '❌'}</span></div>
									</div>
								</div>
								<div class="detail-card">
									<h3 class="subsection-title">📋 {$tr('mobileSecurity.overview.issueBreakdown')}</h3>
									<div class="check-list">
										<div class="check-row"><span class="check-label">🔌 API</span><span class="check-value">{result.api_issues.length}</span></div>
										<div class="check-row"><span class="check-label">💾 {$tr('mobileSecurity.tabs.storage')}</span><span class="check-value">{result.storage_issues.length}</span></div>
										<div class="check-row"><span class="check-label">🔐 {$tr('mobileSecurity.tabs.crypto')}</span><span class="check-value">{result.crypto_issues.length}</span></div>
										<div class="check-row"><span class="check-label">🌐 {$tr('mobileSecurity.tabs.network')}</span><span class="check-value">{result.network_issues.length}</span></div>
										<div class="check-row"><span class="check-label">📝 {$tr('mobileSecurity.tabs.code')}</span><span class="check-value">{result.code_issues.length}</span></div>
										<div class="check-row"><span class="check-label">👁️ {$tr('mobileSecurity.tabs.privacy')}</span><span class="check-value">{result.privacy_issues.length}</span></div>
									</div>
								</div>
							</div>
						{:else if activeResultTab === 'permissions'}
							<div class="items-list">
								{#each result.permissions as p}
									<div class="item-card" style="border-left-color: {p.is_dangerous ? '#ef4444' : '#22c55e'}">
										<div class="item-header">
											<span class="item-title">{p.name}</span>
											{#if p.is_dangerous}<span class="danger-badge">⚠️ {$tr('mobileSecurity.status.dangerous')}</span>{/if}
											<span class="category-badge">{p.category}</span>
											<span class="risk-badge" style="background: {getSeverityColor(p.risk_level)}20; color: {getSeverityColor(p.risk_level)}">{translateSeverity(p.risk_level)}</span>
										</div>
										<p class="item-desc">{p.description}</p>
									</div>
								{/each}
								{#if result.permissions.length === 0}<div class="empty-item">{$tr('mobileSecurity.status.noPermissions')}</div>{/if}
							</div>
						{:else if activeResultTab === 'api'}
							<div class="items-list">
								{#each result.api_issues as i}
									<div class="item-card" style="border-left-color: {getSeverityColor(i.severity)}">
										<div class="item-header">
											<span class="severity-badge" style="background: {getSeverityColor(i.severity)}">{translateSeverity(i.severity)}</span>
											<span class="item-title">{i.issue_type}</span>
										</div>
										<div class="item-meta">{$tr('mobileSecurity.api.endpoint')}: {i.endpoint} | {$tr('mobileSecurity.api.method')}: {i.method}</div>
										<p class="item-desc">{i.description}</p>
										{#if i.recommendation}<p class="item-rec">💡 {i.recommendation}</p>{/if}
									</div>
								{/each}
								{#if result.api_issues.length === 0}<div class="empty-item">{$tr('mobileSecurity.status.noApiIssues')}</div>{/if}
							</div>
						{:else if activeResultTab === 'storage'}
							<div class="items-list">
								{#each result.storage_issues as s}
									<div class="item-card" style="border-left-color: {getSeverityColor(s.risk_level)}">
										<div class="item-header">
											<span class="severity-badge" style="background: {getSeverityColor(s.risk_level)}">{translateSeverity(s.risk_level)}</span>
											<span class="item-title">{s.location}</span>
										</div>
										<div class="item-meta">{$tr('mobileSecurity.storage.dataType')}: {s.data_type} | {$tr('mobileSecurity.storage.encrypted')}: {s.is_encrypted ? '✅' : '❌'}</div>
										<p class="item-desc">{s.description}</p>
									</div>
								{/each}
								{#if result.storage_issues.length === 0}<div class="empty-item">{$tr('mobileSecurity.status.noStorageIssues')}</div>{/if}
							</div>
						{:else if activeResultTab === 'crypto'}
							<div class="items-list">
								{#each result.crypto_issues as c}
									<div class="item-card" style="border-left-color: {getSeverityColor(c.severity)}">
										<div class="item-header">
											<span class="severity-badge" style="background: {getSeverityColor(c.severity)}">{translateSeverity(c.severity)}</span>
											<span class="item-title">{c.algorithm}{#if c.key_size} ({c.key_size}bit){/if}</span>
										</div>
										<div class="item-meta">{$tr('mobileSecurity.crypto.usage')}: {c.usage}</div>
										<p class="item-desc">{c.issue}</p>
										{#if c.recommendation}<p class="item-rec">💡 {c.recommendation}</p>{/if}
									</div>
								{/each}
								{#if result.crypto_issues.length === 0}<div class="empty-item">{$tr('mobileSecurity.status.noCryptoIssues')}</div>{/if}
							</div>
						{:else if activeResultTab === 'network'}
							<div class="items-list">
								{#each result.network_issues as n}
									<div class="item-card" style="border-left-color: {getSeverityColor(n.severity)}">
										<div class="item-header">
											<span class="severity-badge" style="background: {getSeverityColor(n.severity)}">{translateSeverity(n.severity)}</span>
											<span class="item-title">{n.issue_type}</span>
										</div>
										<div class="item-meta">{$tr('mobileSecurity.network.url')}: {n.url} | {$tr('mobileSecurity.network.protocol')}: {n.protocol}</div>
										<p class="item-desc">{n.description}</p>
									</div>
								{/each}
								{#if result.network_issues.length === 0}<div class="empty-item">{$tr('mobileSecurity.status.noNetworkIssues')}</div>{/if}
							</div>
						{:else if activeResultTab === 'code'}
							<div class="items-list">
								{#each result.code_issues as c}
									<div class="item-card" style="border-left-color: {getSeverityColor(c.severity)}">
										<div class="item-header">
											<span class="severity-badge" style="background: {getSeverityColor(c.severity)}">{translateSeverity(c.severity)}</span>
											<span class="item-title">{c.category}</span>
										</div>
										<div class="item-meta">{$tr('mobileSecurity.code.file')}: {c.file}{#if c.line}:{c.line}{/if}</div>
										<p class="item-desc">{c.description}</p>
									</div>
								{/each}
								{#if result.code_issues.length === 0}<div class="empty-item">{$tr('mobileSecurity.status.noCodeIssues')}</div>{/if}
							</div>
						{:else if activeResultTab === 'privacy'}
							<div class="items-list">
								{#each result.privacy_issues as p}
									<div class="item-card" style="border-left-color: {getSeverityColor(p.risk_level)}">
										<div class="item-header">
											<span class="severity-badge" style="background: {getSeverityColor(p.risk_level)}">{translateSeverity(p.risk_level)}</span>
											<span class="item-title">{p.data_collected}</span>
										</div>
										<div class="item-meta">{$tr('mobileSecurity.privacy.purpose')}: {p.purpose} | {$tr('mobileSecurity.privacy.necessary')}: {p.is_necessary ? '✅' : '❌'} | {$tr('mobileSecurity.privacy.regulation')}: {p.regulation}</div>
									</div>
								{/each}
								{#if result.privacy_issues.length === 0}<div class="empty-item">{$tr('mobileSecurity.status.noPrivacyIssues')}</div>{/if}
							</div>
						{/if}
					{:else}
						<div class="empty-state"><div class="empty-icon">📱</div><p>{$tr('mobileSecurity.result.noResults')}</p></div>
					{/if}
				</div>
			</div>
		</div>
	{:else if activeMainTab === 'history'}
		<div class="section-card"><ToolHistory toolType="mobile_security" toolName={$tr('mobileSecurity.title')} bind:this={historyComponent} /></div>
	{:else if activeMainTab === 'help'}
		<div class="section-card"><ToolHelp toolType="mobile_security" /></div>
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

	.target-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 0.35rem; }
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

	.score-banner { display: flex; align-items: center; gap: 1.25rem; padding: 1rem; background: rgba(15, 23, 42, 0.4); border: 1px solid rgba(148, 163, 184, 0.08); border-radius: 0.75rem; margin-bottom: 1rem; }
	.score-circle { width: 72px; height: 72px; border-radius: 50%; border: 4px solid; display: flex; flex-direction: column; align-items: center; justify-content: center; flex-shrink: 0; }
	.score-value { font-size: 1.4rem; font-weight: 700; line-height: 1; }
	.score-unit { font-size: 0.65rem; color: #94a3b8; }
	.score-info { flex: 1; display: flex; flex-direction: column; gap: 0.2rem; }
	.app-name { font-weight: 600; font-size: 0.95rem; color: #f1f5f9; }
	.score-meta { font-size: 0.8rem; color: #94a3b8; }
	.issue-badges { display: flex; flex-direction: column; gap: 0.3rem; }
	.issue-badge { padding: 0.3rem 0.6rem; border-radius: 0.4rem; font-size: 0.75rem; font-weight: 600; text-align: center; }
	.issue-badge.critical { background: rgba(220, 38, 38, 0.15); color: #fca5a5; border: 1px solid rgba(220, 38, 38, 0.3); }
	.issue-badge.high { background: rgba(168, 85, 247, 0.1); color: #c4b5fd; border: 1px solid rgba(168, 85, 247, 0.3); }

	.result-tabs { display: flex; gap: 0.25rem; margin-bottom: 1rem; flex-wrap: wrap; }
	.result-tab { padding: 0.4rem 0.75rem; border-radius: 0.4rem; border: 1px solid rgba(148, 163, 184, 0.15); background: rgba(15, 23, 42, 0.4); color: #94a3b8; cursor: pointer; font-size: 0.8rem; transition: all 0.2s; }
	.result-tab.active { background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%); color: white; border-color: transparent; font-weight: 600; }
	.result-tab:hover:not(.active) { border-color: rgba(168, 85, 247, 0.3); color: #c4b5fd; }

	.overview-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 0.75rem; margin-bottom: 1rem; }
	.overview-stat { display: flex; flex-direction: column; align-items: center; padding: 0.75rem; background: rgba(15, 23, 42, 0.4); border: 1px solid rgba(148, 163, 184, 0.08); border-radius: 0.5rem; border-top: 2px solid; }
	.stat-label { font-size: 0.7rem; color: #94a3b8; margin-bottom: 0.25rem; }
	.stat-value { font-size: 1.25rem; font-weight: 700; color: #f1f5f9; }
	.stat-sub { font-size: 0.65rem; color: #64748b; margin-top: 0.15rem; }

	.detail-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 0.75rem; }
	.detail-card { background: rgba(15, 23, 42, 0.4); border: 1px solid rgba(148, 163, 184, 0.08); border-radius: 0.5rem; padding: 0.75rem; }
	.subsection-title { font-size: 0.9rem; font-weight: 600; color: #e2e8f0; margin: 0 0 0.5rem; }
	.check-list { display: flex; flex-direction: column; gap: 0.3rem; }
	.check-row { display: flex; justify-content: space-between; align-items: center; padding: 0.3rem 0; font-size: 0.8rem; }
	.check-label { color: #94a3b8; }
	.check-value { font-weight: 600; color: #f1f5f9; }

	.items-list { display: flex; flex-direction: column; gap: 0.5rem; }
	.item-card { padding: 0.75rem; background: rgba(15, 23, 42, 0.4); border: 1px solid rgba(148, 163, 184, 0.08); border-radius: 0.5rem; border-left: 3px solid; }
	.item-header { display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.3rem; flex-wrap: wrap; }
	.item-title { font-weight: 600; font-size: 0.85rem; color: #f1f5f9; }
	.item-meta { font-size: 0.75rem; color: #94a3b8; }
	.item-desc { font-size: 0.8rem; color: #94a3b8; margin-top: 0.3rem; }
	.item-rec { font-size: 0.8rem; color: #86efac; margin-top: 0.3rem; }

	.severity-badge { padding: 0.15rem 0.5rem; border-radius: 0.3rem; color: white; font-size: 0.7rem; font-weight: 600; text-transform: uppercase; }
	.danger-badge { padding: 0.15rem 0.4rem; background: rgba(239, 68, 68, 0.15); border-radius: 0.3rem; font-size: 0.7rem; color: #fca5a5; }
	.category-badge { padding: 0.15rem 0.4rem; background: rgba(168, 85, 247, 0.1); border: 1px solid rgba(168, 85, 247, 0.2); border-radius: 0.3rem; font-size: 0.7rem; color: #c4b5fd; }
	.risk-badge { padding: 0.15rem 0.4rem; border-radius: 0.3rem; font-size: 0.7rem; font-weight: 600; }

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
		.overview-grid { grid-template-columns: repeat(2, 1fr); }
		.detail-grid { grid-template-columns: 1fr; }
		.target-grid { grid-template-columns: 1fr; }
		.score-banner { flex-direction: column; align-items: flex-start; }
		.issue-badges { flex-direction: row; }
	}
	@media (max-width: 480px) {
		.nd-page { padding: 0.75rem; }
		.overview-grid { grid-template-columns: 1fr; }
		.tabs { flex-wrap: wrap; }
		.tab-btn { font-size: 0.8rem; padding: 0.5rem 0.75rem; }
		.result-tabs { gap: 0.15rem; }
		.result-tab { font-size: 0.75rem; padding: 0.3rem 0.5rem; }
	}
</style>
