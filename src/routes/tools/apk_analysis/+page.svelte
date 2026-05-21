<script lang="ts">
	import { tr } from '$lib/i18n';
	import ToolHistory from '$lib/components/ToolHistory.svelte';
	import ToolHelp from '$lib/components/ToolHelp.svelte';

	interface CertificateInfo {
		issuer: string;
		subject: string;
		serial_number: string;
		valid_from: string;
		valid_to: string;
		fingerprint_sha1: string;
		fingerprint_sha256: string;
	}

	interface SecurityIssue {
		severity: string;
		category: string;
		description: string;
		detail: string;
	}

	interface NativeLibrary {
		name: string;
		arch: string;
		size: number;
		symbols: string[];
	}

	interface SensitiveFinding {
		finding_type: string;
		file_path: string;
		line_number: number;
		content: string;
		severity: string;
		description: string;
	}

	interface ApiKeyFinding {
		key_type: string;
		key_name: string;
		key_value: string;
		file_path: string;
		line_number: number;
		severity: string;
	}

	interface SecretFinding {
		secret_type: string;
		secret_name: string;
		secret_value: string;
		file_path: string;
		line_number: number;
	}

	interface CodeIssue {
		issue_type: string;
		file_path: string;
		line_number: number;
		code_snippet: string;
		severity: string;
		description: string;
	}

	interface CryptoIssue {
		issue_type: string;
		file_path: string;
		line_number: number;
		algorithm: string;
		severity: string;
		description: string;
	}

	interface WebViewIssue {
		file_path: string;
		line_number: number;
		issue_type: string;
		severity: string;
		description: string;
	}

	interface SdkInfo {
		name: string;
		sdk_type: string;
		package_name: string;
		version: string;
		permissions: string[];
		data_collection: string[];
	}

	interface PrivacyIssue {
		issue_type: string;
		severity: string;
		description: string;
		data_type: string;
		recommendation: string;
	}

	interface NetworkSecurityAnalysis {
		uses_cleartext_traffic: boolean;
		certificate_pinning: boolean;
		trust_manager_issues: string[];
		hostname_verifier_issues: string[];
	}

	interface DeepAnalysisResult {
		decompiled: boolean;
		decompiled_path: string;
		source_file_count: number;
		native_libs: NativeLibrary[];
		sensitive_findings: SensitiveFinding[];
		api_keys: ApiKeyFinding[];
		hardcoded_secrets: SecretFinding[];
		sql_injection_risks: CodeIssue[];
		crypto_issues: CryptoIssue[];
		webview_issues: WebViewIssue[];
		third_party_sdks: SdkInfo[];
		privacy_issues: PrivacyIssue[];
		network_security: NetworkSecurityAnalysis;
		deep_security_score: number;
	}

	interface ApkAnalysisResult {
		success: boolean;
		package_name: string;
		version_name: string;
		version_code: string;
		min_sdk: string;
		target_sdk: string;
		file_size: number;
		file_md5: string;
		file_sha1: string;
		file_sha256: string;
		is_debuggable: boolean;
		is_allow_backup: boolean;
		permissions: string[];
		dangerous_permissions: string[];
		activities: string[];
		services: string[];
		receivers: string[];
		providers: string[];
		exported_activities: string[];
		exported_services: string[];
		exported_receivers: string[];
		exported_providers: string[];
		certificates: CertificateInfo[];
		apis: string[];
		security_issues: SecurityIssue[];
		security_score: number;
		summary: string;
		deep_analysis: DeepAnalysisResult | null;
	}

	let apkPath = $state('');
	let extractManifest = $state(true);
	let extractPermissions = $state(true);
	let extractCertificates = $state(true);
	let extractApis = $state(true);
	let enableDeepAnalysis = $state(false);
	let result: ApkAnalysisResult | null = $state(null as ApkAnalysisResult | null);
	let error = $state('');
	let processing = $state(false);
	let activeMainTab = $state('analyze');
	let activeResultTab = $state('permissions');
	let activeDeepTab = $state('overview');
	let permFilter = $state('all');
	let historyComponent: ToolHistory;

	let highRiskCount = $derived(result?.permissions.filter(p => getPermissionRisk(p) === 'high').length ?? 0);
	let mediumRiskCount = $derived(result?.permissions.filter(p => getPermissionRisk(p) === 'medium').length ?? 0);
	let lowRiskCount = $derived(result?.permissions.filter(p => getPermissionRisk(p) === 'low').length ?? 0);

	let filteredPermissions = $derived.by(() => {
		if (!result) return [];
		if (permFilter === 'all') return result.permissions;
		return result.permissions.filter(p => getPermissionRisk(p) === permFilter);
	});

	async function selectApkFile() {
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			const selected = await invoke<string | null>('select_apk_file');
			if (selected) {
				apkPath = selected;
			}
		} catch {
			try {
				const { open } = await import('@tauri-apps/plugin-dialog');
				const selected = await open({
					multiple: false,
					filters: [{ name: 'APK', extensions: ['apk'] }]
				});
				if (selected) {
					apkPath = selected as string;
				}
			} catch {}
		}
	}

	async function analyze() {
		if (!apkPath.trim()) { error = $tr('apkAnalysis.error.noPath'); return; }
		processing = true; error = ''; result = null;
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			result = await invoke<ApkAnalysisResult>('analyze_apk_command', {
				config: {
					apk_path: apkPath.trim(),
					extract_manifest: extractManifest,
					extract_permissions: extractPermissions,
					extract_certificates: extractCertificates,
					extract_apis: extractApis,
					enable_deep_analysis: enableDeepAnalysis
				}
			});
			if (result && historyComponent) {
				await historyComponent.saveHistory(apkPath.trim(), JSON.stringify(result), result.summary, 'completed');
			}
		} catch (e: any) {
			error = e.toString();
			if (historyComponent) {
				await historyComponent.saveHistory(apkPath.trim(), JSON.stringify({ error: e.toString() }), undefined, 'failed');
			}
		}
		finally { processing = false; }
	}

	function clearAll() {
		apkPath = '';
		result = null;
		error = '';
		permFilter = 'all';
	}

	function getPermissionRisk(perm: string): string {
		const high = ['CAMERA', 'MICROPHONE', 'READ_CONTACTS', 'READ_SMS', 'READ_CALL_LOG', 'ACCESS_FINE_LOCATION', 'RECORD_AUDIO', 'READ_PHONE_STATE', 'CALL_PHONE', 'READ_PHONE_NUMBERS', 'PROCESS_OUTGOING_CALLS', 'BODY_SENSORS', 'READ_CALENDAR', 'WRITE_CALENDAR'];
		const medium = ['ACCESS_COARSE_LOCATION', 'READ_EXTERNAL_STORAGE', 'WRITE_EXTERNAL_STORAGE', 'BLUETOOTH_CONNECT', 'BLUETOOTH_SCAN', 'NEARBY_WIFI_DEVICES', 'POST_NOTIFICATIONS', 'READ_MEDIA_IMAGES', 'READ_MEDIA_VIDEO', 'READ_MEDIA_AUDIO'];
		if (high.some(h => perm.includes(h))) return 'high';
		if (medium.some(m => perm.includes(m))) return 'medium';
		return 'low';
	}

	function getRiskColor(risk: string): string {
		switch (risk) {
			case 'high': return '#ef4444';
			case 'medium': return '#eab308';
			default: return '#22c55e';
		}
	}

	function getRiskBg(risk: string): string {
		switch (risk) {
			case 'high': return 'rgba(239,68,68,0.15)';
			case 'medium': return 'rgba(234,179,8,0.15)';
			default: return 'rgba(34,197,94,0.15)';
		}
	}

	function getRiskLabel(risk: string): string {
		switch (risk) {
			case 'high': return $tr('apkAnalysis.risk.high');
			case 'medium': return $tr('apkAnalysis.risk.medium');
			default: return $tr('apkAnalysis.risk.low');
		}
	}

	function getSdkName(sdk: string): string {
		const sdkMap: Record<string, string> = {
			'21': 'Lollipop 5.0', '22': 'Lollipop 5.1', '23': 'Marshmallow 6.0',
			'24': 'Nougat 7.0', '25': 'Nougat 7.1', '26': 'Oreo 8.0',
			'27': 'Oreo 8.1', '28': 'Pie 9.0', '29': 'Q 10.0',
			'30': 'R 11.0', '31': 'S 12.0', '32': 'S_V2 12L',
			'33': 'Tiramisu 13.0', '34': 'Upside Down Cake 14.0',
			'35': 'Vanilla Ice Cream 15.0'
		};
		return sdkMap[sdk] || `API ${sdk}`;
	}

	function formatFileSize(bytes: number): string {
		if (bytes === 0) return '0 B';
		const k = 1024;
		const sizes = ['B', 'KB', 'MB', 'GB'];
		const i = Math.floor(Math.log(bytes) / Math.log(k));
		return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
	}

	function getScoreColor(score: number): string {
		if (score >= 80) return '#22c55e';
		if (score >= 60) return '#eab308';
		if (score >= 40) return '#f97316';
		return '#ef4444';
	}

	function getScoreLabel(score: number): string {
		if (score >= 80) return $tr('apkAnalysis.score.excellent');
		if (score >= 60) return $tr('apkAnalysis.score.good');
		if (score >= 40) return $tr('apkAnalysis.score.fair');
		return $tr('apkAnalysis.score.poor');
	}

	function getIssueSeverityColor(severity: string): string {
		switch (severity) {
			case 'high': return '#ef4444';
			case 'medium': return '#eab308';
			default: return '#22c55e';
		}
	}

	function getIssueSeverityBg(severity: string): string {
		switch (severity) {
			case 'high': return 'rgba(239,68,68,0.15)';
			case 'medium': return 'rgba(234,179,8,0.15)';
			default: return 'rgba(34,197,94,0.15)';
		}
	}

	function getIssueSeverityLabel(severity: string): string {
		switch (severity) {
			case 'high': return $tr('apkAnalysis.risk.high');
			case 'medium': return $tr('apkAnalysis.risk.medium');
			default: return $tr('apkAnalysis.risk.low');
		}
	}

	function getCategoryIcon(category: string): string {
		switch (category) {
			case 'configuration': return '⚙️';
			case 'component': return '🧩';
			case 'permission': return '🔐';
			case 'certificate': return '🔑';
			default: return '⚠️';
		}
	}

	function isCertExpired(cert: CertificateInfo): boolean {
		if (!cert.valid_to) return false;
		try { return new Date(cert.valid_to) < new Date(); } catch { return false; }
	}

	function isCertExpiringSoon(cert: CertificateInfo): boolean {
		if (!cert.valid_to) return false;
		try {
			const expiry = new Date(cert.valid_to);
			const now = new Date();
			const daysLeft = (expiry.getTime() - now.getTime()) / (1000 * 60 * 60 * 24);
			return daysLeft > 0 && daysLeft < 90;
		} catch { return false; }
	}

	function exportResult() {
		if (!result) return;
		const blob = new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' });
		const url = URL.createObjectURL(blob);
		const a = document.createElement('a');
		a.href = url;
		a.download = `apk-analysis-${result.package_name || 'unknown'}-${Date.now()}.json`;
		a.click();
		URL.revokeObjectURL(url);
	}

	function exportPermissionsCsv() {
		if (!result) return;
		const header = 'Permission,Risk Level\n';
		const rows = result.permissions.map(p => `"${p}","${getPermissionRisk(p)}"`).join('\n');
		const blob = new Blob([header + rows], { type: 'text/csv' });
		const url = URL.createObjectURL(blob);
		const a = document.createElement('a');
		a.href = url;
		a.download = `apk-permissions-${result.package_name || 'unknown'}-${Date.now()}.csv`;
		a.click();
		URL.revokeObjectURL(url);
	}
</script>

<div class="nd-page">
	<div class="page-header">
		<div class="header-left">
			<a href="/" class="back-link">{$tr('common.backToHome')}</a>
			<h1 class="page-title">📱 {$tr('apkAnalysis.title')}</h1>
			<p class="page-subtitle">{$tr('apkAnalysis.subtitle')}</p>
		</div>
	</div>

	<div class="tabs">
		<button class="tab-btn {activeMainTab === 'analyze' ? 'active' : ''}" onclick={() => activeMainTab = 'analyze'}>
			<span class="tab-icon">🔍</span> {$tr('apkAnalysis.mainTabs.analyze')}
		</button>
		<button class="tab-btn {activeMainTab === 'history' ? 'active' : ''}" onclick={() => activeMainTab = 'history'}>
			<span class="tab-icon">📋</span> {$tr('apkAnalysis.mainTabs.history')}
		</button>
		<button class="tab-btn {activeMainTab === 'help' ? 'active' : ''}" onclick={() => activeMainTab = 'help'}>
			<span class="tab-icon">📖</span> {$tr('apkAnalysis.mainTabs.help')}
		</button>
	</div>

	{#if activeMainTab === 'analyze'}
		<div class="content-grid">
			<div class="input-section">
				<div class="section-card">
					<h2 class="section-title">{$tr('apkAnalysis.config.title')}</h2>
					<p class="section-desc">{$tr('apkAnalysis.subtitle')}</p>

					<div class="form-group">
						<label class="form-label">{$tr('apkAnalysis.config.apkPath')}</label>
						<div class="input-with-btn">
							<input type="text" bind:value={apkPath} placeholder="/path/to/app.apk" class="form-input" disabled={processing} />
							<button class="btn-browse" onclick={selectApkFile} disabled={processing}>📁</button>
						</div>
					</div>

					<div class="form-group">
						<label class="form-label">{$tr('apkAnalysis.config.extractOptions')}</label>
						<div class="target-grid">
							<label class="target-chip {extractManifest ? 'active' : ''}">
								<input type="checkbox" bind:checked={extractManifest} disabled={processing} />
								<span>📋 {$tr('apkAnalysis.config.manifest')}</span>
							</label>
							<label class="target-chip {extractPermissions ? 'active' : ''}">
								<input type="checkbox" bind:checked={extractPermissions} disabled={processing} />
								<span>🔐 {$tr('apkAnalysis.config.permissions')}</span>
							</label>
							<label class="target-chip {extractCertificates ? 'active' : ''}">
								<input type="checkbox" bind:checked={extractCertificates} disabled={processing} />
								<span>🔑 {$tr('apkAnalysis.config.certificates')}</span>
							</label>
							<label class="target-chip {extractApis ? 'active' : ''}">
								<input type="checkbox" bind:checked={extractApis} disabled={processing} />
								<span>🔗 {$tr('apkAnalysis.config.apis')}</span>
							</label>
						</div>
					</div>

					<div class="form-group">
						<label class="target-chip {enableDeepAnalysis ? 'active' : ''}" style="width: 100%; justify-content: flex-start; gap: 0.5rem;">
							<input type="checkbox" bind:checked={enableDeepAnalysis} disabled={processing} />
							<span>🔬 {$tr('apkAnalysis.config.deepAnalysis')}</span>
						</label>
						<p class="form-hint">{$tr('apkAnalysis.config.deepAnalysisHint')}</p>
					</div>

					<div class="button-group">
						<button class="btn btn-primary" onclick={analyze} disabled={processing || !apkPath.trim()}>
							{#if processing}⏳ {$tr('apkAnalysis.analyzing')}{:else}📱 {$tr('apkAnalysis.analyze')}{/if}
						</button>
						<button class="btn btn-secondary" onclick={clearAll} disabled={processing}>
							🗑️ {$tr('apkAnalysis.clear')}
						</button>
					</div>
				</div>
			</div>

			<div class="result-section">
				<div class="section-card">
					<h2 class="section-title">{$tr('apkAnalysis.result.title')}</h2>

					{#if error}
						<div class="error-card">
							<div class="error-icon">⚠️</div>
							<div class="error-content"><p>{error}</p></div>
						</div>
					{:else if result}
						<div class="result-summary">{result.summary}</div>

						<div class="security-score-bar">
							<div class="score-circle" style="border-color: {getScoreColor(result.security_score)}">
								<span class="score-number" style="color: {getScoreColor(result.security_score)}">{result.security_score}</span>
							</div>
							<div class="score-info">
								<span class="score-label" style="color: {getScoreColor(result.security_score)}">{getScoreLabel(result.security_score)}</span>
								<span class="score-detail">{$tr('apkAnalysis.score.outOf')}</span>
							</div>
							<div class="score-flags">
								{#if result.is_debuggable}
									<span class="flag-badge danger">🐛 {$tr('apkAnalysis.flags.debuggable')}</span>
								{/if}
								{#if result.is_allow_backup}
									<span class="flag-badge warning">💾 {$tr('apkAnalysis.flags.allowBackup')}</span>
								{/if}
								{#if !result.is_debuggable && !result.is_allow_backup}
									<span class="flag-badge safe">✅ {$tr('apkAnalysis.flags.secure')}</span>
								{/if}
							</div>
						</div>

						<div class="app-info">
							<span class="info-badge package">📦 {result.package_name || 'unknown'}</span>
							<span class="info-badge version">🏷️ v{result.version_name || '?'} ({result.version_code || '1'})</span>
							<span class="info-badge sdk">📱 minSDK {getSdkName(result.min_sdk)}</span>
							<span class="info-badge sdk">🎯 targetSDK {getSdkName(result.target_sdk)}</span>
							<span class="info-badge size">📏 {formatFileSize(result.file_size)}</span>
						</div>

						{#if result.file_md5 || result.file_sha256}
							<div class="file-hash-section">
								{#if result.file_md5}
									<div class="hash-row">
										<span class="hash-label">MD5</span>
										<code class="hash-value">{result.file_md5}</code>
									</div>
								{/if}
								{#if result.file_sha1}
									<div class="hash-row">
										<span class="hash-label">SHA-1</span>
										<code class="hash-value">{result.file_sha1}</code>
									</div>
								{/if}
								{#if result.file_sha256}
									<div class="hash-row">
										<span class="hash-label">SHA-256</span>
										<code class="hash-value">{result.file_sha256}</code>
									</div>
								{/if}
							</div>
						{/if}

						<div class="component-stats">
							<div class="comp-stat">
								<span class="comp-stat-number">{result.permissions.length}</span>
								<span class="comp-stat-label">🔐 {$tr('apkAnalysis.result.permissions')}</span>
							</div>
							<div class="comp-stat danger">
								<span class="comp-stat-number">{result.dangerous_permissions.length}</span>
								<span class="comp-stat-label">⚠️ {$tr('apkAnalysis.result.dangerous')}</span>
							</div>
							<div class="comp-stat">
								<span class="comp-stat-number">{result.activities.length}</span>
								<span class="comp-stat-label">🎬 Activity</span>
							</div>
							<div class="comp-stat">
								<span class="comp-stat-number">{result.services.length}</span>
								<span class="comp-stat-label">⚙️ Service</span>
							</div>
							<div class="comp-stat">
								<span class="comp-stat-number">{result.receivers.length}</span>
								<span class="comp-stat-label">📡 Receiver</span>
							</div>
							<div class="comp-stat">
								<span class="comp-stat-number">{result.providers.length}</span>
								<span class="comp-stat-label">💾 Provider</span>
							</div>
						</div>

						<div class="result-toolbar">
							<div class="result-tabs">
								<button class="result-tab-btn {activeResultTab === 'permissions' ? 'active' : ''}" onclick={() => activeResultTab = 'permissions'}>
									🔐 {$tr('apkAnalysis.resultTabs.permissions')}
								</button>
								<button class="result-tab-btn {activeResultTab === 'components' ? 'active' : ''}" onclick={() => activeResultTab = 'components'}>
									🧩 {$tr('apkAnalysis.resultTabs.components')}
								</button>
								<button class="result-tab-btn {activeResultTab === 'certificates' ? 'active' : ''}" onclick={() => activeResultTab = 'certificates'}>
									🔑 {$tr('apkAnalysis.resultTabs.certificates')}
								</button>
								<button class="result-tab-btn {activeResultTab === 'security' ? 'active' : ''}" onclick={() => activeResultTab = 'security'}>
									🛡️ {$tr('apkAnalysis.resultTabs.security')}
								</button>
								<button class="result-tab-btn {activeResultTab === 'apis' ? 'active' : ''}" onclick={() => activeResultTab = 'apis'}>
									🔗 {$tr('apkAnalysis.resultTabs.apis')}
								</button>
								{#if result.deep_analysis}
									<button class="result-tab-btn deep {activeResultTab === 'deep' ? 'active' : ''}" onclick={() => activeResultTab = 'deep'}>
										🔬 {$tr('apkAnalysis.resultTabs.deep')}
									</button>
								{/if}
							</div>
							<div class="toolbar-actions">
								<button class="btn-icon" onclick={exportResult} title={$tr('apkAnalysis.export.json')}>📥 JSON</button>
								<button class="btn-icon" onclick={exportPermissionsCsv} title={$tr('apkAnalysis.export.csv')}>📊 CSV</button>
							</div>
						</div>

						{#if activeResultTab === 'permissions'}
							<div class="perm-filter-bar">
								<button class="filter-chip {permFilter === 'all' ? 'active' : ''}" onclick={() => permFilter = 'all'}>
									{$tr('apkAnalysis.filter.all')} ({result.permissions.length})
								</button>
								<button class="filter-chip high {permFilter === 'high' ? 'active' : ''}" onclick={() => permFilter = permFilter === 'high' ? 'all' : 'high'}>
									🔴 {$tr('apkAnalysis.risk.high')} ({highRiskCount})
								</button>
								<button class="filter-chip medium {permFilter === 'medium' ? 'active' : ''}" onclick={() => permFilter = permFilter === 'medium' ? 'all' : 'medium'}>
									🟡 {$tr('apkAnalysis.risk.medium')} ({mediumRiskCount})
								</button>
								<button class="filter-chip low {permFilter === 'low' ? 'active' : ''}" onclick={() => permFilter = permFilter === 'low' ? 'all' : 'low'}>
									🟢 {$tr('apkAnalysis.risk.low')} ({lowRiskCount})
								</button>
							</div>

							<div class="perm-list">
								{#each filteredPermissions as perm}
									{@const risk = getPermissionRisk(perm)}
									<div class="perm-item" style="border-left-color: {getRiskColor(risk)}">
										<span class="perm-risk" style="color: {getRiskColor(risk)}">●</span>
										<span class="perm-name">{perm}</span>
										<span class="perm-level" style="background: {getRiskBg(risk)}; color: {getRiskColor(risk)}">{getRiskLabel(risk)}</span>
										{#if result.dangerous_permissions.includes(perm)}
											<span class="danger-badge">⚠️</span>
										{/if}
									</div>
								{/each}
								{#if filteredPermissions.length === 0}
									<div class="empty-sub">{$tr('apkAnalysis.result.noMatching')}</div>
								{/if}
							</div>
						{:else if activeResultTab === 'components'}
							<div class="comp-section">
								{#if result.activities.length > 0}
									<div class="comp-group">
										<h3 class="comp-group-title">🎬 Activities ({result.activities.length})</h3>
										<div class="comp-list">
											{#each result.activities as act}
												<div class="comp-item">
													<span class="comp-icon">🎬</span>
													<code class="comp-name">{act}</code>
												</div>
											{/each}
										</div>
									</div>
								{/if}

								{#if result.services.length > 0}
									<div class="comp-group">
										<h3 class="comp-group-title">⚙️ Services ({result.services.length})</h3>
										<div class="comp-list">
											{#each result.services as svc}
												<div class="comp-item">
													<span class="comp-icon">⚙️</span>
													<code class="comp-name">{svc}</code>
												</div>
											{/each}
										</div>
									</div>
								{/if}

								{#if result.receivers.length > 0}
									<div class="comp-group">
										<h3 class="comp-group-title">📡 Receivers ({result.receivers.length})</h3>
										<div class="comp-list">
											{#each result.receivers as rcv}
												<div class="comp-item">
													<span class="comp-icon">📡</span>
													<code class="comp-name">{rcv}</code>
												</div>
											{/each}
										</div>
									</div>
								{/if}

								{#if result.providers.length > 0}
									<div class="comp-group">
										<h3 class="comp-group-title">💾 Content Providers ({result.providers.length})</h3>
										<div class="comp-list">
											{#each result.providers as prv}
												<div class="comp-item">
													<span class="comp-icon">💾</span>
													<code class="comp-name">{prv}</code>
												</div>
											{/each}
										</div>
									</div>
								{/if}

								{#if result.activities.length === 0 && result.services.length === 0 && result.receivers.length === 0 && result.providers.length === 0}
									<div class="empty-sub">{$tr('apkAnalysis.result.noComponents')}</div>
								{/if}
							</div>
						{:else if activeResultTab === 'certificates'}
							{#each result.certificates as cert}
								<div class="cert-card">
									<div class="cert-status">
										{#if isCertExpired(cert)}
											<span class="cert-badge expired">🔴 {$tr('apkAnalysis.cert.expired')}</span>
										{:else if isCertExpiringSoon(cert)}
											<span class="cert-badge expiring">🟡 {$tr('apkAnalysis.cert.expiringSoon')}</span>
										{:else}
											<span class="cert-badge valid">🟢 {$tr('apkAnalysis.cert.valid')}</span>
										{/if}
									</div>
									<div class="cert-grid">
										<div class="cert-row">
											<span class="cert-label">{$tr('apkAnalysis.cert.issuer')}</span>
											<code class="cert-value">{cert.issuer}</code>
										</div>
										<div class="cert-row">
											<span class="cert-label">{$tr('apkAnalysis.cert.subject')}</span>
											<code class="cert-value">{cert.subject}</code>
										</div>
										<div class="cert-row">
											<span class="cert-label">{$tr('apkAnalysis.cert.serial')}</span>
											<code class="cert-value">{cert.serial_number}</code>
										</div>
										<div class="cert-row">
											<span class="cert-label">{$tr('apkAnalysis.cert.validFrom')}</span>
											<span class="cert-value">{cert.valid_from}</span>
										</div>
										<div class="cert-row">
											<span class="cert-label">{$tr('apkAnalysis.cert.validTo')}</span>
											<span class="cert-value">{cert.valid_to}</span>
										</div>
										{#if cert.fingerprint_sha1}
											<div class="cert-row">
												<span class="cert-label">SHA-1</span>
												<code class="cert-value fingerprint">{cert.fingerprint_sha1}</code>
											</div>
										{/if}
										{#if cert.fingerprint_sha256}
											<div class="cert-row">
												<span class="cert-label">SHA-256</span>
												<code class="cert-value fingerprint">{cert.fingerprint_sha256}</code>
											</div>
										{/if}
									</div>
								</div>
							{/each}
							{#if result.certificates.length === 0}
								<div class="empty-sub">{$tr('apkAnalysis.result.noCerts')}</div>
							{/if}
						{:else if activeResultTab === 'security'}
							<div class="security-issues-section">
								{#if result.security_issues.length > 0}
									<div class="issues-summary">
										<span class="issues-count high">🔴 {result.security_issues.filter((i: SecurityIssue) => i.severity === 'high').length} {$tr('apkAnalysis.risk.high')}</span>
										<span class="issues-count medium">🟡 {result.security_issues.filter((i: SecurityIssue) => i.severity === 'medium').length} {$tr('apkAnalysis.risk.medium')}</span>
										<span class="issues-count low">🟢 {result.security_issues.filter((i: SecurityIssue) => i.severity === 'low').length} {$tr('apkAnalysis.risk.low')}</span>
									</div>
									<div class="issues-list">
										{#each result.security_issues as issue}
											<div class="issue-card" style="border-left-color: {getIssueSeverityColor(issue.severity)}">
												<div class="issue-header">
													<span class="issue-icon">{getCategoryIcon(issue.category)}</span>
													<span class="issue-desc">{issue.description}</span>
													<span class="issue-severity" style="background: {getIssueSeverityBg(issue.severity)}; color: {getIssueSeverityColor(issue.severity)}">{getIssueSeverityLabel(issue.severity)}</span>
												</div>
												<div class="issue-detail">{issue.detail}</div>
											</div>
										{/each}
									</div>
								{:else}
									<div class="no-issues">
										<span class="no-issues-icon">✅</span>
										<p>{$tr('apkAnalysis.result.noIssues')}</p>
									</div>
								{/if}

								{#if result.exported_activities.length > 0 || result.exported_services.length > 0 || result.exported_receivers.length > 0 || result.exported_providers.length > 0}
									<div class="exported-section">
										<h3 class="exported-title">🔓 {$tr('apkAnalysis.exported.title')}</h3>
										{#if result.exported_activities.length > 0}
											<div class="exported-group">
												<span class="exported-label">🎬 Activity:</span>
												{#each result.exported_activities as act}
													<code class="exported-item">{act}</code>
												{/each}
											</div>
										{/if}
										{#if result.exported_services.length > 0}
											<div class="exported-group">
												<span class="exported-label">⚙️ Service:</span>
												{#each result.exported_services as svc}
													<code class="exported-item">{svc}</code>
												{/each}
											</div>
										{/if}
										{#if result.exported_receivers.length > 0}
											<div class="exported-group">
												<span class="exported-label">📡 Receiver:</span>
												{#each result.exported_receivers as rcv}
													<code class="exported-item">{rcv}</code>
												{/each}
											</div>
										{/if}
										{#if result.exported_providers.length > 0}
											<div class="exported-group">
												<span class="exported-label">💾 Provider:</span>
												{#each result.exported_providers as prv}
													<code class="exported-item">{prv}</code>
												{/each}
											</div>
										{/if}
									</div>
								{/if}
							</div>
						{:else if activeResultTab === 'apis'}
							<div class="api-list">
								{#each result.apis as api}
									<div class="api-item">🔗 <code>{api}</code></div>
								{/each}
								{#if result.apis.length === 0}
									<div class="empty-sub">{$tr('apkAnalysis.result.noApis')}</div>
								{/if}
							</div>
						{:else if activeResultTab === 'deep' && result.deep_analysis}
							{@const deep = result.deep_analysis}
							<div class="deep-analysis-section">
								<div class="deep-header">
									<div class="deep-score-bar">
										<div class="score-circle" style="border-color: {getScoreColor(deep.deep_security_score)}">
											<span class="score-number" style="color: {getScoreColor(deep.deep_security_score)}">{deep.deep_security_score}</span>
										</div>
										<div class="score-info">
											<span class="score-label" style="color: {getScoreColor(deep.deep_security_score)}">{$tr('apkAnalysis.deep.score')}</span>
											<span class="score-detail">{$tr('apkAnalysis.score.outOf')}</span>
										</div>
									</div>
									<div class="deep-meta">
										{#if deep.decompiled}
											<span class="meta-badge success">✅ {$tr('apkAnalysis.deep.decompiled')}</span>
											<span class="meta-badge">📄 {deep.source_file_count} {$tr('apkAnalysis.deep.sourceFiles')}</span>
										{:else}
											<span class="meta-badge warning">⚠️ {$tr('apkAnalysis.deep.notDecompiled')}</span>
										{/if}
										{#if deep.native_libs.length > 0}
											<span class="meta-badge">📦 {deep.native_libs.length} {$tr('apkAnalysis.deep.nativeLibs')}</span>
										{/if}
									</div>
								</div>

								<div class="deep-tabs">
									<button class="deep-tab-btn {activeDeepTab === 'overview' ? 'active' : ''}" onclick={() => activeDeepTab = 'overview'}>
										📊 {$tr('apkAnalysis.deep.tabs.overview')}
									</button>
									<button class="deep-tab-btn {activeDeepTab === 'secrets' ? 'active' : ''}" onclick={() => activeDeepTab = 'secrets'}>
										🔑 {$tr('apkAnalysis.deep.tabs.secrets')} ({deep.sensitive_findings.length + deep.api_keys.length + deep.hardcoded_secrets.length})
									</button>
									<button class="deep-tab-btn {activeDeepTab === 'code' ? 'active' : ''}" onclick={() => activeDeepTab = 'code'}>
										💻 {$tr('apkAnalysis.deep.tabs.code')} ({deep.sql_injection_risks.length + deep.crypto_issues.length + deep.webview_issues.length})
									</button>
									<button class="deep-tab-btn {activeDeepTab === 'sdks' ? 'active' : ''}" onclick={() => activeDeepTab = 'sdks'}>
										📦 {$tr('apkAnalysis.deep.tabs.sdks')} ({deep.third_party_sdks.length})
									</button>
									<button class="deep-tab-btn {activeDeepTab === 'privacy' ? 'active' : ''}" onclick={() => activeDeepTab = 'privacy'}>
										🔒 {$tr('apkAnalysis.deep.tabs.privacy')} ({deep.privacy_issues.length})
									</button>
								</div>

								{#if activeDeepTab === 'overview'}
									<div class="deep-overview">
										<div class="overview-grid">
											<div class="overview-card">
												<h4>🔑 {$tr('apkAnalysis.deep.apiKeys')}</h4>
												<span class="count {deep.api_keys.length > 0 ? 'danger' : ''}">{deep.api_keys.length}</span>
												{#if deep.api_keys.length > 0}
													<ul class="mini-list">
														{#each deep.api_keys.slice(0, 3) as key}
															<li><code>{key.key_type}</code> <span class="severity {key.severity}">{key.severity}</span></li>
														{/each}
													</ul>
												{/if}
											</div>
											<div class="overview-card">
												<h4>🔐 {$tr('apkAnalysis.deep.secrets')}</h4>
												<span class="count {deep.hardcoded_secrets.length > 0 ? 'warning' : ''}">{deep.hardcoded_secrets.length}</span>
											</div>
											<div class="overview-card">
												<h4>💉 {$tr('apkAnalysis.deep.sqlInjection')}</h4>
												<span class="count {deep.sql_injection_risks.length > 0 ? 'danger' : ''}">{deep.sql_injection_risks.length}</span>
											</div>
											<div class="overview-card">
												<h4>🔐 {$tr('apkAnalysis.deep.crypto')}</h4>
												<span class="count {deep.crypto_issues.length > 0 ? 'warning' : ''}">{deep.crypto_issues.length}</span>
											</div>
											<div class="overview-card">
												<h4>🌐 {$tr('apkAnalysis.deep.webview')}</h4>
												<span class="count {deep.webview_issues.length > 0 ? 'warning' : ''}">{deep.webview_issues.length}</span>
											</div>
											<div class="overview-card">
												<h4>📦 {$tr('apkAnalysis.deep.sdks')}</h4>
												<span class="count">{deep.third_party_sdks.length}</span>
											</div>
										</div>

										<div class="network-security-card">
											<h4>🌐 {$tr('apkAnalysis.deep.networkSecurity')}</h4>
											<div class="ns-grid">
												<span class="ns-item {deep.network_security.uses_cleartext_traffic ? 'danger' : 'safe'}">
													{deep.network_security.uses_cleartext_traffic ? '⚠️' : '✅'} {$tr('apkAnalysis.deep.cleartextTraffic')}
												</span>
												<span class="ns-item {deep.network_security.certificate_pinning ? 'safe' : 'warning'}">
													{deep.network_security.certificate_pinning ? '✅' : '⚠️'} {$tr('apkAnalysis.deep.certPinning')}
												</span>
												<span class="ns-item {deep.network_security.trust_manager_issues.length > 0 ? 'danger' : 'safe'}">
													{deep.network_security.trust_manager_issues.length > 0 ? '🔴' : '✅'} {$tr('apkAnalysis.deep.trustManager')} ({deep.network_security.trust_manager_issues.length})
												</span>
												<span class="ns-item {deep.network_security.hostname_verifier_issues.length > 0 ? 'danger' : 'safe'}">
													{deep.network_security.hostname_verifier_issues.length > 0 ? '🔴' : '✅'} {$tr('apkAnalysis.deep.hostnameVerifier')} ({deep.network_security.hostname_verifier_issues.length})
												</span>
											</div>
										</div>

										{#if deep.native_libs.length > 0}
											<div class="native-libs-card">
												<h4>📦 {$tr('apkAnalysis.deep.nativeLibs')}</h4>
												<div class="lib-list">
													{#each deep.native_libs as lib}
														<div class="lib-item">
															<span class="lib-name">{lib.name}</span>
															<span class="lib-arch">{lib.arch}</span>
															<span class="lib-size">{formatFileSize(lib.size)}</span>
														</div>
													{/each}
												</div>
											</div>
										{/if}
									</div>
								{:else if activeDeepTab === 'secrets'}
									<div class="secrets-section">
										{#if deep.sensitive_findings.length > 0}
											<div class="secret-group">
												<h4>🔍 {$tr('apkAnalysis.deep.sensitiveFindings')} ({deep.sensitive_findings.length})</h4>
												<div class="secret-list">
													{#each deep.sensitive_findings as finding}
														<div class="secret-item {finding.severity}">
															<div class="secret-header">
																<span class="secret-type">{finding.finding_type}</span>
																<span class="secret-severity">{finding.severity}</span>
															</div>
															<code class="secret-value">{finding.content}</code>
															<p class="issue-desc">{finding.description}</p>
															<div class="secret-location">📁 {finding.file_path}:{finding.line_number}</div>
														</div>
													{/each}
												</div>
											</div>
										{/if}
										{#if deep.api_keys.length > 0}
											<div class="secret-group">
												<h4>🔑 {$tr('apkAnalysis.deep.apiKeys')} ({deep.api_keys.length})</h4>
												<div class="secret-list">
													{#each deep.api_keys as key}
														<div class="secret-item {key.severity}">
															<div class="secret-header">
																<span class="secret-type">{key.key_type}</span>
																<span class="secret-severity">{key.severity}</span>
															</div>
															<code class="secret-value">{key.key_value}</code>
															<div class="secret-location">📁 {key.file_path}:{key.line_number}</div>
														</div>
													{/each}
												</div>
											</div>
										{/if}
										{#if deep.hardcoded_secrets.length > 0}
											<div class="secret-group">
												<h4>🔐 {$tr('apkAnalysis.deep.hardcodedSecrets')} ({deep.hardcoded_secrets.length})</h4>
												<div class="secret-list">
													{#each deep.hardcoded_secrets as secret}
														<div class="secret-item">
															<div class="secret-header">
																<span class="secret-type">{secret.secret_type}</span>
															</div>
															<code class="secret-value">{secret.secret_value}</code>
															<div class="secret-location">📁 {secret.file_path}:{secret.line_number}</div>
														</div>
													{/each}
												</div>
											</div>
										{/if}
										{#if deep.sensitive_findings.length === 0 && deep.api_keys.length === 0 && deep.hardcoded_secrets.length === 0}
											<div class="empty-deep">✅ {$tr('apkAnalysis.deep.noSecrets')}</div>
										{/if}
									</div>
								{:else if activeDeepTab === 'code'}
									<div class="code-issues-section">
										{#if deep.sql_injection_risks.length > 0}
											<div class="issue-group">
												<h4>💉 {$tr('apkAnalysis.deep.sqlInjection')} ({deep.sql_injection_risks.length})</h4>
												<div class="issue-list">
													{#each deep.sql_injection_risks as issue}
														<div class="code-issue high">
															<div class="issue-header">
																<span class="issue-type">{issue.issue_type}</span>
																<span class="issue-severity high">{$tr('apkAnalysis.risk.high')}</span>
															</div>
															<code class="issue-snippet">{issue.code_snippet}</code>
															<div class="issue-location">📁 {issue.file_path}:{issue.line_number}</div>
														</div>
													{/each}
												</div>
											</div>
										{/if}
										{#if deep.crypto_issues.length > 0}
											<div class="issue-group">
												<h4>🔐 {$tr('apkAnalysis.deep.crypto')} ({deep.crypto_issues.length})</h4>
												<div class="issue-list">
													{#each deep.crypto_issues as issue}
														<div class="code-issue {issue.severity}">
															<div class="issue-header">
																<span class="issue-type">{issue.algorithm}</span>
																<span class="issue-severity {issue.severity}">{issue.severity}</span>
															</div>
															<p class="issue-desc">{issue.description}</p>
															<div class="issue-location">📁 {issue.file_path}:{issue.line_number}</div>
														</div>
													{/each}
												</div>
											</div>
										{/if}
										{#if deep.webview_issues.length > 0}
											<div class="issue-group">
												<h4>🌐 {$tr('apkAnalysis.deep.webview')} ({deep.webview_issues.length})</h4>
												<div class="issue-list">
													{#each deep.webview_issues as issue}
														<div class="code-issue {issue.severity}">
															<div class="issue-header">
																<span class="issue-type">{issue.issue_type}</span>
																<span class="issue-severity {issue.severity}">{issue.severity}</span>
															</div>
															<p class="issue-desc">{issue.description}</p>
															<div class="issue-location">📁 {issue.file_path}:{issue.line_number}</div>
														</div>
													{/each}
												</div>
											</div>
										{/if}
										{#if deep.sql_injection_risks.length === 0 && deep.crypto_issues.length === 0 && deep.webview_issues.length === 0}
											<div class="empty-deep">✅ {$tr('apkAnalysis.deep.noCodeIssues')}</div>
										{/if}
									</div>
								{:else if activeDeepTab === 'sdks'}
									<div class="sdks-section">
										{#if deep.third_party_sdks.length > 0}
											<div class="sdk-grid">
												{#each deep.third_party_sdks as sdk}
													<div class="sdk-card">
														<div class="sdk-header">
															<span class="sdk-name">{sdk.name}</span>
															<span class="sdk-type">{sdk.sdk_type}</span>
														</div>
														<code class="sdk-package">{sdk.package_name}</code>
														{#if sdk.data_collection.length > 0}
															<div class="sdk-data">
																<span class="data-label">📊 {$tr('apkAnalysis.deep.dataCollection')}:</span>
																{#each sdk.data_collection as data}
																	<span class="data-item">{data}</span>
																{/each}
															</div>
														{/if}
													</div>
												{/each}
											</div>
										{:else}
											<div class="empty-deep">ℹ️ {$tr('apkAnalysis.deep.noSdks')}</div>
										{/if}
									</div>
								{:else if activeDeepTab === 'privacy'}
									<div class="privacy-section">
										{#if deep.privacy_issues.length > 0}
											<div class="privacy-list">
												{#each deep.privacy_issues as issue}
													<div class="privacy-issue {issue.severity}">
														<div class="privacy-header">
															<span class="privacy-type">{issue.issue_type}</span>
															<span class="privacy-severity">{issue.severity}</span>
														</div>
														<p class="privacy-desc">{issue.description}</p>
														<div class="privacy-details">
															<span class="privacy-data">📊 {$tr('apkAnalysis.deep.dataType')}: {issue.data_type}</span>
														</div>
														<div class="privacy-recommendation">💡 {issue.recommendation}</div>
													</div>
												{/each}
											</div>
										{:else}
											<div class="empty-deep">✅ {$tr('apkAnalysis.deep.noPrivacyIssues')}</div>
										{/if}
									</div>
								{/if}
							</div>
						{/if}
					{:else}
						<div class="empty-state">
							<div class="empty-icon">📱</div>
							<p>{$tr('apkAnalysis.result.noResults')}</p>
						</div>
					{/if}
				</div>
			</div>
		</div>
	{:else if activeMainTab === 'history'}
		<div class="section-card">
			<ToolHistory toolType="apk_analysis" toolName={$tr('apkAnalysis.title')} bind:this={historyComponent} />
		</div>
	{:else if activeMainTab === 'help'}
		<div class="section-card">
			<ToolHelp toolType="apk_analysis" />
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

	.input-with-btn {
		display: flex;
		gap: 0.5rem;
	}

	.input-with-btn .form-input { flex: 1; }

	.btn-browse {
		padding: 0.55rem 0.75rem;
		border-radius: 0.5rem;
		border: 1px solid rgba(148, 163, 184, 0.15);
		background: rgba(15, 23, 42, 0.6);
		cursor: pointer;
		font-size: 1rem;
		transition: all 0.2s;
	}

	.btn-browse:hover {
		border-color: rgba(168, 85, 247, 0.3);
		background: rgba(168, 85, 247, 0.1);
	}

	.btn-browse:disabled { opacity: 0.5; cursor: not-allowed; }

	.target-grid {
		display: grid;
		grid-template-columns: repeat(2, 1fr);
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

	.target-chip:hover:not(.active) {
		border-color: rgba(168, 85, 247, 0.2);
	}

	.button-group {
		display: flex;
		gap: 0.5rem;
		margin-top: 1rem;
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
		flex: 1;
	}

	.btn-primary:hover:not(:disabled) {
		box-shadow: 0 4px 12px rgba(168, 85, 247, 0.4);
		transform: translateY(-1px);
	}

	.btn-primary:disabled { opacity: 0.5; cursor: not-allowed; }

	.btn-secondary {
		background: rgba(15, 23, 42, 0.8);
		color: #94a3b8;
		border: 1px solid rgba(148, 163, 184, 0.15);
	}

	.btn-secondary:hover:not(:disabled) {
		background: rgba(168, 85, 247, 0.1);
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

	.error-icon { font-size: 1.5rem; }
	.error-content { color: #ef4444; font-size: 0.85rem; }

	.result-summary {
		padding: 0.75rem;
		border-radius: 0.5rem;
		margin-bottom: 0.75rem;
		font-size: 0.85rem;
		background: rgba(99, 102, 241, 0.1);
		border: 1px solid rgba(99, 102, 241, 0.2);
		color: #c4b5fd;
	}

	.app-info {
		display: flex;
		flex-wrap: wrap;
		gap: 0.4rem;
		margin-bottom: 0.75rem;
	}

	.info-badge {
		padding: 0.25rem 0.6rem;
		border-radius: 0.375rem;
		font-size: 0.75rem;
		background: rgba(15, 23, 42, 0.8);
		border: 1px solid rgba(148, 163, 184, 0.15);
	}

	.info-badge.package {
		border-color: rgba(168, 85, 247, 0.3);
		background: rgba(168, 85, 247, 0.1);
		color: #c4b5fd;
	}

	.info-badge.version {
		border-color: rgba(34, 197, 94, 0.3);
		background: rgba(34, 197, 94, 0.1);
		color: #86efac;
	}

	.info-badge.sdk {
		border-color: rgba(59, 130, 246, 0.3);
		background: rgba(59, 130, 246, 0.1);
		color: #93c5fd;
	}

	.component-stats {
		display: grid;
		grid-template-columns: repeat(3, 1fr);
		gap: 0.5rem;
		margin-bottom: 0.75rem;
	}

	@media (min-width: 768px) {
		.component-stats { grid-template-columns: repeat(6, 1fr); }
	}

	.comp-stat {
		display: flex;
		flex-direction: column;
		align-items: center;
		padding: 0.5rem;
		border-radius: 0.5rem;
		background: rgba(15, 23, 42, 0.6);
		border: 1px solid rgba(148, 163, 184, 0.1);
	}

	.comp-stat.danger {
		border-color: rgba(239, 68, 68, 0.2);
		background: rgba(239, 68, 68, 0.05);
	}

	.comp-stat-number {
		font-size: 1.2rem;
		font-weight: 700;
		color: #f1f5f9;
	}

	.comp-stat.danger .comp-stat-number { color: #ef4444; }

	.comp-stat-label {
		font-size: 0.7rem;
		color: #94a3b8;
		margin-top: 0.15rem;
	}

	.result-toolbar {
		display: flex;
		justify-content: space-between;
		align-items: center;
		margin-bottom: 0.75rem;
		gap: 0.5rem;
		flex-wrap: wrap;
	}

	.result-tabs {
		display: flex;
		gap: 0.2rem;
		flex-wrap: wrap;
	}

	.result-tab-btn {
		padding: 0.35rem 0.65rem;
		border: 1px solid rgba(148, 163, 184, 0.15);
		border-radius: 0.375rem;
		background: transparent;
		color: #94a3b8;
		cursor: pointer;
		font-size: 0.75rem;
		transition: all 0.2s;
	}

	.result-tab-btn.active {
		background: rgba(168, 85, 247, 0.15);
		border-color: rgba(168, 85, 247, 0.3);
		color: #c4b5fd;
	}

	.result-tab-btn:hover:not(.active) {
		border-color: rgba(168, 85, 247, 0.2);
		color: #c4b5fd;
	}

	.toolbar-actions {
		display: flex;
		gap: 0.3rem;
	}

	.btn-icon {
		padding: 0.3rem 0.6rem;
		border: 1px solid rgba(148, 163, 184, 0.15);
		border-radius: 0.375rem;
		background: transparent;
		color: #94a3b8;
		cursor: pointer;
		font-size: 0.75rem;
		transition: all 0.2s;
	}

	.btn-icon:hover {
		border-color: rgba(168, 85, 247, 0.3);
		background: rgba(168, 85, 247, 0.1);
		color: #c4b5fd;
	}

	.perm-filter-bar {
		display: flex;
		gap: 0.3rem;
		margin-bottom: 0.75rem;
		flex-wrap: wrap;
	}

	.filter-chip {
		padding: 0.25rem 0.6rem;
		border: 1px solid rgba(148, 163, 184, 0.15);
		border-radius: 1rem;
		background: transparent;
		color: #94a3b8;
		cursor: pointer;
		font-size: 0.75rem;
		transition: all 0.2s;
	}

	.filter-chip.active {
		background: rgba(168, 85, 247, 0.15);
		border-color: rgba(168, 85, 247, 0.3);
		color: #c4b5fd;
	}

	.filter-chip.high.active {
		background: rgba(239, 68, 68, 0.15);
		border-color: #ef4444;
		color: #ef4444;
	}

	.filter-chip.medium.active {
		background: rgba(234, 179, 8, 0.15);
		border-color: #eab308;
		color: #eab308;
	}

	.filter-chip.low.active {
		background: rgba(34, 197, 94, 0.15);
		border-color: #22c55e;
		color: #22c55e;
	}

	.perm-list {
		display: flex;
		flex-direction: column;
		gap: 0.3rem;
		max-height: 400px;
		overflow-y: auto;
	}

	.perm-item {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		padding: 0.4rem 0.6rem;
		background: rgba(15, 23, 42, 0.6);
		border-radius: 0.375rem;
		border-left: 3px solid;
		font-size: 0.85rem;
		transition: background 0.2s;
	}

	.perm-item:hover { background: rgba(168, 85, 247, 0.05); }

	.perm-risk { font-size: 0.7rem; }
	.perm-name { flex: 1; font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; }

	.perm-level {
		font-size: 0.7rem;
		padding: 0.1rem 0.4rem;
		border-radius: 0.25rem;
		font-weight: 600;
	}

	.danger-badge { font-size: 0.75rem; }

	.comp-section {
		display: flex;
		flex-direction: column;
		gap: 1rem;
	}

	.comp-group {
		background: rgba(15, 23, 42, 0.4);
		border: 1px solid rgba(148, 163, 184, 0.1);
		border-radius: 0.5rem;
		padding: 0.75rem;
	}

	.comp-group-title {
		font-size: 0.85rem;
		margin: 0 0 0.5rem;
		color: #c4b5fd;
	}

	.comp-list {
		display: flex;
		flex-direction: column;
		gap: 0.2rem;
		max-height: 200px;
		overflow-y: auto;
	}

	.comp-item {
		display: flex;
		align-items: center;
		gap: 0.4rem;
		padding: 0.25rem 0.5rem;
		background: rgba(15, 23, 42, 0.6);
		border-radius: 0.25rem;
		font-size: 0.8rem;
	}

	.comp-icon { font-size: 0.75rem; }
	.comp-name {
		font-family: 'JetBrains Mono', monospace;
		font-size: 0.75rem;
		word-break: break-all;
	}

	.cert-card {
		padding: 1rem;
		background: rgba(15, 23, 42, 0.6);
		border: 1px solid rgba(148, 163, 184, 0.1);
		border-radius: 0.5rem;
		margin-bottom: 0.75rem;
	}

	.cert-status { margin-bottom: 0.75rem; }

	.cert-badge {
		padding: 0.2rem 0.6rem;
		border-radius: 1rem;
		font-size: 0.75rem;
		font-weight: 600;
	}

	.cert-badge.valid { background: rgba(34, 197, 94, 0.15); color: #22c55e; }
	.cert-badge.expired { background: rgba(239, 68, 68, 0.15); color: #ef4444; }
	.cert-badge.expiring { background: rgba(234, 179, 8, 0.15); color: #eab308; }

	.cert-grid {
		display: flex;
		flex-direction: column;
		gap: 0.4rem;
	}

	.cert-row {
		display: flex;
		gap: 0.5rem;
		font-size: 0.8rem;
		align-items: baseline;
	}

	.cert-label {
		color: #94a3b8;
		min-width: 80px;
		flex-shrink: 0;
	}

	.cert-value {
		font-family: 'JetBrains Mono', monospace;
		font-size: 0.75rem;
		word-break: break-all;
	}

	.cert-value.fingerprint {
		font-size: 0.7rem;
		color: #a78bfa;
	}

	.api-list {
		display: flex;
		flex-direction: column;
		gap: 0.2rem;
		max-height: 400px;
		overflow-y: auto;
	}

	.api-item {
		padding: 0.3rem 0.5rem;
		font-size: 0.8rem;
		background: rgba(15, 23, 42, 0.6);
		border-radius: 0.25rem;
		border-left: 2px solid rgba(168, 85, 247, 0.3);
	}

	.api-item code {
		font-family: 'JetBrains Mono', monospace;
		font-size: 0.75rem;
	}

	.empty-sub {
		text-align: center;
		padding: 1.5rem;
		color: #64748b;
		font-size: 0.85rem;
	}

	.empty-state {
		text-align: center;
		padding: 3rem;
		color: #64748b;
	}

	.empty-icon {
		font-size: 3rem;
		margin-bottom: 0.75rem;
	}

	@media (max-width: 768px) {
		.content-grid {
			grid-template-columns: 1fr;
		}
	}

	.security-score-bar {
		display: flex;
		align-items: center;
		gap: 1rem;
		padding: 0.75rem;
		background: rgba(15, 23, 42, 0.6);
		border: 1px solid rgba(148, 163, 184, 0.1);
		border-radius: 0.5rem;
		margin-bottom: 0.75rem;
	}

	.score-circle {
		width: 52px;
		height: 52px;
		border-radius: 50%;
		border: 3px solid;
		display: flex;
		align-items: center;
		justify-content: center;
		flex-shrink: 0;
	}

	.score-number {
		font-size: 1.1rem;
		font-weight: 800;
	}

	.score-info {
		display: flex;
		flex-direction: column;
		gap: 0.1rem;
	}

	.score-label {
		font-size: 0.9rem;
		font-weight: 700;
	}

	.score-detail {
		font-size: 0.7rem;
		color: #64748b;
	}

	.score-flags {
		display: flex;
		gap: 0.3rem;
		flex-wrap: wrap;
		margin-left: auto;
	}

	.flag-badge {
		padding: 0.2rem 0.5rem;
		border-radius: 0.375rem;
		font-size: 0.7rem;
		font-weight: 600;
	}

	.flag-badge.danger {
		background: rgba(239, 68, 68, 0.15);
		color: #ef4444;
		border: 1px solid rgba(239, 68, 68, 0.3);
	}

	.flag-badge.warning {
		background: rgba(234, 179, 8, 0.15);
		color: #eab308;
		border: 1px solid rgba(234, 179, 8, 0.3);
	}

	.flag-badge.safe {
		background: rgba(34, 197, 94, 0.15);
		color: #22c55e;
		border: 1px solid rgba(34, 197, 94, 0.3);
	}

	.info-badge.size {
		border-color: rgba(168, 85, 247, 0.3);
		background: rgba(168, 85, 247, 0.1);
		color: #c4b5fd;
	}

	.file-hash-section {
		padding: 0.5rem 0.75rem;
		background: rgba(15, 23, 42, 0.4);
		border: 1px solid rgba(148, 163, 184, 0.1);
		border-radius: 0.5rem;
		margin-bottom: 0.75rem;
		display: flex;
		flex-direction: column;
		gap: 0.3rem;
	}

	.hash-row {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		font-size: 0.75rem;
	}

	.hash-label {
		color: #94a3b8;
		min-width: 50px;
		font-weight: 600;
		font-size: 0.7rem;
	}

	.hash-value {
		font-family: 'JetBrains Mono', monospace;
		font-size: 0.7rem;
		color: #a78bfa;
		word-break: break-all;
	}

	.security-issues-section {
		display: flex;
		flex-direction: column;
		gap: 0.75rem;
	}

	.issues-summary {
		display: flex;
		gap: 0.75rem;
		flex-wrap: wrap;
	}

	.issues-count {
		font-size: 0.8rem;
		font-weight: 600;
	}

	.issues-count.high { color: #ef4444; }
	.issues-count.medium { color: #eab308; }
	.issues-count.low { color: #22c55e; }

	.issues-list {
		display: flex;
		flex-direction: column;
		gap: 0.4rem;
		max-height: 400px;
		overflow-y: auto;
	}

	.issue-card {
		padding: 0.6rem 0.75rem;
		background: rgba(15, 23, 42, 0.6);
		border-radius: 0.375rem;
		border-left: 3px solid;
	}

	.issue-header {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		margin-bottom: 0.3rem;
	}

	.issue-icon { font-size: 0.85rem; }

	.issue-desc {
		flex: 1;
		font-size: 0.8rem;
		color: #f1f5f9;
		font-weight: 500;
	}

	.issue-severity {
		font-size: 0.65rem;
		padding: 0.1rem 0.4rem;
		border-radius: 0.25rem;
		font-weight: 600;
	}

	.issue-detail {
		font-size: 0.75rem;
		color: #94a3b8;
		padding-left: 1.5rem;
	}

	.no-issues {
		text-align: center;
		padding: 2rem;
		color: #22c55e;
	}

	.no-issues-icon {
		font-size: 2rem;
		display: block;
		margin-bottom: 0.5rem;
	}

	.exported-section {
		padding: 0.75rem;
		background: rgba(15, 23, 42, 0.4);
		border: 1px solid rgba(234, 179, 8, 0.15);
		border-radius: 0.5rem;
	}

	.exported-title {
		font-size: 0.85rem;
		margin: 0 0 0.5rem;
		color: #eab308;
	}

	.exported-group {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		gap: 0.3rem;
		margin-bottom: 0.3rem;
	}

	.exported-label {
		font-size: 0.75rem;
		color: #94a3b8;
		min-width: 80px;
	}

	.exported-item {
		font-family: 'JetBrains Mono', monospace;
		font-size: 0.7rem;
		padding: 0.15rem 0.4rem;
		background: rgba(234, 179, 8, 0.1);
		border: 1px solid rgba(234, 179, 8, 0.2);
		border-radius: 0.25rem;
		color: #fbbf24;
		word-break: break-all;
	}

	.form-hint {
		font-size: 0.7rem;
		color: #64748b;
		margin: 0.25rem 0 0;
	}

	.result-tab-btn.deep {
		background: linear-gradient(135deg, rgba(168, 85, 247, 0.2) 0%, rgba(99, 102, 241, 0.2) 100%);
	}

	.result-tab-btn.deep.active {
		background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%);
	}

	.deep-analysis-section {
		padding: 0.5rem 0;
	}

	.deep-header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		gap: 1rem;
		margin-bottom: 1rem;
		padding-bottom: 0.75rem;
		border-bottom: 1px solid rgba(148, 163, 184, 0.1);
	}

	.deep-score-bar {
		display: flex;
		align-items: center;
		gap: 0.75rem;
	}

	.deep-meta {
		display: flex;
		flex-wrap: wrap;
		gap: 0.4rem;
	}

	.meta-badge {
		font-size: 0.7rem;
		padding: 0.25rem 0.5rem;
		background: rgba(15, 23, 42, 0.6);
		border: 1px solid rgba(148, 163, 184, 0.2);
		border-radius: 0.25rem;
		color: #94a3b8;
	}

	.meta-badge.success {
		background: rgba(34, 197, 94, 0.1);
		border-color: rgba(34, 197, 94, 0.3);
		color: #22c55e;
	}

	.meta-badge.warning {
		background: rgba(234, 179, 8, 0.1);
		border-color: rgba(234, 179, 8, 0.3);
		color: #eab308;
	}

	.deep-tabs {
		display: flex;
		gap: 0.25rem;
		margin-bottom: 0.75rem;
		flex-wrap: wrap;
	}

	.deep-tab-btn {
		padding: 0.4rem 0.75rem;
		border: none;
		border-radius: 0.375rem;
		background: rgba(15, 23, 42, 0.6);
		border: 1px solid rgba(148, 163, 184, 0.1);
		cursor: pointer;
		font-size: 0.75rem;
		color: #94a3b8;
		transition: all 0.2s;
	}

	.deep-tab-btn.active {
		background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%);
		color: white;
		border-color: transparent;
	}

	.deep-tab-btn:hover:not(.active) {
		background: rgba(168, 85, 247, 0.15);
		color: #c4b5fd;
	}

	.deep-overview {
		display: flex;
		flex-direction: column;
		gap: 0.75rem;
	}

	.overview-grid {
		display: grid;
		grid-template-columns: repeat(3, 1fr);
		gap: 0.5rem;
	}

	.overview-card {
		padding: 0.75rem;
		background: rgba(15, 23, 42, 0.6);
		border: 1px solid rgba(148, 163, 184, 0.1);
		border-radius: 0.5rem;
	}

	.overview-card h4 {
		font-size: 0.75rem;
		color: #94a3b8;
		margin: 0 0 0.25rem;
	}

	.overview-card .count {
		font-size: 1.25rem;
		font-weight: 700;
		color: #22c55e;
	}

	.overview-card .count.danger {
		color: #ef4444;
	}

	.overview-card .count.warning {
		color: #eab308;
	}

	.mini-list {
		list-style: none;
		padding: 0;
		margin: 0.5rem 0 0;
		font-size: 0.65rem;
	}

	.mini-list li {
		padding: 0.2rem 0;
		color: #94a3b8;
	}

	.mini-list code {
		font-size: 0.6rem;
		padding: 0.1rem 0.3rem;
		background: rgba(148, 163, 184, 0.1);
		border-radius: 0.2rem;
	}

	.mini-list .severity {
		font-size: 0.55rem;
		padding: 0.1rem 0.25rem;
		border-radius: 0.2rem;
		margin-left: 0.25rem;
	}

	.mini-list .severity.high { background: rgba(239, 68, 68, 0.2); color: #ef4444; }
	.mini-list .severity.medium { background: rgba(234, 179, 8, 0.2); color: #eab308; }
	.mini-list .severity.low { background: rgba(34, 197, 94, 0.2); color: #22c55e; }

	.network-security-card {
		padding: 0.75rem;
		background: rgba(15, 23, 42, 0.6);
		border: 1px solid rgba(148, 163, 184, 0.1);
		border-radius: 0.5rem;
	}

	.network-security-card h4 {
		font-size: 0.8rem;
		color: #f1f5f9;
		margin: 0 0 0.5rem;
	}

	.ns-grid {
		display: grid;
		grid-template-columns: repeat(2, 1fr);
		gap: 0.4rem;
	}

	.ns-item {
		font-size: 0.7rem;
		padding: 0.3rem 0.5rem;
		border-radius: 0.25rem;
	}

	.ns-item.safe { background: rgba(34, 197, 94, 0.1); color: #22c55e; }
	.ns-item.warning { background: rgba(234, 179, 8, 0.1); color: #eab308; }
	.ns-item.danger { background: rgba(239, 68, 68, 0.1); color: #ef4444; }

	.native-libs-card {
		padding: 0.75rem;
		background: rgba(15, 23, 42, 0.6);
		border: 1px solid rgba(148, 163, 184, 0.1);
		border-radius: 0.5rem;
	}

	.native-libs-card h4 {
		font-size: 0.8rem;
		color: #f1f5f9;
		margin: 0 0 0.5rem;
	}

	.lib-list {
		display: flex;
		flex-direction: column;
		gap: 0.3rem;
	}

	.lib-item {
		display: flex;
		gap: 0.5rem;
		font-size: 0.7rem;
		padding: 0.3rem 0.5rem;
		background: rgba(15, 23, 42, 0.4);
		border-radius: 0.25rem;
	}

	.lib-name { flex: 1; color: #f1f5f9; font-family: 'JetBrains Mono', monospace; }
	.lib-arch { color: #a855f7; }
	.lib-size { color: #94a3b8; }

	.secrets-section, .code-issues-section, .sdks-section, .privacy-section {
		padding: 0.5rem 0;
	}

	.secret-group, .issue-group {
		margin-bottom: 1rem;
	}

	.secret-group h4, .issue-group h4 {
		font-size: 0.8rem;
		color: #f1f5f9;
		margin: 0 0 0.5rem;
	}

	.secret-list, .issue-list {
		display: flex;
		flex-direction: column;
		gap: 0.4rem;
	}

	.secret-item, .code-issue {
		padding: 0.5rem 0.75rem;
		background: rgba(15, 23, 42, 0.6);
		border: 1px solid rgba(148, 163, 184, 0.1);
		border-radius: 0.375rem;
		border-left: 3px solid #64748b;
	}

	.secret-item.high, .code-issue.high { border-left-color: #ef4444; }
	.secret-item.medium, .code-issue.medium { border-left-color: #eab308; }
	.secret-item.low, .code-issue.low { border-left-color: #22c55e; }
	.secret-item.critical { border-left-color: #dc2626; background: rgba(220, 38, 38, 0.05); }

	.secret-header, .issue-header, .privacy-header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		margin-bottom: 0.25rem;
	}

	.secret-type, .issue-type, .privacy-type {
		font-size: 0.75rem;
		font-weight: 600;
		color: #f1f5f9;
	}

	.secret-severity, .issue-severity, .privacy-severity {
		font-size: 0.65rem;
		padding: 0.15rem 0.4rem;
		border-radius: 0.2rem;
		text-transform: uppercase;
	}

	.secret-severity.high, .issue-severity.high { background: rgba(239, 68, 68, 0.2); color: #ef4444; }
	.secret-severity.medium, .issue-severity.medium { background: rgba(234, 179, 8, 0.2); color: #eab308; }
	.secret-severity.low, .issue-severity.low { background: rgba(34, 197, 94, 0.2); color: #22c55e; }
	.secret-severity.critical { background: rgba(220, 38, 38, 0.3); color: #fca5a5; }

	.secret-value, .issue-snippet {
		font-family: 'JetBrains Mono', monospace;
		font-size: 0.7rem;
		padding: 0.25rem 0.5rem;
		background: rgba(15, 23, 42, 0.8);
		border-radius: 0.25rem;
		color: #c4b5fd;
		display: block;
		margin: 0.25rem 0;
		word-break: break-all;
	}

	.secret-location, .issue-location {
		font-size: 0.65rem;
		color: #64748b;
	}

	.issue-desc, .privacy-desc {
		font-size: 0.7rem;
		color: #94a3b8;
		margin: 0.25rem 0;
	}

	.sdk-grid {
		display: grid;
		grid-template-columns: repeat(2, 1fr);
		gap: 0.5rem;
	}

	.sdk-card {
		padding: 0.6rem 0.75rem;
		background: rgba(15, 23, 42, 0.6);
		border: 1px solid rgba(148, 163, 184, 0.1);
		border-radius: 0.5rem;
	}

	.sdk-header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		margin-bottom: 0.25rem;
	}

	.sdk-name {
		font-size: 0.8rem;
		font-weight: 600;
		color: #f1f5f9;
	}

	.sdk-type {
		font-size: 0.6rem;
		padding: 0.15rem 0.4rem;
		background: rgba(168, 85, 247, 0.2);
		border-radius: 0.2rem;
		color: #c4b5fd;
		text-transform: uppercase;
	}

	.sdk-package {
		font-size: 0.65rem;
		color: #64748b;
		display: block;
		margin-bottom: 0.25rem;
	}

	.sdk-data {
		display: flex;
		flex-wrap: wrap;
		gap: 0.25rem;
		align-items: center;
	}

	.data-label {
		font-size: 0.6rem;
		color: #94a3b8;
	}

	.data-item {
		font-size: 0.6rem;
		padding: 0.1rem 0.3rem;
		background: rgba(234, 179, 8, 0.1);
		border-radius: 0.2rem;
		color: #fbbf24;
	}

	.privacy-list {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
	}

	.privacy-issue {
		padding: 0.6rem 0.75rem;
		background: rgba(15, 23, 42, 0.6);
		border: 1px solid rgba(148, 163, 184, 0.1);
		border-radius: 0.5rem;
		border-left: 3px solid #64748b;
	}

	.privacy-issue.high { border-left-color: #ef4444; }
	.privacy-issue.medium { border-left-color: #eab308; }
	.privacy-issue.low { border-left-color: #22c55e; }

	.privacy-details {
		font-size: 0.7rem;
		color: #94a3b8;
		margin: 0.25rem 0;
	}

	.privacy-data {
		color: #a855f7;
	}

	.privacy-recommendation {
		font-size: 0.7rem;
		color: #22c55e;
		padding: 0.25rem 0.5rem;
		background: rgba(34, 197, 94, 0.1);
		border-radius: 0.25rem;
		margin-top: 0.25rem;
	}

	.empty-deep {
		text-align: center;
		padding: 2rem;
		color: #22c55e;
		font-size: 0.85rem;
	}

	@media (max-width: 900px) {
		.overview-grid { grid-template-columns: repeat(2, 1fr); }
		.sdk-grid { grid-template-columns: 1fr; }
	}

	@media (max-width: 600px) {
		.overview-grid { grid-template-columns: 1fr; }
		.ns-grid { grid-template-columns: 1fr; }
		.deep-header { flex-direction: column; align-items: flex-start; }
	}
</style>
