<script lang="ts">
	import { tr } from '$lib/i18n';
	import ToolHistory from '$lib/components/ToolHistory.svelte';
	import ToolHelp from '$lib/components/ToolHelp.svelte';

	interface DecompiledMethod {
		name: string;
		return_type: string;
		parameters: string[];
		is_static: boolean;
		is_public: boolean;
		is_native: boolean;
		is_abstract: boolean;
		modifiers: string[];
	}

	interface DecompiledClass {
		class_name: string;
		package: string;
		source_file: string | null;
		methods: DecompiledMethod[];
		fields: string[];
		interfaces: string[];
		superclass: string | null;
		is_abstract: boolean;
		is_public: boolean;
	}

	interface IntentFilter {
		component: string;
		actions: string[];
		categories: string[];
		data_schemes: string[];
		data_hosts: string[];
	}

	interface ManifestInfo {
		package_name: string;
		version_name: string;
		version_code: string;
		min_sdk: string;
		target_sdk: string;
		permissions: string[];
		activities: string[];
		services: string[];
		receivers: string[];
		providers: string[];
		intent_filters: IntentFilter[];
		exported_components: string[];
		deep_links: string[];
	}

	interface ReverseCertificateInfo {
		issuer: string;
		subject: string;
		serial_number: string;
		valid_from: string;
		valid_to: string;
		fingerprint_sha1: string;
		fingerprint_sha256: string;
		signature_algorithm: string;
		is_debug: boolean;
	}

	interface HardcodedSecret {
		type_: string;
		value: string;
		file: string;
		line: number | null;
		severity: string;
		description: string;
	}

	interface SmaliAnalysis {
		total_classes: number;
		total_methods: number;
		native_methods: number;
		crypto_usage: string[];
		network_calls: string[];
		file_io_calls: string[];
		reflection_usage: string[];
		dynamic_code_loading: string[];
		root_detection: string[];
		anti_debug: string[];
	}

	interface ResourceInfo {
		total_resources: number;
		layouts: number;
		drawables: number;
		strings_count: number;
		interesting_strings: string[];
		urls: string[];
		file_paths: string[];
		api_endpoints: string[];
	}

	interface ReverseSecurityFinding {
		severity: string;
		category: string;
		description: string;
		recommendation: string;
		affected_component: string | null;
	}

	interface ReverseEngineerResult {
		success: boolean;
		file_path: string;
		file_type: string;
		file_size: number;
		manifest: ManifestInfo | null;
		certificates: ReverseCertificateInfo[];
		decompiled_classes: DecompiledClass[];
		smali_analysis: SmaliAnalysis | null;
		resources: ResourceInfo | null;
		hardcoded_secrets: HardcodedSecret[];
		strings: string[];
		security_findings: ReverseSecurityFinding[];
		summary: string;
	}

	let filePath = $state('');
	let fileType = $state('auto');
	let decompile = $state(true);
	let extractStrings = $state(true);
	let extractManifest = $state(true);
	let extractCertificates = $state(true);
	let extractResources = $state(true);
	let analyzeSmali = $state(true);
	let findHardcodedSecrets = $state(true);
	let result = $state<ReverseEngineerResult | null>(null);
	let error = $state('');
	let processing = $state(false);
	let activeMainTab = $state('analyze');
	let activeResultTab = $state('overview');
	let stringSearch = $state('');
	let exportFormat = $state('json');
	let exporting = $state(false);
	let historyComponent = $state<ToolHistory>();

	let securityScore = $derived(calcSecurityScore());
	let filteredStrings = $derived(
		result
			? stringSearch
				? result.strings.filter((s: string) => s.toLowerCase().includes(stringSearch.toLowerCase()))
				: result.strings.slice(0, 200)
			: []
	);
	let highFindings = $derived(result ? result.security_findings.filter((f: ReverseSecurityFinding) => f.severity === 'high').length : 0);
	let mediumFindings = $derived(result ? result.security_findings.filter((f: ReverseSecurityFinding) => f.severity === 'medium').length : 0);
	let lowFindings = $derived(result ? result.security_findings.filter((f: ReverseSecurityFinding) => f.severity === 'low').length : 0);

	function calcSecurityScore(): { score: number; level: string } {
		if (!result) return { score: -1, level: '' };
		let score = 100;
		for (const f of result.security_findings) {
			if (f.severity === 'high') score -= 15;
			else if (f.severity === 'medium') score -= 8;
			else if (f.severity === 'low') score -= 3;
			else score -= 1;
		}
		score -= result.hardcoded_secrets.filter((s: HardcodedSecret) => s.severity === 'high').length * 5;
		if (result.certificates.some((c: ReverseCertificateInfo) => c.is_debug)) score -= 20;
		score = Math.max(0, Math.min(100, score));
		let level = '';
		if (score >= 80) level = 'good';
		else if (score >= 60) level = 'warning';
		else if (score >= 40) level = 'danger';
		else level = 'critical';
		return { score, level };
	}

	async function selectFile() {
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			const selected = await invoke<string | null>('select_binary_file');
			if (selected) filePath = selected;
		} catch (e) {
			console.error('File selection failed:', e);
		}
	}

	async function startAnalysis() {
		if (!filePath.trim()) { error = $tr('reverseEngineer.provideFilePath'); return; }
		processing = true; error = ''; result = null;
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			result = await invoke<ReverseEngineerResult>('reverse_engineer_command', {
				config: {
					file_path: filePath.trim(),
					file_type: fileType,
					decompile,
					extract_strings: extractStrings,
					extract_manifest: extractManifest,
					extract_certificates: extractCertificates,
					extract_resources: extractResources,
					analyze_smali: analyzeSmali,
					find_hardcoded_secrets: findHardcodedSecrets,
					timeout: 120,
				}
			});
			if (historyComponent) {
				historyComponent.saveHistory(
					filePath.trim(),
					JSON.stringify(result),
					result.summary,
					'success'
				);
			}
		} catch (e: any) {
			error = e.toString();
			if (historyComponent) {
				historyComponent.saveHistory(
					filePath.trim(),
					JSON.stringify({ error: e.toString() }),
					undefined,
					'failed'
				);
			}
		} finally {
			processing = false;
		}
	}

	async function exportResult() {
		if (!result) return;
		exporting = true;
		try {
			const { save } = await import('@tauri-apps/plugin-dialog');
			const { writeFile } = await import('@tauri-apps/plugin-fs');
			const path = await save({
				defaultPath: `reverse-engineer-${Date.now()}.${exportFormat}`,
				filters: [{ name: exportFormat.toUpperCase(), extensions: [exportFormat] }]
			});
			if (path) {
				const content = exportFormat === 'json'
					? JSON.stringify(result, null, 2)
					: convertToCsv(result);
				const encoder = new TextEncoder();
				await writeFile(path, encoder.encode(content));
			}
		} catch (e) {
			console.error('Export failed:', e);
		} finally {
			exporting = false;
		}
	}

	function convertToCsv(data: ReverseEngineerResult): string {
		const rows: string[][] = [['Category', 'Severity', 'Description', 'Recommendation']];
		for (const f of data.security_findings) {
			rows.push([f.category, f.severity, f.description, f.recommendation]);
		}
		for (const s of data.hardcoded_secrets) {
			rows.push([s.type_, s.severity, s.description, '']);
		}
		return rows.map(r => r.map(c => `"${c.replace(/"/g, '""')}"`).join(',')).join('\n');
	}

	function formatSize(bytes: number): string {
		if (bytes < 1024) return bytes + 'B';
		if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + 'KB';
		return (bytes / (1024 * 1024)).toFixed(1) + 'MB';
	}

	function getScoreColor(score: number): string {
		if (score >= 80) return '#22c55e';
		if (score >= 60) return '#eab308';
		if (score >= 40) return '#f97316';
		return '#ef4444';
	}

	function getScoreLabel(level: string): string {
		switch (level) {
			case 'good': return $tr('reverseEngineer.scoreGood');
			case 'warning': return $tr('reverseEngineer.scoreWarning');
			case 'danger': return $tr('reverseEngineer.scoreDanger');
			case 'critical': return $tr('reverseEngineer.scoreCritical');
			default: return '';
		}
	}

	function getSeverityColor(severity: string): string {
		switch (severity) {
			case 'high': return '#ef4444';
			case 'medium': return '#eab308';
			case 'low': return '#3b82f6';
			case 'info': return '#94a3b8';
			default: return '#94a3b8';
		}
	}

	function getSeverityBg(severity: string): string {
		switch (severity) {
			case 'high': return 'rgba(239, 68, 68, 0.1)';
			case 'medium': return 'rgba(234, 179, 8, 0.1)';
			case 'low': return 'rgba(59, 130, 246, 0.1)';
			case 'info': return 'rgba(148, 163, 184, 0.1)';
			default: return 'rgba(148, 163, 184, 0.1)';
		}
	}

	function getSeverityBorder(severity: string): string {
		switch (severity) {
			case 'high': return 'rgba(239, 68, 68, 0.3)';
			case 'medium': return 'rgba(234, 179, 8, 0.3)';
			case 'low': return 'rgba(59, 130, 246, 0.3)';
			case 'info': return 'rgba(148, 163, 184, 0.3)';
			default: return 'rgba(148, 163, 184, 0.3)';
		}
	}

	function isDangerousPerm(perm: string): boolean {
		return perm.includes('dangerous') || perm.includes('READ_') || perm.includes('WRITE_') ||
			perm.includes('CAMERA') || perm.includes('RECORD') || perm.includes('LOCATION') ||
			perm.includes('SMS') || perm.includes('CALL');
	}
</script>

<div class="nd-page">
	<div class="page-header">
		<a href="/tools" class="back-link">{$tr('common.backToTools')}</a>
		<h1 class="page-title">🔧 {$tr('reverseEngineer.title')}</h1>
		<p class="page-subtitle">{$tr('reverseEngineer.subtitle')}</p>
	</div>

	<div class="tabs">
		<button class="tab-btn {activeMainTab === 'analyze' ? 'active' : ''}" onclick={() => (activeMainTab = 'analyze')}>
			<span class="tab-icon">🔬</span> {$tr('reverseEngineer.analyze')}
		</button>
		<button class="tab-btn {activeMainTab === 'history' ? 'active' : ''}" onclick={() => (activeMainTab = 'history')}>
			<span class="tab-icon">📋</span> {$tr('common.history')}
		</button>
		<button class="tab-btn {activeMainTab === 'help' ? 'active' : ''}" onclick={() => (activeMainTab = 'help')}>
			<span class="tab-icon">📖</span> {$tr('common.help')}
		</button>
	</div>

	{#if activeMainTab === 'analyze'}
		<div class="content-grid">
			<div class="input-section">
				<div class="section-card">
					<h2 class="section-title">🔬 {$tr('reverseEngineer.configTitle')}</h2>
					<p class="section-desc">{$tr('reverseEngineer.configDesc')}</p>

					<div class="form-group">
						<label class="form-label" for="re-filepath">{$tr('reverseEngineer.filePath')}</label>
						<div class="input-with-btn">
							<input
								id="re-filepath"
								type="text"
								bind:value={filePath}
								placeholder={$tr('reverseEngineer.filePathPlaceholder')}
								class="form-input"
								disabled={processing}
							/>
							<button class="btn-browse" onclick={selectFile} disabled={processing} title={$tr('reverseEngineer.selectFile')}>📁</button>
						</div>
					</div>

					<div class="form-group">
						<label class="form-label" for="re-filetype">{$tr('reverseEngineer.fileType')}</label>
						<select id="re-filetype" bind:value={fileType} class="form-input" disabled={processing}>
							<option value="auto">{$tr('reverseEngineer.autoDetect')}</option>
							<option value="apk">APK (Android)</option>
							<option value="dex">DEX (Dalvik)</option>
							<option value="ipa">IPA (iOS)</option>
							<option value="jar">JAR (Java)</option>
							<option value="pe">PE (Windows)</option>
							<option value="elf">ELF (Linux)</option>
							<option value="native">Native (.so)</option>
						</select>
					</div>

					<div class="form-group">
						<span class="form-label">{$tr('reverseEngineer.analysisOptions')}</span>
						<div class="target-grid">
							<label class="target-chip {decompile ? 'active' : ''}">
								<input type="checkbox" bind:checked={decompile} />
								<span>📦 {$tr('reverseEngineer.decompile')}</span>
							</label>
							<label class="target-chip {extractStrings ? 'active' : ''}">
								<input type="checkbox" bind:checked={extractStrings} />
								<span>📝 {$tr('reverseEngineer.extractStrings')}</span>
							</label>
							<label class="target-chip {extractManifest ? 'active' : ''}">
								<input type="checkbox" bind:checked={extractManifest} />
								<span>📋 {$tr('reverseEngineer.extractManifest')}</span>
							</label>
							<label class="target-chip {extractCertificates ? 'active' : ''}">
								<input type="checkbox" bind:checked={extractCertificates} />
								<span>🔐 {$tr('reverseEngineer.extractCertificates')}</span>
							</label>
							<label class="target-chip {extractResources ? 'active' : ''}">
								<input type="checkbox" bind:checked={extractResources} />
								<span>📁 {$tr('reverseEngineer.extractResources')}</span>
							</label>
							<label class="target-chip {analyzeSmali ? 'active' : ''}">
								<input type="checkbox" bind:checked={analyzeSmali} />
								<span>⚙️ {$tr('reverseEngineer.analyzeSmali')}</span>
							</label>
							<label class="target-chip {findHardcodedSecrets ? 'active' : ''}">
								<input type="checkbox" bind:checked={findHardcodedSecrets} />
								<span>🔑 {$tr('reverseEngineer.findSecrets')}</span>
							</label>
						</div>
					</div>

					<div class="button-group">
						<button class="btn-primary" onclick={startAnalysis} disabled={processing || !filePath.trim()}>
							{#if processing}
								<span class="spinner"></span> {$tr('reverseEngineer.analyzing')}
							{:else}
								🔬 {$tr('reverseEngineer.startAnalysis')}
							{/if}
						</button>
						<button class="btn-secondary" onclick={() => { filePath = ''; result = null; error = ''; }} disabled={processing}>
							🗑️ {$tr('common.clear')}
						</button>
					</div>
				</div>
			</div>

			<div class="result-section">
				{#if error}
					<div class="error-banner">
						<span class="error-icon">❌</span>
						<span>{error}</span>
					</div>
				{/if}

				{#if result}
					<div class="section-card score-section">
						<div class="score-row">
							<div class="score-circle" style="border-color: {getScoreColor(securityScore.score)}; color: {getScoreColor(securityScore.score)};">
								<span class="score-number">{securityScore.score}</span>
								<span class="score-label">{getScoreLabel(securityScore.level)}</span>
							</div>
							<div class="score-details">
								<h3 class="section-title" style="margin-bottom:0.5rem">{$tr('reverseEngineer.result.title')}</h3>
								<p class="result-summary">{result.summary}</p>
								<div class="score-badges">
									{#if highFindings > 0}<span class="badge badge-danger">🔴 {highFindings} {$tr('reverseEngineer.highRisk')}</span>{/if}
									{#if mediumFindings > 0}<span class="badge badge-warning">🟡 {mediumFindings} {$tr('reverseEngineer.mediumRisk')}</span>{/if}
									{#if lowFindings > 0}<span class="badge badge-info">🔵 {lowFindings} {$tr('reverseEngineer.lowRisk')}</span>{/if}
								</div>
							</div>
							<div class="export-group">
								<select bind:value={exportFormat} class="export-select">
									<option value="json">JSON</option>
									<option value="csv">CSV</option>
								</select>
								<button class="btn-export" onclick={exportResult} disabled={exporting}>
									{#if exporting}⏳{:else}📥{/if} {$tr('common.export')}
								</button>
							</div>
						</div>
					</div>

					<div class="section-card stats-section">
						<div class="stats-grid">
							<div class="stat-card">
								<div class="stat-value" style="color: #a855f7;">{result.file_type.toUpperCase()}</div>
								<div class="stat-label">{$tr('reverseEngineer.fileType')}</div>
							</div>
							<div class="stat-card">
								<div class="stat-value" style="color: #22c55e;">{formatSize(result.file_size)}</div>
								<div class="stat-label">{$tr('reverseEngineer.fileSize')}</div>
							</div>
							<div class="stat-card">
								<div class="stat-value" style="color: #6366f1;">{result.decompiled_classes.length}</div>
								<div class="stat-label">{$tr('reverseEngineer.classCount')}</div>
							</div>
							<div class="stat-card">
								<div class="stat-value" style="color: #f97316;">{result.hardcoded_secrets.length}</div>
								<div class="stat-label">{$tr('reverseEngineer.hardcodedKeys')}</div>
							</div>
						</div>
					</div>

					<div class="section-card">
						<div class="result-tabs">
							<button class="result-tab {activeResultTab === 'overview' ? 'active' : ''}" onclick={() => (activeResultTab = 'overview')}>📊 {$tr('reverseEngineer.result.overview')}</button>
							{#if result.manifest}
								<button class="result-tab {activeResultTab === 'manifest' ? 'active' : ''}" onclick={() => (activeResultTab = 'manifest')}>📋 Manifest</button>
							{/if}
							{#if result.certificates.length > 0}
								<button class="result-tab {activeResultTab === 'certificates' ? 'active' : ''}" onclick={() => (activeResultTab = 'certificates')}>🔐 {$tr('reverseEngineer.result.certificates')}</button>
							{/if}
							<button class="result-tab {activeResultTab === 'classes' ? 'active' : ''}" onclick={() => (activeResultTab = 'classes')}>📦 {$tr('reverseEngineer.result.classes')}</button>
							{#if result.smali_analysis}
								<button class="result-tab {activeResultTab === 'smali' ? 'active' : ''}" onclick={() => (activeResultTab = 'smali')}>⚙️ {$tr('reverseEngineer.result.smali')}</button>
							{/if}
							{#if result.resources}
								<button class="result-tab {activeResultTab === 'resources' ? 'active' : ''}" onclick={() => (activeResultTab = 'resources')}>📁 {$tr('reverseEngineer.result.resources')}</button>
							{/if}
							<button class="result-tab {activeResultTab === 'secrets' ? 'active' : ''}" onclick={() => (activeResultTab = 'secrets')}>🔑 {$tr('reverseEngineer.result.secrets')}</button>
							<button class="result-tab {activeResultTab === 'strings' ? 'active' : ''}" onclick={() => (activeResultTab = 'strings')}>📝 {$tr('reverseEngineer.result.strings')}</button>
							<button class="result-tab {activeResultTab === 'findings' ? 'active' : ''}" onclick={() => (activeResultTab = 'findings')}>🛡️ {$tr('reverseEngineer.result.findings')}</button>
						</div>

						{#if activeResultTab === 'overview'}
							<div class="detail-grid">
								{#if result.manifest}
									<div class="detail-card">
										<h3 class="subsection-title">📱 {$tr('reverseEngineer.appInfo')}</h3>
										<div class="detail-rows">
											<div class="detail-row"><span class="detail-key">{$tr('reverseEngineer.packageName')}</span><span class="detail-val mono">{result.manifest.package_name || '-'}</span></div>
											<div class="detail-row"><span class="detail-key">{$tr('reverseEngineer.version')}</span><span class="detail-val">{result.manifest.version_name || '-'}</span></div>
											<div class="detail-row"><span class="detail-key">Min SDK</span><span class="detail-val">{result.manifest.min_sdk || '-'}</span></div>
											<div class="detail-row"><span class="detail-key">Target SDK</span><span class="detail-val">{result.manifest.target_sdk || '-'}</span></div>
											<div class="detail-row"><span class="detail-key">{$tr('reverseEngineer.permissions')}</span><span class="detail-val">{result.manifest.permissions.length}</span></div>
											<div class="detail-row"><span class="detail-key">{$tr('reverseEngineer.components')}</span><span class="detail-val">{result.manifest.activities.length + result.manifest.services.length + result.manifest.receivers.length + result.manifest.providers.length}</span></div>
										</div>
									</div>
								{/if}

								{#if result.smali_analysis}
									<div class="detail-card">
										<h3 class="subsection-title">💻 {$tr('reverseEngineer.codeAnalysis')}</h3>
										<div class="mini-stats">
											<div class="mini-stat"><span class="mini-val" style="color:#06b6d4;">{result.smali_analysis.total_classes}</span><span class="mini-label">{$tr('reverseEngineer.classes')}</span></div>
											<div class="mini-stat"><span class="mini-val" style="color:#22c55e;">{result.smali_analysis.total_methods}</span><span class="mini-label">{$tr('reverseEngineer.methods')}</span></div>
											<div class="mini-stat"><span class="mini-val" style="color:#eab308;">{result.smali_analysis.native_methods}</span><span class="mini-label">Native</span></div>
											<div class="mini-stat"><span class="mini-val" style="color:#ef4444;">{result.hardcoded_secrets.length}</span><span class="mini-label">{$tr('reverseEngineer.hardcodedKeys')}</span></div>
										</div>
									</div>
								{/if}

								{#if result.security_findings.length > 0}
									<div class="detail-card">
										<h3 class="subsection-title">🛡️ {$tr('reverseEngineer.securitySummary')}</h3>
										<div class="findings-compact">
											{#each result.security_findings.slice(0, 5) as finding}
												<div class="finding-compact">
													<span class="finding-dot" style="background:{getSeverityColor(finding.severity)};"></span>
													<span class="finding-cat">{finding.category}</span>
													<span class="finding-sep">-</span>
													<span class="finding-desc">{finding.description}</span>
												</div>
											{/each}
											{#if result.security_findings.length > 5}
												<div class="finding-more">+{result.security_findings.length - 5} {$tr('reverseEngineer.moreFindings')}</div>
											{/if}
										</div>
									</div>
								{/if}
							</div>
						{/if}

						{#if activeResultTab === 'manifest' && result.manifest}
							<div class="detail-grid">
								<div class="detail-card">
									<h3 class="subsection-title">🔑 {$tr('reverseEngineer.permissionList')} ({result.manifest.permissions.length})</h3>
									{#if result.manifest.permissions.length > 0}
										<div class="tag-list">
											{#each result.manifest.permissions as perm}
												<span class="tag {isDangerousPerm(perm) ? 'tag-danger' : ''}">{perm}</span>
											{/each}
										</div>
									{:else}
										<p class="empty-text">{$tr('reverseEngineer.noPermissions')}</p>
									{/if}
								</div>

								<div class="detail-card">
									<h3 class="subsection-title">🧩 {$tr('reverseEngineer.componentsDetail')}</h3>
									<div class="component-grid">
										<div class="comp-group">
											<h4 class="comp-title">Activities ({result.manifest.activities.length})</h4>
											<div class="comp-list">
												{#each result.manifest.activities as activity}
													<div class="comp-item mono-blue">{activity}</div>
												{/each}
											</div>
										</div>
										<div class="comp-group">
											<h4 class="comp-title">Services ({result.manifest.services.length})</h4>
											<div class="comp-list">
												{#each result.manifest.services as service}
													<div class="comp-item mono-green">{service}</div>
												{/each}
											</div>
										</div>
										<div class="comp-group">
											<h4 class="comp-title">Receivers ({result.manifest.receivers.length})</h4>
											<div class="comp-list">
												{#each result.manifest.receivers as receiver}
													<div class="comp-item mono-yellow">{receiver}</div>
												{/each}
											</div>
										</div>
										<div class="comp-group">
											<h4 class="comp-title">Providers ({result.manifest.providers.length})</h4>
											<div class="comp-list">
												{#each result.manifest.providers as provider}
													<div class="comp-item mono-purple">{provider}</div>
												{/each}
											</div>
										</div>
									</div>
								</div>

								{#if result.manifest.exported_components.length > 0}
									<div class="detail-card alert-danger">
										<h3 class="subsection-title">⚠️ {$tr('reverseEngineer.exportedComponents')} ({result.manifest.exported_components.length})</h3>
										<div class="comp-list">
											{#each result.manifest.exported_components as comp}
												<div class="comp-item mono-red">{comp}</div>
											{/each}
										</div>
									</div>
								{/if}

								{#if result.manifest.deep_links.length > 0}
									<div class="detail-card alert-warning">
										<h3 class="subsection-title">🔗 {$tr('reverseEngineer.deepLinks')} ({result.manifest.deep_links.length})</h3>
										<div class="comp-list">
											{#each result.manifest.deep_links as link}
												<div class="comp-item mono-yellow">{link}</div>
											{/each}
										</div>
									</div>
								{/if}
							</div>
						{/if}

						{#if activeResultTab === 'certificates'}
							<div class="detail-grid">
								{#each result.certificates as cert, i}
									<div class="detail-card">
										<h3 class="subsection-title">🔐 {$tr('reverseEngineer.certificate')} #{i + 1} {#if cert.is_debug}<span class="debug-badge">{$tr('reverseEngineer.debugCert')}</span>{/if}</h3>
										<div class="detail-rows">
											<div class="detail-row"><span class="detail-key">{$tr('reverseEngineer.issuer')}</span><span class="detail-val mono-small">{cert.issuer}</span></div>
											<div class="detail-row"><span class="detail-key">{$tr('reverseEngineer.subject')}</span><span class="detail-val mono-small">{cert.subject}</span></div>
											<div class="detail-row"><span class="detail-key">{$tr('reverseEngineer.serialNumber')}</span><span class="detail-val mono-small">{cert.serial_number}</span></div>
											<div class="detail-row"><span class="detail-key">{$tr('reverseEngineer.signatureAlgo')}</span><span class="detail-val">{cert.signature_algorithm}</span></div>
											<div class="detail-row"><span class="detail-key">{$tr('reverseEngineer.validity')}</span><span class="detail-val">{cert.valid_from} - {cert.valid_to}</span></div>
											<div class="detail-row"><span class="detail-key">SHA1</span><span class="detail-val mono-small">{cert.fingerprint_sha1}</span></div>
											<div class="detail-row"><span class="detail-key">SHA256</span><span class="detail-val mono-small">{cert.fingerprint_sha256}</span></div>
										</div>
									</div>
								{/each}
								{#if result.certificates.length === 0}
									<div class="detail-card">
										<p class="empty-text">{$tr('reverseEngineer.noCertificates')}</p>
									</div>
								{/if}
							</div>
						{/if}

						{#if activeResultTab === 'classes'}
							<div class="detail-card">
								<h3 class="subsection-title">📦 {$tr('reverseEngineer.decompiledClasses')} ({result.decompiled_classes.length})</h3>
								{#if result.decompiled_classes.length > 0}
									<div class="class-list">
										{#each result.decompiled_classes as cls}
											<div class="class-card">
												<div class="class-header">
													<span class="access-badge {cls.is_public ? 'access-public' : 'access-private'}">{cls.is_public ? 'public' : 'private'}</span>
													{#if cls.is_abstract}
														<span class="access-badge access-abstract">abstract</span>
													{/if}
													<span class="class-name">{cls.class_name}</span>
												</div>
												{#if cls.superclass}
													<div class="class-extends">extends <span class="extends-name">{cls.superclass}</span></div>
												{/if}
												{#if cls.methods.length > 0}
													<div class="methods-section">
														<span class="methods-label">{$tr('reverseEngineer.methods')} ({cls.methods.length}):</span>
														<div class="methods-list">
															{#each cls.methods.slice(0, 10) as method}
																<span class="method-tag {method.is_native ? 'method-native' : ''}">{method.name}()</span>
															{/each}
															{#if cls.methods.length > 10}
																<span class="method-more">+{cls.methods.length - 10}</span>
															{/if}
														</div>
													</div>
												{/if}
											</div>
										{/each}
									</div>
								{:else}
									<p class="empty-text">{$tr('reverseEngineer.noClasses')}</p>
								{/if}
							</div>
						{/if}

						{#if activeResultTab === 'smali' && result.smali_analysis}
							<div class="detail-grid">
								<div class="detail-card">
									<div class="mini-stats">
										<div class="mini-stat"><span class="mini-val" style="color:#06b6d4;">{result.smali_analysis.total_classes}</span><span class="mini-label">{$tr('reverseEngineer.totalClasses')}</span></div>
										<div class="mini-stat"><span class="mini-val" style="color:#22c55e;">{result.smali_analysis.total_methods}</span><span class="mini-label">{$tr('reverseEngineer.totalMethods')}</span></div>
										<div class="mini-stat"><span class="mini-val" style="color:#eab308;">{result.smali_analysis.native_methods}</span><span class="mini-label">Native</span></div>
									</div>
								</div>

								{#if result.smali_analysis.crypto_usage.length > 0}
									<div class="detail-card">
										<h3 class="subsection-title">🔐 {$tr('reverseEngineer.cryptoUsage')}</h3>
										<div class="tag-list">{#each result.smali_analysis.crypto_usage as item}<span class="tag tag-cyan">{item}</span>{/each}</div>
									</div>
								{/if}

								{#if result.smali_analysis.network_calls.length > 0}
									<div class="detail-card">
										<h3 class="subsection-title">🌐 {$tr('reverseEngineer.networkCalls')}</h3>
										<div class="tag-list">{#each result.smali_analysis.network_calls as item}<span class="tag tag-green">{item}</span>{/each}</div>
									</div>
								{/if}

								{#if result.smali_analysis.dynamic_code_loading.length > 0}
									<div class="detail-card alert-danger">
										<h3 class="subsection-title">⚠️ {$tr('reverseEngineer.dynamicLoading')}</h3>
										<div class="tag-list">{#each result.smali_analysis.dynamic_code_loading as item}<span class="tag tag-danger">{item}</span>{/each}</div>
									</div>
								{/if}

								{#if result.smali_analysis.root_detection.length > 0}
									<div class="detail-card alert-success">
										<h3 class="subsection-title">🛡️ {$tr('reverseEngineer.rootDetection')}</h3>
										<div class="tag-list">{#each result.smali_analysis.root_detection as item}<span class="tag tag-success">{item}</span>{/each}</div>
									</div>
								{/if}

								{#if result.smali_analysis.anti_debug.length > 0}
									<div class="detail-card alert-info">
										<h3 class="subsection-title">🛡️ {$tr('reverseEngineer.antiDebug')}</h3>
										<div class="tag-list">{#each result.smali_analysis.anti_debug as item}<span class="tag tag-info">{item}</span>{/each}</div>
									</div>
								{/if}

								{#if result.smali_analysis.reflection_usage.length > 0}
									<div class="detail-card alert-warning">
										<h3 class="subsection-title">🔄 {$tr('reverseEngineer.reflectionUsage')}</h3>
										<div class="tag-list">{#each result.smali_analysis.reflection_usage as item}<span class="tag tag-warning">{item}</span>{/each}</div>
									</div>
								{/if}
							</div>
						{/if}

						{#if activeResultTab === 'resources' && result.resources}
							<div class="detail-grid">
								<div class="detail-card">
									<div class="mini-stats">
										<div class="mini-stat"><span class="mini-val" style="color:#a855f7;">{result.resources.total_resources}</span><span class="mini-label">{$tr('reverseEngineer.totalResources')}</span></div>
										<div class="mini-stat"><span class="mini-val" style="color:#3b82f6;">{result.resources.layouts}</span><span class="mini-label">{$tr('reverseEngineer.layouts')}</span></div>
										<div class="mini-stat"><span class="mini-val" style="color:#22c55e;">{result.resources.drawables}</span><span class="mini-label">{$tr('reverseEngineer.drawables')}</span></div>
										<div class="mini-stat"><span class="mini-val" style="color:#f97316;">{result.resources.strings_count}</span><span class="mini-label">{$tr('reverseEngineer.stringsCount')}</span></div>
									</div>
								</div>

								{#if result.resources.urls.length > 0}
									<div class="detail-card">
										<h3 class="subsection-title">🔗 URL ({result.resources.urls.length})</h3>
										<div class="scroll-list">
											{#each result.resources.urls as url}
												<div class="list-item mono-blue">{url}</div>
											{/each}
										</div>
									</div>
								{/if}

								{#if result.resources.api_endpoints.length > 0}
									<div class="detail-card alert-warning">
										<h3 class="subsection-title">⚡ {$tr('reverseEngineer.apiEndpoints')} ({result.resources.api_endpoints.length})</h3>
										<div class="scroll-list">
											{#each result.resources.api_endpoints as ep}
												<div class="list-item mono-yellow">{ep}</div>
											{/each}
										</div>
									</div>
								{/if}

								{#if result.resources.interesting_strings.length > 0}
									<div class="detail-card">
										<h3 class="subsection-title">🔍 {$tr('reverseEngineer.interestingStrings')} ({result.resources.interesting_strings.length})</h3>
										<div class="scroll-list">
											{#each result.resources.interesting_strings as s}
												<div class="list-item mono-orange">{s}</div>
											{/each}
										</div>
									</div>
								{/if}
							</div>
						{/if}

						{#if activeResultTab === 'secrets'}
							{#if result.hardcoded_secrets.length > 0}
								<div class="alert-danger" style="margin-bottom:1rem; padding:0.75rem 1rem; border-radius:0.5rem;">
									⚠️ {$tr('reverseEngineer.foundSecrets')} {result.hardcoded_secrets.length} {$tr('reverseEngineer.hardcodedSecretsCount')}
								</div>
								<div class="detail-grid">
									{#each result.hardcoded_secrets as secret}
										<div class="detail-card" style="border-color: {getSeverityBorder(secret.severity)}; background: {getSeverityBg(secret.severity)};">
											<div class="secret-header">
												<span class="finding-dot" style="background:{getSeverityColor(secret.severity)};"></span>
												<span class="secret-type">{secret.type_}</span>
												<span class="secret-severity" style="color:{getSeverityColor(secret.severity)};">{secret.severity.toUpperCase()}</span>
											</div>
											<div class="secret-value">{secret.value}</div>
											<div class="secret-desc">{secret.description}</div>
										</div>
									{/each}
								</div>
							{:else}
								<div class="alert-success" style="padding:1rem; border-radius:0.5rem;">
									✅ {$tr('reverseEngineer.noSecrets')}
								</div>
							{/if}
						{/if}

						{#if activeResultTab === 'strings'}
							<div class="strings-section">
								<div class="strings-toolbar">
									<input type="text" bind:value={stringSearch} placeholder={$tr('reverseEngineer.searchStrings')} class="form-input" style="flex:1;" />
									<span class="strings-count">{filteredStrings.length} / {result.strings.length}</span>
								</div>
								<div class="scroll-list" style="max-height:400px;">
									{#each filteredStrings as s}
										<div class="list-item">{s}</div>
									{/each}
								</div>
							</div>
						{/if}

						{#if activeResultTab === 'findings'}
							{#if result.security_findings.length > 0}
								<div class="detail-grid">
									{#each result.security_findings as finding}
										<div class="detail-card" style="border-color: {getSeverityBorder(finding.severity)}; background: {getSeverityBg(finding.severity)};">
											<div class="finding-header">
												<span class="finding-dot" style="background:{getSeverityColor(finding.severity)};"></span>
												<span class="finding-cat">{finding.category}</span>
												<span class="finding-severity" style="color:{getSeverityColor(finding.severity)};">{finding.severity.toUpperCase()}</span>
											</div>
											<p class="finding-desc">{finding.description}</p>
											{#if finding.affected_component}
												<p class="finding-component">{$tr('reverseEngineer.affectedComponent')}: {finding.affected_component}</p>
											{/if}
											<p class="finding-recommendation">💡 {finding.recommendation}</p>
										</div>
									{/each}
								</div>
							{:else}
								<div class="alert-success" style="padding:1rem; border-radius:0.5rem;">
									✅ {$tr('reverseEngineer.noSecurityIssues')}
								</div>
							{/if}
						{/if}
					</div>
				{:else if !processing}
					<div class="section-card empty-state">
						<div class="empty-icon">🔧</div>
						<h3 class="empty-title">{$tr('reverseEngineer.title')}</h3>
						<p class="empty-desc">{$tr('reverseEngineer.emptyHint')}</p>
					</div>
				{/if}
			</div>
		</div>
	{:else if activeMainTab === 'history'}
		<div class="section-card">
			<ToolHistory toolType="reverse_engineer" toolName={$tr('sidebar.reverseEngineer')} bind:this={historyComponent} />
		</div>
	{:else if activeMainTab === 'help'}
		<div class="section-card">
			<ToolHelp toolType="reverse_engineer" />
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
		margin: 0.25rem 0 0.75rem;
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
		border: 1px solid rgba(148, 163, 184, 0.15);
		border-radius: 0.5rem;
		background: rgba(15, 23, 42, 0.6);
		cursor: pointer;
		font-size: 1rem;
		transition: all 0.2s;
		flex-shrink: 0;
	}

	.btn-browse:hover:not(:disabled) {
		border-color: rgba(168, 85, 247, 0.4);
		background: rgba(168, 85, 247, 0.1);
	}

	.btn-browse:disabled { opacity: 0.5; cursor: not-allowed; }

	.target-grid {
		display: grid;
		grid-template-columns: 1fr 1fr;
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

	.target-chip input[type='checkbox'] {
		accent-color: #a855f7;
		width: 0.8rem;
		height: 0.8rem;
	}

	.target-chip:hover:not(.active) {
		border-color: rgba(148, 163, 184, 0.3);
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

	.btn-primary:disabled {
		opacity: 0.5;
		cursor: not-allowed;
		transform: none;
		box-shadow: none;
	}

	.btn-secondary {
		background: rgba(168, 85, 247, 0.1);
		border: 1px solid rgba(168, 85, 247, 0.3);
		color: #c4b5fd;
		font-weight: 500;
		padding: 0.65rem 1.25rem;
		border-radius: 0.5rem;
		cursor: pointer;
		transition: all 0.2s;
		font-size: 0.9rem;
	}

	.btn-secondary:hover:not(:disabled) {
		background: rgba(168, 85, 247, 0.2);
		border-color: rgba(168, 85, 247, 0.5);
	}

	.btn-secondary:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

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

	.error-banner {
		display: flex;
		align-items: center;
		gap: 0.75rem;
		padding: 1rem;
		background: rgba(239, 68, 68, 0.1);
		border: 1px solid rgba(239, 68, 68, 0.2);
		border-radius: 0.5rem;
		color: #fca5a5;
		font-size: 0.85rem;
		margin-bottom: 1rem;
	}

	.error-icon { font-size: 1.25rem; }

	.score-section { margin-bottom: 1rem; }

	.score-row {
		display: flex;
		align-items: center;
		gap: 1.25rem;
	}

	.score-circle {
		width: 80px;
		height: 80px;
		border-radius: 50%;
		border: 3px solid;
		display: flex;
		flex-direction: column;
		align-items: center;
		justify-content: center;
		flex-shrink: 0;
	}

	.score-number {
		font-size: 1.5rem;
		font-weight: 700;
		line-height: 1;
	}

	.score-label {
		font-size: 0.65rem;
		margin-top: 0.15rem;
		opacity: 0.8;
	}

	.score-details { flex: 1; }

	.result-summary {
		font-size: 0.8rem;
		color: #94a3b8;
		margin: 0.25rem 0 0.5rem;
	}

	.score-badges {
		display: flex;
		gap: 0.5rem;
		flex-wrap: wrap;
	}

	.badge {
		padding: 0.2rem 0.5rem;
		border-radius: 0.25rem;
		font-size: 0.7rem;
		font-weight: 600;
	}

	.badge-danger { background: rgba(239, 68, 68, 0.15); color: #fca5a5; }
	.badge-warning { background: rgba(234, 179, 8, 0.15); color: #fde047; }
	.badge-info { background: rgba(59, 130, 246, 0.15); color: #93c5fd; }

	.export-group {
		display: flex;
		gap: 0.35rem;
		align-items: center;
		flex-shrink: 0;
	}

	.export-select {
		padding: 0.4rem 0.5rem;
		border-radius: 0.4rem;
		border: 1px solid rgba(148, 163, 184, 0.15);
		background: rgba(15, 23, 42, 0.8);
		color: #f1f5f9;
		font-size: 0.75rem;
	}

	.btn-export {
		padding: 0.4rem 0.75rem;
		border: 1px solid rgba(168, 85, 247, 0.3);
		border-radius: 0.4rem;
		background: rgba(168, 85, 247, 0.1);
		color: #c4b5fd;
		cursor: pointer;
		font-size: 0.75rem;
		transition: all 0.2s;
	}

	.btn-export:hover:not(:disabled) {
		background: rgba(168, 85, 247, 0.2);
		border-color: rgba(168, 85, 247, 0.5);
	}

	.btn-export:disabled { opacity: 0.5; cursor: not-allowed; }

	.stats-section { margin-bottom: 1rem; }

	.stats-grid {
		display: grid;
		grid-template-columns: repeat(4, 1fr);
		gap: 0.75rem;
	}

	.stat-card {
		text-align: center;
		padding: 0.75rem;
		background: rgba(15, 23, 42, 0.5);
		border-radius: 0.5rem;
		border: 1px solid rgba(148, 163, 184, 0.1);
	}

	.stat-value {
		font-size: 1.25rem;
		font-weight: 700;
	}

	.stat-label {
		font-size: 0.7rem;
		color: #94a3b8;
		margin-top: 0.25rem;
	}

	.result-tabs {
		display: flex;
		gap: 0.25rem;
		flex-wrap: wrap;
		margin-bottom: 1rem;
	}

	.result-tab {
		padding: 0.4rem 0.75rem;
		border: 1px solid rgba(148, 163, 184, 0.15);
		border-radius: 0.4rem;
		background: rgba(15, 23, 42, 0.6);
		color: #94a3b8;
		cursor: pointer;
		font-size: 0.75rem;
		transition: all 0.2s;
	}

	.result-tab.active {
		background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%);
		color: white;
		border-color: transparent;
		font-weight: 600;
	}

	.result-tab:hover:not(.active) {
		border-color: rgba(168, 85, 247, 0.3);
		color: #c4b5fd;
	}

	.detail-grid {
		display: grid;
		grid-template-columns: 1fr 1fr;
		gap: 0.75rem;
	}

	.detail-card {
		background: rgba(15, 23, 42, 0.5);
		border: 1px solid rgba(148, 163, 184, 0.1);
		border-radius: 0.5rem;
		padding: 0.75rem 1rem;
	}

	.subsection-title {
		font-size: 0.85rem;
		font-weight: 600;
		color: #f1f5f9;
		margin: 0 0 0.5rem;
	}

	.detail-rows { display: flex; flex-direction: column; gap: 0.3rem; }

	.detail-row {
		display: flex;
		justify-content: space-between;
		align-items: baseline;
		font-size: 0.8rem;
	}

	.detail-key { color: #94a3b8; }

	.detail-val { color: #e2e8f0; }
	.detail-val.mono { font-family: 'JetBrains Mono', monospace; color: #a855f7; font-size: 0.75rem; }
	.detail-val.mono-small { font-family: 'JetBrains Mono', monospace; font-size: 0.7rem; color: #c4b5fd; word-break: break-all; }

	.mini-stats {
		display: grid;
		grid-template-columns: repeat(4, 1fr);
		gap: 0.5rem;
	}

	.mini-stat { text-align: center; }

	.mini-val { display: block; font-size: 1.1rem; font-weight: 700; }

	.mini-label { font-size: 0.65rem; color: #94a3b8; }

	.tag-list { display: flex; flex-wrap: wrap; gap: 0.35rem; }

	.tag {
		padding: 0.2rem 0.5rem;
		border-radius: 0.25rem;
		font-size: 0.7rem;
		font-family: 'JetBrains Mono', monospace;
		background: rgba(148, 163, 184, 0.1);
		color: #cbd5e1;
		border: 1px solid rgba(148, 163, 184, 0.1);
	}

	.tag-danger { background: rgba(239, 68, 68, 0.15); color: #fca5a5; border-color: rgba(239, 68, 68, 0.2); }
	.tag-cyan { background: rgba(6, 182, 212, 0.15); color: #67e8f9; border-color: rgba(6, 182, 212, 0.2); }
	.tag-green { background: rgba(34, 197, 94, 0.15); color: #86efac; border-color: rgba(34, 197, 94, 0.2); }
	.tag-warning { background: rgba(234, 179, 8, 0.15); color: #fde047; border-color: rgba(234, 179, 8, 0.2); }
	.tag-success { background: rgba(34, 197, 94, 0.15); color: #86efac; border-color: rgba(34, 197, 94, 0.2); }
	.tag-info { background: rgba(59, 130, 246, 0.15); color: #93c5fd; border-color: rgba(59, 130, 246, 0.2); }

	.alert-danger { background: rgba(239, 68, 68, 0.08); border: 1px solid rgba(239, 68, 68, 0.2); }
	.alert-warning { background: rgba(234, 179, 8, 0.08); border: 1px solid rgba(234, 179, 8, 0.2); }
	.alert-success { background: rgba(34, 197, 94, 0.08); border: 1px solid rgba(34, 197, 94, 0.2); }
	.alert-info { background: rgba(59, 130, 246, 0.08); border: 1px solid rgba(59, 130, 246, 0.2); }

	.component-grid {
		display: grid;
		grid-template-columns: 1fr 1fr;
		gap: 0.75rem;
	}

	.comp-group { min-width: 0; }

	.comp-title {
		font-size: 0.75rem;
		font-weight: 600;
		color: #94a3b8;
		margin: 0 0 0.35rem;
	}

	.comp-list {
		max-height: 180px;
		overflow-y: auto;
		display: flex;
		flex-direction: column;
		gap: 0.15rem;
	}

	.comp-item {
		font-size: 0.7rem;
		font-family: 'JetBrains Mono', monospace;
		padding: 0.15rem 0.35rem;
		border-radius: 0.2rem;
	}

	.mono-blue { color: #93c5fd; }
	.mono-green { color: #86efac; }
	.mono-yellow { color: #fde047; }
	.mono-purple { color: #c4b5fd; }
	.mono-red { color: #fca5a5; }
	.mono-orange { color: #fdba74; }

	.debug-badge {
		font-size: 0.65rem;
		padding: 0.1rem 0.4rem;
		border-radius: 0.2rem;
		background: rgba(239, 68, 68, 0.2);
		color: #fca5a5;
		margin-left: 0.5rem;
	}

	.class-list {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
		max-height: 500px;
		overflow-y: auto;
	}

	.class-card {
		background: rgba(15, 23, 42, 0.6);
		border: 1px solid rgba(148, 163, 184, 0.1);
		border-radius: 0.4rem;
		padding: 0.6rem 0.75rem;
	}

	.class-header {
		display: flex;
		align-items: center;
		gap: 0.35rem;
		margin-bottom: 0.25rem;
	}

	.access-badge {
		font-size: 0.6rem;
		padding: 0.1rem 0.35rem;
		border-radius: 0.15rem;
		font-weight: 600;
	}

	.access-public { background: rgba(34, 197, 94, 0.2); color: #86efac; }
	.access-private { background: rgba(148, 163, 184, 0.15); color: #94a3b8; }
	.access-abstract { background: rgba(168, 85, 247, 0.2); color: #c4b5fd; }

	.class-name {
		font-family: 'JetBrains Mono', monospace;
		font-size: 0.8rem;
		color: #93c5fd;
	}

	.class-extends {
		font-size: 0.7rem;
		color: #94a3b8;
		margin-bottom: 0.25rem;
	}

	.extends-name { color: #86efac; }

	.methods-section { margin-top: 0.35rem; }

	.methods-label {
		font-size: 0.7rem;
		color: #94a3b8;
	}

	.methods-list {
		display: flex;
		flex-wrap: wrap;
		gap: 0.25rem;
		margin-top: 0.25rem;
	}

	.method-tag {
		font-size: 0.65rem;
		font-family: 'JetBrains Mono', monospace;
		padding: 0.1rem 0.35rem;
		border-radius: 0.15rem;
		background: rgba(15, 23, 42, 0.8);
		color: #cbd5e1;
	}

	.method-native { color: #fca5a5; }

	.method-more {
		font-size: 0.65rem;
		color: #94a3b8;
		padding: 0.1rem 0.35rem;
	}

	.findings-compact {
		display: flex;
		flex-direction: column;
		gap: 0.3rem;
	}

	.finding-compact {
		display: flex;
		align-items: baseline;
		gap: 0.35rem;
		font-size: 0.75rem;
	}

	.finding-dot {
		width: 6px;
		height: 6px;
		border-radius: 50%;
		flex-shrink: 0;
		margin-top: 2px;
	}

	.finding-cat { color: #e2e8f0; font-weight: 500; }
	.finding-sep { color: #64748b; }
	.finding-desc { color: #94a3b8; }

	.finding-more {
		font-size: 0.7rem;
		color: #94a3b8;
		text-align: center;
		padding: 0.25rem;
	}

	.finding-header {
		display: flex;
		align-items: center;
		gap: 0.4rem;
		margin-bottom: 0.35rem;
	}

	.finding-severity {
		font-size: 0.65rem;
		font-weight: 700;
		padding: 0.1rem 0.35rem;
		border-radius: 0.15rem;
	}

	.finding-desc {
		font-size: 0.8rem;
		color: #e2e8f0;
		margin: 0 0 0.25rem;
	}

	.finding-component {
		font-size: 0.7rem;
		color: #94a3b8;
		margin: 0 0 0.25rem;
	}

	.finding-recommendation {
		font-size: 0.75rem;
		color: #86efac;
		margin: 0;
	}

	.secret-header {
		display: flex;
		align-items: center;
		gap: 0.4rem;
		margin-bottom: 0.35rem;
	}

	.secret-type {
		font-weight: 600;
		font-size: 0.8rem;
		color: #e2e8f0;
	}

	.secret-severity {
		font-size: 0.65rem;
		font-weight: 700;
	}

	.secret-value {
		font-family: 'JetBrains Mono', monospace;
		font-size: 0.7rem;
		color: #cbd5e1;
		background: rgba(15, 23, 42, 0.8);
		padding: 0.35rem 0.5rem;
		border-radius: 0.3rem;
		margin-bottom: 0.25rem;
		word-break: break-all;
	}

	.secret-desc {
		font-size: 0.7rem;
		color: #94a3b8;
	}

	.strings-section { min-width: 0; }

	.strings-toolbar {
		display: flex;
		gap: 0.5rem;
		align-items: center;
		margin-bottom: 0.75rem;
	}

	.strings-count {
		font-size: 0.7rem;
		color: #94a3b8;
		flex-shrink: 0;
	}

	.scroll-list {
		max-height: 300px;
		overflow-y: auto;
		display: flex;
		flex-direction: column;
		gap: 0.15rem;
	}

	.list-item {
		font-size: 0.7rem;
		font-family: 'JetBrains Mono', monospace;
		color: #cbd5e1;
		padding: 0.15rem 0.35rem;
		border-radius: 0.15rem;
		transition: background 0.15s;
	}

	.list-item:hover { background: rgba(148, 163, 184, 0.1); }

	.empty-state {
		text-align: center;
		padding: 3rem 1.5rem;
	}

	.empty-icon { font-size: 3rem; margin-bottom: 0.75rem; }

	.empty-title {
		font-size: 1.1rem;
		color: #94a3b8;
		margin: 0 0 0.5rem;
	}

	.empty-desc {
		font-size: 0.8rem;
		color: #64748b;
	}

	.empty-text {
		font-size: 0.8rem;
		color: #64748b;
		margin: 0;
	}

	@media (max-width: 768px) {
		.content-grid { grid-template-columns: 1fr; }
		.detail-grid { grid-template-columns: 1fr; }
		.stats-grid { grid-template-columns: repeat(2, 1fr); }
		.mini-stats { grid-template-columns: repeat(2, 1fr); }
		.component-grid { grid-template-columns: 1fr; }
		.score-row { flex-direction: column; align-items: flex-start; }
	}
</style>
