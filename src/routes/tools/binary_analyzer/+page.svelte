<script lang="ts">
	import { tr } from '$lib/i18n';
	import ToolHistory from '$lib/components/ToolHistory.svelte';
	import ToolHelp from '$lib/components/ToolHelp.svelte';

	interface BinaryHeaders {
		magic: string;
		machine: string;
		class: string;
		os_abi: string;
		linker: string;
		build_id: string;
	}

	interface BinarySection {
		name: string;
		offset: number;
		size: number;
		virtual_address: string;
		permissions: string;
		entropy: number;
		suspicious: boolean;
		reason: string;
	}

	interface ImportEntry {
		library: string;
		function: string;
		risk_level: string;
		category: string;
		description: string;
	}

	interface ExportEntry {
		name: string;
		address: string;
		ordinal: number | null;
	}

	interface FoundString {
		value: string;
		offset: number;
		category: string;
		risk_level: string;
	}

	interface SymbolEntry {
		name: string;
		address: string;
		symbol_type: string;
		section: string;
	}

	interface SectionEntropy {
		section: string;
		entropy: number;
		suspicious: boolean;
	}

	interface EntropyAnalysis {
		overall_entropy: number;
		section_entropies: SectionEntropy[];
		is_packed: boolean;
		is_encrypted: boolean;
		analysis: string;
	}

	interface PackingDetection {
		is_packed: boolean;
		packer_name: string;
		confidence: number;
		indicators: string[];
	}

	interface AntiDebugTechnique {
		name: string;
		description: string;
		risk_level: string;
	}

	interface AntiDebugDetection {
		has_anti_debug: boolean;
		techniques: AntiDebugTechnique[];
	}

	interface SecurityFeatures {
		nx_enabled: boolean;
		pie_enabled: boolean;
		canary_enabled: boolean;
		relro: string;
		aslr: boolean;
		dep: boolean;
		code_signing: boolean;
		stack_protector: boolean;
		fortify_source: boolean;
	}

	interface BinaryVulnerability {
		severity: string;
		category: string;
		description: string;
		recommendation: string;
	}

	interface SecurityScore {
		score: number;
		level: string;
		critical_count: number;
		high_count: number;
		medium_count: number;
		low_count: number;
		total_findings: number;
	}

	interface BinaryAnalyzerResult {
		success: boolean;
		file_path: string;
		file_size: number;
		file_type: string;
		architecture: string;
		binary_type: string;
		endianness: string;
		entry_point: string;
		compiler: string;
		headers: BinaryHeaders;
		sections: BinarySection[];
		imports: ImportEntry[];
		exports: ExportEntry[];
		strings: FoundString[];
		symbols: SymbolEntry[];
		entropy_analysis: EntropyAnalysis;
		packing_detection: PackingDetection;
		anti_debug_detection: AntiDebugDetection;
		security_features: SecurityFeatures;
		vulnerabilities: BinaryVulnerability[];
		security_score: SecurityScore;
		summary: string;
	}

	interface DiscoveredBinary {
		file_path: string;
		file_name: string;
		file_size: number;
		file_type: string;
		architecture: string;
		binary_type: string;
		is_executable: boolean;
		risk_level: string;
	}

	interface DirectoryScanResult {
		directory: string;
		binaries: DiscoveredBinary[];
		total_count: number;
		scan_depth: number;
	}

	let filePath = $state('');
	let scanDir = $state('');
	let scanDepth = $state(3);
	let analyzeHeaders = $state(true);
	let analyzeSections = $state(true);
	let analyzeImports = $state(true);
	let analyzeExports = $state(true);
	let analyzeStrings = $state(true);
	let analyzeSymbols = $state(true);
	let analyzeEntropy = $state(true);
	let detectPacking = $state(true);
	let detectAntiDebug = $state(true);
	let result: BinaryAnalyzerResult | null = $state(null);
	let error = $state('');
	let processing = $state(false);
	let activeMainTab = $state('analyze');
	let activeResultTab = $state('overview');
	let exportFormat = $state('json');
	let exporting = $state(false);
	let scanning = $state(false);
	let scanResult: DirectoryScanResult | null = $state(null);
	let scanError = $state('');
	let selectedBinaries = $state<Set<string>>(new Set());
	let batchResults = $state<Map<string, BinaryAnalyzerResult>>(new Map());
	let batchProcessing = $state(false);
	let batchProgress = $state({ current: 0, total: 0 });

	let historyComponent: ToolHistory;

	let scoreColor = $derived(
		result
			? (result as BinaryAnalyzerResult).security_score.score >= 90
				? '#22c55e'
				: (result as BinaryAnalyzerResult).security_score.score >= 70
					? '#3b82f6'
					: (result as BinaryAnalyzerResult).security_score.score >= 50
						? '#f59e0b'
						: (result as BinaryAnalyzerResult).security_score.score >= 30
							? '#ef4444'
							: '#dc2626'
			: '#6b7280'
	);

	let scoreLevelText = $derived(
		result
			? $tr(`binaryAnalyzer.scoreLevels.${(result as BinaryAnalyzerResult).security_score.level.toLowerCase().replace(' ', '_').replace('risk', 'risk')}`)
			: ''
	);

	let highRiskCount = $derived(
		scanResult ? (scanResult as DirectoryScanResult).binaries.filter((b: DiscoveredBinary) => b.risk_level === 'high').length : 0
	);
	let mediumRiskCount = $derived(
		scanResult ? (scanResult as DirectoryScanResult).binaries.filter((b: DiscoveredBinary) => b.risk_level === 'medium').length : 0
	);
	let lowRiskCount = $derived(
		scanResult ? (scanResult as DirectoryScanResult).binaries.filter((b: DiscoveredBinary) => b.risk_level === 'low').length : 0
	);

	async function selectBinaryFile() {
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			const selected = await invoke<string | null>('select_binary_file');
			if (selected) {
				filePath = selected;
			}
		} catch {
			try {
				const { open } = await import('@tauri-apps/plugin-dialog');
				const selected = await open({
					multiple: false,
					filters: [
						{ name: 'Binary Files', extensions: ['exe', 'dll', 'so', 'dylib', 'bin', 'elf', 'o', 'ko', 'sys', 'apk', 'ipa', 'app', 'rom', 'fw', 'img'] },
						{ name: 'All Files', extensions: ['*'] }
					]
				});
				if (selected) {
					filePath = selected as string;
				}
			} catch {}
		}
	}

	async function selectScanDirectory() {
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			const selected = await invoke<string | null>('select_directory_for_scan');
			if (selected) {
				scanDir = selected;
			}
		} catch {
			try {
				const { open } = await import('@tauri-apps/plugin-dialog');
				const selected = await open({ directory: true });
				if (selected) {
					scanDir = selected as string;
				}
			} catch {}
		}
	}

	async function startDirectoryScan() {
		if (!scanDir.trim()) {
			scanError = $tr('binaryAnalyzer.error.emptyDir');
			return;
		}
		scanning = true;
		scanError = '';
		scanResult = null;
		selectedBinaries = new Set();
		batchResults = new Map();
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			scanResult = await invoke<DirectoryScanResult>('scan_directory_for_binaries', {
				directory: scanDir.trim(),
				maxDepth: scanDepth
			});
		} catch (e: any) {
			scanError = e.toString();
		} finally {
			scanning = false;
		}
	}

	function toggleBinarySelection(path: string) {
		const newSet = new Set(selectedBinaries);
		if (newSet.has(path)) {
			newSet.delete(path);
		} else {
			newSet.add(path);
		}
		selectedBinaries = newSet;
	}

	function selectAllBinaries() {
		if (!scanResult) return;
		selectedBinaries = new Set(scanResult.binaries.map((b) => b.file_path));
	}

	function deselectAllBinaries() {
		selectedBinaries = new Set();
	}

	function selectHighRisk() {
		if (!scanResult) return;
		selectedBinaries = new Set(scanResult.binaries.filter((b) => b.risk_level === 'high').map((b) => b.file_path));
	}

	function pickBinaryForAnalysis(bin: DiscoveredBinary) {
		filePath = bin.file_path;
		activeMainTab = 'analyze';
	}

	async function batchAnalyze() {
		if (selectedBinaries.size === 0) return;
		batchProcessing = true;
		batchResults = new Map();
		batchProgress = { current: 0, total: selectedBinaries.size };
		const { invoke } = await import('@tauri-apps/api/core');
		for (const binPath of selectedBinaries) {
			try {
				const res = await invoke<BinaryAnalyzerResult>('analyze_binary_command', {
					config: {
						file_path: binPath,
						analyze_headers: analyzeHeaders,
						analyze_sections: analyzeSections,
						analyze_imports: analyzeImports,
						analyze_exports: analyzeExports,
						analyze_strings: analyzeStrings,
						analyze_symbols: analyzeSymbols,
						analyze_entropy: analyzeEntropy,
						detect_packing: detectPacking,
						detect_anti_debug: detectAntiDebug
					}
				});
				batchResults = new Map(batchResults).set(binPath, res);
			} catch {
				batchResults = new Map(batchResults).set(binPath, null as any);
			}
			batchProgress = { current: batchProgress.current + 1, total: batchProgress.total };
		}
		batchProcessing = false;
	}

	async function startAnalysis() {
		if (!filePath.trim()) {
			error = $tr('binaryAnalyzer.error.emptyPath');
			return;
		}
		processing = true;
		error = '';
		result = null;
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			result = await invoke<BinaryAnalyzerResult>('analyze_binary_command', {
				config: {
					file_path: filePath.trim(),
					analyze_headers: analyzeHeaders,
					analyze_sections: analyzeSections,
					analyze_imports: analyzeImports,
					analyze_exports: analyzeExports,
					analyze_strings: analyzeStrings,
					analyze_symbols: analyzeSymbols,
					analyze_entropy: analyzeEntropy,
					detect_packing: detectPacking,
					detect_anti_debug: detectAntiDebug
				}
			});
			if (result && historyComponent) {
				await historyComponent.saveHistory(filePath.trim(), JSON.stringify(result), result.summary, 'completed');
			}
		} catch (e: any) {
			error = e.toString();
			if (historyComponent) {
				await historyComponent.saveHistory(filePath.trim(), JSON.stringify({ error: e.toString() }), undefined, 'failed');
			}
		} finally {
			processing = false;
		}
	}

	function clearAll() {
		filePath = '';
		result = null;
		error = '';
	}

	function getSeverityColor(severity: string): string {
		switch (severity) {
			case 'critical':
				return '#dc2626';
			case 'high':
				return '#ef4444';
			case 'medium':
				return '#f59e0b';
			case 'low':
				return '#3b82f6';
			default:
				return '#6b7280';
		}
	}

	function formatSize(bytes: number): string {
		if (bytes < 1024) return bytes + ' B';
		if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
		return (bytes / 1048576).toFixed(1) + ' MB';
	}

	async function exportResult() {
		if (!result) return;
		exporting = true;
		try {
			const { save } = await import('@tauri-apps/plugin-dialog');
			const { writeFile } = await import('@tauri-apps/plugin-fs');
			const path = await save({
				defaultPath: `binary-analysis-${Date.now()}.${exportFormat}`,
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

	function convertToCsv(data: BinaryAnalyzerResult): string {
		const rows = [['Category', 'Name', 'Risk Level', 'Description']];
		for (const v of data.vulnerabilities) {
			rows.push([v.category, '', v.severity, v.description]);
		}
		for (const i of data.imports) {
			rows.push(['Import', `${i.library}!${i.function}`, i.risk_level, i.description]);
		}
		for (const s of data.strings) {
			rows.push(['String', s.value, s.risk_level, s.category]);
		}
		return rows.map((r) => r.map((c) => `"${c}"`).join(',')).join('\n');
	}
</script>

<div class="nd-page">
	<div class="page-header">
		<div class="header-left">
			<a href="/" class="back-link">{$tr('common.backToHome')}</a>
			<h1 class="page-title">🔬 {$tr('binaryAnalyzer.title')}</h1>
			<p class="page-subtitle">{$tr('binaryAnalyzer.subtitle')}</p>
		</div>
	</div>

	<div class="tabs">
		<button class="tab-btn {activeMainTab === 'analyze' ? 'active' : ''}" onclick={() => (activeMainTab = 'analyze')}>
			<span class="tab-icon">🔬</span> {$tr('binaryAnalyzer.analyze')}
		</button>
		<button class="tab-btn {activeMainTab === 'discover' ? 'active' : ''}" onclick={() => (activeMainTab = 'discover')}>
			<span class="tab-icon">🔍</span> {$tr('binaryAnalyzer.discover')}
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
					<h2 class="section-title">{$tr('binaryAnalyzer.configTitle')}</h2>
					<p class="section-desc">{$tr('binaryAnalyzer.configDesc')}</p>

					<div class="form-group">
						<label class="form-label" for="ba-filepath">{$tr('binaryAnalyzer.filePath')}</label>
						<div class="input-with-btn">
							<input
								id="ba-filepath"
								type="text"
								bind:value={filePath}
								placeholder={$tr('binaryAnalyzer.filePathPlaceholder')}
								class="form-input"
								disabled={processing}
							/>
							<button class="btn-browse" onclick={selectBinaryFile} disabled={processing} title={$tr('binaryAnalyzer.selectFile')}>📁</button>
						</div>
					</div>

					<div class="form-group">
						<label class="form-label">{$tr('binaryAnalyzer.checkItems')}</label>
						<div class="check-grid">
							<label class="check-chip {analyzeHeaders ? 'active' : ''}">
								<input type="checkbox" bind:checked={analyzeHeaders} disabled={processing} />
								<span class="check-icon">📄</span>
								<span>{$tr('binaryAnalyzer.tabs.headers')}</span>
							</label>
							<label class="check-chip {analyzeSections ? 'active' : ''}">
								<input type="checkbox" bind:checked={analyzeSections} disabled={processing} />
								<span class="check-icon">📦</span>
								<span>{$tr('binaryAnalyzer.tabs.sections')}</span>
							</label>
							<label class="check-chip {analyzeImports ? 'active' : ''}">
								<input type="checkbox" bind:checked={analyzeImports} disabled={processing} />
								<span class="check-icon">📥</span>
								<span>{$tr('binaryAnalyzer.tabs.imports')}</span>
							</label>
							<label class="check-chip {analyzeExports ? 'active' : ''}">
								<input type="checkbox" bind:checked={analyzeExports} disabled={processing} />
								<span class="check-icon">📤</span>
								<span>{$tr('binaryAnalyzer.tabs.exports')}</span>
							</label>
							<label class="check-chip {analyzeStrings ? 'active' : ''}">
								<input type="checkbox" bind:checked={analyzeStrings} disabled={processing} />
								<span class="check-icon">📝</span>
								<span>{$tr('binaryAnalyzer.tabs.strings')}</span>
							</label>
							<label class="check-chip {analyzeSymbols ? 'active' : ''}">
								<input type="checkbox" bind:checked={analyzeSymbols} disabled={processing} />
								<span class="check-icon">🔣</span>
								<span>{$tr('binaryAnalyzer.tabs.symbols')}</span>
							</label>
							<label class="check-chip {analyzeEntropy ? 'active' : ''}">
								<input type="checkbox" bind:checked={analyzeEntropy} disabled={processing} />
								<span class="check-icon">📊</span>
								<span>{$tr('binaryAnalyzer.tabs.entropy')}</span>
							</label>
							<label class="check-chip {detectPacking ? 'active' : ''}">
								<input type="checkbox" bind:checked={detectPacking} disabled={processing} />
								<span class="check-icon">🔒</span>
								<span>{$tr('binaryAnalyzer.tabs.packing')}</span>
							</label>
							<label class="check-chip {detectAntiDebug ? 'active' : ''}">
								<input type="checkbox" bind:checked={detectAntiDebug} disabled={processing} />
								<span class="check-icon">🛡️</span>
								<span>{$tr('binaryAnalyzer.tabs.antiDebug')}</span>
							</label>
						</div>
					</div>

					<div class="button-group">
						<button class="btn-primary" onclick={startAnalysis} disabled={processing || !filePath.trim()}>
							{#if processing}
								<span class="spinner"></span> {$tr('binaryAnalyzer.analyzing')}
							{:else}
								🔬 {$tr('binaryAnalyzer.startAnalysis')}
							{/if}
						</button>
						<button class="btn-secondary" onclick={clearAll} disabled={processing}>
							🗑️ {$tr('common.reset')}
						</button>
					</div>
				</div>
			</div>

			<div class="result-section">
				{#if error}
					<div class="error-banner">
						<span class="error-icon">⚠️</span>
						<span>{error}</span>
					</div>
				{:else if result}
					<div class="section-card score-section">
						<div class="score-row">
							<div class="score-circle" style="border-color: {scoreColor}">
								<span class="score-number" style="color: {scoreColor}">{result.security_score.score}</span>
								<span class="score-max">/100</span>
							</div>
							<div class="score-details">
								<div class="score-level" style="color: {scoreColor}">{scoreLevelText}</div>
								<div class="score-stats">
									<span class="stat-item critical">🔴 {$tr('binaryAnalyzer.severity.critical')}: {result.security_score.critical_count}</span>
									<span class="stat-item high">🟠 {$tr('binaryAnalyzer.severity.high')}: {result.security_score.high_count}</span>
									<span class="stat-item medium">🟡 {$tr('binaryAnalyzer.severity.medium')}: {result.security_score.medium_count}</span>
									<span class="stat-item low">🔵 {$tr('binaryAnalyzer.severity.low')}: {result.security_score.low_count}</span>
								</div>
								<div class="score-total">{$tr('binaryAnalyzer.totalFindings')}: {result.security_score.total_findings}</div>
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

					<div class="section-card">
						<div class="result-tabs">
							<button class="result-tab {activeResultTab === 'overview' ? 'active' : ''}" onclick={() => (activeResultTab = 'overview')}>📊 {$tr('binaryAnalyzer.tabs.overview')}</button>
							<button class="result-tab {activeResultTab === 'sections' ? 'active' : ''}" onclick={() => (activeResultTab = 'sections')}>📦 {$tr('binaryAnalyzer.tabs.sections')} ({result.sections.length})</button>
							<button class="result-tab {activeResultTab === 'imports' ? 'active' : ''}" onclick={() => (activeResultTab = 'imports')}>📥 {$tr('binaryAnalyzer.tabs.imports')} ({result.imports.length})</button>
							<button class="result-tab {activeResultTab === 'exports' ? 'active' : ''}" onclick={() => (activeResultTab = 'exports')}>📤 {$tr('binaryAnalyzer.tabs.exports')} ({result.exports.length})</button>
							<button class="result-tab {activeResultTab === 'strings' ? 'active' : ''}" onclick={() => (activeResultTab = 'strings')}>📝 {$tr('binaryAnalyzer.tabs.strings')} ({result.strings.length})</button>
							<button class="result-tab {activeResultTab === 'security' ? 'active' : ''}" onclick={() => (activeResultTab = 'security')}>🛡️ {$tr('binaryAnalyzer.tabs.security')}</button>
							<button class="result-tab {activeResultTab === 'vulns' ? 'active' : ''}" onclick={() => (activeResultTab = 'vulns')}>⚠️ {$tr('binaryAnalyzer.tabs.vulns')} ({result.vulnerabilities.length})</button>
						</div>

						{#if activeResultTab === 'overview'}
							<div class="overview-grid">
								<div class="overview-stat">
									<span class="stat-label">{$tr('binaryAnalyzer.fileType')}</span>
									<span class="stat-value">{result.file_type}</span>
								</div>
								<div class="overview-stat">
									<span class="stat-label">{$tr('binaryAnalyzer.architecture')}</span>
									<span class="stat-value">{result.architecture}</span>
								</div>
								<div class="overview-stat">
									<span class="stat-label">{$tr('binaryAnalyzer.binaryType')}</span>
									<span class="stat-value">{result.binary_type}</span>
								</div>
								<div class="overview-stat">
									<span class="stat-label">{$tr('binaryAnalyzer.endianness')}</span>
									<span class="stat-value">{result.endianness}</span>
								</div>
								<div class="overview-stat">
									<span class="stat-label">{$tr('binaryAnalyzer.fileSize')}</span>
									<span class="stat-value">{formatSize(result.file_size)}</span>
								</div>
								<div class="overview-stat">
									<span class="stat-label">{$tr('binaryAnalyzer.entryPoint')}</span>
									<span class="stat-value mono">{result.entry_point}</span>
								</div>
								<div class="overview-stat">
									<span class="stat-label">{$tr('binaryAnalyzer.compiler')}</span>
									<span class="stat-value">{result.compiler}</span>
								</div>
								<div class="overview-stat">
									<span class="stat-label">{$tr('binaryAnalyzer.magic')}</span>
									<span class="stat-value mono-sm">{result.headers.magic}</span>
								</div>
							</div>

							<div class="overview-info-grid">
								<div class="info-row">
									<span class="info-label">{$tr('binaryAnalyzer.packingStatus')}</span>
									<span class="info-value" style="color: {result.packing_detection.is_packed ? '#ef4444' : '#22c55e'}">
										{result.packing_detection.is_packed ? '⚠️ ' + result.packing_detection.packer_name : '✅ ' + $tr('binaryAnalyzer.notDetected')}
									</span>
								</div>
								<div class="info-row">
									<span class="info-label">{$tr('binaryAnalyzer.antiDebugStatus')}</span>
									<span class="info-value" style="color: {result.anti_debug_detection.has_anti_debug ? '#f59e0b' : '#22c55e'}">
										{result.anti_debug_detection.has_anti_debug ? '⚠️ ' + $tr('binaryAnalyzer.detected') + ' (' + result.anti_debug_detection.techniques.length + ')' : '✅ ' + $tr('binaryAnalyzer.notDetected')}
									</span>
								</div>
								{#if result.headers.machine}
									<div class="info-row">
										<span class="info-label">Machine</span>
										<span class="info-value">{result.headers.machine}</span>
									</div>
								{/if}
								{#if result.headers.class}
									<div class="info-row">
										<span class="info-label">Class</span>
										<span class="info-value">{result.headers.class}</span>
									</div>
								{/if}
								{#if result.headers.os_abi}
									<div class="info-row">
										<span class="info-label">OS/ABI</span>
										<span class="info-value">{result.headers.os_abi}</span>
									</div>
								{/if}
								{#if result.headers.linker}
									<div class="info-row">
										<span class="info-label">Linker</span>
										<span class="info-value mono-sm">{result.headers.linker}</span>
									</div>
								{/if}
								{#if result.headers.build_id}
									<div class="info-row">
										<span class="info-label">Build ID</span>
										<span class="info-value mono-sm">{result.headers.build_id}</span>
									</div>
								{/if}
							</div>
						{:else if activeResultTab === 'sections'}
							<div class="sections-table">
								<div class="table-header">
									<span>{$tr('binaryAnalyzer.name')}</span>
									<span>{$tr('binaryAnalyzer.address')}</span>
									<span>{$tr('binaryAnalyzer.size')}</span>
									<span>{$tr('binaryAnalyzer.permissions')}</span>
									<span>{$tr('binaryAnalyzer.entropy')}</span>
									<span>{$tr('binaryAnalyzer.status')}</span>
								</div>
								{#each result.sections as section}
									<div class="table-row" class:suspicious={section.suspicious}>
										<span class="section-name">{section.name}</span>
										<span class="mono">{section.virtual_address}</span>
										<span>{formatSize(section.size)}</span>
										<span class="perms">{section.permissions}</span>
										<span class:entropy-high={section.entropy > 7.5}>{section.entropy.toFixed(2)}</span>
										<span>{#if section.suspicious}<span style="color: #ef4444" title={section.reason}>⚠️</span>{:else}✅{/if}</span>
									</div>
								{/each}
							</div>
						{:else if activeResultTab === 'imports'}
							<div class="imports-list">
								{#each result.imports as imp}
									<div class="import-card" style="border-left-color: {getSeverityColor(imp.risk_level)}">
										<div class="import-header">
											<span class="import-severity" style="background: {getSeverityColor(imp.risk_level)}">{imp.risk_level}</span>
											<code>{imp.library}</code> → <code>{imp.function}</code>
											<span class="import-category">{imp.category}</span>
										</div>
										<p class="import-desc">{imp.description}</p>
									</div>
								{/each}
								{#if result.imports.length === 0}
									<div class="empty-state"><p>{$tr('binaryAnalyzer.noResults')}</p></div>
								{/if}
							</div>
						{:else if activeResultTab === 'exports'}
							<div class="exports-list">
								{#each result.exports as exp}
									<div class="export-card">
										<code class="export-name">{exp.name}</code>
										<span class="export-addr mono">{exp.address}</span>
										{#if exp.ordinal}
											<span class="export-ordinal">ord: {exp.ordinal}</span>
										{/if}
									</div>
								{/each}
								{#if result.exports.length === 0}
									<div class="empty-state"><p>{$tr('binaryAnalyzer.noResults')}</p></div>
								{/if}
							</div>
						{:else if activeResultTab === 'strings'}
							<div class="strings-list">
								{#each result.strings as str}
									<div class="string-card" style="border-left-color: {getSeverityColor(str.risk_level)}">
										<span class="string-severity" style="background: {getSeverityColor(str.risk_level)}">{str.risk_level}</span>
										<span class="string-category">{str.category}</span>
										<code class="string-value">{str.value}</code>
										<span class="string-offset mono-sm">0x{str.offset.toString(16)}</span>
									</div>
								{/each}
								{#if result.strings.length === 0}
									<div class="empty-state"><p>{$tr('binaryAnalyzer.noResults')}</p></div>
								{/if}
							</div>
						{:else if activeResultTab === 'security'}
							<div class="security-grid">
								<div class="security-item {result.security_features.nx_enabled ? 'enabled' : 'disabled'}">
									<span class="security-name">NX/DEP</span>
									<span class="security-status">{result.security_features.nx_enabled ? '✅ ' + $tr('binaryAnalyzer.enabled') : '❌ ' + $tr('binaryAnalyzer.disabled')}</span>
								</div>
								<div class="security-item {result.security_features.pie_enabled ? 'enabled' : 'disabled'}">
									<span class="security-name">PIE</span>
									<span class="security-status">{result.security_features.pie_enabled ? '✅ ' + $tr('binaryAnalyzer.enabled') : '❌ ' + $tr('binaryAnalyzer.disabled')}</span>
								</div>
								<div class="security-item {result.security_features.canary_enabled ? 'enabled' : 'disabled'}">
									<span class="security-name">Stack Canary</span>
									<span class="security-status">{result.security_features.canary_enabled ? '✅ ' + $tr('binaryAnalyzer.enabled') : '❌ ' + $tr('binaryAnalyzer.disabled')}</span>
								</div>
								<div class="security-item {result.security_features.relro === 'Full' ? 'enabled' : result.security_features.relro === 'Partial' ? 'partial' : 'disabled'}">
									<span class="security-name">RELRO</span>
									<span class="security-status">{result.security_features.relro}</span>
								</div>
								<div class="security-item {result.security_features.aslr ? 'enabled' : 'disabled'}">
									<span class="security-name">ASLR</span>
									<span class="security-status">{result.security_features.aslr ? '✅ ' + $tr('binaryAnalyzer.enabled') : '❌ ' + $tr('binaryAnalyzer.disabled')}</span>
								</div>
								<div class="security-item {result.security_features.fortify_source ? 'enabled' : 'disabled'}">
									<span class="security-name">Fortify</span>
									<span class="security-status">{result.security_features.fortify_source ? '✅ ' + $tr('binaryAnalyzer.enabled') : '❌ ' + $tr('binaryAnalyzer.disabled')}</span>
								</div>
								<div class="security-item {result.security_features.code_signing ? 'enabled' : 'disabled'}">
									<span class="security-name">Code Signing</span>
									<span class="security-status">{result.security_features.code_signing ? '✅ ' + $tr('binaryAnalyzer.enabled') : '❌ ' + $tr('binaryAnalyzer.disabled')}</span>
								</div>
								<div class="security-item {result.security_features.dep ? 'enabled' : 'disabled'}">
									<span class="security-name">DEP</span>
									<span class="security-status">{result.security_features.dep ? '✅ ' + $tr('binaryAnalyzer.enabled') : '❌ ' + $tr('binaryAnalyzer.disabled')}</span>
								</div>
							</div>

							{#if result.entropy_analysis.overall_entropy > 0}
								<h3 class="subsection-title">📊 {$tr('binaryAnalyzer.tabs.entropy')}</h3>
								<div class="entropy-info">
									<div class="info-row">
										<span class="info-label">{$tr('binaryAnalyzer.overallEntropy')}</span>
										<span class="info-value">{result.entropy_analysis.overall_entropy.toFixed(3)}</span>
									</div>
									<div class="info-row">
										<span class="info-label">{$tr('binaryAnalyzer.analysis')}</span>
										<span class="info-value">{result.entropy_analysis.analysis}</span>
									</div>
								</div>
								{#if result.entropy_analysis.section_entropies.length > 0}
									<div class="entropy-bars">
										{#each result.entropy_analysis.section_entropies as se}
											<div class="entropy-bar-row">
												<span class="entropy-bar-label">{se.section}</span>
												<div class="entropy-bar-track">
													<div class="entropy-bar-fill {se.suspicious ? 'suspicious' : ''}" style="width: {(se.entropy / 8) * 100}%"></div>
												</div>
												<span class="entropy-bar-value" style="color: {se.suspicious ? '#ef4444' : '#94a3b8'}">{se.entropy.toFixed(2)}</span>
											</div>
										{/each}
									</div>
								{/if}
							{/if}

							{#if result.packing_detection.indicators.length > 0}
								<h3 class="subsection-title">🔒 {$tr('binaryAnalyzer.packingIndicators')}</h3>
								<div class="indicators-list">
									{#each result.packing_detection.indicators as indicator}
										<div class="indicator-item">⚠️ {indicator}</div>
									{/each}
								</div>
							{/if}

							{#if result.anti_debug_detection.has_anti_debug}
								<h3 class="subsection-title">🛡️ {$tr('binaryAnalyzer.antiDebugTechniques')}</h3>
								<div class="anti-debug-list">
									{#each result.anti_debug_detection.techniques as tech}
										<div class="anti-debug-card" style="border-left-color: {getSeverityColor(tech.risk_level)}">
											<div class="ad-header">
												<span class="ad-severity" style="background: {getSeverityColor(tech.risk_level)}">{tech.risk_level}</span>
												<span class="ad-name">{tech.name}</span>
											</div>
											<p class="ad-desc">{tech.description}</p>
										</div>
									{/each}
								</div>
							{/if}
						{:else if activeResultTab === 'vulns'}
							<div class="vulns-list">
								{#each result.vulnerabilities as vuln}
									<div class="vuln-card" style="border-left-color: {getSeverityColor(vuln.severity)}">
										<div class="vuln-header">
											<span class="vuln-severity" style="background: {getSeverityColor(vuln.severity)}">{vuln.severity}</span>
											<span class="vuln-category">{vuln.category}</span>
										</div>
										<p class="vuln-desc">{vuln.description}</p>
										<p class="vuln-rec">💡 {vuln.recommendation}</p>
									</div>
								{/each}
								{#if result.vulnerabilities.length === 0}
									<div class="empty-state"><p>✅ {$tr('binaryAnalyzer.noVulns')}</p></div>
								{/if}
							</div>
						{/if}
					</div>
				{:else}
					<div class="section-card">
						<div class="empty-state">
							<div class="empty-icon">🔬</div>
							<p>{$tr('binaryAnalyzer.emptyState')}</p>
						</div>
					</div>
				{/if}
			</div>
		</div>
	{:else if activeMainTab === 'discover'}
		<div class="content-grid">
			<div class="input-section">
				<div class="section-card">
					<h2 class="section-title">🔍 {$tr('binaryAnalyzer.scanConfig')}</h2>
					<p class="section-desc">{$tr('binaryAnalyzer.scanConfigDesc')}</p>

					<div class="form-group">
						<label class="form-label" for="ba-scandir">{$tr('binaryAnalyzer.scanDirectory')}</label>
						<div class="input-with-btn">
							<input
								id="ba-scandir"
								type="text"
								bind:value={scanDir}
								placeholder={$tr('binaryAnalyzer.scanDirPlaceholder')}
								class="form-input"
								disabled={scanning}
							/>
							<button class="btn-browse" onclick={selectScanDirectory} disabled={scanning} title={$tr('binaryAnalyzer.selectDir')}>📂</button>
						</div>
					</div>

					<div class="form-group">
						<label class="form-label">{$tr('binaryAnalyzer.scanDepth')}</label>
						<div class="depth-control">
							<input type="range" min="1" max="10" bind:value={scanDepth} disabled={scanning} class="depth-slider" />
							<span class="depth-value">{scanDepth}</span>
						</div>
						<p class="form-hint">{$tr('binaryAnalyzer.scanDepthHint')}</p>
					</div>

					<button class="btn-primary" onclick={startDirectoryScan} disabled={scanning || !scanDir.trim()} style="width: 100%">
						{#if scanning}
							<span class="spinner"></span> {$tr('binaryAnalyzer.scanning')}
						{:else}
							🔍 {$tr('binaryAnalyzer.startScan')}
						{/if}
					</button>
				</div>
			</div>

			<div class="result-section">
				{#if scanError}
					<div class="error-banner">
						<span class="error-icon">⚠️</span>
						<span>{scanError}</span>
					</div>
				{:else if scanResult}
					<div class="section-card scan-summary">
						<div class="scan-stats-row">
							<div class="scan-stat">
								<span class="scan-stat-number">{scanResult.total_count}</span>
								<span class="scan-stat-label">{$tr('binaryAnalyzer.foundBinaries')}</span>
							</div>
							<div class="scan-stat high-risk">
								<span class="scan-stat-number">{highRiskCount}</span>
								<span class="scan-stat-label">🔴 {$tr('binaryAnalyzer.severity.high')}</span>
							</div>
							<div class="scan-stat medium-risk">
								<span class="scan-stat-number">{mediumRiskCount}</span>
								<span class="scan-stat-label">🟡 {$tr('binaryAnalyzer.severity.medium')}</span>
							</div>
							<div class="scan-stat low-risk">
								<span class="scan-stat-number">{lowRiskCount}</span>
								<span class="scan-stat-label">🔵 {$tr('binaryAnalyzer.severity.low')}</span>
							</div>
						</div>
						{#if selectedBinaries.size > 0}
							<div class="batch-actions">
								<span class="selected-count">✅ {$tr('binaryAnalyzer.selected')}: {selectedBinaries.size}/{scanResult.total_count}</span>
								<button class="btn-primary btn-sm" onclick={batchAnalyze} disabled={batchProcessing}>
									{#if batchProcessing}
										<span class="spinner-sm"></span> {batchProgress.current}/{batchProgress.total}
									{:else}
										🔬 {$tr('binaryAnalyzer.batchAnalyze')}
									{/if}
								</button>
							</div>
						{/if}
					</div>

					<div class="section-card">
						<div class="discovery-toolbar">
							<button class="toolbar-btn" onclick={selectAllBinaries}>☑️ {$tr('binaryAnalyzer.selectAll')}</button>
							<button class="toolbar-btn" onclick={selectHighRisk}>🔴 {$tr('binaryAnalyzer.selectHighRisk')}</button>
							<button class="toolbar-btn" onclick={deselectAllBinaries}>☐ {$tr('binaryAnalyzer.deselectAll')}</button>
						</div>

						<div class="discovery-list">
							{#each scanResult.binaries as bin (bin.file_path)}
								<div class="discovery-card" class:selected={selectedBinaries.has(bin.file_path)}>
									<div class="discovery-check">
										<input
											type="checkbox"
											checked={selectedBinaries.has(bin.file_path)}
											onchange={() => toggleBinarySelection(bin.file_path)}
											disabled={batchProcessing}
										/>
									</div>
									<div class="discovery-info">
										<div class="discovery-header">
											<span class="discovery-name">{bin.file_name}</span>
											<span class="discovery-badge" style="background: {getSeverityColor(bin.risk_level)}">{bin.risk_level}</span>
											<span class="discovery-type-badge">{bin.file_type}</span>
											{#if bin.is_executable}
												<span class="discovery-exec">⚡</span>
											{/if}
										</div>
										<div class="discovery-meta">
											<span class="discovery-path" title={bin.file_path}>{bin.file_path}</span>
											<span class="discovery-size">{formatSize(bin.file_size)}</span>
											<span class="discovery-arch">{bin.architecture}</span>
										</div>
									</div>
									<div class="discovery-actions">
										<button class="btn-analyze-one" onclick={() => pickBinaryForAnalysis(bin)} disabled={processing}>
											🔬
										</button>
										{#if batchResults.has(bin.file_path)}
											<span class="batch-score" style="color: {(batchResults.get(bin.file_path)?.security_score?.score ?? 0) >= 70 ? '#22c55e' : '#ef4444'}">
												{batchResults.get(bin.file_path)?.security_score?.score ?? '?'}
											</span>
										{/if}
									</div>
								</div>
							{/each}
						</div>
					</div>
				{:else}
					<div class="section-card">
						<div class="empty-state">
							<div class="empty-icon">🔍</div>
							<p>{$tr('binaryAnalyzer.scanEmpty')}</p>
						</div>
					</div>
				{/if}
			</div>
		</div>
	{:else if activeMainTab === 'history'}
		<div class="section-card">
			<ToolHistory toolType="binary_analyzer" toolName={$tr('binaryAnalyzer.title')} bind:this={historyComponent} />
		</div>
	{:else if activeMainTab === 'help'}
		<div class="section-card">
			<ToolHelp toolType="binary_analyzer" />
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

	.back-link:hover {
		color: #a855f7;
	}

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

	.tab-btn:hover:not(.active) {
		background: rgba(168, 85, 247, 0.1);
		color: #c4b5fd;
	}

	.tab-icon {
		font-size: 0.9rem;
	}

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

	.form-group {
		margin-bottom: 0.75rem;
	}

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

	.form-input::placeholder {
		color: #475569;
	}

	.check-grid {
		display: grid;
		grid-template-columns: 1fr 1fr 1fr;
		gap: 0.35rem;
		margin-bottom: 0.75rem;
	}

	.check-chip {
		display: flex;
		align-items: center;
		gap: 0.3rem;
		padding: 0.35rem 0.5rem;
		border: 1px solid rgba(148, 163, 184, 0.15);
		border-radius: 0.4rem;
		background: rgba(15, 23, 42, 0.6);
		cursor: pointer;
		font-size: 0.75rem;
		color: #94a3b8;
		transition: all 0.2s;
	}

	.check-chip.active {
		border-color: rgba(168, 85, 247, 0.4);
		background: rgba(168, 85, 247, 0.1);
		color: #c4b5fd;
	}

	.check-chip input[type='checkbox'] {
		accent-color: #a855f7;
		width: 0.8rem;
		height: 0.8rem;
	}

	.check-icon {
		font-size: 0.8rem;
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
		background: rgba(148, 163, 184, 0.1);
		color: #94a3b8;
		padding: 0.65rem 1rem;
		border: 1px solid rgba(148, 163, 184, 0.15);
		border-radius: 0.5rem;
		cursor: pointer;
		transition: all 0.2s;
		font-size: 0.9rem;
	}

	.btn-secondary:hover:not(:disabled) {
		background: rgba(148, 163, 184, 0.2);
		color: #e2e8f0;
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

	@keyframes spin {
		to {
			transform: rotate(360deg);
		}
	}

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

	.error-icon {
		font-size: 1.25rem;
	}

	.score-section {
		margin-bottom: 1rem;
	}

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

	.score-max {
		font-size: 0.7rem;
		color: #94a3b8;
	}

	.score-details {
		flex: 1;
	}

	.score-level {
		font-size: 1rem;
		font-weight: 600;
		margin-bottom: 0.4rem;
	}

	.score-stats {
		display: flex;
		gap: 0.75rem;
		flex-wrap: wrap;
	}

	.stat-item {
		font-size: 0.75rem;
	}

	.stat-item.critical {
		color: #dc2626;
	}

	.stat-item.high {
		color: #ef4444;
	}

	.stat-item.medium {
		color: #f59e0b;
	}

	.stat-item.low {
		color: #3b82f6;
	}

	.score-total {
		font-size: 0.8rem;
		color: #94a3b8;
		margin-top: 0.3rem;
	}

	.export-group {
		display: flex;
		gap: 0.35rem;
		align-items: center;
	}

	.export-select {
		padding: 0.35rem 0.5rem;
		border-radius: 0.4rem;
		border: 1px solid rgba(148, 163, 184, 0.15);
		background: rgba(15, 23, 42, 0.6);
		color: #f1f5f9;
		font-size: 0.8rem;
	}

	.btn-export {
		padding: 0.35rem 0.75rem;
		border-radius: 0.4rem;
		border: 1px solid rgba(168, 85, 247, 0.3);
		background: rgba(168, 85, 247, 0.1);
		color: #c4b5fd;
		cursor: pointer;
		font-size: 0.8rem;
		transition: all 0.2s;
	}

	.btn-export:hover:not(:disabled) {
		background: rgba(168, 85, 247, 0.2);
	}

	.btn-export:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

	.result-tabs {
		display: flex;
		gap: 0.25rem;
		margin-bottom: 1rem;
		flex-wrap: wrap;
	}

	.result-tab {
		padding: 0.4rem 0.75rem;
		border-radius: 0.4rem;
		border: 1px solid rgba(148, 163, 184, 0.15);
		background: rgba(15, 23, 42, 0.4);
		color: #94a3b8;
		cursor: pointer;
		font-size: 0.8rem;
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

	.overview-grid {
		display: grid;
		grid-template-columns: repeat(4, 1fr);
		gap: 0.75rem;
		margin-bottom: 1rem;
	}

	.overview-stat {
		display: flex;
		flex-direction: column;
		align-items: center;
		padding: 0.75rem;
		background: rgba(15, 23, 42, 0.4);
		border: 1px solid rgba(148, 163, 184, 0.08);
		border-radius: 0.5rem;
	}

	.stat-label {
		font-size: 0.7rem;
		color: #94a3b8;
		margin-bottom: 0.25rem;
	}

	.stat-value {
		font-size: 1rem;
		font-weight: 700;
		color: #f1f5f9;
		text-align: center;
		word-break: break-all;
	}

	.overview-info-grid {
		display: flex;
		flex-direction: column;
		gap: 0.35rem;
	}

	.info-row {
		display: flex;
		gap: 0.5rem;
		padding: 0.5rem 0.75rem;
		background: rgba(15, 23, 42, 0.4);
		border-radius: 0.4rem;
		font-size: 0.85rem;
	}

	.info-label {
		font-weight: 600;
		min-width: 100px;
		color: #94a3b8;
		font-size: 0.8rem;
	}

	.info-value {
		color: #f1f5f9;
	}

	.mono {
		font-family: 'SF Mono', 'Fira Code', monospace;
		font-size: 0.8rem;
	}

	.mono-sm {
		font-family: 'SF Mono', 'Fira Code', monospace;
		font-size: 0.72rem;
	}

	.sections-table {
		display: flex;
		flex-direction: column;
		gap: 0.25rem;
	}

	.table-header {
		display: grid;
		grid-template-columns: 1.2fr 1.2fr 0.8fr 0.7fr 0.6fr 0.5fr;
		gap: 0.5rem;
		padding: 0.5rem 0.75rem;
		font-weight: 600;
		font-size: 0.75rem;
		color: #94a3b8;
		background: rgba(15, 23, 42, 0.4);
		border-radius: 0.4rem;
	}

	.table-row {
		display: grid;
		grid-template-columns: 1.2fr 1.2fr 0.8fr 0.7fr 0.6fr 0.5fr;
		gap: 0.5rem;
		padding: 0.5rem 0.75rem;
		background: rgba(15, 23, 42, 0.3);
		border-radius: 0.4rem;
		font-size: 0.82rem;
		color: #cbd5e1;
	}

	.table-row.suspicious {
		border-left: 3px solid #ef4444;
	}

	.section-name {
		font-weight: 600;
		color: #f1f5f9;
	}

	.perms {
		font-family: 'SF Mono', 'Fira Code', monospace;
	}

	.entropy-high {
		color: #ef4444;
		font-weight: 600;
	}

	.imports-list,
	.exports-list,
	.strings-list,
	.vulns-list,
	.anti-debug-list,
	.indicators-list {
		display: flex;
		flex-direction: column;
		gap: 0.35rem;
	}

	.import-card,
	.anti-debug-card {
		padding: 0.5rem 0.75rem;
		background: rgba(15, 23, 42, 0.3);
		border-radius: 0.4rem;
		border-left: 3px solid;
	}

	.import-header,
	.ad-header {
		display: flex;
		align-items: center;
		gap: 0.4rem;
		font-size: 0.82rem;
		flex-wrap: wrap;
	}

	.import-severity,
	.ad-severity,
	.vuln-severity,
	.string-severity {
		padding: 0.1rem 0.4rem;
		border-radius: 0.25rem;
		color: white;
		font-size: 0.65rem;
		font-weight: 600;
		text-transform: uppercase;
	}

	.import-category,
	.vuln-category,
	.string-category {
		padding: 0.1rem 0.4rem;
		background: rgba(168, 85, 247, 0.15);
		border-radius: 0.25rem;
		font-size: 0.7rem;
		color: #c4b5fd;
	}

	.import-desc,
	.ad-desc {
		font-size: 0.78rem;
		color: #94a3b8;
		margin: 0.25rem 0 0;
	}

	.export-card {
		display: flex;
		align-items: center;
		gap: 0.75rem;
		padding: 0.4rem 0.75rem;
		background: rgba(15, 23, 42, 0.3);
		border-radius: 0.4rem;
		font-size: 0.82rem;
	}

	.export-name {
		color: #c4b5fd;
		font-weight: 600;
	}

	.export-addr {
		color: #94a3b8;
	}

	.export-ordinal {
		font-size: 0.7rem;
		color: #64748b;
	}

	.string-card {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		padding: 0.4rem 0.75rem;
		background: rgba(15, 23, 42, 0.3);
		border-radius: 0.4rem;
		border-left: 3px solid;
		font-size: 0.82rem;
	}

	.string-value {
		flex: 1;
		color: #cbd5e1;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.string-offset {
		color: #64748b;
	}

	.security-grid {
		display: grid;
		grid-template-columns: repeat(2, 1fr);
		gap: 0.5rem;
		margin-bottom: 1rem;
	}

	.security-item {
		display: flex;
		justify-content: space-between;
		align-items: center;
		padding: 0.6rem 0.75rem;
		border-radius: 0.4rem;
		border: 1px solid rgba(148, 163, 184, 0.08);
	}

	.security-item.enabled {
		background: rgba(34, 197, 94, 0.05);
		border-color: rgba(34, 197, 94, 0.15);
	}

	.security-item.disabled {
		background: rgba(239, 68, 68, 0.05);
		border-color: rgba(239, 68, 68, 0.15);
	}

	.security-item.partial {
		background: rgba(245, 158, 11, 0.05);
		border-color: rgba(245, 158, 11, 0.15);
	}

	.security-name {
		font-weight: 600;
		font-size: 0.85rem;
		color: #f1f5f9;
	}

	.security-status {
		font-size: 0.82rem;
	}

	.subsection-title {
		font-size: 0.9rem;
		font-weight: 600;
		color: #e2e8f0;
		margin: 1rem 0 0.5rem;
	}

	.entropy-info {
		display: flex;
		flex-direction: column;
		gap: 0.35rem;
		margin-bottom: 1rem;
	}

	.entropy-bars {
		display: flex;
		flex-direction: column;
		gap: 0.4rem;
	}

	.entropy-bar-row {
		display: flex;
		align-items: center;
		gap: 0.5rem;
	}

	.entropy-bar-label {
		width: 80px;
		font-size: 0.75rem;
		color: #94a3b8;
		text-align: right;
	}

	.entropy-bar-track {
		flex: 1;
		height: 8px;
		background: rgba(15, 23, 42, 0.6);
		border-radius: 4px;
		overflow: hidden;
	}

	.entropy-bar-fill {
		height: 100%;
		background: linear-gradient(90deg, #3b82f6, #a855f7);
		border-radius: 4px;
		transition: width 0.3s;
	}

	.entropy-bar-fill.suspicious {
		background: linear-gradient(90deg, #f59e0b, #ef4444);
	}

	.entropy-bar-value {
		width: 40px;
		font-size: 0.75rem;
		text-align: right;
		font-family: 'SF Mono', 'Fira Code', monospace;
	}

	.indicator-item {
		padding: 0.35rem 0.6rem;
		background: rgba(245, 158, 11, 0.08);
		border-radius: 0.3rem;
		font-size: 0.8rem;
		color: #fbbf24;
	}

	.vuln-card {
		padding: 0.6rem 0.75rem;
		background: rgba(15, 23, 42, 0.3);
		border-radius: 0.4rem;
		border-left: 3px solid;
	}

	.vuln-header {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		margin-bottom: 0.3rem;
	}

	.vuln-desc {
		font-size: 0.82rem;
		color: #cbd5e1;
		margin: 0 0 0.25rem;
	}

	.vuln-rec {
		font-size: 0.78rem;
		color: #94a3b8;
		margin: 0;
	}

	.empty-state {
		text-align: center;
		padding: 2rem;
		color: #64748b;
	}

	.empty-icon {
		font-size: 2.5rem;
		margin-bottom: 0.75rem;
	}

	@media (max-width: 900px) {
		.content-grid {
			grid-template-columns: 1fr;
		}

		.overview-grid {
			grid-template-columns: repeat(2, 1fr);
		}

		.check-grid {
			grid-template-columns: 1fr 1fr;
		}

		.score-row {
			flex-wrap: wrap;
		}

		.table-header,
		.table-row {
			grid-template-columns: 1fr 1fr 0.6fr 0.5fr 0.5fr 0.4fr;
			font-size: 0.72rem;
		}

		.scan-stats-row {
			flex-wrap: wrap;
		}

		.scan-stat {
			min-width: calc(50% - 0.5rem);
		}

		.discovery-card {
			flex-wrap: wrap;
		}
	}

	.input-with-btn {
		display: flex;
		gap: 0.5rem;
	}

	.input-with-btn .form-input {
		flex: 1;
	}

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

	.btn-browse:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

	.form-hint {
		font-size: 0.7rem;
		color: #64748b;
		margin: 0.25rem 0 0;
	}

	.depth-control {
		display: flex;
		align-items: center;
		gap: 0.75rem;
	}

	.depth-slider {
		flex: 1;
		accent-color: #a855f7;
		height: 4px;
	}

	.depth-value {
		font-size: 0.9rem;
		font-weight: 600;
		color: #c4b5fd;
		min-width: 1.5rem;
		text-align: center;
	}

	.scan-summary {
		margin-bottom: 1rem;
	}

	.scan-stats-row {
		display: flex;
		gap: 1rem;
		margin-bottom: 0.75rem;
	}

	.scan-stat {
		display: flex;
		flex-direction: column;
		align-items: center;
		padding: 0.5rem 1rem;
		background: rgba(15, 23, 42, 0.4);
		border-radius: 0.5rem;
		flex: 1;
	}

	.scan-stat-number {
		font-size: 1.5rem;
		font-weight: 700;
		color: #f1f5f9;
	}

	.scan-stat-label {
		font-size: 0.7rem;
		color: #94a3b8;
	}

	.scan-stat.high-risk .scan-stat-number { color: #ef4444; }
	.scan-stat.medium-risk .scan-stat-number { color: #f59e0b; }
	.scan-stat.low-risk .scan-stat-number { color: #3b82f6; }

	.batch-actions {
		display: flex;
		align-items: center;
		justify-content: space-between;
		padding: 0.5rem 0.75rem;
		background: rgba(168, 85, 247, 0.08);
		border-radius: 0.4rem;
	}

	.selected-count {
		font-size: 0.82rem;
		color: #c4b5fd;
	}

	.btn-sm {
		padding: 0.4rem 0.75rem;
		font-size: 0.8rem;
		flex: none;
	}

	.spinner-sm {
		display: inline-block;
		width: 0.75rem;
		height: 0.75rem;
		border: 2px solid rgba(255, 255, 255, 0.3);
		border-top-color: white;
		border-radius: 50%;
		animation: spin 0.6s linear infinite;
	}

	.discovery-toolbar {
		display: flex;
		gap: 0.5rem;
		margin-bottom: 0.75rem;
		flex-wrap: wrap;
	}

	.toolbar-btn {
		padding: 0.35rem 0.65rem;
		border-radius: 0.4rem;
		border: 1px solid rgba(148, 163, 184, 0.15);
		background: rgba(15, 23, 42, 0.4);
		color: #94a3b8;
		cursor: pointer;
		font-size: 0.78rem;
		transition: all 0.2s;
	}

	.toolbar-btn:hover {
		border-color: rgba(168, 85, 247, 0.3);
		color: #c4b5fd;
		background: rgba(168, 85, 247, 0.08);
	}

	.discovery-list {
		display: flex;
		flex-direction: column;
		gap: 0.35rem;
		max-height: 500px;
		overflow-y: auto;
	}

	.discovery-card {
		display: flex;
		align-items: center;
		gap: 0.6rem;
		padding: 0.5rem 0.75rem;
		background: rgba(15, 23, 42, 0.3);
		border-radius: 0.4rem;
		border: 1px solid rgba(148, 163, 184, 0.08);
		transition: all 0.2s;
	}

	.discovery-card.selected {
		border-color: rgba(168, 85, 247, 0.3);
		background: rgba(168, 85, 247, 0.05);
	}

	.discovery-card:hover {
		border-color: rgba(168, 85, 247, 0.2);
	}

	.discovery-check {
		flex-shrink: 0;
	}

	.discovery-check input[type='checkbox'] {
		accent-color: #a855f7;
		width: 0.9rem;
		height: 0.9rem;
	}

	.discovery-info {
		flex: 1;
		min-width: 0;
	}

	.discovery-header {
		display: flex;
		align-items: center;
		gap: 0.4rem;
		flex-wrap: wrap;
	}

	.discovery-name {
		font-weight: 600;
		font-size: 0.85rem;
		color: #f1f5f9;
	}

	.discovery-badge {
		padding: 0.1rem 0.4rem;
		border-radius: 0.25rem;
		color: white;
		font-size: 0.6rem;
		font-weight: 600;
		text-transform: uppercase;
	}

	.discovery-type-badge {
		padding: 0.1rem 0.35rem;
		background: rgba(99, 102, 241, 0.15);
		border-radius: 0.25rem;
		font-size: 0.65rem;
		color: #a5b4fc;
	}

	.discovery-exec {
		font-size: 0.75rem;
	}

	.discovery-meta {
		display: flex;
		gap: 0.75rem;
		margin-top: 0.2rem;
		font-size: 0.72rem;
		color: #64748b;
	}

	.discovery-path {
		flex: 1;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.discovery-size {
		flex-shrink: 0;
	}

	.discovery-arch {
		flex-shrink: 0;
	}

	.discovery-actions {
		display: flex;
		align-items: center;
		gap: 0.4rem;
		flex-shrink: 0;
	}

	.btn-analyze-one {
		padding: 0.3rem 0.5rem;
		border-radius: 0.35rem;
		border: 1px solid rgba(168, 85, 247, 0.2);
		background: rgba(168, 85, 247, 0.08);
		cursor: pointer;
		font-size: 0.85rem;
		transition: all 0.2s;
	}

	.btn-analyze-one:hover:not(:disabled) {
		background: rgba(168, 85, 247, 0.2);
		border-color: rgba(168, 85, 247, 0.4);
	}

	.btn-analyze-one:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

	.batch-score {
		font-size: 0.85rem;
		font-weight: 700;
		font-family: 'SF Mono', 'Fira Code', monospace;
	}
</style>
