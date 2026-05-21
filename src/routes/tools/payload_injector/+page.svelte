<script lang="ts">
	import { tr } from '$lib/i18n';
	import ToolHistory from '$lib/components/ToolHistory.svelte';
	import ToolHelp from '$lib/components/ToolHelp.svelte';

	interface PayloadTemplate {
		name: string;
		payload_type: string;
		platform: string;
		architecture: string;
		language: string;
		size_bytes: number;
		description: string;
		detection_rate: number;
		code: string;
		mitre_id: string;
	}

	interface InjectionResult {
		original_size: number;
		injected_size: number;
		injection_offset: number;
		method: string;
		success: boolean;
		integrity_preserved: boolean;
		file_type: string;
	}

	interface EncodingResult {
		encoding_type: string;
		original_size: number;
		encoded_size: number;
		encoded_payload: string;
		decoder_stub: string;
	}

	interface DetectionEvasion {
		technique: string;
		description: string;
		effectiveness: string;
		mitre_id: string;
	}

	interface PayloadInjectorResult {
		success: boolean;
		target_file: string;
		payload_type: string;
		injection_method: string;
		payload_templates: PayloadTemplate[];
		injection_result: InjectionResult;
		encoding_result: EncodingResult | null;
		obfuscation_applied: boolean;
		anti_debug_applied: boolean;
		persistence_applied: boolean;
		detection_evasion: DetectionEvasion[];
		warnings: string[];
		summary: string;
	}

	let targetFile = $state('');
	let payloadType = $state('reverse_shell');
	let injectionMethod = $state('append');
	let encodePayload = $state(true);
	let obfuscate = $state(false);
	let antiDebug = $state(false);
	let persistence = $state(false);
	let customPayload = $state('');
	let listenerHost = $state('');
	let listenerPort = $state(4444);
	let result: PayloadInjectorResult | null = $state(null);
	let error = $state('');
	let processing = $state(false);
	let activeMainTab = $state('analyze');
	let activeResultTab = $state('payloads');
	let exportFormat = $state('json');
	let exporting = $state(false);
	let historyComponent: ToolHistory = $state(null!);

	let avgDetectionRate = $derived.by(() => {
		if (!result || result.payload_templates.length === 0) return 0;
		const total = result.payload_templates.reduce((sum, t) => sum + t.detection_rate, 0);
		return total / result.payload_templates.length;
	});

	let detectionColor = $derived.by(() => {
		const r = avgDetectionRate;
		if (r >= 0.8) return '#dc2626';
		if (r >= 0.6) return '#ef4444';
		if (r >= 0.4) return '#f59e0b';
		return '#22c55e';
	});

	let detectionLevel = $derived.by(() => {
		const r = avgDetectionRate;
		if (r >= 0.8) return $tr('payloadInjector.detectionLevels.high');
		if (r >= 0.6) return $tr('payloadInjector.detectionLevels.medium');
		if (r >= 0.4) return $tr('payloadInjector.detectionLevels.low');
		return $tr('payloadInjector.detectionLevels.minimal');
	});

	async function inject() {
		if (!targetFile.trim()) {
			error = $tr('payloadInjector.error.emptyTarget');
			return;
		}
		processing = true;
		error = '';
		result = null;
		activeResultTab = 'payloads';
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			result = await invoke<PayloadInjectorResult>('inject_payload_command', {
				config: {
					target_file: targetFile.trim(),
					payload_type: payloadType,
					injection_method: injectionMethod,
					encode_payload: encodePayload,
					obfuscate,
					anti_debug: antiDebug,
					persistence,
					custom_payload: customPayload.trim() || null,
					listener_host: listenerHost.trim() || null,
					listener_port: listenerPort || null,
					timeout: 30
				}
			});
			if (result && historyComponent) {
				await historyComponent.saveHistory(targetFile.trim(), JSON.stringify(result), result.summary, 'completed');
			}
		} catch (e: any) {
			error = e.toString();
			if (historyComponent) {
				await historyComponent.saveHistory(targetFile.trim(), JSON.stringify({ error: e.toString() }), undefined, 'failed');
			}
		} finally {
			processing = false;
		}
	}

	function clearAll() {
		targetFile = '';
		result = null;
		error = '';
		activeResultTab = 'payloads';
	}

	function getEffectivenessColor(e: string): string {
		switch (e.toLowerCase()) {
			case 'critical': return '#dc2626';
			case 'high': return '#ef4444';
			case 'medium': return '#f59e0b';
			case 'low': return '#3b82f6';
			default: return '#6b7280';
		}
	}

	function getEffectivenessLabel(e: string): string {
		return $tr(`payloadInjector.effectiveness.${e.toLowerCase()}`) || e;
	}

	async function exportResult() {
		if (!result) return;
		exporting = true;
		try {
			const { open } = await import('@tauri-apps/plugin-dialog');
			const savePath = await open({ directory: true, multiple: false });
			if (!savePath) { exporting = false; return; }
			const ext = exportFormat === 'csv' ? 'csv' : 'json';
			const fileName = `payload-inject-${new Date().toISOString().slice(0, 10)}.${ext}`;
			let content: string;
			if (exportFormat === 'csv') {
				const rows = [['Type', 'Name', 'Platform', 'Language', 'Detection Rate', 'MITRE ID']];
				result.payload_templates.forEach(t => rows.push([t.payload_type, t.name, t.platform, t.language, `${Math.round(t.detection_rate * 100)}%`, t.mitre_id]));
				content = rows.map(r => r.map(c => `"${c.replace(/"/g, '""')}"`).join(',')).join('\n');
			} else {
				content = JSON.stringify(result, null, 2);
			}
			const { writeTextFile } = await import('@tauri-apps/plugin-fs');
			await writeTextFile(`${savePath}/${fileName}`, content);
		} catch (e: any) {
			console.error('Export failed:', e);
		} finally {
			exporting = false;
		}
	}

	function copyToClipboard(text: string) {
		navigator.clipboard.writeText(text).catch(() => {});
	}
</script>

<div class="nd-page">
	<div class="page-header">
		<div class="header-left">
			<a href="/" class="back-link">{$tr('common.backToHome')}</a>
			<h1 class="page-title">💉 {$tr('payloadInjector.title')}</h1>
			<p class="page-subtitle">{$tr('payloadInjector.subtitle')}</p>
		</div>
	</div>

	<div class="tabs">
		<button class="tab-btn {activeMainTab === 'analyze' ? 'active' : ''}" onclick={() => activeMainTab = 'analyze'}>
			<span class="tab-icon">💉</span> {$tr('payloadInjector.startInject')}
		</button>
		<button class="tab-btn {activeMainTab === 'history' ? 'active' : ''}" onclick={() => activeMainTab = 'history'}>
			<span class="tab-icon">📋</span> {$tr('common.history')}
		</button>
		<button class="tab-btn {activeMainTab === 'help' ? 'active' : ''}" onclick={() => activeMainTab = 'help'}>
			<span class="tab-icon">📖</span> {$tr('common.help')}
		</button>
	</div>

	{#if activeMainTab === 'analyze'}
		<div class="content-grid">
			<div class="input-section">
				<div class="section-card">
					<h2 class="section-title">{$tr('payloadInjector.configTitle')}</h2>
					<p class="section-desc">{$tr('payloadInjector.configDesc')}</p>

					<div class="form-group">
						<label class="form-label" for="pi-target">{$tr('payloadInjector.targetFile')}</label>
						<input id="pi-target" type="text" bind:value={targetFile} placeholder={$tr('payloadInjector.targetFilePlaceholder')} class="form-input" disabled={processing} />
					</div>

					<div class="form-group">
						<label class="form-label" for="pi-type">{$tr('payloadInjector.payloadType')}</label>
						<select id="pi-type" bind:value={payloadType} class="form-input" disabled={processing}>
							<option value="reverse_shell">🐚 {$tr('payloadInjector.payloadTypes.reverse_shell')}</option>
							<option value="bind_shell">📡 {$tr('payloadInjector.payloadTypes.bind_shell')}</option>
							<option value="webshell">🌐 {$tr('payloadInjector.payloadTypes.webshell')}</option>
							<option value="meterpreter">⚡ {$tr('payloadInjector.payloadTypes.meterpreter')}</option>
							<option value="dll_inject">📦 {$tr('payloadInjector.payloadTypes.dll_inject')}</option>
							<option value="custom">✏️ {$tr('payloadInjector.payloadTypes.custom')}</option>
						</select>
					</div>

					<div class="form-group">
						<label class="form-label" for="pi-method">{$tr('payloadInjector.injectionMethod')}</label>
						<select id="pi-method" bind:value={injectionMethod} class="form-input" disabled={processing}>
							<option value="append">➕ {$tr('payloadInjector.injectionMethods.append')}</option>
							<option value="prepend">⬆️ {$tr('payloadInjector.injectionMethods.prepend')}</option>
							<option value="cave">🕳️ {$tr('payloadInjector.injectionMethods.cave')}</option>
							<option value="section">📄 {$tr('payloadInjector.injectionMethods.section')}</option>
							<option value="replace">🔄 {$tr('payloadInjector.injectionMethods.replace')}</option>
						</select>
					</div>

					<div class="form-group">
						<label class="form-label" for="pi-host">{$tr('payloadInjector.listenerHost')}</label>
						<input id="pi-host" type="text" bind:value={listenerHost} placeholder="attacker.com" class="form-input" disabled={processing} />
					</div>

					<div class="form-group">
						<label class="form-label" for="pi-port">{$tr('payloadInjector.listenerPort')}</label>
						<input id="pi-port" type="number" bind:value={listenerPort} placeholder="4444" class="form-input" disabled={processing} />
					</div>

					{#if payloadType === 'custom'}
						<div class="form-group">
							<label class="form-label" for="pi-custom">{$tr('payloadInjector.customPayload')}</label>
							<textarea id="pi-custom" bind:value={customPayload} placeholder={$tr('payloadInjector.customPayloadPlaceholder')} class="form-input form-textarea" disabled={processing} rows="3"></textarea>
						</div>
					{/if}

					<div class="form-group">
						<label class="form-label">{$tr('payloadInjector.options')}</label>
						<div class="check-grid">
							<label class="check-chip {encodePayload ? 'active' : ''}">
								<input type="checkbox" bind:checked={encodePayload} disabled={processing} />
								🔐 {$tr('payloadInjector.optionEncode')}
							</label>
							<label class="check-chip {obfuscate ? 'active' : ''}">
								<input type="checkbox" bind:checked={obfuscate} disabled={processing} />
								🎭 {$tr('payloadInjector.optionObfuscate')}
							</label>
							<label class="check-chip {antiDebug ? 'active' : ''}">
								<input type="checkbox" bind:checked={antiDebug} disabled={processing} />
								🛡️ {$tr('payloadInjector.optionAntiDebug')}
							</label>
							<label class="check-chip {persistence ? 'active' : ''}">
								<input type="checkbox" bind:checked={persistence} disabled={processing} />
								🔗 {$tr('payloadInjector.optionPersistence')}
							</label>
						</div>
					</div>

					<div class="button-group">
						<button class="btn-primary" onclick={inject} disabled={processing || !targetFile.trim()}>
							{#if processing}⏳ {$tr('payloadInjector.injecting')}{:else}💉 {$tr('payloadInjector.startInject')}{/if}
						</button>
						<button class="btn-secondary" onclick={clearAll} disabled={processing}>🗑️ {$tr('common.clear')}</button>
					</div>
				</div>
			</div>

			<div class="result-section">
				{#if error}
					<div class="section-card">
						<div class="error-banner">
							<span class="error-icon">⚠️</span>
							<span>{error}</span>
						</div>
					</div>
				{:else if result}
					<div class="section-card score-section">
						<div class="score-row">
							<div class="score-circle" style="border-color: {detectionColor}">
								<span class="score-number" style="color: {detectionColor}">{Math.round(avgDetectionRate * 100)}</span>
								<span class="score-max">%</span>
							</div>
							<div class="score-details">
								<div class="score-level" style="color: {detectionColor}">{detectionLevel}</div>
								<div class="score-stats">
									<span class="stat-item">💉 {$tr('payloadInjector.templates')}: {result.payload_templates.length}</span>
									<span class="stat-item">🔓 {$tr('payloadInjector.evasion')}: {result.detection_evasion.length}</span>
									<span class="stat-item">⚠️ {$tr('payloadInjector.warnings')}: {result.warnings.length}</span>
								</div>
								<div class="score-total">{result.summary}</div>
							</div>
							<div class="export-group">
								<select bind:value={exportFormat} class="export-select">
									<option value="json">JSON</option>
									<option value="csv">CSV</option>
								</select>
								<button class="btn-export" onclick={exportResult} disabled={exporting}>
									{#if exporting}⏳{:else}📥{/if} {$tr('payloadInjector.export')}
								</button>
							</div>
						</div>
					</div>

					{#if result.warnings.length > 0}
						<div class="section-card warnings-section">
							{#each result.warnings as w}
								<div class="warning-item">⚠️ {w}</div>
							{/each}
						</div>
					{/if}

					<div class="section-card">
						<div class="result-tabs">
							<button class="result-tab {activeResultTab === 'payloads' ? 'active' : ''}" onclick={() => activeResultTab = 'payloads'}>
								💉 {$tr('payloadInjector.tabs.payloads')} ({result.payload_templates.length})
							</button>
							<button class="result-tab {activeResultTab === 'injection' ? 'active' : ''}" onclick={() => activeResultTab = 'injection'}>
								🎯 {$tr('payloadInjector.tabs.injection')}
							</button>
							<button class="result-tab {activeResultTab === 'encoding' ? 'active' : ''}" onclick={() => activeResultTab = 'encoding'}>
								🔐 {$tr('payloadInjector.tabs.encoding')}
							</button>
							<button class="result-tab {activeResultTab === 'evasion' ? 'active' : ''}" onclick={() => activeResultTab = 'evasion'}>
								🛡️ {$tr('payloadInjector.tabs.evasion')} ({result.detection_evasion.length})
							</button>
						</div>

						{#if activeResultTab === 'payloads'}
							{#if result.payload_templates.length > 0}
								<div class="detail-list">
									{#each result.payload_templates as t}
										<div class="detail-card" style="border-left-color: {t.detection_rate >= 0.8 ? '#dc2626' : t.detection_rate >= 0.6 ? '#ef4444' : t.detection_rate >= 0.4 ? '#f59e0b' : '#22c55e'}">
											<div class="detail-header">
												<span class="lang-badge">{t.language}</span>
												<span class="detail-title">{t.name}</span>
												<span class="platform-badge">{t.platform}</span>
												<span class="mitre-badge">{t.mitre_id}</span>
											</div>
											<p class="detail-desc">{t.description}</p>
											<div class="detail-meta">
												<span>📏 {t.size_bytes} bytes</span>
												<span>🏗️ {t.architecture}</span>
												<span style="color: {t.detection_rate >= 0.8 ? '#dc2626' : t.detection_rate >= 0.6 ? '#ef4444' : t.detection_rate >= 0.4 ? '#f59e0b' : '#22c55e'}">
													🔍 {$tr('payloadInjector.detectionRate')}: {Math.round(t.detection_rate * 100)}%
												</span>
											</div>
											<div class="code-wrapper">
												<pre class="code-block">{t.code}</pre>
												<button class="copy-btn" onclick={() => copyToClipboard(t.code)} title={$tr('common.copy')}>📋</button>
											</div>
										</div>
									{/each}
								</div>
							{:else}
								<div class="empty-state">
									<div class="empty-icon">💉</div>
									<p>{$tr('payloadInjector.noTemplates')}</p>
								</div>
							{/if}
						{:else if activeResultTab === 'injection'}
							<div class="injection-info">
								<div class="info-grid">
									<div class="info-item">
										<span class="info-label">{$tr('payloadInjector.injection.method')}</span>
										<span class="info-value">{result.injection_result.method}</span>
									</div>
									<div class="info-item">
										<span class="info-label">{$tr('payloadInjector.injection.fileType')}</span>
										<span class="info-value">{result.injection_result.file_type}</span>
									</div>
									<div class="info-item">
										<span class="info-label">{$tr('payloadInjector.injection.originalSize')}</span>
										<span class="info-value">{result.injection_result.original_size} bytes</span>
									</div>
									<div class="info-item">
										<span class="info-label">{$tr('payloadInjector.injection.injectedSize')}</span>
										<span class="info-value">{result.injection_result.injected_size} bytes</span>
									</div>
									<div class="info-item">
										<span class="info-label">{$tr('payloadInjector.injection.offset')}</span>
										<span class="info-value">0x{result.injection_result.injection_offset.toString(16).toUpperCase()}</span>
									</div>
									<div class="info-item">
										<span class="info-label">{$tr('payloadInjector.injection.status')}</span>
										<span class="info-value" style="color: {result.injection_result.success ? '#22c55e' : '#ef4444'}">
											{result.injection_result.success ? '✅ ' + $tr('payloadInjector.injection.success') : '❌ ' + $tr('payloadInjector.injection.failed')}
										</span>
									</div>
									<div class="info-item">
										<span class="info-label">{$tr('payloadInjector.injection.integrity')}</span>
										<span class="info-value" style="color: {result.injection_result.integrity_preserved ? '#22c55e' : '#f59e0b'}">
											{result.injection_result.integrity_preserved ? '✅ ' + $tr('payloadInjector.injection.preserved') : '⚠️ ' + $tr('payloadInjector.injection.notPreserved')}
										</span>
									</div>
									<div class="info-item">
										<span class="info-label">{$tr('payloadInjector.injection.sizeDiff')}</span>
										<span class="info-value">+{result.injection_result.injected_size - result.injection_result.original_size} bytes</span>
									</div>
								</div>
							</div>
						{:else if activeResultTab === 'encoding'}
							{#if result.encoding_result}
								{@const enc = result.encoding_result}
								<div class="encoding-info">
									<div class="info-grid">
										<div class="info-item">
											<span class="info-label">{$tr('payloadInjector.encoding.type')}</span>
											<span class="info-value">{enc.encoding_type}</span>
										</div>
										<div class="info-item">
											<span class="info-label">{$tr('payloadInjector.encoding.originalSize')}</span>
											<span class="info-value">{enc.original_size} bytes</span>
										</div>
										<div class="info-item">
											<span class="info-label">{$tr('payloadInjector.encoding.encodedSize')}</span>
											<span class="info-value">{enc.encoded_size} bytes</span>
										</div>
										<div class="info-item">
											<span class="info-label">{$tr('payloadInjector.encoding.ratio')}</span>
											<span class="info-value">{enc.original_size > 0 ? ((enc.encoded_size / enc.original_size) * 100).toFixed(1) : 0}%</span>
										</div>
									</div>
									<div class="code-section">
										<h4 class="code-section-title">{$tr('payloadInjector.encoding.encodedPayload')}</h4>
										<div class="code-wrapper">
											<pre class="code-block">{enc.encoded_payload}</pre>
											<button class="copy-btn" onclick={() => copyToClipboard(enc.encoded_payload)} title={$tr('common.copy')}>📋</button>
										</div>
									</div>
									<div class="code-section">
										<h4 class="code-section-title">{$tr('payloadInjector.encoding.decoderStub')}</h4>
										<div class="code-wrapper">
											<pre class="code-block">{enc.decoder_stub}</pre>
											<button class="copy-btn" onclick={() => copyToClipboard(enc.decoder_stub)} title={$tr('common.copy')}>📋</button>
										</div>
									</div>
								</div>
							{:else}
								<div class="empty-state">
									<div class="empty-icon">🔐</div>
									<p>{$tr('payloadInjector.encoding.notEnabled')}</p>
								</div>
							{/if}
						{:else if activeResultTab === 'evasion'}
							{#if result.detection_evasion.length > 0}
								<div class="detail-list">
									{#each result.detection_evasion as e}
										<div class="detail-card" style="border-left-color: {getEffectivenessColor(e.effectiveness)}">
											<div class="detail-header">
												<span class="mitre-badge">{e.mitre_id}</span>
												<span class="detail-title">{e.technique}</span>
												<span class="effectiveness-badge" style="background: {getEffectivenessColor(e.effectiveness)}; color: white">
													{getEffectivenessLabel(e.effectiveness)}
												</span>
											</div>
											<p class="detail-desc">{e.description}</p>
										</div>
									{/each}
								</div>
							{:else}
								<div class="empty-state">
									<div class="empty-icon">🛡️</div>
									<p>{$tr('payloadInjector.evasion.noEvasion')}</p>
								</div>
							{/if}
						{/if}
					</div>
				{:else}
					<div class="section-card">
						<div class="empty-state">
							<div class="empty-icon">💉</div>
							<p>{$tr('payloadInjector.noResults')}</p>
						</div>
					</div>
				{/if}
			</div>
		</div>
	{:else if activeMainTab === 'history'}
		<div class="section-card">
			<ToolHistory toolType="payload_injector" toolName={$tr('payloadInjector.title')} bind:this={historyComponent} />
		</div>
	{:else if activeMainTab === 'help'}
		<div class="section-card">
			<ToolHelp toolType="payload_injector" />
		</div>
	{/if}
</div>

<style>
	.nd-page { padding: 20px; max-width: 1400px; margin: 0 auto; min-height: 100vh; }

	.page-header { margin-bottom: 20px; }
	.header-left { display: flex; flex-direction: column; gap: 4px; }
	.back-link { color: #94a3b8; text-decoration: none; font-size: 0.85rem; transition: color 0.2s; }
	.back-link:hover { color: #a855f7; }
	.page-title { font-size: 1.5rem; margin: 8px 0 4px; color: #f1f5f9; font-weight: 700; }
	.page-subtitle { color: #94a3b8; font-size: 0.9rem; margin: 0; }

	.tabs { display: flex; gap: 4px; margin-bottom: 16px; background: rgba(15, 23, 42, 0.6); border-radius: 12px; padding: 4px; border: 1px solid rgba(168, 85, 247, 0.1); }
	.tab-btn { flex: 1; padding: 10px 16px; border: none; border-radius: 8px; background: transparent; cursor: pointer; font-size: 0.9rem; color: #94a3b8; transition: all 0.2s; display: flex; align-items: center; justify-content: center; gap: 6px; }
	.tab-btn:hover { color: #e2e8f0; background: rgba(168, 85, 247, 0.1); }
	.tab-btn.active { background: linear-gradient(135deg, #a855f7, #7c3aed); color: white; box-shadow: 0 2px 8px rgba(168, 85, 247, 0.3); }
	.tab-icon { font-size: 1rem; }

	.content-grid { display: grid; grid-template-columns: 380px 1fr; gap: 20px; }

	.section-card { background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(168, 85, 247, 0.1); border-radius: 12px; padding: 20px; }
	.section-title { font-size: 1.1rem; margin: 0 0 4px; color: #f1f5f9; font-weight: 600; }
	.section-desc { font-size: 0.8rem; color: #64748b; margin: 0 0 16px; }

	.form-group { margin-bottom: 14px; }
	.form-label { display: block; font-size: 0.8rem; color: #94a3b8; margin-bottom: 6px; font-weight: 500; text-transform: uppercase; letter-spacing: 0.05em; }
	.form-input { width: 100%; padding: 10px 12px; border-radius: 8px; border: 1px solid rgba(168, 85, 247, 0.2); background: rgba(15, 23, 42, 0.8); color: #f1f5f9; font-size: 0.9rem; box-sizing: border-box; transition: border-color 0.2s; }
	.form-input:focus { outline: none; border-color: #a855f7; box-shadow: 0 0 0 2px rgba(168, 85, 247, 0.2); }
	.form-input:disabled { opacity: 0.5; cursor: not-allowed; }
	.form-input::placeholder { color: #475569; }
	select.form-input { appearance: auto; }
	.form-textarea { resize: vertical; min-height: 60px; font-family: 'SF Mono', 'Fira Code', monospace; font-size: 0.8rem; }

	.check-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 6px; }
	.check-chip { display: flex; align-items: center; gap: 6px; padding: 8px 10px; border-radius: 8px; background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(168, 85, 247, 0.1); cursor: pointer; font-size: 0.8rem; color: #94a3b8; transition: all 0.2s; }
	.check-chip:hover { border-color: rgba(168, 85, 247, 0.3); }
	.check-chip.active { background: rgba(168, 85, 247, 0.15); border-color: rgba(168, 85, 247, 0.4); color: #e2e8f0; }
	.check-chip input { display: none; }

	.button-group { display: flex; gap: 8px; margin-top: 16px; }
	.btn-primary { flex: 1; padding: 10px 16px; border-radius: 8px; border: none; cursor: pointer; font-size: 0.9rem; font-weight: 600; background: linear-gradient(135deg, #a855f7, #7c3aed); color: white; transition: all 0.2s; }
	.btn-primary:hover:not(:disabled) { box-shadow: 0 4px 12px rgba(168, 85, 247, 0.4); transform: translateY(-1px); }
	.btn-primary:disabled { opacity: 0.5; cursor: not-allowed; }
	.btn-secondary { padding: 10px 16px; border-radius: 8px; border: 1px solid rgba(168, 85, 247, 0.2); cursor: pointer; font-size: 0.9rem; background: rgba(15, 23, 42, 0.6); color: #94a3b8; transition: all 0.2s; }
	.btn-secondary:hover:not(:disabled) { border-color: rgba(168, 85, 247, 0.4); color: #e2e8f0; }
	.btn-secondary:disabled { opacity: 0.5; cursor: not-allowed; }

	.error-banner { display: flex; align-items: center; gap: 12px; padding: 14px; background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.2); border-radius: 8px; color: #fca5a5; font-size: 0.9rem; }
	.error-icon { font-size: 1.3rem; }

	.score-section { margin-bottom: 12px; }
	.score-row { display: flex; align-items: center; gap: 16px; }
	.score-circle { width: 70px; height: 70px; border-radius: 50%; border: 3px solid; display: flex; flex-direction: column; align-items: center; justify-content: center; flex-shrink: 0; }
	.score-number { font-size: 1.4rem; font-weight: 700; line-height: 1; }
	.score-max { font-size: 0.6rem; color: #94a3b8; }
	.score-details { flex: 1; }
	.score-level { font-size: 1rem; font-weight: 600; margin-bottom: 4px; }
	.score-stats { display: flex; gap: 12px; font-size: 0.8rem; color: #94a3b8; flex-wrap: wrap; }
	.stat-item { white-space: nowrap; }
	.score-total { font-size: 0.75rem; color: #64748b; margin-top: 4px; }
	.export-group { display: flex; gap: 4px; align-items: center; flex-shrink: 0; }
	.export-select { padding: 6px 8px; border-radius: 6px; border: 1px solid rgba(168, 85, 247, 0.2); background: rgba(15, 23, 42, 0.8); color: #f1f5f9; font-size: 0.8rem; }
	.btn-export { padding: 6px 12px; border-radius: 6px; border: none; cursor: pointer; font-size: 0.8rem; background: rgba(168, 85, 247, 0.2); color: #e2e8f0; transition: all 0.2s; }
	.btn-export:hover:not(:disabled) { background: rgba(168, 85, 247, 0.3); }
	.btn-export:disabled { opacity: 0.5; cursor: not-allowed; }

	.warnings-section { margin-bottom: 12px; padding: 12px; }
	.warning-item { padding: 6px 10px; background: rgba(245, 158, 11, 0.1); border: 1px solid rgba(245, 158, 11, 0.15); border-radius: 6px; font-size: 0.8rem; color: #fbbf24; margin-bottom: 4px; }
	.warning-item:last-child { margin-bottom: 0; }

	.result-tabs { display: flex; gap: 4px; margin-bottom: 16px; flex-wrap: wrap; }
	.result-tab { padding: 7px 14px; border: 1px solid rgba(168, 85, 247, 0.15); border-radius: 8px; background: transparent; color: #94a3b8; cursor: pointer; font-size: 0.8rem; transition: all 0.2s; }
	.result-tab:hover { border-color: rgba(168, 85, 247, 0.3); color: #e2e8f0; }
	.result-tab.active { background: rgba(168, 85, 247, 0.2); border-color: rgba(168, 85, 247, 0.4); color: #e2e8f0; }

	.detail-list { display: flex; flex-direction: column; gap: 10px; }
	.detail-card { padding: 14px; background: rgba(15, 23, 42, 0.4); border-radius: 8px; border-left: 3px solid #a855f7; }
	.detail-header { display: flex; align-items: center; gap: 8px; margin-bottom: 6px; flex-wrap: wrap; }
	.detail-title { font-weight: 600; font-size: 0.9rem; color: #f1f5f9; }
	.detail-desc { font-size: 0.8rem; color: #94a3b8; margin: 0 0 6px; }
	.detail-meta { display: flex; gap: 12px; font-size: 0.75rem; color: #64748b; flex-wrap: wrap; }

	.lang-badge { padding: 2px 8px; background: rgba(99, 102, 241, 0.15); border: 1px solid rgba(99, 102, 241, 0.2); border-radius: 4px; font-size: 0.7rem; color: #a5b4fc; }
	.platform-badge { padding: 2px 8px; background: rgba(34, 197, 94, 0.15); border: 1px solid rgba(34, 197, 94, 0.2); border-radius: 4px; font-size: 0.7rem; color: #86efac; }
	.mitre-badge { padding: 2px 8px; background: rgba(168, 85, 247, 0.15); border: 1px solid rgba(168, 85, 247, 0.2); border-radius: 4px; font-size: 0.7rem; color: #c4b5fd; font-family: 'SF Mono', 'Fira Code', monospace; }
	.effectiveness-badge { padding: 2px 8px; border-radius: 4px; font-size: 0.7rem; font-weight: 600; }

	.code-wrapper { position: relative; margin-top: 8px; }
	.code-block { background: rgba(15, 23, 42, 0.8); border: 1px solid rgba(168, 85, 247, 0.1); border-radius: 6px; padding: 10px; font-family: 'SF Mono', 'Fira Code', monospace; font-size: 0.75rem; overflow-x: auto; white-space: pre-wrap; word-break: break-all; max-height: 150px; overflow-y: auto; margin: 0; color: #e2e8f0; }
	.copy-btn { position: absolute; top: 6px; right: 6px; padding: 4px 8px; border-radius: 4px; border: none; background: rgba(168, 85, 247, 0.2); cursor: pointer; font-size: 0.75rem; transition: background 0.2s; }
	.copy-btn:hover { background: rgba(168, 85, 247, 0.4); }

	.info-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 8px; }
	.info-item { display: flex; flex-direction: column; gap: 2px; padding: 10px; background: rgba(15, 23, 42, 0.4); border: 1px solid rgba(168, 85, 247, 0.1); border-radius: 6px; }
	.info-label { font-size: 0.7rem; color: #64748b; text-transform: uppercase; letter-spacing: 0.05em; font-weight: 500; }
	.info-value { font-size: 0.9rem; color: #f1f5f9; font-weight: 500; word-break: break-all; }

	.code-section { margin-top: 14px; }
	.code-section-title { font-size: 0.85rem; color: #94a3b8; margin: 0 0 8px; font-weight: 500; }

	.empty-state { text-align: center; padding: 40px; color: #64748b; }
	.empty-icon { font-size: 3rem; margin-bottom: 12px; }
	.empty-state p { margin: 0; font-size: 0.9rem; }

	@media (max-width: 900px) {
		.content-grid { grid-template-columns: 1fr; }
		.score-row { flex-direction: column; align-items: flex-start; }
		.info-grid { grid-template-columns: 1fr; }
		.check-grid { grid-template-columns: 1fr; }
	}
</style>
