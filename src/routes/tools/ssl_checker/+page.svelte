<script lang="ts">
	import { tr } from '$lib/i18n';
	import { open } from '@tauri-apps/plugin-dialog';
	import { readFile } from '@tauri-apps/plugin-fs';

	interface CertificateInfo {
		subject: string;
		issuer: string;
		serial_number: string;
		not_before: string;
		not_after: string;
		is_expired: boolean;
		days_remaining: number;
		signature_algorithm: string;
		key_type: string;
		key_bits: number;
		san_domains: string[];
		is_self_signed: boolean;
		subject_cn: string;
		issuer_cn: string;
		fingerprint_sha256: string;
	}

	interface SslCheckResult {
		host: string;
		port: number;
		is_secure: boolean;
		protocol_version: string;
		cipher_name: string;
		cipher_bits: number;
		certificate: CertificateInfo;
		protocol_issues: string[];
		cipher_issues: string[];
		overall_grade: string;
		score: number;
		summary: string;
	}

	interface BatchSslCheckResult {
		host: string;
		result: SslCheckResult | null;
		error: string | null;
	}

	let host = '';
	let port = 443;
	let result: SslCheckResult | null = null;
	let batchResults: BatchSslCheckResult[] = [];
	let error = '';
	let processing = false;
	let showHelpModal = false;
	let activeTab = 'single';

	let showTargetSelector = false;
	let targetList: any[] = [];
	let selectedTargets: any[] = [];
	let selectedTargetIds: number[] = [];
	let targetSearchQuery = '';
	let loadingTargets = false;

	let currentPage = 1;
	let pageSize = 10;

	let history: any[] = [];
	let loadingHistory = false;
	let historyError = '';
	let historyCurrentPage = 1;
	let historyPageSize = 20;
	let selectedHistoryItem: any = null;
	let showHistoryDetail = false;
	let showConfirmDialog = false;
	let confirmDialogTitle = '';
	let confirmDialogMessage = '';
	let confirmAction: (() => Promise<void>) | null = null;

	$: totalPages = Math.ceil(batchResults.length / pageSize);
	$: paginatedResults = batchResults.slice((currentPage - 1) * pageSize, currentPage * pageSize);
	$: successCount = batchResults.filter(r => r.result).length;
	$: failedCount = batchResults.filter(r => r.error).length;
	$: filteredTargets = targetList.filter((t: any) =>
		!targetSearchQuery ||
		t.name?.toLowerCase().includes(targetSearchQuery.toLowerCase()) ||
		t.target_value?.toLowerCase().includes(targetSearchQuery.toLowerCase())
	);

	async function checkSsl() {
		if (!host.trim()) {
			error = $tr('sslChecker.error.emptyInput');
			return;
		}

		processing = true;
		error = '';
		result = null;

		try {
			const { invoke } = await import('@tauri-apps/api/core');
			result = await invoke<SslCheckResult>('check_ssl_command', {
				host: host.trim(),
				port: port !== 443 ? port : undefined,
				targetId: selectedTargetIds.length > 0 ? selectedTargetIds[0] : null,
			});

			if (result) {
				try {
					await invoke('save_ssl_check_record', {
						host: result.host,
						port: result.port,
						isSecure: result.is_secure,
						protocolVersion: result.protocol_version,
						cipherName: result.cipher_name,
						cipherBits: result.cipher_bits,
						score: result.score,
						grade: result.overall_grade,
						subjectCn: result.certificate.subject_cn,
						issuerCn: result.certificate.issuer_cn,
						isExpired: result.certificate.is_expired,
						daysRemaining: result.certificate.days_remaining,
						isSelfSigned: result.certificate.is_self_signed,
						keyType: result.certificate.key_type,
						keyBits: result.certificate.key_bits,
						summary: result.summary,
						result: JSON.stringify(result),
					});
				} catch (e) {
					console.error('Failed to save history:', e);
				}
			}
		} catch (e: any) {
			error = friendlyError(e.toString());
		} finally {
			processing = false;
		}
	}

	async function batchCheck() {
		const hosts = host
			.split(/[\n,;]+/)
			.map(h => h.trim())
			.filter(h => h.length > 0);

		if (hosts.length === 0) {
			error = $tr('sslChecker.error.emptyInput');
			return;
		}

		processing = true;
		error = '';
		batchResults = [];

		try {
			const { invoke } = await import('@tauri-apps/api/core');
			for (const targetHost of hosts) {
				try {
					const r = await invoke<SslCheckResult>('check_ssl_command', {
						host: targetHost,
						port: port !== 443 ? port : undefined,
					});
					batchResults.push({ host: targetHost, result: r, error: null });

					try {
						await invoke('save_ssl_check_record', {
							host: r.host,
							port: r.port,
							isSecure: r.is_secure,
							protocolVersion: r.protocol_version,
							cipherName: r.cipher_name,
							cipherBits: r.cipher_bits,
							score: r.score,
							grade: r.overall_grade,
							subjectCn: r.certificate.subject_cn,
							issuerCn: r.certificate.issuer_cn,
							isExpired: r.certificate.is_expired,
							daysRemaining: r.certificate.days_remaining,
							isSelfSigned: r.certificate.is_self_signed,
							keyType: r.certificate.key_type,
							keyBits: r.certificate.key_bits,
							summary: r.summary,
							result: JSON.stringify(r),
						});
					} catch (e) {
						console.error('Failed to save history:', e);
					}
				} catch (e: any) {
					batchResults.push({ host: targetHost, result: null, error: friendlyError(e.toString()) });
				}
			}
		} catch (e: any) {
			error = friendlyError(e.toString());
		} finally {
			processing = false;
		}
	}

	async function openTargetSelectorModal() {
		showTargetSelector = true;
		await loadTargets();
	}

	async function loadTargets() {
		loadingTargets = true;
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			const res = await invoke<{ targets: any[], total: number }>('target_manager', {
				action: 'list',
				page: 1,
				pageSize: 100,
			});
			targetList = res.targets || [];
		} catch (e) {
			targetList = [];
		} finally {
			loadingTargets = false;
		}
	}

	function toggleTargetSelection(t: any) {
		const index = selectedTargets.findIndex((st: any) => st.id === t.id);
		if (index >= 0) {
			selectedTargets.splice(index, 1);
			selectedTargets = selectedTargets;
		} else {
			selectedTargets = [...selectedTargets, t];
		}
	}

	function confirmTargetSelection() {
		if (selectedTargets.length > 0) {
			const targetValues = selectedTargets.map((t: any) => t.target_value).join('\n');
			host = host ? `${host}\n${targetValues}` : targetValues;
			selectedTargetIds = selectedTargets.map((t: any) => t.id).filter((id: number | null): id is number => id !== null);
		}
		showTargetSelector = false;
		selectedTargets = [];
	}

	async function importHosts() {
		try {
			const selected = await open({
				multiple: false,
				filters: [{ name: 'Text', extensions: ['txt', 'csv', 'list'] }],
			});
			if (selected) {
				const fileData = await readFile(selected as string);
				const content = new TextDecoder('utf-8').decode(fileData);
				const hosts = content
					.split(/[\n,;]+/)
					.map(h => h.trim())
					.filter(h => h.length > 0);
				if (hosts.length > 0) {
					host = host ? `${host}\n${hosts.join('\n')}` : hosts.join('\n');
				}
			}
		} catch (e) {
			console.error('Import failed:', e);
		}
	}

	function clearAll() {
		host = '';
		port = 443;
		result = null;
		batchResults = [];
		error = '';
	}

	function friendlyError(raw: string): string {
		const lower = raw.toLowerCase();
		if (lower.includes('connection refused') || lower.includes('os error 61')) {
			return $tr('sslChecker.error.connectionRefused');
		}
		if (lower.includes('timed out') || lower.includes('timeout')) {
			return $tr('sslChecker.error.timeout');
		}
		if (lower.includes('tls handshake failed') || lower.includes('handshake')) {
			return $tr('sslChecker.error.handshakeFailed');
		}
		if (lower.includes('no route to host') || lower.includes('os error 51')) {
			return $tr('sslChecker.error.noRoute');
		}
		if (lower.includes('name resolution') || lower.includes('dns') || lower.includes('nodename nor servname')) {
			return $tr('sslChecker.error.dnsFailed');
		}
		if (lower.includes('network is unreachable') || lower.includes('os error 51')) {
			return $tr('sslChecker.error.networkUnreachable');
		}
		if (lower.includes('connection reset') || lower.includes('broken pipe')) {
			return $tr('sslChecker.error.connectionReset');
		}
		if (lower.includes('invalid address') || lower.includes('addrparse')) {
			return $tr('sslChecker.error.invalidAddress');
		}
		if (lower.includes('no certificate')) {
			return $tr('sslChecker.error.noCertificate');
		}
		return raw;
	}

	function switchTab(tab: string) {
		activeTab = tab;
		error = '';
		result = null;
		batchResults = [];
		if (tab === 'history') {
			loadHistory();
		}
	}

	function getGradeColor(grade: string): string {
		switch (grade) {
			case 'A': return '#22c55e';
			case 'B': return '#84cc16';
			case 'C': return '#eab308';
			case 'D': return '#f97316';
			case 'F': return '#ef4444';
			default: return '#94a3b8';
		}
	}

	function getGradeBgColor(grade: string): string {
		switch (grade) {
			case 'A': return 'rgba(34, 197, 94, 0.15)';
			case 'B': return 'rgba(132, 204, 22, 0.15)';
			case 'C': return 'rgba(234, 179, 8, 0.15)';
			case 'D': return 'rgba(249, 115, 22, 0.15)';
			case 'F': return 'rgba(239, 68, 68, 0.15)';
			default: return 'rgba(148, 163, 184, 0.15)';
		}
	}

	async function loadHistory() {
		loadingHistory = true;
		historyError = '';

		try {
			const { invoke } = await import('@tauri-apps/api/core');
			history = await invoke('get_ssl_check_history', {
				limit: historyPageSize,
				offset: (historyCurrentPage - 1) * historyPageSize,
			});
		} catch (e) {
			historyError = `${$tr('sslChecker.history.messages.loadFailed')}: ${e}`;
		} finally {
			loadingHistory = false;
		}
	}

	function showConfirm(title: string, message: string, action: () => Promise<void>) {
		confirmDialogTitle = title;
		confirmDialogMessage = message;
		confirmAction = action;
		showConfirmDialog = true;
	}

	async function executeConfirmAction() {
		if (confirmAction) {
			showConfirmDialog = false;
			await confirmAction();
			confirmAction = null;
		}
	}

	function cancelConfirm() {
		showConfirmDialog = false;
		confirmAction = null;
	}

	async function deleteHistoryItem(id: number) {
		showConfirm(
			$tr('sslChecker.history.messages.deleteConfirm'),
			$tr('sslChecker.history.messages.deleteConfirmMessage'),
			async () => {
				try {
					const { invoke } = await import('@tauri-apps/api/core');
					await invoke('delete_ssl_check_record', { id });
					await loadHistory();
				} catch (e) {
					historyError = `${$tr('sslChecker.history.messages.deleteFailed')}: ${e}`;
				}
			}
		);
	}

	async function clearAllHistory() {
		showConfirm(
			$tr('sslChecker.history.messages.clearAllConfirm'),
			$tr('sslChecker.history.messages.clearAllConfirmMessage'),
			async () => {
				try {
					const { invoke } = await import('@tauri-apps/api/core');
					await invoke('clear_ssl_check_history');
					await loadHistory();
				} catch (e) {
					historyError = `${$tr('sslChecker.history.messages.clearFailed')}: ${e}`;
				}
			}
		);
	}

	function viewHistoryDetail(item: any) {
		try {
			selectedHistoryItem = JSON.parse(item.result);
		} catch {
			selectedHistoryItem = null;
		}
		showHistoryDetail = true;
	}

	function recheckFromHistory(item: any) {
		host = item.host;
		port = item.port || 443;
		activeTab = 'single';
		result = null;
		batchResults = [];
		error = '';
		checkSsl();
	}

	function formatDateTime(dateStr: string): string {
		const date = new Date(dateStr);
		return date.toLocaleString('zh-CN', {
			year: 'numeric',
			month: '2-digit',
			day: '2-digit',
			hour: '2-digit',
			minute: '2-digit',
			second: '2-digit',
		});
	}
</script>

<div class="ssl-checker-page">
	<div class="page-header">
		<div class="header-left">
			<a href="/" class="back-link">{$tr('common.backToHome')}</a>
			<h1 class="page-title">🔒 {$tr('sslChecker.title')}</h1>
			<p class="page-subtitle">{$tr('sslChecker.subtitle')}</p>
		</div>
		<button class="help-button" on:click={() => showHelpModal = true}>
			{$tr('common.userManual')}
		</button>
	</div>

	<div class="tabs">
		<button
			class="tab-button {activeTab === 'single' ? 'active' : ''}"
			on:click={() => switchTab('single')}
		>
			{$tr('sslChecker.tabs.single')}
		</button>
		<button
			class="tab-button {activeTab === 'batch' ? 'active' : ''}"
			on:click={() => switchTab('batch')}
		>
			{$tr('sslChecker.tabs.batch')}
		</button>
		<button
			class="tab-button {activeTab === 'history' ? 'active' : ''}"
			on:click={() => { activeTab = 'history'; loadHistory(); }}
		>
			{$tr('sslChecker.tabs.history')}
		</button>
	</div>

	{#if activeTab !== 'history'}
	<div class="content-grid">
		<div class="input-section">
			<div class="section-card">
				{#if activeTab === 'single'}
					<h2 class="section-title">{$tr('sslChecker.input.title')}</h2>
					<div class="form-group">
						<label class="form-label">{$tr('sslChecker.input.hostLabel')}</label>
						<input
							type="text"
							bind:value={host}
							placeholder={$tr('sslChecker.input.hostPlaceholder')}
							class="form-input"
							disabled={processing}
							on:keydown={(e) => e.key === 'Enter' && checkSsl()}
						/>
					</div>
					<div class="form-group">
						<label class="form-label">{$tr('sslChecker.input.portLabel')}</label>
						<input
							type="number"
							bind:value={port}
							placeholder="443"
							class="form-input"
							disabled={processing}
							min="1"
							max="65535"
						/>
					</div>
					<div class="button-group">
						<button class="btn btn-primary" on:click={checkSsl} disabled={processing || !host.trim()}>
							{#if processing}⏳ {$tr('sslChecker.buttons.checking')}{:else}🔍 {$tr('sslChecker.buttons.check')}{/if}
						</button>
						<button class="btn btn-secondary" on:click={clearAll} disabled={processing}>
							🗑️ {$tr('sslChecker.buttons.clear')}
						</button>
					</div>
				{:else}
					<h2 class="section-title">{$tr('sslChecker.batch.inputTitle')}</h2>
					<div class="form-group">
						<label class="form-label">{$tr('sslChecker.batch.inputLabel')}</label>
						<textarea
							bind:value={host}
							placeholder={$tr('sslChecker.batch.inputPlaceholder')}
							class="form-textarea"
							rows="8"
							disabled={processing}
						></textarea>
						<div class="textarea-actions">
							<button type="button" class="action-btn" on:click={openTargetSelectorModal} disabled={processing}>
								🎯 {$tr('sslChecker.batch.selectTarget')}
							</button>
							<button type="button" class="action-btn" on:click={importHosts} disabled={processing}>
								📥 {$tr('sslChecker.batch.import')}
							</button>
						</div>
					</div>
					<div class="form-group">
						<label class="form-label">{$tr('sslChecker.input.portLabel')}</label>
						<input
							type="number"
							bind:value={port}
							placeholder="443"
							class="form-input"
							disabled={processing}
							min="1"
							max="65535"
						/>
					</div>
					<div class="button-group">
						<button class="btn btn-primary" on:click={batchCheck} disabled={processing || !host.trim()}>
							{#if processing}⏳ {$tr('sslChecker.buttons.checking')}{:else}🔍 {$tr('sslChecker.batch.checkAll')}{/if}
						</button>
						<button class="btn btn-secondary" on:click={clearAll} disabled={processing}>
							🗑️ {$tr('sslChecker.buttons.clear')}
						</button>
					</div>
				{/if}
			</div>
		</div>

		<div class="result-section">
			<div class="section-card">
				{#if activeTab === 'single'}
					<h2 class="section-title">{$tr('sslChecker.result.title')}</h2>
					{#if error}
						<div class="error-card">
							<div class="error-icon">⚠️</div>
							<div class="error-content">
								<h3>{$tr('sslChecker.result.error')}</h3>
								<p>{error}</p>
							</div>
						</div>
					{:else if result}
						<div class="result-content">
							<div class="grade-header">
								<div class="grade-badge" style="background: {getGradeBgColor(result.overall_grade)}; border: 2px solid {getGradeColor(result.overall_grade)}">
									<span class="grade-letter" style="color: {getGradeColor(result.overall_grade)}">{result.overall_grade}</span>
									<span class="grade-score" style="color: {getGradeColor(result.overall_grade)}">{result.score}/100</span>
								</div>
								<div class="grade-info">
									<h3>{result.host}:{result.port}</h3>
									<p class="grade-summary">{result.summary}</p>
								</div>
							</div>

							<div class="ssl-details">
								<div class="detail-section">
									<h4>🔒 {$tr('sslChecker.result.protocol')}</h4>
									<div class="detail-item">
										<span class="detail-label">{$tr('sslChecker.result.protocolVersion')}</span>
										<span class="detail-value" class:secure={result.protocol_issues.length === 0} class:insecure={result.protocol_issues.length > 0}>
											{result.protocol_version}
											{#if result.protocol_issues.length === 0}✅{:else}⚠️{/if}
										</span>
									</div>
									<div class="detail-item">
										<span class="detail-label">{$tr('sslChecker.result.cipherSuite')}</span>
										<span class="detail-value">{result.cipher_name} ({result.cipher_bits} bits)</span>
									</div>
								</div>

								<div class="detail-section">
									<h4>📜 {$tr('sslChecker.result.certificate')}</h4>
									<div class="detail-item">
										<span class="detail-label">{$tr('sslChecker.result.subject')}</span>
										<span class="detail-value">{result.certificate.subject_cn}</span>
									</div>
									<div class="detail-item">
										<span class="detail-label">{$tr('sslChecker.result.issuer')}</span>
										<span class="detail-value">{result.certificate.issuer_cn}</span>
									</div>
									<div class="detail-item">
										<span class="detail-label">{$tr('sslChecker.result.validFrom')}</span>
										<span class="detail-value">{result.certificate.not_before}</span>
									</div>
									<div class="detail-item">
										<span class="detail-label">{$tr('sslChecker.result.validTo')}</span>
										<span class="detail-value" class:expired={result.certificate.is_expired} class:warning={result.certificate.days_remaining < 30 && !result.certificate.is_expired}>
											{result.certificate.not_after}
											{#if result.certificate.is_expired}❌{:else if result.certificate.days_remaining < 30}⚠️{:else}✅{/if}
										</span>
									</div>
									<div class="detail-item">
										<span class="detail-label">{$tr('sslChecker.result.daysRemaining')}</span>
										<span class="detail-value" class:expired={result.certificate.is_expired} class:warning={result.certificate.days_remaining < 30 && !result.certificate.is_expired}>
											{result.certificate.days_remaining} {$tr('sslChecker.result.days')}
										</span>
									</div>
									<div class="detail-item">
										<span class="detail-label">{$tr('sslChecker.result.keyType')}</span>
										<span class="detail-value">{result.certificate.key_type} ({result.certificate.key_bits} bits)</span>
									</div>
									<div class="detail-item">
										<span class="detail-label">{$tr('sslChecker.result.signatureAlgorithm')}</span>
										<span class="detail-value">{result.certificate.signature_algorithm}</span>
									</div>
									{#if result.certificate.is_self_signed}
										<div class="detail-item">
											<span class="detail-label">{$tr('sslChecker.result.selfSigned')}</span>
											<span class="detail-value warning">⚠️ {$tr('sslChecker.result.yes')}</span>
										</div>
									{/if}
									{#if result.certificate.san_domains.length > 0}
										<div class="detail-item">
											<span class="detail-label">{$tr('sslChecker.result.sanDomains')}</span>
											<span class="detail-value san-list">
												{#each result.certificate.san_domains as domain}
													<span class="san-tag">{domain}</span>
												{/each}
											</span>
										</div>
									{/if}
									<div class="detail-item">
										<span class="detail-label">{$tr('sslChecker.result.fingerprint')}</span>
										<span class="detail-value fingerprint">{result.certificate.fingerprint_sha256}</span>
									</div>
								</div>

								{#if result.protocol_issues.length > 0}
									<div class="detail-section issues">
										<h4>⚠️ {$tr('sslChecker.result.protocolIssues')}</h4>
										{#each result.protocol_issues as issue}
											<div class="issue-item protocol-issue">⚠️ {issue}</div>
										{/each}
									</div>
								{/if}

								{#if result.cipher_issues.length > 0}
									<div class="detail-section issues">
										<h4>⚠️ {$tr('sslChecker.result.cipherIssues')}</h4>
										{#each result.cipher_issues as issue}
											<div class="issue-item cipher-issue">⚠️ {issue}</div>
										{/each}
									</div>
								{/if}
							</div>
						</div>
					{:else}
						<div class="empty-state">
							<div class="empty-icon">🔒</div>
							<p>{$tr('sslChecker.result.empty')}</p>
							<p class="empty-hint">{$tr('sslChecker.result.hint')}</p>
						</div>
					{/if}
				{:else}
					<h2 class="section-title">{$tr('sslChecker.batch.resultTitle')}</h2>
					{#if batchResults.length > 0}
						<div class="batch-stats">
							<div class="stat-item">
								<span class="stat-label">{$tr('sslChecker.batch.total')}</span>
								<span class="stat-value">{batchResults.length}</span>
							</div>
							<div class="stat-item success">
								<span class="stat-label">{$tr('sslChecker.batch.success')}</span>
								<span class="stat-value">{successCount}</span>
							</div>
							<div class="stat-item failed">
								<span class="stat-label">{$tr('sslChecker.batch.failed')}</span>
								<span class="stat-value">{failedCount}</span>
							</div>
						</div>
						<div class="batch-results">
							{#each paginatedResults as item}
								<div class="batch-item {item.error ? 'error' : 'success'}">
									<div class="batch-item-header">
										<span class="batch-host">{item.host}</span>
										{#if item.result}
											<span class="grade-badge-small" style="background: {getGradeBgColor(item.result.overall_grade)}; color: {getGradeColor(item.result.overall_grade)}">
												{item.result.overall_grade} ({item.result.score})
											</span>
											<span class="batch-info">{item.result.protocol_version} - {item.result.certificate.subject_cn}</span>
										{:else}
											<span class="batch-error-text">❌ {item.error}</span>
										{/if}
									</div>
									{#if item.result}
										<div class="batch-item-details">
											<span>🔑 {item.result.cipher_name} ({item.result.cipher_bits} bits)</span>
											<span>📅 {item.result.certificate.days_remaining} {$tr('sslChecker.result.days')}</span>
											{#if item.result.certificate.is_expired}
												<span class="expired">❌ {$tr('sslChecker.result.expired')}</span>
											{/if}
										</div>
									{/if}
								</div>
							{/each}
						</div>
						{#if totalPages > 1}
							<div class="pagination">
								<button class="pagination-btn" disabled={currentPage === 1} on:click={() => currentPage--}>
									←
								</button>
								<span class="pagination-info">{$tr('common.page')} {currentPage}/{totalPages}</span>
								<button class="pagination-btn" disabled={currentPage >= totalPages} on:click={() => currentPage++}>
									→
								</button>
							</div>
						{/if}
					{:else}
						<div class="empty-state">
							<div class="empty-icon">🔒</div>
							<p>{$tr('sslChecker.result.empty')}</p>
							<p class="empty-hint">{$tr('sslChecker.batch.hint')}</p>
						</div>
					{/if}
				{/if}
			</div>
		</div>
	</div>
	{:else}
		<div class="history-section">
			<div class="section-card">
				<div class="history-header">
					<h2 class="section-title">📋 {$tr('sslChecker.history.title')}</h2>
					<div class="history-actions">
						<button class="btn btn-secondary" on:click={loadHistory} disabled={loadingHistory}>
							🔄 {$tr('sslChecker.history.refresh')}
						</button>
						<button class="btn btn-danger" on:click={clearAllHistory} disabled={loadingHistory || history.length === 0}>
							🗑️ {$tr('sslChecker.history.clearAll')}
						</button>
					</div>
				</div>

				{#if historyError}
					<div class="error-card">
						<div class="error-icon">⚠️</div>
						<div class="error-content">
							<p>{historyError}</p>
						</div>
					</div>
				{/if}

				{#if loadingHistory}
					<div class="loading-state">
						<div class="spinner"></div>
						<p>{$tr('common.loading')}</p>
					</div>
				{:else if history.length === 0}
					<div class="empty-state">
						<div class="empty-icon">📋</div>
						<p>{$tr('sslChecker.history.empty')}</p>
						<p class="empty-hint">{$tr('sslChecker.history.hint')}</p>
					</div>
				{:else}
					<div class="history-table-wrapper">
						<table class="history-table">
							<thead>
								<tr>
									<th>{$tr('sslChecker.history.table.host')}</th>
									<th>{$tr('sslChecker.history.table.grade')}</th>
									<th>{$tr('sslChecker.history.table.protocol')}</th>
									<th>{$tr('sslChecker.history.table.certificate')}</th>
									<th>{$tr('sslChecker.history.table.time')}</th>
									<th>{$tr('sslChecker.history.table.actions')}</th>
								</tr>
							</thead>
							<tbody>
								{#each history as item}
									<tr>
										<td class="host-cell"><code>{item.host}:{item.port}</code></td>
										<td>
											<span class="grade-badge-small" style="background: {getGradeBgColor(item.grade)}; color: {getGradeColor(item.grade)}">
												{item.grade} ({item.score})
											</span>
										</td>
										<td>{item.protocol_version}</td>
										<td>
											{item.subject_cn}
											{#if item.is_expired}<span class="expired-tag">❌</span>{/if}
										</td>
										<td class="time-cell">{formatDateTime(item.created_at)}</td>
										<td class="actions-cell">
											<button class="action-link" on:click={() => recheckFromHistory(item)} title={$tr('sslChecker.history.recheck')}>🔄</button>
											<button class="action-link" on:click={() => viewHistoryDetail(item)} title={$tr('sslChecker.history.viewDetail')}>👁️</button>
											<button class="action-link delete" on:click={() => deleteHistoryItem(item.id)} title={$tr('sslChecker.history.deleteRecord')}>🗑️</button>
										</td>
									</tr>
								{/each}
							</tbody>
						</table>
					</div>

					<div class="history-pagination">
						<button class="pagination-btn" disabled={historyCurrentPage === 1} on:click={() => { historyCurrentPage--; loadHistory(); }}>
							← {$tr('common.previous')}
						</button>
						<span class="pagination-info">{historyCurrentPage}</span>
						<button class="pagination-btn" disabled={history.length < historyPageSize} on:click={() => { historyCurrentPage++; loadHistory(); }}>
							{$tr('common.next')} →
						</button>
					</div>
				{/if}
			</div>
		</div>
	{/if}
</div>

{#if showTargetSelector}
	<div class="modal-overlay" on:click={() => showTargetSelector = false} on:keydown={(e) => e.key === 'Escape' && (showTargetSelector = false)}>
		<div class="modal-content target-selector-modal" on:click|stopPropagation on:keydown|stopPropagation>
			<div class="modal-header">
				<h2>🎯 {$tr('sslChecker.batch.targetSelector.title')}</h2>
				<button class="modal-close" on:click={() => showTargetSelector = false}>✕</button>
			</div>
			<div class="modal-body">
				<div class="target-search">
					<input type="text" bind:value={targetSearchQuery} placeholder={$tr('sslChecker.batch.targetSelector.searchPlaceholder')} />
				</div>
				{#if loadingTargets}
					<div class="loading-message">⏳ {$tr('sslChecker.batch.targetSelector.loading')}</div>
				{:else if filteredTargets.length === 0}
					<div class="empty-message">{$tr('sslChecker.batch.targetSelector.noTargets')}</div>
				{:else}
					<div class="target-list">
						{#each filteredTargets as t (t.id)}
							<div
								class="target-item {selectedTargets.some((st: any) => st.id === t.id) ? 'selected' : ''}"
								on:click={() => toggleTargetSelection(t)}
							>
								<div class="target-checkbox">
									{#if selectedTargets.some((st: any) => st.id === t.id)}✓{/if}
								</div>
								<div class="target-info">
									<span class="target-name">{t.name}</span>
									<span class="target-value">{t.target_value}</span>
								</div>
							</div>
						{/each}
					</div>
				{/if}
			</div>
			<div class="modal-footer">
				<span class="selected-count">{$tr('sslChecker.batch.targetSelector.selectedCount', { count: selectedTargets.length })}</span>
				<div class="modal-actions">
					<button class="btn btn-secondary" on:click={() => showTargetSelector = false}>{$tr('common.cancel')}</button>
					<button class="btn btn-primary" on:click={confirmTargetSelection} disabled={selectedTargets.length === 0}>
						{$tr('common.confirm')}
					</button>
				</div>
			</div>
		</div>
	</div>
{/if}

{#if showHistoryDetail && selectedHistoryItem}
	<div class="modal-overlay" on:click={() => showHistoryDetail = false} on:keydown={(e) => e.key === 'Escape' && (showHistoryDetail = false)}>
		<div class="modal-content history-detail-modal" on:click|stopPropagation on:keydown|stopPropagation>
			<div class="modal-header">
				<h2>📋 {$tr('sslChecker.history.detailTitle')}</h2>
				<button class="modal-close" on:click={() => showHistoryDetail = false}>✕</button>
			</div>
			<div class="modal-body">
				<div class="grade-header">
					<div class="grade-badge" style="background: {getGradeBgColor(selectedHistoryItem.overall_grade)}; border: 2px solid {getGradeColor(selectedHistoryItem.overall_grade)}">
						<span class="grade-letter" style="color: {getGradeColor(selectedHistoryItem.overall_grade)}">{selectedHistoryItem.overall_grade}</span>
						<span class="grade-score" style="color: {getGradeColor(selectedHistoryItem.overall_grade)}">{selectedHistoryItem.score}/100</span>
					</div>
					<div class="grade-info">
						<h3>{selectedHistoryItem.host}:{selectedHistoryItem.port}</h3>
						<p>{selectedHistoryItem.summary}</p>
					</div>
				</div>
				<div class="detail-section">
					<h4>🔒 {$tr('sslChecker.result.protocol')}</h4>
					<div class="detail-item">
						<span class="detail-label">{$tr('sslChecker.result.protocolVersion')}</span>
						<span class="detail-value">{selectedHistoryItem.protocol_version}</span>
					</div>
					<div class="detail-item">
						<span class="detail-label">{$tr('sslChecker.result.cipherSuite')}</span>
						<span class="detail-value">{selectedHistoryItem.cipher_name} ({selectedHistoryItem.cipher_bits} bits)</span>
					</div>
				</div>
				{#if selectedHistoryItem.certificate}
					<div class="detail-section">
						<h4>📜 {$tr('sslChecker.result.certificate')}</h4>
						<div class="detail-item">
							<span class="detail-label">{$tr('sslChecker.result.subject')}</span>
							<span class="detail-value">{selectedHistoryItem.certificate.subject_cn}</span>
						</div>
						<div class="detail-item">
							<span class="detail-label">{$tr('sslChecker.result.issuer')}</span>
							<span class="detail-value">{selectedHistoryItem.certificate.issuer_cn}</span>
						</div>
						<div class="detail-item">
							<span class="detail-label">{$tr('sslChecker.result.daysRemaining')}</span>
							<span class="detail-value">{selectedHistoryItem.certificate.days_remaining} {$tr('sslChecker.result.days')}</span>
						</div>
					</div>
				{/if}
			</div>
			<div class="modal-footer">
				<button class="btn btn-primary" on:click={() => { showHistoryDetail = false; recheckFromHistory(selectedHistoryItem); }}>
					🔄 {$tr('sslChecker.history.recheck')}
				</button>
				<button class="btn btn-secondary" on:click={() => showHistoryDetail = false}>{$tr('common.close')}</button>
			</div>
		</div>
	</div>
{/if}

{#if showConfirmDialog}
	<div class="modal-overlay" on:click={cancelConfirm}>
		<div class="modal-content confirm-modal" on:click|stopPropagation on:keydown|stopPropagation>
			<div class="modal-header">
				<h2>⚠️ {confirmDialogTitle}</h2>
			</div>
			<div class="modal-body">
				<p>{confirmDialogMessage}</p>
			</div>
			<div class="modal-footer">
				<button class="btn btn-secondary" on:click={cancelConfirm}>{$tr('common.cancel')}</button>
				<button class="btn btn-danger" on:click={executeConfirmAction}>{$tr('common.confirm')}</button>
			</div>
		</div>
	</div>
{/if}

{#if showHelpModal}
	<div class="modal-overlay" on:click={() => showHelpModal = false} on:keydown={(e) => e.key === 'Escape' && (showHelpModal = false)}>
		<div class="modal-content help-modal" on:click|stopPropagation on:keydown|stopPropagation>
			<div class="modal-header">
				<h2>📖 {$tr('sslChecker.help.title')}</h2>
				<button class="modal-close" on:click={() => showHelpModal = false}>✕</button>
			</div>
			<div class="modal-body">
				<div class="help-section">
					<h3>{$tr('sslChecker.help.whatIsSsl')}</h3>
					<p>{$tr('sslChecker.help.whatIsSslDesc')}</p>
				</div>
				<div class="help-section">
					<h3>{$tr('sslChecker.help.howToUse')}</h3>
					<ol>
						<li>{$tr('sslChecker.help.step1')}</li>
						<li>{$tr('sslChecker.help.step2')}</li>
						<li>{$tr('sslChecker.help.step3')}</li>
						<li>{$tr('sslChecker.help.step4')}</li>
					</ol>
				</div>
				<div class="help-section">
					<h3>{$tr('sslChecker.help.gradingSystem')}</h3>
					<ul class="tip-list">
						<li><strong>A (90-100):</strong> {$tr('sslChecker.help.gradeA')}</li>
						<li><strong>B (75-89):</strong> {$tr('sslChecker.help.gradeB')}</li>
						<li><strong>C (60-74):</strong> {$tr('sslChecker.help.gradeC')}</li>
						<li><strong>D (40-59):</strong> {$tr('sslChecker.help.gradeD')}</li>
						<li><strong>F (0-39):</strong> {$tr('sslChecker.help.gradeF')}</li>
					</ul>
				</div>
				<div class="help-section">
					<h3>{$tr('sslChecker.help.checkingItems')}</h3>
					<ul class="tip-list">
						<li>{$tr('sslChecker.help.checkProtocol')}</li>
						<li>{$tr('sslChecker.help.checkCipher')}</li>
						<li>{$tr('sslChecker.help.checkCert')}</li>
						<li>{$tr('sslChecker.help.checkKey')}</li>
					</ul>
				</div>
				<div class="help-section">
					<h3>{$tr('sslChecker.help.resultTitle')}</h3>
					<ul class="tip-list">
						<li>{$tr('sslChecker.help.resultFeatures.grade')}</li>
						<li>{$tr('sslChecker.help.resultFeatures.protocol')}</li>
						<li>{$tr('sslChecker.help.resultFeatures.cipher')}</li>
						<li>{$tr('sslChecker.help.resultFeatures.certificate')}</li>
						<li>{$tr('sslChecker.help.resultFeatures.key')}</li>
						<li>{$tr('sslChecker.help.resultFeatures.issues')}</li>
					</ul>
				</div>
				<div class="help-section">
					<h3>{$tr('sslChecker.help.warningTitle')}</h3>
					<ul class="tip-list">
						<li>{$tr('sslChecker.help.warnings.warning1')}</li>
						<li>{$tr('sslChecker.help.warnings.warning2')}</li>
						<li>{$tr('sslChecker.help.warnings.warning3')}</li>
						<li>{$tr('sslChecker.help.warnings.warning4')}</li>
					</ul>
				</div>
			</div>
			<div class="modal-footer">
				<button class="btn btn-primary" on:click={() => showHelpModal = false}>{$tr('common.close')}</button>
			</div>
		</div>
	</div>
{/if}

<style>
	.ssl-checker-page {
		padding: 1.5rem;
		max-width: 1200px;
		margin: 0 auto;
	}

	.page-header {
		display: flex;
		justify-content: space-between;
		align-items: flex-start;
		margin-bottom: 1.5rem;
	}

	.header-left {
		display: flex;
		flex-direction: column;
		gap: 0.25rem;
	}

	.back-link {
		color: var(--text-muted);
		text-decoration: none;
		font-size: 0.85rem;
		margin-bottom: 0.25rem;
	}

	.back-link:hover {
		color: var(--primary);
	}

	.page-title {
		font-size: 1.75rem;
		font-weight: 700;
		color: var(--text-primary);
		margin: 0;
	}

	.page-subtitle {
		color: var(--text-secondary);
		font-size: 0.9rem;
		margin: 0;
	}

	.help-button {
		padding: 0.5rem 1rem;
		border-radius: 8px;
		border: 1px solid rgba(168, 85, 247, 0.3);
		background: rgba(168, 85, 247, 0.1);
		color: var(--primary);
		cursor: pointer;
		font-size: 0.85rem;
	}

	.help-button:hover {
		background: rgba(168, 85, 247, 0.2);
	}

	.tabs {
		display: flex;
		gap: 0.5rem;
		margin-bottom: 1rem;
	}

	.tab-button {
		padding: 0.5rem 1rem;
		border-radius: 6px;
		border: 1px solid rgba(168, 85, 247, 0.2);
		background: transparent;
		color: var(--text-secondary);
		cursor: pointer;
		font-size: 0.85rem;
		transition: all 0.2s;
	}

	.tab-button.active {
		background: var(--primary);
		color: white;
		border-color: var(--primary);
	}

	.tab-button:hover {
		background: rgba(168, 85, 247, 0.1);
	}

	.content-grid {
		display: grid;
		grid-template-columns: 1fr 1.5fr;
		gap: 1.5rem;
	}

	.section-card {
		background: var(--card-bg);
		border: 1px solid rgba(168, 85, 247, 0.15);
		border-radius: 12px;
		padding: 1.5rem;
	}

	.section-title {
		font-size: 1.1rem;
		font-weight: 600;
		color: var(--text-primary);
		margin: 0 0 1rem 0;
	}

	.form-group {
		margin-bottom: 1rem;
	}

	.form-label {
		display: block;
		font-size: 0.85rem;
		font-weight: 500;
		color: var(--text-secondary);
		margin-bottom: 0.4rem;
	}

	.form-input {
		width: 100%;
		padding: 0.6rem 0.8rem;
		border-radius: 8px;
		border: 1px solid rgba(168, 85, 247, 0.2);
		background: var(--input-bg);
		color: var(--text-primary);
		font-size: 0.9rem;
		box-sizing: border-box;
	}

	.form-input:focus {
		outline: none;
		border-color: var(--primary);
		box-shadow: 0 0 0 2px rgba(168, 85, 247, 0.2);
	}

	.form-textarea {
		width: 100%;
		padding: 0.6rem 0.8rem;
		border-radius: 8px;
		border: 1px solid rgba(168, 85, 247, 0.2);
		background: var(--input-bg);
		color: var(--text-primary);
		font-size: 0.9rem;
		resize: vertical;
		font-family: monospace;
		box-sizing: border-box;
	}

	.form-textarea:focus {
		outline: none;
		border-color: var(--primary);
		box-shadow: 0 0 0 2px rgba(168, 85, 247, 0.2);
	}

	.textarea-actions {
		display: flex;
		gap: 0.5rem;
		margin-top: 0.5rem;
	}

	.action-btn {
		padding: 0.3rem 0.6rem;
		border-radius: 6px;
		border: 1px solid rgba(168, 85, 247, 0.2);
		background: rgba(168, 85, 247, 0.05);
		color: var(--text-secondary);
		cursor: pointer;
		font-size: 0.8rem;
	}

	.action-btn:hover {
		background: rgba(168, 85, 247, 0.15);
	}

	.button-group {
		display: flex;
		gap: 0.75rem;
		margin-top: 1rem;
	}

	.btn {
		padding: 0.6rem 1.2rem;
		border-radius: 8px;
		border: none;
		cursor: pointer;
		font-size: 0.9rem;
		font-weight: 500;
		transition: all 0.2s;
	}

	.btn:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

	.btn-primary {
		background: linear-gradient(135deg, #a855f7, #6366f1);
		color: white;
	}

	.btn-primary:hover:not(:disabled) {
		transform: translateY(-1px);
		box-shadow: 0 4px 12px rgba(168, 85, 247, 0.4);
	}

	.btn-secondary {
		background: rgba(168, 85, 247, 0.1);
		color: var(--text-secondary);
		border: 1px solid rgba(168, 85, 247, 0.2);
	}

	.btn-secondary:hover:not(:disabled) {
		background: rgba(168, 85, 247, 0.2);
	}

	.btn-danger {
		background: rgba(239, 68, 68, 0.1);
		color: #ef4444;
		border: 1px solid rgba(239, 68, 68, 0.2);
	}

	.btn-danger:hover:not(:disabled) {
		background: rgba(239, 68, 68, 0.2);
	}

	.error-card {
		display: flex;
		align-items: center;
		gap: 1rem;
		padding: 1rem;
		border-radius: 8px;
		background: rgba(239, 68, 68, 0.1);
		border: 1px solid rgba(239, 68, 68, 0.2);
	}

	.error-icon {
		font-size: 1.5rem;
	}

	.error-content h3 {
		color: #ef4444;
		margin: 0 0 0.25rem 0;
	}

	.error-content p {
		color: var(--text-secondary);
		margin: 0;
		font-size: 0.85rem;
	}

	.grade-header {
		display: flex;
		align-items: center;
		gap: 1.25rem;
		margin-bottom: 1.5rem;
		padding-bottom: 1rem;
		border-bottom: 1px solid rgba(168, 85, 247, 0.1);
	}

	.grade-badge {
		display: flex;
		flex-direction: column;
		align-items: center;
		justify-content: center;
		width: 80px;
		height: 80px;
		border-radius: 16px;
		flex-shrink: 0;
	}

	.grade-letter {
		font-size: 2rem;
		font-weight: 800;
		line-height: 1;
	}

	.grade-score {
		font-size: 0.75rem;
		font-weight: 600;
	}

	.grade-info h3 {
		color: var(--text-primary);
		margin: 0 0 0.25rem 0;
		font-size: 1.1rem;
	}

	.grade-summary {
		color: var(--text-secondary);
		font-size: 0.85rem;
		margin: 0;
	}

	.grade-badge-small {
		display: inline-block;
		padding: 0.15rem 0.5rem;
		border-radius: 4px;
		font-size: 0.75rem;
		font-weight: 600;
	}

	.ssl-details {
		display: flex;
		flex-direction: column;
		gap: 1rem;
	}

	.detail-section {
		padding: 0.75rem;
		border-radius: 8px;
		background: rgba(168, 85, 247, 0.03);
		border: 1px solid rgba(168, 85, 247, 0.08);
	}

	.detail-section h4 {
		color: var(--text-primary);
		margin: 0 0 0.75rem 0;
		font-size: 0.95rem;
	}

	.detail-section.issues {
		background: rgba(234, 179, 8, 0.05);
		border-color: rgba(234, 179, 8, 0.15);
	}

	.detail-item {
		display: flex;
		justify-content: space-between;
		align-items: flex-start;
		padding: 0.4rem 0;
		border-bottom: 1px solid rgba(168, 85, 247, 0.05);
		gap: 0.5rem;
	}

	.detail-item:last-child {
		border-bottom: none;
	}

	.detail-label {
		color: var(--text-secondary);
		font-size: 0.85rem;
		white-space: nowrap;
		flex-shrink: 0;
	}

	.detail-value {
		color: var(--text-primary);
		font-size: 0.85rem;
		text-align: right;
		word-break: break-all;
	}

	.detail-value.secure {
		color: #22c55e;
	}

	.detail-value.insecure {
		color: #ef4444;
	}

	.detail-value.expired {
		color: #ef4444;
		font-weight: 600;
	}

	.detail-value.warning {
		color: #eab308;
	}

	.san-list {
		display: flex;
		flex-wrap: wrap;
		gap: 0.25rem;
	}

	.san-tag {
		display: inline-block;
		padding: 0.1rem 0.4rem;
		border-radius: 4px;
		background: rgba(168, 85, 247, 0.1);
		color: var(--text-primary);
		font-size: 0.75rem;
	}

	.fingerprint {
		font-family: monospace;
		font-size: 0.7rem;
	}

	.issue-item {
		padding: 0.4rem 0.6rem;
		border-radius: 4px;
		margin-bottom: 0.4rem;
		font-size: 0.85rem;
	}

	.protocol-issue {
		background: rgba(239, 68, 68, 0.08);
		color: #f97316;
	}

	.cipher-issue {
		background: rgba(234, 179, 8, 0.08);
		color: #eab308;
	}

	.empty-state {
		text-align: center;
		padding: 2rem;
	}

	.empty-icon {
		font-size: 3rem;
		margin-bottom: 0.5rem;
	}

	.empty-state p {
		color: var(--text-secondary);
		margin: 0;
	}

	.empty-hint {
		font-size: 0.85rem;
		margin-top: 0.25rem !important;
	}

	.batch-stats {
		display: flex;
		gap: 1rem;
		margin-bottom: 1rem;
	}

	.stat-item {
		padding: 0.5rem 1rem;
		border-radius: 8px;
		background: rgba(168, 85, 247, 0.05);
		border: 1px solid rgba(168, 85, 247, 0.1);
	}

	.stat-item.success {
		background: rgba(34, 197, 94, 0.05);
		border-color: rgba(34, 197, 94, 0.15);
	}

	.stat-item.failed {
		background: rgba(239, 68, 68, 0.05);
		border-color: rgba(239, 68, 68, 0.15);
	}

	.stat-label {
		color: var(--text-secondary);
		font-size: 0.8rem;
		display: block;
	}

	.stat-value {
		color: var(--text-primary);
		font-size: 1.25rem;
		font-weight: 700;
	}

	.batch-results {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
	}

	.batch-item {
		padding: 0.75rem;
		border-radius: 8px;
		border: 1px solid rgba(168, 85, 247, 0.1);
	}

	.batch-item.success {
		background: rgba(34, 197, 94, 0.03);
		border-color: rgba(34, 197, 94, 0.1);
	}

	.batch-item.error {
		background: rgba(239, 68, 68, 0.03);
		border-color: rgba(239, 68, 68, 0.1);
	}

	.batch-item-header {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		flex-wrap: wrap;
	}

	.batch-host {
		font-weight: 600;
		color: var(--text-primary);
		font-family: monospace;
	}

	.batch-info {
		color: var(--text-secondary);
		font-size: 0.85rem;
	}

	.batch-error-text {
		color: #ef4444;
		font-size: 0.85rem;
	}

	.batch-item-details {
		display: flex;
		gap: 1rem;
		margin-top: 0.4rem;
		font-size: 0.8rem;
		color: var(--text-secondary);
	}

	.expired {
		color: #ef4444;
		font-weight: 600;
	}

	.pagination {
		display: flex;
		align-items: center;
		justify-content: center;
		gap: 0.75rem;
		margin-top: 1rem;
	}

	.pagination-btn {
		padding: 0.4rem 0.8rem;
		border-radius: 6px;
		border: 1px solid rgba(168, 85, 247, 0.2);
		background: transparent;
		color: var(--text-secondary);
		cursor: pointer;
	}

	.pagination-btn:disabled {
		opacity: 0.4;
		cursor: not-allowed;
	}

	.pagination-info {
		color: var(--text-secondary);
		font-size: 0.85rem;
	}

	.history-header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		margin-bottom: 1rem;
	}

	.history-actions {
		display: flex;
		gap: 0.5rem;
	}

	.history-table-wrapper {
		overflow-x: auto;
	}

	.history-table {
		width: 100%;
		border-collapse: collapse;
	}

	.history-table th {
		text-align: left;
		padding: 0.6rem;
		color: var(--text-secondary);
		font-size: 0.8rem;
		font-weight: 600;
		border-bottom: 1px solid rgba(168, 85, 247, 0.15);
	}

	.history-table td {
		padding: 0.6rem;
		border-bottom: 1px solid rgba(168, 85, 247, 0.05);
		font-size: 0.85rem;
	}

	.host-cell code {
		font-family: monospace;
		color: var(--primary);
	}

	.time-cell {
		color: var(--text-secondary);
		font-size: 0.8rem;
		white-space: nowrap;
	}

	.actions-cell {
		white-space: nowrap;
	}

	.action-link {
		background: none;
		border: none;
		cursor: pointer;
		padding: 0.2rem;
		font-size: 1rem;
	}

	.action-link.delete:hover {
		filter: brightness(1.3);
	}

	.expired-tag {
		margin-left: 0.25rem;
	}

	.history-pagination {
		display: flex;
		align-items: center;
		justify-content: center;
		gap: 0.75rem;
		margin-top: 1rem;
	}

	.modal-overlay {
		position: fixed;
		top: 0;
		left: 0;
		right: 0;
		bottom: 0;
		background: rgba(0, 0, 0, 0.6);
		display: flex;
		align-items: center;
		justify-content: center;
		z-index: 1000;
	}

	.modal-content {
		background: var(--card-bg);
		border-radius: 12px;
		max-width: 600px;
		width: 90%;
		max-height: 80vh;
		overflow-y: auto;
	}

	.target-selector-modal {
		max-width: 500px;
	}

	.history-detail-modal {
		max-width: 700px;
	}

	.confirm-modal {
		max-width: 400px;
	}

	.help-modal {
		max-width: 600px;
	}

	.modal-header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		padding: 1rem 1.5rem;
		border-bottom: 1px solid rgba(168, 85, 247, 0.1);
	}

	.modal-header h2 {
		margin: 0;
		font-size: 1.1rem;
		color: var(--text-primary);
	}

	.modal-close {
		background: none;
		border: none;
		color: var(--text-secondary);
		cursor: pointer;
		font-size: 1.2rem;
		padding: 0.25rem;
	}

	.modal-body {
		padding: 1.5rem;
	}

	.modal-footer {
		display: flex;
		justify-content: space-between;
		align-items: center;
		padding: 1rem 1.5rem;
		border-top: 1px solid rgba(168, 85, 247, 0.1);
	}

	.modal-actions {
		display: flex;
		gap: 0.5rem;
	}

	.selected-count {
		color: var(--text-secondary);
		font-size: 0.85rem;
	}

	.target-search input {
		width: 100%;
		padding: 0.5rem;
		border-radius: 6px;
		border: 1px solid rgba(168, 85, 247, 0.2);
		background: var(--input-bg);
		color: var(--text-primary);
		box-sizing: border-box;
	}

	.target-list {
		max-height: 300px;
		overflow-y: auto;
	}

	.target-item {
		display: flex;
		align-items: center;
		gap: 0.75rem;
		padding: 0.6rem;
		border-radius: 6px;
		cursor: pointer;
		transition: background 0.2s;
	}

	.target-item:hover {
		background: rgba(168, 85, 247, 0.05);
	}

	.target-item.selected {
		background: rgba(168, 85, 247, 0.1);
	}

	.target-checkbox {
		width: 20px;
		height: 20px;
		border: 2px solid rgba(168, 85, 247, 0.3);
		border-radius: 4px;
		display: flex;
		align-items: center;
		justify-content: center;
		flex-shrink: 0;
	}

	.target-item.selected .target-checkbox {
		background: var(--primary);
		border-color: var(--primary);
		color: white;
	}

	.target-info {
		display: flex;
		flex-direction: column;
	}

	.target-name {
		font-weight: 500;
		color: var(--text-primary);
	}

	.target-value {
		font-size: 0.8rem;
		color: var(--text-secondary);
	}

	.loading-message, .empty-message {
		text-align: center;
		padding: 1rem;
		color: var(--text-secondary);
	}

	.loading-state {
		text-align: center;
		padding: 2rem;
	}

	.spinner {
		width: 2rem;
		height: 2rem;
		border: 3px solid rgba(168, 85, 247, 0.2);
		border-top-color: var(--primary);
		border-radius: 50%;
		animation: spin 0.8s linear infinite;
		margin: 0 auto 0.5rem;
	}

	@keyframes spin {
		to { transform: rotate(360deg); }
	}

	.help-section {
		margin-bottom: 1.25rem;
	}

	.help-section h3 {
		color: var(--text-primary);
		margin: 0 0 0.5rem 0;
		font-size: 1rem;
	}

	.help-section p {
		color: var(--text-secondary);
		font-size: 0.85rem;
		margin: 0;
		line-height: 1.5;
	}

	.help-section ul {
		list-style: none;
		padding: 0;
		margin: 0;
	}

	.help-section li {
		padding: 0.25rem 0;
		color: var(--text-secondary);
		font-size: 0.85rem;
	}

	.input-hint {
		color: var(--text-muted);
		font-size: 0.8rem;
		margin-top: 0.25rem;
		display: block;
	}
</style>
