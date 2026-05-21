<script lang="ts">
	import { tr } from '$lib/i18n';
	import { open } from '@tauri-apps/plugin-dialog';
	import { readFile } from '@tauri-apps/plugin-fs';
import ToolHistory from '$lib/components/ToolHistory.svelte';
	import ToolHelp from '$lib/components/ToolHelp.svelte';

	interface HashTypeMatch {
		hash_type: string;
		description: string;
		confidence: number;
		length: number;
	}

	interface HashIdentification {
		hash_value: string;
		possible_types: HashTypeMatch[];
	}

	interface BatchHashResult {
		hash_value: string;
		result: HashIdentification | null;
		error: string | null;
	}

	let input = '';
	let result: HashIdentification | null = null;
	let batchResults: BatchHashResult[] = [];
	let error = '';
	let processing = false;
	let showHelpModal = false;
	let activeTab = 'single';
	let activeMainTab = 'identify';
	let historyComponent: ToolHistory;

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
	$: successCount = batchResults.filter(r => r.result && r.result.possible_types.length > 0).length;
	$: failedCount = batchResults.filter(r => r.error || (r.result && r.result.possible_types.length === 0)).length;

	async function identifyHash() {
		if (!input.trim()) {
			error = $tr('hashId.error.emptyInput');
			return;
		}

		processing = true;
		error = '';
		result = null;

		try {
			const { invoke } = await import('@tauri-apps/api/core');
			result = await invoke<HashIdentification>('identify_hash_command', { input: input.trim() });

			if (result.possible_types.length === 0) {
				error = $tr('hashId.error.noMatch');
			}

			if (result) {
				try {
					await invoke('save_hash_identifier_record', {
						hashValue: result.hash_value,
						possibleTypes: JSON.stringify(result.possible_types),
					});
				} catch (e) {
					console.error('Failed to save history:', e);
				}
			}
		} catch (e: any) {
			error = e.toString();
		} finally {
			processing = false;
		}
	}

	async function batchIdentify() {
		const hashes = input
			.split(/[\n,;]+/)
			.map(h => h.trim())
			.filter(h => h.length > 0);

		if (hashes.length === 0) {
			error = $tr('hashId.error.emptyInput');
			return;
		}

		processing = true;
		error = '';
		batchResults = [];

		try {
			const { invoke } = await import('@tauri-apps/api/core');
			for (const hash of hashes) {
				try {
					const r = await invoke<HashIdentification>('identify_hash_command', { input: hash });
					batchResults.push({ hash_value: hash, result: r, error: null });

					try {
						await invoke('save_hash_identifier_record', {
							hashValue: r.hash_value,
							possibleTypes: JSON.stringify(r.possible_types),
						});
					} catch (e) {
						console.error('Failed to save history:', e);
					}
				} catch (e: any) {
					batchResults.push({ hash_value: hash, result: null, error: e.toString() });
				}
			}
		} catch (e: any) {
			error = e.toString();
		} finally {
			processing = false;
		}
	}

	async function importHashes() {
		try {
			const selected = await open({
				multiple: false,
				filters: [{ name: 'Text', extensions: ['txt', 'csv', 'list'] }]
			});
			if (selected) {
				const fileData = await readFile(selected as string);
				const content = new TextDecoder('utf-8').decode(fileData);
				const hashes = content
					.split(/[\n,;]+/)
					.map(h => h.trim())
					.filter(h => h.length > 0);
				if (hashes.length > 0) {
					input = input ? `${input}\n${hashes.join('\n')}` : hashes.join('\n');
				}
			}
		} catch (e) {
			console.error('Import failed:', e);
		}
	}

	function getConfidenceColor(confidence: number): string {
		if (confidence >= 0.8) return '#10b981';
		if (confidence >= 0.5) return '#f59e0b';
		return '#ef4444';
	}

	function getConfidenceLabel(confidence: number): string {
		if (confidence >= 0.8) return $tr('hashId.confidence.high');
		if (confidence >= 0.5) return $tr('hashId.confidence.medium');
		return $tr('hashId.confidence.low');
	}

	function clearAll() {
		input = '';
		result = null;
		batchResults = [];
		error = '';
	}

	function switchTab(tab: string) {
		activeTab = tab;
		error = '';
		result = null;
		batchResults = [];
	}

	async function loadHistory() {
		loadingHistory = true;
		historyError = '';

		try {
			const { invoke } = await import('@tauri-apps/api/core');
			history = await invoke('get_hash_identifier_history', {
				limit: historyPageSize,
				offset: (historyCurrentPage - 1) * historyPageSize,
			});
		} catch (e) {
			historyError = `${$tr('hashId.history.messages.loadFailed')}: ${e}`;
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
			$tr('hashId.history.messages.deleteConfirm'),
			$tr('hashId.history.messages.deleteConfirmMessage'),
			async () => {
				try {
					const { invoke } = await import('@tauri-apps/api/core');
					await invoke('delete_hash_identifier_record', { id });
					await loadHistory();
				} catch (e) {
					historyError = `${$tr('hashId.history.messages.deleteFailed')}: ${e}`;
				}
			}
		);
	}

	async function clearAllHistory() {
		showConfirm(
			$tr('hashId.history.messages.clearAllConfirm'),
			$tr('hashId.history.messages.clearAllConfirmMessage'),
			async () => {
				try {
					const { invoke } = await import('@tauri-apps/api/core');
					await invoke('clear_hash_identifier_history');
					await loadHistory();
				} catch (e) {
					historyError = `${$tr('hashId.history.messages.clearFailed')}: ${e}`;
				}
			}
		);
	}

	function viewHistoryDetail(item: any) {
		selectedHistoryItem = item;
		showHistoryDetail = true;
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

	function parsePossibleTypes(possibleTypesStr: string): HashTypeMatch[] {
		try {
			return JSON.parse(possibleTypesStr);
		} catch {
			return [];
		}
	}
</script>

<div class="hash-identifier-page">
	<div class="page-header">
		<div class="header-left">
			<a href="/" class="back-link">{$tr('common.backToHome')}</a>
			<h1 class="page-title">🔍 {$tr('hashId.title')}</h1>
			<p class="page-subtitle">{$tr('hashId.subtitle')}</p>
		</div>
		<button class="help-button" on:click={() => showHelpModal = true}>
			{$tr('common.userManual')}
		</button>
	</div>

	<div class="main-tabs">
		<button
			class="main-tab-button {activeMainTab === 'identify' ? 'active' : ''}"
			on:click={() => activeMainTab = 'identify'}
		>
			🔍 {$tr('hashId.tabs.identify')}
		</button>
		<button
			class="main-tab-button {activeMainTab === 'history' ? 'active' : ''}"
			on:click={() => { activeMainTab = 'history'; loadHistory(); }}
		>
			📋 {$tr('hashId.tabs.history')}
		</button>
		<button
			class="main-tab-button {activeMainTab === 'help' ? 'active' : ''}"
			on:click={() => activeMainTab = 'help'}
		>
			📖 使用手册
		</button>
	</div>

	{#if activeMainTab === 'identify'}
	<div class="tabs">
		<button
			class="tab-button {activeTab === 'single' ? 'active' : ''}"
			on:click={() => switchTab('single')}
		>
			{$tr('hashId.tabs.single')}
		</button>
		<button
			class="tab-button {activeTab === 'batch' ? 'active' : ''}"
			on:click={() => switchTab('batch')}
		>
			{$tr('hashId.tabs.batch')}
		</button>
	</div>

	{#if activeTab === 'single'}
	<div class="content-grid">
		<div class="input-section">
			<div class="section-card">
				<h2 class="section-title">{$tr('hashId.input.title')}</h2>

				<div class="form-group">
					<label class="form-label">{$tr('hashId.input.label')}</label>
					<textarea
						bind:value={input}
						placeholder={$tr('hashId.input.placeholder')}
						class="form-textarea"
						rows="4"
						disabled={processing}
					></textarea>
				</div>

				<div class="button-group">
					<button
						class="btn btn-primary"
						on:click={identifyHash}
						disabled={processing || !input.trim()}
					>
						{#if processing}
							⏳ {$tr('hashId.buttons.analyzing')}
						{:else}
							🔍 {$tr('hashId.buttons.analyze')}
						{/if}
					</button>
					<button
						class="btn btn-secondary"
						on:click={clearAll}
						disabled={processing}
					>
						🗑️ {$tr('hashId.buttons.clear')}
					</button>
				</div>
			</div>
		</div>

		<div class="result-section">
			<div class="section-card">
				<h2 class="section-title">{$tr('hashId.result.title')}</h2>

				{#if error}
					<div class="error-card">
						<div class="error-icon">⚠️</div>
						<div class="error-content">
							<h3>{$tr('hashId.result.error')}</h3>
							<p>{error}</p>
						</div>
					</div>
				{:else if result}
					<div class="result-content">
						<div class="hash-display">
							<span class="hash-label">{$tr('hashId.result.hashValue')}</span>
							<code class="hash-value">{result.hash_value}</code>
						</div>

						<div class="matches-header">
							{$tr('hashId.result.possibleTypes')} ({result.possible_types.length})
						</div>

						<div class="matches-list">
							{#each result.possible_types as match, index}
								<div class="match-card" class:match-first={index === 0}>
									<div class="match-header">
										<span class="match-rank">#{index + 1}</span>
										<span class="match-type">{match.hash_type}</span>
										<span
											class="match-confidence"
											style="color: {getConfidenceColor(match.confidence)}"
										>
											{(match.confidence * 100).toFixed(0)}% {getConfidenceLabel(match.confidence)}
										</span>
									</div>
									<div class="match-description">{match.description}</div>
									<div class="match-meta">
										<span>{$tr('hashId.result.length')}: {match.length}</span>
									</div>
									<div class="confidence-bar">
										<div
											class="confidence-fill"
											style="width: {match.confidence * 100}%; background: {getConfidenceColor(match.confidence)}"
										></div>
									</div>
								</div>
							{/each}
						</div>
					</div>
				{:else}
					<div class="empty-state">
						<div class="empty-icon">🔍</div>
						<p>{$tr('hashId.result.empty')}</p>
						<p class="empty-hint">{$tr('hashId.result.hint')}</p>
					</div>
				{/if}
			</div>
		</div>
	</div>
	{:else}
	<div class="content-grid">
		<div class="input-section">
			<div class="section-card">
				<h2 class="section-title">{$tr('hashId.batch.inputTitle')}</h2>

				<div class="form-group">
					<label class="form-label">{$tr('hashId.batch.inputLabel')}</label>
					<div class="textarea-wrapper">
						<textarea
							bind:value={input}
							placeholder={$tr('hashId.batch.inputPlaceholder')}
							class="form-textarea"
							rows="8"
							disabled={processing}
						></textarea>
						<div class="textarea-actions">
							<button type="button" class="action-btn" on:click={importHashes} disabled={processing}>
								📥 {$tr('hashId.batch.import')}
							</button>
						</div>
					</div>
					<span class="input-hint">{$tr('hashId.batch.inputHint')}</span>
				</div>

				<div class="button-group">
					<button
						class="btn btn-primary"
						on:click={batchIdentify}
						disabled={processing || !input.trim()}
					>
						{#if processing}
							⏳ {$tr('hashId.buttons.analyzing')}
						{:else}
							🔍 {$tr('hashId.batch.identifyAll')}
						{/if}
					</button>
					<button
						class="btn btn-secondary"
						on:click={clearAll}
						disabled={processing}
					>
						🗑️ {$tr('hashId.buttons.clear')}
					</button>
				</div>
			</div>
		</div>

		<div class="result-section">
			<div class="section-card">
				<h2 class="section-title">{$tr('hashId.result.title')}</h2>

				{#if error}
					<div class="error-card">
						<div class="error-icon">⚠️</div>
						<div class="error-content">
							<h3>{$tr('hashId.result.error')}</h3>
							<p>{error}</p>
						</div>
					</div>
				{:else if batchResults.length > 0}
					<div class="results-info">
						<span class="results-count">{$tr('hashId.batch.total')}: {batchResults.length}</span>
						<span class="results-separator">|</span>
						<span class="success-count">✓ {$tr('hashId.batch.success')}: {successCount}</span>
						<span class="results-separator">|</span>
						<span class="failed-count">✗ {$tr('hashId.batch.failed')}: {failedCount}</span>
					</div>

					<div class="batch-results">
						{#each paginatedResults as item}
							<div class="result-item">
								<div class="result-item-header">
									<h3 class="hash-name">{item.hash_value}</h3>
									<div class="result-meta">
										{#if item.result}
											<span class="meta-badge type-badge">{item.result.possible_types.length} {$tr('hashId.batch.typesFound')}</span>
											{#if item.result.possible_types.length > 0}
												<span class="meta-badge best-badge">🏆 {item.result.possible_types[0].hash_type}</span>
											{/if}
										{/if}
									</div>
									</div>

								{#if item.result && item.result.possible_types.length > 0}
									<div class="mini-matches">
										{#each item.result.possible_types.slice(0, 3) as match, idx}
											<div class="mini-match">
												<span class="mini-match-type">{match.hash_type}</span>
												<span class="mini-match-conf" style="color: {getConfidenceColor(match.confidence)}">
													{(match.confidence * 100).toFixed(0)}%
												</span>
											</div>
										{/each}
										{#if item.result.possible_types.length > 3}
											<span class="more-types">+{item.result.possible_types.length - 3} more</span>
										{/if}
									</div>
								{:else if item.error}
									<div class="result-error">
										<span>⚠️</span> {item.error}
									</div>
								{:else}
									<div class="no-match">{$tr('hashId.error.noMatch')}</div>
								{/if}
							</div>
						{/each}
					</div>

					{#if totalPages > 1}
						<div class="pagination">
							<button class="pagination-btn" disabled={currentPage === 1} on:click={() => currentPage--}>
								← {$tr('common.previous')}
							</button>
							<span class="pagination-info">{currentPage} / {totalPages}</span>
							<button class="pagination-btn" disabled={currentPage === totalPages} on:click={() => currentPage++}>
								{$tr('common.next')} →
							</button>
						</div>
					{/if}
				{:else}
					<div class="empty-state">
						<div class="empty-icon">🔍</div>
						<p>{$tr('hashId.result.empty')}</p>
						<p class="empty-hint">{$tr('hashId.batch.hint')}</p>
					</div>
				{/if}
			</div>
		</div>
	</div>
	{/if}
	{:else}
		<div class="history-section">
			<div class="section-card">
				<div class="history-header">
					<h2 class="section-title">📋 {$tr('hashId.history.title')}</h2>
					<div class="history-actions">
						<button class="btn btn-secondary" on:click={loadHistory} disabled={loadingHistory}>
							🔄 {$tr('hashId.history.refresh')}
						</button>
						<button class="btn btn-danger" on:click={clearAllHistory} disabled={loadingHistory || history.length === 0}>
							🗑️ {$tr('hashId.history.clearAll')}
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
						<p>{$tr('hashId.history.empty')}</p>
						<p class="empty-hint">{$tr('hashId.history.hint')}</p>
					</div>
				{:else}
					<div class="history-table-wrapper">
						<table class="history-table">
							<thead>
								<tr>
									<th>{$tr('hashId.history.table.hashValue')}</th>
									<th>{$tr('hashId.history.table.topType')}</th>
									<th>{$tr('hashId.history.table.typesCount')}</th>
									<th>{$tr('hashId.history.table.time')}</th>
									<th>{$tr('hashId.history.table.actions')}</th>
								</tr>
							</thead>
							<tbody>
								{#each history as item}
									<tr>
										<td class="hash-cell"><code>{item.hash_value}</code></td>
										<td>
											{#if parsePossibleTypes(item.possible_types).length > 0}
												<span class="type-badge-main">{parsePossibleTypes(item.possible_types)[0].hash_type}</span>
											{:else}
												<span class="no-type">-</span>
											{/if}
										</td>
										<td>{parsePossibleTypes(item.possible_types).length}</td>
										<td class="time-cell">{formatDateTime(item.created_at)}</td>
										<td class="actions-cell">
											<button class="action-link" on:click={() => viewHistoryDetail(item)}>👁️</button>
											<button class="action-link delete" on:click={() => deleteHistoryItem(item.id)}>🗑️</button>
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

{#if showHistoryDetail && selectedHistoryItem}
	<div class="modal-overlay" on:click={() => showHistoryDetail = false} on:keydown={(e) => e.key === 'Escape' && (showHistoryDetail = false)}>
		<div class="modal-content" on:click|stopPropagation on:keydown|stopPropagation>
			<div class="modal-header">
				<h2>{$tr('hashId.history.detailTitle')}</h2>
				<button class="modal-close" on:click={() => showHistoryDetail = false}>✕</button>
			</div>
			<div class="modal-body">
				<div class="detail-section">
					<div class="detail-label">{$tr('hashId.result.hashValue')}</div>
					<code class="detail-value hash-detail-value">{selectedHistoryItem.hash_value}</code>
				</div>
				<div class="detail-section">
					<div class="detail-label">{$tr('hashId.result.possibleTypes')} ({parsePossibleTypes(selectedHistoryItem.possible_types).length})</div>
					<div class="detail-types">
						{#each parsePossibleTypes(selectedHistoryItem.possible_types) as match, index}
							<div class="match-card" class:match-first={index === 0}>
								<div class="match-header">
									<span class="match-rank">#{index + 1}</span>
									<span class="match-type">{match.hash_type}</span>
									<span class="match-confidence" style="color: {getConfidenceColor(match.confidence)}">
										{(match.confidence * 100).toFixed(0)}% {getConfidenceLabel(match.confidence)}
									</span>
								</div>
								<div class="match-description">{match.description}</div>
								<div class="confidence-bar">
									<div class="confidence-fill" style="width: {match.confidence * 100}%; background: {getConfidenceColor(match.confidence)}"></div>
								</div>
							</div>
						{/each}
					</div>
				</div>
				<div class="detail-section">
					<div class="detail-label">{$tr('hashId.history.table.time')}</div>
					<div class="detail-value">{formatDateTime(selectedHistoryItem.created_at)}</div>
				</div>
			</div>
		</div>
	</div>
{/if}

{#if showConfirmDialog}
	<div class="modal-overlay" on:click={cancelConfirm} on:keydown={(e) => e.key === 'Escape' && cancelConfirm()}>
		<div class="modal-content confirm-modal" on:click|stopPropagation on:keydown|stopPropagation>
			<div class="modal-header">
				<h2>⚠️ {confirmDialogTitle}</h2>
				<button class="modal-close" on:click={cancelConfirm}>✕</button>
			</div>
			<div class="modal-body">
				<p>{confirmDialogMessage}</p>
			</div>
			<div class="modal-footer">
				<button class="btn-cancel" on:click={cancelConfirm}>{$tr('common.cancel')}</button>
				<button class="btn-danger" on:click={executeConfirmAction}>{$tr('common.confirm')}</button>
			</div>
		</div>
	</div>
{/if}

{#if showHelpModal}
	<div class="modal-overlay" on:click={() => showHelpModal = false} on:keydown={(e) => e.key === 'Escape' && (showHelpModal = false)}>
		<div class="modal-content" on:click|stopPropagation on:keydown|stopPropagation>
			<div class="modal-header">
				<h2>{$tr('hashId.helpModal.title')}</h2>
				<button class="modal-close" on:click={() => showHelpModal = false}>✕</button>
			</div>
			<div class="modal-body">
				<section class="help-section">
					<h3>{$tr('hashId.helpModal.overview')}</h3>
					<p>{$tr('hashId.helpModal.overviewText')}</p>
				</section>
				<section class="help-section">
					<h3>{$tr('hashId.helpModal.supportedTypes')}</h3>
					<ul>
						<li><strong>MD5 / MD4 / NTLM / LM</strong> - 32 chars (128-bit)</li>
						<li><strong>SHA-1 / MySQL5</strong> - 40 chars (160-bit)</li>
						<li><strong>SHA-224</strong> - 56 chars (224-bit)</li>
						<li><strong>SHA-256 / SHA3-256 / HMAC-SHA256</strong> - 64 chars (256-bit)</li>
						<li><strong>SHA-384 / SHA3-384</strong> - 96 chars (384-bit)</li>
						<li><strong>SHA-512 / SHA3-512 / Whirlpool</strong> - 128 chars (512-bit)</li>
						<li><strong>CRC-16</strong> - 4 chars, <strong>CRC-32</strong> - 8 chars</li>
					</ul>
				</section>
				<section class="help-section">
					<h3>{$tr('hashId.helpModal.howToUse')}</h3>
					<ol>
						<li>{$tr('hashId.helpModal.step1')}</li>
						<li>{$tr('hashId.helpModal.step2')}</li>
						<li>{$tr('hashId.helpModal.step3')}</li>
					</ol>
				</section>
				<section class="help-section">
					<h3>{$tr('hashId.helpModal.tips')}</h3>
					<ul>
						<li>{$tr('hashId.helpModal.tip1')}</li>
						<li>{$tr('hashId.helpModal.tip2')}</li>
						<li>{$tr('hashId.helpModal.tip3')}</li>
					</ul>
				</section>
			</div>
		</div>
	</div>
{/if}

<style>
	.hash-identifier-page {
		padding: 2rem;
		max-width: 1400px;
		margin: 0 auto;
	}

	.page-header {
		display: flex;
		justify-content: space-between;
		align-items: flex-start;
		margin-bottom: 2rem;
	}

	.header-left {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
	}

	.back-link {
		color: var(--text-muted);
		text-decoration: none;
		font-size: 0.875rem;
		transition: color 0.2s;
	}

	.back-link:hover {
		color: var(--primary);
	}

	.page-title {
		font-size: 1.75rem;
		font-weight: 700;
		background: linear-gradient(135deg, #a855f7, #6366f1);
		-webkit-background-clip: text;
		-webkit-text-fill-color: transparent;
		background-clip: text;
	}

	.page-subtitle {
		color: var(--text-muted);
		font-size: 0.95rem;
	}

	.help-button {
		padding: 0.5rem 1rem;
		background: rgba(168, 85, 247, 0.1);
		border: 1px solid rgba(168, 85, 247, 0.3);
		border-radius: 0.5rem;
		color: #a855f7;
		cursor: pointer;
		font-size: 0.875rem;
		transition: all 0.2s;
	}

	.help-button:hover {
		background: rgba(168, 85, 247, 0.2);
	}

	.tabs {
		display: flex;
		gap: 0.5rem;
		margin-bottom: 1.5rem;
	}

	.tab-button {
		padding: 0.6rem 1.25rem;
		background: rgba(255, 255, 255, 0.03);
		border: 1px solid rgba(255, 255, 255, 0.08);
		border-radius: 0.5rem;
		color: var(--text-muted);
		cursor: pointer;
		font-size: 0.875rem;
		transition: all 0.2s;
	}

	.tab-button.active {
		background: rgba(168, 85, 247, 0.15);
		border-color: rgba(168, 85, 247, 0.4);
		color: #a855f7;
	}

	.tab-button:hover:not(.active) {
		background: rgba(255, 255, 255, 0.06);
	}

	.content-grid {
		display: grid;
		grid-template-columns: 1fr 1fr;
		gap: 2rem;
	}

	.section-card {
		background: rgba(255, 255, 255, 0.03);
		border: 1px solid rgba(255, 255, 255, 0.08);
		border-radius: 1rem;
		padding: 1.5rem;
	}

	.section-title {
		font-size: 1.1rem;
		font-weight: 600;
		margin-bottom: 1.25rem;
		color: var(--text-primary);
	}

	.form-group {
		margin-bottom: 1.25rem;
	}

	.form-label {
		display: block;
		margin-bottom: 0.5rem;
		font-size: 0.875rem;
		font-weight: 500;
		color: var(--text-secondary);
	}

	.form-textarea {
		width: 100%;
		padding: 0.75rem;
		background: rgba(0, 0, 0, 0.3);
		border: 1px solid rgba(255, 255, 255, 0.1);
		border-radius: 0.5rem;
		color: var(--text-primary);
		font-family: 'JetBrains Mono', monospace;
		font-size: 0.875rem;
		resize: vertical;
		transition: border-color 0.2s;
	}

	.form-textarea:focus {
		outline: none;
		border-color: var(--primary);
	}

	.textarea-wrapper {
		position: relative;
	}

	.textarea-actions {
		display: flex;
		gap: 0.5rem;
		margin-top: 0.5rem;
	}

	.action-btn {
		padding: 0.4rem 0.75rem;
		background: rgba(255, 255, 255, 0.05);
		border: 1px solid rgba(255, 255, 255, 0.1);
		border-radius: 0.375rem;
		color: var(--text-secondary);
		cursor: pointer;
		font-size: 0.8rem;
		transition: all 0.2s;
	}

	.action-btn:hover:not(:disabled) {
		background: rgba(255, 255, 255, 0.1);
		color: var(--text-primary);
	}

	.action-btn:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

	.input-hint {
		display: block;
		font-size: 0.75rem;
		color: var(--text-muted);
		margin-top: 0.35rem;
	}

	.button-group {
		display: flex;
		gap: 0.75rem;
	}

	.btn {
		padding: 0.75rem 1.5rem;
		border-radius: 0.5rem;
		font-size: 0.875rem;
		font-weight: 500;
		cursor: pointer;
		transition: all 0.2s;
		border: none;
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
		background: rgba(255, 255, 255, 0.05);
		border: 1px solid rgba(255, 255, 255, 0.1);
		color: var(--text-secondary);
	}

	.btn-secondary:hover:not(:disabled) {
		background: rgba(255, 255, 255, 0.1);
	}

	.error-card {
		display: flex;
		align-items: flex-start;
		gap: 1rem;
		padding: 1rem;
		background: rgba(239, 68, 68, 0.1);
		border: 1px solid rgba(239, 68, 68, 0.3);
		border-radius: 0.5rem;
	}

	.error-icon { font-size: 1.5rem; }

	.error-content h3 {
		color: #ef4444;
		font-size: 0.95rem;
		margin-bottom: 0.25rem;
	}

	.error-content p {
		color: var(--text-muted);
		font-size: 0.85rem;
	}

	.result-content {
		display: flex;
		flex-direction: column;
		gap: 1rem;
	}

	.hash-display {
		display: flex;
		flex-direction: column;
		gap: 0.25rem;
		padding: 0.75rem;
		background: rgba(0, 0, 0, 0.3);
		border-radius: 0.5rem;
		border: 1px solid rgba(255, 255, 255, 0.05);
	}

	.hash-label {
		font-size: 0.75rem;
		color: var(--text-muted);
		text-transform: uppercase;
		letter-spacing: 0.05em;
	}

	.hash-value {
		font-family: 'JetBrains Mono', monospace;
		font-size: 0.85rem;
		color: #a855f7;
		word-break: break-all;
	}

	.matches-header {
		font-size: 0.95rem;
		font-weight: 600;
		color: var(--text-primary);
		padding-top: 0.5rem;
		border-top: 1px solid rgba(255, 255, 255, 0.05);
	}

	.matches-list {
		display: flex;
		flex-direction: column;
		gap: 0.75rem;
	}

	.match-card {
		padding: 1rem;
		background: rgba(255, 255, 255, 0.03);
		border: 1px solid rgba(255, 255, 255, 0.08);
		border-radius: 0.5rem;
		transition: border-color 0.2s;
	}

	.match-card:hover {
		border-color: rgba(168, 85, 247, 0.3);
	}

	.match-first {
		border-color: rgba(16, 185, 129, 0.3);
		background: rgba(16, 185, 129, 0.05);
	}

	.match-header {
		display: flex;
		align-items: center;
		gap: 0.75rem;
		margin-bottom: 0.5rem;
	}

	.match-rank {
		font-size: 0.75rem;
		color: var(--text-muted);
		font-weight: 600;
	}

	.match-type {
		font-size: 1rem;
		font-weight: 700;
		color: var(--text-primary);
	}

	.match-confidence {
		margin-left: auto;
		font-size: 0.8rem;
		font-weight: 600;
	}

	.match-description {
		font-size: 0.85rem;
		color: var(--text-muted);
		margin-bottom: 0.5rem;
	}

	.match-meta {
		font-size: 0.75rem;
		color: var(--text-muted);
		margin-bottom: 0.5rem;
	}

	.confidence-bar {
		height: 4px;
		background: rgba(255, 255, 255, 0.05);
		border-radius: 2px;
		overflow: hidden;
	}

	.confidence-fill {
		height: 100%;
		border-radius: 2px;
		transition: width 0.5s ease;
	}

	.results-info {
		display: flex;
		align-items: center;
		gap: 0.75rem;
		padding: 0.75rem 1rem;
		background: rgba(255, 255, 255, 0.02);
		border-radius: 0.5rem;
		margin-bottom: 1rem;
		font-size: 0.85rem;
	}

	.results-count { color: var(--text-primary); }
	.success-count { color: #10b981; }
	.failed-count { color: #ef4444; }
	.results-separator { color: var(--text-muted); }

	.batch-results {
		display: flex;
		flex-direction: column;
		gap: 0.75rem;
	}

	.result-item {
		padding: 1rem;
		background: rgba(255, 255, 255, 0.02);
		border: 1px solid rgba(255, 255, 255, 0.06);
		border-radius: 0.5rem;
	}

	.result-item-header {
		display: flex;
		align-items: center;
		justify-content: space-between;
		margin-bottom: 0.75rem;
		flex-wrap: wrap;
		gap: 0.5rem;
	}

	.hash-name {
		font-size: 0.9rem;
		font-weight: 600;
		color: var(--text-primary);
		font-family: 'JetBrains Mono', monospace;
		word-break: break-all;
	}

	.result-meta {
		display: flex;
		gap: 0.5rem;
		flex-wrap: wrap;
	}

	.meta-badge {
		font-size: 0.7rem;
		padding: 0.15rem 0.5rem;
		border-radius: 0.375rem;
		font-weight: 500;
	}

	.type-badge {
		background: rgba(168, 85, 247, 0.1);
		color: #a855f7;
		border: 1px solid rgba(168, 85, 247, 0.2);
	}

	.best-badge {
		background: rgba(245, 158, 11, 0.1);
		color: #f59e0b;
		border: 1px solid rgba(245, 158, 11, 0.2);
	}

	.mini-matches {
		display: flex;
		flex-wrap: wrap;
		gap: 0.5rem;
		align-items: center;
	}

	.mini-match {
		display: flex;
		align-items: center;
		gap: 0.35rem;
		padding: 0.2rem 0.6rem;
		background: rgba(255, 255, 255, 0.03);
		border: 1px solid rgba(255, 255, 255, 0.06);
		border-radius: 0.375rem;
	}

	.mini-match-type {
		font-size: 0.8rem;
		font-weight: 600;
		color: var(--text-primary);
	}

	.mini-match-conf {
		font-size: 0.75rem;
		font-weight: 500;
	}

	.more-types {
		font-size: 0.75rem;
		color: var(--text-muted);
	}

	.result-error {
		font-size: 0.85rem;
		color: #ef4444;
		display: flex;
		align-items: center;
		gap: 0.35rem;
	}

	.no-match {
		font-size: 0.85rem;
		color: var(--text-muted);
	}

	.pagination {
		display: flex;
		align-items: center;
		justify-content: center;
		gap: 1rem;
		margin-top: 1rem;
	}

	.pagination-btn {
		padding: 0.4rem 1rem;
		background: rgba(255, 255, 255, 0.05);
		border: 1px solid rgba(255, 255, 255, 0.1);
		border-radius: 0.375rem;
		color: var(--text-secondary);
		cursor: pointer;
		font-size: 0.8rem;
	}

	.pagination-btn:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

	.pagination-info {
		font-size: 0.85rem;
		color: var(--text-muted);
	}

	.empty-state {
		text-align: center;
		padding: 3rem 1rem;
	}

	.empty-icon {
		font-size: 3rem;
		margin-bottom: 1rem;
		opacity: 0.5;
	}

	.empty-state p {
		color: var(--text-muted);
		font-size: 0.95rem;
	}

	.empty-hint {
		font-size: 0.85rem !important;
		margin-top: 0.5rem;
	}

	.modal-overlay {
		position: fixed;
		inset: 0;
		background: rgba(0, 0, 0, 0.7);
		display: flex;
		align-items: center;
		justify-content: center;
		z-index: 1000;
	}

	.modal-content {
		background: #1a1a2e;
		border: 1px solid rgba(168, 85, 247, 0.3);
		border-radius: 1rem;
		width: 90%;
		max-width: 700px;
		max-height: 80vh;
		overflow-y: auto;
	}

	.modal-header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		padding: 1.25rem 1.5rem;
		border-bottom: 1px solid rgba(255, 255, 255, 0.1);
	}

	.modal-header h2 {
		font-size: 1.1rem;
		font-weight: 600;
	}

	.modal-close {
		background: none;
		border: none;
		color: var(--text-muted);
		font-size: 1.25rem;
		cursor: pointer;
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
		border-top: 1px solid rgba(255, 255, 255, 0.1);
	}

	.help-section {
		margin-bottom: 1.5rem;
	}

	.help-section h3 {
		font-size: 1rem;
		font-weight: 600;
		margin-bottom: 0.75rem;
		color: #a855f7;
	}

	.help-section p {
		color: var(--text-muted);
		font-size: 0.9rem;
		line-height: 1.6;
	}

	.help-section ul, .help-section ol {
		padding-left: 1.5rem;
		color: var(--text-muted);
		font-size: 0.9rem;
		line-height: 1.8;
	}

	.help-section li {
		margin-bottom: 0.25rem;
	}

	@media (max-width: 768px) {
		.content-grid {
			grid-template-columns: 1fr;
		}
	}

	.main-tabs {
		display: flex;
		gap: 0.5rem;
		margin-bottom: 1.5rem;
	}

	.main-tab-button {
		padding: 0.7rem 1.5rem;
		background: rgba(255, 255, 255, 0.03);
		border: 1px solid rgba(255, 255, 255, 0.08);
		border-radius: 0.5rem;
		color: var(--text-muted);
		cursor: pointer;
		font-size: 0.9rem;
		font-weight: 500;
		transition: all 0.2s;
	}

	.main-tab-button.active {
		background: rgba(168, 85, 247, 0.15);
		border-color: rgba(168, 85, 247, 0.4);
		color: #a855f7;
	}

	.main-tab-button:hover:not(.active) {
		background: rgba(255, 255, 255, 0.06);
	}

	.history-section {
		margin-top: 0;
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

	.btn-danger {
		background: rgba(239, 68, 68, 0.1);
		border: 1px solid rgba(239, 68, 68, 0.3);
		color: #ef4444;
		padding: 0.5rem 1rem;
		border-radius: 0.5rem;
		cursor: pointer;
		font-size: 0.85rem;
	}

	.btn-danger:hover:not(:disabled) {
		background: rgba(239, 68, 68, 0.2);
	}

	.btn-danger:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

	.loading-state {
		text-align: center;
		padding: 3rem 1rem;
	}

	.spinner {
		width: 40px;
		height: 40px;
		border: 3px solid rgba(168, 85, 247, 0.2);
		border-top-color: #a855f7;
		border-radius: 50%;
		animation: spin 0.8s linear infinite;
		margin: 0 auto 1rem;
	}

	@keyframes spin {
		to { transform: rotate(360deg); }
	}

	.history-table-wrapper {
		overflow-x: auto;
	}

	.history-table {
		width: 100%;
		border-collapse: collapse;
		font-size: 0.85rem;
	}

	.history-table th {
		padding: 0.75rem 1rem;
		text-align: left;
		font-weight: 600;
		color: var(--text-secondary);
		border-bottom: 1px solid rgba(255, 255, 255, 0.1);
		font-size: 0.8rem;
		text-transform: uppercase;
		letter-spacing: 0.05em;
	}

	.history-table td {
		padding: 0.75rem 1rem;
		border-bottom: 1px solid rgba(255, 255, 255, 0.05);
		color: var(--text-primary);
	}

	.history-table tr:hover {
		background: rgba(255, 255, 255, 0.02);
	}

	.hash-cell code {
		font-family: 'JetBrains Mono', monospace;
		font-size: 0.8rem;
		color: #a855f7;
		word-break: break-all;
	}

	.type-badge-main {
		display: inline-block;
		padding: 0.15rem 0.5rem;
		background: rgba(168, 85, 247, 0.1);
		border: 1px solid rgba(168, 85, 247, 0.2);
		border-radius: 0.375rem;
		font-size: 0.8rem;
		font-weight: 600;
		color: #a855f7;
	}

	.no-type {
		color: var(--text-muted);
	}

	.time-cell {
		font-size: 0.8rem;
		color: var(--text-muted);
		white-space: nowrap;
	}

	.actions-cell {
		white-space: nowrap;
	}

	.action-link {
		background: none;
		border: none;
		cursor: pointer;
		font-size: 1rem;
		padding: 0.2rem 0.4rem;
		border-radius: 0.25rem;
		transition: background 0.2s;
	}

	.action-link:hover {
		background: rgba(255, 255, 255, 0.1);
	}

	.action-link.delete:hover {
		background: rgba(239, 68, 68, 0.2);
	}

	.history-pagination {
		display: flex;
		align-items: center;
		justify-content: center;
		gap: 1rem;
		margin-top: 1rem;
	}

	.confirm-modal .modal-body p {
		color: var(--text-secondary);
		font-size: 0.95rem;
		line-height: 1.6;
	}

	.detail-section {
		margin-bottom: 1.5rem;
	}

	.detail-label {
		font-size: 0.8rem;
		color: var(--text-muted);
		text-transform: uppercase;
		letter-spacing: 0.05em;
		margin-bottom: 0.5rem;
	}

	.detail-value {
		font-size: 0.9rem;
		color: var(--text-primary);
	}

	.hash-detail-value {
		font-family: 'JetBrains Mono', monospace;
		font-size: 0.85rem;
		color: #a855f7;
		word-break: break-all;
		background: rgba(0, 0, 0, 0.3);
		padding: 0.5rem 0.75rem;
		border-radius: 0.375rem;
		display: block;
	}

	.detail-types {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
	}
</style>
