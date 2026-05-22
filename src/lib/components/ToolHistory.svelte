<script lang="ts">
	import { onMount } from 'svelte';
	import { tr, t, getLocale } from '$lib/i18n';

	export let toolType: string;
	export let toolName: string;

	interface ToolHistoryItem {
		id: number;
		tool_type: string;
		tool_name: string;
		input_summary: string;
		result_summary: string | null;
		result_json: string;
		status: string;
		created_at: string;
	}

	let history: ToolHistoryItem[] = [];
	let loading = false;
	let error = '';
	let currentPage = 1;
	let pageSize = 20;
	let selectedItem: ToolHistoryItem | null = null;
	let showDetail = false;
	let showConfirm = false;
	let confirmAction: (() => Promise<void>) | null = null;
	let confirmMessage = '';

	$: totalPages = Math.ceil(history.length / pageSize);
	$: paginatedHistory = history.slice((currentPage - 1) * pageSize, currentPage * pageSize);

	export async function loadHistory() {
		loading = true;
		error = '';
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			history = await invoke<ToolHistoryItem[]>('get_tool_history', {
				toolType,
				limit: 100,
				offset: 0,
			});
		} catch (e: any) {
			const msg = e.toString();
			if (msg.includes('no such table')) {
				history = [];
			} else {
				error = msg;
			}
		} finally {
			loading = false;
		}
	}

	export async function saveHistory(inputSummary: string, resultJson: string, resultSummary?: string, status: string = 'completed') {
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			await invoke('save_tool_history', {
				toolType,
				toolName,
				inputSummary,
				resultSummary: resultSummary || null,
				resultJson,
				status,
			});
		} catch (e) {
			console.warn('Failed to save history:', e);
		}
	}

	async function deleteItem(id: number) {
		confirmMessage = t('toolHistory.deleteConfirm');
		confirmAction = async () => {
			try {
				const { invoke } = await import('@tauri-apps/api/core');
				await invoke('delete_tool_history', { id });
				await loadHistory();
			} catch (e: any) {
				error = e.toString();
			}
		};
		showConfirm = true;
	}

	async function clearAll() {
		confirmMessage = t('toolHistory.clearAllConfirm');
		confirmAction = async () => {
			try {
				const { invoke } = await import('@tauri-apps/api/core');
				await invoke('clear_tool_history', { toolType });
				await loadHistory();
			} catch (e: any) {
				error = e.toString();
			}
		};
		showConfirm = true;
	}

	async function executeConfirm() {
		showConfirm = false;
		if (confirmAction) {
			await confirmAction();
			confirmAction = null;
		}
	}

	function viewDetail(item: ToolHistoryItem) {
		selectedItem = item;
		showDetail = true;
	}

	function formatDateTime(dateStr: string): string {
		const date = new Date(dateStr);
		const loc = getLocale() === 'zh' ? 'zh-CN' : 'en-US';
		return date.toLocaleString(loc, {
			year: 'numeric',
			month: '2-digit',
			day: '2-digit',
			hour: '2-digit',
			minute: '2-digit',
			second: '2-digit',
		});
	}

	function getStatusBadge(status: string): string {
		switch (status) {
			case 'completed': return '✅';
			case 'failed': return '❌';
			case 'error': return '⚠️';
			default: return 'ℹ️';
		}
	}

	onMount(() => {
		loadHistory();
	});
</script>

<div class="tool-history">
	<div class="history-header">
		<h3 class="history-title">{$tr('toolHistory.title')}</h3>
		<div class="history-actions">
			<button class="btn-icon" on:click={loadHistory} disabled={loading} title={$tr('toolHistory.refresh')}>🔄</button>
			<button class="btn-icon btn-danger" on:click={clearAll} disabled={loading || history.length === 0} title={$tr('toolHistory.clearAll')}>🗑️</button>
		</div>
	</div>

	{#if error}
		<div class="history-error">⚠️ {error}</div>
	{/if}

	{#if loading}
		<div class="history-loading">
			<div class="spinner"></div>
			<span>{$tr('common.loading')}</span>
		</div>
	{:else if history.length === 0}
		<div class="history-empty">
			<div class="empty-icon">📋</div>
			<p>{$tr('toolHistory.emptyTitle')}</p>
			<p class="empty-hint">{$tr('toolHistory.emptyHint')}</p>
		</div>
	{:else}
		<div class="history-list">
			{#each paginatedHistory as item}
				<div class="history-item" on:click={() => viewDetail(item)}>
					<div class="item-header">
						<span class="item-status">{getStatusBadge(item.status)}</span>
						<span class="item-input">{item.input_summary}</span>
						<span class="item-time">{formatDateTime(item.created_at)}</span>
					</div>
					{#if item.result_summary}
						<div class="item-summary">{item.result_summary}</div>
					{/if}
					<div class="item-footer">
						<button class="btn-delete" on:click|stopPropagation={() => deleteItem(item.id)} title={$tr('common.delete')}>🗑️</button>
					</div>
				</div>
			{/each}
		</div>

		{#if totalPages > 1}
			<div class="pagination">
				<button class="page-btn" disabled={currentPage === 1} on:click={() => currentPage--}>←</button>
				<span class="page-info">{currentPage} / {totalPages}</span>
				<button class="page-btn" disabled={currentPage === totalPages} on:click={() => currentPage++}>→</button>
			</div>
		{/if}
	{/if}

	{#if showDetail && selectedItem}
		<div class="modal-overlay" on:click={() => showDetail = false}>
			<div class="modal-content" on:click|stopPropagation>
				<div class="modal-header">
					<h3>{$tr('toolHistory.detailTitle')}</h3>
					<button class="modal-close" on:click={() => showDetail = false}>✕</button>
				</div>
				<div class="modal-body">
					<div class="detail-row">
						<span class="detail-label">{$tr('toolHistory.labelTool')}</span>
						<span class="detail-value">{selectedItem.tool_name}</span>
					</div>
					<div class="detail-row">
						<span class="detail-label">{$tr('toolHistory.labelInput')}</span>
						<span class="detail-value">{selectedItem.input_summary}</span>
					</div>
					<div class="detail-row">
						<span class="detail-label">{$tr('toolHistory.labelStatus')}</span>
						<span class="detail-value">{getStatusBadge(selectedItem.status)} {selectedItem.status}</span>
					</div>
					<div class="detail-row">
						<span class="detail-label">{$tr('toolHistory.labelTime')}</span>
						<span class="detail-value">{formatDateTime(selectedItem.created_at)}</span>
					</div>
					{#if selectedItem.result_summary}
						<div class="detail-row">
							<span class="detail-label">{$tr('toolHistory.labelSummary')}</span>
							<span class="detail-value">{selectedItem.result_summary}</span>
						</div>
					{/if}
					<div class="detail-json">
						<div class="detail-label">{$tr('toolHistory.labelDetailResult')}</div>
						<pre class="json-content">{JSON.stringify(JSON.parse(selectedItem.result_json), null, 2)}</pre>
					</div>
				</div>
			</div>
		</div>
	{/if}

	{#if showConfirm}
		<div class="modal-overlay" on:click={() => showConfirm = false}>
			<div class="confirm-dialog" on:click|stopPropagation>
				<p>{confirmMessage}</p>
				<div class="confirm-actions">
					<button class="btn-secondary" on:click={() => showConfirm = false}>{$tr('common.cancel')}</button>
					<button class="btn-danger" on:click={executeConfirm}>{$tr('common.confirm')}</button>
				</div>
			</div>
		</div>
	{/if}
</div>

<style>
	.tool-history { display: flex; flex-direction: column; height: 100%; }
	.history-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
	.history-title { font-size: 1rem; margin: 0; }
	.history-actions { display: flex; gap: 6px; }
	.btn-icon { background: none; border: 1px solid var(--border); border-radius: 6px; padding: 4px 8px; cursor: pointer; font-size: 0.85rem; }
	.btn-icon:hover { background: var(--bg-primary); }
	.btn-icon:disabled { opacity: 0.4; cursor: not-allowed; }
	.btn-icon.btn-danger:hover { background: rgba(239,68,68,0.1); border-color: #ef4444; }
	.history-error { padding: 8px 12px; background: rgba(239,68,68,0.1); border-radius: 8px; color: #ef4444; font-size: 0.85rem; margin-bottom: 8px; }
	.history-loading { display: flex; align-items: center; justify-content: center; gap: 8px; padding: 30px; color: var(--text-secondary); }
	.spinner { width: 20px; height: 20px; border: 2px solid var(--border); border-top-color: var(--accent); border-radius: 50%; animation: spin 0.8s linear infinite; }
	@keyframes spin { to { transform: rotate(360deg); } }
	.history-empty { text-align: center; padding: 30px; color: var(--text-secondary); }
	.empty-icon { font-size: 2.5rem; margin-bottom: 8px; }
	.empty-hint { font-size: 0.8rem; color: var(--text-secondary); opacity: 0.7; }
	.history-list { display: flex; flex-direction: column; gap: 6px; flex: 1; overflow-y: auto; }
	.history-item { padding: 10px 12px; background: var(--bg-primary); border-radius: 8px; border: 1px solid var(--border); cursor: pointer; transition: all 0.2s; }
	.history-item:hover { border-color: var(--accent); transform: translateX(2px); }
	.item-header { display: flex; align-items: center; gap: 8px; }
	.item-status { font-size: 0.85rem; }
	.item-input { flex: 1; font-size: 0.85rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
	.item-time { font-size: 0.75rem; color: var(--text-secondary); white-space: nowrap; }
	.item-summary { font-size: 0.8rem; color: var(--text-secondary); margin-top: 4px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
	.item-footer { display: flex; justify-content: flex-end; margin-top: 4px; }
	.btn-delete { background: none; border: none; cursor: pointer; font-size: 0.8rem; opacity: 0; transition: opacity 0.2s; padding: 2px 4px; }
	.history-item:hover .btn-delete { opacity: 0.6; }
	.btn-delete:hover { opacity: 1 !important; }
	.pagination { display: flex; justify-content: center; align-items: center; gap: 12px; margin-top: 12px; padding-top: 12px; border-top: 1px solid var(--border); }
	.page-btn { background: var(--bg-primary); border: 1px solid var(--border); border-radius: 6px; padding: 4px 10px; cursor: pointer; font-size: 0.85rem; }
	.page-btn:disabled { opacity: 0.4; cursor: not-allowed; }
	.page-info { font-size: 0.85rem; color: var(--text-secondary); }
	.modal-overlay { position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.5); display: flex; align-items: center; justify-content: center; z-index: 1000; }
	.modal-content { background: var(--bg-secondary); border-radius: 12px; padding: 20px; max-width: 700px; width: 90%; max-height: 80vh; overflow-y: auto; }
	.modal-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; }
	.modal-header h3 { margin: 0; }
	.modal-close { background: none; border: none; cursor: pointer; font-size: 1.2rem; color: var(--text-secondary); }
	.modal-body { display: flex; flex-direction: column; gap: 10px; }
	.detail-row { display: flex; gap: 8px; font-size: 0.9rem; }
	.detail-label { color: var(--text-secondary); min-width: 60px; }
	.detail-value { flex: 1; word-break: break-all; }
	.detail-json { margin-top: 8px; }
	.json-content { background: var(--bg-primary); border-radius: 8px; padding: 12px; font-size: 0.8rem; overflow-x: auto; max-height: 400px; overflow-y: auto; white-space: pre-wrap; word-break: break-all; }
	.confirm-dialog { background: var(--bg-secondary); border-radius: 12px; padding: 20px; max-width: 400px; width: 90%; text-align: center; }
	.confirm-dialog p { margin: 0 0 16px; font-size: 0.95rem; }
	.confirm-actions { display: flex; gap: 8px; justify-content: center; }
	.btn-secondary { padding: 8px 20px; border-radius: 8px; border: 1px solid var(--border); background: var(--bg-primary); cursor: pointer; font-size: 0.9rem; }
	.btn-danger { padding: 8px 20px; border-radius: 8px; border: none; background: #ef4444; color: white; cursor: pointer; font-size: 0.9rem; }
</style>
