<script lang="ts">
  import { invoke } from '@tauri-apps/api/core';
  import { onMount } from 'svelte';
  import { tr, t } from '$lib/i18n';

  interface PortMarkingData {
    port: number;
    mark_type: string;
    note?: string;
    created_at?: string;
    updated_at?: string;
  }

  let markings: PortMarkingData[] = [];
  let showAddModal = false;
  let editingPort: number | null = null;
  
  let newMarking = {
    port: '',
    markType: 'favorite',
    note: ''
  };

  interface MarkTypeOption {
    value: string;
    labelKey: string;
    color: string;
  }

  const markTypes: MarkTypeOption[] = [
    { value: 'favorite', labelKey: 'portMarker.markTypeFavorite', color: '#fbbf24' },
    { value: 'important', labelKey: 'portMarker.markTypeImportant', color: '#ef4444' },
    { value: 'dangerous', labelKey: 'portMarker.markTypeDangerous', color: '#f97316' },
  ];

  async function loadMarkings() {
    try {
      markings = await invoke('get_all_port_markings');
      console.log('Loaded port markings:', markings.length);
    } catch (error) {
      console.error('Failed to load port markings:', error);
    }
  }

  function openAddModal() {
    editingPort = null;
    newMarking = {
      port: '',
      markType: 'favorite',
      note: ''
    };
    showAddModal = true;
  }

  function editMarking(marking: PortMarkingData) {
    editingPort = marking.port;
    newMarking = {
      port: marking.port.toString(),
      markType: marking.mark_type,
      note: marking.note || ''
    };
    showAddModal = true;
  }

  async function saveMarking() {
    if (!newMarking.port || !newMarking.port.match(/^\d+$/)) {
      alert(t('portMarker.errors.invalidPort'));
      return;
    }

    try {
      await invoke('mark_port', {
        port: parseInt(newMarking.port),
        markType: newMarking.markType,
        note: newMarking.note
      });
      
      console.log(`Port ${newMarking.port} marked as ${newMarking.markType}`);
      showAddModal = false;
      await loadMarkings();
    } catch (error) {
      console.error('Failed to save marking:', error);
      alert(t('portMarker.errors.saveFailed', { error: String(error) }));
    }
  }

  async function removeMarking(port: number) {
    if (!confirm(t('portMarker.deleteConfirm', { port }))) return;

    try {
      await invoke('unmark_port', { port });
      console.log(`Port ${port} unmarked`);
      await loadMarkings();
    } catch (error) {
      console.error('Failed to unmark port:', error);
      alert(t('portMarker.errors.deleteFailed', { error: String(error) }));
    }
  }

  async function exportMarkings() {
    try {
      const json: string = await invoke('export_port_markings');
      
      const blob = new Blob([json], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      const dateStr = new Date().toISOString().split('T')[0] || '';
      a.download = `port-markings-${dateStr}.json`;
      a.click();
      URL.revokeObjectURL(url);
      
      console.log('Port markings exported');
    } catch (error) {
      console.error('Failed to export markings:', error);
      alert(t('portMarker.errors.exportFailed', { error: String(error) }));
    }
  }

  async function importMarkings() {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.json';
    
    input.onchange = async (e: Event) => {
      const target = e.target as HTMLInputElement;
      if (!target.files || !target.files[0]) return;
      
      const file = target.files[0];
      const reader = new FileReader();
      reader.onload = async (event: ProgressEvent<FileReader>) => {
        const eventTarget = event.target as FileReader;
        if (!eventTarget.result) return;
        
        try {
          const count = await invoke<number>('import_port_markings', {
            jsonData: eventTarget.result
          });
          
          alert(t('portMarker.importSuccess', { count }));
          await loadMarkings();
        } catch (error) {
          console.error('Failed to import markings:', error);
          alert(t('portMarker.errors.importFailed', { error: String(error) }));
        }
      };
      reader.readAsText(file);
    };

    input.click();
  }

  function getMarkTypeIcon(type: string): string {
    switch(type) {
      case 'favorite': return '⭐';
      case 'important': return '🔴';
      case 'dangerous': return '⚠️';
      default: return '📌';
    }
  }

  function getMarkTypeLabel(type: string): string {
    const opt = markTypes.find(mt => mt.value === type);
    return opt ? t(opt.labelKey) : (type || t('portMarker.markTypeCustom'));
  }

  function getMarkTypeColor(type: string): string {
    switch(type) {
      case 'favorite': return '#fbbf24';
      case 'important': return '#ef4444';
      case 'dangerous': return '#f97316';
      default: return '#8b5cf6';
    }
  }

  onMount(() => {
    loadMarkings();
  });
</script>

<div class="container">
  <div class="header">
    <h2>{$tr('portMarker.title')}</h2>
    <p class="subtitle">{$tr('portMarker.subtitle')}</p>
  </div>

  <div class="actions-bar">
    <button class="btn btn-primary" on:click={openAddModal}>
      {$tr('portMarker.addButton')}
    </button>
    
    <button class="btn btn-secondary" on:click={exportMarkings}>
      {$tr('portMarker.exportButton')}
    </button>
    
    <button class="btn btn-secondary" on:click={importMarkings}>
      {$tr('portMarker.importButton')}
    </button>
  </div>

  {#if markings.length > 0}
    <div class="markings-grid">
      {#each markings as marking (marking.port)}
        <div class="marking-card" style="border-left-color: {getMarkTypeColor(marking.mark_type)};">
          <div class="card-header">
            <span class="port-number">:{marking.port}</span>
            <span class="mark-badge" style="background-color: {getMarkTypeColor(marking.mark_type)};">
              {getMarkTypeIcon(marking.mark_type)} {getMarkTypeLabel(marking.mark_type)}
            </span>
          </div>
          
          {#if marking.note}
            <div class="card-note">{marking.note}</div>
          {/if}
          
          <div class="card-meta">
            {#if marking.created_at}
              <small>{$tr('portMarker.createdLabel')}{new Date(marking.created_at).toLocaleString()}</small>
            {/if}
            {#if marking.updated_at}
              <small>{$tr('portMarker.updatedLabel')}{new Date(marking.updated_at).toLocaleString()}</small>
            {/if}
          </div>
          
          <div class="card-actions">
            <button class="btn-icon" on:click={() => editMarking(marking)} title={$tr('portMarker.editTooltip')}>
              ✏️
            </button>
            <button class="btn-icon danger" on:click={() => removeMarking(marking.port)} title={$tr('portMarker.deleteTooltip')}>
              🗑️
            </button>
          </div>
        </div>
      {/each}
    </div>
  {:else}
    <div class="empty-state">
      <div class="empty-icon">📝</div>
      <h3>{$tr('portMarker.emptyTitle')}</h3>
      <p>{$tr('portMarker.emptyHint')}</p>
    </div>
  {/if}
</div>

{#if showAddModal}
  <div class="modal-overlay" on:click|self={() => showAddModal = false}>
    <div class="modal-content">
      <div class="modal-header">
        <h3>{editingPort ? $tr('portMarker.editTitle') : $tr('portMarker.addTitle')}</h3>
        <button class="close-btn" on:click={() => showAddModal = false}>×</button>
      </div>
      
      <form on:submit|preventDefault={saveMarking}>
        <div class="form-group">
          <label for="port">{$tr('portMarker.portLabel')}</label>
          <input
            type="number"
            id="port"
            bind:value={newMarking.port}
            placeholder={$tr('portMarker.portPlaceholder')}
            min="1"
            max="65535"
            required
          />
        </div>

        <div class="form-group">
          <label>{$tr('portMarker.markTypeLabel')}</label>
          <div class="mark-type-options">
            {#each markTypes as type}
              <label class="radio-option" style="--color: {type.color}">
                <input
                  type="radio"
                  bind:group={newMarking.markType}
                  value={type.value}
                />
                <span>{$tr(type.labelKey)}</span>
              </label>
            {/each}
          </div>
        </div>

        <div class="form-group">
          <label for="note">{$tr('portMarker.noteLabel')}</label>
          <textarea
            id="note"
            bind:value={newMarking.note}
            placeholder={$tr('portMarker.notePlaceholder')}
            rows="3"
          ></textarea>
        </div>

        <div class="modal-actions">
          <button type="button" class="btn btn-secondary" on:click={() => showAddModal = false}>
            {$tr('common.cancel')}
          </button>
          <button type="submit" class="btn btn-primary">
            {$tr('portMarker.saveButton')}
          </button>
        </div>
      </form>
    </div>
  </div>
{/if}

<style>
  .container {
    padding: 20px;
    max-width: 1200px;
    margin: 0 auto;
  }

  .header {
    text-align: center;
    margin-bottom: 30px;
  }

  .header h2 {
    font-size: 28px;
    margin-bottom: 10px;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
  }

  .subtitle {
    color: #666;
    font-size: 14px;
  }

  .actions-bar {
    display: flex;
    gap: 12px;
    justify-content: center;
    margin-bottom: 30px;
    flex-wrap: wrap;
  }

  .btn {
    padding: 10px 20px;
    border-radius: 8px;
    border: none;
    cursor: pointer;
    font-size: 14px;
    transition: all 0.2s ease;
    display: inline-flex;
    align-items: center;
    gap: 6px;
  }

  .btn-primary {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
  }

  .btn-primary:hover {
    transform: translateY(-2px);
    box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4);
  }

  .btn-secondary {
    background: white;
    color: #333;
    border: 2px solid #e5e7eb;
  }

  .btn-secondary:hover {
    border-color: #667eea;
    color: #667eea;
  }

  .markings-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
    gap: 20px;
  }

  .marking-card {
    background: white;
    border-radius: 12px;
    padding: 20px;
    border-left: 4px solid #ddd;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.08);
    transition: all 0.3s ease;
  }

  .marking-card:hover {
    transform: translateY(-4px);
    box-shadow: 0 8px 24px rgba(0, 0, 0, 0.15);
  }

  .card-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 12px;
  }

  .port-number {
    font-size: 32px;
    font-weight: bold;
    color: #333;
  }

  .mark-badge {
    padding: 4px 12px;
    border-radius: 20px;
    font-size: 13px;
    color: white;
    font-weight: 500;
  }

  .card-note {
    color: #555;
    font-size: 14px;
    line-height: 1.5;
    margin-bottom: 12px;
    min-height: 21px;
  }

  .card-meta {
    color: #999;
    font-size: 12px;
    margin-bottom: 12px;
  }

  .card-meta small {
    display: block;
    margin-top: 2px;
  }

  .card-actions {
    display: flex;
    gap: 8px;
    justify-content: flex-end;
  }

  .btn-icon {
    background: none;
    border: none;
    cursor: pointer;
    font-size: 18px;
    padding: 6px;
    border-radius: 6px;
    transition: background 0.2s;
  }

  .btn-icon:hover {
    background: #f3f4f6;
  }

  .btn-icon.danger:hover {
    background: #fee2e2;
  }

  .empty-state {
    text-align: center;
    padding: 60px 20px;
    color: #999;
  }

  .empty-icon {
    font-size: 64px;
    margin-bottom: 16px;
  }

  .empty-state h3 {
    color: #666;
    margin-bottom: 8px;
  }

  /* Modal Styles */
  .modal-overlay {
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: rgba(0, 0, 0, 0.5);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 1000;
  }

  .modal-content {
    background: white;
    border-radius: 16px;
    padding: 30px;
    width: 90%;
    max-width: 500px;
    max-height: 90vh;
    overflow-y: auto;
  }

  .modal-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 24px;
  }

  .modal-header h3 {
    margin: 0;
    font-size: 20px;
  }

  .close-btn {
    background: none;
    border: none;
    font-size: 28px;
    cursor: pointer;
    color: #999;
    line-height: 1;
  }

  .close-btn:hover {
    color: #333;
  }

  .form-group {
    margin-bottom: 20px;
  }

  .form-group label {
    display: block;
    margin-bottom: 8px;
    font-weight: 500;
    color: #374151;
  }

  .form-group input,
  .form-group textarea {
    width: 100%;
    padding: 10px 14px;
    border: 2px solid #e5e7eb;
    border-radius: 8px;
    font-size: 14px;
    transition: border-color 0.2s;
    box-sizing: border-box;
    font-family: inherit;
  }

  .form-group input:focus,
  .form-group textarea:focus {
    outline: none;
    border-color: #667eea;
  }

  .mark-type-options {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 10px;
  }

  .radio-option {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 12px;
    border: 2px solid var(--color, #e5e7eb);
    border-radius: 8px;
    cursor: pointer;
    transition: all 0.2s;
  }

  .radio-option:hover {
    border-color: var(--color);
    background: rgba(var(--color), 0.05);
  }

  .radio-option input[type="radio"] {
    accent-color: var(--color);
  }

  .radio-option span {
    font-size: 14px;
  }

  .modal-actions {
    display: flex;
    gap: 12px;
    justify-content: flex-end;
    margin-top: 24px;
  }

  @media (max-width: 768px) {
    .markings-grid {
      grid-template-columns: 1fr;
    }

    .actions-bar {
      flex-direction: column;
    }

    .btn {
      width: 100%;
      justify-content: center;
    }
  }
</style>
