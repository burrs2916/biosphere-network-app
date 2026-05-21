<script lang="ts">
  import { tr } from '$lib/i18n';

  export let tool: {
    id: string;
    name: string;
    description: string;
    icon: string;
    category: string;
    installed: boolean;
  };

  export let compact = false;
</script>

<article class="tool-card" class:compact>
  <div class="card-header">
    <div class="tool-icon">{tool.icon}</div>
    <div class="tool-status">
      {#if tool.installed}
        <span class="badge success">✓ {$tr('toolCard.installed')}</span>
      {:else}
        <span class="badge">{$tr('toolCard.notInstalled')}</span>
      {/if}
    </div>
  </div>

  <div class="card-body">
    <h3 class="tool-name">{tool.name}</h3>
    <p class="tool-description">{tool.description}</p>
    <div class="tool-category">
      <span class="category-tag">{tool.category}</span>
    </div>
  </div>

  <div class="card-footer">
    <a href="/tools/{tool.id}" class="btn-primary">
      {#if tool.installed}{$tr('toolCard.run')}{:else}{$tr('toolCard.view')}{/if}
    </a>
    <button class="btn-secondary" title={$tr('common.favorites')}>
      ⭐
    </button>
  </div>
</article>

<style>
  .tool-card {
    background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
    border: 1px solid rgba(168, 85, 247, 0.2);
    border-radius: 12px;
    padding: 1.5rem;
    display: flex;
    flex-direction: column;
    gap: 1rem;
    transition: all 0.3s ease;
    height: 100%;
  }

  .tool-card:hover {
    border-color: #a855f7;
    transform: translateY(-4px);
    box-shadow: 0 8px 24px rgba(168, 85, 247, 0.3);
  }

  .tool-card.compact {
    padding: 1rem;
  }

  .card-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
  }

  .tool-icon {
    font-size: 2rem;
    width: 50px;
    height: 50px;
    display: flex;
    align-items: center;
    justify-content: center;
    background: rgba(168, 85, 247, 0.1);
    border-radius: 10px;
  }

  .compact .tool-icon {
    width: 40px;
    height: 40px;
    font-size: 1.5rem;
  }

  .badge {
    padding: 0.25rem 0.75rem;
    border-radius: 12px;
    font-size: 0.75rem;
    font-weight: 600;
    background: rgba(168, 85, 247, 0.1);
    color: var(--text-secondary);
    border: 1px solid rgba(168, 85, 247, 0.2);
  }

  .badge.success {
    background: rgba(16, 185, 129, 0.1);
    color: #10b981;
    border-color: rgba(16, 185, 129, 0.2);
  }

  .card-body {
    flex: 1;
  }

  .tool-name {
    font-size: 1.1rem;
    font-weight: 600;
    color: var(--text-primary);
    margin-bottom: 0.5rem;
  }

  .compact .tool-name {
    font-size: 1rem;
    margin-bottom: 0.25rem;
  }

  .tool-description {
    font-size: 0.875rem;
    color: var(--text-secondary);
    line-height: 1.5;
    margin-bottom: 0.75rem;
    display: -webkit-box;
    -webkit-line-clamp: 2;
    line-clamp: 2;
    -webkit-box-orient: vertical;
    overflow: hidden;
  }

  .compact .tool-description {
    font-size: 0.8rem;
    -webkit-line-clamp: 1;
    line-clamp: 1;
  }

  .tool-category {
    display: flex;
    gap: 0.5rem;
  }

  .category-tag {
    font-size: 0.75rem;
    padding: 0.25rem 0.5rem;
    background: rgba(99, 102, 241, 0.1);
    color: #6366f1;
    border-radius: 6px;
    border: 1px solid rgba(99, 102, 241, 0.2);
  }

  .card-footer {
    display: flex;
    gap: 0.75rem;
    align-items: center;
  }

  .btn-primary {
    flex: 1;
    background: linear-gradient(135deg, #a855f7, #6366f1);
    color: white;
    text-align: center;
    padding: 0.625rem 1rem;
    border-radius: 8px;
    font-weight: 500;
    font-size: 0.875rem;
    text-decoration: none;
    transition: all 0.2s;
    border: none;
    cursor: pointer;
  }

  .btn-primary:hover {
    transform: translateY(-1px);
    box-shadow: 0 4px 12px rgba(168, 85, 247, 0.4);
  }

  .btn-secondary {
    background: rgba(168, 85, 247, 0.1);
    border: 1px solid rgba(168, 85, 247, 0.2);
    color: var(--text-primary);
    padding: 0.625rem;
    border-radius: 8px;
    font-size: 1rem;
    cursor: pointer;
    transition: all 0.2s;
  }

  .btn-secondary:hover {
    background: rgba(168, 85, 247, 0.2);
    border-color: #a855f7;
  }
</style>
