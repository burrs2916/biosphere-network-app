<script lang="ts">
  import '../app.css';
  import Header from '$lib/components/Header.svelte';
  import Sidebar from '$lib/components/Sidebar.svelte';
</script>

<div class="app-layout">
  <Header />
  <div class="main-container">
    <Sidebar />
    <main class="main-content">
      <slot />
    </main>
  </div>
</div>

<style>
  .app-layout {
    display: flex;
    flex-direction: column;
    height: 100vh;
    background: var(--bg-dark);
  }

  .main-container {
    display: flex;
    flex: 1;
    min-height: 0;
  }

  .main-content {
    flex: 1;
    overflow-y: auto;
    padding: 2rem;
    background: var(--bg-dark);
    min-width: 0;
  }
</style>
