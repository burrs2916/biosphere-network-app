<script lang="ts">
  import { invoke } from '@tauri-apps/api/core';
  import { open } from '@tauri-apps/plugin-dialog';
  import { readFile } from '@tauri-apps/plugin-fs';
  import { tr } from '$lib/i18n';
  import { onMount } from 'svelte';
import ToolHistory from '$lib/components/ToolHistory.svelte';
	import ToolHelp from '$lib/components/ToolHelp.svelte';

  interface TargetInfo {
    id: number | null;
    name: string;
    target_type: string;
    target_value: string;
    description: string | null;
    tags: string | null;
    location: string | null;
    organization: string | null;
    created_at: string;
    updated_at: string;
    last_scanned_at: string | null;
    is_active: boolean;
    group_id?: number | null;
    status?: string;
    risk_level?: string;
    priority?: string;
    owner?: string | null;
    contact?: string | null;
    auto_scan?: boolean;
    scan_interval?: number | null;
    next_scan_at?: string | null;
    total_scans?: number;
    open_ports_count?: number;
    vulnerabilities_count?: number;
    metadata?: string | null;
  }

  interface TargetGroup {
    id: number | null;
    name: string;
    description: string | null;
    color: string;
    icon: string | null;
    target_count: number;
    created_at: string;
    updated_at: string | null;
  }

  interface TargetListResult {
    targets: TargetInfo[];
    total: number;
    page: number;
    page_size: number;
  }

  interface TargetOperationResult {
    success: boolean;
    message: string;
    target_id: number | null;
  }

  interface GroupOperationResult {
    success: boolean;
    message: string;
    group_id: number | null;
  }

  interface WellKnownPort {
    port: number;
    service: string;
    protocol: string;
    description: string;
    category: string;
    risk_level: string;
  }

  interface PortMarking {
    port: number;
    mark_type: string;
    note?: string;
    created_at?: string;
    updated_at?: string | null;
  }

  let activeTab = 'targets';
  let activeMainTab = 'analyze';
  let historyComponent: ToolHistory;
  
  let targets: TargetInfo[] = [];
  let total = 0;
  let currentPage = 1;
  let pageSize = 10;
  let loading = false;
  let error = '';
  let searchQuery = '';

  let groups: TargetGroup[] = [];
  let selectedGroupId: number | null = null;
  let showGroupModal = false;
  let editingGroup: TargetGroup | null = null;
  let groupFormName = '';
  let groupFormDescription = '';
  let groupFormColor = '#3498db';
  let groupFormIcon = '📁';
  let iconSelectedCategory = 0;
  let iconSearchQuery = '';

  let contextMenu = {
    show: false,
    x: 0,
    y: 0,
    group: null as TargetGroup | null
  };

  let showCreateModal = false;
  let showEditModal = false;
  let editingTarget: TargetInfo | null = null;

  let showAddPortModal = false;
  let newPortNumber: number | undefined = undefined;
  let newPortService = '';
  let newPortProtocol = 'TCP';
  let newPortCategory = 'Other';
  let newPortRisk = 'Medium';
  let newPortDescription = '';

  let formName = '';
  let formType = 'IP';
  let formValue = '';
  let formDescription = '';
  let formTags = '';
  let formLocation = '';
  let formOrganization = '';
  let formGroupId: number | null = null;
  let formOwner = '';
  let formContact = '';
  let formPriority = 'normal';
  let formAutoScan = false;
  let formScanInterval: number | null = null;
  let formMetadata = '';

  let selectedTargets: Set<number | null> = new Set();
  let showDetailPanel = false;
  let detailTarget: TargetInfo | null = null;
  let showBatchImportModal = false;
  let batchImportContent = '';
  let batchImporting = false;
  let batchExporting = false;
  let batchDeleting = false;

  let filterType = '';
  let filterStatus = '';
  let filterRiskLevel = '';
  let filterPriority = '';
  let filterTag = '';
  let sortBy = 'created_at';
  let sortOrder = 'DESC';
  let showBatchGroupModal = false;
  let showBatchTagModal = false;
  let batchTagValue = '';
  let batchTagAppend = true;

  const groupIconCategories = [
    {
      name: $tr('targetManager.iconCategories.network'),
      icons: ['🌐', '📡', '🛡️', '🔒', '🔑', '🗝️', '⚙️', '🔧', '📊']
    },
    {
      name: $tr('targetManager.iconCategories.targets'),
      icons: ['🎯', '📍', '📌', '🏢', '🏠', '🖥️', '💻', '📱', '📂']
    },
    {
      name: $tr('targetManager.iconCategories.status'),
      icons: ['✅', '⚠️', '🚫', '⭐', '🔥', '💡']
    }
  ];

  const groupIcons = groupIconCategories.flatMap(cat => cat.icons);

  $: totalPages = Math.ceil(total / pageSize);

  $: targetTypes = [
    { value: 'IP', label: $tr('targetManager.types.IP') },
    { value: 'Domain', label: $tr('targetManager.types.Domain') },
    { value: 'URL', label: $tr('targetManager.types.URL') },
    { value: 'Subnet', label: $tr('targetManager.types.Subnet') },
    { value: 'Range', label: $tr('targetManager.types.Range') },
    { value: 'Hostname', label: $tr('targetManager.types.Hostname') },
    { value: 'Network', label: $tr('targetManager.types.Network') },
    { value: 'Service', label: $tr('targetManager.types.Service') },
    { value: 'Username', label: $tr('targetManager.types.Username') },
    { value: 'Email', label: $tr('targetManager.types.Email') },
    { value: 'Phone', label: $tr('targetManager.types.Phone') },
    { value: 'SocialMedia', label: $tr('targetManager.types.SocialMedia') },
  ];

  $: valuePlaceholder = (() => {
    switch (formType) {
      case 'IP':
        return $tr('targetManager.placeholders.valueIP');
      case 'Domain':
        return $tr('targetManager.placeholders.valueDomain');
      case 'URL':
        return $tr('targetManager.placeholders.valueURL');
      case 'Subnet':
        return $tr('targetManager.placeholders.valueSubnet');
      case 'Range':
        return $tr('targetManager.placeholders.valueRange');
      case 'Hostname':
        return $tr('targetManager.placeholders.valueHostname');
      case 'Network':
        return $tr('targetManager.placeholders.valueNetwork');
      case 'Service':
        return $tr('targetManager.placeholders.valueService');
      case 'Username':
        return $tr('targetManager.placeholders.valueUsername');
      case 'Email':
        return $tr('targetManager.placeholders.valueEmail');
      case 'Phone':
        return $tr('targetManager.placeholders.valuePhone');
      case 'SocialMedia':
        return $tr('targetManager.placeholders.valueSocialMedia');
      default:
        return $tr('targetManager.placeholders.value');
    }
  })();

  let ports: WellKnownPort[] = [];
  let markings: PortMarking[] = [];
  let portLoading = false;
  let portError = '';
  
  let portSearchQuery = '';
  let selectedCategory = '';
  let selectedRisk = '';
  let selectedMarkFilter = '';
  
  // Reactive filtered ports - dependencies are automatically tracked
  $: filteredPorts = ports.filter(port => {
    const query = portSearchQuery.trim().toLowerCase();
    const matchesSearch = !query ||
      port.port.toString().includes(query) ||
      port.service.toLowerCase().includes(query) ||
      port.description.toLowerCase().includes(query);

    const matchesCategory = !selectedCategory || port.category === selectedCategory;
    const matchesRisk = !selectedRisk || port.risk_level === selectedRisk;

    const portMarking = markings.find(m => m.port === port.port);
    const matchesMark = !selectedMarkFilter ||
      (selectedMarkFilter === 'marked' && portMarking) ||
      (portMarking && portMarking.mark_type === selectedMarkFilter);

    return matchesSearch && matchesCategory && matchesRisk && matchesMark;
  });

  let portCurrentPage = 1;
  let portPageSize = 20;

  $: categories = [
    { value: '', label: $tr('portKnowledge.filters.allCategories') },
    { value: 'Web', label: $tr('portKnowledge.categories.Web') },
    { value: 'Database', label: $tr('portKnowledge.categories.Database') },
    { value: 'RemoteAccess', label: $tr('portKnowledge.categories.RemoteAccess') },
    { value: 'Mail', label: $tr('portKnowledge.categories.Mail') },
    { value: 'FileTransfer', label: $tr('portKnowledge.categories.FileTransfer') },
    { value: 'Administration', label: $tr('portKnowledge.categories.Administration') },
    { value: 'IoT', label: $tr('portKnowledge.categories.IoT') },
    { value: 'Development', label: $tr('portKnowledge.categories.Development') },
    { value: 'Messaging', label: $tr('portKnowledge.categories.Messaging') },
    { value: 'Streaming', label: $tr('portKnowledge.categories.Streaming') },
    { value: 'VPN', label: $tr('portKnowledge.categories.VPN') },
    { value: 'Proxy', label: $tr('portKnowledge.categories.Proxy') },
    { value: 'Printing', label: $tr('portKnowledge.categories.Printing') },
    { value: 'Gaming', label: $tr('portKnowledge.categories.Gaming') },
    { value: 'Other', label: $tr('portKnowledge.categories.Other') }
  ];

  $: riskLevels = [
    { value: '', label: $tr('portKnowledge.filters.allRisks') },
    { value: 'Critical', label: $tr('portKnowledge.riskLevels.Critical') },
    { value: 'High', label: $tr('portKnowledge.riskLevels.High') },
    { value: 'Medium', label: $tr('portKnowledge.riskLevels.Medium') },
    { value: 'Low', label: $tr('portKnowledge.riskLevels.Low') },
    { value: 'Info', label: $tr('portKnowledge.riskLevels.Info') }
  ];

  $: markFilters = [
    { value: '', label: $tr('portKnowledge.filters.allMarks') },
    { value: 'marked', label: $tr('portKnowledge.filters.marked') },
    { value: 'favorite', label: $tr('portKnowledge.marks.favorite') },
    { value: 'important', label: $tr('portKnowledge.marks.important') },
    { value: 'dangerous', label: $tr('portKnowledge.marks.dangerous') }
  ];

  $: portTotalPages = Math.ceil(filteredPorts.length / portPageSize);
  $: paginatedPorts = filteredPorts.slice((portCurrentPage - 1) * portPageSize, portCurrentPage * portPageSize);

  async function loadPorts() {
    portLoading = true;
    portError = '';
    
    try {
      const [portsData, markingsData] = await Promise.all([
        invoke<WellKnownPort[]>('get_well_known_ports'),
        invoke<PortMarking[]>('get_all_port_markings')
      ]);
      
      console.log('Ports data:', portsData);
      console.log('Markings data:', markingsData);
      
      ports = portsData;
      markings = markingsData;
      
      console.log('Loaded ports:', ports.length);
      console.log('Loaded markings:', markings.length);
    } catch (e: any) {
      console.error('Load ports error:', e);
      portError = $tr('portKnowledge.errors.loadFailed', { error: e.toString() });
    } finally {
      portLoading = false;
    }
  }

  function getMarking(port: number): PortMarking | undefined {
    const marking = markings.find(m => m.port === port);
    console.log(`getMarking(${port}):`, marking, 'from markings:', markings);
    return marking;
  }

  function getRiskColor(risk: string): string {
    switch (risk) {
      case 'Critical': return '#dc2626';
      case 'High': return '#ea580c';
      case 'Medium': return '#ca8a04';
      case 'Low': return '#16a34a';
      case 'Info': return '#6b7280';
      default: return '#6b7280';
    }
  }

  function getCategoryIcon(category: string): string {
    const cat = categories.find(c => c.value === category);
    return cat ? cat.label.split(' ')[0] : '❓';
  }

  async function toggleMark(port: number, markType: string) {
    console.log('toggleMark called:', { port, markType });
    const existing = getMarking(port);
    console.log('Existing marking:', existing);
    
    try {
      if (existing && existing.mark_type === markType) {
        console.log('Unmarking port:', port);
        await invoke('unmark_port', { port });
      } else {
        console.log('Marking port:', { port, markType });
        await invoke('mark_port', {
          port,
          markType,
          note: ''
        });
      }
      
      // Only reload markings instead of all ports
      const markingsData = await invoke<PortMarking[]>('get_all_port_markings');
      markings = markingsData;
      console.log('Markings reloaded:', markings.length);
    } catch (e: any) {
      console.error('Toggle mark error:', e);
      portError = $tr('portKnowledge.errors.markFailed', { error: e.toString() });
    }
  }

  async function removeMark(port: number) {
    try {
      await invoke('unmark_port', { port });
      
      // Only reload markings instead of all ports
      const markingsData = await invoke<PortMarking[]>('get_all_port_markings');
      markings = markingsData;
    } catch (e: any) {
      console.error('Remove mark error:', e);
      portError = $tr('portKnowledge.errors.unmarkFailed', { error: e.toString() });
    }
  }

  async function addCustomPort() {
    if (!newPortNumber || isNaN(newPortNumber) || newPortNumber < 1 || newPortNumber > 65535) {
      portError = $tr('portKnowledge.errors.portNumberInvalid');
      return;
    }

    const portNum = newPortNumber;

    if (!newPortService.trim()) {
      portError = $tr('portKnowledge.errors.serviceNameEmpty');
      return;
    }

    try {
      const existingPort = ports.find(p => p.port === portNum);
      if (existingPort) {
        portError = $tr('portKnowledge.errors.portExists', { port: portNum });
        return;
      }

      const newPort: WellKnownPort = {
        port: portNum,
        service: newPortService.trim(),
        protocol: newPortProtocol,
        category: newPortCategory,
        risk_level: newPortRisk,
        description: newPortDescription.trim() || $tr('targetManager.ports.customPort', { port: portNum })
      };

      ports = [...ports, newPort].sort((a, b) => a.port - b.port);
      
      showAddPortModal = false;
      newPortNumber = undefined;
      newPortService = '';
      newPortProtocol = 'TCP';
      newPortCategory = 'Other';
      newPortRisk = 'Medium';
      newPortDescription = '';
      portError = '';
      
      console.log('Added custom port:', newPort);
    } catch (e: any) {
      console.error('Add port error:', e);
      portError = $tr('portKnowledge.errors.addPortFailed', { error: e.toString() });
    }
  }

  async function loadTargets() {
    loading = true;
    error = '';

    try {
      const hasFilters = filterType || filterStatus || filterRiskLevel || filterPriority || filterTag;

      if (hasFilters) {
        const params: any = {
          action: 'filtered_list',
          page: currentPage,
          pageSize: pageSize,
        };
        if (filterType) params.targetType = filterType;
        if (filterStatus) params.status = filterStatus;
        if (filterRiskLevel) params.riskLevel = filterRiskLevel;
        if (filterPriority) params.priority = filterPriority;
        if (filterTag) params.tags = filterTag;
        if (sortBy) params.sortBy = sortBy;
        if (sortOrder) params.sortOrder = sortOrder;

        const result = await invoke<TargetListResult>('target_manager', params);
        targets = result.targets;
        total = result.total;
      } else {
        const params: any = {
          action: 'list',
          page: currentPage,
          pageSize: pageSize,
        };

        if (selectedGroupId !== null) {
          params.groupId = selectedGroupId;
        }

        const result = await invoke<TargetListResult>('target_manager', params);
        targets = result.targets;
        total = result.total;
      }
    } catch (e: any) {
      error = $tr('targetManager.errors.loadFailed', { error: e.toString() });
    } finally {
      loading = false;
    }
  }

  function clearFilters() {
    filterType = '';
    filterStatus = '';
    filterRiskLevel = '';
    filterPriority = '';
    filterTag = '';
    sortBy = 'created_at';
    sortOrder = 'DESC';
    currentPage = 1;
    loadTargets();
  }

  async function executeBatchGroup() {
    if (selectedTargets.size === 0) {
      error = $tr('targetManager.batch.noSelection');
      return;
    }

    const ids = Array.from(selectedTargets).filter(id => id !== null) as number[];
    if (ids.length === 0) return;

    loading = true;
    try {
      await invoke('target_manager', {
        action: 'batch_group',
        query: ids.join(','),
        groupId: selectedGroupId,
      });
      selectedTargets.clear();
      selectedTargets = selectedTargets;
      loadTargets();
    } catch (e: any) {
      error = $tr('targetManager.errors.batchFailed', { error: e.toString() });
    } finally {
      loading = false;
    }
  }

  async function executeBatchTags() {
    if (selectedTargets.size === 0 || !batchTagValue.trim()) {
      error = $tr('targetManager.batch.noSelection');
      return;
    }

    const ids = Array.from(selectedTargets).filter(id => id !== null) as number[];
    if (ids.length === 0) return;

    loading = true;
    try {
      await invoke('target_manager', {
        action: 'batch_tags',
        query: ids.join(','),
        tags: batchTagValue.trim(),
        description: batchTagAppend ? 'append' : 'replace',
      });
      showBatchTagModal = false;
      batchTagValue = '';
      selectedTargets.clear();
      selectedTargets = selectedTargets;
      loadTargets();
    } catch (e: any) {
      error = $tr('targetManager.errors.batchFailed', { error: e.toString() });
    } finally {
      loading = false;
    }
  }

  async function loadGroups() {
    try {
      const result = await invoke<{ groups: TargetGroup[] }>('target_manager', {
        action: 'get_groups'
      });
      groups = result.groups || [];
    } catch (e: any) {
      console.error('Load groups error:', e);
    }
  }

  async function createGroup() {
    if (!groupFormName.trim()) {
      error = $tr('targetManager.errors.groupNameRequired');
      return;
    }

    loading = true;
    error = '';

    try {
      const result = await invoke<GroupOperationResult>('target_manager', {
        action: 'create_group',
        name: groupFormName.trim(),
        description: groupFormDescription.trim() || null,
        color: groupFormColor,
        icon: groupFormIcon || null,
      });

      if (result.success) {
        showGroupModal = false;
        resetGroupForm();
        loadGroups();
      } else {
        error = result.message;
      }
    } catch (e: any) {
      error = $tr('targetManager.errors.createGroupFailed', { error: e.toString() });
    } finally {
      loading = false;
    }
  }

  async function updateGroup() {
    if (!editingGroup || !groupFormName.trim()) {
      error = $tr('targetManager.errors.groupNameRequired');
      return;
    }

    loading = true;
    error = '';

    try {
      const result = await invoke<GroupOperationResult>('target_manager', {
        action: 'update_group',
        id: editingGroup.id,
        name: groupFormName.trim(),
        description: groupFormDescription.trim() || null,
        color: groupFormColor,
        icon: groupFormIcon || null,
      });

      if (result.success) {
        showGroupModal = false;
        resetGroupForm();
        loadGroups();
      } else {
        error = result.message;
      }
    } catch (e: any) {
      error = $tr('targetManager.errors.updateGroupFailed', { error: e.toString() });
    } finally {
      loading = false;
    }
  }

  async function deleteGroup(id: number) {
    if (!confirm($tr('targetManager.confirmDeleteGroup'))) {
      return;
    }

    loading = true;
    error = '';

    try {
      const result = await invoke<GroupOperationResult>('target_manager', {
        action: 'delete_group',
        id: id,
      });

      if (result.success) {
        if (selectedGroupId === id) {
          selectedGroupId = null;
        }
        loadGroups();
        loadTargets();
      } else {
        error = result.message;
      }
    } catch (e: any) {
      error = $tr('targetManager.errors.deleteGroupFailed', { error: e.toString() });
    } finally {
      loading = false;
    }
  }

  function openCreateGroupModal() {
    editingGroup = null;
    groupFormName = '';
    groupFormDescription = '';
    groupFormColor = '#3498db';
    groupFormIcon = '📁';
    showGroupModal = true;
  }

  function openEditGroupModal(group: TargetGroup) {
    editingGroup = group;
    groupFormName = group.name;
    groupFormDescription = group.description || '';
    groupFormColor = group.color || '#3498db';
    groupFormIcon = group.icon || '📁';
    showGroupModal = true;
  }

  function resetGroupForm() {
    editingGroup = null;
    groupFormName = '';
    groupFormDescription = '';
    groupFormColor = '#3498db';
    groupFormIcon = '📁';
  }

  function handleContextMenu(event: MouseEvent, group: TargetGroup) {
    event.preventDefault();
    contextMenu = {
      show: true,
      x: event.clientX,
      y: event.clientY,
      group: group
    };
  }

  function closeContextMenu() {
    contextMenu = {
      show: false,
      x: 0,
      y: 0,
      group: null
    };
  }

  function editGroupFromContextMenu() {
    if (contextMenu.group) {
      openEditGroupModal(contextMenu.group);
      closeContextMenu();
    }
  }

  function deleteGroupFromContextMenu() {
    if (contextMenu.group && contextMenu.group.id) {
      deleteGroup(contextMenu.group.id);
      closeContextMenu();
    }
  }

  function selectGroup(groupId: number | null) {
    selectedGroupId = groupId;
    currentPage = 1;
    loadTargets();
  }

  async function searchTargets() {
    if (!searchQuery.trim()) {
      loadTargets();
      return;
    }

    loading = true;
    error = '';

    try {
      const result = await invoke<TargetListResult>('target_manager', {
        action: 'search',
        query: searchQuery.trim(),
        page: currentPage,
        pageSize: pageSize,
      });

      targets = result.targets;
      total = result.total;
    } catch (e: any) {
      error = $tr('targetManager.errors.searchFailed', { error: e.toString() });
    } finally {
      loading = false;
    }
  }

  async function createTarget() {
    if (!formName.trim() || !formValue.trim()) {
      error = $tr('targetManager.errors.requiredFields');
      return;
    }

    loading = true;
    error = '';

    try {
      const result = await invoke<TargetOperationResult>('target_manager', {
        action: 'create',
        name: formName.trim(),
        targetType: formType,
        targetValue: formValue.trim(),
        description: formDescription.trim() || null,
        tags: formTags.trim() || null,
        location: formLocation.trim() || null,
        organization: formOrganization.trim() || null,
        groupId: formGroupId,
        owner: formOwner.trim() || null,
        contact: formContact.trim() || null,
        priority: formPriority || null,
        autoScan: formAutoScan || null,
        scanInterval: formScanInterval || null,
        metadata: formMetadata.trim() || null,
      });

      if (result.success) {
        showCreateModal = false;
        resetForm();
        loadTargets();
      } else {
        error = result.message;
      }
    } catch (e: any) {
      error = $tr('targetManager.errors.createFailed', { error: e.toString() });
    } finally {
      loading = false;
    }
  }

  async function updateTarget() {
    if (!editingTarget || !formName.trim() || !formValue.trim()) {
      error = $tr('targetManager.errors.requiredFields');
      return;
    }

    loading = true;
    error = '';

    try {
      const result = await invoke<TargetOperationResult>('target_manager', {
        action: 'update',
        id: editingTarget.id,
        name: formName.trim(),
        targetType: formType,
        targetValue: formValue.trim(),
        description: formDescription.trim() || null,
        tags: formTags.trim() || null,
        location: formLocation.trim() || null,
        organization: formOrganization.trim() || null,
        groupId: formGroupId,
        owner: formOwner.trim() || null,
        contact: formContact.trim() || null,
        priority: formPriority || null,
        autoScan: formAutoScan || null,
        scanInterval: formScanInterval || null,
        metadata: formMetadata.trim() || null,
      });

      if (result.success) {
        showEditModal = false;
        editingTarget = null;
        resetForm();
        loadTargets();
      } else {
        error = result.message;
      }
    } catch (e: any) {
      error = $tr('targetManager.errors.updateFailed', { error: e.toString() });
    } finally {
      loading = false;
    }
  }

  async function deleteTarget(id: number) {
    if (!confirm($tr('targetManager.confirmDelete'))) {
      return;
    }

    loading = true;
    error = '';

    try {
      const result = await invoke<TargetOperationResult>('target_manager', {
        action: 'delete',
        id: id,
      });

      if (result.success) {
        loadTargets();
      } else {
        error = result.message;
      }
    } catch (e: any) {
      error = $tr('targetManager.errors.deleteFailed', { error: e.toString() });
    } finally {
      loading = false;
    }
  }

  function toggleSelectAll() {
    const allIds = targets.map(t => t.id).filter(id => id !== null) as number[];
    if (selectedTargets.size === allIds.length) {
      selectedTargets.clear();
    } else {
      selectedTargets = new Set(allIds);
    }
    selectedTargets = selectedTargets;
  }

  function toggleTargetSelection(id: number | null) {
    if (id === null) return;
    
    if (selectedTargets.has(id)) {
      selectedTargets.delete(id);
    } else {
      selectedTargets.add(id);
    }
    selectedTargets = selectedTargets;
  }

  function openBatchImportModal() {
    batchImportContent = '';
    showBatchImportModal = true;
  }

  function closeBatchImportModal() {
    showBatchImportModal = false;
    batchImportContent = '';
  }

  async function selectImportFile() {
    try {
      const selected = await open({
        multiple: false,
        filters: [
          {
            name: 'CSV/TXT',
            extensions: ['csv', 'txt'],
          },
        ],
      });

      if (selected) {
        const contents = await readFile(selected as string);
        const text = new TextDecoder().decode(contents);
        batchImportContent = text;
      }
    } catch (e) {
      console.error('Failed to read file:', e);
      error = $tr('targetManager.batch.importFailed', { error: String(e) });
    }
  }

  async function executeBatchImport() {
    if (!batchImportContent.trim()) {
      error = $tr('targetManager.batch.importFailed', { error: 'No content' });
      return;
    }

    batchImporting = true;
    error = '';

    try {
      const lines = batchImportContent.trim().split('\n');
      let successCount = 0;
      let failCount = 0;

      for (const line of lines) {
        if (!line.trim()) continue;

        const parts = line.split(',').map(p => p.trim());
        if (parts.length < 3) {
          failCount++;
          continue;
        }

        const [name, type, value, description, tags, organization, location] = parts;

        try {
          const result = await invoke<TargetOperationResult>('target_manager', {
            action: 'create',
            name: name,
            targetType: type,
            targetValue: value,
            description: description || '',
            tags: tags || '',
            organization: organization || '',
            location: location || '',
            groupId: selectedGroupId,
          });

          if (result.success) {
            successCount++;
          } else {
            failCount++;
          }
        } catch (e) {
          failCount++;
        }
      }

      if (successCount > 0) {
        loadTargets();
        closeBatchImportModal();
      }

      if (failCount > 0) {
        error = $tr('targetManager.batch.importSuccess', { count: successCount }) + 
                ` (${failCount} failed)`;
      } else {
        error = '';
      }
    } catch (e: any) {
      error = $tr('targetManager.batch.importFailed', { error: e.toString() });
    } finally {
      batchImporting = false;
    }
  }

  async function executeBatchExport(format: 'csv' | 'json') {
    if (selectedTargets.size === 0) {
      error = $tr('targetManager.batch.noSelection');
      return;
    }

    batchExporting = true;
    error = '';

    try {
      const selectedTargetList = targets.filter(t => selectedTargets.has(t.id));
      
      let content = '';
      let filename = '';
      const timestamp = new Date().toISOString().split('T')[0];

      if (format === 'csv') {
        content = 'Name,Type,Value,Description,Tags,Organization,Location\n';
        content += selectedTargetList.map(t => 
          `"${t.name}","${t.target_type}","${t.target_value}","${t.description || ''}","${t.tags || ''}","${t.organization || ''}","${t.location || ''}"`
        ).join('\n');
        filename = `targets_${timestamp}.csv`;
      } else {
        content = JSON.stringify(selectedTargetList, null, 2);
        filename = `targets_${timestamp}.json`;
      }

      const blob = new Blob([content], { type: format === 'csv' ? 'text/csv' : 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      selectedTargets.clear();
      selectedTargets = selectedTargets;
    } catch (e: any) {
      error = $tr('targetManager.batch.exportFailed', { error: e.toString() });
    } finally {
      batchExporting = false;
    }
  }

  async function executeBatchDelete() {
    if (selectedTargets.size === 0) {
      error = $tr('targetManager.batch.noSelection');
      return;
    }

    if (!confirm($tr('targetManager.batch.deleteConfirm', { count: selectedTargets.size }))) {
      return;
    }

    batchDeleting = true;
    error = '';

    try {
      let successCount = 0;
      let failCount = 0;

      const idsToDelete = Array.from(selectedTargets).filter(id => id !== null) as number[];

      for (const id of idsToDelete) {
        try {
          const result = await invoke<TargetOperationResult>('target_manager', {
            action: 'delete',
            id: id,
          });

          if (result.success) {
            successCount++;
          } else {
            failCount++;
          }
        } catch (e) {
          failCount++;
        }
      }

      if (successCount > 0) {
        loadTargets();
        selectedTargets.clear();
        selectedTargets = selectedTargets;
      }

      if (failCount > 0) {
        error = $tr('targetManager.batch.deleteSuccess', { count: successCount }) + 
                ` (${failCount} failed)`;
      } else {
        error = '';
      }
    } catch (e: any) {
      error = $tr('targetManager.batch.deleteFailed', { error: e.toString() });
    } finally {
      batchDeleting = false;
    }
  }

  function openCreateModal() {
    resetForm();
    showCreateModal = true;
  }

  function openEditModal(target: TargetInfo) {
    editingTarget = target;
    formName = target.name;
    formType = target.target_type;
    formValue = target.target_value;
    formDescription = target.description || '';
    formTags = target.tags || '';
    formLocation = target.location || '';
    formOrganization = target.organization || '';
    formGroupId = target.group_id || null;
    formOwner = target.owner || '';
    formContact = target.contact || '';
    formPriority = target.priority || 'normal';
    formAutoScan = target.auto_scan || false;
    formScanInterval = target.scan_interval || null;
    formMetadata = target.metadata || '';
    showEditModal = true;
  }

  function openDetailPanel(target: TargetInfo) {
    detailTarget = target;
    showDetailPanel = true;
  }

  function closeDetailPanel() {
    showDetailPanel = false;
    detailTarget = null;
  }

  function resetForm() {
    formName = '';
    formType = 'IP';
    formValue = '';
    formDescription = '';
    formTags = '';
    formLocation = '';
    formOrganization = '';
    formGroupId = null;
    formOwner = '';
    formContact = '';
    formPriority = 'normal';
    formAutoScan = false;
    formScanInterval = null;
    formMetadata = '';
  }

  function getTagsList(tags: string | null): string[] {
    return tags ? tags.split(',').map(t => t.trim()).filter(t => t) : [];
  }

  function formatDate(dateStr: string | null): string {
    if (!dateStr) return '-';
    return new Date(dateStr).toLocaleString();
  }

  function changePage(newPage: number) {
    if (newPage < 1 || newPage > totalPages) return;
    currentPage = newPage;
    if (searchQuery.trim()) {
      searchTargets();
    } else {
      loadTargets();
    }
  }

  $: {
    if (activeTab === 'targets') {
      loadTargets();
    } else if (activeTab === 'ports') {
      loadPorts();
    }
  }

  onMount(() => {
    loadGroups();
    loadTargets();
  });
</script>

<div class="nd-page">
	<div class="page-header">
		<div class="header-left">
			<a href="/" class="back-link">{$tr('common.backToHome')}</a>
			<h1 class="page-title">🎯 {$tr('targetManager.title')}</h1>
			<p class="page-subtitle">{$tr('targetManager.subtitle')}</p>
		</div>
	</div>

	<div class="tabs">
		<button class="tab-btn {activeMainTab === 'analyze' ? 'active' : ''}" onclick={() => activeMainTab = 'analyze'}>
			<span class="tab-icon">🎯</span> {$tr('targetManager.mainTabs.manage')}
		</button>
		<button class="tab-btn {activeMainTab === 'history' ? 'active' : ''}" onclick={() => activeMainTab = 'history'}>
			<span class="tab-icon">📋</span> {$tr('targetManager.mainTabs.history')}
		</button>
		<button class="tab-btn {activeMainTab === 'help' ? 'active' : ''}" onclick={() => activeMainTab = 'help'}>
			<span class="tab-icon">📖</span> {$tr('targetManager.mainTabs.help')}
		</button>
	</div>
  {#if activeMainTab === 'analyze'}
  <div class="sub-tabs">
    <button 
      class="sub-tab {activeTab === 'targets' ? 'active' : ''}" 
      onclick={() => activeTab = 'targets'}
    >
      {$tr('targetManager.tabs.targets')}
    </button>
  </div>

  {#if activeTab === 'targets'}
    <div class="targets-layout">
      <div class="groups-sidebar">
        <div class="groups-header">
          <h3>{$tr('targetManager.groups.title')}</h3>
          <button class="add-group-btn" onclick={openCreateGroupModal} title={$tr('targetManager.groups.addGroup')}>
            +
          </button>
        </div>
        
        <div class="groups-list">
          <button 
            class="group-item {selectedGroupId === null ? 'active' : ''}"
            onclick={() => selectGroup(null)}
          >
            <span class="group-icon">📋</span>
            <span class="group-name">{$tr('targetManager.groups.allTargets')}</span>
            <span class="group-count">{targets.length}</span>
          </button>
          
          {#each groups as group (group.id)}
            <div class="group-item-wrapper">
              <button 
                class="group-item {selectedGroupId === group.id ? 'active' : ''}"
                style="background: {group.color}15; border-left: 5px solid {group.color};"
                onclick={() => {
                  if (group.id !== null && group.id !== undefined) {
                    selectGroup(group.id);
                  }
                }}
                oncontextmenu={(e) => handleContextMenu(e, group)}
              >
                <span class="group-icon">
                  {group.icon || '📁'}
                </span>
                <span class="group-name">{group.name}</span>
                <span class="group-count">{group.target_count || 0}</span>
              </button>
            </div>
          {/each}
        </div>
      </div>
      
      <div class="targets-content">
        <div class="toolbar">
          <div class="search-box">
            <input
              type="text"
              bind:value={searchQuery}
              placeholder={$tr('targetManager.searchPlaceholder')}
              onkeypress={(e) => e.key === 'Enter' && searchTargets()}
            />
            <button class="search-button" onclick={searchTargets}>{$tr('targetManager.buttons.search')}</button>
          </div>
          <div class="toolbar-actions">
            {#if selectedTargets.size > 0}
              <div class="selection-info">
                {$tr('targetManager.batch.selectedCount', { count: selectedTargets.size })}
              </div>
              <button type="button" class="batch-button group" onclick={executeBatchGroup} disabled={loading}>
                📁 {$tr('targetManager.buttons.batchGroup')}
              </button>
              <button type="button" class="batch-button tag" onclick={() => showBatchTagModal = true} disabled={loading}>
                🏷️ {$tr('targetManager.buttons.batchTag')}
              </button>
              <button type="button" class="batch-button export" onclick={() => executeBatchExport('csv')} disabled={batchExporting}>
                📤 {$tr('targetManager.buttons.batchExport')}
              </button>
              <button type="button" class="batch-button delete" onclick={executeBatchDelete} disabled={batchDeleting}>
                🗑️ {$tr('targetManager.buttons.batchDelete')}
              </button>
            {/if}
            <button type="button" class="batch-button import" onclick={openBatchImportModal}>
              📥 {$tr('targetManager.buttons.batchImport')}
            </button>
            <button type="button" class="refresh-button" onclick={loadTargets} disabled={loading}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class:spinning={loading}>
                <path d="M21 12a9 9 0 11-9-9c2.52 0 4.93 1.04 6.68 2.88L21 8"></path>
                <path d="M21 3v5h-5"></path>
              </svg>
              {$tr('targetManager.buttons.refresh')}
            </button>
            <button type="button" class="create-button" onclick={openCreateModal}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <line x1="12" y1="5" x2="12" y2="19"></line>
                <line x1="5" y1="12" x2="19" y2="12"></line>
              </svg>
              {$tr('targetManager.buttons.create')}
            </button>
          </div>
        </div>

        <div class="filter-bar">
          <select bind:value={filterType} onchange={() => { currentPage = 1; loadTargets(); }} class="filter-select">
            <option value="">{$tr('targetManager.filter.allTypes')}</option>
            <option value="IP">IP</option>
            <option value="Domain">Domain</option>
            <option value="URL">URL</option>
            <option value="Subnet">Subnet</option>
            <option value="Hostname">Hostname</option>
            <option value="Username">Username</option>
            <option value="Email">Email</option>
          </select>
          <select bind:value={filterStatus} onchange={() => { currentPage = 1; loadTargets(); }} class="filter-select">
            <option value="">{$tr('targetManager.filter.allStatus')}</option>
            <option value="new">{$tr('targetManager.status.new')}</option>
            <option value="pending">{$tr('targetManager.status.pending')}</option>
            <option value="scanning">{$tr('targetManager.status.scanning')}</option>
            <option value="completed">{$tr('targetManager.status.completed')}</option>
            <option value="has_risk">{$tr('targetManager.status.hasRisk')}</option>
            <option value="offline">{$tr('targetManager.status.offline')}</option>
          </select>
          <select bind:value={filterRiskLevel} onchange={() => { currentPage = 1; loadTargets(); }} class="filter-select">
            <option value="">{$tr('targetManager.filter.allRisk')}</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="none">None</option>
          </select>
          <select bind:value={filterPriority} onchange={() => { currentPage = 1; loadTargets(); }} class="filter-select">
            <option value="">{$tr('targetManager.filter.allPriority')}</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="normal">Normal</option>
            <option value="low">Low</option>
          </select>
          <input type="text" bind:value={filterTag} placeholder={$tr('targetManager.filter.tagPlaceholder')} class="filter-input" onkeydown={(e) => e.key === 'Enter' && (currentPage = 1, loadTargets())} />
          <select bind:value={sortBy} onchange={() => { currentPage = 1; loadTargets(); }} class="filter-select sort-select">
            <option value="created_at">{$tr('targetManager.sort.createdAt')}</option>
            <option value="name">{$tr('targetManager.sort.name')}</option>
            <option value="last_scanned_at">{$tr('targetManager.sort.lastScanned')}</option>
            <option value="risk_level">{$tr('targetManager.sort.riskLevel')}</option>
            <option value="total_scans">{$tr('targetManager.sort.totalScans')}</option>
          </select>
          <button class="sort-order-btn" onclick={() => { sortOrder = sortOrder === 'DESC' ? 'ASC' : 'DESC'; loadTargets(); }} title={sortOrder === 'DESC' ? $tr('targetManager.sort.desc') : $tr('targetManager.sort.asc')}>
            {sortOrder === 'DESC' ? '↓' : '↑'}
          </button>
          {#if filterType || filterStatus || filterRiskLevel || filterPriority || filterTag}
            <button class="clear-filter-btn" onclick={clearFilters}>
              ✕ {$tr('targetManager.filter.clear')}
            </button>
          {/if}
        </div>

        {#if error}
          <div class="error-message">
            <span class="error-icon">⚠️</span>
            {error}
          </div>
        {/if}

  <div class="targets-table">
    {#if loading && targets.length === 0}
      <div class="loading">
        <span class="spinner"></span>
        {$tr('targetManager.loading')}
      </div>
    {:else if targets.length === 0}
      <div class="empty-state">
        <span class="empty-icon">📋</span>
        <p>{$tr('targetManager.empty')}</p>
      </div>
    {:else}
      <table>
        <thead>
          <tr>
            <th class="checkbox-cell">
              <input 
                type="checkbox" 
                checked={selectedTargets.size === targets.filter(t => t.id !== null).length && targets.length > 0}
                onchange={toggleSelectAll}
              />
            </th>
            <th>{$tr('targetManager.table.name')}</th>
            <th>{$tr('targetManager.table.type')}</th>
            <th>{$tr('targetManager.table.value')}</th>
            <th>{$tr('targetManager.table.group')}</th>
            <th>{$tr('targetManager.table.tags')}</th>
            <th>{$tr('targetManager.table.organization')}</th>
            <th>{$tr('targetManager.table.priority')}</th>
            <th>{$tr('targetManager.table.riskLevel')}</th>
            <th>{$tr('targetManager.table.lastScanned')}</th>
            <th>{$tr('targetManager.table.actions')}</th>
          </tr>
        </thead>
        <tbody>
          {#each targets as target}
            <tr>
              <td class="checkbox-cell">
                <input 
                  type="checkbox" 
                  checked={selectedTargets.has(target.id)}
                  onchange={() => toggleTargetSelection(target.id)}
                />
              </td>
              <td class="name-cell clickable" onclick={() => openDetailPanel(target)}>
                <strong>{target.name}</strong>
                {#if target.description}
                  <div class="description">{target.description}</div>
                {/if}
              </td>
              <td>
                <span class="type-badge {target.target_type.toLowerCase()}">{target.target_type}</span>
              </td>
              <td class="value-cell">{target.target_value}</td>
              <td>
                {#if target.group_id}
                  {#each groups as group}
                    {#if group.id === target.group_id}
                      <span class="group-badge" style="background: {group.color}; color: white; box-shadow: 0 2px 4px {group.color}40;">
                        {group.icon || '📁'} {group.name}
                      </span>
                    {/if}
                  {/each}
                {:else}
                  -
                {/if}
              </td>
              <td>
                {#if target.tags}
                  <div class="tags-container">
                    {#each getTagsList(target.tags) as tag}
                      <span class="tag">{tag}</span>
                    {/each}
                  </div>
                {:else}
                  -
                {/if}
              </td>
              <td>{target.organization || '-'}</td>
              <td>
                {#if target.priority}
                  <span class="priority-badge {target.priority}">{target.priority}</span>
                {:else}
                  -
                {/if}
              </td>
              <td>
                {#if target.risk_level}
                  <span class="risk-badge {target.risk_level.toLowerCase()}">{target.risk_level}</span>
                {:else}
                  -
                {/if}
              </td>
              <td>{formatDate(target.last_scanned_at)}</td>
              <td class="actions-cell">
                <button class="action-button edit" onclick={() => openEditModal(target)}>
                  {$tr('targetManager.buttons.edit')}
                </button>
                <button type="button" class="action-button delete" onclick={() => deleteTarget(target.id!)}>
                  {$tr('targetManager.buttons.delete')}
                </button>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
  </div>

  {#if totalPages > 1}
    <div class="pagination">
      <button
        class="pagination-button"
        disabled={currentPage === 1}
        onclick={() => changePage(currentPage - 1)}
      >
        {$tr('targetManager.pagination.previous')}
      </button>
      <span class="pagination-info">
        {$tr('targetManager.pagination.info', { current: currentPage, total: totalPages })}
      </span>
      <button
        class="pagination-button"
        disabled={currentPage === totalPages}
        onclick={() => changePage(currentPage + 1)}
      >
        {$tr('targetManager.pagination.next')}
      </button>
    </div>
  {/if}
      </div>
    </div>
  {:else if activeTab === 'ports'}
    <div class="port-filters">
      <div class="port-search-box">
        <input
          type="text"
          bind:value={portSearchQuery}
          placeholder={$tr('portKnowledge.search.placeholder')}
        />
        {#if portSearchQuery}
          <button 
            class="clear-search-btn" 
            onclick={() => portSearchQuery = ''}
            title={$tr('targetManager.buttons.clearSearch')}
          >
            ✕
          </button>
        {/if}
      </div>
      
      <div class="filter-row">
        <select bind:value={selectedCategory}>
          {#each categories as cat}
            <option value={cat.value}>{cat.label}</option>
          {/each}
        </select>
        
        <select bind:value={selectedRisk}>
          {#each riskLevels as risk}
            <option value={risk.value}>{risk.label}</option>
          {/each}
        </select>
        
        <select bind:value={selectedMarkFilter}>
          {#each markFilters as filter}
            <option value={filter.value}>{filter.label}</option>
          {/each}
        </select>
      </div>
      
      <div class="port-stats">
        <span>
          {$tr('portKnowledge.stats.showing', { 
            shown: paginatedPorts.length, 
            filtered: filteredPorts.length, 
            total: ports.length 
          })}
        </span>
        <button 
          class="add-port-btn" 
          onclick={() => showAddPortModal = true}
          title={$tr('portKnowledge.addPort.title')}
        >
          {$tr('portKnowledge.addPort.button')}
        </button>
      </div>
    </div>

    {#if portLoading}
      <div class="loading">
        <div class="spinner"></div>
        <p>{$tr('portKnowledge.loading')}</p>
      </div>
    {:else if paginatedPorts.length === 0}
      <div class="empty-state">
        <p>{$tr('portKnowledge.empty')}</p>
      </div>
    {:else}
      <div class="port-table">
        <table>
          <thead>
            <tr>
              <th>{$tr('portKnowledge.table.port')}</th>
              <th>{$tr('portKnowledge.table.service')}</th>
              <th>{$tr('portKnowledge.table.protocol')}</th>
              <th>{$tr('portKnowledge.table.category')}</th>
              <th>{$tr('portKnowledge.table.risk')}</th>
              <th>{$tr('portKnowledge.table.description')}</th>
              <th>{$tr('portKnowledge.table.marking')}</th>
              <th>{$tr('portKnowledge.table.actions')}</th>
            </tr>
          </thead>
          <tbody>
            {#each paginatedPorts as port (port.port)}
              <tr>
                <td class="port-number">
                  <strong>{port.port}</strong>
                </td>
                <td class="service-name">{port.service}</td>
                <td class="protocol">{port.protocol}</td>
                <td class="category">
                  <span class="category-badge">
                    {getCategoryIcon(port.category)} {port.category}
                  </span>
                </td>
                <td class="risk">
                  <span 
                    class="risk-badge" 
                    style="background-color: {getRiskColor(port.risk_level)}"
                  >
                    {port.risk_level}
                  </span>
                </td>
                <td class="description">{port.description}</td>
                <td class="marking">
                  {#if getMarking(port.port)}
                    <div class="mark-badges">
                      {#if getMarking(port.port)?.mark_type === 'favorite'}
                        <span class="mark-badge favorite" title={$tr('portKnowledge.marks.favorite')}>⭐</span>
                      {/if}
                      {#if getMarking(port.port)?.mark_type === 'important'}
                        <span class="mark-badge important" title={$tr('portKnowledge.marks.important')}>🔴</span>
                      {/if}
                      {#if getMarking(port.port)?.mark_type === 'dangerous'}
                        <span class="mark-badge dangerous" title={$tr('portKnowledge.marks.dangerous')}>⚠️</span>
                      {/if}
                      {#if getMarking(port.port)?.note}
                        <span class="mark-note" title={getMarking(port.port)?.note}>📝</span>
                      {/if}
                    </div>
                  {:else}
                    <span class="no-mark">-</span>
                  {/if}
                </td>
                <td class="actions">
                  <button 
                    class="action-btn favorite" 
                    onclick={() => toggleMark(port.port, 'favorite')}
                    title={$tr('portKnowledge.markTitles.favorite')}
                  >
                    ⭐
                  </button>
                  <button 
                    class="action-btn important" 
                    onclick={() => toggleMark(port.port, 'important')}
                    title={$tr('portKnowledge.markTitles.important')}
                  >
                    🔴
                  </button>
                  <button 
                    class="action-btn dangerous" 
                    onclick={() => toggleMark(port.port, 'dangerous')}
                    title={$tr('portKnowledge.markTitles.dangerous')}
                  >
                    ⚠️
                  </button>
                  {#if getMarking(port.port)}
                    <button 
                      class="action-btn remove" 
                      onclick={() => removeMark(port.port)}
                      title={$tr('portKnowledge.markTitles.unmark')}
                    >
                      ✕
                    </button>
                  {/if}
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>

      {#if portTotalPages > 1}
        <div class="pagination">
          <button 
            class="page-btn" 
            onclick={() => portCurrentPage = Math.max(1, portCurrentPage - 1)}
            disabled={portCurrentPage === 1}
          >
            {$tr('targetManager.pagination.previous')}
          </button>
          
          <span class="page-info">
            {$tr('targetManager.pagination.info', { current: portCurrentPage, total: portTotalPages })}
          </span>
          
          <button 
            class="page-btn" 
            onclick={() => portCurrentPage = Math.min(portTotalPages, portCurrentPage + 1)}
            disabled={portCurrentPage === portTotalPages}
          >
            {$tr('targetManager.pagination.next')}
          </button>
        </div>
      {/if}
    {/if}
  {/if}
  {:else if activeMainTab === 'history'}
    <div class="section-card"><ToolHistory toolType="target_manager" toolName={$tr('targetManager.title')} bind:this={historyComponent} /></div>
  {:else if activeMainTab === 'help'}
    <div class="section-card"><ToolHelp toolType="target_manager" /></div>
  {/if}
</div>

{#if showDetailPanel && detailTarget}
  <!-- svelte-ignore a11y_no_static_element_interactions -->
  <div
    class="drawer-overlay"
    onclick={closeDetailPanel}
    onkeydown={(e) => e.key === 'Escape' && closeDetailPanel()}
  >
    <div
      class="drawer-panel detail-panel"
      onclick={(e) => e.stopPropagation()}
      onkeydown={(e) => e.stopPropagation()}
      role="dialog"
      aria-label="{$tr('targetManager.detail.title')}"
    >
      <div class="drawer-header">
        <h2>{$tr('targetManager.detail.title')}: {detailTarget.name}</h2>
        <button class="close-button" onclick={closeDetailPanel}>×</button>
      </div>
      <div class="drawer-body">
        <div class="detail-section">
          <h3>{$tr('targetManager.detail.basicInfo')}</h3>
          <div class="detail-grid">
            <div class="detail-item">
              <label>{$tr('targetManager.table.name')}</label>
              <span>{detailTarget.name}</span>
            </div>
            <div class="detail-item">
              <label>{$tr('targetManager.table.type')}</label>
              <span class="type-badge {detailTarget.target_type.toLowerCase()}">{detailTarget.target_type}</span>
            </div>
            <div class="detail-item">
              <label>{$tr('targetManager.table.value')}</label>
              <span class="value-text">{detailTarget.target_value}</span>
            </div>
            <div class="detail-item full-width">
              <label>{$tr('targetManager.form.description')}</label>
              <span>{detailTarget.description || '-'}</span>
            </div>
          </div>
        </div>

        <div class="detail-section">
          <h3>{$tr('targetManager.detail.statusInfo')}</h3>
          <div class="detail-grid">
            <div class="detail-item">
              <label>{$tr('targetManager.table.status')}</label>
              <span class="status-badge {detailTarget.status || 'unknown'}">{detailTarget.status || '-'}</span>
            </div>
            <div class="detail-item">
              <label>{$tr('targetManager.table.riskLevel')}</label>
              {#if detailTarget.risk_level}
                <span class="risk-badge {detailTarget.risk_level.toLowerCase()}">{detailTarget.risk_level}</span>
              {:else}
                <span>-</span>
              {/if}
            </div>
            <div class="detail-item">
              <label>{$tr('targetManager.table.priority')}</label>
              {#if detailTarget.priority}
                <span class="priority-badge {detailTarget.priority}">{detailTarget.priority}</span>
              {:else}
                <span>-</span>
              {/if}
            </div>
            <div class="detail-item">
              <label>{$tr('targetManager.form.isActive')}</label>
              <span>{detailTarget.is_active ? '✅ ' + $tr('common.yes') : '❌ ' + $tr('common.no')}</span>
            </div>
          </div>
        </div>

        <div class="detail-section">
          <h3>{$tr('targetManager.detail.orgInfo')}</h3>
          <div class="detail-grid">
            <div class="detail-item">
              <label>{$tr('targetManager.table.organization')}</label>
              <span>{detailTarget.organization || '-'}</span>
            </div>
            <div class="detail-item">
              <label>{$tr('targetManager.form.location')}</label>
              <span>{detailTarget.location || '-'}</span>
            </div>
            <div class="detail-item">
              <label>{$tr('targetManager.form.owner')}</label>
              <span>{detailTarget.owner || '-'}</span>
            </div>
            <div class="detail-item">
              <label>{$tr('targetManager.form.contact')}</label>
              <span>{detailTarget.contact || '-'}</span>
            </div>
          </div>
        </div>

        <div class="detail-section">
          <h3>{$tr('targetManager.detail.scanInfo')}</h3>
          <div class="detail-grid">
            <div class="detail-item">
              <label>{$tr('targetManager.table.lastScanned')}</label>
              <span>{formatDate(detailTarget.last_scanned_at ?? null)}</span>
            </div>
            <div class="detail-item">
              <label>{$tr('targetManager.detail.totalScans')}</label>
              <span>{detailTarget.total_scans ?? 0}</span>
            </div>
            <div class="detail-item">
              <label>{$tr('targetManager.detail.openPorts')}</label>
              <span>{detailTarget.open_ports_count ?? 0}</span>
            </div>
            <div class="detail-item">
              <label>{$tr('targetManager.detail.vulnerabilities')}</label>
              <span>{detailTarget.vulnerabilities_count ?? 0}</span>
            </div>
          </div>
        </div>

        <div class="detail-section">
          <h3>{$tr('targetManager.detail.autoScan')}</h3>
          <div class="detail-grid">
            <div class="detail-item">
              <label>{$tr('targetManager.form.autoScan')}</label>
              <span>{detailTarget.auto_scan ? '✅ ' + $tr('common.yes') : '❌ ' + $tr('common.no')}</span>
            </div>
            <div class="detail-item">
              <label>{$tr('targetManager.form.scanInterval')}</label>
              <span>{detailTarget.scan_interval ? detailTarget.scan_interval + ' ' + $tr('targetManager.detail.hours') : '-'}</span>
            </div>
            <div class="detail-item">
              <label>{$tr('targetManager.detail.nextScan')}</label>
              <span>{formatDate(detailTarget.next_scan_at ?? null)}</span>
            </div>
          </div>
        </div>

        <div class="detail-section">
          <h3>{$tr('targetManager.detail.tagsAndMeta')}</h3>
          <div class="detail-grid">
            <div class="detail-item full-width">
              <label>{$tr('targetManager.table.tags')}</label>
              <div>
                {#if detailTarget.tags}
                  <div class="tags-container">
                    {#each getTagsList(detailTarget.tags) as tag}
                      <span class="tag">{tag}</span>
                    {/each}
                  </div>
                {:else}
                  <span>-</span>
                {/if}
              </div>
            </div>
            <div class="detail-item full-width">
              <label>{$tr('targetManager.form.metadata')}</label>
              <span class="metadata-text">{detailTarget.metadata || '-'}</span>
            </div>
          </div>
        </div>

        <div class="detail-section">
          <h3>{$tr('targetManager.detail.groupInfo')}</h3>
          <div class="detail-grid">
            <div class="detail-item">
              <label>{$tr('targetManager.table.group')}</label>
              {#if detailTarget.group_id}
                {#each groups as group}
                  {#if group.id === detailTarget.group_id}
                    <span class="group-badge" style="background: {group.color}; color: white;">
                      {group.icon || '📁'} {group.name}
                    </span>
                  {/if}
                {/each}
              {:else}
                <span>-</span>
              {/if}
            </div>
            <div class="detail-item">
              <label>{$tr('targetManager.detail.createdAt')}</label>
              <span>{formatDate(detailTarget.created_at ?? null)}</span>
            </div>
            <div class="detail-item">
              <label>{$tr('targetManager.detail.updatedAt')}</label>
              <span>{formatDate(detailTarget.updated_at ?? null)}</span>
            </div>
          </div>
        </div>
      </div>
      <div class="quick-actions">
        <h3>{$tr('targetManager.detail.quickActions')}</h3>
        <div class="quick-action-buttons">
          <a href="/tools/port_scanner" class="quick-action-btn" title={$tr('tools.portScanner')}>🔌 {$tr('tools.portScanner')}</a>
          <a href="/tools/subdomain_enum" class="quick-action-btn" title={$tr('tools.subdomainEnum')}>🌐 {$tr('tools.subdomainEnum')}</a>
          <a href="/tools/dir_scanner" class="quick-action-btn" title={$tr('tools.dirScanner')}>📂 {$tr('tools.dirScanner')}</a>
          <a href="/tools/sqli_scanner" class="quick-action-btn" title={$tr('tools.sqliScanner')}>💉 {$tr('tools.sqliScanner')}</a>
          <a href="/tools/xss_scanner" class="quick-action-btn" title={$tr('tools.xssScanner')}>⚠️ {$tr('tools.xssScanner')}</a>
          <a href="/tools/command_injection" class="quick-action-btn" title={$tr('tools.commandInjection')}>⌨️ {$tr('tools.commandInjection')}</a>
          <a href="/tools/social_finder" class="quick-action-btn" title={$tr('tools.socialFinder')}>👤 {$tr('tools.socialFinder')}</a>
        </div>
      </div>
      <div class="drawer-footer">
        <button class="btn-primary" onclick={() => { closeDetailPanel(); openEditModal(detailTarget!); }}>
          {$tr('targetManager.buttons.edit')}
        </button>
        <button class="cancel-button" onclick={closeDetailPanel}>{$tr('targetManager.buttons.close')}</button>
      </div>
    </div>
  </div>
{/if}

{#if showCreateModal}
  <!-- svelte-ignore a11y_no_static_element_interactions -->
  <div 
    class="drawer-overlay" 
    onclick={() => showCreateModal = false}
    onkeydown={(e) => e.key === 'Escape' && (showCreateModal = false)}
    role="button"
    tabindex="0"
  >
    <!-- svelte-ignore a11y_click_events_have_key_events -->
    <div class="drawer" onclick={(e) => e.stopPropagation()}>
      <div class="drawer-header">
        <h2>{$tr('targetManager.modal.createTitle')}</h2>
        <button class="close-button" onclick={() => showCreateModal = false}>×</button>
      </div>
      <div class="drawer-body">
        <div class="form-group">
          <label for="create-name">{$tr('targetManager.labels.name')} *</label>
          <input id="create-name" type="text" bind:value={formName} placeholder={$tr('targetManager.placeholders.name')} />
        </div>
        <div class="form-group">
          <label for="create-type">{$tr('targetManager.labels.type')} *</label>
          <select id="create-type" bind:value={formType}>
            {#each targetTypes as type}
              <option value={type.value}>{type.label}</option>
            {/each}
          </select>
        </div>
        <div class="form-group">
          <label for="create-value">{$tr('targetManager.labels.value')} *</label>
          <input id="create-value" type="text" bind:value={formValue} placeholder={valuePlaceholder} />
        </div>
        <div class="form-group">
          <label for="create-description">{$tr('targetManager.labels.description')}</label>
          <textarea id="create-description" bind:value={formDescription} placeholder={$tr('targetManager.placeholders.description')} rows="3"></textarea>
        </div>
        <div class="form-group">
          <label for="create-tags">{$tr('targetManager.labels.tags')}</label>
          <input id="create-tags" type="text" bind:value={formTags} placeholder={$tr('targetManager.placeholders.tags')} />
        </div>
        <div class="form-group">
          <label for="create-location">{$tr('targetManager.labels.location')}</label>
          <input id="create-location" type="text" bind:value={formLocation} placeholder={$tr('targetManager.placeholders.location')} />
        </div>
        <div class="form-group">
          <label for="create-organization">{$tr('targetManager.labels.organization')}</label>
          <input id="create-organization" type="text" bind:value={formOrganization} placeholder={$tr('targetManager.placeholders.organization')} />
        </div>
        <div class="form-group">
          <label for="create-group">{$tr('targetManager.labels.group')}</label>
          <select id="create-group" bind:value={formGroupId}>
            <option value={null}>{$tr('targetManager.placeholders.noGroup')}</option>
            {#each groups as group}
              <option value={group.id}>{group.name}</option>
            {/each}
          </select>
        </div>
        <div class="form-group">
          <label for="create-owner">{$tr('targetManager.labels.owner')}</label>
          <input id="create-owner" type="text" bind:value={formOwner} placeholder={$tr('targetManager.placeholders.owner')} />
        </div>
        <div class="form-group">
          <label for="create-contact">{$tr('targetManager.labels.contact')}</label>
          <input id="create-contact" type="text" bind:value={formContact} placeholder={$tr('targetManager.placeholders.contact')} />
        </div>
        <div class="form-group">
          <label for="create-priority">{$tr('targetManager.labels.priority')}</label>
          <select id="create-priority" bind:value={formPriority}>
            <option value="critical">{$tr('targetManager.priorities.critical')}</option>
            <option value="high">{$tr('targetManager.priorities.high')}</option>
            <option value="medium">{$tr('targetManager.priorities.medium')}</option>
            <option value="low">{$tr('targetManager.priorities.low')}</option>
            <option value="normal">{$tr('targetManager.priorities.normal')}</option>
          </select>
        </div>
        <div class="form-group">
          <label for="create-metadata">{$tr('targetManager.labels.metadata')}</label>
          <input id="create-metadata" type="text" bind:value={formMetadata} placeholder={$tr('targetManager.placeholders.metadata')} />
        </div>
      </div>
      <div class="drawer-footer">
        <button class="cancel-button" onclick={() => showCreateModal = false}>{$tr('targetManager.buttons.cancel')}</button>
        <button class="submit-button" onclick={createTarget} disabled={loading}>
          {#if loading}
            <span class="spinner"></span>
          {/if}
          {$tr('targetManager.buttons.create')}
        </button>
      </div>
    </div>
  </div>
{/if}

{#if showEditModal}
  <!-- svelte-ignore a11y_no_static_element_interactions -->
  <div 
    class="drawer-overlay" 
    onclick={() => showEditModal = false}
    onkeydown={(e) => e.key === 'Escape' && (showEditModal = false)}
    role="button"
    tabindex="0"
  >
    <!-- svelte-ignore a11y_click_events_have_key_events -->
    <div class="drawer" onclick={(e) => e.stopPropagation()}>
      <div class="drawer-header">
        <h2>{$tr('targetManager.modal.editTitle')}</h2>
        <button class="close-button" onclick={() => showEditModal = false}>×</button>
      </div>
      <div class="drawer-body">
        <div class="form-group">
          <label for="edit-name">{$tr('targetManager.labels.name')} *</label>
          <input id="edit-name" type="text" bind:value={formName} placeholder={$tr('targetManager.placeholders.name')} />
        </div>
        <div class="form-group">
          <label for="edit-type">{$tr('targetManager.labels.type')} *</label>
          <select id="edit-type" bind:value={formType}>
            {#each targetTypes as type}
              <option value={type.value}>{type.label}</option>
            {/each}
          </select>
        </div>
        <div class="form-group">
          <label for="edit-value">{$tr('targetManager.labels.value')} *</label>
          <input id="edit-value" type="text" bind:value={formValue} placeholder={valuePlaceholder} />
        </div>
        <div class="form-group">
          <label for="edit-description">{$tr('targetManager.labels.description')}</label>
          <textarea id="edit-description" bind:value={formDescription} placeholder={$tr('targetManager.placeholders.description')} rows="3"></textarea>
        </div>
        <div class="form-group">
          <label for="edit-tags">{$tr('targetManager.labels.tags')}</label>
          <input id="edit-tags" type="text" bind:value={formTags} placeholder={$tr('targetManager.placeholders.tags')} />
        </div>
        <div class="form-group">
          <label for="edit-location">{$tr('targetManager.labels.location')}</label>
          <input id="edit-location" type="text" bind:value={formLocation} placeholder={$tr('targetManager.placeholders.location')} />
        </div>
        <div class="form-group">
          <label for="edit-organization">{$tr('targetManager.labels.organization')}</label>
          <input id="edit-organization" type="text" bind:value={formOrganization} placeholder={$tr('targetManager.placeholders.organization')} />
        </div>
        <div class="form-group">
          <label for="edit-group">{$tr('targetManager.labels.group')}</label>
          <select id="edit-group" bind:value={formGroupId}>
            <option value={null}>{$tr('targetManager.placeholders.noGroup')}</option>
            {#each groups as group}
              <option value={group.id}>{group.name}</option>
            {/each}
          </select>
        </div>
        <div class="form-group">
          <label for="edit-owner">{$tr('targetManager.labels.owner')}</label>
          <input id="edit-owner" type="text" bind:value={formOwner} placeholder={$tr('targetManager.placeholders.owner')} />
        </div>
        <div class="form-group">
          <label for="edit-contact">{$tr('targetManager.labels.contact')}</label>
          <input id="edit-contact" type="text" bind:value={formContact} placeholder={$tr('targetManager.placeholders.contact')} />
        </div>
        <div class="form-group">
          <label for="edit-priority">{$tr('targetManager.labels.priority')}</label>
          <select id="edit-priority" bind:value={formPriority}>
            <option value="critical">{$tr('targetManager.priorities.critical')}</option>
            <option value="high">{$tr('targetManager.priorities.high')}</option>
            <option value="medium">{$tr('targetManager.priorities.medium')}</option>
            <option value="low">{$tr('targetManager.priorities.low')}</option>
            <option value="normal">{$tr('targetManager.priorities.normal')}</option>
          </select>
        </div>
        <div class="form-group">
          <label for="edit-metadata">{$tr('targetManager.labels.metadata')}</label>
          <input id="edit-metadata" type="text" bind:value={formMetadata} placeholder={$tr('targetManager.placeholders.metadata')} />
        </div>
      </div>
      <div class="drawer-footer">
        <button class="cancel-button" onclick={() => showEditModal = false}>{$tr('targetManager.buttons.cancel')}</button>
        <button class="submit-button" onclick={updateTarget} disabled={loading}>
          {#if loading}
            <span class="spinner"></span>
          {/if}
          {$tr('targetManager.buttons.save')}
        </button>
      </div>
    </div>
  </div>
{/if}

{#if showGroupModal}
  <!-- svelte-ignore a11y_no_static_element_interactions -->
  <div 
    class="drawer-overlay" 
    onclick={() => showGroupModal = false}
    onkeydown={(e) => e.key === 'Escape' && (showGroupModal = false)}
    role="button"
    tabindex="0"
  >
    <!-- svelte-ignore a11y_click_events_have_key_events -->
    <div class="drawer" onclick={(e) => e.stopPropagation()}>
      <div class="drawer-header">
        <h2>{editingGroup ? $tr('targetManager.groups.editGroup') : $tr('targetManager.groups.createGroup')}</h2>
        <button class="close-button" onclick={() => showGroupModal = false}>×</button>
      </div>
      <div class="drawer-body">
        {#if error}
          <div class="error-message">{error}</div>
        {/if}
        
        <div class="form-group">
          <label for="group-name">{$tr('targetManager.groups.groupName')}</label>
          <input id="group-name" type="text" bind:value={groupFormName} placeholder={$tr('targetManager.groups.groupNamePlaceholder')} />
        </div>
        
        <div class="form-group">
          <label for="group-description">{$tr('targetManager.groups.groupDescription')}</label>
          <textarea id="group-description" bind:value={groupFormDescription} placeholder={$tr('targetManager.groups.groupDescriptionPlaceholder')} rows="3"></textarea>
        </div>
        
        <div class="form-group">
          <label for="group-color">{$tr('targetManager.groups.groupColor')}</label>
          <div class="color-picker-wrapper">
            <input id="group-color" type="color" bind:value={groupFormColor} class="color-input" />
            <div class="color-preview" style="background-color: {groupFormColor}">
              <span class="color-value">{groupFormColor}</span>
            </div>
          </div>
        </div>
        
        <div class="form-group">
          <div class="form-label">{$tr('targetManager.groups.groupIcon')}</div>
          <div class="icon-picker">
            <div class="selected-icon" style="background: {groupFormColor}20; border: 2px solid {groupFormColor};">
              <span style="filter: drop-shadow(0 0 3px {groupFormColor});">{groupFormIcon}</span>
            </div>
            
            <div class="icon-search">
              <input 
                type="text" 
                bind:value={iconSearchQuery}
                placeholder={$tr('targetManager.iconCategories.searchPlaceholder')}
                class="search-input"
              />
            </div>
            
            <div class="category-tabs">
              {#each groupIconCategories as category, index}
                <button 
                  type="button"
                  class="category-tab {iconSelectedCategory === index ? 'active' : ''}"
                  onclick={() => {
                    iconSelectedCategory = index;
                    iconSearchQuery = '';
                  }}
                >
                  {category.icons[0]} {category.name}
                </button>
              {/each}
            </div>
            
            <div class="icon-grid-container">
              {#if iconSearchQuery}
                <div class="icon-grid">
                  {#each groupIcons.filter(icon => icon.includes(iconSearchQuery)) as icon (icon)}
                    <button 
                      type="button"
                      class="icon-option {groupFormIcon === icon ? 'selected' : ''}"
                      onclick={() => {
                        groupFormIcon = icon;
                        iconSearchQuery = '';
                      }}
                    >
                      {icon}
                    </button>
                  {/each}
                </div>
              {:else}
                <div class="icon-grid">
                  {#each groupIconCategories[iconSelectedCategory].icons as icon (icon)}
                    <button 
                      type="button"
                      class="icon-option {groupFormIcon === icon ? 'selected' : ''}"
                      onclick={() => groupFormIcon = icon}
                    >
                      {icon}
                    </button>
                  {/each}
                </div>
              {/if}
            </div>
          </div>
        </div>
      </div>
      <div class="drawer-footer">
        <button class="cancel-button" onclick={() => showGroupModal = false}>{$tr('targetManager.buttons.cancel')}</button>
        <button class="submit-button" onclick={editingGroup ? updateGroup : createGroup} disabled={loading}>
          {#if loading}
            <span class="spinner"></span>
          {/if}
          {editingGroup ? $tr('targetManager.buttons.save') : $tr('targetManager.groups.createGroupButton')}
        </button>
      </div>
    </div>
  </div>
{/if}

{#if contextMenu.show}
  <!-- svelte-ignore a11y_no_static_element_interactions -->
  <div 
    class="context-menu-overlay" 
    onclick={closeContextMenu}
    onkeydown={(e) => e.key === 'Escape' && closeContextMenu()}
    role="button"
    tabindex="0"
  >
    <!-- svelte-ignore a11y_click_events_have_key_events -->
    <div 
      class="context-menu" 
      style="left: {contextMenu.x}px; top: {contextMenu.y}px;"
      onclick={(e) => e.stopPropagation()}
    >
      <button class="context-menu-item" onclick={editGroupFromContextMenu}>
        <span class="context-menu-icon">✏️</span>
        <span>{$tr('targetManager.groups.editGroup')}</span>
      </button>
      <button type="button" class="context-menu-item delete" onclick={deleteGroupFromContextMenu}>
        <span class="context-menu-icon">🗑️</span>
        <span>{$tr('targetManager.groups.deleteGroup')}</span>
      </button>
    </div>
  </div>
{/if}

{#if showAddPortModal}
  <!-- svelte-ignore a11y_no_static_element_interactions -->
  <div 
    class="modal-overlay" 
    onclick={() => showAddPortModal = false}
    onkeydown={(e) => e.key === 'Escape' && (showAddPortModal = false)}
    role="button"
    tabindex="0"
  >
    <!-- svelte-ignore a11y_click_events_have_key_events -->
    <div class="modal" onclick={(e) => e.stopPropagation()}>
      <div class="modal-header">
        <h2>{$tr('portKnowledge.addPort.title')}</h2>
        <button class="close-button" onclick={() => showAddPortModal = false}>×</button>
      </div>
      <div class="modal-body">
        {#if portError}
          <div class="error-message">{portError}</div>
        {/if}
        
        <div class="form-group">
          <label for="add-port-number">{$tr('portKnowledge.addPort.portNumber')} *</label>
          <input 
            id="add-port-number"
            type="number" 
            bind:value={newPortNumber} 
            placeholder={$tr('portKnowledge.addPort.portNumberPlaceholder')}
            min="1"
            max="65535"
          />
        </div>
        
        <div class="form-group">
          <label for="add-port-service">{$tr('portKnowledge.addPort.serviceName')} *</label>
          <input 
            id="add-port-service"
            type="text" 
            bind:value={newPortService} 
            placeholder={$tr('portKnowledge.addPort.serviceNamePlaceholder')}
          />
        </div>
        
        <div class="form-group">
          <label for="add-port-protocol">{$tr('portKnowledge.addPort.protocol')}</label>
          <select id="add-port-protocol" bind:value={newPortProtocol}>
            <option value="TCP">TCP</option>
            <option value="UDP">UDP</option>
            <option value="TCP/UDP">TCP/UDP</option>
          </select>
        </div>
        
        <div class="form-group">
          <label for="add-port-category">{$tr('portKnowledge.addPort.category')}</label>
          <select id="add-port-category" bind:value={newPortCategory}>
            <option value="Web">🌐 Web</option>
            <option value="Database">💾 Database</option>
            <option value="RemoteAccess">🖥️ Remote Access</option>
            <option value="Mail">📧 Mail</option>
            <option value="FileTransfer">📁 File Transfer</option>
            <option value="Administration">⚙️ Administration</option>
            <option value="IoT">🔌 IoT</option>
            <option value="Development">💻 Development</option>
            <option value="Messaging">💬 Messaging</option>
            <option value="Streaming">📺 Streaming</option>
            <option value="VPN">🔒 VPN</option>
            <option value="Proxy">🔄 Proxy</option>
            <option value="Printing">🖨️ Printing</option>
            <option value="Gaming">🎮 Gaming</option>
            <option value="Other">📦 Other</option>
          </select>
        </div>
        
        <div class="form-group">
          <label for="add-port-risk">{$tr('portKnowledge.addPort.riskLevel')}</label>
          <select id="add-port-risk" bind:value={newPortRisk}>
            <option value="Critical">🔴 Critical</option>
            <option value="High">🟠 High</option>
            <option value="Medium">🟡 Medium</option>
            <option value="Low">🟢 Low</option>
            <option value="Info">ℹ️ Info</option>
          </select>
        </div>
        
        <div class="form-group">
          <label for="add-port-description">{$tr('portKnowledge.addPort.description')}</label>
          <textarea 
            id="add-port-description"
            bind:value={newPortDescription} 
            placeholder={$tr('portKnowledge.addPort.descriptionPlaceholder')}
            rows="3"
          ></textarea>
        </div>
      </div>
      <div class="modal-footer">
        <button class="cancel-button" onclick={() => showAddPortModal = false}>
          {$tr('portKnowledge.addPort.cancel')}
        </button>
        <button class="submit-button" onclick={addCustomPort}>
          {$tr('portKnowledge.addPort.submit')}
        </button>
      </div>
    </div>
  </div>
{/if}

{#if showBatchImportModal}
  <div 
    class="modal-overlay" 
    role="button"
    tabindex="-1"
    onclick={closeBatchImportModal} 
    onkeydown={(e) => e.key === 'Escape' && closeBatchImportModal()}
  >
    <div 
      class="modal-content batch-import-modal" 
      role="dialog"
      aria-modal="true"
      onclick={(e) => e.stopPropagation()} 
      onkeydown={(e) => e.stopPropagation()}
    >
      <div class="modal-header">
        <h2>{$tr('targetManager.batch.importTitle')}</h2>
        <button class="modal-close" onclick={closeBatchImportModal}>✕</button>
      </div>
      
      <div class="modal-body">
        <div class="import-hint">
          <p>{$tr('targetManager.batch.importHint')}</p>
        </div>
        
        <div class="format-guide">
          <h3>{$tr('targetManager.batch.importFormat')}</h3>
          <p class="format-hint">{$tr('targetManager.batch.importFormatHint')}</p>
          <pre class="format-example">{$tr('targetManager.batch.importExample')}</pre>
        </div>
        
        <div class="import-methods">
          <button type="button" class="file-select-button" onclick={selectImportFile} disabled={batchImporting}>
            📁 {$tr('targetManager.batch.selectFile')}
          </button>
          <div class="or-divider">
            <span>{$tr('targetManager.batch.or')}</span>
          </div>
        </div>
        
        <div class="form-group">
          <label for="batch-import-content">{$tr('targetManager.batch.pasteHere')}</label>
          <textarea 
            id="batch-import-content"
            bind:value={batchImportContent}
            placeholder={$tr('targetManager.batch.importPlaceholder')}
            rows="10"
            disabled={batchImporting}
          ></textarea>
        </div>
      </div>
      
      <div class="modal-footer">
        <button class="cancel-button" onclick={closeBatchImportModal} disabled={batchImporting}>
          {$tr('targetManager.buttons.cancel')}
        </button>
        <button class="submit-button" onclick={executeBatchImport} disabled={batchImporting || !batchImportContent.trim()}>
          {batchImporting ? $tr('targetManager.batch.importing') : $tr('targetManager.buttons.batchImport')}
        </button>
      </div>
    </div>
  </div>
{/if}

{#if showBatchTagModal}
  <div 
    class="modal-overlay" 
    role="button"
    tabindex="-1"
    onclick={() => showBatchTagModal = false} 
    onkeydown={(e) => e.key === 'Escape' && (showBatchTagModal = false)}
  >
    <div 
      class="modal-content batch-tag-modal" 
      role="dialog"
      aria-modal="true"
      onclick={(e) => e.stopPropagation()} 
      onkeydown={(e) => e.stopPropagation()}
    >
      <div class="modal-header">
        <h2>{$tr('targetManager.batch.tagTitle')}</h2>
        <button class="modal-close" onclick={() => showBatchTagModal = false}>✕</button>
      </div>
      
      <div class="modal-body">
        <p class="batch-hint">{$tr('targetManager.batch.selectedCount', { count: selectedTargets.size })}</p>
        
        <div class="form-group">
          <label for="batch-tag-value">{$tr('targetManager.batch.tagLabel')}</label>
          <input 
            id="batch-tag-value"
            type="text"
            bind:value={batchTagValue}
            placeholder={$tr('targetManager.batch.tagPlaceholder')}
            class="form-input"
            onkeydown={(e) => e.key === 'Enter' && executeBatchTags()}
          />
        </div>
        
        <div class="form-group">
          <label class="checkbox-label">
            <input type="checkbox" bind:checked={batchTagAppend} />
            {$tr('targetManager.batch.tagAppend')}
          </label>
        </div>
      </div>
      
      <div class="modal-footer">
        <button class="cancel-button" onclick={() => showBatchTagModal = false}>
          {$tr('targetManager.buttons.cancel')}
        </button>
        <button class="submit-button" onclick={executeBatchTags} disabled={!batchTagValue.trim()}>
          {$tr('targetManager.buttons.confirm')}
        </button>
      </div>
    </div>
  </div>
{/if}

<style>
	.nd-page { padding: 1.5rem; max-width: 1200px; margin: 0 auto; min-height: 100vh; }
	.page-header { margin-bottom: 1.5rem; padding-bottom: 1rem; border-bottom: 1px solid rgba(168, 85, 247, 0.15); }
	.header-left { display: flex; flex-direction: column; }
	.back-link { color: #94a3b8; text-decoration: none; font-size: 0.8rem; transition: color 0.2s; }
	.back-link:hover { color: #a855f7; }
	.page-title { font-size: 1.5rem; font-weight: 700; margin: 0.5rem 0 0.25rem; color: #f1f5f9; }
	.page-subtitle { color: #94a3b8; font-size: 0.875rem; margin: 0; }

	.tabs { display: flex; gap: 0.25rem; margin-bottom: 1.25rem; background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(168, 85, 247, 0.15); border-radius: 0.75rem; padding: 0.25rem; }
	.tab-btn { flex: 1; padding: 0.6rem 1rem; border: none; border-radius: 0.5rem; background: transparent; cursor: pointer; font-size: 0.85rem; color: #94a3b8; transition: all 0.2s; display: flex; align-items: center; justify-content: center; gap: 0.4rem; }
	.tab-btn.active { background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%); color: white; font-weight: 600; box-shadow: 0 2px 8px rgba(168, 85, 247, 0.3); }
	.tab-btn:hover:not(.active) { background: rgba(168, 85, 247, 0.1); color: #c4b5fd; }
	.tab-icon { font-size: 0.9rem; }

	.section-card { background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(168, 85, 247, 0.15); border-radius: 0.75rem; padding: 1.25rem; }

	.sub-tabs { display: flex; gap: 0.2rem; margin-bottom: 0.75rem; background: rgba(15, 23, 42, 0.6); border-radius: 0.5rem; padding: 0.2rem; flex-wrap: wrap; }
	.sub-tab { padding: 0.35rem 0.75rem; border: none; border-radius: 0.375rem; background: transparent; cursor: pointer; font-size: 0.8rem; color: #94a3b8; transition: all 0.2s; white-space: nowrap; }
	.sub-tab.active { background: rgba(168, 85, 247, 0.2); color: #c4b5fd; }
	.sub-tab:hover:not(.active) { color: #e2e8f0; }

  .toolbar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 0.75rem;
    margin-bottom: 1rem;
    flex-wrap: wrap;
  }

  .toolbar-actions {
    display: flex;
    gap: 0.5rem;
    align-items: center;
  }

  .selection-info {
    padding: 0.35rem 0.75rem;
    background: rgba(168, 85, 247, 0.1);
    border: 1px solid rgba(168, 85, 247, 0.2);
    border-radius: 0.4rem;
    color: #c4b5fd;
    font-size: 0.8rem;
    font-weight: 500;
  }

  .batch-button {
    display: inline-flex;
    align-items: center;
    gap: 0.35rem;
    padding: 0.4rem 0.75rem;
    border-radius: 0.4rem;
    font-size: 0.8rem;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.2s;
    border: 1px solid;
  }

  .batch-button:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .batch-button.import {
    background: rgba(16, 185, 129, 0.1);
    border-color: rgba(16, 185, 129, 0.2);
    color: #10b981;
  }

  .batch-button.import:hover:not(:disabled) {
    background: rgba(16, 185, 129, 0.15);
    border-color: rgba(16, 185, 129, 0.3);
  }

  .batch-button.export {
    background: rgba(59, 130, 246, 0.1);
    border-color: rgba(59, 130, 246, 0.2);
    color: #60a5fa;
  }

  .batch-button.export:hover:not(:disabled) {
    background: rgba(59, 130, 246, 0.15);
    border-color: rgba(59, 130, 246, 0.3);
  }

  .batch-button.delete {
    background: rgba(239, 68, 68, 0.1);
    border-color: rgba(239, 68, 68, 0.2);
    color: #f87171;
  }

  .batch-button.delete:hover:not(:disabled) {
    background: rgba(239, 68, 68, 0.15);
    border-color: rgba(239, 68, 68, 0.3);
  }

  .batch-button.group {
    background: rgba(59, 130, 246, 0.1);
    border-color: rgba(59, 130, 246, 0.2);
    color: #60a5fa;
  }

  .batch-button.group:hover:not(:disabled) {
    background: rgba(59, 130, 246, 0.15);
    border-color: rgba(59, 130, 246, 0.3);
  }

  .batch-button.tag {
    background: rgba(34, 197, 94, 0.1);
    border-color: rgba(34, 197, 94, 0.2);
    color: #4ade80;
  }

  .batch-button.tag:hover:not(:disabled) {
    background: rgba(34, 197, 94, 0.15);
    border-color: rgba(34, 197, 94, 0.3);
  }

  .filter-bar {
    display: flex;
    gap: 0.5rem;
    align-items: center;
    padding: 0.6rem 0;
    flex-wrap: wrap;
  }

  .filter-select {
    padding: 0.35rem 0.5rem;
    background: rgba(15, 23, 42, 0.6);
    border: 1px solid rgba(148, 163, 184, 0.2);
    border-radius: 0.4rem;
    color: #e2e8f0;
    font-size: 0.8rem;
    cursor: pointer;
    min-width: 100px;
  }

  .filter-select:focus {
    outline: none;
    border-color: #a855f7;
  }

  .filter-select.sort-select {
    min-width: 120px;
  }

  .filter-input {
    padding: 0.35rem 0.5rem;
    background: rgba(15, 23, 42, 0.6);
    border: 1px solid rgba(148, 163, 184, 0.2);
    border-radius: 0.4rem;
    color: #e2e8f0;
    font-size: 0.8rem;
    width: 120px;
  }

  .filter-input:focus {
    outline: none;
    border-color: #a855f7;
  }

  .filter-input::placeholder {
    color: #64748b;
  }

  .sort-order-btn {
    padding: 0.35rem 0.5rem;
    background: rgba(168, 85, 247, 0.1);
    border: 1px solid rgba(168, 85, 247, 0.2);
    border-radius: 0.4rem;
    color: #a855f7;
    font-size: 0.9rem;
    cursor: pointer;
    min-width: 32px;
    text-align: center;
  }

  .sort-order-btn:hover {
    background: rgba(168, 85, 247, 0.2);
  }

  .clear-filter-btn {
    padding: 0.35rem 0.6rem;
    background: rgba(239, 68, 68, 0.1);
    border: 1px solid rgba(239, 68, 68, 0.2);
    border-radius: 0.4rem;
    color: #f87171;
    font-size: 0.8rem;
    cursor: pointer;
    white-space: nowrap;
  }

  .clear-filter-btn:hover {
    background: rgba(239, 68, 68, 0.15);
  }

  .quick-actions {
    padding: 1rem 0;
    border-top: 1px solid rgba(148, 163, 184, 0.1);
  }

  .quick-actions h3 {
    font-size: 0.85rem;
    color: #94a3b8;
    margin-bottom: 0.6rem;
  }

  .quick-action-buttons {
    display: flex;
    flex-wrap: wrap;
    gap: 0.4rem;
  }

  .quick-action-btn {
    display: inline-flex;
    align-items: center;
    gap: 0.3rem;
    padding: 0.35rem 0.6rem;
    background: rgba(168, 85, 247, 0.08);
    border: 1px solid rgba(168, 85, 247, 0.15);
    border-radius: 0.4rem;
    color: #c4b5fd;
    font-size: 0.78rem;
    text-decoration: none;
    transition: all 0.2s;
  }

  .quick-action-btn:hover {
    background: rgba(168, 85, 247, 0.15);
    border-color: rgba(168, 85, 247, 0.3);
    color: #e2e8f0;
  }

  .batch-tag-modal {
    max-width: 420px;
  }

  .batch-hint {
    color: #94a3b8;
    font-size: 0.85rem;
    margin-bottom: 1rem;
  }

  .checkbox-label {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    color: #cbd5e1;
    font-size: 0.85rem;
    cursor: pointer;
  }

  .checkbox-label input[type="checkbox"] {
    width: 16px;
    height: 16px;
    accent-color: #a855f7;
  }

  .checkbox-cell {
    width: 40px;
    text-align: center;
  }

  .checkbox-cell input[type="checkbox"] {
    width: 18px;
    height: 18px;
    cursor: pointer;
    accent-color: #a855f7;
  }

  .refresh-button {
    display: inline-flex;
    align-items: center;
    gap: 0.35rem;
    padding: 0.4rem 0.75rem;
    background: rgba(15, 23, 42, 0.6);
    border: 1px solid rgba(148, 163, 184, 0.2);
    color: #94a3b8;
    border-radius: 0.4rem;
    font-size: 0.8rem;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.2s;
  }

  .refresh-button:hover:not(:disabled) {
    border-color: rgba(168, 85, 247, 0.3);
    color: #c4b5fd;
  }

  .refresh-button:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .refresh-button svg {
    transition: transform 0.3s ease;
  }

  .refresh-button svg.spinning {
    animation: spin 1s linear infinite;
  }

  @keyframes spin {
    from {
      transform: rotate(0deg);
    }
    to {
      transform: rotate(360deg);
    }
  }

  .targets-layout {
    display: flex;
    gap: 1.5rem;
    min-height: 600px;
  }

  .groups-sidebar {
    width: 280px;
    background: rgba(15, 23, 42, 0.6);
    border-radius: 0.75rem;
    padding: 1rem;
    border: 1px solid rgba(168, 85, 247, 0.15);
    height: fit-content;
  }

  .groups-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 0.75rem;
    padding-bottom: 0.5rem;
    border-bottom: 1px solid rgba(168, 85, 247, 0.15);
  }

  .groups-header h3 {
    font-size: 0.95rem;
    font-weight: 600;
    color: #c4b5fd;
  }

  .add-group-btn {
    width: 28px;
    height: 28px;
    border-radius: 0.4rem;
    background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%);
    border: none;
    color: white;
    font-size: 1rem;
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    transition: all 0.2s;
  }

  .add-group-btn:hover {
    box-shadow: 0 2px 8px rgba(168, 85, 247, 0.3);
  }

  .groups-list {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }

  .group-item-wrapper {
    position: relative;
  }

  .group-item {
    width: 100%;
    display: flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.5rem;
    border-radius: 0.4rem;
    cursor: pointer;
    transition: all 0.2s;
    text-align: left;
  }

  .group-item:hover {
    filter: brightness(1.1);
  }

  .group-item.active {
    filter: brightness(1.2);
  }

  .group-icon {
    font-size: 1rem;
  }

  .group-name {
    flex: 1;
    color: #e2e8f0;
    font-size: 0.8rem;
    font-weight: 500;
  }

  .group-count {
    background: rgba(168, 85, 247, 0.15);
    color: #c4b5fd;
    padding: 0.1rem 0.4rem;
    border-radius: 0.3rem;
    font-size: 0.7rem;
    font-weight: 600;
  }

  .context-menu-overlay {
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    z-index: 2000;
  }

  .context-menu {
    position: fixed;
    background: rgba(15, 23, 42, 0.95);
    border: 1px solid rgba(168, 85, 247, 0.2);
    border-radius: 0.5rem;
    box-shadow: 0 8px 24px rgba(0, 0, 0, 0.5);
    padding: 0.35rem 0;
    min-width: 160px;
    z-index: 2001;
    animation: contextMenuFadeIn 0.15s ease-out;
  }

  @keyframes contextMenuFadeIn {
    from {
      opacity: 0;
      transform: scale(0.95);
    }
    to {
      opacity: 1;
      transform: scale(1);
    }
  }

  .context-menu-item {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    width: 100%;
    padding: 0.5rem 0.75rem;
    background: transparent;
    border: none;
    color: #e2e8f0;
    font-size: 0.8rem;
    font-family: inherit;
    cursor: pointer;
    transition: all 0.2s;
    text-align: left;
  }

  .context-menu-item:hover {
    background: rgba(168, 85, 247, 0.1);
    color: #f1f5f9;
  }

  .context-menu-item.delete {
    color: #fca5a5;
  }

  .context-menu-item.delete:hover {
    background: rgba(239, 68, 68, 0.1);
  }

  .context-menu-icon {
    font-size: 0.9rem;
  }

  .color-picker-wrapper {
    display: flex;
    gap: 1rem;
    align-items: center;
  }

  .color-input {
    width: 60px;
    height: 50px;
    border: 2px solid rgba(168, 85, 247, 0.3);
    border-radius: 10px;
    cursor: pointer;
    padding: 0;
    background: transparent;
  }

  .color-input::-webkit-color-swatch-wrapper {
    padding: 4px;
  }

  .color-input::-webkit-color-swatch {
    border-radius: 6px;
    border: none;
  }

  .color-preview {
    flex: 1;
    height: 50px;
    border-radius: 10px;
    display: flex;
    align-items: center;
    justify-content: center;
    border: 2px solid rgba(255, 255, 255, 0.1);
    transition: all 0.3s ease;
  }

  .color-value {
    font-size: 0.9rem;
    font-weight: 600;
    color: white;
    text-shadow: 0 1px 3px rgba(0, 0, 0, 0.5);
    font-family: 'Courier New', monospace;
    text-transform: uppercase;
  }

  .icon-picker {
    display: flex;
    flex-direction: column;
    gap: 1rem;
    max-width: 100%;
    overflow: hidden;
  }

  .selected-icon {
    font-size: 2.5rem;
    text-align: center;
    padding: 1rem;
    border-radius: 10px;
    transition: all 0.3s ease;
    max-width: 100%;
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .icon-search {
    position: relative;
  }

  .icon-search .search-input {
    width: 100%;
    padding: 0.75rem 1rem;
    background: rgba(30, 30, 46, 0.4);
    border: 1px solid rgba(168, 85, 247, 0.3);
    border-radius: 8px;
    color: #e2e8f0;
    font-size: 0.9rem;
    transition: all 0.2s;
  }

  .icon-search .search-input:focus {
    outline: none;
    border-color: #a855f7;
    background: rgba(30, 30, 46, 0.6);
  }

  .icon-search .search-input::placeholder {
    color: #94a3b8;
  }

  .category-tabs {
    display: flex;
    gap: 0.5rem;
    overflow-x: auto;
    padding: 0.5rem 0;
    scrollbar-width: none;
    max-width: 100%;
    flex-wrap: wrap;
  }

  .category-tabs::-webkit-scrollbar {
    display: none;
  }

  .category-tab {
    flex-shrink: 0;
    padding: 0.5rem 1rem;
    background: rgba(30, 30, 46, 0.4);
    border: 1px solid rgba(168, 85, 247, 0.2);
    border-radius: 20px;
    color: #e2e8f0;
    font-size: 0.85rem;
    cursor: pointer;
    transition: all 0.2s;
    white-space: nowrap;
  }

  .category-tab:hover {
    background: rgba(168, 85, 247, 0.2);
    border-color: rgba(168, 85, 247, 0.4);
  }

  .category-tab.active {
    background: rgba(168, 85, 247, 0.3);
    border-color: #a855f7;
    color: #f1f5f9;
  }

  .icon-grid-container {
    background: rgba(30, 30, 46, 0.3);
    border-radius: 10px;
    border: 1px solid rgba(168, 85, 247, 0.15);
    padding: 0.75rem;
    overflow: hidden;
    max-width: 100%;
  }

  .icon-grid {
    display: grid;
    grid-template-columns: repeat(8, 1fr);
    gap: 0.5rem;
    max-width: 100%;
  }

  .icon-option {
    width: 100%;
    aspect-ratio: 1;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 1.35rem;
    background: rgba(30, 30, 46, 0.4);
    border: 2px solid transparent;
    border-radius: 8px;
    cursor: pointer;
    transition: all 0.2s ease;
    padding: 0;
  }

  .icon-option:hover {
    background: rgba(168, 85, 247, 0.2);
    border-color: rgba(168, 85, 247, 0.4);
    transform: scale(1.1);
  }

  .icon-option.selected {
    background: rgba(168, 85, 247, 0.3);
    border-color: #a855f7;
    box-shadow: 0 0 12px rgba(168, 85, 247, 0.4);
  }

  .targets-content {
    flex: 1;
    min-width: 0;
  }

  .search-box {
    display: flex;
    gap: 0.5rem;
    flex: 1;
    max-width: 500px;
  }

  .search-box input {
    flex: 1;
    padding: 0.75rem 1rem;
    background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
    border: 1px solid rgba(168, 85, 247, 0.2);
    border-radius: 6px;
    font-size: 1rem;
    color: #f1f5f9;
    transition: all 0.2s;
  }

  .search-box input::placeholder {
    color: #64748b;
  }

  .search-box input:focus {
    outline: none;
    border-color: #a855f7;
    box-shadow: 0 0 0 3px rgba(168, 85, 247, 0.1);
  }

  .search-button {
    padding: 0.75rem 1.5rem;
    background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%);
    color: white;
    border: none;
    border-radius: 6px;
    font-size: 1rem;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.2s;
    box-shadow: 0 4px 6px -1px rgba(168, 85, 247, 0.3);
  }

  .search-button:hover {
    background: linear-gradient(135deg, #9333ea 0%, #4f46e5 100%);
    transform: translateY(-2px);
    box-shadow: 0 6px 12px -1px rgba(168, 85, 247, 0.4);
  }

  .create-button {
    display: inline-flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.875rem 1.75rem;
    background: linear-gradient(135deg, #10b981 0%, #059669 100%);
    color: white;
    border: none;
    border-radius: 12px;
    font-size: 1rem;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    box-shadow: 0 4px 14px 0 rgba(16, 185, 129, 0.39);
    position: relative;
    overflow: hidden;
  }

  .create-button::before {
    content: '';
    position: absolute;
    top: 0;
    left: -100%;
    width: 100%;
    height: 100%;
    background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.2), transparent);
    transition: left 0.5s;
  }

  .create-button:hover::before {
    left: 100%;
  }

  .create-button:hover {
    background: linear-gradient(135deg, #059669 0%, #047857 100%);
    transform: translateY(-3px);
    box-shadow: 0 8px 20px 0 rgba(16, 185, 129, 0.5);
  }

  .create-button:active {
    transform: translateY(-1px);
    box-shadow: 0 4px 12px 0 rgba(16, 185, 129, 0.4);
  }

  .error-message {
    background: linear-gradient(135deg, #dc2626 0%, #991b1b 100%);
    border: 1px solid rgba(239, 68, 68, 0.3);
    color: white;
    padding: 1rem;
    border-radius: 6px;
    margin-bottom: 1.5rem;
    display: flex;
    align-items: center;
    gap: 0.5rem;
    box-shadow: 0 4px 6px -1px rgba(239, 68, 68, 0.2);
  }

  .error-icon {
    font-size: 1.25rem;
  }

  .targets-table {
    background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
    border: 1px solid rgba(168, 85, 247, 0.2);
    border-radius: 1rem;
    overflow: hidden;
    box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.3);
  }

  .loading,
  .empty-state {
    padding: 3rem;
    text-align: center;
    color: #94a3b8;
  }

  .spinner {
    width: 24px;
    height: 24px;
    border: 3px solid rgba(168, 85, 247, 0.2);
    border-top-color: #a855f7;
    border-radius: 50%;
    animation: spin 0.6s linear infinite;
    display: inline-block;
  }

  @keyframes spin {
    to {
      transform: rotate(360deg);
    }
  }

  .empty-icon {
    font-size: 3rem;
    margin-bottom: 1rem;
    display: block;
  }

  .targets-table table {
    width: 100%;
    border-collapse: collapse;
  }

  .targets-table thead {
    background: rgba(168, 85, 247, 0.1);
  }

  .targets-table th {
    padding: 1rem;
    text-align: left;
    font-size: 0.875rem;
    font-weight: 600;
    color: #f1f5f9;
    border-bottom: 1px solid rgba(168, 85, 247, 0.2);
  }

  .targets-table td {
    padding: 1rem;
    border-bottom: 1px solid rgba(168, 85, 247, 0.1);
    font-size: 0.875rem;
    color: #cbd5e1;
  }

  .targets-table tr:last-child td {
    border-bottom: none;
  }

  .targets-table tr:hover {
    background: rgba(168, 85, 247, 0.05);
  }

  .name-cell strong {
    display: block;
    color: #f1f5f9;
    margin-bottom: 0.25rem;
  }

  .description {
    font-size: 0.75rem;
    color: #64748b;
  }

  .type-badge {
    display: inline-block;
    padding: 0.25rem 0.5rem;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: 600;
  }

  .type-badge.ip {
    background: rgba(59, 130, 246, 0.2);
    color: #60a5fa;
    border: 1px solid rgba(59, 130, 246, 0.3);
  }

  .type-badge.domain {
    background: rgba(16, 185, 129, 0.2);
    color: #34d399;
    border: 1px solid rgba(16, 185, 129, 0.3);
  }

  .type-badge.url {
    background: rgba(245, 158, 11, 0.2);
    color: #fbbf24;
    border: 1px solid rgba(245, 158, 11, 0.3);
  }

  .type-badge.subnet {
    background: rgba(236, 72, 153, 0.2);
    color: #f472b6;
    border: 1px solid rgba(236, 72, 153, 0.3);
  }

  .type-badge.range {
    background: rgba(139, 92, 246, 0.2);
    color: #a78bfa;
    border: 1px solid rgba(139, 92, 246, 0.3);
  }

  .type-badge.hostname {
    background: rgba(20, 184, 166, 0.2);
    color: #2dd4bf;
    border: 1px solid rgba(20, 184, 166, 0.3);
  }

  .type-badge.network {
    background: rgba(99, 102, 241, 0.2);
    color: #818cf8;
    border: 1px solid rgba(99, 102, 241, 0.3);
  }

  .type-badge.service {
    background: rgba(251, 146, 60, 0.2);
    color: #fb923c;
    border: 1px solid rgba(251, 146, 60, 0.3);
  }

  .type-badge.username {
    background: rgba(34, 197, 94, 0.2);
    color: #4ade80;
    border: 1px solid rgba(34, 197, 94, 0.3);
  }

  .type-badge.email {
    background: rgba(168, 85, 247, 0.2);
    color: #c084fc;
    border: 1px solid rgba(168, 85, 247, 0.3);
  }

  .type-badge.phone {
    background: rgba(236, 72, 153, 0.2);
    color: #f472b6;
    border: 1px solid rgba(236, 72, 153, 0.3);
  }

  .type-badge.socialmedia {
    background: rgba(14, 165, 233, 0.2);
    color: #38bdf8;
    border: 1px solid rgba(14, 165, 233, 0.3);
  }

  .priority-badge {
    display: inline-block;
    padding: 0.125rem 0.375rem;
    border-radius: 3px;
    font-size: 0.7rem;
    font-weight: 600;
    text-transform: uppercase;
  }

  .priority-badge.critical {
    background: rgba(220, 38, 38, 0.2);
    color: #ef4444;
    border: 1px solid rgba(220, 38, 38, 0.3);
  }

  .priority-badge.high {
    background: rgba(234, 88, 12, 0.2);
    color: #f97316;
    border: 1px solid rgba(234, 88, 12, 0.3);
  }

  .priority-badge.medium {
    background: rgba(202, 138, 4, 0.2);
    color: #eab308;
    border: 1px solid rgba(202, 138, 4, 0.3);
  }

  .priority-badge.low {
    background: rgba(16, 185, 129, 0.2);
    color: #22c55e;
    border: 1px solid rgba(16, 185, 129, 0.3);
  }

  .priority-badge.normal {
    background: rgba(100, 116, 139, 0.2);
    color: #94a3b8;
    border: 1px solid rgba(100, 116, 139, 0.3);
  }

  .risk-badge {
    display: inline-block;
    padding: 0.125rem 0.375rem;
    border-radius: 3px;
    font-size: 0.7rem;
    font-weight: 600;
  }

  .risk-badge.critical {
    background: rgba(220, 38, 38, 0.2);
    color: #ef4444;
    border: 1px solid rgba(220, 38, 38, 0.3);
  }

  .risk-badge.high {
    background: rgba(234, 88, 12, 0.2);
    color: #f97316;
    border: 1px solid rgba(234, 88, 12, 0.3);
  }

  .risk-badge.medium {
    background: rgba(202, 138, 4, 0.2);
    color: #eab308;
    border: 1px solid rgba(202, 138, 4, 0.3);
  }

  .risk-badge.low {
    background: rgba(16, 185, 129, 0.2);
    color: #22c55e;
    border: 1px solid rgba(16, 185, 129, 0.3);
  }

  .risk-badge.info {
    background: rgba(100, 116, 139, 0.2);
    color: #94a3b8;
    border: 1px solid rgba(100, 116, 139, 0.3);
  }

  .tags-container {
    display: flex;
    flex-wrap: wrap;
    gap: 0.25rem;
  }

  .tag {
    display: inline-block;
    padding: 0.125rem 0.375rem;
    background: rgba(148, 163, 184, 0.1);
    color: #94a3b8;
    border-radius: 3px;
    font-size: 0.75rem;
    border: 1px solid rgba(148, 163, 184, 0.2);
  }

  .group-badge {
    display: inline-flex;
    align-items: center;
    gap: 0.25rem;
    padding: 0.25rem 0.5rem;
    border-radius: 6px;
    font-size: 0.875rem;
    font-weight: 500;
  }

  .actions-cell {
    display: flex;
    gap: 0.5rem;
  }

  .action-button {
    padding: 0.375rem 0.75rem;
    border: none;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.2s;
  }

  .action-button.edit {
    background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);
    color: white;
    box-shadow: 0 2px 4px -1px rgba(59, 130, 246, 0.3);
  }

  .action-button.edit:hover {
    transform: translateY(-1px);
    box-shadow: 0 4px 6px -1px rgba(59, 130, 246, 0.4);
  }

  .action-button.delete {
    background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
    color: white;
    box-shadow: 0 2px 4px -1px rgba(239, 68, 68, 0.3);
  }

  .action-button.delete:hover {
    transform: translateY(-1px);
    box-shadow: 0 4px 6px -1px rgba(239, 68, 68, 0.4);
  }

  .pagination {
    display: flex;
    justify-content: center;
    align-items: center;
    gap: 1rem;
    margin-top: 1.5rem;
  }

  .pagination-button {
    padding: 0.5rem 1rem;
    background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
    border: 1px solid rgba(168, 85, 247, 0.2);
    border-radius: 6px;
    font-size: 0.875rem;
    color: #f1f5f9;
    cursor: pointer;
    transition: all 0.2s;
  }

  .pagination-button:hover:not(:disabled) {
    background: rgba(168, 85, 247, 0.1);
    border-color: #a855f7;
  }

  .pagination-button:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .pagination-info {
    font-size: 0.875rem;
    color: #94a3b8;
  }

  .drawer-overlay {
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: rgba(0, 0, 0, 0.75);
    backdrop-filter: blur(4px);
    z-index: 1000;
    animation: fadeIn 0.3s ease-out;
  }

  @keyframes fadeIn {
    from {
      opacity: 0;
    }
    to {
      opacity: 1;
    }
  }

  .drawer {
    position: fixed;
    top: 0;
    right: 0;
    bottom: 0;
    width: 500px;
    max-width: 100%;
    background: linear-gradient(135deg, #1e1e2e 0%, #181825 100%);
    border-left: 1px solid rgba(168, 85, 247, 0.3);
    box-shadow: -10px 0 40px rgba(0, 0, 0, 0.5),
                0 0 0 1px rgba(168, 85, 247, 0.1);
    backdrop-filter: blur(10px);
    display: flex;
    flex-direction: column;
    animation: slideInRight 0.3s cubic-bezier(0.4, 0, 0.2, 1);
  }

  @keyframes slideInRight {
    from {
      transform: translateX(100%);
      opacity: 0;
    }
    to {
      transform: translateX(0);
      opacity: 1;
    }
  }

  .drawer-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 2rem 2rem 1.5rem;
    border-bottom: 1px solid rgba(168, 85, 247, 0.15);
    background: linear-gradient(180deg, rgba(168, 85, 247, 0.08) 0%, transparent 100%);
    flex-shrink: 0;
  }

  .drawer-header h2 {
    font-size: 1.5rem;
    font-weight: 700;
    color: #f1f5f9;
    background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%);
    -webkit-background-clip: text;
    background-clip: text;
    -webkit-text-fill-color: transparent;
    letter-spacing: -0.025em;
  }

  .close-button {
    background: rgba(239, 68, 68, 0.1);
    border: 1px solid rgba(239, 68, 68, 0.2);
    font-size: 1.5rem;
    color: #ef4444;
    cursor: pointer;
    padding: 0;
    width: 2.5rem;
    height: 2.5rem;
    display: flex;
    align-items: center;
    justify-content: center;
    transition: all 0.2s;
    border-radius: 8px;
  }

  .close-button:hover {
    background: rgba(239, 68, 68, 0.2);
    border-color: rgba(239, 68, 68, 0.4);
    color: #fca5a5;
    transform: rotate(90deg);
  }

  .drawer-body {
    flex: 1;
    overflow-y: auto;
    padding: 2rem;
  }

  .form-group {
    margin-bottom: 1.5rem;
  }

  .form-group label,
  .form-group .form-label {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.9rem;
    font-weight: 600;
    color: #e2e8f0;
    margin-bottom: 0.625rem;
  }

  .form-group label::before,
  .form-group .form-label::before {
    content: '';
    width: 4px;
    height: 1rem;
    background: linear-gradient(180deg, #a855f7 0%, #6366f1 100%);
    border-radius: 2px;
  }

  .form-group input,
  .form-group textarea {
    width: 100%;
    padding: 0.875rem 1.25rem;
    background: rgba(30, 30, 46, 0.6);
    border: 2px solid rgba(168, 85, 247, 0.15);
    border-radius: 10px;
    font-size: 1rem;
    font-family: inherit;
    color: #f1f5f9;
    transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
  }

  .form-group select {
    width: 100%;
    padding: 0.875rem 1.25rem;
    background-color: rgba(30, 30, 46, 0.6);
    border: 2px solid rgba(168, 85, 247, 0.15);
    border-radius: 10px;
    font-size: 1rem;
    font-family: inherit;
    color: #f1f5f9;
    transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    cursor: pointer;
    appearance: none;
    background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' fill='none' viewBox='0 0 24 24' stroke='%23a855f7'%3E%3Cpath stroke-linecap='round' stroke-linejoin='round' stroke-width='2' d='M19 9l-7 7-7-7'%3E%3C/path%3E%3C/svg%3E");
    background-repeat: no-repeat;
    background-position: right 1rem center;
    background-size: 1.25rem;
    padding-right: 3rem;
  }

  .form-group input::placeholder,
  .form-group textarea::placeholder {
    color: #64748b;
  }

  .form-group input:hover,
  .form-group textarea:hover {
    border-color: rgba(168, 85, 247, 0.3);
    background: rgba(30, 30, 46, 0.8);
  }

  .form-group select:hover {
    border-color: rgba(168, 85, 247, 0.3);
    background-color: rgba(30, 30, 46, 0.8);
  }

  .form-group input:focus,
  .form-group textarea:focus {
    outline: none;
    border-color: #a855f7;
    box-shadow: 0 0 0 4px rgba(168, 85, 247, 0.15),
                0 0 20px rgba(168, 85, 247, 0.2);
    background: rgba(30, 30, 46, 0.9);
  }

  .form-group select:focus {
    outline: none;
    border-color: #a855f7;
    box-shadow: 0 0 0 4px rgba(168, 85, 247, 0.15),
                0 0 20px rgba(168, 85, 247, 0.2);
    background-color: rgba(30, 30, 46, 0.9);
  }

  .drawer-footer {
    display: flex;
    justify-content: flex-end;
    gap: 1rem;
    padding: 1.5rem 2rem 2rem;
    border-top: 1px solid rgba(168, 85, 247, 0.15);
    background: linear-gradient(180deg, transparent 0%, rgba(168, 85, 247, 0.05) 100%);
    flex-shrink: 0;
  }

  .cancel-button {
    padding: 0.875rem 2rem;
    background: rgba(148, 163, 184, 0.1);
    border: 2px solid rgba(148, 163, 184, 0.2);
    border-radius: 10px;
    font-size: 1rem;
    font-weight: 500;
    color: #94a3b8;
    cursor: pointer;
    transition: all 0.2s;
  }

  .cancel-button:hover {
    background: rgba(148, 163, 184, 0.15);
    border-color: rgba(148, 163, 184, 0.4);
    color: #f1f5f9;
    transform: translateY(-1px);
  }

  .submit-button {
    padding: 0.875rem 2rem;
    background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%);
    color: white;
    border: none;
    border-radius: 10px;
    font-size: 1rem;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    display: flex;
    align-items: center;
    gap: 0.5rem;
    box-shadow: 0 4px 14px 0 rgba(168, 85, 247, 0.4);
    position: relative;
    overflow: hidden;
  }

  .submit-button::before {
    content: '';
    position: absolute;
    top: 0;
    left: -100%;
    width: 100%;
    height: 100%;
    background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.3), transparent);
    transition: left 0.5s;
  }

  .submit-button:hover:not(:disabled)::before {
    left: 100%;
  }

  .submit-button:hover:not(:disabled) {
    background: linear-gradient(135deg, #9333ea 0%, #4f46e5 100%);
    transform: translateY(-3px);
    box-shadow: 0 8px 20px 0 rgba(168, 85, 247, 0.5);
  }

  .submit-button:active:not(:disabled) {
    transform: translateY(-1px);
    box-shadow: 0 4px 12px 0 rgba(168, 85, 247, 0.4);
  }

  .submit-button:disabled {
    opacity: 0.6;
    cursor: not-allowed;
    filter: grayscale(0.3);
  }

  @media (max-width: 768px) {
    .toolbar {
      flex-direction: column;
      align-items: stretch;
    }

    .search-box {
      max-width: none;
    }

    .targets-table {
      overflow-x: auto;
    }

    .drawer {
      width: 100%;
    }

    .drawer-header,
    .drawer-body,
    .drawer-footer {
      padding-left: 1.5rem;
      padding-right: 1.5rem;
    }
  }

  .port-filters {
    background: rgba(255, 255, 255, 0.05);
    padding: 1.5rem;
    border-radius: 0.75rem;
    margin-bottom: 1.5rem;
    border: 1px solid rgba(255, 255, 255, 0.1);
  }

  .port-search-box {
    position: relative;
    margin-bottom: 1rem;
  }

  .port-search-box input {
    width: 100%;
    padding: 0.75rem 2.5rem 0.75rem 1rem;
    background: rgba(255, 255, 255, 0.05);
    border: 1px solid rgba(255, 255, 255, 0.1);
    border-radius: 0.5rem;
    color: #e5e7eb;
    font-size: 1rem;
  }

  .port-search-box input:focus {
    outline: none;
    border-color: #a855f7;
    background: rgba(255, 255, 255, 0.08);
  }

  .clear-search-btn {
    position: absolute;
    right: 0.75rem;
    top: 50%;
    transform: translateY(-50%);
    background: rgba(255, 255, 255, 0.1);
    border: none;
    border-radius: 50%;
    width: 1.5rem;
    height: 1.5rem;
    display: flex;
    align-items: center;
    justify-content: center;
    cursor: pointer;
    color: #9ca3af;
    font-size: 0.875rem;
    transition: all 0.2s;
  }

  .clear-search-btn:hover {
    background: rgba(255, 255, 255, 0.2);
    color: #e5e7eb;
  }

  .filter-row {
    display: flex;
    gap: 1rem;
    margin-bottom: 1rem;
  }

  .filter-row select {
    flex: 1;
    padding: 0.5rem;
    background: rgba(255, 255, 255, 0.05);
    border: 1px solid rgba(255, 255, 255, 0.1);
    border-radius: 0.5rem;
    color: #e5e7eb;
  }

  .port-stats {
    display: flex;
    justify-content: space-between;
    align-items: center;
    color: #9ca3af;
    font-size: 0.9rem;
  }

  .add-port-btn {
    padding: 0.5rem 1rem;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    border: none;
    border-radius: 0.5rem;
    color: white;
    font-size: 0.9rem;
    cursor: pointer;
    transition: all 0.2s ease;
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }

  .add-port-btn:hover {
    transform: translateY(-2px);
    box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4);
  }

  .port-table {
    background: rgba(255, 255, 255, 0.05);
    border-radius: 0.75rem;
    overflow: hidden;
    border: 1px solid rgba(255, 255, 255, 0.1);
  }

  .port-table table {
    width: 100%;
    border-collapse: collapse;
  }

  .port-table thead {
    background: rgba(0, 0, 0, 0.3);
  }

  .port-table th {
    padding: 1rem;
    text-align: left;
    font-weight: 600;
    color: #e5e7eb;
    border-bottom: 2px solid rgba(255, 255, 255, 0.1);
  }

  .port-table td {
    padding: 0.75rem 1rem;
    border-bottom: 1px solid rgba(255, 255, 255, 0.05);
  }

  .port-table tbody tr:hover {
    background: rgba(255, 255, 255, 0.05);
  }

  .port-number strong {
    font-size: 1.1rem;
    color: #60a5fa;
  }

  .service-name {
    font-weight: 500;
    color: #e5e7eb;
  }

  .protocol {
    color: #9ca3af;
    font-size: 0.9rem;
  }

  .category-badge {
    display: inline-block;
    padding: 0.25rem 0.75rem;
    background: rgba(168, 85, 247, 0.2);
    border-radius: 1rem;
    font-size: 0.85rem;
    white-space: nowrap;
  }

  .risk-badge {
    display: inline-block;
    padding: 0.25rem 0.75rem;
    border-radius: 1rem;
    font-size: 0.85rem;
    color: white;
    font-weight: 500;
  }

  .description {
    color: #9ca3af;
    font-size: 0.9rem;
    max-width: 300px;
  }

  .mark-badges {
    display: flex;
    gap: 0.25rem;
    align-items: center;
  }

  .mark-badge {
    font-size: 1.1rem;
  }

  .mark-note {
    font-size: 1rem;
    cursor: help;
  }

  .no-mark {
    color: #6b7280;
  }

  .actions {
    display: flex;
    gap: 0.5rem;
  }

  .action-btn {
    padding: 0.375rem 0.625rem;
    background: rgba(255, 255, 255, 0.05);
    border: 1px solid rgba(255, 255, 255, 0.1);
    border-radius: 0.375rem;
    cursor: pointer;
    transition: all 0.2s ease;
    font-size: 1.1rem;
    min-width: 2.5rem;
    height: 2.5rem;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    line-height: 1;
  }

  .action-btn:hover {
    background: rgba(255, 255, 255, 0.1);
    transform: translateY(-2px);
    box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
  }

  .action-btn.favorite:hover {
    background: rgba(251, 191, 36, 0.2);
    border-color: rgba(251, 191, 36, 0.4);
  }

  .action-btn.important:hover {
    background: rgba(239, 68, 68, 0.2);
    border-color: rgba(239, 68, 68, 0.4);
  }

  .action-btn.dangerous:hover {
    background: rgba(249, 115, 22, 0.2);
    border-color: rgba(249, 115, 22, 0.4);
  }

  .action-btn.remove {
    background: rgba(239, 68, 68, 0.1);
    border-color: rgba(239, 68, 68, 0.2);
  }

  .action-btn.remove:hover {
    background: rgba(239, 68, 68, 0.3);
    border-color: rgba(239, 68, 68, 0.5);
  }

  .pagination {
    display: flex;
    justify-content: center;
    align-items: center;
    gap: 1rem;
    margin-top: 2rem;
  }

  .page-btn {
    padding: 0.5rem 1.5rem;
    background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%);
    border: none;
    border-radius: 0.5rem;
    color: white;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.2s;
  }

  .page-btn:hover:not(:disabled) {
    background: linear-gradient(135deg, #9333ea 0%, #4f46e5 100%);
    transform: translateY(-1px);
  }

  .page-btn:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .page-info {
    color: #9ca3af;
  }

  .batch-import-modal {
    max-width: 700px;
    max-height: 90vh;
    overflow-y: auto;
  }

  .import-hint {
    padding: 1rem;
    background: rgba(168, 85, 247, 0.1);
    border: 1px solid rgba(168, 85, 247, 0.2);
    border-radius: 8px;
    margin-bottom: 1.5rem;
  }

  .import-hint p {
    margin: 0;
    color: #c4b5fd;
    font-size: 0.9rem;
  }

  .format-guide {
    margin-bottom: 1.5rem;
    padding: 1rem;
    background: rgba(30, 30, 50, 0.5);
    border: 1px solid rgba(168, 85, 247, 0.1);
    border-radius: 8px;
  }

  .format-guide h3 {
    margin: 0 0 0.75rem 0;
    font-size: 1rem;
    color: #a855f7;
  }

  .format-hint {
    margin: 0 0 0.75rem 0;
    color: #94a3b8;
    font-size: 0.875rem;
  }

  .format-example {
    margin: 0;
    padding: 0.75rem;
    background: rgba(0, 0, 0, 0.3);
    border-radius: 6px;
    color: #e2e8f0;
    font-size: 0.8rem;
    font-family: 'Courier New', monospace;
    white-space: pre-wrap;
    word-wrap: break-word;
  }

  .batch-import-modal .form-group label {
    display: block;
    margin-bottom: 0.5rem;
    color: #e2e8f0;
    font-weight: 500;
  }

  .batch-import-modal textarea {
    width: 100%;
    padding: 0.75rem;
    background: rgba(30, 30, 50, 0.5);
    border: 2px solid rgba(168, 85, 247, 0.2);
    border-radius: 8px;
    color: #e2e8f0;
    font-size: 0.9rem;
    font-family: 'Courier New', monospace;
    resize: vertical;
    transition: all 0.3s ease;
  }

  .batch-import-modal textarea:focus {
    outline: none;
    border-color: #a855f7;
    background: rgba(30, 30, 50, 0.8);
  }

  .batch-import-modal textarea:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }

  .modal-overlay {
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: rgba(0, 0, 0, 0.75);
    backdrop-filter: blur(4px);
    z-index: 1000;
    display: flex;
    align-items: center;
    justify-content: center;
    animation: fadeIn 0.3s ease-out;
  }

  .modal-content {
    background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
    border: 2px solid rgba(168, 85, 247, 0.3);
    border-radius: 16px;
    padding: 2rem;
    max-width: 600px;
    width: 90%;
    max-height: 90vh;
    overflow-y: auto;
    animation: slideIn 0.3s ease-out;
    box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
  }

  @keyframes slideIn {
    from {
      opacity: 0;
      transform: translateY(-20px);
    }
    to {
      opacity: 1;
      transform: translateY(0);
    }
  }

  .modal-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 1.5rem;
    padding-bottom: 1rem;
    border-bottom: 2px solid rgba(168, 85, 247, 0.2);
  }

  .modal-header h2 {
    margin: 0;
    font-size: 1.5rem;
    font-weight: 600;
    background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%);
    -webkit-background-clip: text;
    background-clip: text;
    -webkit-text-fill-color: transparent;
  }

  .modal-close {
    background: transparent;
    border: none;
    color: #94a3b8;
    font-size: 1.5rem;
    cursor: pointer;
    padding: 0.5rem;
    line-height: 1;
    transition: color 0.2s;
  }

  .modal-close:hover {
    color: #e2e8f0;
  }

  .modal-body {
    margin-bottom: 1.5rem;
  }

  .modal-footer {
    display: flex;
    justify-content: flex-end;
    gap: 1rem;
    padding-top: 1rem;
    border-top: 2px solid rgba(168, 85, 247, 0.2);
  }

  .cancel-button,
  .submit-button {
    padding: 0.75rem 1.5rem;
    border-radius: 10px;
    font-size: 1rem;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    border: 2px solid;
  }

  .cancel-button {
    background: rgba(100, 116, 139, 0.1);
    border-color: rgba(100, 116, 139, 0.3);
    color: #94a3b8;
  }

  .cancel-button:hover:not(:disabled) {
    background: rgba(100, 116, 139, 0.2);
    border-color: rgba(100, 116, 139, 0.5);
  }

  .submit-button {
    background: linear-gradient(135deg, rgba(168, 85, 247, 0.2) 0%, rgba(99, 102, 241, 0.2) 100%);
    border-color: rgba(168, 85, 247, 0.3);
    color: #a855f7;
  }

  .submit-button:hover:not(:disabled) {
    background: linear-gradient(135deg, rgba(168, 85, 247, 0.3) 0%, rgba(99, 102, 241, 0.3) 100%);
    border-color: #a855f7;
    transform: translateY(-2px);
    box-shadow: 0 8px 24px rgba(168, 85, 247, 0.3);
  }

  .cancel-button:disabled,
  .submit-button:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .import-methods {
    margin-bottom: 1.5rem;
    display: flex;
    flex-direction: column;
    gap: 1rem;
  }

  .file-select-button {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 0.5rem;
    padding: 1rem 2rem;
    background: linear-gradient(135deg, rgba(59, 130, 246, 0.15) 0%, rgba(99, 102, 241, 0.15) 100%);
    border: 2px solid rgba(59, 130, 246, 0.3);
    border-radius: 10px;
    color: #60a5fa;
    font-size: 1rem;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
  }

  .file-select-button:hover:not(:disabled) {
    background: linear-gradient(135deg, rgba(59, 130, 246, 0.25) 0%, rgba(99, 102, 241, 0.25) 100%);
    border-color: #60a5fa;
    transform: translateY(-2px);
    box-shadow: 0 8px 24px rgba(59, 130, 246, 0.3);
  }

  .file-select-button:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .or-divider {
    display: flex;
    align-items: center;
    gap: 1rem;
  }

  .or-divider::before,
  .or-divider::after {
    content: '';
    flex: 1;
    height: 1px;
    background: linear-gradient(90deg, transparent, rgba(168, 85, 247, 0.3), transparent);
  }

  .or-divider span {
    color: #94a3b8;
    font-size: 0.875rem;
    font-weight: 500;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }

  .detail-panel {
    width: 600px;
  }

  .detail-section {
    margin-bottom: 1.5rem;
    padding-bottom: 1.5rem;
    border-bottom: 1px solid rgba(168, 85, 247, 0.1);
  }

  .detail-section:last-child {
    border-bottom: none;
    margin-bottom: 0;
    padding-bottom: 0;
  }

  .detail-section h3 {
    font-size: 1rem;
    font-weight: 700;
    color: #a855f7;
    margin-bottom: 1rem;
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }

  .detail-section h3::before {
    content: '';
    width: 4px;
    height: 1rem;
    background: linear-gradient(180deg, #a855f7 0%, #6366f1 100%);
    border-radius: 2px;
  }

  .detail-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1rem;
  }

  .detail-item {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
  }

  .detail-item.full-width {
    grid-column: 1 / -1;
  }

  .detail-item label {
    font-size: 0.75rem;
    font-weight: 600;
    color: #64748b;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }

  .detail-item span {
    font-size: 0.95rem;
    color: #e2e8f0;
  }

  .value-text {
    font-family: 'JetBrains Mono', 'Fira Code', monospace;
    color: #38bdf8 !important;
    word-break: break-all;
  }

  .metadata-text {
    font-family: 'JetBrains Mono', 'Fira Code', monospace;
    font-size: 0.85rem !important;
    color: #94a3b8 !important;
    white-space: pre-wrap;
    word-break: break-all;
    max-height: 200px;
    overflow-y: auto;
    background: rgba(0, 0, 0, 0.2);
    padding: 0.75rem;
    border-radius: 8px;
    border: 1px solid rgba(168, 85, 247, 0.1);
  }

  .status-badge {
    display: inline-block;
    padding: 0.2rem 0.6rem;
    border-radius: 6px;
    font-size: 0.8rem;
    font-weight: 600;
    text-transform: capitalize;
  }

  .status-badge.active,
  .status-badge.completed {
    background: rgba(34, 197, 94, 0.15);
    color: #22c55e;
  }

  .status-badge.inactive,
  .status-badge.failed {
    background: rgba(239, 68, 68, 0.15);
    color: #ef4444;
  }

  .status-badge.scanning {
    background: rgba(59, 130, 246, 0.15);
    color: #3b82f6;
  }

  .status-badge.unknown {
    background: rgba(148, 163, 184, 0.15);
    color: #94a3b8;
  }

  .name-cell.clickable {
    cursor: pointer;
    transition: color 0.2s;
  }

  .name-cell.clickable:hover strong {
    color: #a855f7;
  }

  .btn-primary {
    padding: 0.875rem 2rem;
    background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%);
    color: white;
    border: none;
    border-radius: 10px;
    font-size: 1rem;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.3s;
    box-shadow: 0 4px 14px 0 rgba(168, 85, 247, 0.4);
  }

  .btn-primary:hover {
    transform: translateY(-1px);
    box-shadow: 0 6px 20px 0 rgba(168, 85, 247, 0.6);
  }
</style>
