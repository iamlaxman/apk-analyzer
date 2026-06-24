// APK Analyzer Pro - Main Application JavaScript
(function() {
    'use strict';

    // Configuration
    const API_BASE = '/api';
    let currentSession = null;
    let analysisData = null;
    let currentFilePath = null;
    let isUploading = false;

    // Initialize when DOM is ready
    document.addEventListener('DOMContentLoaded', init);

    function init() {
        setupDragAndDrop();
        setupKeyboardShortcuts();
        console.log('APK Analyzer Pro initialized');
    }

    // ============ Sidebar Toggle ============
    window.toggleSidebar = function() {
        const sidebar = document.getElementById('sidebar');
        const overlay = document.getElementById('sidebarOverlay');
        
        sidebar.classList.toggle('open');
        overlay.classList.toggle('open');
    };

    // Close sidebar when clicking on mobile
    document.addEventListener('click', function(e) {
        const sidebar = document.getElementById('sidebar');
        const overlay = document.getElementById('sidebarOverlay');
        
        if (e.target === overlay) {
            sidebar.classList.remove('open');
            overlay.classList.remove('open');
        }
    });

    // Close sidebar on window resize (desktop)
    window.addEventListener('resize', function() {
        if (window.innerWidth >= 768) {
            const sidebar = document.getElementById('sidebar');
            const overlay = document.getElementById('sidebarOverlay');
            sidebar.classList.remove('open');
            overlay.classList.remove('open');
        }
    });

    // ============ File Upload ============
    window.handleFileUpload = async function(input) {
        const file = input.files[0];
        if (!file) return;
        
        if (!file.name.toLowerCase().endsWith('.apk')) {
            showToast('Please upload a valid APK file', 'error');
            input.value = '';
            return;
        }

        if (isUploading) {
            showToast('Upload already in progress', 'error');
            return;
        }

        isUploading = true;
        
        try {
            showProgress();
            updateProgress(10, 'Uploading APK...');

            const formData = new FormData();
            formData.append('file', file);

            const response = await fetch(`${API_BASE}/upload`, {
                method: 'POST',
                body: formData
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || 'Upload failed');
            }

            const data = await response.json();
            currentSession = data.session_id;
            
            updateProgress(50, 'Analyzing...');
            
            // Get full analysis
            const analysisResponse = await fetch(`${API_BASE}/analyze/${currentSession}`);
            if (!analysisResponse.ok) {
                throw new Error('Analysis failed');
            }
            
            const analysisData2 = await analysisResponse.json();
            analysisData = analysisData2.analysis;
            
            updateProgress(80, 'Loading file tree...');
            
            // Load file tree
            await loadFileTree();
            
            updateProgress(100, 'Complete!');
            
            // Show dashboard
            setTimeout(() => {
                hideProgress();
                document.getElementById('uploadZone').style.display = 'none';
                document.getElementById('dashboard').classList.remove('hidden');
                document.getElementById('currentFileName').textContent = file.name;
                
                renderAllTabs();
                switchTab('overview');
                showToast('APK analyzed successfully!', 'success');
            }, 500);

        } catch (error) {
            hideProgress();
            showToast(error.message || 'Upload failed', 'error');
            console.error('Upload error:', error);
        } finally {
            isUploading = false;
            input.value = '';
        }
    };

    // ============ Progress ============
    function showProgress() {
        document.getElementById('progressContainer').classList.remove('hidden');
    }

    function hideProgress() {
        document.getElementById('progressContainer').classList.add('hidden');
        updateProgress(0, '');
    }

    function updateProgress(percent, text) {
        document.getElementById('progressFill').style.width = percent + '%';
        document.getElementById('progressText').textContent = text;
    }

    // ============ Drag and Drop ============
    function setupDragAndDrop() {
        const uploadZone = document.getElementById('uploadZone');
        if (!uploadZone) return;

        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            document.body.addEventListener(eventName, preventDefaults, false);
        });

        function preventDefaults(e) {
            e.preventDefault();
            e.stopPropagation();
        }

        ['dragenter', 'dragover'].forEach(eventName => {
            document.body.addEventListener(eventName, () => {
                uploadZone.style.borderColor = 'var(--border-brand)';
                uploadZone.style.background = 'var(--brand-softer)';
            }, false);
        });

        ['dragleave', 'drop'].forEach(eventName => {
            document.body.addEventListener(eventName, () => {
                uploadZone.style.borderColor = 'var(--border-default)';
                uploadZone.style.background = 'var(--neutral-primary-soft)';
            }, false);
        });

        document.body.addEventListener('drop', function(e) {
            const files = e.dataTransfer.files;
            if (files.length > 0) {
                const input = document.getElementById('fileInput');
                const dataTransfer = new DataTransfer();
                dataTransfer.items.add(files[0]);
                input.files = dataTransfer.files;
                handleFileUpload(input);
            }
        }, false);
    }

    // ============ File Tree ============
    async function loadFileTree(path = '') {
        if (!currentSession) return;

        try {
            const response = await fetch(`${API_BASE}/files/${currentSession}?path=${encodeURIComponent(path)}`);
            if (!response.ok) throw new Error('Failed to load files');
            
            const data = await response.json();
            renderFileTree(data.files, document.getElementById('fileTreeContainer'));
        } catch (error) {
            console.error('Error loading file tree:', error);
            document.getElementById('fileTreeContainer').innerHTML = 
                '<p class="text-sm text-danger p-4">Error loading files</p>';
        }
    }

    function renderFileTree(files, container, level = 0) {
        if (level === 0) {
            container.innerHTML = '';
        }

        const list = document.createElement('ul');
        list.className = 'file-tree';

        files.forEach(file => {
            const item = document.createElement('li');
            const link = document.createElement('a');
            link.className = 'file-tree-item';
            link.href = '#';
            link.style.paddingLeft = (12 + level * 24) + 'px';
            
            link.innerHTML = `
                <span style="font-size: 18px;">${file.icon || (file.type === 'directory' ? '📁' : '📄')}</span>
                <span class="truncate" style="flex: 1;">${escapeHtml(file.name)}</span>
                ${file.type === 'file' ? `<span class="text-xs text-body" style="margin-left: auto;">${file.size_formatted || formatSize(file.size)}</span>` : ''}
                <button class="btn btn-icon btn-sm" onclick="event.stopPropagation(); downloadPath('${file.path}')" title="Download" style="margin-left: 4px;">
                    ⬇️
                </button>
            `;

            if (file.type === 'directory') {
                link.onclick = (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    
                    // Toggle children
                    const existingChildren = item.querySelector('.file-tree-children');
                    if (existingChildren) {
                        existingChildren.remove();
                    } else {
                        const childrenContainer = document.createElement('div');
                        childrenContainer.className = 'file-tree-children';
                        item.appendChild(childrenContainer);
                        
                        fetch(`${API_BASE}/files/${currentSession}?path=${encodeURIComponent(file.path)}`)
                            .then(res => res.json())
                            .then(data => {
                                renderFileTree(data.files, childrenContainer, level + 1);
                            })
                            .catch(err => {
                                console.error('Error loading directory:', err);
                            });
                    }
                };
            } else {
                link.onclick = (e) => {
                    e.preventDefault();
                    previewFile(file.path, file.name);
                };
            }

            item.appendChild(link);
            list.appendChild(item);
        });

        container.appendChild(list);
    }

    // ============ File Preview ============
    async function previewFile(filepath, filename) {
        if (!currentSession) return;

        currentFilePath = filepath;
        
        try {
            const response = await fetch(`${API_BASE}/file-content/${currentSession}?path=${encodeURIComponent(filepath)}`);
            if (!response.ok) throw new Error('Failed to load file');
            
            const data = await response.json();
            
            const modal = document.getElementById('filePreviewModal');
            const title = document.getElementById('filePreviewTitle');
            const content = document.getElementById('filePreviewContent');
            const downloadBtn = document.getElementById('filePreviewDownload');
            
            title.textContent = filename;
            downloadBtn.onclick = () => downloadPath(filepath);
            
            if (data.preview) {
                content.innerHTML = `<div class="code-block">${escapeHtml(data.content)}</div>`;
            } else {
                content.innerHTML = `
                    <div class="alert alert-warning">
                        <h4>Preview Not Available</h4>
                        <p>${data.message || 'This file type cannot be previewed.'}</p>
                        <p class="text-sm mt-2">Size: ${data.size || 'Unknown'}</p>
                    </div>
                `;
            }
            
            modal.classList.remove('hidden');
            
        } catch (error) {
            showToast('Error loading file preview', 'error');
            console.error('Preview error:', error);
        }
    }

    window.closeFilePreview = function(event) {
        if (event && event.target !== document.getElementById('filePreviewModal')) return;
        document.getElementById('filePreviewModal').classList.add('hidden');
        currentFilePath = null;
    };

    // ============ Download Functions ============
    window.downloadPath = function(filepath) {
        if (!currentSession) {
            showToast('Please upload an APK first', 'error');
            return;
        }
        
        const url = `${API_BASE}/download/${currentSession}/${encodeURIComponent(filepath)}`;
        const link = document.createElement('a');
        link.href = url;
        link.download = filepath.split('/').pop();
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        
        showToast('Download started!', 'success');
    };

    window.downloadAll = function() {
        if (!currentSession) {
            showToast('Please upload an APK first', 'error');
            return;
        }
        
        const url = `${API_BASE}/download-all/${currentSession}`;
        const link = document.createElement('a');
        link.href = url;
        link.download = 'extracted_apk.zip';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        
        showToast('Downloading all files...', 'success');
    };

    window.exportReport = function() {
        if (!currentSession) {
            showToast('Please upload an APK first', 'error');
            return;
        }
        
        const url = `${API_BASE}/export-report/${currentSession}`;
        const link = document.createElement('a');
        link.href = url;
        link.download = 'apk_analysis_report.json';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        
        showToast('Report downloaded!', 'success');
    };

    // ============ Tab Switching ============
    window.switchTab = function(tabName) {
        // Update tab buttons
        document.querySelectorAll('.tab').forEach(tab => {
            tab.classList.remove('active');
            tab.setAttribute('aria-selected', 'false');
        });
        
        const activeTab = document.querySelector(`.tab[onclick="switchTab('${tabName}')"]`);
        if (activeTab) {
            activeTab.classList.add('active');
            activeTab.setAttribute('aria-selected', 'true');
        }
        
        // Update tab contents
        document.querySelectorAll('[id^="tab-"]').forEach(content => {
            content.classList.add('hidden');
        });
        
        const activeContent = document.getElementById(`tab-${tabName}`);
        if (activeContent) {
            activeContent.classList.remove('hidden');
        }
        
        // Render tab content if needed
        if (analysisData) {
            renderTabContent(tabName);
        }
    };

    function renderTabContent(tabName) {
        switch(tabName) {
            case 'overview': renderOverview(); break;
            case 'manifest': renderManifest(); break;
            case 'classes': renderClasses(); break;
            case 'permissions': renderPermissions(); break;
            case 'security': renderSecurity(); break;
            case 'techstack': renderTechStack(); break;
        }
    }

    function renderAllTabs() {
        renderOverview();
    }

    // ============ Tab Renderers ============
    function renderOverview() {
        if (!analysisData) return;
        
        const info = analysisData.basic_info;
        const dex = analysisData.dex_analysis;
        const components = analysisData.components;
        
        // Stats cards
        document.getElementById('statsGrid').innerHTML = `
            <div class="card">
                <p class="text-xs text-body font-semibold" style="text-transform: uppercase; letter-spacing: 0.5px;">Package Name</p>
                <p class="text-heading font-bold truncate" style="font-size: 14px;">${escapeHtml(info.package_name)}</p>
            </div>
            <div class="card">
                <p class="text-xs text-body font-semibold" style="text-transform: uppercase; letter-spacing: 0.5px;">Version</p>
                <p class="text-heading font-bold">${escapeHtml(info.version_name)} (${info.version_code})</p>
            </div>
            <div class="card">
                <p class="text-xs text-body font-semibold" style="text-transform: uppercase; letter-spacing: 0.5px;">SDK Range</p>
                <p class="text-heading font-bold">Min: ${info.min_sdk} | Target: ${info.target_sdk}</p>
            </div>
            <div class="card">
                <p class="text-xs text-body font-semibold" style="text-transform: uppercase; letter-spacing: 0.5px;">Total Classes</p>
                <p class="text-heading font-bold" style="font-size: 28px;">${dex.total_classes || 0}</p>
            </div>
            <div class="card">
                <p class="text-xs text-body font-semibold" style="text-transform: uppercase; letter-spacing: 0.5px;">Total Methods</p>
                <p class="text-heading font-bold" style="font-size: 28px;">${dex.total_methods || 0}</p>
            </div>
            <div class="card">
                <p class="text-xs text-body font-semibold" style="text-transform: uppercase; letter-spacing: 0.5px;">File Size</p>
                <p class="text-heading font-bold" style="font-size: 28px;">${formatSize(analysisData.total_size)}</p>
            </div>
        `;
        
        // Components table
        document.getElementById('tab-overview').innerHTML = `
            <h3>Components</h3>
            <div class="table-wrapper">
                <table class="table">
                    <thead>
                        <tr>
                            <th>Type</th>
                            <th>Count</th>
                            <th>Examples</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td class="font-semibold">Activities</td>
                            <td>${components.activities.length}</td>
                            <td class="truncate" style="max-width: 300px;">${components.activities.slice(0, 3).join(', ') || 'None'}</td>
                        </tr>
                        <tr>
                            <td class="font-semibold">Services</td>
                            <td>${components.services.length}</td>
                            <td class="truncate" style="max-width: 300px;">${components.services.slice(0, 3).join(', ') || 'None'}</td>
                        </tr>
                        <tr>
                            <td class="font-semibold">Receivers</td>
                            <td>${components.receivers.length}</td>
                            <td class="truncate" style="max-width: 300px;">${components.receivers.slice(0, 3).join(', ') || 'None'}</td>
                        </tr>
                        <tr>
                            <td class="font-semibold">Providers</td>
                            <td>${components.providers.length}</td>
                            <td class="truncate" style="max-width: 300px;">${components.providers.slice(0, 3).join(', ') || 'None'}</td>
                        </tr>
                    </tbody>
                </table>
            </div>
            
            <h3 class="mt-8">DEX Files</h3>
            <div class="table-wrapper">
                <table class="table">
                    <thead>
                        <tr>
                            <th>File</th>
                            <th>Size</th>
                            <th>Classes</th>
                            <th>Methods</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${dex.dex_files.map(d => `
                            <tr>
                                <td class="font-semibold">${escapeHtml(d.name)}</td>
                                <td>${formatSize(d.size)}</td>
                                <td>${d.class_count}</td>
                                <td>${d.method_count}</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        `;
    }

    async function renderManifest() {
        if (!currentSession) return;
        
        try {
            const response = await fetch(`${API_BASE}/manifest/${currentSession}`);
            if (!response.ok) throw new Error('Failed to load manifest');
            
            const data = await response.json();
            
            document.getElementById('tab-manifest').innerHTML = `
                <h3>AndroidManifest.xml</h3>
                <div class="code-block">${escapeHtml(data.manifest)}</div>
            `;
        } catch (error) {
            document.getElementById('tab-manifest').innerHTML = `
                <div class="alert alert-danger">Error loading manifest: ${error.message}</div>
            `;
        }
    }

    function renderClasses() {
        if (!analysisData) return;
        
        const dex = analysisData.dex_analysis;
        
        let html = `
            <div class="search-wrapper">
                <span class="search-icon">🔍</span>
                <input type="text" class="input search-input" id="classSearch" placeholder="Search classes..." onkeyup="filterClasses()">
            </div>
        `;
        
        dex.dex_files.forEach((dexFile, index) => {
            html += `
                <div class="accordion mb-4">
                    <div class="accordion-item">
                        <button class="accordion-trigger" onclick="this.parentElement.querySelector('.accordion-panel').classList.toggle('hidden'); this.querySelector('.accordion-chevron').classList.toggle('rotated')">
                            <span>📦 ${escapeHtml(dexFile.name)} (${dexFile.class_count} classes)</span>
                            <span class="accordion-chevron">▼</span>
                        </button>
                        <div class="accordion-panel hidden">
                            <div class="table-wrapper">
                                <table class="table" id="classesTable${index}">
                                    <thead>
                                        <tr>
                                            <th>Class Name</th>
                                            <th>Type</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        ${dexFile.classes.map(cls => `
                                            <tr>
                                                <td class="truncate" style="max-width: 400px;">${escapeHtml(cls)}</td>
                                                <td><span class="badge badge-brand">class</span></td>
                                            </tr>
                                        `).join('')}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
            `;
        });
        
        document.getElementById('tab-classes').innerHTML = html;
    }

    window.filterClasses = function() {
        const search = document.getElementById('classSearch')?.value.toLowerCase() || '';
        document.querySelectorAll('[id^="classesTable"] tbody tr').forEach(row => {
            const text = row.textContent.toLowerCase();
            row.style.display = text.includes(search) ? '' : 'none';
        });
    };

    function renderPermissions() {
        if (!analysisData) return;
        
        const permissions = analysisData.permissions;
        const dangerous = ['SMS', 'LOCATION', 'CAMERA', 'CONTACTS', 'PHONE', 'STORAGE', 'MICROPHONE', 'CALL_LOG'];
        
        document.getElementById('tab-permissions').innerHTML = `
            <h3>Permissions (${permissions.length})</h3>
            <div class="table-wrapper">
                <table class="table">
                    <thead>
                        <tr>
                            <th>Permission</th>
                            <th>Risk Level</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${permissions.map(perm => {
                            const isDangerous = dangerous.some(d => perm.toUpperCase().includes(d));
                            return `
                                <tr>
                                    <td class="truncate" style="max-width: 500px;">${escapeHtml(perm)}</td>
                                    <td>
                                        <span class="badge ${isDangerous ? 'badge-danger' : 'badge-success'}">
                                            ${isDangerous ? '⚠️ Dangerous' : '✅ Normal'}
                                        </span>
                                    </td>
                                </tr>
                            `;
                        }).join('')}
                        ${permissions.length === 0 ? '<tr><td colspan="2" class="text-center">No permissions found</td></tr>' : ''}
                    </tbody>
                </table>
            </div>
        `;
    }

    function renderSecurity() {
        if (!analysisData) return;
        
        const issues = analysisData.security;
        
        document.getElementById('tab-security').innerHTML = `
            <h3>Security Analysis</h3>
            ${issues.length === 0 ? 
                '<div class="alert alert-success">✅ No security issues found</div>' :
                issues.map(issue => `
                    <div class="alert alert-${issue.severity === 'high' ? 'danger' : issue.severity === 'medium' ? 'warning' : 'brand'} mb-3">
                        <h4>${escapeHtml(issue.type)}</h4>
                        <p>${escapeHtml(issue.description)}</p>
                        <span class="badge badge-${issue.severity === 'high' ? 'danger' : issue.severity === 'medium' ? 'warning' : 'brand'} text-xs">
                            ${issue.severity.toUpperCase()}
                        </span>
                    </div>
                `).join('')
            }
        `;
    }

    function renderTechStack() {
        if (!analysisData) return;
        
        const tech = analysisData.tech_stack;
        
        document.getElementById('tab-techstack').innerHTML = `
            <div class="grid grid-3">
                <div class="card">
                    <h4>Languages</h4>
                    <div class="flex flex-wrap gap-2">
                        ${tech.languages.map(l => `<span class="badge badge-brand">${escapeHtml(l)}</span>`).join('')}
                        ${tech.languages.length === 0 ? '<p class="text-body text-sm">None detected</p>' : ''}
                    </div>
                </div>
                <div class="card">
                    <h4>Frameworks</h4>
                    <div class="flex flex-wrap gap-2">
                        ${tech.frameworks.map(f => `<span class="badge badge-warning">${escapeHtml(f)}</span>`).join('')}
                        ${tech.frameworks.length === 0 ? '<p class="text-body text-sm">None detected</p>' : ''}
                    </div>
                </div>
                <div class="card">
                    <h4>Libraries</h4>
                    <div class="flex flex-wrap gap-2">
                        ${tech.libraries.map(lib => `<span class="badge badge-dark">${escapeHtml(lib)}</span>`).join('')}
                        ${tech.libraries.length === 0 ? '<p class="text-body text-sm">None detected</p>' : ''}
                    </div>
                </div>
            </div>
        `;
    }

    // ============ Keyboard Shortcuts ============
    function setupKeyboardShortcuts() {
        document.addEventListener('keydown', function(e) {
            // Escape to close modals
            if (e.key === 'Escape') {
                closeFilePreview();
            }
            
            // Ctrl+O to open file
            if (e.ctrlKey && e.key === 'o') {
                e.preventDefault();
                document.getElementById('fileInput').click();
            }
        });
    }

    // ============ Toast Notifications ============
    window.showToast = function(message, type = 'success') {
        const container = document.getElementById('toastContainer');
        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        toast.textContent = message;
        toast.setAttribute('role', 'alert');
        
        container.appendChild(toast);
        
        setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.transition = 'opacity 300ms ease';
            setTimeout(() => toast.remove(), 300);
        }, 3000);
    };

    // ============ Utility Functions ============
    function formatSize(bytes) {
        if (bytes === 0) return '0 B';
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(1024));
        return Math.round((bytes / Math.pow(1024, i)) * 100) / 100 + ' ' + sizes[i];
    }

    function escapeHtml(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    // Expose to global scope
    window.formatSize = formatSize;
    window.escapeHtml = escapeHtml;

})();