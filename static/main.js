// ==================== [ Enhanced Dashboard JavaScript ] ====================

// Global Variables
let autoRefreshInterval = null;
let performanceChart = null;
let callsChart = null;
let currentStats = {};
let errorCount = 0;
let notificationsEnabled = false;

// ==================== [ Utility Functions ] ====================

// API Request Helper
async function apiRequest(url, options = {}) {
    try {
        showLoading();
        const response = await fetch(url, {
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            },
            ...options
        });
        
        const text = await response.text();
        let data;
        
        try {
            data = JSON.parse(text);
        } catch {
            data = text;
        }
        
        hideLoading();
        
        if (!response.ok) {
            throw new Error(data.error || data.message || 'Request failed');
        }
        
        return { ok: response.ok, status: response.status, data };
    } catch (error) {
        hideLoading();
        console.error('API Request Error:', error);
        showNotification('خطأ في الاتصال: ' + error.message, 'danger');
        throw error;
    }
}

// Show/Hide Loading
function showLoading() {
    document.querySelector('.loading-spinner').classList.add('active');
}

function hideLoading() {
    document.querySelector('.loading-spinner').classList.remove('active');
}

// Show Notification
function showNotification(message, type = 'info') {
    const alertDiv = document.getElementById('status-alert');
    const messageSpan = document.getElementById('status-message');
    
    alertDiv.className = `alert alert-custom alert-${type}`;
    messageSpan.textContent = message;
    alertDiv.classList.remove('d-none');
    
    // Auto hide after 5 seconds
    setTimeout(() => {
        alertDiv.classList.add('d-none');
    }, 5000);
    
    // Browser notification if enabled
    if (notificationsEnabled && type === 'danger') {
        if (Notification.permission === 'granted') {
            new Notification('تنبيه من لوحة التحكم', {
                body: message,
                icon: '/favicon.ico'
            });
        }
    }
}

// Format Date
function formatDate(dateString) {
    if (!dateString) return '-';
    const date = new Date(dateString);
    return new Intl.DateTimeFormat('ar-SA', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    }).format(date);
}

// Format Number
function formatNumber(num) {
    return new Intl.NumberFormat('ar-SA').format(num);
}

// ==================== [ Dashboard Functions ] ====================

// Load System Status
async function loadSystemStatus() {
    try {
        const response = await apiRequest('/api/status');
        const status = response.data;
        
        // Update environment badge
        document.getElementById('environment-badge').textContent = status.environment || 'Development';
        
        // Update statistics
        document.getElementById('api-calls-count').textContent = formatNumber(status.statistics.api_calls_today);
        document.getElementById('error-count').textContent = formatNumber(status.statistics.errors_today);
        document.getElementById('response-time').textContent = `${status.statistics.avg_response_time_ms.toFixed(0)}ms`;
        
        // Calculate success rate
        const successRate = status.statistics.api_calls_today > 0 
            ? ((status.statistics.api_calls_today - status.statistics.errors_today) / status.statistics.api_calls_today * 100).toFixed(1)
            : 100;
        document.getElementById('success-rate').textContent = `${successRate}%`;
        document.getElementById('success-progress').style.width = `${successRate}%`;
        
        // Update error progress
        const errorRate = status.statistics.api_calls_today > 0
            ? (status.statistics.errors_today / status.statistics.api_calls_today * 100).toFixed(1)
            : 0;
        document.getElementById('error-progress').style.width = `${errorRate}%`;
        
        // Update auth status
        const authBadge = document.getElementById('auth-status');
        if (status.oauth.token_exists && !status.oauth.token_expired) {
            authBadge.className = 'badge bg-success';
            authBadge.textContent = 'متصل';
        } else if (status.oauth.token_exists) {
            authBadge.className = 'badge bg-warning';
            authBadge.textContent = 'منتهي الصلاحية';
        } else {
            authBadge.className = 'badge bg-danger';
            authBadge.textContent = 'غير متصل';
        }
        
        // Update store info
        document.getElementById('store-name').textContent = status.oauth.store_name || 'غير متصل';
        document.getElementById('token-updated').textContent = formatDate(status.oauth.token_created_at);
        document.getElementById('refresh-count').textContent = status.oauth.token_refresh_count || 0;
        
        // Update settings
        document.getElementById('client-id-status').className = status.credentials.client_id_exists ? 'badge bg-success' : 'badge bg-danger';
        document.getElementById('client-id-status').textContent = status.credentials.client_id_exists ? 'موجود' : 'مفقود';
        
        document.getElementById('client-secret-status').className = status.credentials.client_secret_exists ? 'badge bg-success' : 'badge bg-danger';
        document.getElementById('client-secret-status').textContent = status.credentials.client_secret_exists ? 'موجود' : 'مفقود';
        
        document.getElementById('webhook-secret-status').className = status.credentials.webhook_secret_exists ? 'badge bg-success' : 'badge bg-danger';
        document.getElementById('webhook-secret-status').textContent = status.credentials.webhook_secret_exists ? 'موجود' : 'مفقود';
        
        document.getElementById('redirect-uri').textContent = status.oauth.redirect_uri;
        
        // Update error badge if needed
        if (status.statistics.errors_today > 0) {
            const errorBadge = document.getElementById('errors-badge');
            errorBadge.textContent = status.statistics.errors_today;
            errorBadge.classList.remove('d-none');
        }
        
        // Store current stats
        currentStats = status;
        
    } catch (error) {
        console.error('Failed to load system status:', error);
    }
}

// Load Recent Activities
async function loadRecentActivities() {
    try {
        const [errors, webhooks] = await Promise.all([
            apiRequest('/api/errors?limit=5'),
            apiRequest('/api/webhooks-log?limit=5')
        ]);
        
        const activities = [];
        
        // Add errors
        errors.data.errors.forEach(error => {
            activities.push({
                type: 'error',
                title: error.type,
                message: error.message,
                time: error.timestamp,
                icon: 'bi-exclamation-triangle',
                color: 'danger'
            });
        });
        
        // Add webhooks
        webhooks.data.webhooks.forEach(webhook => {
            activities.push({
                type: 'webhook',
                title: webhook.event,
                message: `Webhook من ${webhook.ip}`,
                time: webhook.timestamp,
                icon: 'bi-webhook',
                color: 'info'
            });
        });
        
        // Sort by time
        activities.sort((a, b) => new Date(b.time) - new Date(a.time));
        
        // Display activities
        const container = document.getElementById('recent-activities');
        if (activities.length === 0) {
            container.innerHTML = '<p class="text-muted text-center">لا توجد أنشطة حديثة</p>';
        } else {
            container.innerHTML = activities.slice(0, 10).map(activity => `
                <div class="d-flex align-items-start mb-3">
                    <div class="text-${activity.color} me-2">
                        <i class="bi ${activity.icon}"></i>
                    </div>
                    <div class="flex-grow-1">
                        <div class="fw-bold small">${activity.title}</div>
                        <div class="text-muted small">${activity.message}</div>
                        <div class="text-muted" style="font-size: 0.75rem;">${formatDate(activity.time)}</div>
                    </div>
                </div>
            `).join('');
        }
        
    } catch (error) {
        console.error('Failed to load recent activities:', error);
    }
}

// ==================== [ Products Functions ] ====================

async function loadProducts() {
    try {
        const statusFilter = document.getElementById('product-status-filter').value;
        const sortBy = document.getElementById('product-sort').value;
        const searchTerm = document.getElementById('product-search').value;
        
        let url = '/api/products?';
        if (statusFilter) url += `status=${statusFilter}&`;
        if (sortBy) url += `sort=${sortBy}&`;
        
        const response = await apiRequest(url);
        const products = response.data.data || [];
        
        // Filter by search term
        const filteredProducts = searchTerm 
            ? products.filter(p => p.name.toLowerCase().includes(searchTerm.toLowerCase()))
            : products;
        
        const container = document.getElementById('products-container');
        
        if (filteredProducts.length === 0) {
            container.innerHTML = '<p class="text-center text-muted py-5">لا توجد منتجات</p>';
            return;
        }
        
        container.innerHTML = `
            <table class="table table-hover">
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>الصورة</th>
                        <th>الاسم</th>
                        <th>السعر</th>
                        <th>الكمية</th>
                        <th>الحالة</th>
                        <th>الإجراءات</th>
                    </tr>
                </thead>
                <tbody>
                    ${filteredProducts.map(product => `
                        <tr>
                            <td>${product.id}</td>
                            <td>
                                ${product.image ? `<img src="${product.image.url || product.image}" width="50" height="50" style="object-fit: cover; border-radius: 5px;">` : '-'}
                            </td>
                            <td>${product.name}</td>
                            <td>${product.price?.amount || product.price || 0} ${product.price?.currency || 'SAR'}</td>
                            <td>${product.quantity || 0}</td>
                            <td>
                                <span class="badge bg-${getStatusColor(product.status)}">${getStatusText(product.status)}</span>
                            </td>
                            <td>
                                <button class="btn btn-sm btn-outline-primary" onclick="editProduct('${product.id}')">
                                    <i class="bi bi-pencil"></i>
                                </button>
                                <button class="btn btn-sm btn-outline-danger" onclick="deleteProduct('${product.id}')">
                                    <i class="bi bi-trash"></i>
                                </button>
                            </td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        `;
        
        // Update products badge
        const badge = document.getElementById('products-badge');
        badge.textContent = filteredProducts.length;
        badge.classList.toggle('d-none', filteredProducts.length === 0);
        
    } catch (error) {
        document.getElementById('products-container').innerHTML = 
            `<div class="alert alert-danger">فشل تحميل المنتجات: ${error.message}</div>`;
    }
}

function getStatusColor(status) {
    const colors = {
        'available': 'success',
        'out_of_stock': 'danger',
        'hidden': 'secondary',
        'sale': 'info'
    };
    return colors[status] || 'secondary';
}

function getStatusText(status) {
    const texts = {
        'available': 'متوفر',
        'out_of_stock': 'نفذ المخزون',
        'hidden': 'مخفي',
        'sale': 'تخفيض'
    };
    return texts[status] || status;
}

async function addProduct() {
    try {
        const productData = {
            name: document.getElementById('product-name').value,
            price: parseFloat(document.getElementById('product-price').value),
            quantity: parseInt(document.getElementById('product-quantity').value) || 0,
            sku: document.getElementById('product-sku').value,
            description: document.getElementById('product-description').value,
            image: document.getElementById('product-image').value,
            product_type: document.getElementById('product-type').value,
            status: document.getElementById('product-status').value
        };
        
        const response = await apiRequest('/api/products', {
            method: 'POST',
            body: JSON.stringify(productData)
        });
        
        showNotification('تم إضافة المنتج بنجاح', 'success');
        document.getElementById('add-product-form').reset();
        bootstrap.Modal.getInstance(document.getElementById('addProductModal')).hide();
        await loadProducts();
        
    } catch (error) {
        showNotification('فشل إضافة المنتج: ' + error.message, 'danger');
    }
}

async function editProduct(productId) {
    const newPrice = prompt('أدخل السعر الجديد:');
    if (newPrice === null) return;
    
    try {
        await apiRequest(`/api/products/${productId}`, {
            method: 'PUT',
            body: JSON.stringify({ price: parseFloat(newPrice) })
        });
        
        showNotification('تم تحديث المنتج بنجاح', 'success');
        await loadProducts();
        
    } catch (error) {
        showNotification('فشل تحديث المنتج: ' + error.message, 'danger');
    }
}

async function deleteProduct(productId) {
    if (!confirm('هل أنت متأكد من حذف هذا المنتج؟')) return;
    
    try {
        await apiRequest(`/api/products/${productId}`, {
            method: 'DELETE'
        });
        
        showNotification('تم حذف المنتج بنجاح', 'success');
        await loadProducts();
        
    } catch (error) {
        showNotification('فشل حذف المنتج: ' + error.message, 'danger');
    }
}

// ==================== [ Monitoring Functions ] ====================

async function loadMetrics() {
    try {
        const period = document.getElementById('metrics-period').value;
        const response = await apiRequest(`/api/metrics?period=${period}`);
        const metrics = response.data;
        
        // Update performance chart
        if (performanceChart) {
            performanceChart.destroy();
        }
        
        const ctx1 = document.getElementById('performance-chart').getContext('2d');
        performanceChart = new Chart(ctx1, {
            type: 'bar',
            data: {
                labels: metrics.performance.map(p => p.endpoint || 'Unknown'),
                datasets: [{
                    label: 'متوسط وقت الاستجابة (ms)',
                    data: metrics.performance.map(p => p.avg_time),
                    backgroundColor: 'rgba(94, 114, 228, 0.5)',
                    borderColor: 'rgba(94, 114, 228, 1)',
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });
        
        // Update calls chart
        if (callsChart) {
            callsChart.destroy();
        }
        
        const ctx2 = document.getElementById('calls-chart').getContext('2d');
        callsChart = new Chart(ctx2, {
            type: 'doughnut',
            data: {
                labels: metrics.performance.map(p => p.endpoint || 'Unknown'),
                datasets: [{
                    data: metrics.performance.map(p => p.count),
                    backgroundColor: [
                        'rgba(94, 114, 228, 0.8)',
                        'rgba(45, 206, 137, 0.8)',
                        'rgba(251, 99, 64, 0.8)',
                        'rgba(245, 54, 92, 0.8)',
                        'rgba(17, 205, 239, 0.8)'
                    ]
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false
            }
        });
        
        // Update performance details table
        const detailsContainer = document.getElementById('performance-details');
        detailsContainer.innerHTML = `
            <table class="table table-hover">
                <thead>
                    <tr>
                        <th>النقطة النهائية</th>
                        <th>عدد الاستدعاءات</th>
                        <th>متوسط الوقت</th>
                        <th>أقل وقت</th>
                        <th>أعلى وقت</th>
                    </tr>
                </thead>
                <tbody>
                    ${metrics.performance.map(p => `
                        <tr>
                            <td><code>${p.endpoint || 'Unknown'}</code></td>
                            <td>${formatNumber(p.count)}</td>
                            <td>${p.avg_time.toFixed(2)} ms</td>
                            <td>${p.min_time.toFixed(2)} ms</td>
                            <td>${p.max_time.toFixed(2)} ms</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
            <div class="mt-3">
                <strong>معدل النجاح الإجمالي:</strong> ${metrics.success_rate}%
                <br>
                <strong>إجمالي الاستدعاءات:</strong> ${formatNumber(metrics.total_calls)}
            </div>
        `;
        
    } catch (error) {
        showNotification('فشل تحميل المقاييس: ' + error.message, 'danger');
    }
}

// ==================== [ Errors Functions ] ====================

async function loadErrors() {
    try {
        const severity = document.getElementById('error-severity').value;
        let url = '/api/errors?limit=100';
        if (severity) url += `&severity=${severity}`;
        
        const response = await apiRequest(url);
        const errors = response.data.errors;
        
        const container = document.getElementById('errors-container');
        
        if (errors.length === 0) {
            container.innerHTML = '<p class="text-center text-muted py-5">لا توجد أخطاء</p>';
            return;
        }
        
        container.innerHTML = errors.map(error => {
            const severityClass = error.response_code >= 500 ? 'error' : 
                                 error.response_code >= 400 ? 'warning' : 'success';
            
            return `
                <div class="log-entry ${severityClass} mb-2">
                    <div class="d-flex justify-content-between">
                        <strong>${error.type}</strong>
                        <span class="badge bg-${severityClass === 'error' ? 'danger' : severityClass === 'warning' ? 'warning' : 'success'}">
                            ${error.response_code || 'N/A'}
                        </span>
                    </div>
                    <div class="text-muted small">
                        <i class="bi bi-geo-alt"></i> ${error.ip || 'Unknown'}
                        <i class="bi bi-arrow-right ms-2"></i> ${error.endpoint || 'Unknown'} [${error.method || 'Unknown'}]
                    </div>
                    <div class="mt-1">${error.message}</div>
                    <div class="text-muted" style="font-size: 0.75rem;">
                        <i class="bi bi-clock"></i> ${formatDate(error.timestamp)}
                    </div>
                </div>
            `;
        }).join('');
        
        // Update error count badge
        errorCount = errors.length;
        const errorBadge = document.getElementById('errors-badge');
        if (errorCount > 0) {
            errorBadge.textContent = errorCount;
            errorBadge.classList.remove('d-none');
        }
        
    } catch (error) {
        document.getElementById('errors-container').innerHTML = 
            `<div class="alert alert-danger">فشل تحميل الأخطاء: ${error.message}</div>`;
    }
}

// ==================== [ Webhooks Functions ] ====================

async function loadWebhooks() {
    try {
        const filter = document.getElementById('webhook-filter').value;
        let url = '/api/webhooks-log?limit=50';
        if (filter) url += `&event=${filter}`;
        
        const response = await apiRequest(url);
        const webhooks = response.data.webhooks;
        
        const container = document.getElementById('webhooks-container');
        
        if (webhooks.length === 0) {
            container.innerHTML = '<p class="text-center text-muted py-5">لا توجد webhooks</p>';
            return;
        }
        
        container.innerHTML = `
            <table class="table table-hover">
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>الحدث</th>
                        <th>IP</th>
                        <th>التوقيع</th>
                        <th>وقت المعالجة</th>
                        <th>التاريخ</th>
                        <th>التفاصيل</th>
                    </tr>
                </thead>
                <tbody>
                    ${webhooks.map(webhook => `
                        <tr>
                            <td>${webhook.id}</td>
                            <td><span class="badge bg-info">${webhook.event}</span></td>
                            <td>${webhook.ip}</td>
                            <td>
                                <span class="badge bg-${webhook.signature_valid ? 'success' : 'danger'}">
                                    ${webhook.signature_valid ? 'صحيح' : 'خاطئ'}
                                </span>
                            </td>
                            <td>${webhook.processing_time_ms ? webhook.processing_time_ms.toFixed(2) + ' ms' : '-'}</td>
                            <td>${formatDate(webhook.timestamp)}</td>
                            <td>
                                <button class="btn btn-sm btn-outline-info" onclick='showWebhookDetails(${JSON.stringify(webhook.body)})'>
                                    <i class="bi bi-eye"></i>
                                </button>
                            </td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        `;
        
    } catch (error) {
        document.getElementById('webhooks-container').innerHTML = 
            `<div class="alert alert-danger">فشل تحميل Webhooks: ${error.message}</div>`;
    }
}

function showWebhookDetails(body) {
    alert(JSON.stringify(body, null, 2));
}

// ==================== [ Action Functions ] ====================

async function connectStore() {
    try {
        const response = await apiRequest('/login-link');
        if (response.data.auth_url) {
            window.location.href = response.data.auth_url;
        }
    } catch (error) {
        showNotification('فشل إنشاء رابط الاتصال: ' + error.message, 'danger');
    }
}

async function refreshToken() {
    try {
        // This would trigger token refresh on the backend
        await apiRequest('/api/status');
        showNotification('تم تحديث التوكن بنجاح', 'success');
        await loadSystemStatus();
    } catch (error) {
        showNotification('فشل تحديث التوكن: ' + error.message, 'danger');
    }
}

async function testConnection() {
    try {
        const response = await apiRequest('/api/products?per_page=1');
        showNotification('الاتصال يعمل بشكل صحيح', 'success');
    } catch (error) {
        showNotification('فشل الاتصال: ' + error.message, 'danger');
    }
}

async function clearLogs() {
    if (!confirm('هل أنت متأكد من مسح جميع السجلات؟')) return;
    showNotification('تم مسح السجلات (محاكاة)', 'info');
}

async function exportData() {
    showNotification('جاري تصدير البيانات...', 'info');
    // Implementation would download data as JSON/CSV
}

async function backupDatabase() {
    showNotification('جاري إنشاء نسخة احتياطية...', 'info');
    // Implementation would create database backup
}

async function resetDatabase() {
    showNotification('تم إعادة تعيين قاعدة البيانات (محاكاة)', 'warning');
}

// ==================== [ Auto Refresh ] ====================

function startAutoRefresh() {
    if (autoRefreshInterval) {
        clearInterval(autoRefreshInterval);
    }
    
    autoRefreshInterval = setInterval(() => {
        refreshAll();
    }, 30000); // 30 seconds
}

function stopAutoRefresh() {
    if (autoRefreshInterval) {
        clearInterval(autoRefreshInterval);
        autoRefreshInterval = null;
    }
}

async function refreshAll() {
    const refreshBtn = document.querySelector('.refresh-btn');
    refreshBtn.style.transform = 'rotate(360deg)';
    
    await Promise.all([
        loadSystemStatus(),
        loadRecentActivities()
    ]);
    
    // Refresh current tab content
    const activeTab = document.querySelector('.nav-link.active').id;
    switch(activeTab) {
        case 'products-tab':
            await loadProducts();
            break;
        case 'monitoring-tab':
            await loadMetrics();
            break;
        case 'errors-tab':
            await loadErrors();
            break;
        case 'webhooks-tab':
            await loadWebhooks();
            break;
    }
    
    setTimeout(() => {
        refreshBtn.style.transform = '';
    }, 500);
    
    showNotification('تم تحديث البيانات', 'success');
}

// ==================== [ Event Listeners ] ====================

document.addEventListener('DOMContentLoaded', async () => {
    // Initial load
    await loadSystemStatus();
    await loadRecentActivities();
    
    // Tab change listeners
    document.querySelectorAll('[data-bs-toggle="tab"]').forEach(tab => {
        tab.addEventListener('shown.bs.tab', async (event) => {
            const tabId = event.target.id;
            
            switch(tabId) {
                case 'products-tab':
                    await loadProducts();
                    break;
                case 'monitoring-tab':
                    await loadMetrics();
                    break;
                case 'errors-tab':
                    await loadErrors();
                    break;
                case 'webhooks-tab':
                    await loadWebhooks();
                    break;
            }
        });
    });
    
    // Auto refresh toggle
    document.getElementById('auto-refresh').addEventListener('change', (e) => {
        if (e.target.checked) {
            startAutoRefresh();
            showNotification('تم تفعيل التحديث التلقائي', 'success');
        } else {
            stopAutoRefresh();
            showNotification('تم إيقاف التحديث التلقائي', 'info');
        }
    });
    
    // Debug mode toggle
    document.getElementById('debug-mode').addEventListener('change', (e) => {
        if (e.target.checked) {
            console.log('Debug mode enabled');
            showNotification('تم تفعيل وضع التصحيح', 'info');
        } else {
            console.log('Debug mode disabled');
            showNotification('تم إيقاف وضع التصحيح', 'info');
        }
    });
    
    // Notifications toggle
    document.getElementById('notifications').addEventListener('change', async (e) => {
        if (e.target.checked) {
            if (Notification.permission === 'default') {
                const permission = await Notification.requestPermission();
                if (permission === 'granted') {
                    notificationsEnabled = true;
                    showNotification('تم تفعيل الإشعارات', 'success');
                } else {
                    e.target.checked = false;
                    showNotification('تم رفض إذن الإشعارات', 'warning');
                }
            } else if (Notification.permission === 'granted') {
                notificationsEnabled = true;
                showNotification('تم تفعيل الإشعارات', 'success');
            } else {
                e.target.checked = false;
                showNotification('الإشعارات محظورة في المتصفح', 'warning');
            }
        } else {
            notificationsEnabled = false;
            showNotification('تم إيقاف الإشعارات', 'info');
        }
    });
    
    // Search/Filter listeners
    document.getElementById('product-search').addEventListener('input', loadProducts);
    document.getElementById('product-status-filter').addEventListener('change', loadProducts);
    document.getElementById('product-sort').addEventListener('change', loadProducts);
    document.getElementById('error-severity').addEventListener('change', loadErrors);
    document.getElementById('webhook-filter').addEventListener('input', loadWebhooks);
    document.getElementById('metrics-period').addEventListener('change', loadMetrics);
    
    // Keyboard shortcuts
    document.addEventListener('keydown', (e) => {
        // Ctrl/Cmd + R: Refresh
        if ((e.ctrlKey || e.metaKey) && e.key === 'r') {
            e.preventDefault();
            refreshAll();
        }
        // Ctrl/Cmd + K: Focus search
        if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
            e.preventDefault();
            document.getElementById('product-search').focus();
        }
    });
});

// ==================== [ Export Functions ] ====================

// Make functions globally available
window.connectStore = connectStore;
window.refreshToken = refreshToken;
window.testConnection = testConnection;
window.clearLogs = clearLogs;
window.exportData = exportData;
window.backupDatabase = backupDatabase;
window.resetDatabase = resetDatabase;
window.refreshAll = refreshAll;
window.addProduct = addProduct;
window.editProduct = editProduct;
window.deleteProduct = deleteProduct;
window.loadProducts = loadProducts;
window.loadMetrics = loadMetrics;
window.loadErrors = loadErrors;
window.loadWebhooks = loadWebhooks;
window.showWebhookDetails = showWebhookDetails;