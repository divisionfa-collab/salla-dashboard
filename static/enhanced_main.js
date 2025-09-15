// ==================== [ Simple Enhanced Main JS ] ====================

// Utility function for API calls
async function j(url, opts = {}) {
    const r = await fetch(url, {
        headers: {'Content-Type': 'application/json'},
        ...opts
    });
    const t = await r.text();
    try {
        return {ok: r.ok, status: r.status, json: JSON.parse(t)}
    } catch {
        return {ok: r.ok, status: r.status, json: t}
    }
}

// Badge helper
function badge(ok) {
    return `<span class="badge ${ok ? 'bg-success' : 'bg-danger'}">${ok ? 'متوفر' : 'غير متوفر'}</span>`;
}

// Load Status
async function loadStatus() {
    try {
        const r = await j('/api/status');
        if (!r.ok) {
            document.getElementById('statusBox').innerHTML = '❌ فشل جلب الحالة';
            return;
        }
        
        const s = r.json;
        
        // Update status display
        document.getElementById('statusBox').innerHTML = `
            Client ID: ${badge(s.client_id_exists)} |
            Secret: ${badge(s.client_secret_exists)} |
            Token: ${badge(s.token_exists && !s.token_expired)}
            <div class="small text-muted mt-1">Redirect URI: ${s.redirect_uri}</div>
        `;
        
        // Update dashboard stats if elements exist
        if (document.getElementById('api-calls-count')) {
            document.getElementById('api-calls-count').textContent = s.statistics?.api_calls_today || 0;
            document.getElementById('error-count').textContent = s.statistics?.errors_today || 0;
            document.getElementById('response-time').textContent = `${Math.round(s.statistics?.avg_response_time_ms || 0)}ms`;
            
            const successRate = s.statistics?.api_calls_today > 0 
                ? ((s.statistics.api_calls_today - s.statistics.errors_today) / s.statistics.api_calls_today * 100).toFixed(1)
                : 100;
            document.getElementById('success-rate').textContent = `${successRate}%`;
        }
        
        // Update auth status
        if (document.getElementById('auth-status')) {
            const authBadge = document.getElementById('auth-status');
            if (s.token_exists && !s.token_expired) {
                authBadge.className = 'badge bg-success';
                authBadge.textContent = 'متصل';
            } else if (s.token_exists) {
                authBadge.className = 'badge bg-warning';
                authBadge.textContent = 'منتهي الصلاحية';
            } else {
                authBadge.className = 'badge bg-danger';
                authBadge.textContent = 'غير متصل';
            }
        }
        
        // Update store info
        if (document.getElementById('store-name')) {
            document.getElementById('store-name').textContent = s.store_name || 'غير متصل';
        }
        
    } catch (error) {
        console.error('Failed to load status:', error);
    }
}

// Load Products
async function loadProducts() {
    try {
        const r = await j('/api/products');
        if (!r.ok) {
            document.getElementById('productsBox').innerHTML = `❌ ${r.json.error || 'فشل جلب المنتجات'}`;
            return;
        }
        
        const data = r.json.data || [];
        if (!data.length) {
            document.getElementById('productsBox').innerHTML = 'لا توجد منتجات.';
            return;
        }
        
        const rows = data.map(p => `
            <tr>
                <td>${p.id}</td>
                <td>${p.name || ''}</td>
                <td>${(p.price && p.price.amount) || 0}</td>
                <td class="text-nowrap">
                    <button class="btn btn-sm btn-outline-primary" onclick="editPrice('${p.id}')">تعديل السعر</button>
                    <button class="btn btn-sm btn-outline-danger" onclick="delProd('${p.id}')">حذف</button>
                </td>
            </tr>
        `).join('');
        
        document.getElementById('productsBox').innerHTML = `
            <div class="table-responsive">
                <table class="table table-sm table-striped align-middle">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>الاسم</th>
                            <th>السعر</th>
                            <th></th>
                        </tr>
                    </thead>
                    <tbody>${rows}</tbody>
                </table>
            </div>
        `;
        
        // Update products container if exists
        if (document.getElementById('products-container')) {
            document.getElementById('products-container').innerHTML = document.getElementById('productsBox').innerHTML;
        }
        
    } catch (error) {
        console.error('Failed to load products:', error);
    }
}

// Load Webhooks
async function loadWH() {
    try {
        const r = await j('/api/webhooks-log');
        if (!r.ok) {
            document.getElementById('whBox').innerHTML = '❌ فشل جلب السجلات';
            return;
        }
        
        const rows = r.json.map(e => `
            <tr>
                <td>${e.id}</td>
                <td>${e.event}</td>
                <td><pre class="m-0 small">${JSON.stringify(e.body, null, 2)}</pre></td>
                <td>${e.created_at}</td>
            </tr>
        `).join('');
        
        document.getElementById('whBox').innerHTML = `
            <div class="table-responsive">
                <table class="table table-sm table-bordered">
                    <thead>
                        <tr>
                            <th>#</th>
                            <th>الحدث</th>
                            <th>المحتوى</th>
                            <th>التاريخ</th>
                        </tr>
                    </thead>
                    <tbody>${rows}</tbody>
                </table>
            </div>
        `;
        
        // Update webhooks container if exists
        if (document.getElementById('webhooks-container')) {
            document.getElementById('webhooks-container').innerHTML = document.getElementById('whBox').innerHTML;
        }
        
    } catch (error) {
        console.error('Failed to load webhooks:', error);
    }
}

// Load Errors (for enhanced dashboard)
async function loadErrors() {
    try {
        const r = await j('/api/errors?limit=50');
        if (!r.ok) {
            console.error('Failed to load errors');
            return;
        }
        
        const errors = r.json.errors || [];
        const container = document.getElementById('errors-container');
        
        if (!container) return;
        
        if (errors.length === 0) {
            container.innerHTML = '<p class="text-center text-muted py-5">لا توجد أخطاء</p>';
            return;
        }
        
        container.innerHTML = errors.map(error => `
            <div class="alert alert-danger mb-2">
                <strong>${error.type}</strong>
                <div class="small text-muted">
                    ${error.endpoint || 'Unknown'} [${error.method || 'Unknown'}] - ${error.ip || 'Unknown'}
                </div>
                <div>${error.message}</div>
                <div class="text-muted small">${error.timestamp}</div>
            </div>
        `).join('');
        
    } catch (error) {
        console.error('Failed to load errors:', error);
    }
}

// Load Metrics (for enhanced dashboard)
async function loadMetrics() {
    try {
        const period = document.getElementById('metrics-period')?.value || '24h';
        const r = await j(`/api/metrics?period=${period}`);
        
        if (!r.ok) {
            console.error('Failed to load metrics');
            return;
        }
        
        const metrics = r.json;
        const container = document.getElementById('performance-details');
        
        if (!container) return;
        
        container.innerHTML = `
            <table class="table table-hover">
                <thead>
                    <tr>
                        <th>النقطة النهائية</th>
                        <th>عدد الاستدعاءات</th>
                        <th>متوسط الوقت</th>
                    </tr>
                </thead>
                <tbody>
                    ${metrics.performance.map(p => `
                        <tr>
                            <td><code>${p.endpoint || 'Unknown'}</code></td>
                            <td>${p.count}</td>
                            <td>${p.avg_time.toFixed(2)} ms</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
            <div class="mt-3">
                <strong>معدل النجاح:</strong> ${metrics.success_rate}%
                <br>
                <strong>إجمالي الاستدعاءات:</strong> ${metrics.total_calls}
            </div>
        `;
        
    } catch (error) {
        console.error('Failed to load metrics:', error);
    }
}

// Connect Store
async function connectStore() {
    const r = await j('/login-link');
    if (r.ok && r.json.auth_url) {
        window.location = r.json.auth_url;
    } else {
        alert('تعذر إنشاء رابط الدخول');
    }
}

// Add Product
async function addProduct() {
    const body = {
        name: document.getElementById('p_name')?.value || document.getElementById('product-name')?.value,
        price: document.getElementById('p_price')?.value || document.getElementById('product-price')?.value,
        image: document.getElementById('p_image')?.value || document.getElementById('product-image')?.value,
        status: document.getElementById('p_status')?.value || document.getElementById('product-status')?.value || 'available',
        description: document.getElementById('product-description')?.value || '',
        quantity: document.getElementById('product-quantity')?.value || 0,
        sku: document.getElementById('product-sku')?.value || '',
        product_type: document.getElementById('product-type')?.value || 'physical'
    };
    
    const r = await j('/api/products', {
        method: 'POST',
        body: JSON.stringify(body)
    });
    
    if (r.ok) {
        await loadProducts();
        alert('تمت الإضافة');
        // Close modal if exists
        const modal = document.getElementById('addProductModal');
        if (modal && window.bootstrap) {
            bootstrap.Modal.getInstance(modal)?.hide();
        }
    } else {
        alert('فشل الإضافة: ' + JSON.stringify(r.json));
    }
}

// Edit Price
window.editPrice = async function(pid) {
    const v = prompt('السعر الجديد:');
    if (v === null) return;
    
    const r = await j(`/api/products/${pid}`, {
        method: 'PUT',
        body: JSON.stringify({price: v})
    });
    
    if (r.ok) {
        await loadProducts();
        alert('تم التعديل');
    } else {
        alert('فشل التعديل: ' + JSON.stringify(r.json));
    }
}

// Delete Product
window.delProd = window.deleteProduct = async function(pid) {
    if (!confirm('تأكيد حذف المنتج؟')) return;
    
    const r = await j(`/api/products/${pid}`, {
        method: 'DELETE'
    });
    
    if (r.ok) {
        await loadProducts();
        alert('تم الحذف');
    } else {
        alert('فشل الحذف: ' + JSON.stringify(r.json));
    }
}

// Refresh All
async function refreshAll() {
    await loadStatus();
    await loadProducts();
    await loadWH();
    await loadErrors();
    await loadMetrics();
}

// Test Connection
async function testConnection() {
    const r = await j('/api/products?per_page=1');
    if (r.ok) {
        alert('الاتصال يعمل بشكل صحيح');
    } else {
        alert('فشل الاتصال');
    }
}

// Placeholder functions
function refreshToken() {
    alert('جاري تحديث التوكن...');
    loadStatus();
}

function clearLogs() {
    if (confirm('هل أنت متأكد من مسح السجلات؟')) {
        alert('تم مسح السجلات (محاكاة)');
    }
}

function exportData() {
    alert('جاري تصدير البيانات...');
}

function backupDatabase() {
    alert('جاري إنشاء نسخة احتياطية...');
}

function resetDatabase() {
    alert('تم إعادة تعيين قاعدة البيانات (محاكاة)');
}

function loadWebhooks() {
    loadWH();
}

function showWebhookDetails(body) {
    alert(JSON.stringify(body, null, 2));
}

// Make functions globally available
window.connectStore = connectStore;
window.addProduct = addProduct;
window.refreshAll = refreshAll;
window.testConnection = testConnection;
window.refreshToken = refreshToken;
window.clearLogs = clearLogs;
window.exportData = exportData;
window.backupDatabase = backupDatabase;
window.resetDatabase = resetDatabase;
window.loadProducts = loadProducts;
window.loadMetrics = loadMetrics;
window.loadErrors = loadErrors;
window.loadWebhooks = loadWebhooks;
window.showWebhookDetails = showWebhookDetails;

// Initialize on DOM ready
document.addEventListener('DOMContentLoaded', async function() {
    // Initial load
    await loadStatus();
    await loadProducts();
    await loadWH();
    
    // Setup login button if exists
    const loginBtn = document.getElementById('loginBtn');
    if (loginBtn) {
        loginBtn.addEventListener('click', connectStore);
    }
    
    // Setup add button if exists  
    const addBtn = document.getElementById('addBtn');
    if (addBtn) {
        addBtn.addEventListener('click', addProduct);
    }
    
    // Setup tab listeners if enhanced dashboard
    document.querySelectorAll('[data-bs-toggle="tab"]').forEach(tab => {
        tab.addEventListener('shown.bs.tab', async (event) => {
            const tabId = event.target.id;
            
            switch(tabId) {
                case 'products-tab':
                    await loadProducts();
                    break;
                case 'errors-tab':
                    await loadErrors();
                    break;
                case 'webhooks-tab':
                    await loadWH();
                    break;
                case 'monitoring-tab':
                    await loadMetrics();
                    break;
            }
        });
    });
    
    // Setup filters if they exist
    const searchInput = document.getElementById('product-search');
    if (searchInput) {
        searchInput.addEventListener('input', loadProducts);
    }
    
    const statusFilter = document.getElementById('product-status-filter');
    if (statusFilter) {
        statusFilter.addEventListener('change', loadProducts);
    }
    
    const sortSelect = document.getElementById('product-sort');
    if (sortSelect) {
        sortSelect.addEventListener('change', loadProducts);
    }
    
    // Auto refresh option
    const autoRefresh = document.getElementById('auto-refresh');
    if (autoRefresh) {
        autoRefresh.addEventListener('change', (e) => {
            if (e.target.checked) {
                window.autoRefreshInterval = setInterval(refreshAll, 30000);
            } else {
                clearInterval(window.autoRefreshInterval);
            }
        });
    }
});