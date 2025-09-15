async function j(url, opts={}) {
  const r = await fetch(url, {headers: {'Content-Type':'application/json'}, ...opts});
  const t = await r.text();
  try { return {ok:r.ok, status:r.status, json: JSON.parse(t)} } catch { return {ok:r.ok, status:r.status, json:t} }
}

function badge(ok){return `<span class="badge ${ok?'bg-success':'bg-danger'}">${ok?'متوفر':'غير متوفر'}</span>`}

async function loadStatus(){
  const r = await j('/api/status');
  if(!r.ok){ document.getElementById('statusBox').innerHTML='❌ فشل جلب الحالة'; return;}
  const s = r.json;
  document.getElementById('statusBox').innerHTML = `
    Client ID: ${badge(s.client_id_exists)} |
    Secret: ${badge(s.client_secret_exists)} |
    Token: ${badge(s.token_exists && !s.token_expired)} 
    <div class="small text-muted mt-1">Redirect URI: ${s.redirect_uri}</div>
  `;
}

async function loadProducts(){
  const r = await j('/api/products');
  if(!r.ok){ document.getElementById('productsBox').innerHTML=`❌ ${r.json.error||'فشل جلب المنتجات'}`; return;}
  const data = r.json.data || [];
  if(!data.length){ document.getElementById('productsBox').innerHTML='لا توجد منتجات.'; return;}
  const rows = data.map(p => `
    <tr>
      <td>${p.id}</td>
      <td>${p.name||''}</td>
      <td>${(p.price&&p.price.amount)||0}</td>
      <td class="text-nowrap">
        <button class="btn btn-sm btn-outline-primary" onclick="editPrice('${p.id}')">تعديل السعر</button>
        <button class="btn btn-sm btn-outline-danger" onclick="delProd('${p.id}')">حذف</button>
      </td>
    </tr>`).join('');
  document.getElementById('productsBox').innerHTML = `
    <div class="table-responsive">
      <table class="table table-sm table-striped align-middle">
        <thead><tr><th>ID</th><th>الاسم</th><th>السعر</th><th></th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
}

async function loadWH(){
  const r = await j('/api/webhooks-log');
  if(!r.ok){ document.getElementById('whBox').innerHTML='❌ فشل جلب السجلات'; return;}
  const rows = r.json.map(e => `
    <tr>
      <td>${e.id}</td>
      <td>${e.event}</td>
      <td><pre class="m-0 small">${JSON.stringify(e.body, null, 2)}</pre></td>
      <td>${e.created_at}</td>
    </tr>`).join('');
  document.getElementById('whBox').innerHTML = `
    <div class="table-responsive">
      <table class="table table-sm table-bordered">
        <thead><tr><th>#</th><th>الحدث</th><th>المحتوى</th><th>التاريخ</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
}

document.getElementById('loginBtn').addEventListener('click', async ()=>{
  const r = await j('/login-link');
  if(r.ok && r.json.auth_url){ window.location = r.json.auth_url; }
  else alert('تعذر إنشاء رابط الدخول');
});

document.getElementById('addBtn').addEventListener('click', async ()=>{
  const body = {
    name: document.getElementById('p_name').value,
    price: document.getElementById('p_price').value,
    image: document.getElementById('p_image').value,
    status: document.getElementById('p_status').value
  };
  const r = await j('/api/products', {method:'POST', body: JSON.stringify(body)});
  if(r.ok){ await loadProducts(); alert('تمت الإضافة'); }
  else alert('فشل الإضافة: '+JSON.stringify(r.json));
});

window.editPrice = async function(pid){
  const v = prompt('السعر الجديد:');
  if(v===null) return;
  const r = await j(`/api/products/${pid}`, {method:'PUT', body: JSON.stringify({price: v})});
  if(r.ok){ await loadProducts(); alert('تم التعديل'); }
  else alert('فشل التعديل: '+JSON.stringify(r.json));
}

window.delProd = async function(pid){
  if(!confirm('تأكيد حذف المنتج؟')) return;
  const r = await j(`/api/products/${pid}`, {method:'DELETE'});
  if(r.ok){ await loadProducts(); alert('تم الحذف'); }
  else alert('فشل الحذف: '+JSON.stringify(r.json));
}

(async function init(){
  await loadStatus();
  await loadProducts();
  await loadWH();
})();
