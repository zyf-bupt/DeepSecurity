/**
 * Detection Dashboard - Alert polling, RAG search, full pipeline analysis
 */
(function(){
  var POLL_MS = 3000;
  var timer = null;

  function init() {
    refreshAll();
    timer = setInterval(refreshAll, POLL_MS);
  }

  window.refreshAll = function() {
    fetchStats();
    fetchAlerts();
  };

  function fetchStats() {
    fetch('/detection/api/stats')
      .then(function(r){ return r.json(); })
      .then(function(d){
        if (!d.ok) return;
        var s = d.data;
        document.getElementById('stat-high').textContent = (s.by_severity||{}).high || 0;
        document.getElementById('stat-medium').textContent = (s.by_severity||{}).medium || 0;
        document.getElementById('stat-low').textContent = (s.by_severity||{}).low || 0;
        document.getElementById('stat-events').textContent = s.total_events || 0;
        // Tactic distribution
        var tactics = s.by_tactic || {};
        var distEl = document.getElementById('tacticDist');
        var keys = Object.keys(tactics);
        if (!keys.length) { distEl.innerHTML = '<div class="text-dim" style="font-size:12px">暂无战术数据</div>'; return; }
        distEl.innerHTML = keys.sort(function(a,b){return tactics[b]-tactics[a];}).map(function(k){
          return '<div class="d-flex justify-between mb-1" style="font-size:12px"><span>'+k+'</span><span class="badge badge-blue">'+tactics[k]+'</span></div>';
        }).join('');
      });
  }

  function fetchAlerts() {
    fetch('/detection/api/alerts?limit=30')
      .then(function(r){ return r.json(); })
      .then(function(d){
        if (!d.ok) return;
        var alerts = d.data || [];
        var box = document.getElementById('alertsBox');
        if (!alerts.length) {
          box.innerHTML = '<div class="text-center text-dim" style="padding:60px 20px"><div style="font-size:40px;margin-bottom:10px">&#128737;</div><p>暂无告警数据</p><p style="font-size:12px">请先在「场景管理」中启动攻击场景，然后执行全管线分析</p></div>';
          return;
        }
        box.innerHTML = alerts.map(function(a){
          var sev = a.severity||'low';
          var sevClass = sev==='high'?'red':(sev==='medium'?'orange':'blue');
          var srcBadge = a.source==='llm_deep_analysis'?'purple':(a.source==='rag_enhanced'?'cyan':'gray');
          return '<div class="alert alert-'+sevClass+'">'+
            '<div class="d-flex justify-between items-center mb-1">'+
              '<strong style="font-size:13px">'+ (a.title||'Alert') +'</strong>'+
              '<div class="d-flex gap-1">'+
                '<span class="badge badge-'+sevClass+'">'+ (sev.toUpperCase()) +'</span>'+
                '<span class="badge badge-'+srcBadge+'">'+ (a.source||'rule') +'</span>'+
                (a.ai_specific ? '<span class="badge badge-purple">AI</span>' : '') +
              '</div>'+
            '</div>'+
            '<div style="font-size:12px;color:var(--text-dim)">'+ (a.description||'') +'</div>'+
            '<div class="d-flex gap-1 mt-1" style="font-size:11px">'+
              '<span class="badge badge-gray">'+ (a.technique_id||'?') +'</span>'+
              '<span class="text-dim">'+ (a.technique_name||'') +'</span>'+
              '<span class="text-dim">| confidence: '+ ((a.confidence||0)*100).toFixed(0) +'%</span>'+
            '</div>'+
          '</div>';
        }).join('');
      });
  }

  window.runFullAnalysis = function() {
    var btn = document.getElementById('btnAnalyze');
    btn.disabled = true;
    btn.textContent = '分析中...';
    var box = document.getElementById('reportContent');
    box.textContent = '正在执行 检测→捕获→溯源 全管线分析，请稍候...';

    fetch('/detection/api/analyze', {method:'POST'})
      .then(function(r){ return r.json(); })
      .then(function(d){
        btn.disabled = false;
        btn.textContent = '▶ 执行全管线分析';
        if (!d.ok) { showToast('分析失败: '+(d.error||'未知错误'), 'error'); return; }
        box.textContent = d.data.report || '(空报告)';
        openModal('reportModal');
        refreshAll();
        showToast('全管线分析完成！', 'success');
      })
      .catch(function(e){
        btn.disabled = false;
        btn.textContent = '▶ 执行全管线分析';
        showToast('请求失败: '+e.message, 'error');
      });
  };

  window.doRagSearch = function() {
    var q = document.getElementById('ragQuery').value.trim();
    if (!q) return;
    var el = document.getElementById('ragResults');
    el.innerHTML = '<div class="text-dim" style="font-size:12px">搜索中...</div>';
    fetch('/detection/api/rag/search?q='+encodeURIComponent(q))
      .then(function(r){ return r.json(); })
      .then(function(d){
        if (!d.ok) { el.innerHTML = '<div class="text-red" style="font-size:12px">搜索失败</div>'; return; }
        var results = d.data||[];
        if (!results.length) { el.innerHTML = '<div class="text-dim" style="font-size:11px">未找到匹配结果</div>'; return; }
        el.innerHTML = results.map(function(r){
          return '<div style="padding:8px 0;border-bottom:1px solid var(--border)">'+
            '<strong style="font-size:12px">'+r.title+'</strong> '+
            '<span class="badge badge-cyan">'+r.category+'</span> '+
            '<span class="badge badge-gray">'+ (r.similarity*100).toFixed(0) +'%</span>'+
            '<div style="font-size:11px;color:var(--text-dim);margin-top:2px">'+ (r.content||'').substring(0,120) +'...</div>'+
          '</div>';
        }).join('');
      });
  };

  window.copyReport = function() {
    var text = document.getElementById('reportContent').textContent;
    if (navigator.clipboard) {
      navigator.clipboard.writeText(text).then(function(){ showToast('报告已复制到剪贴板', 'success'); });
    } else {
      showToast('请手动复制 (Ctrl+A, Ctrl+C)', 'info');
    }
  };

  // Modal helpers
  window.openModal = function(id) { document.getElementById(id).classList.add('show'); };
  window.closeModal = function(id) { document.getElementById(id).classList.remove('show'); };
  // Close modal on overlay click
  document.addEventListener('click', function(e){
    if (e.target.classList.contains('modal-overlay')) e.target.classList.remove('show');
  });

  // Enter key for RAG search
  document.addEventListener('DOMContentLoaded', function(){
    var ragInput = document.getElementById('ragQuery');
    if (ragInput) ragInput.addEventListener('keydown', function(e){ if (e.key==='Enter') doRagSearch(); });
  });

  init();
})();
