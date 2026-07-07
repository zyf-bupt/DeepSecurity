/**
 * Network Topology - Canvas-based interactive visualization
 */
(function(){
  var canvas, ctx, nodesData, zonesData, routesData;
  var nodePositions = {};
  var hoveredNode = null;
  var selectedNodeId = null;
  var W = 0, H = 0;
  var animFrame = null;
  var particles = [];

  // Zone layout (relative 0-1)
  var zoneLayout = {
    external:        {cx:0.82, cy:0.22, r:0.11},
    dmz:             {cx:0.55, cy:0.22, r:0.13},
    internal:        {cx:0.25, cy:0.55, r:0.16},
    secure_internal: {cx:0.50, cy:0.72, r:0.13},
    management:      {cx:0.75, cy:0.78, r:0.12}
  };
  var zoneColors = {
    external:        '#e74c3c',
    dmz:             '#f39c12',
    internal:        '#3b9eff',
    secure_internal: '#2ecc71',
    management:      '#9b59b6'
  };

  function init() {
    canvas = document.getElementById('topoCanvasEl');
    if (!canvas) return;
    ctx = canvas.getContext('2d');

    function resize() {
      var parent = canvas.parentElement;
      W = parent.clientWidth;
      H = parent.clientHeight;
      canvas.width = W;
      canvas.height = H;
      draw();
    }
    window.addEventListener('resize', resize);
    resize();

    // Mouse events
    canvas.addEventListener('mousemove', onMouseMove);
    canvas.addEventListener('click', onClick);
    canvas.addEventListener('mouseleave', function(){ hoveredNode=null; draw(); });

    // Load data
    loadData();
    setInterval(loadData, 8000);

    // Animation loop
    function anim() {
      updateParticles();
      if (nodesData) draw();
      animFrame = requestAnimationFrame(anim);
    }
    anim();
  }

  function loadData() {
    fetch('/scenario/api/network')
      .then(function(r){ return r.json(); })
      .then(function(d){
        if (!d.ok) return;
        nodesData = d.data.nodes || [];
        zonesData = d.data.zones || {};
        routesData = d.data.routes || [];
        updateSidebar(d.data);
        draw();
      }).catch(function(){});
  }

  function updateSidebar(data) {
    var s = data.summary || {};
    document.getElementById('netSummary').innerHTML =
      '<div class="d-flex justify-between mb-1"><span>总节点</span><strong>'+ (s.total_nodes||data.nodes.length) +'</strong></div>'+
      '<div class="d-flex justify-between mb-1"><span>运行中</span><span class="badge badge-green">'+ (s.running||0) +'</span></div>'+
      '<div class="d-flex justify-between mb-1"><span>已攻陷</span><span class="badge badge-red">'+ (s.compromised||0) +'</span></div>'+
      '<div class="d-flex justify-between mb-1"><span>已隔离</span><span class="badge badge-orange">'+ (s.isolated||0) +'</span></div>'+
      '<hr style="border-color:var(--border)">'+
      '<div class="d-flex justify-between mb-1"><span>安全区</span><strong>'+ Object.keys(data.zones||{}).length +'</strong></div>'+
      '<div class="d-flex justify-between"><span>路由规则</span><strong>'+ (data.routes||[]).length +'</strong></div>';
    // Security posture
    fetch('/scenario/api/status').then(function(r){return r.json()}).then(function(dd){
      if (!dd.ok) return;
      var pos = dd.network || {};
      var risk = pos.overall_risk||'low';
      var rc = risk==='critical'?'red':(risk==='high'?'orange':(risk==='medium'?'cyan':'green'));
      document.getElementById('secPosture').innerHTML =
        '<div style="font-size:48px;font-weight:800;color:var(--'+rc+')">'+risk.toUpperCase()+'</div>'+
        '<div class="text-dim" style="font-size:12px">当前风险等级</div>';
    });
  }

  // ---- Drawing ----
  function draw() {
    ctx.clearRect(0,0,W,H);

    // Draw zone backgrounds
    for (var zId in zoneLayout) {
      var zl = zoneLayout[zId];
      var zx = zl.cx * W, zy = zl.cy * H, zr = zl.r * Math.min(W,H);
      ctx.beginPath();
      ctx.arc(zx, zy, zr, 0, Math.PI*2);
      ctx.fillStyle = zoneColors[zId] + '0a';
      ctx.fill();
      ctx.strokeStyle = zoneColors[zId] + '33';
      ctx.lineWidth = 1.5;
      ctx.setLineDash([6,4]);
      ctx.stroke();
      ctx.setLineDash([]);

      // Zone name
      var zName = (zonesData[zId]||{}).name || zId;
      ctx.fillStyle = zoneColors[zId];
      ctx.font = 'bold 10px system-ui';
      ctx.textAlign = 'center';
      ctx.fillText(zName, zx, zy - zr - 6);
    }

    // Draw routes (lines between zones)
    if (routesData) {
      routesData.forEach(function(route){
        if (!route.allowed) return;
        var fn = nodesData.find(function(n){return n.id===route.from;});
        if (!fn) return;
        var targets = route.to==='all' ? nodesData.filter(function(n){return n.id!==route.from;}) :
                      nodesData.filter(function(n){return n.id===route.to;});
        var fz = zoneLayout[fn.zone];
        if (!fz) return;
        targets.forEach(function(tn){
          var tz = zoneLayout[tn.zone];
          if (!tz) return;
          ctx.beginPath();
          ctx.moveTo(fz.cx*W, fz.cy*H);
          ctx.lineTo(tz.cx*W, tz.cy*H);
          ctx.strokeStyle = 'rgba(136,153,176,.12)';
          ctx.lineWidth = 1;
          ctx.stroke();
        });
      });
    }

    // Draw particles along routes
    particles.forEach(function(p){
      ctx.beginPath();
      ctx.arc(p.x, p.y, 2, 0, Math.PI*2);
      ctx.fillStyle = p.color;
      ctx.fill();
    });

    // Position nodes within zones
    if (nodesData) {
      var zoneCounts = {};
      nodesData.forEach(function(n){ zoneCounts[n.zone] = (zoneCounts[n.zone]||0) + 1; });
      var zoneIdx = {};
      nodePositions = {};

      nodesData.forEach(function(n){
        var zl = zoneLayout[n.zone] || {cx:0.5,cy:0.5,r:0.2};
        var idx = zoneIdx[n.zone] || 0; zoneIdx[n.zone] = idx+1;
        var count = zoneCounts[n.zone]||1;
        var angle = (idx/count)*Math.PI*2 - Math.PI/2;
        var rr = zl.r * Math.min(W,H) * 0.5;
        var nx = zl.cx*W + Math.cos(angle)*rr;
        var ny = zl.cy*H + Math.sin(angle)*rr;
        nodePositions[n.id] = {x:nx, y:ny, node:n};

        // Glow for compromised
        if (n.status === 'compromised') {
          var grad = ctx.createRadialGradient(nx, ny, 10, nx, ny, 26);
          grad.addColorStop(0, 'rgba(231,76,60,.4)');
          grad.addColorStop(1, 'rgba(231,76,60,0)');
          ctx.beginPath(); ctx.arc(nx, ny, 26, 0, Math.PI*2); ctx.fillStyle = grad; ctx.fill();
        }

        // Node circle
        var color = n.status==='compromised'?'#e74c3c':zoneColors[n.zone];
        var r = (hoveredNode===n.id||selectedNodeId===n.id) ? 22 : 18;
        ctx.beginPath(); ctx.arc(nx, ny, r, 0, Math.PI*2);
        ctx.fillStyle = color;
        ctx.fill();
        ctx.strokeStyle = n.status==='compromised'?'#ff4444':(hoveredNode===n.id?'#fff':'rgba(255,255,255,.2)');
        ctx.lineWidth = n.status==='compromised'?2.5:(hoveredNode===n.id?2:1);
        ctx.stroke();

        // Icon
        ctx.fillStyle = '#fff';
        ctx.font = (r>20?'15px':'13px') + ' system-ui';
        ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
        var icon = n.is_soc?'🛡':(n.is_threat_source?'💀':(n.is_domain_controller?'🏛':(n.is_patient_zero?'🎯':'🖥')));
        ctx.fillText(icon, nx, ny);

        // Small label
        ctx.fillStyle = '#8899b0';
        ctx.font = '9px system-ui';
        ctx.fillText(n.name, nx, ny + r + 12);
      });
    }
  }

  // ---- Particles ----
  function updateParticles() {
    // Spawn new particles occasionally
    if (particles.length < 20 && nodesData && Math.random()<0.3) {
      var validRoutes = (routesData||[]).filter(function(r){return r.allowed;});
      if (validRoutes.length) {
        var route = validRoutes[Math.floor(Math.random()*validRoutes.length)];
        var fn = nodesData.find(function(n){return n.id===route.from;});
        if (fn) {
          var targets = route.to==='all' ? nodesData.filter(function(n){return n.id!==route.from;}) :
                        nodesData.filter(function(n){return n.id===route.to;});
          if (targets.length) {
            var tn = targets[Math.floor(Math.random()*targets.length)];
            var fz = zoneLayout[fn.zone], tz = zoneLayout[tn.zone];
            if (fz && tz) {
              particles.push({
                x: fz.cx*W, y: fz.cy*H,
                tx: tz.cx*W, ty: tz.cy*H,
                speed: 0.003 + Math.random()*0.006,
                progress: 0,
                color: zoneColors[fn.zone] + '88'
              });
            }
          }
        }
      }
    }
    // Update
    for (var i=particles.length-1; i>=0; i--) {
      var p = particles[i];
      p.progress += p.speed;
      p.x = p.x + (p.tx - p.x) * p.speed * 3;
      p.y = p.y + (p.ty - p.y) * p.speed * 3;
      if (p.progress >= 1) particles.splice(i,1);
    }
  }

  // ---- Mouse ----
  function onMouseMove(e) {
    var rect = canvas.getBoundingClientRect();
    var mx = e.clientX - rect.left;
    var my = e.clientY - rect.top;
    var found = null;
    for (var id in nodePositions) {
      var np = nodePositions[id];
      var dx = mx - np.x, dy = my - np.y;
      if (Math.sqrt(dx*dx+dy*dy) < 22) { found = id; break; }
    }
    if (found !== hoveredNode) { hoveredNode = found; draw(); }

    // Tooltip
    var tip = document.getElementById('topoTip');
    if (found && nodePositions[found]) {
      var n = nodePositions[found].node;
      tip.innerHTML = '<strong>'+n.name+'</strong><br>IP: <code>'+n.ip+'</code><br>Role: '+n.role+'<br>Zone: '+n.zone+'<br>Status: '+
        '<span style="color:'+(n.status==='compromised'?'#e74c3c':'#2ecc71')+'">'+n.status+'</span>'+
        (n.is_patient_zero?'<br><span style="color:#f39c12">⚠ Patient Zero</span>':'')+
        (n.is_domain_controller?'<br><span style="color:#3b9eff">🏛 Domain Controller</span>':'');
      tip.style.display = 'block';
      tip.style.left = (e.clientX - canvas.getBoundingClientRect().left + 16) + 'px';
      tip.style.top = (e.clientY - canvas.getBoundingClientRect().top - 10) + 'px';
    } else {
      tip.style.display = 'none';
    }
  }

  function onClick(e) {
    var rect = canvas.getBoundingClientRect();
    var mx = e.clientX - rect.left;
    var my = e.clientY - rect.top;
    for (var id in nodePositions) {
      var np = nodePositions[id];
      var dx = mx - np.x, dy = my - np.y;
      if (Math.sqrt(dx*dx+dy*dy) < 22) {
        selectedNodeId = id;
        showNodeDetail(np.node);
        draw();
        return;
      }
    }
  }

  function showNodeDetail(n) {
    document.getElementById('nodeDetail').innerHTML =
      '<h4 style="margin:0 0 8px;color:var(--text-bright)">'+n.name+'</h4>'+
      '<div class="mb-1"><strong>IP:</strong> <code>'+n.ip+'</code></div>'+
      '<div class="mb-1"><strong>主机名:</strong> '+n.hostname+'</div>'+
      '<div class="mb-1"><strong>OS:</strong> '+n.os+'</div>'+
      '<div class="mb-1"><strong>类型:</strong> '+n.type+'</div>'+
      '<div class="mb-1"><strong>角色:</strong> '+n.role+'</div>'+
      '<div class="mb-1"><strong>安全区:</strong> <span class="badge badge-gray">'+n.zone+'</span></div>'+
      '<div class="mb-1"><strong>状态:</strong> <span class="badge badge-'+(n.status==='compromised'?'red':(n.status==='isolated'?'orange':'green'))+'">'+n.status+'</span></div>'+
      '<div class="mb-1"><strong>服务:</strong> '+ (n.services||[]).join(', ') +'</div>'+
      '<div><strong>CPU:</strong> '+n.cpu_usage+'% | <strong>MEM:</strong> '+n.memory_usage+'%</div>'+
      '<div class="d-flex gap-1 flex-wrap mt-2">'+
        (n.is_threat_source?'<span class="badge badge-red">威胁源</span>':'')+
        (n.is_initial_victim?'<span class="badge badge-orange">初始受害者</span>':'')+
        (n.is_patient_zero?'<span class="badge badge-orange">跳板机</span>':'')+
        (n.is_domain_controller?'<span class="badge badge-blue">域控制器</span>':'')+
        (n.is_soc?'<span class="badge badge-green">SOC节点</span>':'')+
        (n.contains_sensitive_data?'<span class="badge badge-purple">敏感数据</span>':'')+
      '</div>';
  }

  document.addEventListener('DOMContentLoaded', init);
})();
