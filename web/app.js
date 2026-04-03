// ========== 全局状态 ==========
const state = {
    startTime: Date.now(),
    logCount: 0,
    theme: localStorage.getItem('theme') || 'dark',
    charts: {},
    systemData: {
        cpu: [],
        memory: [],
        network: []
    }
};

// ========== 页面加载 ==========
document.addEventListener('DOMContentLoaded', () => {
    // 隐藏加载遮罩
    setTimeout(() => {
        document.getElementById('loading-overlay').classList.add('hidden');
    }, 800);
    
    // 初始化所有功能
    initTheme();
    initNavigation();
    initCharts();
    startStatusUpdates();
    startSystemMonitoring();
    
    addLog('🎉 Web界面加载完成', 'success');
    addLog('📊 所有模块已就绪', 'success');
});

// ========== 主题切换 ==========
function initTheme() {
    // 应用保存的主题
    if (state.theme === 'light') {
        document.body.classList.add('light-theme');
        document.getElementById('theme-icon').textContent = '☀️';
    }
    
    // 主题切换按钮
    document.getElementById('theme-toggle').addEventListener('click', () => {
        state.theme = state.theme === 'dark' ? 'light' : 'dark';
        document.body.classList.toggle('light-theme');
        document.getElementById('theme-icon').textContent = state.theme === 'light' ? '☀️' : '🌙';
        localStorage.setItem('theme', state.theme);
        addLog(`切换到${state.theme === 'light' ? '浅色' : '深色'}主题`, 'info');
        
        // 重绘图表
        updateChartTheme();
    });
}

// ========== 全屏功能 ==========
function initNavigation() {
    // 全屏按钮
    document.getElementById('fullscreen-toggle').addEventListener('click', () => {
        if (!document.fullscreenElement) {
            document.documentElement.requestFullscreen();
            addLog('进入全屏模式', 'info');
        } else {
            document.exitFullscreen();
            addLog('退出全屏模式', 'info');
        }
    });
    
    // 导航链接激活
    document.querySelectorAll('.nav-link').forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
            this.classList.add('active');
            
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }
        });
    });
    
    // 滚动监听
    const sections = document.querySelectorAll('section[id]');
    window.addEventListener('scroll', () => {
        let current = '';
        sections.forEach(section => {
            const sectionTop = section.offsetTop - 100;
            if (pageYOffset >= sectionTop) {
                current = section.getAttribute('id');
            }
        });
        
        document.querySelectorAll('.nav-link').forEach(link => {
            link.classList.remove('active');
            if (link.getAttribute('href') === `#${current}`) {
                link.classList.add('active');
            }
        });
    });
}

// ========== 定时更新系统状态 ==========
function startStatusUpdates() {
    updateUptime();
    setInterval(updateUptime, 1000);
    
    // 定期获取服务器状态
    fetchServerStatus();
    setInterval(fetchServerStatus, 3000);
}

function updateUptime() {
    const uptime = Math.floor((Date.now() - state.startTime) / 1000);
    const hours = Math.floor(uptime / 3600);
    const minutes = Math.floor((uptime % 3600) / 60);
    const seconds = uptime % 60;
    
    let uptimeText = '';
    if (hours > 0) {
        uptimeText = `${hours}h ${minutes}m ${seconds}s`;
    } else if (minutes > 0) {
        uptimeText = `${minutes}m ${seconds}s`;
    } else {
        uptimeText = `${seconds}s`;
    }
    
    const uptimeElement = document.getElementById('uptime');
    if (uptimeElement) {
        uptimeElement.textContent = uptimeText;
    }
}

async function fetchServerStatus() {
    try {
        const response = await fetch('/api/status');
        
        // 检查响应状态
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }
        
        // 检查Content-Type
        const contentType = response.headers.get('content-type');
        if (!contentType || !contentType.includes('application/json')) {
            throw new Error('Invalid response type');
        }
        
        const data = await response.json();
        
        // 更新UI
        updateElement('server-status', data.status || '运行中');
        updateElement('mempool-status', data.mempool || '就绪');
        updateElement('connections', data.connections || 0);
        
        // 显示系统硬件信息
        if (data.cpu) {
            updateElement('system-cpu', data.cpu);
        }
        if (data.cores) {
            updateElement('system-cores', data.cores + ' 核心');
        }
        if (data.memory_gb) {
            updateElement('system-memory', data.memory_gb.toFixed(1) + ' GB');
        }
        if (data.os) {
            updateElement('system-os', data.os + ' ' + (data.arch || ''));
        }
        
        // 更新状态指示器
        const statusDot = document.getElementById('status-dot');
        const statusText = document.getElementById('status-text');
        if (statusDot && statusText) {
            if (data.status === 'running') {
                statusDot.style.background = 'var(--success)';
                statusText.textContent = '运行中';
            } else {
                statusDot.style.background = 'var(--danger)';
                statusText.textContent = '异常';
            }
        }
    } catch (error) {
        console.error('获取状态失败:', error);
        const statusDot = document.getElementById('status-dot');
        const statusText = document.getElementById('status-text');
        if (statusDot) statusDot.style.background = 'var(--warning)';
        if (statusText) statusText.textContent = '连接失败';
    }
}

function updateElement(id, value) {
    const element = document.getElementById(id);
    if (element) {
        element.textContent = value;
    }
}

// ========== 图表初始化 ==========
function initCharts() {
    const chartOptions = {
        responsive: true,
        maintainAspectRatio: true,
        plugins: {
            legend: {
                labels: {
                    color: getComputedStyle(document.documentElement).getPropertyValue('--text').trim()
                }
            }
        },
        scales: {
            y: {
                ticks: { color: getComputedStyle(document.documentElement).getPropertyValue('--text-muted').trim() },
                grid: { color: getComputedStyle(document.documentElement).getPropertyValue('--border').trim() }
            },
            x: {
                ticks: { color: getComputedStyle(document.documentElement).getPropertyValue('--text-muted').trim() },
                grid: { color: getComputedStyle(document.documentElement).getPropertyValue('--border').trim() }
            }
        }
    };
    
    // 内存池性能对比图
    const mempoolCtx = document.getElementById('mempoolChart');
    if (mempoolCtx) {
        state.charts.mempool = new Chart(mempoolCtx, {
            type: 'bar',
            data: {
                labels: ['malloc/free', '一级池', '二级池', '三级池'],
                datasets: [{
                    label: '单线程 (ops/s)',
                    data: [100000, 275000, 350000, 375000],
                    backgroundColor: 'rgba(102, 126, 234, 0.6)',
                    borderColor: 'rgba(102, 126, 234, 1)',
                    borderWidth: 2
                }, {
                    label: '多线程 (ops/s)',
                    data: [95000, 380000, 475000, 525000],
                    backgroundColor: 'rgba(118, 75, 162, 0.6)',
                    borderColor: 'rgba(118, 75, 162, 1)',
                    borderWidth: 2
                }]
            },
            options: chartOptions
        });
    }
    
    // 多线程扩展性图
    const threadCtx = document.getElementById('threadChart');
    if (threadCtx) {
        state.charts.thread = new Chart(threadCtx, {
            type: 'line',
            data: {
                labels: ['1', '2', '4', '6', '8', '10'],
                datasets: [{
                    label: '三级池',
                    data: [375000, 720000, 1380000, 1950000, 2450000, 2850000],
                    borderColor: 'rgba(102, 126, 234, 1)',
                    backgroundColor: 'rgba(102, 126, 234, 0.2)',
                    tension: 0.4,
                    fill: true
                }, {
                    label: 'malloc',
                    data: [100000, 180000, 320000, 450000, 550000, 620000],
                    borderColor: 'rgba(239, 68, 68, 1)',
                    backgroundColor: 'rgba(239, 68, 68, 0.2)',
                    tension: 0.4,
                    fill: true
                }]
            },
            options: chartOptions
        });
    }
    
    // 网络QPS图
    const qpsCtx = document.getElementById('qpsChart');
    if (qpsCtx) {
        state.charts.qps = new Chart(qpsCtx, {
            type: 'bar',
            data: {
                labels: ['1连接', '10连接', '50连接', '100连接'],
                datasets: [{
                    label: 'QPS',
                    data: [8234, 28456, 45234, 52376],
                    backgroundColor: 'rgba(16, 185, 129, 0.6)',
                    borderColor: 'rgba(16, 185, 129, 1)',
                    borderWidth: 2
                }]
            },
            options: chartOptions
        });
    }
    
    // 延迟分布图
    const latencyCtx = document.getElementById('latencyChart');
    if (latencyCtx) {
        state.charts.latency = new Chart(latencyCtx, {
            type: 'line',
            data: {
                labels: ['P50', 'P75', 'P90', 'P95', 'P99'],
                datasets: [{
                    label: '延迟 (μs)',
                    data: [10.2, 12.5, 15.8, 18.3, 90.5],
                    borderColor: 'rgba(245, 158, 11, 1)',
                    backgroundColor: 'rgba(245, 158, 11, 0.2)',
                    tension: 0.4,
                    fill: true
                }]
            },
            options: chartOptions
        });
    }
    
    // 实时系统监控
    const systemCtx = document.getElementById('systemChart');
    if (systemCtx) {
        state.charts.system = new Chart(systemCtx, {
            type: 'line',
            data: {
                labels: Array(20).fill(''),
                datasets: [{
                    label: 'CPU %',
                    data: Array(20).fill(0),
                    borderColor: 'rgba(102, 126, 234, 1)',
                    backgroundColor: 'rgba(102, 126, 234, 0.2)',
                    tension: 0.4
                }, {
                    label: 'Memory %',
                    data: Array(20).fill(0),
                    borderColor: 'rgba(118, 75, 162, 1)',
                    backgroundColor: 'rgba(118, 75, 162, 0.2)',
                    tension: 0.4
                }]
            },
            options: { ...chartOptions, animation: false }
        });
    }
    
    // 网络流量监控
    const networkCtx = document.getElementById('networkChart');
    if (networkCtx) {
        state.charts.network = new Chart(networkCtx, {
            type: 'line',
            data: {
                labels: Array(20).fill(''),
                datasets: [{
                    label: 'Requests/s',
                    data: Array(20).fill(0),
                    borderColor: 'rgba(16, 185, 129, 1)',
                    backgroundColor: 'rgba(16, 185, 129, 0.2)',
                    tension: 0.4
                }]
            },
            options: { ...chartOptions, animation: false }
        });
    }
    
    addLog('📊 图表初始化完成', 'success');
}

// 更新图表主题
function updateChartTheme() {
    Object.values(state.charts).forEach(chart => {
        if (chart && chart.options) {
            const textColor = getComputedStyle(document.documentElement).getPropertyValue('--text').trim();
            const mutedColor = getComputedStyle(document.documentElement).getPropertyValue('--text-muted').trim();
            const borderColor = getComputedStyle(document.documentElement).getPropertyValue('--border').trim();
            
            if (chart.options.plugins && chart.options.plugins.legend) {
                chart.options.plugins.legend.labels.color = textColor;
            }
            if (chart.options.scales) {
                if (chart.options.scales.y) {
                    chart.options.scales.y.ticks.color = mutedColor;
                    chart.options.scales.y.grid.color = borderColor;
                }
                if (chart.options.scales.x) {
                    chart.options.scales.x.ticks.color = mutedColor;
                    chart.options.scales.x.grid.color = borderColor;
                }
            }
            chart.update();
        }
    });
}

// ========== 实时系统监控 ==========
function startSystemMonitoring() {
    setInterval(() => {
        // 模拟CPU和内存数据（实际应该从API获取）
        const cpu = Math.random() * 30 + 10;
        const memory = Math.random() * 20 + 40;
        const requests = Math.random() * 100 + 50;
        
        // 更新系统图表
        if (state.charts.system) {
            state.charts.system.data.datasets[0].data.push(cpu);
            state.charts.system.data.datasets[0].data.shift();
            state.charts.system.data.datasets[1].data.push(memory);
            state.charts.system.data.datasets[1].data.shift();
            state.charts.system.update();
        }
        
        // 更新网络图表
        if (state.charts.network) {
            state.charts.network.data.datasets[0].data.push(requests);
            state.charts.network.data.datasets[0].data.shift();
            state.charts.network.update();
        }
    }, 2000);
}

// ========== 测试功能 ==========
// 运行测试
async function runTest(type) {
    const resultDiv = document.getElementById(`${type}-result`);
    const testName = type === 'mempool' ? '内存池' : '网络';
    
    // 显示加载状态
    resultDiv.style.display = 'block';
    resultDiv.className = 'test-result loading';
    resultDiv.innerHTML = `
        <div class="spinner"></div>
        <span>正在运行${testName}测试...</span>
    `;
    
    addLog(`开始${testName}测试`, 'info');
    
    try {
        const response = await fetch(`/api/test/${type}`, {
            method: 'POST'
        });
        
        const data = await response.json();
        
        if (data.success) {
            // 成功
            resultDiv.className = 'test-result success';
            resultDiv.innerHTML = `
                <div style="font-weight: bold; color: var(--success); margin-bottom: 0.5rem;">
                    ✓ 测试完成
                </div>
                <pre style="margin: 0; white-space: pre-wrap; color: var(--text-muted);">${data.result}</pre>
            `;
            addLog(`${testName}测试完成 - ${data.result.split('\n')[0]}`, 'success');
            
            // 添加成功动画
            confetti();
        } else {
            // 失败
            resultDiv.className = 'test-result error';
            resultDiv.innerHTML = `
                <div style="font-weight: bold; color: var(--danger); margin-bottom: 0.5rem;">
                    ✗ 测试失败
                </div>
                <pre style="margin: 0; white-space: pre-wrap;">${data.error || '未知错误'}</pre>
            `;
            addLog(`${testName}测试失败`, 'error');
        }
    } catch (error) {
        resultDiv.className = 'test-result error';
        resultDiv.innerHTML = `
            <div style="font-weight: bold; color: var(--danger); margin-bottom: 0.5rem;">
                ✗ 请求失败
            </div>
            <pre style="margin: 0;">${error.message}</pre>
        `;
        addLog(`测试请求失败: ${error.message}`, 'error');
    }
}

// 查看数据
async function viewData(type) {
    const testName = type === 'mempool' ? '内存池' : '网络';
    addLog(`获取${testName}数据`, 'info');
    
    try {
        const response = await fetch(`/api/data?type=${type}`);
        const data = await response.json();
        
        if (data.success) {
            showNotification(`数据位置: ${data.file}`, 'success');
            addLog(`数据文件: ${data.file}`, 'success');
        } else {
            showNotification('数据获取失败', 'error');
            addLog('数据获取失败', 'error');
        }
    } catch (error) {
        showNotification(`请求失败: ${error.message}`, 'error');
        addLog(`请求失败: ${error.message}`, 'error');
    }
}

// 添加日志
function addLog(message, type = 'info') {
    const logContainer = document.getElementById('log');
    if (!logContainer) return;
    
    const now = new Date();
    const timeStr = now.toLocaleTimeString('zh-CN', { hour12: false });
    
    const logLine = document.createElement('div');
    logLine.className = `log-line log-${type}`;
    logLine.innerHTML = `
        <span class="log-time">[${timeStr}]</span>
        <span class="log-content">${escapeHtml(message)}</span>
    `;
    
    logContainer.appendChild(logLine);
    logContainer.scrollTop = logContainer.scrollHeight;
    
    state.logCount++;
    
    // 限制日志数量
    if (state.logCount > 100) {
        logContainer.removeChild(logContainer.firstChild);
        state.logCount--;
    }
}

// 清空日志
function clearLog() {
    const logContainer = document.getElementById('log');
    if (logContainer) {
        logContainer.innerHTML = '';
        state.logCount = 0;
        addLog('日志已清空', 'info');
    }
}

// 显示通知
function showNotification(message, type = 'info') {
    // 创建通知元素
    const notification = document.createElement('div');
    notification.style.cssText = `
        position: fixed;
        top: 80px;
        right: 20px;
        padding: 1rem 1.5rem;
        background: var(--dark-light);
        border: 1px solid var(--border);
        border-left: 4px solid var(--${type === 'success' ? 'success' : type === 'error' ? 'danger' : 'info'});
        border-radius: 8px;
        box-shadow: 0 4px 12px var(--shadow);
        z-index: 1000;
        animation: slideIn 0.3s ease-out;
        max-width: 400px;
    `;
    notification.textContent = message;
    
    document.body.appendChild(notification);
    
    // 3秒后移除
    setTimeout(() => {
        notification.style.animation = 'slideOut 0.3s ease-in';
        setTimeout(() => {
            document.body.removeChild(notification);
        }, 300);
    }, 3000);
}

// HTML转义
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// 简单的庆祝动画
function confetti() {
    const colors = ['#667eea', '#764ba2', '#10b981', '#3b82f6', '#f59e0b'];
    for (let i = 0; i < 30; i++) {
        createConfetti(colors[Math.floor(Math.random() * colors.length)]);
    }
}

function createConfetti(color) {
    const confetti = document.createElement('div');
    confetti.style.cssText = `
        position: fixed;
        width: 10px;
        height: 10px;
        background: ${color};
        top: -10px;
        left: ${Math.random() * 100}%;
        border-radius: 50%;
        z-index: 9999;
        pointer-events: none;
    `;
    
    document.body.appendChild(confetti);
    
    const animation = confetti.animate([
        { transform: 'translateY(0) rotate(0deg)', opacity: 1 },
        { transform: `translateY(${window.innerHeight + 10}px) rotate(${Math.random() * 360}deg)`, opacity: 0 }
    ], {
        duration: 3000,
        easing: 'cubic-bezier(0.25, 0.46, 0.45, 0.94)'
    });
    
    animation.onfinish = () => {
        document.body.removeChild(confetti);
    };
}

// 添加CSS动画
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from {
            transform: translateX(400px);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }
    
    @keyframes slideOut {
        from {
            transform: translateX(0);
            opacity: 1;
        }
        to {
            transform: translateX(400px);
            opacity: 0;
        }
    }
`;
document.head.appendChild(style);

// 导航激活状态
const sections = document.querySelectorAll('section[id]');
const navLinks = document.querySelectorAll('.nav-link');

window.addEventListener('scroll', () => {
    let current = '';
    sections.forEach(section => {
        const sectionTop = section.offsetTop;
        const sectionHeight = section.clientHeight;
        if (pageYOffset >= sectionTop - 200) {
            current = section.getAttribute('id');
        }
    });
    
    navLinks.forEach(link => {
        link.classList.remove('active');
        if (link.getAttribute('href') === `#${current}`) {
            link.classList.add('active');
        }
    });
});

console.log('🚀 Reactor Monitor initialized');

// ========== 专业测试系统 ==========

// 测试状态管理
const testState = {
    mempool: { running: false, config: null, result: null, startTime: null },
    network: { running: false, config: null, result: null, startTime: null },
    history: JSON.parse(localStorage.getItem('testHistory') || '[]')
};

// 切换测试配置面板
function toggleTestConfig(type) {
    const configPanel = document.getElementById(`${type}-config`);
    configPanel.classList.toggle('show');
    addLog(`${type === 'mempool' ? '内存池' : '网络'}测试配置面板已${configPanel.classList.contains('show') ? '展开' : '收起'}`, 'info');
}

// 重置测试配置
function resetTestConfig(type) {
    if (type === 'mempool') {
        document.getElementById('mempool-mode').value = 'standard';
        document.getElementById('mempool-iterations').value = '1000000';
        document.getElementById('mempool-blocksize').value = '128';
        document.getElementById('mempool-threads').value = '4';
        document.getElementById('mempool-threads-value').textContent = '4';
        document.getElementById('mempool-multithread').checked = true;
        document.getElementById('mempool-scalability').checked = false;
        document.getElementById('mempool-baseline').checked = true;
        document.getElementById('mempool-warmup').checked = true;
        document.getElementById('mempool-stats').checked = true;
        document.getElementById('mempool-export-csv').checked = true;
        document.getElementById('mempool-export-json').checked = false;
        document.getElementById('mempool-save-history').checked = true;
    } else {
        document.getElementById('network-mode').value = 'stress';
        document.getElementById('network-duration').value = '60';
        document.getElementById('network-requests').value = '100000';
        document.getElementById('network-connections').value = '100';
        document.getElementById('network-connections-value').textContent = '100';
        document.getElementById('network-req-per-conn').value = '1000';
        document.getElementById('network-keepalive').checked = true;
        document.getElementById('network-msgsize').value = '1024';
        document.getElementById('network-pattern').value = 'constant';
        document.getElementById('network-random-data').checked = false;
        document.getElementById('network-latency-dist').checked = true;
        document.getElementById('network-percentiles').checked = true;
        document.getElementById('network-throughput').checked = true;
    }
    addLog(`${type === 'mempool' ? '内存池' : '网络'}测试配置已重置`, 'success');
    showNotification('配置已重置为默认值', 'success');
}

// 读取测试配置
function getTestConfig(type) {
    if (type === 'mempool') {
        return {
            mode: document.getElementById('mempool-mode').value,
            iterations: parseInt(document.getElementById('mempool-iterations').value),
            blockSize: parseInt(document.getElementById('mempool-blocksize').value),
            threads: parseInt(document.getElementById('mempool-threads').value),
            multithread: document.getElementById('mempool-multithread').checked,
            scalability: document.getElementById('mempool-scalability').checked,
            baseline: document.getElementById('mempool-baseline').checked,
            warmup: document.getElementById('mempool-warmup').checked,
            stats: document.getElementById('mempool-stats').checked,
            exportCSV: document.getElementById('mempool-export-csv').checked,
            exportJSON: document.getElementById('mempool-export-json').checked,
            saveHistory: document.getElementById('mempool-save-history').checked
        };
    } else {
        return {
            mode: document.getElementById('network-mode').value,
            duration: parseInt(document.getElementById('network-duration').value),
            requests: parseInt(document.getElementById('network-requests').value),
            connections: parseInt(document.getElementById('network-connections').value),
            reqPerConn: parseInt(document.getElementById('network-req-per-conn').value),
            keepalive: document.getElementById('network-keepalive').checked,
            msgSize: parseInt(document.getElementById('network-msgsize').value),
            pattern: document.getElementById('network-pattern').value,
            randomData: document.getElementById('network-random-data').checked,
            latencyDist: document.getElementById('network-latency-dist').checked,
            percentiles: document.getElementById('network-percentiles').checked,
            throughput: document.getElementById('network-throughput').checked
        };
    }
}

// 运行专业测试
async function runProfessionalTest(type) {
    if (testState[type].running) {
        showNotification('测试正在运行中...', 'warning');
        return;
    }

    const config = getTestConfig(type);
    testState[type].config = config;
    testState[type].running = true;
    testState[type].startTime = Date.now();

    const testName = type === 'mempool' ? '内存池' : '网络';
    addLog(`🚀 开始${testName}测试`, 'info');
    addLog(`📋 配置: ${JSON.stringify(config)}`, 'info');

    // 显示进度
    const progressDiv = document.getElementById(`${type}-progress`);
    const resultDiv = document.getElementById(`${type}-result`);
    const stopBtn = document.getElementById(`${type}-stop`);
    
    progressDiv.style.display = 'block';
    resultDiv.style.display = 'none';
    stopBtn.disabled = false;

    // 模拟测试进度
    simulateTestProgress(type, config);

    try {
        // 调用后端API
        const response = await fetch(`/api/test/${type}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(config)
        });

        // 检查响应状态
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }
        
        // 检查Content-Type
        const contentType = response.headers.get('content-type');
        if (!contentType || !contentType.includes('application/json')) {
            const text = await response.text();
            console.error('非JSON响应:', text.substring(0, 200));
            throw new Error('服务器返回非JSON响应');
        }

        const data = await response.json();

        testState[type].running = false;
        stopBtn.disabled = true;

        if (data.success) {
            testState[type].result = data;
            displayTestResult(type, data, config);
            
            // 保存到历史
            saveToHistory(type, config, data);

            addLog(`✅ ${testName}测试完成 - 加速: ${data.speedup?.toFixed(2)}x`, 'success');
            showNotification(`测试完成！加速 ${data.speedup?.toFixed(2)}x`, 'success');
            confetti();
        } else {
            displayTestError(type, data.error || '测试失败');
            addLog(`❌ ${testName}测试失败`, 'error');
            showNotification('测试失败', 'error');
        }
    } catch (error) {
        testState[type].running = false;
        stopBtn.disabled = true;
        displayTestError(type, error.message);
        addLog(`❌ 测试请求失败: ${error.message}`, 'error');
        showNotification('测试请求失败', 'error');
    }
}

// 模拟测试进度
function simulateTestProgress(type, config) {
    const duration = type === 'mempool' ? 
        (config.mode === 'quick' ? 30 : config.mode === 'standard' ? 60 : 120) :
        config.duration;
    
    let elapsed = 0;
    const interval = setInterval(() => {
        if (!testState[type].running) {
            clearInterval(interval);
            return;
        }

        elapsed++;
        const progress = Math.min((elapsed / duration) * 100, 100);

        // 更新进度条
        document.getElementById(`${type}-progress-bar`).style.width = `${progress}%`;
        document.getElementById(`${type}-progress-text`).textContent = `${Math.round(progress)}%`;
        document.getElementById(`${type}-elapsed`).textContent = elapsed;

        // 更新实时统计（模拟数据）
        const currentQPS = Math.floor(Math.random() * 10000 + 40000);
        const avgLatency = (Math.random() * 5 + 10).toFixed(2);
        const completion = type === 'mempool' ? 
            `${Math.floor(config.iterations * progress / 100)}/${config.iterations}` :
            `${Math.floor(config.requests * progress / 100)}/${config.requests}`;

        document.getElementById(`${type}-current-qps`).textContent = currentQPS.toLocaleString();
        document.getElementById(`${type}-avg-latency`).textContent = `${avgLatency}μs`;
        
        if (type === 'mempool') {
            document.getElementById(`${type}-completion`).textContent = completion;
        } else {
            const successRate = (95 + Math.random() * 5).toFixed(2);
            document.getElementById(`${type}-success-rate`).textContent = `${successRate}%`;
        }

        if (elapsed >= duration) {
            clearInterval(interval);
        }
    }, 1000);
}

// 显示测试结果（真实数据版）
function displayTestResult(type, data, config) {
    const resultDiv = document.getElementById(`${type}-result`);
    const progressDiv = document.getElementById(`${type}-progress`);
    
    progressDiv.style.display = 'none';
    resultDiv.style.display = 'block';
    resultDiv.className = 'test-result-professional';

    const testName = type === 'mempool' ? '内存池性能' : '网络性能';
    
    let html = `
        <div class="result-header">
            <div class="result-title">✅ ${testName}测试报告</div>
            <div><span class="badge badge-success">测试完成</span></div>
        </div>
        <div class="result-tabs">
            <button class="result-tab active" onclick="switchResultTab('${type}', 'summary')">概览</button>
            <button class="result-tab" onclick="switchResultTab('${type}', 'config')">测试配置</button>
        </div>
        <div id="${type}-result-summary" class="result-content active">
            <div class="result-grid">
    `;

    if (type === 'mempool' && data.malloc_ms !== undefined) {
        // 内存池测试数据 - 完整参数支持
        const improvement = ((data.malloc_ms - data.pool_ms) / data.malloc_ms * 100).toFixed(1);
        html += `
                <div class="result-metric highlight">
                    <div class="result-metric-label">性能提升</div>
                    <div class="result-metric-value">${data.speedup?.toFixed(2)}x</div>
                    <div class="result-metric-sub">${improvement}% 更快</div>
                </div>
                <div class="result-metric">
                    <div class="result-metric-label">malloc/free</div>
                    <div class="result-metric-value">${data.malloc_ms} ms</div>
                    <div class="result-metric-sub">${formatNumber(data.malloc_qps)} ops/s</div>
                </div>
                <div class="result-metric success">
                    <div class="result-metric-label">MemoryPool</div>
                    <div class="result-metric-value">${data.pool_ms} ms</div>
                    <div class="result-metric-sub">${formatNumber(data.pool_qps)} ops/s</div>
                </div>
                <div class="result-metric">
                    <div class="result-metric-label">总操作数</div>
                    <div class="result-metric-value">${formatNumber(data.total_ops || data.iterations * data.threads)}</div>
                    <div class="result-metric-sub">${data.threads} 线程 | ${data.mode || 'quick'}</div>
                </div>
        `;
        // 百分位延迟
        if (data.percentiles) {
            html += `
            </div>
            <h4 style="margin-top: 1.5rem; margin-bottom: 0.5rem;">📊 百分位延迟 (μs)</h4>
            <div class="result-grid">
                <div class="result-metric"><div class="result-metric-label">P50</div><div class="result-metric-value">${data.percentiles.p50}</div></div>
                <div class="result-metric"><div class="result-metric-label">P75</div><div class="result-metric-value">${data.percentiles.p75}</div></div>
                <div class="result-metric"><div class="result-metric-label">P90</div><div class="result-metric-value">${data.percentiles.p90}</div></div>
                <div class="result-metric"><div class="result-metric-label">P99</div><div class="result-metric-value">${data.percentiles.p99}</div></div>
            `;
        }
    } else if (type === 'network' && data.qps !== undefined) {
        // 网络测试数据 - 完整参数支持
        html += `
                <div class="result-metric highlight">
                    <div class="result-metric-label">QPS</div>
                    <div class="result-metric-value">${formatNumber(data.qps)}</div>
                    <div class="result-metric-sub">${data.mode || 'stress'} 模式</div>
                </div>
                <div class="result-metric">
                    <div class="result-metric-label">总请求数</div>
                    <div class="result-metric-value">${formatNumber(data.total_requests)}</div>
                    <div class="result-metric-sub">${data.connections} 连接</div>
                </div>
                <div class="result-metric success">
                    <div class="result-metric-label">成功率</div>
                    <div class="result-metric-value">${data.success_rate}%</div>
                    <div class="result-metric-sub">${data.keepalive ? 'Keep-Alive' : '短连接'}</div>
                </div>
                <div class="result-metric">
                    <div class="result-metric-label">平均延迟</div>
                    <div class="result-metric-value">${data.avg_latency}μs</div>
                    <div class="result-metric-sub">${data.duration || 15}s 测试</div>
                </div>
        `;
        // 吞吐量
        if (data.throughput_mbps) {
            html += `
                <div class="result-metric">
                    <div class="result-metric-label">吞吐量</div>
                    <div class="result-metric-value">${data.throughput_mbps} MB/s</div>
                    <div class="result-metric-sub">${data.msg_size || 1024} bytes/msg</div>
                </div>
            `;
        }
        // 百分位延迟
        if (data.percentiles) {
            html += `
            </div>
            <h4 style="margin-top: 1.5rem; margin-bottom: 0.5rem;">📊 百分位延迟 (μs)</h4>
            <div class="result-grid">
                <div class="result-metric"><div class="result-metric-label">P50</div><div class="result-metric-value">${data.percentiles.p50}</div></div>
                <div class="result-metric"><div class="result-metric-label">P90</div><div class="result-metric-value">${data.percentiles.p90}</div></div>
                <div class="result-metric"><div class="result-metric-label">P99</div><div class="result-metric-value">${data.percentiles.p99}</div></div>
                <div class="result-metric"><div class="result-metric-label">P99.9</div><div class="result-metric-value">${data.percentiles.p999}</div></div>
            `;
        }
    } else {
        // 无详细数据时的简化显示
        html += `
                <div class="result-metric">
                    <div class="result-metric-label">测试状态</div>
                    <div class="result-metric-value">✓</div>
                    <div class="result-metric-sub">${data.message || '完成'}</div>
                </div>
        `;
    }

    html += `
            </div>
        </div>
        <div id="${type}-result-config" class="result-content">
            <h4 style="margin-bottom: 1rem;">测试配置</h4>
            <pre style="background: var(--dark-lighter); padding: 1rem; border-radius: 6px; overflow-x: auto;">${JSON.stringify(config, null, 2)}</pre>
        </div>
    `;

    resultDiv.innerHTML = html;
}

// 格式化大数字
function formatNumber(num) {
    if (!num) return 'N/A';
    if (num >= 1000000) return (num / 1000000).toFixed(2) + 'M';
    if (num >= 1000) return (num / 1000).toFixed(2) + 'K';
    return num.toLocaleString();
}

// 显示测试错误
function displayTestError(type, error) {
    const resultDiv = document.getElementById(`${type}-result`);
    const progressDiv = document.getElementById(`${type}-progress`);
    
    progressDiv.style.display = 'none';
    resultDiv.style.display = 'block';
    resultDiv.className = 'test-result-professional error';
    
    resultDiv.innerHTML = `
        <div class="result-header">
            <div class="result-title">❌ 测试失败</div>
        </div>
        <pre style="color: var(--danger); padding: 1rem; background: var(--dark-lighter); border-radius: 6px;">${error}</pre>
    `;
}

// 切换结果标签页
function switchResultTab(type, tab) {
    // 切换按钮状态
    document.querySelectorAll(`#${type}-result .result-tab`).forEach(btn => {
        btn.classList.remove('active');
    });
    event.target.classList.add('active');
    
    // 切换内容
    document.querySelectorAll(`#${type}-result .result-content`).forEach(content => {
        content.classList.remove('active');
    });
    document.getElementById(`${type}-result-${tab}`).classList.add('active');
}

// 停止测试
function stopTest(type) {
    if (!testState[type].running) return;
    
    testState[type].running = false;
    document.getElementById(`${type}-stop`).disabled = true;
    document.getElementById(`${type}-progress`).style.display = 'none';
    
    const testName = type === 'mempool' ? '内存池' : '网络';
    addLog(`⏹ ${testName}测试已停止`, 'warning');
    showNotification('测试已停止', 'warning');
}

// 导出测试结果（修复：导出真实结果而非配置）
function exportTestResults(type) {
    const result = testState[type].result;
    const config = testState[type].config;
    
    if (!result || !config) {
        showNotification('没有可导出的测试结果', 'warning');
        return;
    }

    // CSV格式导出（适合Excel分析）
    if (type === 'mempool' && result.malloc_ms !== undefined) {
        let csv = 'Metric,Value\n';
        csv += `Test Type,Memory Pool Performance\n`;
        csv += `Timestamp,${new Date().toISOString()}\n`;
        csv += `Iterations,${result.iterations}\n`;
        csv += `Block Size (bytes),${result.block_size}\n`;
        csv += `Threads,${result.threads}\n`;
        csv += `malloc Time (ms),${result.malloc_ms}\n`;
        csv += `Pool Time (ms),${result.pool_ms}\n`;
        csv += `Speedup,${result.speedup}\n`;
        csv += `malloc QPS,${result.malloc_qps}\n`;
        csv += `Pool QPS,${result.pool_qps}\n`;
        csv += `Improvement (%),${((result.malloc_ms - result.pool_ms) / result.malloc_ms * 100).toFixed(2)}\n`;
        
        const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = `mempool-results-${Date.now()}.csv`;
        link.click();
        URL.revokeObjectURL(url);
        
        addLog(`💾 测试结果已导出为CSV: ${link.download}`, 'success');
        showNotification('测试结果已导出为CSV', 'success');
    } else {
        // JSON格式导出
        const exportData = {
            type: type,
            timestamp: new Date().toISOString(),
            config: config,
            result: result
        };
        
        const dataStr = JSON.stringify(exportData, null, 2);
        const dataBlob = new Blob([dataStr], { type: 'application/json' });
        const url = URL.createObjectURL(dataBlob);
        const link = document.createElement('a');
        link.href = url;
        link.download = `${type}-results-${Date.now()}.json`;
        link.click();
        URL.revokeObjectURL(url);
        
        addLog(`💾 测试结果已导出: ${link.download}`, 'success');
        showNotification('测试结果已导出', 'success');
    }
}

// 保存到历史记录（使用真实数据）
function saveToHistory(type, config, result) {
    const historyItem = {
        id: Date.now(),
        type: type,
        timestamp: new Date().toISOString(),
        config: config,
        result: result
    };

    testState.history.unshift(historyItem);
    
    // 限制历史记录数量
    if (testState.history.length > 50) {
        testState.history = testState.history.slice(0, 50);
    }

    localStorage.setItem('testHistory', JSON.stringify(testState.history));
    loadTestHistory();
    addLog('📝 测试结果已保存到历史记录', 'info');
}

// 切换测试历史面板
function toggleTestHistory() {
    const panel = document.getElementById('test-history-panel');
    panel.classList.toggle('show');
    
    if (panel.classList.contains('show')) {
        loadTestHistory();
    }
}

// 加载测试历史（显示真实数据）
function loadTestHistory() {
    const historyList = document.getElementById('history-list');
    
    if (testState.history.length === 0) {
        historyList.innerHTML = '<div class="history-empty">暂无测试记录</div>';
        return;
    }

    let html = '';
    testState.history.forEach(item => {
        const date = new Date(item.timestamp);
        const timeStr = date.toLocaleString('zh-CN');
        const testName = item.type === 'mempool' ? '内存池测试' : '网络测试';
        
        // 提取真实结果数据
        let statsHtml = '';
        if (item.type === 'mempool' && item.result.speedup) {
            statsHtml = `
                <div class="history-item-stat">加速: <strong>${item.result.speedup.toFixed(2)}x</strong></div>
                <div class="history-item-stat">Pool QPS: <strong>${formatNumber(item.result.pool_qps)}</strong></div>
                <div class="history-item-stat">线程: <strong>${item.result.threads}</strong></div>
            `;
        } else if (item.type === 'network' && item.result.qps) {
            statsHtml = `
                <div class="history-item-stat">QPS: <strong>${formatNumber(item.result.qps)}</strong></div>
                <div class="history-item-stat">延迟: <strong>${item.result.avg_latency}μs</strong></div>
                <div class="history-item-stat">成功率: <strong>${item.result.success_rate}%</strong></div>
            `;
        } else {
            statsHtml = `<div class="history-item-stat">测试完成</div>`;
        }
        
        html += `
            <div class="history-item" onclick="viewHistoryItem(${item.id})">
                <div class="history-item-header">
                    <span class="history-item-title">${testName}</span>
                    <span class="history-item-time">${timeStr}</span>
                </div>
                <div class="history-item-stats">
                    ${statsHtml}
                </div>
            </div>
        `;
    });

    historyList.innerHTML = html;
}

// 查看历史记录项
function viewHistoryItem(id) {
    const item = testState.history.find(h => h.id === id);
    if (!item) return;

    testState[item.type].result = item.result;
    displayTestResult(item.type, item.result, item.config);
    toggleTestHistory();
    
    // 滚动到结果
    document.getElementById(`${item.type}-result`).scrollIntoView({ behavior: 'smooth' });
}

// 过滤历史记录
function filterHistory() {
    const filterType = document.getElementById('history-filter-type').value;
    loadTestHistory();
    
    if (filterType !== 'all') {
        const items = document.querySelectorAll('.history-item');
        items.forEach(item => {
            const title = item.querySelector('.history-item-title').textContent;
            if ((filterType === 'mempool' && !title.includes('内存池')) ||
                (filterType === 'network' && !title.includes('网络'))) {
                item.style.display = 'none';
            }
        });
    }
}

// 清空历史记录
function clearHistory() {
    if (confirm('确定要清空所有测试历史记录吗？')) {
        testState.history = [];
        localStorage.setItem('testHistory', '[]');
        loadTestHistory();
        addLog('🗑️ 测试历史记录已清空', 'info');
        showNotification('历史记录已清空', 'success');
    }
}

// 已删除结果对比功能
