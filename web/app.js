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
        const data = await response.json();
        
        // 更新UI
        updateElement('server-status', data.status || '运行中');
        updateElement('mempool-status', data.mempool || '就绪');
        updateElement('connections', data.connections || 0);
        
        // 更新状态指示器
        const statusDot = document.getElementById('status-dot');
        const statusText = document.getElementById('status-text');
        if (data.status === 'running') {
            statusDot.style.background = 'var(--success)';
            statusText.textContent = '运行中';
        } else {
            statusDot.style.background = 'var(--danger)';
            statusText.textContent = '异常';
        }
    } catch (error) {
        console.error('获取状态失败:', error);
        document.getElementById('status-dot').style.background = 'var(--warning)';
        document.getElementById('status-text').textContent = '连接失败';
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
