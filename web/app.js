// 全局状态
const state = {
    startTime: Date.now(),
    logCount: 0
};

// 初始化
document.addEventListener('DOMContentLoaded', () => {
    initApp();
    startStatusUpdates();
    addLog('Web界面加载完成', 'success');
});

function initApp() {
    // 平滑滚动
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({ behavior: 'smooth' });
            }
        });
    });
}

// 定时更新系统状态
function startStatusUpdates() {
    updateUptime();
    setInterval(updateUptime, 1000);
    
    // 定期获取服务器状态
    setInterval(fetchServerStatus, 5000);
    fetchServerStatus();
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
        
    } catch (error) {
        console.error('获取状态失败:', error);
    }
}

function updateElement(id, value) {
    const element = document.getElementById(id);
    if (element) {
        element.textContent = value;
    }
}

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
