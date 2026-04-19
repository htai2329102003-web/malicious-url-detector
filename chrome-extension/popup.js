// Popup script
let currentTab = null;
let currentConfig = null;

// Load dữ liệu khi popup mở
document.addEventListener('DOMContentLoaded', async () => {
  try {
    // Lấy tab hiện tại
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    currentTab = tab;

    // Lấy config
    currentConfig = await chrome.runtime.sendMessage({ action: 'getConfig' });

    // Cập nhật UI với config
    document.getElementById('toggle-enabled').checked = currentConfig.enabled;
    document.getElementById('toggle-notifications').checked = currentConfig.notificationsEnabled;
    document.getElementById('toggle-autoblock').checked = currentConfig.autoBlock;

    // Hiển thị URL hiện tại
    document.getElementById('current-url').textContent = tab.url || 'N/A';

    // Lấy kết quả đã lưu cho tab này
    const result = await getTabResult(tab.id);

    if (result) {
      updateUI(result);
    } else {
      // Nếu chưa có kết quả, scan ngay
      await scanCurrentURL();
    }

    // Ẩn loading, hiện content
    document.getElementById('loading').style.display = 'none';
    document.getElementById('main-content').style.display = 'block';

  } catch (error) {
    console.error('Error loading popup:', error);
    showError('Không thể tải dữ liệu');
  }
});

// Lấy kết quả đã lưu cho tab
async function getTabResult(tabId) {
  return new Promise((resolve) => {
    chrome.storage.local.get([`tab_${tabId}`], (result) => {
      const data = result[`tab_${tabId}`];
      if (data && data.result) {
        resolve(data.result);
      } else {
        resolve(null);
      }
    });
  });
}

// Scan URL hiện tại
async function scanCurrentURL() {
  if (!currentTab || !currentTab.url) {
    showError('Không có URL để quét');
    return;
  }

  // Hiển thị trạng thái đang quét
  updateStatus('scanning', 'Đang quét...', 'Vui lòng đợi');

  try {
    const result = await chrome.runtime.sendMessage({
      action: 'checkURL',
      url: currentTab.url
    });

    updateUI(result);
  } catch (error) {
    console.error('Error scanning URL:', error);
    showError('Lỗi khi quét URL');
  }
}

// Cập nhật UI với kết quả
function updateUI(result) {
  if (result.error) {
    updateStatus('offline', 'Lỗi kết nối', 'Không thể kết nối đến server');
    document.getElementById('confidence-value').textContent = 'N/A';
    document.getElementById('risk-value').textContent = 'N/A';
    return;
  }

  // Cập nhật status
  if (result.is_malicious) {
    const statusClass = result.risk_level === 'critical' ? 'danger' : 'warning';
    updateStatus(
      statusClass,
      '⚠️ URL độc hại!',
      result.risk_text
    );
  } else {
    updateStatus(
      'safe',
      '✓ URL an toàn',
      'Không phát hiện mối đe dọa'
    );
  }

  // Cập nhật stats
  document.getElementById('confidence-value').textContent =
    `${(result.confidence * 100).toFixed(1)}%`;

  document.getElementById('risk-value').textContent =
    getRiskLabel(result.risk_level);
}

// Cập nhật status indicator
function updateStatus(type, title, subtitle) {
  const dot = document.getElementById('status-dot');
  const titleEl = document.getElementById('status-title');
  const subtitleEl = document.getElementById('status-subtitle');

  // Reset classes
  dot.className = 'status-dot';
  dot.classList.add(type);

  titleEl.textContent = title;
  subtitleEl.textContent = subtitle;
}

// Lấy label mức độ rủi ro
function getRiskLabel(level) {
  switch (level) {
    case 'critical':
      return '🔴 Nguy hiểm';
    case 'high':
      return '🟠 Cao';
    case 'medium':
      return '🟡 Trung bình';
    case 'low':
      return '🟢 Thấp';
    default:
      return 'N/A';
  }
}

// Hiển thị lỗi
function showError(message) {
  updateStatus('offline', '❌ Lỗi', message);
  document.getElementById('confidence-value').textContent = 'N/A';
  document.getElementById('risk-value').textContent = 'N/A';
}

// Event listeners cho các toggle
document.getElementById('toggle-enabled').addEventListener('change', async (e) => {
  currentConfig.enabled = e.target.checked;
  await chrome.runtime.sendMessage({
    action: 'updateConfig',
    config: currentConfig
  });
});

document.getElementById('toggle-notifications').addEventListener('change', async (e) => {
  currentConfig.notificationsEnabled = e.target.checked;
  await chrome.runtime.sendMessage({
    action: 'updateConfig',
    config: currentConfig
  });
});

document.getElementById('toggle-autoblock').addEventListener('change', async (e) => {
  currentConfig.autoBlock = e.target.checked;
  await chrome.runtime.sendMessage({
    action: 'updateConfig',
    config: currentConfig
  });
});

// Event listener cho nút scan
document.getElementById('btn-scan').addEventListener('click', async () => {
  await scanCurrentURL();
});