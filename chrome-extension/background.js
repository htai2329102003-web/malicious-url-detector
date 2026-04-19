// API Server URL
const API_URL = 'http://127.0.0.1:5000'; // sẽ thử 127.0.0.1 nếu localhost lỗi

// Cache để tránh gọi API nhiều lần cho cùng 1 URL
const urlCache = new Map();
const CACHE_DURATION = 5 * 60 * 1000; // 5 phút

// Cấu hình mặc định
const defaultConfig = {
  enabled: true,
  notificationsEnabled: true,
  autoBlock: false,
};

let currentConfig = { ...defaultConfig };

// Helpers lấy/lưu config
function loadConfig() {
  return new Promise((resolve) => {
    chrome.storage.local.get(['config'], (res) => {
      currentConfig = { ...defaultConfig, ...(res.config || {}) };
      resolve(currentConfig);
    });
  });
}

function saveConfig(config) {
  currentConfig = { ...currentConfig, ...config };
  return new Promise((resolve) => {
    chrome.storage.local.set({ config: currentConfig }, () => resolve(currentConfig));
  });
}

// Kiểm tra URL với API
async function checkURL(url) {
  // Check cache trước
  const cached = urlCache.get(url);
  if (cached && Date.now() - cached.timestamp < CACHE_DURATION) {
    return cached.data;
  }

  try {
    // Helper: fetch với timeout
    const fetchWithTimeout = (resource, options = {}) => {
      const { timeout = 6000 } = options;
      const controller = new AbortController();
      const id = setTimeout(() => controller.abort(), timeout);
      return fetch(resource, { ...options, signal: controller.signal })
        .finally(() => clearTimeout(id));
    };

    // Thử gọi bằng localhost trước
    let response = await fetchWithTimeout(`${API_URL}/scan`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ url: url })
    });

    // Nếu lỗi kết nối hoặc status không OK → thử lại với 127.0.0.1
    if (!response.ok) {
      throw new Error(`API Error: ${response.status}`);
    }

    const data = await response.json();

    // Lưu vào cache
    urlCache.set(url, {
      data: data,
      timestamp: Date.now()
    });

    return data;
  } catch (error) {
    console.warn('Retrying with 127.0.0.1 due to:', error && (error.message || error));
    try {
      const response2 = await fetch(`http://127.0.0.1:5000/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: url })
      });
      if (!response2.ok) {
        throw new Error(`API Error: ${response2.status}`);
      }
      const data2 = await response2.json();
      urlCache.set(url, { data: data2, timestamp: Date.now() });
      return data2;
    } catch (e2) {
      console.error('Error checking URL (both hosts failed):', e2);
      return null;
    }
  }
}

// Lắng nghe khi người dùng truy cập URL mới
chrome.webNavigation.onCommitted.addListener(async (details) => {
  // Chỉ check main frame (không check iframe, images, etc.)
  if (details.frameId !== 0) return;

  const url = details.url;

  // Bỏ qua các URL nội bộ
  if (url.startsWith('chrome://') ||
      url.startsWith('chrome-extension://') ||
      url.startsWith('about:')) {
    return;
  }

  // Load config mỗi lần điều hướng (nhanh vì lưu local)
  await loadConfig();
  if (!currentConfig.enabled) return;

  console.log('Checking URL:', url);

  // Gọi API kiểm tra
  const result = await checkURL(url);

  if (!result) {
    console.error('Failed to check URL');
    return;
  }

  console.log('Result:', result);

  // Lưu kết quả cho tab hiện tại để popup đọc được
  chrome.storage.local.set({ [`tab_${details.tabId}`]: { result } });

  // Gửi kết quả đến content script khi phát hiện nguy hiểm
  if (result.is_malicious) {
    chrome.tabs.sendMessage(details.tabId, {
      action: 'showWarning',
      result: result
    });
  }

  // Cập nhật badge
  updateBadge(details.tabId, result);

  // Hiển thị cảnh báo nếu nguy hiểm
  if (result.is_malicious && currentConfig.notificationsEnabled) {
    showWarningNotification(url, result);
  }
});

// Cập nhật badge trên icon
function updateBadge(tabId, result) {
  const colors = {
    'low': '#00CC00',
    'medium': '#FFA500',
    'high': '#FF6600',
    'critical': '#FF0000'
  };

  chrome.action.setBadgeBackgroundColor({
    color: colors[result.risk_level] || '#808080',
    tabId: tabId
  });

  const percentage = Math.round((result.confidence || 0) * 100);
  chrome.action.setBadgeText({
    text: `${percentage}%`,
    tabId: tabId
  });
}

// Hiển thị cảnh báo
function showWarningNotification(url, result) {
  const domain = new URL(url).hostname;

  chrome.notifications.create({
    type: 'basic',
    iconUrl: 'icons/icon128.png',
    title: '⚠️ CẢNH BÁO: Trang web nguy hiểm!',
    message: `${domain}\nXác suất lừa đảo: ${Math.round((result.confidence || 0) * 100)}%\nMức độ: ${getRiskLevelText(result.risk_level)}`,
    priority: 2,
    requireInteraction: true
  });
}

function getRiskLevelText(level) {
  const texts = {
    'low': 'Thấp',
    'medium': 'Trung bình',
    'high': 'Cao',
    'critical': 'Rất nguy hiểm'
  };
  return texts[level] || 'Không rõ';
}

// Lắng nghe message từ popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  // Lấy config hiện tại
  if (request.action === 'getConfig') {
    loadConfig().then((cfg) => sendResponse(cfg));
    return true;
  }

  // Cập nhật config
  if (request.action === 'updateConfig' && request.config) {
    saveConfig(request.config).then((cfg) => sendResponse(cfg));
    return true;
  }

  // Quét URL hiện tại (popup)
  if (request.action === 'checkURL') {
    chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
      if (tabs[0] && tabs[0].url) {
        await loadConfig();
        if (!currentConfig.enabled) {
          sendResponse({ error: 'disabled' });
          return;
        }
        const result = await checkURL(tabs[0].url);
        if (result) {
          // Lưu và cập nhật badge
          chrome.storage.local.set({ [`tab_${tabs[0].id}`]: { result } });
          updateBadge(tabs[0].id, result);
        }
        sendResponse(result || { error: 'request_failed' });
      } else {
        sendResponse({ error: 'no_active_tab' });
      }
    });
    return true; // async response
  }
});

// Dọn dẹp cache định kỳ (mỗi 10 phút)
setInterval(() => {
  const now = Date.now();
  for (const [url, cached] of urlCache.entries()) {
    if (now - cached.timestamp > CACHE_DURATION) {
      urlCache.delete(url);
    }
  }
}, 10 * 60 * 1000);

// Khởi động: load config
loadConfig().then(() => {
  console.log('Malicious URL Detector loaded with config:', currentConfig);
});