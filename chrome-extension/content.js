// Content script - Chạy trên mỗi trang web

// Lắng nghe message từ background script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'showWarning') {
    showWarningBanner(message.result);
  }
});

// Hiển thị banner cảnh báo
function showWarningBanner(result) {
  // Xóa banner cũ nếu có
  const existingBanner = document.getElementById('malicious-url-warning');
  if (existingBanner) {
    existingBanner.remove();
  }

  // Tạo banner mới
  const banner = document.createElement('div');
  banner.id = 'malicious-url-warning';

  // Style cho banner
  const styles = `
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    background: linear-gradient(135deg, #dc2626 0%, #991b1b 100%);
    color: white;
    padding: 16px 20px;
    z-index: 999999;
    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    font-size: 14px;
    animation: slideDown 0.3s ease-out;
  `;

  banner.setAttribute('style', styles);

  // Thêm keyframe animation
  if (!document.getElementById('malicious-url-styles')) {
    const styleSheet = document.createElement('style');
    styleSheet.id = 'malicious-url-styles';
    styleSheet.textContent = `
      @keyframes slideDown {
        from {
          transform: translateY(-100%);
        }
        to {
          transform: translateY(0);
        }
      }
    `;
    document.head.appendChild(styleSheet);
  }

  // Nội dung banner
  const getRiskColor = (level) => {
    switch(level) {
      case 'critical': return '#dc2626';
      case 'high': return '#f59e0b';
      case 'medium': return '#eab308';
      default: return '#10b981';
    }
  };

  banner.innerHTML = `
    <div style="display: flex; align-items: center; justify-content: space-between; max-width: 1200px; margin: 0 auto;">
      <div style="display: flex; align-items: center; gap: 12px;">
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
          <line x1="12" y1="9" x2="12" y2="13"></line>
          <line x1="12" y1="17" x2="12.01" y2="17"></line>
        </svg>
        <div>
          <div style="font-weight: 600; font-size: 16px; margin-bottom: 4px;">
            ⚠️ Cảnh báo: URL có thể độc hại!
          </div>
          <div style="opacity: 0.9;">
            ${result.risk_text} - Độ tin cậy: ${(result.confidence * 100).toFixed(1)}%
          </div>
        </div>
      </div>
      <div style="display: flex; gap: 12px; align-items: center;">
        <button id="malicious-url-details" style="
          background: rgba(255, 255, 255, 0.2);
          border: 1px solid rgba(255, 255, 255, 0.3);
          color: white;
          padding: 8px 16px;
          border-radius: 6px;
          cursor: pointer;
          font-size: 14px;
          font-weight: 500;
          transition: all 0.2s;
        " onmouseover="this.style.background='rgba(255, 255, 255, 0.3)'"
           onmouseout="this.style.background='rgba(255, 255, 255, 0.2)'">
          Chi tiết
        </button>
        <button id="malicious-url-close" style="
          background: transparent;
          border: none;
          color: white;
          cursor: pointer;
          font-size: 24px;
          line-height: 1;
          padding: 4px 8px;
          opacity: 0.8;
          transition: opacity 0.2s;
        " onmouseover="this.style.opacity='1'"
           onmouseout="this.style.opacity='0.8'">
          ×
        </button>
      </div>
    </div>
  `;

  // Thêm vào body
  document.body.insertBefore(banner, document.body.firstChild);

  // Thêm padding cho body để không bị che nội dung
  const originalPaddingTop = document.body.style.paddingTop;
  document.body.style.paddingTop = `${banner.offsetHeight + (parseInt(originalPaddingTop) || 0)}px`;

  // Xử lý nút đóng
  document.getElementById('malicious-url-close').addEventListener('click', () => {
    banner.style.animation = 'slideUp 0.3s ease-out';
    setTimeout(() => {
      banner.remove();
      document.body.style.paddingTop = originalPaddingTop;
    }, 300);
  });

  // Xử lý nút chi tiết
  document.getElementById('malicious-url-details').addEventListener('click', () => {
    alert(`Thông tin chi tiết:\n\n` +
          `URL: ${window.location.href}\n` +
          `Mức độ nguy hiểm: ${result.risk_text}\n` +
          `Độ tin cậy: ${(result.confidence * 100).toFixed(2)}%\n` +
          `Ngưỡng: ${(result.threshold * 100).toFixed(2)}%\n\n` +
          `Khuyến nghị: Không nhập thông tin cá nhân hoặc tài chính trên trang này.`);
  });

  // Tự động ẩn sau 10 giây nếu không phải critical
  if (result.risk_level !== 'critical') {
    setTimeout(() => {
      if (document.getElementById('malicious-url-warning')) {
        document.getElementById('malicious-url-close').click();
      }
    }, 10000);
  }
}

console.log('Malicious URL Detector - Content script loaded');