let initialUrl = location.href;
let countdownInterval;
let modalOpen = false;

// Main URL monitoring function
function checkEmailUrl() {
  if (location.href !== initialUrl && !modalOpen) {
    console.log("URL changed. Extracting email data...");
    extractEmailData();
    initialUrl = location.href;
  }
}

// Initial setup
console.log("Secure Inbox extension loaded");
setInterval(checkEmailUrl, 3000);
setTimeout(extractEmailData, 2500);

function extractEmailData() {
  // Extract email metadata
  const titleElement = document.querySelector('h2.hP');
  const title = titleElement?.textContent || "No title found";

  const senderElement = document.querySelector("span.go");
  const sender = senderElement?.textContent.trim().replace(/(^[^\w]+|[^\w]+$)/g, '') || "Sender not found";

  // Extract email content
  const emailBodyElement = document.querySelector(".a3s.aiL");
  const emailBody = emailBodyElement?.innerText || "Email body not found";

  // Extract links
  const hyperlinks = Array.from(emailBodyElement?.querySelectorAll("a") || [])
    .map(a => ({ url: a.href, text: a.innerText }))
    .filter(link => link.url);

  // Extract attachments
  const attachments = Array.from(document.querySelectorAll('[class*="aQH"]'))
    .flatMap(attachment =>
      Array.from(attachment.querySelectorAll('[class*="aZo"] [class*="aQy"]'))
        .map(fileUrl => ({ href: fileUrl.href }))
    );

  // Send data for analysis
  analyzeEmailContent({
    sender,
    body: emailBody,
    anchor: hyperlinks,
    attachments,
    title
  });
}

function analyzeEmailContent(emailData) {
  console.log("Sending email data for analysis:", emailData);

  fetch('http://localhost:5000', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(emailData)
  })
  .then(response => response.json())
  .then(data => {
    if (data.grammarUrl) {
      showSecurityWarningModal(data);
    } else {
      showSafetyIndicator(data);
    }
  })
  .catch(error => {
    console.error("Analysis failed:", error);
    showSafetyIndicator({ grammarUrl: "Could not verify email safety due to connection error" });
  });
}

function showSecurityWarningModal(data) {
  modalOpen = true;

  // Create modal backdrop
  const backdrop = document.createElement('div');
  backdrop.className = 'secure-inbox-backdrop';
  Object.assign(backdrop.style, {
    position: 'fixed',
    top: '0',
    left: '0',
    width: '100%',
    height: '100%',
    backgroundColor: 'rgba(0, 0, 0, 0.5)',
    zIndex: '9998'
  });

  // Create modal
  const modal = document.createElement('div');
  modal.className = 'secure-inbox-modal';
  Object.assign(modal.style, {
    position: 'fixed',
    top: '50%',
    left: '50%',
    transform: 'translate(-50%, -50%)',
    width: '50vw',
    maxWidth: '600px',
    minWidth: '300px',
    backgroundColor: 'white',
    zIndex: '9999',
    boxShadow: '0 0 20px rgba(0, 0, 0, 0.3)',
    borderRadius: '8px',
    padding: '20px',
    borderLeft: '5px solid #dc3545'
  });

  // Modal content
  const header = document.createElement('h3');
  header.textContent = "Security Warning!";
  header.style.color = '#dc3545';
  header.style.marginTop = '0';

  const warningText = document.createElement('p');
  warningText.textContent = data.grammarUrl;
  warningText.style.marginBottom = '20px';

  // Countdown button
  const closeButton = document.createElement('button');
  closeButton.className = 'secure-inbox-close-btn';
  let count = 10;

  Object.assign(closeButton.style, {
    padding: '10px 20px',
    background: '#d8d8d8',
    color: 'white',
    border: 'none',
    borderRadius: '4px',
    cursor: 'pointer',
    fontSize: '14px',
    fontWeight: 'bold',
    display: 'block',
    margin: '0 auto',
    transition: 'background 0.3s'
  });

  function updateButton() {
    closeButton.textContent = count > 0 ? `Close (${count}s)` : 'Close';
    closeButton.disabled = count > 0;
    if (count === 0) {
      closeButton.style.background = '#dc3545';
    }
  }

  countdownInterval = setInterval(() => {
    count--;
    updateButton();
    if (count < 0) clearInterval(countdownInterval);
  }, 1000);

  closeButton.addEventListener('click', () => {
    clearInterval(countdownInterval);
    document.body.removeChild(modal);
    document.body.removeChild(backdrop);
    modalOpen = false;
  });

  // Assemble modal
  modal.appendChild(header);
  modal.appendChild(warningText);
  modal.appendChild(closeButton);
  document.body.appendChild(backdrop);
  document.body.appendChild(modal);
  updateButton();
}

function showSafetyIndicator(data) {
  const headerArea = document.querySelector('.ha');
  if (!headerArea) return;

  // Create checkmark indicator
  const indicator = document.createElement('div');
  indicator.className = 'secure-inbox-indicator';
  indicator.title = 'This email was verified as safe';

  Object.assign(indicator.style, {
    position: 'absolute',
    top: '-5px',
    right: '-30px',
    width: '24px',
    height: '24px',
    borderRadius: '50%',
    background: '#28a745',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    color: 'white',
    fontSize: '16px',
    cursor: 'pointer'
  });
  indicator.innerHTML = '✓';

  // Create tooltip
  const tooltip = document.createElement('div');
  tooltip.className = 'secure-inbox-tooltip';

  Object.assign(tooltip.style, {
    position: 'fixed',
    zIndex: '9999',
    background: '#28a745',
    color: 'white',
    borderRadius: '4px',
    padding: '10px',
    maxWidth: '300px',
    opacity: '0',
    transition: 'opacity 0.2s',
    pointerEvents: 'none',
    boxShadow: '0 2px 10px rgba(0,0,0,0.2)'
  });

  // Add interaction
  indicator.addEventListener('mouseover', (e) => {
    tooltip.textContent = data.grammarUrl || 'This email appears to be safe';
    tooltip.style.left = `${e.clientX + 15}px`;
    tooltip.style.top = `${e.clientY + 15}px`;
    tooltip.style.opacity = '1';
  });

  indicator.addEventListener('mouseout', () => {
    tooltip.style.opacity = '0';
  });

  // Position header area relatively
  headerArea.style.position = 'relative';
  headerArea.appendChild(indicator);
  document.body.appendChild(tooltip);
}
