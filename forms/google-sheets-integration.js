/**
 * GOOGLE SHEETS INTEGRATION MODULE
 * 
 * Connects all forms to Google Sheets
 * Automatically saves all submissions to Sheets
 * Supports multiple sheets for different forms
 */

class GoogleSheetsIntegration {
  constructor(config) {
    this.spreadsheetId = config.spreadsheetId;
    this.apiKey = config.apiKey;
    this.sheets = config.sheets || {};
    this.baseUrl = 'https://sheets.googleapis.com/v4/spreadsheets';
  }

  /**
   * ADD ROW TO SHEET
   * Appends a new row to the specified sheet
   */
  async addRowToSheet(sheetName, data) {
    try {
      console.log(`📝 Adding row to ${sheetName}:`, data);

      // Prepare values for the sheet
      const values = this.formatDataForSheet(data);

      // Make request to Google Sheets API
      const response = await fetch(
        `${this.baseUrl}/${this.spreadsheetId}/values/${sheetName}!A1:append?key=${this.apiKey}`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            values: [values],
            majorDimension: 'ROWS'
          })
        }
      );

      if (!response.ok) {
        throw new Error(`Sheet API error: ${response.statusText}`);
      }

      const result = await response.json();
      console.log('✅ Row added successfully:', result);

      return {
        success: true,
        updatedRange: result.updates.updatedRange,
        updatedRows: result.updates.updatedRows
      };
    } catch (error) {
      console.error('❌ Error adding row to sheet:', error);
      throw error;
    }
  }

  /**
   * GET ALL DATA FROM SHEET
   */
  async getSheetData(sheetName) {
    try {
      const response = await fetch(
        `${this.baseUrl}/${this.spreadsheetId}/values/${sheetName}?key=${this.apiKey}`
      );

      if (!response.ok) {
        throw new Error(`Sheet API error: ${response.statusText}`);
      }

      const data = await response.json();
      return data.values || [];
    } catch (error) {
      console.error('❌ Error getting sheet data:', error);
      throw error;
    }
  }

  /**
   * FORMAT DATA FOR SHEET
   * Converts form data object to array for sheets
   */
  formatDataForSheet(data) {
    const timestamp = new Date().toLocaleString();

    // Define column order for different form types
    const columnMaps = {
      contact: [
        timestamp,
        data.name || '',
        data.email || '',
        data.phone || '',
        data.subject || '',
        data.message || '',
        data.ip || '',
        data.userAgent || ''
      ],
      support: [
        timestamp,
        data.name || '',
        data.email || '',
        data.orderNumber || '',
        data.category || '',
        data.priority || '',
        data.description || '',
        data.status || 'Open'
      ],
      review: [
        timestamp,
        data.customerName || '',
        data.email || '',
        data.productName || '',
        data.rating || '',
        data.review || '',
        data.recommend || 'No'
      ],
      newsletter: [
        timestamp,
        data.firstName || '',
        data.email || '',
        (data.interests || []).join(', '),
        data.consent ? 'Yes' : 'No'
      ],
      feedback: [
        timestamp,
        data.name || '',
        data.email || '',
        data.feedbackType || '',
        data.subject || '',
        data.feedback || '',
        data.contactPermission ? 'Yes' : 'No'
      ],
      receipt: [
        timestamp,
        data.purchaseId || '',
        data.customerName || '',
        data.email || '',
        data.orderDate || '',
        data.amount || '',
        'Receipt Generated'
      ]
    };

    // Return formatted data for the sheet
    const formType = data.formType || 'contact';
    return columnMaps[formType] || [timestamp, JSON.stringify(data)];
  }

  /**
   * CREATE SHEET IF NOT EXISTS
   */
  async createSheet(sheetTitle) {
    try {
      console.log(`📄 Creating sheet: ${sheetTitle}`);

      const response = await fetch(
        `${this.baseUrl}/${this.spreadsheetId}:batchUpdate?key=${this.apiKey}`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            requests: [
              {
                addSheet: {
                  properties: {
                    title: sheetTitle
                  }
                }
              }
            ]
          })
        }
      );

      const result = await response.json();
      console.log('✅ Sheet created:', result);
      return result;
    } catch (error) {
      console.error('❌ Error creating sheet:', error);
      throw error;
    }
  }

  /**
   * ADD HEADERS TO SHEET
   */
  async addHeadersToSheet(sheetName, headers) {
    try {
      console.log(`📋 Adding headers to ${sheetName}`);

      const response = await fetch(
        `${this.baseUrl}/${this.spreadsheetId}/values/${sheetName}!A1?key=${this.apiKey}`,
        {
          method: 'PUT',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            values: [headers],
            majorDimension: 'ROWS'
          })
        }
      );

      const result = await response.json();
      console.log('✅ Headers added:', result);
      return result;
    } catch (error) {
      console.error('❌ Error adding headers:', error);
      throw error;
    }
  }

  /**
   * EXPORT DATA (as CSV)
   */
  async exportDataAsCSV(sheetName) {
    try {
      const data = await this.getSheetData(sheetName);

      // Convert to CSV
      const csv = data
        .map(row => row.map(cell => `"${cell}"`).join(','))
        .join('\n');

      // Create download
      const blob = new Blob([csv], { type: 'text/csv' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${sheetName}-export-${new Date().toISOString().split('T')[0]}.csv`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);

      console.log('✅ Data exported as CSV');
    } catch (error) {
      console.error('❌ Error exporting data:', error);
      throw error;
    }
  }
}

/**
 * GLOBAL GOOGLE SHEETS INSTANCE
 */
let googleSheets = null;

/**
 * INITIALIZE GOOGLE SHEETS
 */
function initializeGoogleSheets() {
  if (!FORMS_CONFIG.googleSheets?.enabled) {
    console.log('ℹ️ Google Sheets integration is disabled');
    return;
  }

  googleSheets = new GoogleSheetsIntegration({
    spreadsheetId: FORMS_CONFIG.googleSheets.spreadsheetId,
    apiKey: FORMS_CONFIG.googleSheets.apiKey,
    sheets: FORMS_CONFIG.googleSheets.sheets
  });

  console.log('✅ Google Sheets integration initialized');
}

/**
 * SUBMIT FORM TO GOOGLE SHEETS
 */
async function submitFormToSheets(formType, formData) {
  if (!googleSheets) {
    console.warn('⚠️ Google Sheets not initialized');
    return false;
  }

  try {
    const sheetName = FORMS_CONFIG.googleSheets.sheets[formType] || 'Submissions';

    const dataWithMetadata = {
      ...formData,
      formType: formType,
      ip: await getClientIP(),
      userAgent: navigator.userAgent
    };

    const result = await googleSheets.addRowToSheet(sheetName, dataWithMetadata);

    console.log(`✅ Form submitted to ${sheetName}:`, result);
    return true;
  } catch (error) {
    console.error(`❌ Error submitting to Google Sheets:`, error);
    return false;
  }
}

/**
 * GET CLIENT IP ADDRESS
 */
async function getClientIP() {
  try {
    const response = await fetch('https://api.ipify.org?format=json');
    const data = await response.json();
    return data.ip;
  } catch (error) {
    return 'Unknown';
  }
}

/**
 * ENHANCED FORM SUBMISSION WITH SHEETS
 */
async function submitFormWithSheets(formElement, formType) {
  try {
    // Show loading state
    const submitBtn = formElement.querySelector('button[type="submit"]');
    const originalText = submitBtn.textContent;
    submitBtn.disabled = true;
    submitBtn.textContent = '⏳ Saving to database...';

    // Get form data
    const formData = new FormData(formElement);
    const data = Object.fromEntries(formData);

    // Submit to Google Sheets
    const sheetsSuccess = await submitFormToSheets(formType, data);

    if (sheetsSuccess) {
      // Also submit to backend if configured
      if (FORMS_CONFIG.api.baseUrl) {
        try {
          const endpoint = FORMS_CONFIG.api[formType + 'Form'] || '/contact-form';
          await fetch(FORMS_CONFIG.api.baseUrl + endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
          });
        } catch (error) {
          console.log('ℹ️ Backend submission skipped');
        }
      }

      // Show success
      submitBtn.textContent = '✅ Saved!';
      showSuccess(FORMS_CONFIG.messages[formType]?.success || 'Thank you! Your submission has been saved.');
      formElement.reset();

      // Reset button after 2 seconds
      setTimeout(() => {
        submitBtn.disabled = false;
        submitBtn.textContent = originalText;
      }, 2000);

      return true;
    } else {
      throw new Error('Failed to save to Google Sheets');
    }
  } catch (error) {
    console.error('❌ Form submission error:', error);
    showError('Error saving your submission. Please try again.');

    // Reset button
    const submitBtn = formElement.querySelector('button[type="submit"]');
    submitBtn.disabled = false;
    submitBtn.textContent = originalText;

    return false;
  }
}

/**
 * HELPER: Show success message
 */
function showSuccess(message) {
  const alert = document.createElement('div');
  alert.className = 'alert alert-success';
  alert.textContent = message;
  alert.style.cssText = `
    position: fixed;
    top: 20px;
    right: 20px;
    background: #27ae60;
    color: white;
    padding: 15px 20px;
    border-radius: 5px;
    z-index: 1000;
  `;
  document.body.appendChild(alert);
  setTimeout(() => alert.remove(), 5000);
}

/**
 * HELPER: Show error message
 */
function showError(message) {
  const alert = document.createElement('div');
  alert.className = 'alert alert-error';
  alert.textContent = message;
  alert.style.cssText = `
    position: fixed;
    top: 20px;
    right: 20px;
    background: #e74c3c;
    color: white;
    padding: 15px 20px;
    border-radius: 5px;
    z-index: 1000;
  `;
  document.body.appendChild(alert);
  setTimeout(() => alert.remove(), 5000);
}

/**
 * EXPORT
 */
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { GoogleSheetsIntegration, initializeGoogleSheets, submitFormToSheets };
}
