function doPost(e) {
  try {
    if (!e || !e.postData || !e.postData.contents) {
      return jsonResponse({ ok: false, error: 'Missing request body' }, 400);
    }

    var payload = JSON.parse(e.postData.contents);
    if (!payload.to || !payload.subject || !payload.html) {
      return jsonResponse({ ok: false, error: 'Missing to, subject, or html' }, 400);
    }

    GmailApp.sendEmail(payload.to, payload.subject, payload.text || 'New KizunaShield scan request', {
      htmlBody: payload.html,
      name: 'KizunaShield'
    });

    return jsonResponse({ ok: true }, 200);
  } catch (error) {
    return jsonResponse({ ok: false, error: String(error) }, 500);
  }
}

function jsonResponse(body, statusCode) {
  // Apps Script ContentService does not allow custom HTTP status codes;
  // the JSON ok flag is used by the caller for reliable success detection.
  return ContentService
    .createTextOutput(JSON.stringify(body))
    .setMimeType(ContentService.MimeType.JSON);
}
