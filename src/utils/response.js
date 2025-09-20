function jsonResponse(ok, data = {}, errorCode = null) {
  if (ok) return { ok: true, data };
  return { ok: false, error: { code: errorCode || 'ERROR', message: data } };
}

module.exports = { jsonResponse };
