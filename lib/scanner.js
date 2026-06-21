/*!
 * Veilr QR Scanner
 * Uses the native BarcodeDetector API (Chrome/Edge/Android — no library needed).
 * Falls back to a clear "not supported, use manual entry" message on browsers
 * that don't implement it yet (notably Safari/iOS as of this writing), rather
 * than silently failing or loading a large external scanning library.
 */
(function (global) {
  'use strict';

  function isScannerSupported() {
    return ('BarcodeDetector' in window) && navigator.mediaDevices && navigator.mediaDevices.getUserMedia;
  }

  let _stream = null;
  let _detector = null;
  let _scanLoopId = null;

  /**
   * Start scanning using the given <video> element to show the camera feed.
   * Calls onResult(text) once a QR code is found, or onError(err) on failure.
   * Returns a stop() function to call when done (panel closed, etc.)
   */
  async function startScan(videoEl, onResult, onError) {
    if (!isScannerSupported()) {
      onError(new Error('UNSUPPORTED'));
      return function stop() {};
    }

    try {
      _detector = new window.BarcodeDetector({ formats: ['qr_code'] });
      _stream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: 'environment' }
      });
      videoEl.srcObject = _stream;
      await videoEl.play();

      let stopped = false;
      async function loop() {
        if (stopped) return;
        try {
          const codes = await _detector.detect(videoEl);
          if (codes && codes.length > 0) {
            stopped = true;
            onResult(codes[0].rawValue);
            stopStream();
            return;
          }
        } catch (e) {
          // detect() can throw transiently on some frames — keep scanning
        }
        _scanLoopId = requestAnimationFrame(loop);
      }
      loop();

      function stopStream() {
        if (_stream) {
          _stream.getTracks().forEach((t) => t.stop());
          _stream = null;
        }
        if (_scanLoopId) {
          cancelAnimationFrame(_scanLoopId);
          _scanLoopId = null;
        }
      }

      return function stop() {
        stopped = true;
        stopStream();
      };
    } catch (e) {
      // Most common real-world case: user denied camera permission
      onError(e);
      return function stop() {};
    }
  }

  global.VeilrScanner = { isScannerSupported, startScan };
})(typeof window !== 'undefined' ? window : globalThis);
