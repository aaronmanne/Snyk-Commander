'use strict';

/**
 * electron/preload.js — Context bridge between Electron renderer and main process.
 *
 * Exposes window.snykAPI to the renderer:
 *   - invoke(method, params)  → Promise<result>
 *   - stream(method, params, streamChannel, onProgress)  → Promise<result>
 *   - removeListener(channel)  → void
 */

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('snykAPI', {
  /**
   * Send a single-shot IPC request to the Python backend.
   * @param {string} method  - Python method name, e.g. "auth.verify_token"
   * @param {object} params  - Request parameters
   * @returns {Promise<any>} - Resolves with the result or rejects with an Error
   */
  invoke: (method, params = {}) => {
    return ipcRenderer.invoke('snyk:invoke', { method, params });
  },

  /**
   * Send a streaming IPC request. Progress events are delivered via onProgress.
   * @param {string}   method        - Python method name, e.g. "scanner.scan"
   * @param {object}   params        - Request parameters
   * @param {string}   streamChannel - Unique IPC channel name for progress events
   * @param {function} onProgress    - Called with each {event, data} progress object
   * @returns {Promise<any>}         - Resolves with the final result
   */
  stream: (method, params = {}, streamChannel, onProgress) => {
    // Register the progress listener before invoking so we don't miss early events
    ipcRenderer.on(streamChannel, (_event, data) => {
      try {
        onProgress(data);
      } catch (err) {
        console.error('[preload] onProgress handler threw:', err);
      }
    });

    return ipcRenderer.invoke('snyk:stream', { method, params, streamChannel });
  },

  /**
   * Remove all IPC listeners for a channel (call after stream() resolves).
   * @param {string} channel
   */
  removeListener: (channel) => {
    ipcRenderer.removeAllListeners(channel);
  },

  /**
   * Convenience: generate a UUID for use as a streamChannel.
   * Avoids bundling crypto in the renderer.
   */
  newStreamChannel: () => {
    return `stream-${Date.now()}-${Math.random().toString(36).slice(2)}`;
  },

  /**
   * Open a native folder picker dialog.
   * @returns {Promise<string|null>} - Selected folder path or null if cancelled
   */
  openFolder: () => {
    return ipcRenderer.invoke('dialog:openFolder');
  },

  /**
   * Open a file or folder in the OS default app (Finder, Explorer, etc.)
   * @param {string} filePath
   */
  openPath: (filePath) => {
    return ipcRenderer.invoke('shell:openPath', filePath);
  },
});
