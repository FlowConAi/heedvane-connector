// The version the connector reports in every client-hello. Keep in sync with
// package.json; the gateway refuses below MIN_SUPPORTED_CONNECTOR_VERSION with a
// message naming both numbers, so this value is a support-window contract.
export const CONNECTOR_VERSION = "0.2.1";
