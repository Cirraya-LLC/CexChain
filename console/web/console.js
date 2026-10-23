// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The console's page. Ledger data is only ever written through textContent.
const status = document.getElementById("status");
if (status) {
    status.dataset.ready = "true";
}
