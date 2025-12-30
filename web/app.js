const bundleInput = document.getElementById("bundle-input");
const mediaInput = document.getElementById("media-input");
const certificateInput = document.getElementById("certificate-input");
const verifyBtn = document.getElementById("verify-btn");
const resultEl = document.getElementById("result");
const statusEl = document.getElementById("status");
const downloadBtn = document.getElementById("download-btn");

const toHex = (buffer) =>
  [...new Uint8Array(buffer)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

const sha256 = async (data) => {
  const digest = await crypto.subtle.digest("SHA-256", data);
  return toHex(digest);
};

const sortObject = (value) => {
  if (Array.isArray(value)) {
    return value.map(sortObject);
  }
  if (value && typeof value === "object") {
    return Object.keys(value)
      .sort()
      .reduce((acc, key) => {
        acc[key] = sortObject(value[key]);
        return acc;
      }, {});
  }
  return value;
};

const canonicalize = (value) =>
  JSON.stringify(sortObject(value), Object.keys(sortObject(value)), 0);

const parseJsonFile = async (file) => {
  const text = await file.text();
  return JSON.parse(text);
};

const collectMediaMap = async (files) => {
  const map = new Map();
  for (const file of files) {
    const buffer = await file.arrayBuffer();
    map.set(file.name, {
      file,
      hash: await sha256(buffer),
      size: file.size,
    });
  }
  return map;
};

const verifyBundle = async (bundle, mediaMap, certificate) => {
  const issues = [];
  const record = bundle.record || {};
  const digests = record.digests || {};

  const requireKeys = ["record", "rti0", "rti1", "rti2", "rti3", "rti4"];
  requireKeys.forEach((key) => {
    if (!bundle[key]) {
      issues.push({
        code: "SCHEMA_ERROR",
        severity: "critical",
        layer: "schema",
        details: `missing top-level key: ${key}`,
      });
    }
  });

  if (issues.length) {
    return buildResult(record.record_id || "unknown", issues);
  }

  const digestLayers = {
    rti0: "digest_rti0",
    rti1: "digest_rti1",
    rti2: "digest_rti2",
    rti3: "digest_rti3",
    rti4: "digest_rti4",
  };
  for (const [layer, digestKey] of Object.entries(digestLayers)) {
    const expected = digests[digestKey];
    const computed = await sha256(
      new TextEncoder().encode(canonicalize(bundle[layer]))
    );
    if (!expected || computed !== expected) {
      issues.push({
        code: `DIGEST_MISMATCH_${layer.toUpperCase()}`,
        severity: "critical",
        layer,
        details: `expected ${expected || "missing"} but computed ${computed}`,
      });
    }
  }

  const recordCopy = JSON.parse(JSON.stringify(record));
  if (recordCopy.digests) {
    delete recordCopy.digests.record_hash;
  }
  const recordPayload = [
    canonicalize(recordCopy),
    canonicalize(bundle.rti0),
    canonicalize(bundle.rti1),
    canonicalize(bundle.rti2),
    canonicalize(bundle.rti3),
    canonicalize(bundle.rti4),
  ].join("");
  const recordHash = await sha256(new TextEncoder().encode(recordPayload));
  if (digests.record_hash && recordHash !== digests.record_hash) {
    issues.push({
      code: "RECORD_HASH_MISMATCH",
      severity: "critical",
      layer: "record",
      details: `expected ${digests.record_hash} but computed ${recordHash}`,
    });
  }

  const rti2Required = new Map();
  (bundle.rti2?.set?.files || []).forEach((item) => {
    if (item.file_id) {
      rti2Required.set(item.file_id, item.required !== false);
    }
  });

  for (const entry of record.media_index || []) {
    const expectedPath = entry.expected_path || "";
    const basename = expectedPath.split("/").pop();
    const media = mediaMap.get(basename);
    const required = rti2Required.get(entry.file_id) ?? true;

    if (!media) {
      issues.push({
        code: required ? "MISSING_CRITICAL_MEDIA" : "MISSING_OPTIONAL_MEDIA",
        severity: required ? "critical" : "warning",
        layer: "media",
        details: `missing file ${expectedPath}`,
        related_ids: [entry.file_id],
      });
      continue;
    }
    if (entry.hash_value && entry.hash_value !== media.hash) {
      issues.push({
        code: "MEDIA_HASH_MISMATCH",
        severity: "critical",
        layer: "media",
        details: `hash mismatch for ${expectedPath}`,
        related_ids: [entry.file_id],
      });
    }
  }

  if (certificate?.rti6?.certificate) {
    const certHash =
      certificate.rti6.certificate.integrity?.record_hash ||
      certificate.rti6.certificate.record_hash;
    if (certHash && digests.record_hash && certHash !== digests.record_hash) {
      issues.push({
        code: "CERTIFICATE_MISMATCH",
        severity: "warning",
        layer: "certificate",
        details: "certificate record_hash does not match bundle",
      });
    }
  }

  return buildResult(record.record_id || "unknown", issues);
};

const buildResult = (recordId, issues) => {
  let decision = "valid";
  const layerResults = {
    rti0: "ok",
    rti1: "ok",
    rti2: "ok",
    rti3: "ok",
    rti4: "ok",
    record: "ok",
    media: "ok",
    certificate: "not_provided",
  };
  issues.forEach((issue) => {
    if (layerResults[issue.layer]) {
      layerResults[issue.layer] =
        issue.severity === "critical" ? "invalid" : "suspect";
    }
    if (issue.severity === "critical") {
      decision = "invalid";
    }
  });
  if (decision !== "invalid" && issues.length) {
    decision = "suspect";
  }
  return {
    record_id: recordId,
    decision,
    layer_results: layerResults,
    issues,
  };
};

const updateStatus = (message) => {
  statusEl.textContent = message;
};

verifyBtn.addEventListener("click", async () => {
  if (!bundleInput.files.length) {
    updateStatus("Select bundle.json first.");
    return;
  }

  updateStatus("Verifying…");
  resultEl.textContent = "";
  downloadBtn.disabled = true;

  const bundle = await parseJsonFile(bundleInput.files[0]);
  const mediaMap = await collectMediaMap(mediaInput.files);
  const certificate = certificateInput.files.length
    ? await parseJsonFile(certificateInput.files[0])
    : null;
  const result = await verifyBundle(bundle, mediaMap, certificate);
  resultEl.textContent = JSON.stringify(result, null, 2);
  updateStatus(`Decision: ${result.decision.toUpperCase()}`);
  downloadBtn.disabled = false;

  downloadBtn.onclick = () => {
    const blob = new Blob([JSON.stringify(result, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "verification.json";
    link.click();
    URL.revokeObjectURL(url);
  };
});
