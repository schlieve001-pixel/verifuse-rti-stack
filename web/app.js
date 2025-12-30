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

const canonicalize = (value) => JSON.stringify(sortObject(value));

const parseJsonFile = async (file) => {
  const text = await file.text();
  return JSON.parse(text);
};

const schemaByLayer = {
  rti0: {
    type: "object",
    required: ["rti0_id", "time_utc", "policy_id"],
    properties: {
      rti0_id: { type: "string" },
      time_utc: { type: "string" },
      policy_id: { type: "string" },
    },
  },
  rti1: {
    type: "object",
    required: ["files"],
    properties: {
      files: {
        type: "array",
        items: {
          type: "object",
          required: ["file_id", "capture_time_utc", "hash_algo", "hash_value"],
          properties: {
            file_id: { type: "string" },
            capture_time_utc: { type: "string" },
            hash_algo: { type: "string" },
            hash_value: { type: "string" },
          },
        },
      },
    },
  },
  rti2: {
    type: "object",
    required: ["set"],
    properties: {
      set: {
        type: "object",
        required: ["set_id", "rti0_id", "policy_id", "files"],
        properties: {
          set_id: { type: "string" },
          rti0_id: { type: "string" },
          policy_id: { type: "string" },
          files: {
            type: "array",
            items: {
              type: "object",
              required: ["file_id", "role", "required"],
              properties: {
                file_id: { type: "string" },
                role: { type: "string" },
                required: { type: "boolean" },
              },
            },
          },
        },
      },
    },
  },
  rti3: {
    type: "object",
    required: ["actor"],
    properties: {
      actor: {
        type: "object",
        required: ["actor_id", "rti0_id"],
        properties: {
          actor_id: { type: "string" },
          rti0_id: { type: "string" },
        },
      },
    },
  },
  rti4: {
    type: "object",
    required: ["checks", "transcript"],
    properties: {
      checks: {
        type: "object",
        required: ["time", "policy"],
        properties: {
          time: {
            type: "object",
            required: ["max_skew_seconds"],
            properties: {
              max_skew_seconds: { type: "number" },
            },
          },
          policy: {
            type: "object",
            required: ["policy_id"],
            properties: {
              policy_id: { type: "string" },
            },
          },
        },
      },
      transcript: {
        type: "array",
        items: {
          type: "object",
          required: ["step_id", "ts_utc", "kind", "result"],
          properties: {
            step_id: { type: "string" },
            ts_utc: { type: "string" },
            kind: { type: "string" },
            result: { type: "string" },
            actor_ref: { type: "string" },
            file_ref: { type: "string" },
          },
        },
      },
    },
  },
  rti6: {
    type: "object",
    required: ["certificate"],
    properties: {
      certificate: {
        type: "object",
        required: ["record_id"],
        properties: {
          record_id: { type: "string" },
          record_hash: { type: "string" },
          integrity: {
            type: "object",
            properties: {
              record_hash: { type: "string" },
            },
          },
        },
      },
    },
  },
};

const isValidType = (value, expected) => {
  if (expected === "object") {
    return value && typeof value === "object" && !Array.isArray(value);
  }
  if (expected === "array") {
    return Array.isArray(value);
  }
  if (expected === "string") {
    return typeof value === "string";
  }
  if (expected === "boolean") {
    return typeof value === "boolean";
  }
  if (expected === "number") {
    return typeof value === "number";
  }
  return true;
};

const pushSchemaIssue = (issues, layer, path, message) => {
  issues.push({
    code: "SCHEMA_ERROR",
    severity: "critical",
    layer,
    details: `schema violation at ${path}: ${message}`,
  });
};

const validateSchemaValue = (value, schema, path, layer, issues) => {
  const schemaType = schema.type;
  if (schemaType && !isValidType(value, schemaType)) {
    pushSchemaIssue(
      issues,
      layer,
      path,
      `expected ${schemaType} but found ${Array.isArray(value) ? "array" : typeof value}`
    );
    return;
  }
  if (schemaType === "object") {
    const required = schema.required || [];
    const properties = schema.properties || {};
    required.forEach((prop) => {
      if (!(prop in value)) {
        pushSchemaIssue(issues, layer, `${path}/${prop}`, "missing required field");
      }
    });
    Object.entries(properties).forEach(([prop, subschema]) => {
      if (prop in value) {
        validateSchemaValue(value[prop], subschema, `${path}/${prop}`, layer, issues);
      }
    });
  }
  if (schemaType === "array" && schema.items) {
    value.forEach((item, index) => {
      validateSchemaValue(item, schema.items, `${path}/${index}`, layer, issues);
    });
  }
};

const validateBundleSchema = (bundle, certificate) => {
  const issues = [];
  ["rti0", "rti1", "rti2", "rti3", "rti4"].forEach((layer) => {
    if (!bundle[layer]) {
      pushSchemaIssue(issues, layer, `/${layer}`, "missing required object");
      return;
    }
    validateSchemaValue(bundle[layer], schemaByLayer[layer], `/${layer}`, layer, issues);
  });
  if (certificate) {
    if (!certificate.rti6) {
      pushSchemaIssue(issues, "certificate", "/rti6", "missing required object");
    } else {
      validateSchemaValue(
        certificate.rti6,
        schemaByLayer.rti6,
        "/rti6",
        "certificate",
        issues
      );
    }
  }
  return issues;
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

  if (!bundle.record) {
    pushSchemaIssue(issues, "record", "/record", "missing required object");
  }
  issues.push(...validateBundleSchema(bundle, certificate));

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

if ("serviceWorker" in navigator) {
  window.addEventListener("load", () => {
    navigator.serviceWorker.register("./sw.js");
  });
}
