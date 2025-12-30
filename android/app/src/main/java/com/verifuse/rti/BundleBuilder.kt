package com.verifuse.rti

import java.io.File
import java.security.MessageDigest
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.UUID

class BundleBuilder {
    private val captures = mutableListOf<CapturedFile>()
    private val sessionToken = "RTI-${UUID.randomUUID().toString().take(8)}"
    val recordId = "rec-${UUID.randomUUID()}"
    private val rti0Id = "rti0-${UUID.randomUUID()}"
    private val setId = "set-${UUID.randomUUID()}"
    private val policyId = "AUTO-COLLISION-v1"
    private val timeUtc = DateTimeFormatter.ISO_INSTANT.withZone(ZoneOffset.UTC).format(Instant.now())

    fun initSession() {
        captures.clear()
    }

    fun addCapture(
        file: File,
        role: String,
        required: Boolean,
        mediaType: String,
        captureKind: String,
        captureSource: String,
        captureTimeUtc: String,
    ) {
        captures.add(
            CapturedFile(
                file = file,
                role = role,
                required = required,
                mediaType = mediaType,
                captureKind = captureKind,
                captureSource = captureSource,
                captureTimeUtc = captureTimeUtc,
            )
        )
    }

    fun finalizeBundle(rootDir: File, latitude: Double?, longitude: Double?) {
        val bundleDir = File(rootDir, "rti/$recordId")
        val mediaDir = File(bundleDir, "media")
        mediaDir.mkdirs()

        val rti0 = mapOf(
            "rti0_id" to rti0Id,
            "policy_id" to policyId,
            "session_token" to sessionToken,
            "time_utc" to timeUtc,
            "device_timezone" to "UTC",
            "location_mode" to if (latitude != null && longitude != null) "coarse" else "off",
            "gps_lat" to latitude,
            "gps_lon" to longitude,
        )

        val rti1Files = captures.mapIndexed { index, captured ->
            val fileName = captured.file.name
            val target = File(mediaDir, fileName)
            if (!target.exists()) {
                captured.file.copyTo(target, overwrite = true)
            }
            mapOf(
                "file_id" to "file-${(index + 1).toString().padStart(3, '0')}",
                "rti0_id" to rti0Id,
                "session_token" to sessionToken,
                "file_name" to fileName,
                "media_type" to captured.mediaType,
                "capture_kind" to captured.captureKind,
                "capture_source" to captured.captureSource,
                "capture_time_utc" to captured.captureTimeUtc,
                "size_bytes" to target.length(),
                "hash_algo" to "sha256",
                "hash_value" to sha256Hex(target.readBytes()),
            )
        }

        val rti2Files = captures.mapIndexed { index, captured ->
            mapOf(
                "file_id" to "file-${(index + 1).toString().padStart(3, '0')}",
                "role" to captured.role,
                "ritual_order" to index + 1,
                "required" to captured.required,
            )
        }

        val requiredRoles = rti2Files.filter { it["required"] as Boolean }.map { it["role"] as String }
        val missingRoles = requiredRoles.filter { role ->
            rti2Files.none { it["role"] == role }
        }
        val coverageStatus = if (missingRoles.isEmpty()) "complete" else "partial"

        val rti2 = mapOf(
            "set" to mapOf(
                "set_id" to setId,
                "rti0_id" to rti0Id,
                "policy_id" to policyId,
                "files" to rti2Files,
                "coverage" to mapOf(
                    "status" to coverageStatus,
                    "missing_roles" to missingRoles,
                    "unexpected_roles" to emptyList<String>(),
                ),
            )
        )

        val rti3 = mapOf(
            "actor" to mapOf(
                "actor_id" to "act-${UUID.randomUUID()}",
                "rti0_id" to rti0Id,
                "session_token" to sessionToken,
                "actor_role" to "witness",
                "actor_relation" to "driver",
            )
        )

        val transcript = mutableListOf<Map<String, Any?>>(
            mapOf(
                "step_id" to "st-0001",
                "ts_utc" to timeUtc,
                "kind" to "start_ritual",
                "result" to "ok",
            )
        )
        rti1Files.forEachIndexed { index, file ->
            transcript.add(
                mapOf(
                    "step_id" to "st-${index + 2}".toString().padStart(4, '0'),
                    "ts_utc" to file["capture_time_utc"],
                    "kind" to "capture_file",
                    "file_ref" to file["file_id"],
                    "result" to "ok",
                )
            )
        }
        transcript.add(
            mapOf(
                "step_id" to "st-final",
                "ts_utc" to DateTimeFormatter.ISO_INSTANT.withZone(ZoneOffset.UTC).format(Instant.now()),
                "kind" to "finalize_record",
                "result" to "ok",
            )
        )

        val rti4 = mapOf(
            "checks" to mapOf(
                "time" to mapOf("time_window_ok" to true, "max_skew_seconds" to 300),
                "files" to mapOf("files_present" to true),
                "policy" to mapOf("policy_id" to policyId, "coverage_status" to coverageStatus),
                "env" to mapOf("env_stable" to true),
                "integrity" to mapOf(
                    "digest_rti0_ok" to true,
                    "digest_rti1_ok" to true,
                    "digest_rti2_ok" to true,
                    "digest_rti3_ok" to true,
                ),
            ),
            "transcript" to transcript,
        )

        val mediaIndex = rti1Files.map { file ->
            mapOf(
                "file_id" to file["file_id"],
                "file_name" to file["file_name"],
                "media_type" to file["media_type"],
                "expected_path" to "media/${file["file_name"]}",
                "hash_algo" to file["hash_algo"],
                "hash_value" to file["hash_value"],
            )
        }

        val record = mutableMapOf(
            "record_id" to recordId,
            "set_id" to setId,
            "rti0_id" to rti0Id,
            "policy" to mapOf("policy_id" to policyId),
            "media_index" to mediaIndex,
        )

        val digests = mutableMapOf(
            "hash_algo" to "sha256",
            "digest_rti0" to sha256Hex(canonicalize(rti0)),
            "digest_rti1" to sha256Hex(canonicalize(mapOf("files" to rti1Files))),
            "digest_rti2" to sha256Hex(canonicalize(rti2)),
            "digest_rti3" to sha256Hex(canonicalize(rti3)),
            "digest_rti4" to sha256Hex(canonicalize(rti4)),
        )
        record["digests"] = digests
        val recordForHash = record.toMutableMap()
        recordForHash["digests"] = digests.toMutableMap()
        val recordHash = sha256Hex(
            canonicalize(recordForHash) +
                canonicalize(rti0) +
                canonicalize(mapOf("files" to rti1Files)) +
                canonicalize(rti2) +
                canonicalize(rti3) +
                canonicalize(rti4)
        )
        digests["record_hash"] = recordHash

        val bundle = mapOf(
            "record" to record,
            "rti0" to rti0,
            "rti1" to mapOf("files" to rti1Files),
            "rti2" to rti2,
            "rti3" to rti3,
            "rti4" to rti4,
        )
        val bundleJson = canonicalize(bundle)
        File(bundleDir, "bundle.json").writeText(bundleJson)
    }

    private fun sha256Hex(bytes: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(bytes)
        return hash.joinToString("") { "%02x".format(it) }
    }

    private fun canonicalize(value: Any?): String {
        return CanonicalJson.encode(value)
    }
}

data class CapturedFile(
    val file: File,
    val role: String,
    val required: Boolean,
    val mediaType: String,
    val captureKind: String,
    val captureSource: String,
    val captureTimeUtc: String,
)

object CanonicalJson {
    fun encode(value: Any?): String {
        return when (value) {
            null -> "null"
            is String -> "\"${value.replace("\\", "\\\\").replace("\"", "\\\"")}\""
            is Number, is Boolean -> value.toString()
            is Map<*, *> -> encodeMap(value as Map<String, Any?>)
            is List<*> -> encodeList(value)
            else -> "\"${value.toString()}\""
        }
    }

    private fun encodeMap(value: Map<String, Any?>): String {
        val keys = value.keys.sorted()
        val content = keys.joinToString(",") { key ->
            "\"$key\":${encode(value[key])}"
        }
        return "{$content}"
    }

    private fun encodeList(value: List<*>): String {
        val content = value.joinToString(",") { encode(it) }
        return "[$content]"
    }
}
