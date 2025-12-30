package com.verifuse.rti

import android.Manifest
import android.media.MediaRecorder
import android.os.Build
import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageCapture
import androidx.camera.core.ImageCaptureException
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.core.content.ContextCompat
import com.google.android.gms.location.LocationServices
import java.io.File
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.UUID

class MainActivity : AppCompatActivity() {
    private lateinit var previewView: PreviewView
    private lateinit var stepLabel: TextView
    private lateinit var statusLabel: TextView
    private lateinit var captureButton: Button
    private lateinit var audioButton: Button
    private lateinit var nextButton: Button

    private var imageCapture: ImageCapture? = null
    private var mediaRecorder: MediaRecorder? = null
    private var isRecording = false

    private val bundleBuilder = BundleBuilder()
    private val steps = listOf(
        WizardStep("overview", "Step 1: Overview shot", required = true, allowMultiple = false),
        WizardStep("detail_damage", "Step 2: Damage close-ups (2-5)", required = true, allowMultiple = true),
        WizardStep("id_document", "Step 3: Driver’s license / plate / VIN", required = true, allowMultiple = false),
        WizardStep("witness_audio", "Step 4: Witness statement (audio)", required = false, allowMultiple = false, isAudio = true),
    )
    private var stepIndex = 0

    private val permissions = arrayOf(
        Manifest.permission.CAMERA,
        Manifest.permission.RECORD_AUDIO,
        Manifest.permission.ACCESS_FINE_LOCATION,
        Manifest.permission.ACCESS_COARSE_LOCATION,
    )

    private val permissionLauncher =
        registerForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { _ ->
            startCamera()
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        previewView = findViewById(R.id.previewView)
        stepLabel = findViewById(R.id.stepLabel)
        statusLabel = findViewById(R.id.status)
        captureButton = findViewById(R.id.captureButton)
        audioButton = findViewById(R.id.audioButton)
        nextButton = findViewById(R.id.nextButton)

        permissionLauncher.launch(permissions)

        captureButton.setOnClickListener { capturePhoto() }
        audioButton.setOnClickListener { toggleAudio() }
        nextButton.setOnClickListener { advanceStep() }

        updateStepUI()
        bundleBuilder.initSession()
    }

    private fun startCamera() {
        val cameraProviderFuture = ProcessCameraProvider.getInstance(this)
        cameraProviderFuture.addListener({
            val cameraProvider = cameraProviderFuture.get()
            val preview = Preview.Builder().build()
            preview.setSurfaceProvider(previewView.surfaceProvider)

            imageCapture = ImageCapture.Builder().build()
            val cameraSelector = CameraSelector.DEFAULT_BACK_CAMERA
            cameraProvider.unbindAll()
            cameraProvider.bindToLifecycle(this, cameraSelector, preview, imageCapture)
        }, ContextCompat.getMainExecutor(this))
    }

    private fun capturePhoto() {
        val step = steps[stepIndex]
        if (step.isAudio) {
            statusLabel.text = "Audio step: use Record Audio."
            return
        }
        val capture = imageCapture ?: return
        val outputDir = File(filesDir, "rti/${bundleBuilder.recordId}/media")
        outputDir.mkdirs()
        val fileName = "${step.role}_${System.currentTimeMillis()}.jpg"
        val file = File(outputDir, fileName)
        val outputOptions = ImageCapture.OutputFileOptions.Builder(file).build()
        capture.takePicture(
            outputOptions,
            ContextCompat.getMainExecutor(this),
            object : ImageCapture.OnImageSavedCallback {
                override fun onImageSaved(outputFileResults: ImageCapture.OutputFileResults) {
                    val timestamp = utcNow()
                    bundleBuilder.addCapture(
                        file = file,
                        role = step.role,
                        required = step.required,
                        mediaType = "image/jpeg",
                        captureKind = "photo",
                        captureSource = "camera_rear",
                        captureTimeUtc = timestamp,
                    )
                    statusLabel.text = "Captured ${file.name}"
                }

                override fun onError(exception: ImageCaptureException) {
                    statusLabel.text = "Capture failed: ${exception.message}"
                }
            },
        )
    }

    private fun toggleAudio() {
        val step = steps[stepIndex]
        if (!step.isAudio) {
            statusLabel.text = "Photo step: use Capture Photo."
            return
        }
        if (isRecording) {
            stopAudio()
        } else {
            startAudio()
        }
    }

    private fun startAudio() {
        val outputDir = File(filesDir, "rti/${bundleBuilder.recordId}/media")
        outputDir.mkdirs()
        val file = File(outputDir, "witness_audio_${System.currentTimeMillis()}.m4a")
        mediaRecorder = MediaRecorder().apply {
            setAudioSource(MediaRecorder.AudioSource.MIC)
            setOutputFormat(MediaRecorder.OutputFormat.MPEG_4)
            setAudioEncoder(MediaRecorder.AudioEncoder.AAC)
            setOutputFile(file.absolutePath)
            prepare()
            start()
        }
        isRecording = true
        audioButton.text = "Stop Audio"
        statusLabel.text = "Recording audio…"
    }

    private fun stopAudio() {
        val recorder = mediaRecorder ?: return
        recorder.stop()
        recorder.release()
        mediaRecorder = null
        isRecording = false
        audioButton.text = "Record Audio"
        val outputDir = File(filesDir, "rti/${bundleBuilder.recordId}/media")
        val audioFile = outputDir.listFiles()?.maxByOrNull { it.lastModified() }
        if (audioFile != null) {
            bundleBuilder.addCapture(
                file = audioFile,
                role = "witness_audio",
                required = false,
                mediaType = "audio/mp4",
                captureKind = "audio",
                captureSource = "microphone",
                captureTimeUtc = utcNow(),
            )
            statusLabel.text = "Audio saved: ${audioFile.name}"
        }
    }

    private fun advanceStep() {
        if (stepIndex < steps.size - 1) {
            stepIndex += 1
            updateStepUI()
            return
        }
        val locationClient = LocationServices.getFusedLocationProviderClient(this)
        locationClient.lastLocation.addOnSuccessListener { location ->
            bundleBuilder.finalizeBundle(
                filesDir,
                location?.latitude,
                location?.longitude,
            )
            statusLabel.text = "RTI pack created: ${bundleBuilder.recordId}"
        }
    }

    private fun updateStepUI() {
        val step = steps[stepIndex]
        stepLabel.text = step.label
        captureButton.text = if (step.isAudio) "Capture Photo" else "Capture Photo"
        audioButton.isEnabled = step.isAudio
        audioButton.alpha = if (step.isAudio) 1.0f else 0.4f
    }

    private fun utcNow(): String {
        return DateTimeFormatter.ISO_INSTANT.withZone(ZoneOffset.UTC).format(Instant.now())
    }
}

data class WizardStep(
    val role: String,
    val label: String,
    val required: Boolean,
    val allowMultiple: Boolean,
    val isAudio: Boolean = false,
)
