@tool
extends EditorPlugin

class CertaelExportPreflight extends EditorExportPlugin:
	func _get_name() -> String:
		return "CertaelExportPreflight"

	func _supports_platform(platform: EditorExportPlatform) -> bool:
		return platform.get_os_name() in ["Windows", "Linux", "macOS"]

	func _export_begin(features: PackedStringArray, is_debug: bool, _path: String, _flags: int) -> void:
		var binary := _binary_for(features, is_debug)
		if binary.is_empty():
			get_export_platform().add_message(EditorExportPlatform.EXPORT_MESSAGE_ERROR,
				"Certael", "Unsupported Certael export platform or architecture: %s" % [features])
		elif not FileAccess.file_exists(binary):
			get_export_platform().add_message(EditorExportPlatform.EXPORT_MESSAGE_ERROR,
				"Certael", "Required native library is missing: %s. Install the prebuilt Certael package for this target." % binary)
		var probe := _agent_probe_for(features)
		if probe.is_empty():
			return
		if not FileAccess.file_exists(probe):
			var severity := EditorExportPlatform.EXPORT_MESSAGE_ERROR if ProjectSettings.get_setting("certael/agent/required", false) else EditorExportPlatform.EXPORT_MESSAGE_WARNING
			get_export_platform().add_message(severity, "Certael Agent",
				"Agent probe is missing: %s. Reinstall the full package or disable certael/agent/required." % probe)
		else:
			# Native libraries must remain outside the PCK so the runtime loader can
			# open them. macOS places shared objects in the app's Frameworks folder.
			add_shared_object(probe, features, ".")

	func _binary_for(features: PackedStringArray, is_debug: bool) -> String:
		var configuration := "template_debug" if is_debug else "template_release"
		if "windows" in features and "x86_64" in features:
			return "res://addons/certael/bin/certael.windows.%s.x86_64.dll" % configuration
		if "linux" in features and "x86_64" in features:
			return "res://addons/certael/bin/libcertael.linux.%s.x86_64.so" % configuration
		if "macos" in features and "arm64" in features:
			return "res://addons/certael/bin/libcertael.macos.template_release.arm64.dylib"
		if "macos" in features and "x86_64" in features:
			return "res://addons/certael/bin/libcertael.macos.template_release.x86_64.dylib"
		return ""

	func _agent_probe_for(features: PackedStringArray) -> String:
		if "windows" in features:
			return "res://addons/certael/bin/certael_agent_probe.dll"
		if "linux" in features:
			return "res://addons/certael/bin/libcertael_agent_probe.so"
		if "macos" in features:
			if "arm64" in features:
				return "res://addons/certael/bin/libcertael_agent_probe.macos.arm64.dylib"
			if "x86_64" in features:
				return "res://addons/certael/bin/libcertael_agent_probe.macos.x86_64.dylib"
		return ""

var _export_preflight: CertaelExportPreflight

func _enter_tree() -> void:
	if not ProjectSettings.has_setting("certael/agent/required"):
		ProjectSettings.set_setting("certael/agent/required", false)
	ProjectSettings.set_initial_value("certael/agent/required", false)
	_export_preflight = CertaelExportPreflight.new()
	add_export_plugin(_export_preflight)

func _exit_tree() -> void:
	if _export_preflight != null:
		remove_export_plugin(_export_preflight)
		_export_preflight = null

func _enable_plugin() -> void:
	add_autoload_singleton("Certael", "res://addons/certael/certael_client.gd")

func _disable_plugin() -> void:
	remove_autoload_singleton("Certael")
