@tool
extends EditorPlugin

func _enable_plugin() -> void:
	add_autoload_singleton("Certael", "res://addons/certael/certael_client.gd")

func _disable_plugin() -> void:
	remove_autoload_singleton("Certael")
