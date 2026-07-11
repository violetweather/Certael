#include "register_types.h"
#include "certael_native.h"
#include <gdextension_interface.h>
#include <godot_cpp/godot.hpp>

using namespace godot;

void initialize_certael_module(ModuleInitializationLevel level) {
    if (level == MODULE_INITIALIZATION_LEVEL_SCENE)
        ClassDB::register_class<CertaelNative>();
}

void uninitialize_certael_module(ModuleInitializationLevel) {}

extern "C" GDExtensionBool GDE_EXPORT certael_library_init(
    GDExtensionInterfaceGetProcAddress get_proc_address,
    const GDExtensionClassLibraryPtr library,
    GDExtensionInitialization* initialization) {
    GDExtensionBinding::InitObject init(get_proc_address, library, initialization);
    init.register_initializer(initialize_certael_module);
    init.register_terminator(uninitialize_certael_module);
    init.set_minimum_library_initialization_level(MODULE_INITIALIZATION_LEVEL_SCENE);
    return init.init();
}
