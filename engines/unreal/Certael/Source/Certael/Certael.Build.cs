using UnrealBuildTool;
using System.IO;

public class Certael : ModuleRules
{
    public Certael(ReadOnlyTargetRules Target) : base(Target)
    {
        PCHUsage = PCHUsageMode.UseExplicitOrSharedPCHs;
        PublicDependencyModuleNames.AddRange(new[] { "Core", "CoreUObject", "Engine" });
        string Native = Path.GetFullPath(Path.Combine(ModuleDirectory, "..", "..", "Native"));
        PublicIncludePaths.Add(Path.Combine(Native, "include"));
        if (Target.Platform == UnrealTargetPlatform.Win64)
        {
            PublicAdditionalLibraries.Add(Path.Combine(Native, "Win64", "certael_c_api.lib"));
            RuntimeDependencies.Add("$(PluginDir)/Binaries/Win64/certael_c_api.dll");
        }
        else if (Target.Platform == UnrealTargetPlatform.Linux)
        {
            PublicAdditionalLibraries.Add(Path.Combine(Native, "Linux", "libcertael_c_api.a"));
        }
        else
        {
            throw new BuildException("Certael supports Win64 and Linux targets in this release.");
        }
    }
}
