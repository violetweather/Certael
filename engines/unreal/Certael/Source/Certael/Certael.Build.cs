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
            PublicAdditionalLibraries.Add(Path.Combine(Native, "Win64", "certael_agent_probe.lib"));
            PublicDelayLoadDLLs.Add("certael_c_api.dll");
            PublicDelayLoadDLLs.Add("certael_agent_probe.dll");
            RuntimeDependencies.Add("$(PluginDir)/Binaries/Win64/certael_c_api.dll");
            RuntimeDependencies.Add("$(PluginDir)/Binaries/Win64/certael_agent_probe.dll");
        }
        else if (Target.Platform == UnrealTargetPlatform.Linux)
        {
            PublicAdditionalLibraries.Add(Path.Combine(Native, "Linux", "libcertael_c_api.a"));
            PublicAdditionalLibraries.Add(Path.Combine(Native, "Linux", "libcertael_agent_probe.a"));
        }
        else if (Target.Platform == UnrealTargetPlatform.Mac)
        {
            string Architecture = Target.Architecture.ToString().ToLowerInvariant();
            string Folder = Architecture.Contains("arm64") ? "arm64" : "x86_64";
            PublicAdditionalLibraries.Add(Path.Combine(Native, "Mac", Folder, "libcertael_c_api.a"));
            PublicAdditionalLibraries.Add(Path.Combine(Native, "Mac", Folder, "libcertael_agent_probe.a"));
        }
        else
        {
            throw new BuildException("Certael supports Win64, Linux, and macOS targets in this release.");
        }
    }
}
