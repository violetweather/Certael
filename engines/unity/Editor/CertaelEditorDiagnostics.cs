using System;
using UnityEditor;
using UnityEngine;

namespace Certael.Unity.Editor
{
internal static class CertaelEditorDiagnostics
{
    [MenuItem("Tools/Certael/Validate Installation")]
    private static void ValidateInstallation()
    {
        try
        {
            using var client = new CertaelClient();
            byte[] key = client.CreateSessionPublicKey();
            if (key.Length != 32) throw new InvalidOperationException("Native runtime returned an invalid public key.");
            Debug.Log("Certael installation is valid for the current Unity Editor platform.");
        }
        catch (Exception exception) when (exception is DllNotFoundException
            or BadImageFormatException or EntryPointNotFoundException or InvalidOperationException)
        {
            Debug.LogError($"Certael installation validation failed: {exception.Message}. "
                + "Install the verified package containing the native library for this Editor platform.");
        }
    }
}
}
