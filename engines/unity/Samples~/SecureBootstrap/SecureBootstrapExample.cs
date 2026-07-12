using Certael.Unity;
using UnityEngine;

public sealed class SecureBootstrapExample : MonoBehaviour
{
    private CertaelClient _client;

    private void Awake()
    {
        _client = new CertaelClient();
        byte[] publicKey = _client.CreateSessionPublicKey();
        Debug.Log($"Send this {publicKey.Length}-byte key over the authenticated game connection.");
    }

    private void OnDestroy() => _client?.Dispose();
}
