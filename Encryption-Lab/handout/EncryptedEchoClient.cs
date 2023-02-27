using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.Logging;

/// <summary>
/// Provides a base class for implementing an Echo client.
/// </summary>
internal sealed class EncryptedEchoClient : EchoClientBase {
    RSA rsa = RSA.Create(2048);
    /// <summary>
    /// Logger to use in this class.
    /// </summary>
    private ILogger<EncryptedEchoClient> Logger { get; init; } =
        Settings.LoggerFactory.CreateLogger<EncryptedEchoClient>()!;

    /// <inheritdoc />
    public EncryptedEchoClient(ushort port, string address) : base(port, address) { }

    /// <inheritdoc />
    public override void ProcessServerHello(string message) {
        // todo: Step 1: Get the server's public key. Decode using Base64.
        // Throw a CryptographicException if the received key is invalid.
        var rsa_key = Convert.FromBase64String(message);
        rsa.ImportRSAPublicKey(rsa_key, out _);
    }

    /// <inheritdoc />
    public override string TransformOutgoingMessage(string input) {
        byte[] data = Settings.Encoding.GetBytes(input);

        // todo: Step 1: Encrypt the input using hybrid encryption.
        // Encrypt using AES with CBC mode and PKCS7 padding.
        // Use a different key each time.
        Aes aes = Aes.Create();
        byte[] aes_text = aes.EncryptCbc(data, aes.IV);

        // todo: Step 2: Generate an HMAC of the message.
        // Use the SHA256 variant of HMAC.
        // Use a different key each time.
        HMACSHA256 hmac = new HMACSHA256(data);
        byte[] hmac_hash = hmac.ComputeHash(data);

        // todo: Step 3: Encrypt the message encryption and HMAC keys using RSA.
        // Encrypt using the OAEP padding scheme with SHA256.
        byte[] aes_wrap = rsa.Encrypt(aes.Key, RSAEncryptionPadding.OaepSHA256);
        byte[] hmac_wrap = rsa.Encrypt(hmac.Key, RSAEncryptionPadding.OaepSHA256);

        // todo: Step 4: Put the data in an EncryptedMessage object and serialize to JSON.
        // Return that JSON.
        var message = new EncryptedMessage(aes_wrap, aes.IV, aes_text, hmac_wrap, hmac_hash);
        return JsonSerializer.Serialize(message);

        //return input;
    }

    /// <inheritdoc />
    public override string TransformIncomingMessage(string input) {
        // todo: Step 1: Deserialize the message.
        var signedMessage = JsonSerializer.Deserialize<SignedMessage>(input);

        // todo: Step 2: Check the messages signature.
        // Use PSS padding with SHA256.
        // Throw an InvalidSignatureException if the signature is bad.
        if (!(rsa.VerifyData(signedMessage.Message, signedMessage.Signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss))){
              throw new InvalidSignatureException("Invalid Signature -- Client\n");                      
        }

        // todo: Step 3: Return the message from the server.
        return Settings.Encoding.GetString(signedMessage.Message);
        //return input;
    }
}