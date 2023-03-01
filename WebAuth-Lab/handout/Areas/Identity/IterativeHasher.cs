using System.Security.Cryptography;
using Microsoft.AspNetCore.Identity;

namespace App.Areas.Identity;

/// <summary>
/// Password hasher backed by iterative SHA256 hashing.
/// </summary>
/// <remarks>
/// For reference, consider the <see href="https://github.com/aspnet/AspNetIdentity/blob/main/src/Microsoft.AspNet.Identity.Core/PasswordHasher.cs">default implementation</see>
/// </remarks>
internal class IterativeHasher : IPasswordHasher<IdentityUser> {

    /// <summary>
    /// Hash a password using iterative SHA256 hashing.
    /// </summary>
    /// <param name="password">Password to hash.</param>
    /// <returns>String containing all the information needed to verify the password in the future.</returns>
    public string HashPassword(IdentityUser user, string password) {
        // todo: Use a random 32-byte salt. Use a 32-byte digest.
        byte[] salt = RandomNumberGenerator.GetBytes(32);
        byte[] passBytes = Utils.Encoding.GetBytes(password);
        byte[] digest = new byte[salt.Length + passBytes.Length];
        Buffer.BlockCopy(salt, 0, digest, 0, salt.Length);
        Buffer.BlockCopy(passBytes, 0, digest, salt.Length, passBytes.Length);
        SHA256 hash = SHA256.Create();
        // todo: Use 100,000 iterations and the SHA256 algorithm.
        for (int i = 0; i < 100000; i++) {
            digest = hash.ComputeHash(digest);
        }
        // todo: Encode as "Base64(salt):Base64(digest)"
        //Console.WriteLine(Utils.EncodeSaltAndDigest(salt, digest));
        return Utils.EncodeSaltAndDigest(salt, digest);
    }

    /// <summary>
    /// Verify that a password matches the hashed password.
    /// </summary>
    /// <param name="hashedPassword">Hashed password value stored when registering.</param>
    /// <param name="providedPassword">Password provided by user in login attempt.</param>
    /// <returns></returns>
    public PasswordVerificationResult VerifyHashedPassword(IdentityUser user, string hashedPassword, string providedPassword) {
        // todo: Verify that the given password matches the hashedPassword (as originally encoded by HashPassword)
        (byte[], byte[]) hashVals = Utils.DecodeSaltAndDigest(hashedPassword);
        SHA256 hash = SHA256.Create();
        byte[] passBytes = Utils.Encoding.GetBytes(providedPassword);
        byte[] digest = new byte[hashVals.Item1.Length + providedPassword.Length];
        Buffer.BlockCopy(hashVals.Item1, 0, digest, 0, hashVals.Item1.Length);
        Buffer.BlockCopy(passBytes, 0, digest, hashVals.Item1.Length, passBytes.Length);
        for (int i = 0; i < 100000; i++) {
            digest = hash.ComputeHash(digest);
        }
        if (digest.SequenceEqual(hashVals.Item2)) return PasswordVerificationResult.Success;
        return PasswordVerificationResult.Failed;
    }

}