namespace Medo;

/// <summary>
/// Algorithm for generating one time password.
/// </summary>
public enum OneTimePasswordAlgorithm {
    /// <summary>
    /// SHA-1.
    /// </summary>
    Sha1 = 0,
    /// <summary>
    /// SHA-256.
    /// </summary>
    Sha256 = 1,
    /// <summary>
    /// SHA-512.
    /// </summary>
    Sha512 = 2,
}
