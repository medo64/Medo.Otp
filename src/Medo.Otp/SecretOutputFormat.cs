namespace Medo;

using System;

/// <summary>
/// Enumerates formatting option for secret.
/// </summary>
[Flags()]
public enum SecretOutputFormat {
    /// <summary>
    /// Secret will be returned as a minimal Base32 string.
    /// </summary>
    None = 0,
    /// <summary>
    /// Secret will have space every four characters.
    /// </summary>
    Spacing = 1,
    /// <summary>
    /// Secret will be properly padded to full Base32 length.
    /// </summary>
    Padding = 2,
    /// <summary>
    /// Secret will be returned in upper case characters.
    /// </summary>
    Uppercase = 4,
}
