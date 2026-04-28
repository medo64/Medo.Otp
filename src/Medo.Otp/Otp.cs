/* Josip Medved <jmedved@jmedved.com> * www.medo64.com * MIT License */

namespace Medo;

using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

/// <summary>
/// Base for one-time password as per HOTP (RFC 4226) and TOTP (RFC 6238).
/// </summary>
public abstract class Otp : IDisposable {

    /// <summary>
    /// Creates a new instance of the OTP class.
    /// </summary>
    protected Otp() {
        SecretBuffer = GC.AllocateUninitializedArray<byte>(MaxSecretLength, pinned: true);
        SecretLength = DefaultSecretLength;
        RandomKey = GC.AllocateUninitializedArray<byte>(16, pinned: true);
        RandomIV = GC.AllocateUninitializedArray<byte>(16, pinned: true);

        Random.GetBytes(SecretBuffer);
        Random.GetBytes(RandomIV);
        Random.GetBytes(RandomKey);
    }

    /// <summary>
    /// Create new instance with predefined secret.
    /// </summary>
    /// <param name="secret">Secret. It should not be shorter than 128 bits (16 bytes). Minimum of 160 bits (20 bytes) is strongly recommended.</param>
    /// <exception cref="ArgumentNullException">Secret cannot be null.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Secret cannot be longer than 8192 bits (1024 bytes).</exception>
    protected Otp(byte[] secret)
        : this() {
        if (secret == null) { throw new ArgumentNullException(nameof(secret), "Secret cannot be null."); }
        if (secret.Length > MaxSecretLength) { throw new ArgumentOutOfRangeException(nameof(secret), "Secret cannot be longer than 8192 bits (1024 bytes)."); }

        Buffer.BlockCopy(secret, 0, SecretBuffer, 0, secret.Length);
        SecretLength = secret.Length;

        ProtectSecret();
    }

    /// <summary>
    /// Create new instance with predefined secret.
    /// </summary>
    /// <param name="base32Secret">Secret in Base32 encoding. It should not be shorter than 128 bits (16 bytes). Minimum of 160 bits (20 bytes) is strongly recommended.</param>
    /// <exception cref="ArgumentNullException">Secret cannot be null.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Secret is not a valid Base32 string. -or- Secret cannot be longer than 8192 bits (1024 bytes).</exception>
    protected Otp(string base32Secret)
        : this() {
        if (base32Secret == null) { throw new ArgumentNullException(nameof(base32Secret), "Secret cannot be null."); }

        try {
            FromBase32(base32Secret, SecretBuffer, out SecretLength);
        } catch (IndexOutOfRangeException) {
            throw new ArgumentOutOfRangeException(nameof(base32Secret), "Secret cannot be longer than 8192 bits (1024 bytes).");
        } catch (Exception) {
            throw new ArgumentOutOfRangeException(nameof(base32Secret), "Secret is not a valid Base32 string.");
        }

        ProtectSecret();
    }


    #region Setup

    private OneTimePasswordAlgorithm _algorithm = OneTimePasswordAlgorithm.Sha1;
    /// <summary>
    /// Gets/sets crypto algorithm.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">Unknown algorithm.</exception>
    public OneTimePasswordAlgorithm Algorithm {
        get { return _algorithm; }
        set {
            switch (value) {
                case OneTimePasswordAlgorithm.Sha1:
                case OneTimePasswordAlgorithm.Sha256:
                case OneTimePasswordAlgorithm.Sha512: break;
                default: throw new ArgumentOutOfRangeException(nameof(value), "Unknown algorithm.");
            }
            _algorithm = value;
            CachedCounter = -1;  // needs recalculation
        }
    }

    private int _digits = 6;
    /// <summary>
    /// Gets/Sets number of digits to return.
    /// Number of digits should be kept between 6 and 8 for best results.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">Number of digits to return must be between 4 and 9.</exception>
    public int Digits {
        get { return _digits; }
        set {
            if (value is < 4 or > 9) { throw new ArgumentOutOfRangeException(nameof(value), "Number of digits to return must be between 4 and 9."); }
            _digits = value;
            CachedCounter = -1;  // needs recalculation
        }
    }

    /// <summary>
    /// Gets/sets counter value.
    /// </summary>
    public abstract long Counter { get; set; }

    #endregion Setup


    #region Code

    /// <summary>
    /// Returns code.
    /// </summary>
    public abstract int GetCode();


    private long CachedCounter = -1;
    private int CachedCode;

    /// <summary>
    /// Gets code for given number of digits and counter.
    /// </summary>
    /// <param name="counter">Counter value.</param>
    protected int CalculateCode(long counter) {
        if (CachedCounter == counter) { return CachedCode; }  // to avoid recalculation if all is the same

        var counterBytes = BitConverter.GetBytes(counter);
        if (BitConverter.IsLittleEndian) { Array.Reverse(counterBytes, 0, 8); }

        byte[] hash;
        var secret = GetSecret();
        try {
            using HMAC hmac = Algorithm switch {
                OneTimePasswordAlgorithm.Sha1 => new HMACSHA1(secret),
                OneTimePasswordAlgorithm.Sha256 => new HMACSHA256(secret),
                OneTimePasswordAlgorithm.Sha512 => new HMACSHA512(secret),
                _ => new HMACSHA1(secret),
            };
            hash = hmac.ComputeHash(counterBytes);
        } finally {
            ClearSecret(secret);
        }

        var offset = hash[^1] & 0x0F;
        var truncatedHash = new byte[] { (byte)(hash[offset + 0] & 0x7F), hash[offset + 1], hash[offset + 2], hash[offset + 3] };
        if (BitConverter.IsLittleEndian) { Array.Reverse(truncatedHash, 0, 4); }
        var number = BitConverter.ToInt32(truncatedHash, 0);
        var code = number % DigitsDivisor[Digits - 4];

        CachedCounter = counter;
        CachedCode = code;

        return code;
    }

    private static readonly int[] DigitsDivisor = [10000, 100000, 1000000, 10000000, 100000000, 1000000000];

    #endregion Code


    #region Validate

    /// <summary>
    /// Returns true if code has been validated.
    /// </summary>
    /// <param name="code">Code to validate.</param>
    /// <exception cref="ArgumentOutOfRangeException">Code must contain only numbers and whitespace.</exception>
    /// <exception cref="ArgumentNullException">Code cannot be null.</exception>
    public bool IsCodeValid(string code) {
        if (code == null) { throw new ArgumentNullException(nameof(code), "Code cannot be null."); }
        var number = 0;
        foreach (var ch in code) {
            if (char.IsWhiteSpace(ch)) { continue; }
            if (!char.IsDigit(ch)) { throw new ArgumentOutOfRangeException(nameof(code), "Code must contain only numbers and whitespace."); }
            if (number >= 100000000) { return false; } //number cannot be more than 9 digits
            number *= 10;
            number += (ch - 0x30);
        }
        return IsCodeValid(number);
    }

    /// <summary>
    /// Returns true if code has been validated.
    /// </summary>
    /// <param name="code">Code to validate.</param>
    public abstract bool IsCodeValid(int code);

    #endregion Validate


    #region Secret buffer

    private static readonly RandomNumberGenerator Random = RandomNumberGenerator.Create();  // needed due to .NET Standard 2.0

    /// <summary>
    /// Returns secret in byte array.
    /// It is up to the caller to secure the given byte array.
    /// </summary>
    public byte[] GetSecret() {
        var buffer = GC.AllocateUninitializedArray<byte>(SecretLength, pinned: true);

        UnprotectSecret();
        try {
            Buffer.BlockCopy(SecretBuffer, 0, buffer, 0, buffer.Length);
        } finally {
            ProtectSecret();
        }

        return buffer;
    }

    /// <summary>
    /// Returns secret as a Base32 string.
    /// String will be shown in quads and without padding.
    /// It is up to the caller to secure given string.
    /// </summary>
    public string GetSecretAsText() {
        return GetSecretAsText(SecretOutputFormat.Spacing);
    }

    /// <summary>
    /// Returns secret as a Base32 string with custom formatting.
    /// It is up to the caller to secure given string.
    /// </summary>
    /// <param name="format">Format of Base32 string.</param>
    public string GetSecretAsText(SecretOutputFormat format) {
        UnprotectSecret();
        try {
            return ToBase32(SecretBuffer, SecretLength, format);
        } finally {
            ProtectSecret();
        }
    }


    private const int MaxSecretLength = 1024;  // must be multiple of 8 for AES
    private const int DefaultSecretLength = 20;
    private readonly byte[] SecretBuffer;
    private readonly int SecretLength;

    private readonly byte[] RandomIV;
    private readonly byte[] RandomKey;
    private readonly Lazy<Aes> _aesAlgorithm = new(delegate {
        var aes = Aes.Create();
        aes.Padding = PaddingMode.None;
        return aes;
    });

    private void ProtectSecret() {  // essentially obfuscation as ProtectedData is not really portable
        var aes = _aesAlgorithm.Value;

        using var encryptor = aes.CreateEncryptor(RandomKey, RandomIV);
        encryptor.TransformBlock(SecretBuffer, 0, SecretBuffer.Length, SecretBuffer, 0);
    }

    private void UnprotectSecret() {
        var aes = _aesAlgorithm.Value;

        using var decryptor = aes.CreateDecryptor(RandomKey, RandomIV);
        decryptor.TransformBlock(SecretBuffer, 0, SecretBuffer.Length, SecretBuffer, 0);
    }

    private static void ClearSecret(byte[] array) {
        for (var i = 0; i < array.Length; i++) {
            array[i] = 0;
        }
    }

    #endregion Secret buffer


    #region Base32

    private static readonly IList<char> Base32Alphabet = new List<char>("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567").AsReadOnly();
    private static readonly byte[] Base32Bitmask = new byte[] { 0x00, 0x01, 0x03, 0x07, 0x0F, 0x1F };

    private static void FromBase32(string text, byte[] buffer, out int length) {
        var index = 0;

        var bitPosition = 0;
        byte partialByte = 0;
        foreach (var ch in text) { //always assume padding - easier to code than actually checking
            if (char.IsWhiteSpace(ch)) { continue; } //ignore whitespaces
            if (ch == '=') { // finish up
                bitPosition = -1;
                continue;
            } else if (bitPosition == -1) { throw new FormatException("Character '" + ch + "' found after padding ."); }

            var bits = Base32Alphabet.IndexOf(char.ToUpperInvariant(ch));
            if (bits < 0) { throw new FormatException("Unknown character '" + ch + "'."); }

            var bitCount1 = (bitPosition < 3) ? 5 : 8 - bitPosition; //how many bits go in current partial byte
            var bitCount2 = 5 - bitCount1; //how many bits are for next byte

            partialByte <<= bitCount1;
            partialByte |= (byte)(bits >> (5 - bitCount1));
            bitPosition += bitCount1;

            if (bitPosition >= 8) {
                buffer[index] = partialByte;
                index++;
                bitPosition = bitCount2;
                partialByte = (byte)(bits & Base32Bitmask[bitCount2]);
            }
        }

        if (bitPosition is > (-1) and >= 5) {
            partialByte <<= (8 - bitPosition);
            buffer[index] = partialByte;
            index++;
        }

        length = index;
    }

    private static string ToBase32(byte[] bytes, int length, SecretOutputFormat format) {
        if (length == 0) { return string.Empty; }

        var hasSpacing = (format & SecretOutputFormat.Spacing) == SecretOutputFormat.Spacing;
        var hasPadding = (format & SecretOutputFormat.Padding) == SecretOutputFormat.Padding;
        var isUpper = (format & SecretOutputFormat.Uppercase) == SecretOutputFormat.Uppercase;

        var bitLength = (length * 8);
        var textLength = bitLength / 5 + ((bitLength % 5) == 0 ? 0 : 1);
        var totalLength = textLength;

        var padLength = (textLength % 8 == 0) ? 0 : 8 - textLength % 8;
        totalLength += (hasPadding ? padLength : 0);

        var spaceLength = totalLength / 4 + ((totalLength % 4 == 0) ? -1 : 0);
        totalLength += (hasSpacing ? spaceLength : 0);


        var chars = new char[totalLength];
        var index = 0;

        var bits = 0;
        var bitsRemaining = 0;
        for (var i = 0; i < length; i++) {
            bits = (bits << 8) | bytes[i];
            bitsRemaining += 8;
            while (bitsRemaining >= 5) {
                var bitsIndex = (bits >> (bitsRemaining - 5)) & 0x1F;
                bitsRemaining -= 5;
                chars[index] = isUpper ? Base32Alphabet[bitsIndex] : char.ToLowerInvariant(Base32Alphabet[bitsIndex]);
                index++;

                if (hasSpacing && (index < chars.Length) && (bitsRemaining % 4 == 0)) {
                    chars[index] = ' ';
                    index++;
                }
            }
        }
        if (bitsRemaining > 0) {
            var bitsIndex = (bits & Base32Bitmask[bitsRemaining]) << (5 - bitsRemaining);
            chars[index] = isUpper ? Base32Alphabet[bitsIndex] : char.ToLowerInvariant(Base32Alphabet[bitsIndex]);
            index++;
        }

        if (hasPadding) {
            for (var i = 0; i < padLength; i++) {
                if (hasSpacing && (i % 4 == padLength % 4)) {
                    chars[index] = ' ';
                    index++;
                }
                chars[index] = '=';
                index++;
            }
        }

        return new string(chars);
    }

    #endregion Base32


    #region IDispose

    private bool DisposedValue;

    /// <summary>
    /// Disposes the object and clears the secret from memory.
    /// </summary>
    /// <param name="disposing">If true, managed elements should be disposed too.</param>
    protected virtual void Dispose(bool disposing) {
        if (!DisposedValue) {
            ClearSecret(SecretBuffer);  // not unmanaged resource, but we want to get rid of data as soon as possible

            if (disposing) {
                ClearSecret(RandomKey);
                ClearSecret(RandomIV);
                if (_aesAlgorithm.IsValueCreated) { _aesAlgorithm.Value.Dispose(); }
            }

            DisposedValue = true;
        }
    }

    /// <summary>
    /// Disposes the object and clears the secret from memory.
    /// </summary>
    public void Dispose() {
        Dispose(disposing: true);
        GC.SuppressFinalize(this);
    }

    #endregion IDispose

}
