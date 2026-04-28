/* Josip Medved <jmedved@jmedved.com> * www.medo64.com * MIT License */

namespace Medo;

using System;

/// <summary>
/// Implementation of counter-based one-time password algorithm as per HOTP (RFC 4226).
/// </summary>
public sealed class CounterBasedOtp : Otp {

    /// <summary>
    /// Creates a new instance using  a random key.
    /// </summary>
    public CounterBasedOtp()
        : base() {
    }

    /// <summary>
    /// Create new instance with predefined secret.
    /// </summary>
    /// <param name="secret">Secret. It should not be shorter than 128 bits (16 bytes). Minimum of 160 bits (20 bytes) is strongly recommended.</param>
    /// <exception cref="ArgumentNullException">Secret cannot be null.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Secret cannot be longer than 8192 bits (1024 bytes).</exception>
    public CounterBasedOtp(byte[] secret)
        : base(secret) {
    }

    /// <summary>
    /// Create new instance with predefined secret.
    /// </summary>
    /// <param name="base32Secret">Secret in Base32 encoding. It should not be shorter than 128 bits (16 bytes). Minimum of 160 bits (20 bytes) is strongly recommended.</param>
    /// <exception cref="ArgumentNullException">Secret cannot be null.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Secret is not a valid Base32 string. -or- Secret cannot be longer than 8192 bits (1024 bytes).</exception>
    public CounterBasedOtp(string base32Secret)
        : base(base32Secret) {
    }


    #region Setup

    private long _counter;
    /// <summary>
    /// Gets/sets counter value.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">Counter value must be a positive number.</exception>
    public override long Counter {
        get { return _counter; }
        set {
            if (value < 0) { throw new ArgumentOutOfRangeException(nameof(value), "Counter value must be a positive number."); }
            _counter = value;
        }
    }

    #endregion Setup


    #region Code

    /// <summary>
    /// Returns code based on the current counter.
    /// Counter will be automatically increased.
    /// </summary>
    public override int GetCode() {
        var code = CalculateCode(Counter);
        Counter += 1;
        return code;
    }

    #endregion Code


    #region Validate

    /// <summary>
    /// Returns true if code has been validated.
    /// Counter will increased if code is valid.
    /// </summary>
    /// <param name="code">Code to validate.</param>
    public override bool IsCodeValid(int code) {
        var currCode = CalculateCode(Counter);
        var prevCode = CalculateCode(Counter - 1);

        var isCurrValid = (code == currCode);
        var isPrevValid = (code == prevCode) && (Counter > 0); //don't check previous code if counter is zero; but calculate it anyhow (to keep timing)
        var isValid = isCurrValid || isPrevValid;
        if (isValid) { Counter++; }
        return isValid;
    }

    #endregion Validate

}
