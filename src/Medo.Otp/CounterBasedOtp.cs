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

}
