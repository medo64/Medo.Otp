/* Josip Medved <jmedved@jmedved.com> * www.medo64.com * MIT License */

namespace Medo;

using System;

/// <summary>
/// Implementation of time-based one-time password algorithm as per TOTP (RFC 6238).
/// </summary>
public sealed class TimeBasedOtp : Otp {

    /// <summary>
    /// Creates a new instance using  a random key.
    /// </summary>
    public TimeBasedOtp()
        : base() {
    }

    /// <summary>
    /// Create new instance with predefined secret.
    /// </summary>
    /// <param name="secret">Secret. It should not be shorter than 128 bits (16 bytes). Minimum of 160 bits (20 bytes) is strongly recommended.</param>
    /// <exception cref="ArgumentNullException">Secret cannot be null.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Secret cannot be longer than 8192 bits (1024 bytes).</exception>
    public TimeBasedOtp(byte[] secret)
        : base(secret) {
    }

    /// <summary>
    /// Create new instance with predefined secret.
    /// </summary>
    /// <param name="base32Secret">Secret in Base32 encoding. It should not be shorter than 128 bits (16 bytes). Minimum of 160 bits (20 bytes) is strongly recommended.</param>
    /// <exception cref="ArgumentNullException">Secret cannot be null.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Secret is not a valid Base32 string. -or- Secret cannot be longer than 8192 bits (1024 bytes).</exception>
    public TimeBasedOtp(string base32Secret)
        : base(base32Secret) {
    }


    /// <summary>
    /// Gets counter value.
    /// </summary>
    /// <exception cref="NotSupportedException">Counter value cannot be set for time-based OTP).</exception>
    public override long Counter {
        get {
            var seconds = Time.ToUnixTimeSeconds();
            return (seconds / TimeStep);
        }
        set {
            var seconds = value * TimeStep;
            Time = DateTimeOffset.FromUnixTimeSeconds(seconds);
        }
    }

    private int _timeStep = 30;
    /// <summary>
    /// Gets/sets time step in seconds for TOTP algorithm.
    /// Value must be between 15 and 300 seconds.
    /// If value is zero, time step won't be used and HOTP will be resulting protocol.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">Time step must be between 15 and 300 seconds.</exception>
    public int TimeStep {
        get { return _timeStep; }
        set {
            if (value == 0) {
                _timeStep = 0;
                Counter = 0;
            } else {
                if (value is < 15 or > 300) { throw new ArgumentOutOfRangeException(nameof(value), "Time step must be between 15 and 300 seconds."); }
                _timeStep = value;
            }
        }
    }

    private DateTimeOffset? _time;
    /// <summary>
    /// Gets/sets time value.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">Counter value must be a positive number.</exception>
    public DateTimeOffset Time {
        get { return _time ?? DateTimeOffset.UtcNow; }
        set { _time = value; }
    }


}
