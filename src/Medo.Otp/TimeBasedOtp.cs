/* Josip Medved <jmedved@jmedved.com> * www.medo64.com * MIT License */

namespace Medo;

using System;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading;

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


    #region Setup

    /// <summary>
    /// Gets counter value.
    /// </summary>
    /// <exception cref="NotSupportedException">Counter value cannot be set for time-based OTP).</exception>
    public override long Counter {
        get { return GetTimeBasedCounter(DateTime.UtcNow, TimeStep); }
        set { throw new NotSupportedException("Counter value cannot be set for time-based OTP)."); }
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

    #endregion Setup


    #region Code

    /// <summary>
    /// Returns code based on the current time.
    /// </summary>
    public override int GetCode() {
        return CalculateCode(Counter);
    }

    /// <summary>
    /// Returns code.
    /// Number of digits should be kept between 6 and 8 for best results.
    /// </summary>
    /// <param name="time">UTC or Local time for code retrieval.</param>
    /// <exception cref="ArgumentOutOfRangeException">Time must be either UTC or Local.</exception>
    /// <exception cref="NotSupportedException">Cannot specify time in HOTP mode (time step is zero).</exception>
    public int GetCode(DateTime time) {
        if (time.Kind is not DateTimeKind.Utc and not DateTimeKind.Local) { throw new ArgumentOutOfRangeException(nameof(time), "Time must be either UTC or Local."); }
        return GetCode(new DateTimeOffset(time));
    }

    /// <summary>
    /// Returns code.
    /// Number of digits should be kept between 6 and 8 for best results.
    /// </summary>
    /// <param name="time">UTC time for code retrieval.</param>
    /// <exception cref="NotSupportedException">Cannot specify time in HOTP mode (time step is zero).</exception>
    public int GetCode(DateTimeOffset time) {
        if (TimeStep == 0) { throw new NotSupportedException("Cannot specify time in HOTP mode (time step is zero)."); }
        return CalculateCode(GetTimeBasedCounter(time, TimeStep));
    }

    private static long GetTimeBasedCounter(DateTimeOffset time, int timeStep) {
        var seconds = time.ToUnixTimeSeconds();
        return (seconds / timeStep);
    }

    #endregion Code


    #region Validate

    /// <summary>
    /// Returns true if code has been validated.
    /// </summary>
    /// <param name="code">Code to validate.</param>
    public override bool IsCodeValid(int code) {
        var currCode = CalculateCode(Counter);
        var prevCode = CalculateCode(Counter - 1);

        var isCurrValid = (code == currCode);
        var isPrevValid = (code == prevCode) && (Counter > 0); //don't check previous code if counter is zero; but calculate it anyhow (to keep rough timing)
        return isCurrValid || isPrevValid;
    }

    /// <summary>
    /// Returns true if code has been validated.
    /// </summary>
    /// <param name="code">Code to validate.</param>
    /// <param name="time">UTC time.</param>
    /// <exception cref="ArgumentOutOfRangeException">Time must be either UTC or Local.</exception>
    /// <exception cref="NotSupportedException">Cannot specify time in HOTP mode (time step is zero).</exception>
    public bool IsCodeValid(int code, DateTime time) {
        if (time.Kind is not DateTimeKind.Utc and not DateTimeKind.Local) { throw new ArgumentOutOfRangeException(nameof(time), "Time must be either UTC or Local."); }
        return IsCodeValid(code, new DateTimeOffset(time));
    }

    /// <summary>
    /// Returns true if code has been validated.
    /// </summary>
    /// <param name="code">Code to validate.</param>
    /// <param name="time">UTC time.</param>
    /// <exception cref="NotSupportedException">Cannot specify time in HOTP mode (time step is zero).</exception>
    public bool IsCodeValid(int code, DateTimeOffset time) {
        if (TimeStep == 0) { throw new NotSupportedException("Cannot specify time in HOTP mode (time step is zero)."); }

        var counter = GetTimeBasedCounter(time, TimeStep);
        var currCode = CalculateCode(counter);
        var prevCode = CalculateCode(counter - 1);

        var isCurrValid = (code == currCode);
        var isPrevValid = (code == prevCode) && (Counter > 0); //don't check previous code if counter is zero; but calculate it anyhow (to keep timing)
        var isValid = isCurrValid || isPrevValid;
        return isValid;
    }

    #endregion Validate

}
