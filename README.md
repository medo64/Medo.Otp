# Medo.Otp

Simple implementation of second factor one-time password algorithms as
per HOTP (RFC 4226) and TOTP (RFC 6238). These OTP codes are most known
for their 6-digit variant used in two-factor setups.


## Features

* Counter-based one-time passwords
* Time-based one-time passwords
* Configurable time-step
* Configurable number of digits


## Example

### Time-based

~~~sh
// setup
var secret = "base32secret";
using var totp = new TimeBasedOtp();

// creation
var code = totp.GetCode();

// validation
if (totp.IsCodeValid(code) {
    // TODO
}
~~~

### Counter-based

~~~sh
var secret = "base32secret";
using var hotp = new CounterBasedOtp(secret) {
    Counter = 0,
};

// creation
var code = hotp.GetCode();

// validation
if (hotp.IsCodeValid(code) {
    // TODO
}
~~~
