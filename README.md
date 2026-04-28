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

Time-based:
~~~sh
using var totp = new TimeBasedOtp();
var code = totp.GetCode();
~~~

Counter-based:
~~~sh
using var hotp = new CounterBasedOtp();
hotp.Counter = 123;
var code = hotp.GetCode();
~~~
