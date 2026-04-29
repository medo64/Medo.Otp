using System;
using Medo;

var secret = "base32secret";

using var totp = new TimeBasedOtp(secret);
var code = totp.GetCode();
Console.WriteLine($"Code: {code}");
