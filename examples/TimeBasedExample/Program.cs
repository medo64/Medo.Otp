using System;
using Medo;

var secret = "jbsw y3dp ehpk 3pxpjbsw y3dp ehpk 3pxp";

var totp = new TimeBasedOtp(secret);
var code = totp.GetCode();
Console.WriteLine($"Code: {code}");
