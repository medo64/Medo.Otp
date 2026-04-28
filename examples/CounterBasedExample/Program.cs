using System;
using Medo;

var secret = "jbsw y3dp ehpk 3pxpjbsw y3dp ehpk 3pxp";

var hotp = new CounterBasedOtp(secret);
while (true) {
    var counter = hotp.Counter;
    var code = hotp.GetCode();
    Console.WriteLine();
    Console.WriteLine($"Code: {code} ({counter})");

    Console.WriteLine("Press any key for the next code...");
    var key = Console.ReadKey(true);
    if (key.Key == ConsoleKey.Escape) { break; }
}
