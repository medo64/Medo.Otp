using System;
using Medo;

var secret = "base32secret";

using var hotp = new CounterBasedOtp(secret) {
    Counter = 123,
};
while (true) {
    var counter = hotp.Counter;
    var code = hotp.GetCode();
    Console.WriteLine();
    Console.WriteLine($"Code: {code} ({counter})");

    Console.WriteLine("Press any key for the next code...");
    var key = Console.ReadKey(true);
    if (key.Key == ConsoleKey.Escape) { break; }
    hotp.Counter++;
}
