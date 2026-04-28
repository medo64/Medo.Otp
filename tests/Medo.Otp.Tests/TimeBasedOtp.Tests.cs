namespace Tests;

using System;
using System.IO;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Medo;
using System.Text;

[TestClass]
public class TimeBasedOtp_Tests {

    #region TOTP/6

    [TestMethod]
    public void TimeBaedOtp_Generate6_SHA1() {
        var o = new TimeBasedOtp(ASCIIEncoding.ASCII.GetBytes("12345678901234567890")) {
            Digits = 6
        };

        Assert.AreEqual(287082, o.GetCode(new DateTimeOffset(1970, 01, 01, 01, 00, 59, TimeSpan.FromHours(1))));
        Assert.AreEqual(081804, o.GetCode(new DateTimeOffset(2005, 03, 18, 02, 58, 29, TimeSpan.FromHours(1))));
        Assert.AreEqual(050471, o.GetCode(new DateTimeOffset(2005, 03, 18, 02, 58, 31, TimeSpan.FromHours(1))));
        Assert.AreEqual(005924, o.GetCode(new DateTimeOffset(2009, 02, 14, 00, 31, 30, TimeSpan.FromHours(1))));
        Assert.AreEqual(279037, o.GetCode(new DateTimeOffset(2033, 05, 18, 04, 33, 20, TimeSpan.FromHours(1))));
        Assert.AreEqual(353130, o.GetCode(new DateTimeOffset(2603, 10, 11, 12, 33, 20, TimeSpan.FromHours(1))));

        Assert.AreEqual(287082, o.GetCode(new DateTime(1970, 01, 01, 00, 00, 59, DateTimeKind.Utc)));
        Assert.AreEqual(081804, o.GetCode(new DateTime(2005, 03, 18, 01, 58, 29, DateTimeKind.Utc)));
        Assert.AreEqual(050471, o.GetCode(new DateTime(2005, 03, 18, 01, 58, 31, DateTimeKind.Utc)));
        Assert.AreEqual(005924, o.GetCode(new DateTime(2009, 02, 13, 23, 31, 30, DateTimeKind.Utc)));
        Assert.AreEqual(279037, o.GetCode(new DateTime(2033, 05, 18, 03, 33, 20, DateTimeKind.Utc)));
        Assert.AreEqual(353130, o.GetCode(new DateTime(2603, 10, 11, 11, 33, 20, DateTimeKind.Utc)));

        Assert.AreEqual(287082, o.GetCode(new DateTime(1970, 01, 01, 00, 00, 59, DateTimeKind.Utc).ToLocalTime()));
        Assert.AreEqual(081804, o.GetCode(new DateTime(2005, 03, 18, 01, 58, 29, DateTimeKind.Utc).ToLocalTime()));
        Assert.AreEqual(050471, o.GetCode(new DateTime(2005, 03, 18, 01, 58, 31, DateTimeKind.Utc).ToLocalTime()));
        Assert.AreEqual(005924, o.GetCode(new DateTime(2009, 02, 13, 23, 31, 30, DateTimeKind.Utc).ToLocalTime()));
        Assert.AreEqual(279037, o.GetCode(new DateTime(2033, 05, 18, 03, 33, 20, DateTimeKind.Utc).ToLocalTime()));
        Assert.AreEqual(353130, o.GetCode(new DateTime(2603, 10, 11, 11, 33, 20, DateTimeKind.Utc).ToLocalTime()));

        Assert.AreEqual(o.GetCode(), o.GetCode(DateTime.UtcNow));
        Assert.AreEqual(o.GetCode(), o.GetCode(DateTime.Now));
    }

    [TestMethod]
    public void TimeBaedOtp_Validate6_SHA1() {
        var o = new TimeBasedOtp(ASCIIEncoding.ASCII.GetBytes("12345678901234567890")) {
            Digits = 6
        };

        Assert.IsTrue(o.IsCodeValid(287082, new DateTimeOffset(1970, 01, 01, 01, 00, 59, TimeSpan.FromHours(1))));
        Assert.IsTrue(o.IsCodeValid(081804, new DateTimeOffset(2005, 03, 18, 02, 58, 29, TimeSpan.FromHours(1))));
        Assert.IsTrue(o.IsCodeValid(050471, new DateTimeOffset(2005, 03, 18, 02, 58, 31, TimeSpan.FromHours(1))));
        Assert.IsTrue(o.IsCodeValid(005924, new DateTimeOffset(2009, 02, 14, 00, 31, 30, TimeSpan.FromHours(1))));
        Assert.IsTrue(o.IsCodeValid(279037, new DateTimeOffset(2033, 05, 18, 04, 33, 20, TimeSpan.FromHours(1))));
        Assert.IsTrue(o.IsCodeValid(353130, new DateTimeOffset(2603, 10, 11, 12, 33, 20, TimeSpan.FromHours(1))));

        Assert.IsTrue(o.IsCodeValid(287082, new DateTime(1970, 01, 01, 00, 00, 59, DateTimeKind.Utc)));
        Assert.IsTrue(o.IsCodeValid(081804, new DateTime(2005, 03, 18, 01, 58, 29, DateTimeKind.Utc)));
        Assert.IsTrue(o.IsCodeValid(050471, new DateTime(2005, 03, 18, 01, 58, 31, DateTimeKind.Utc)));
        Assert.IsTrue(o.IsCodeValid(005924, new DateTime(2009, 02, 13, 23, 31, 30, DateTimeKind.Utc)));
        Assert.IsTrue(o.IsCodeValid(279037, new DateTime(2033, 05, 18, 03, 33, 20, DateTimeKind.Utc)));
        Assert.IsTrue(o.IsCodeValid(353130, new DateTime(2603, 10, 11, 11, 33, 20, DateTimeKind.Utc)));

        Assert.IsTrue(o.IsCodeValid(287082, new DateTime(1970, 01, 01, 00, 00, 59, DateTimeKind.Utc).ToLocalTime()));
        Assert.IsTrue(o.IsCodeValid(081804, new DateTime(2005, 03, 18, 01, 58, 29, DateTimeKind.Utc).ToLocalTime()));
        Assert.IsTrue(o.IsCodeValid(050471, new DateTime(2005, 03, 18, 01, 58, 31, DateTimeKind.Utc).ToLocalTime()));
        Assert.IsTrue(o.IsCodeValid(005924, new DateTime(2009, 02, 13, 23, 31, 30, DateTimeKind.Utc).ToLocalTime()));
        Assert.IsTrue(o.IsCodeValid(279037, new DateTime(2033, 05, 18, 03, 33, 20, DateTimeKind.Utc).ToLocalTime()));
        Assert.IsTrue(o.IsCodeValid(353130, new DateTime(2603, 10, 11, 11, 33, 20, DateTimeKind.Utc).ToLocalTime()));
    }


    [TestMethod]
    public void TimeBaedOtp_Generate6_SHA256() {
        var o = new TimeBasedOtp(ASCIIEncoding.ASCII.GetBytes("12345678901234567890123456789012")) {
            Algorithm = OneTimePasswordAlgorithm.Sha256,
            Digits = 6
        };

        Assert.AreEqual(119246, o.GetCode(new DateTimeOffset(1970, 01, 01, 01, 00, 59, TimeSpan.FromHours(1))));
        Assert.AreEqual(084774, o.GetCode(new DateTimeOffset(2005, 03, 18, 02, 58, 29, TimeSpan.FromHours(1))));
        Assert.AreEqual(062674, o.GetCode(new DateTimeOffset(2005, 03, 18, 02, 58, 31, TimeSpan.FromHours(1))));
        Assert.AreEqual(819424, o.GetCode(new DateTimeOffset(2009, 02, 14, 00, 31, 30, TimeSpan.FromHours(1))));
        Assert.AreEqual(698825, o.GetCode(new DateTimeOffset(2033, 05, 18, 04, 33, 20, TimeSpan.FromHours(1))));
        Assert.AreEqual(737706, o.GetCode(new DateTimeOffset(2603, 10, 11, 12, 33, 20, TimeSpan.FromHours(1))));

        Assert.AreEqual(119246, o.GetCode(new DateTime(1970, 01, 01, 00, 00, 59, DateTimeKind.Utc)));
        Assert.AreEqual(084774, o.GetCode(new DateTime(2005, 03, 18, 01, 58, 29, DateTimeKind.Utc)));
        Assert.AreEqual(062674, o.GetCode(new DateTime(2005, 03, 18, 01, 58, 31, DateTimeKind.Utc)));
        Assert.AreEqual(819424, o.GetCode(new DateTime(2009, 02, 13, 23, 31, 30, DateTimeKind.Utc)));
        Assert.AreEqual(698825, o.GetCode(new DateTime(2033, 05, 18, 03, 33, 20, DateTimeKind.Utc)));
        Assert.AreEqual(737706, o.GetCode(new DateTime(2603, 10, 11, 11, 33, 20, DateTimeKind.Utc)));

        Assert.AreEqual(119246, o.GetCode(new DateTime(1970, 01, 01, 00, 00, 59, DateTimeKind.Utc).ToLocalTime()));
        Assert.AreEqual(084774, o.GetCode(new DateTime(2005, 03, 18, 01, 58, 29, DateTimeKind.Utc).ToLocalTime()));
        Assert.AreEqual(062674, o.GetCode(new DateTime(2005, 03, 18, 01, 58, 31, DateTimeKind.Utc).ToLocalTime()));
        Assert.AreEqual(819424, o.GetCode(new DateTime(2009, 02, 13, 23, 31, 30, DateTimeKind.Utc).ToLocalTime()));
        Assert.AreEqual(698825, o.GetCode(new DateTime(2033, 05, 18, 03, 33, 20, DateTimeKind.Utc).ToLocalTime()));
        Assert.AreEqual(737706, o.GetCode(new DateTime(2603, 10, 11, 11, 33, 20, DateTimeKind.Utc).ToLocalTime()));

        Assert.AreEqual(o.GetCode(), o.GetCode(DateTime.UtcNow));
        Assert.AreEqual(o.GetCode(), o.GetCode(DateTime.Now));
    }

    [TestMethod]
    public void TimeBaedOtp_Validate6_SHA256() {
        var o = new TimeBasedOtp(ASCIIEncoding.ASCII.GetBytes("12345678901234567890123456789012")) {
            Algorithm = OneTimePasswordAlgorithm.Sha256,
            Digits = 6
        };

        Assert.IsTrue(o.IsCodeValid(119246, new DateTimeOffset(1970, 01, 01, 01, 00, 59, TimeSpan.FromHours(1))));
        Assert.IsTrue(o.IsCodeValid(084774, new DateTimeOffset(2005, 03, 18, 02, 58, 29, TimeSpan.FromHours(1))));
        Assert.IsTrue(o.IsCodeValid(062674, new DateTimeOffset(2005, 03, 18, 02, 58, 31, TimeSpan.FromHours(1))));
        Assert.IsTrue(o.IsCodeValid(819424, new DateTimeOffset(2009, 02, 14, 00, 31, 30, TimeSpan.FromHours(1))));
        Assert.IsTrue(o.IsCodeValid(698825, new DateTimeOffset(2033, 05, 18, 04, 33, 20, TimeSpan.FromHours(1))));
        Assert.IsTrue(o.IsCodeValid(737706, new DateTimeOffset(2603, 10, 11, 12, 33, 20, TimeSpan.FromHours(1))));

        Assert.IsTrue(o.IsCodeValid(119246, new DateTime(1970, 01, 01, 00, 00, 59, DateTimeKind.Utc)));
        Assert.IsTrue(o.IsCodeValid(084774, new DateTime(2005, 03, 18, 01, 58, 29, DateTimeKind.Utc)));
        Assert.IsTrue(o.IsCodeValid(062674, new DateTime(2005, 03, 18, 01, 58, 31, DateTimeKind.Utc)));
        Assert.IsTrue(o.IsCodeValid(819424, new DateTime(2009, 02, 13, 23, 31, 30, DateTimeKind.Utc)));
        Assert.IsTrue(o.IsCodeValid(698825, new DateTime(2033, 05, 18, 03, 33, 20, DateTimeKind.Utc)));
        Assert.IsTrue(o.IsCodeValid(737706, new DateTime(2603, 10, 11, 11, 33, 20, DateTimeKind.Utc)));

        Assert.IsTrue(o.IsCodeValid(119246, new DateTime(1970, 01, 01, 00, 00, 59, DateTimeKind.Utc).ToLocalTime()));
        Assert.IsTrue(o.IsCodeValid(084774, new DateTime(2005, 03, 18, 01, 58, 29, DateTimeKind.Utc).ToLocalTime()));
        Assert.IsTrue(o.IsCodeValid(062674, new DateTime(2005, 03, 18, 01, 58, 31, DateTimeKind.Utc).ToLocalTime()));
        Assert.IsTrue(o.IsCodeValid(819424, new DateTime(2009, 02, 13, 23, 31, 30, DateTimeKind.Utc).ToLocalTime()));
        Assert.IsTrue(o.IsCodeValid(698825, new DateTime(2033, 05, 18, 03, 33, 20, DateTimeKind.Utc).ToLocalTime()));
        Assert.IsTrue(o.IsCodeValid(737706, new DateTime(2603, 10, 11, 11, 33, 20, DateTimeKind.Utc).ToLocalTime()));
    }


    [TestMethod]
    public void TimeBaedOtp_Generate6_SHA512() {
        var o = new TimeBasedOtp(ASCIIEncoding.ASCII.GetBytes("1234567890123456789012345678901234567890123456789012345678901234")) {
            Algorithm = OneTimePasswordAlgorithm.Sha512,
            Digits = 6
        };

        Assert.AreEqual(693936, o.GetCode(new DateTimeOffset(1970, 01, 01, 01, 00, 59, TimeSpan.FromHours(1))));
        Assert.AreEqual(091201, o.GetCode(new DateTimeOffset(2005, 03, 18, 02, 58, 29, TimeSpan.FromHours(1))));
        Assert.AreEqual(943326, o.GetCode(new DateTimeOffset(2005, 03, 18, 02, 58, 31, TimeSpan.FromHours(1))));
        Assert.AreEqual(441116, o.GetCode(new DateTimeOffset(2009, 02, 14, 00, 31, 30, TimeSpan.FromHours(1))));
        Assert.AreEqual(618901, o.GetCode(new DateTimeOffset(2033, 05, 18, 04, 33, 20, TimeSpan.FromHours(1))));
        Assert.AreEqual(863826, o.GetCode(new DateTimeOffset(2603, 10, 11, 12, 33, 20, TimeSpan.FromHours(1))));

        Assert.AreEqual(693936, o.GetCode(new DateTime(1970, 01, 01, 00, 00, 59, DateTimeKind.Utc)));
        Assert.AreEqual(091201, o.GetCode(new DateTime(2005, 03, 18, 01, 58, 29, DateTimeKind.Utc)));
        Assert.AreEqual(943326, o.GetCode(new DateTime(2005, 03, 18, 01, 58, 31, DateTimeKind.Utc)));
        Assert.AreEqual(441116, o.GetCode(new DateTime(2009, 02, 13, 23, 31, 30, DateTimeKind.Utc)));
        Assert.AreEqual(618901, o.GetCode(new DateTime(2033, 05, 18, 03, 33, 20, DateTimeKind.Utc)));
        Assert.AreEqual(863826, o.GetCode(new DateTime(2603, 10, 11, 11, 33, 20, DateTimeKind.Utc)));

        Assert.AreEqual(693936, o.GetCode(new DateTime(1970, 01, 01, 00, 00, 59, DateTimeKind.Utc).ToLocalTime()));
        Assert.AreEqual(091201, o.GetCode(new DateTime(2005, 03, 18, 01, 58, 29, DateTimeKind.Utc).ToLocalTime()));
        Assert.AreEqual(943326, o.GetCode(new DateTime(2005, 03, 18, 01, 58, 31, DateTimeKind.Utc).ToLocalTime()));
        Assert.AreEqual(441116, o.GetCode(new DateTime(2009, 02, 13, 23, 31, 30, DateTimeKind.Utc).ToLocalTime()));
        Assert.AreEqual(618901, o.GetCode(new DateTime(2033, 05, 18, 03, 33, 20, DateTimeKind.Utc).ToLocalTime()));
        Assert.AreEqual(863826, o.GetCode(new DateTime(2603, 10, 11, 11, 33, 20, DateTimeKind.Utc).ToLocalTime()));

        Assert.AreEqual(o.GetCode(), o.GetCode(DateTime.UtcNow));
        Assert.AreEqual(o.GetCode(), o.GetCode(DateTime.Now));
    }

    [TestMethod]
    public void TimeBaedOtp_Validate6_SHA512() {
        var o = new TimeBasedOtp(ASCIIEncoding.ASCII.GetBytes("1234567890123456789012345678901234567890123456789012345678901234")) {
            Algorithm = OneTimePasswordAlgorithm.Sha512,
            Digits = 6
        };

        Assert.IsTrue(o.IsCodeValid(693936, new DateTimeOffset(1970, 01, 01, 01, 00, 59, TimeSpan.FromHours(1))));
        Assert.IsTrue(o.IsCodeValid(091201, new DateTimeOffset(2005, 03, 18, 02, 58, 29, TimeSpan.FromHours(1))));
        Assert.IsTrue(o.IsCodeValid(943326, new DateTimeOffset(2005, 03, 18, 02, 58, 31, TimeSpan.FromHours(1))));
        Assert.IsTrue(o.IsCodeValid(441116, new DateTimeOffset(2009, 02, 14, 00, 31, 30, TimeSpan.FromHours(1))));
        Assert.IsTrue(o.IsCodeValid(618901, new DateTimeOffset(2033, 05, 18, 04, 33, 20, TimeSpan.FromHours(1))));
        Assert.IsTrue(o.IsCodeValid(863826, new DateTimeOffset(2603, 10, 11, 12, 33, 20, TimeSpan.FromHours(1))));

        Assert.IsTrue(o.IsCodeValid(693936, new DateTime(1970, 01, 01, 00, 00, 59, DateTimeKind.Utc)));
        Assert.IsTrue(o.IsCodeValid(091201, new DateTime(2005, 03, 18, 01, 58, 29, DateTimeKind.Utc)));
        Assert.IsTrue(o.IsCodeValid(943326, new DateTime(2005, 03, 18, 01, 58, 31, DateTimeKind.Utc)));
        Assert.IsTrue(o.IsCodeValid(441116, new DateTime(2009, 02, 13, 23, 31, 30, DateTimeKind.Utc)));
        Assert.IsTrue(o.IsCodeValid(618901, new DateTime(2033, 05, 18, 03, 33, 20, DateTimeKind.Utc)));
        Assert.IsTrue(o.IsCodeValid(863826, new DateTime(2603, 10, 11, 11, 33, 20, DateTimeKind.Utc)));

        Assert.IsTrue(o.IsCodeValid(693936, new DateTime(1970, 01, 01, 00, 00, 59, DateTimeKind.Utc).ToLocalTime()));
        Assert.IsTrue(o.IsCodeValid(091201, new DateTime(2005, 03, 18, 01, 58, 29, DateTimeKind.Utc).ToLocalTime()));
        Assert.IsTrue(o.IsCodeValid(943326, new DateTime(2005, 03, 18, 01, 58, 31, DateTimeKind.Utc).ToLocalTime()));
        Assert.IsTrue(o.IsCodeValid(441116, new DateTime(2009, 02, 13, 23, 31, 30, DateTimeKind.Utc).ToLocalTime()));
        Assert.IsTrue(o.IsCodeValid(618901, new DateTime(2033, 05, 18, 03, 33, 20, DateTimeKind.Utc).ToLocalTime()));
        Assert.IsTrue(o.IsCodeValid(863826, new DateTime(2603, 10, 11, 11, 33, 20, DateTimeKind.Utc).ToLocalTime()));
    }

    #endregion


    #region TOTP/8

    [TestMethod]
    public void TimeBaedOtp_Generate_SHA1() {
        var o = new TimeBasedOtp(ASCIIEncoding.ASCII.GetBytes("12345678901234567890")) {
            Digits = 8
        };

        Assert.AreEqual(94287082, o.GetCode(new DateTimeOffset(1970, 01, 01, 01, 00, 59, TimeSpan.FromHours(1))));
        Assert.AreEqual(07081804, o.GetCode(new DateTimeOffset(2005, 03, 18, 02, 58, 29, TimeSpan.FromHours(1))));
        Assert.AreEqual(14050471, o.GetCode(new DateTimeOffset(2005, 03, 18, 02, 58, 31, TimeSpan.FromHours(1))));
        Assert.AreEqual(89005924, o.GetCode(new DateTimeOffset(2009, 02, 14, 00, 31, 30, TimeSpan.FromHours(1))));
        Assert.AreEqual(69279037, o.GetCode(new DateTimeOffset(2033, 05, 18, 04, 33, 20, TimeSpan.FromHours(1))));
        Assert.AreEqual(65353130, o.GetCode(new DateTimeOffset(2603, 10, 11, 12, 33, 20, TimeSpan.FromHours(1))));

        Assert.AreEqual(94287082, o.GetCode(new DateTime(1970, 01, 01, 00, 00, 59, DateTimeKind.Utc)));
        Assert.AreEqual(07081804, o.GetCode(new DateTime(2005, 03, 18, 01, 58, 29, DateTimeKind.Utc)));
        Assert.AreEqual(14050471, o.GetCode(new DateTime(2005, 03, 18, 01, 58, 31, DateTimeKind.Utc)));
        Assert.AreEqual(89005924, o.GetCode(new DateTime(2009, 02, 13, 23, 31, 30, DateTimeKind.Utc)));
        Assert.AreEqual(69279037, o.GetCode(new DateTime(2033, 05, 18, 03, 33, 20, DateTimeKind.Utc)));
        Assert.AreEqual(65353130, o.GetCode(new DateTime(2603, 10, 11, 11, 33, 20, DateTimeKind.Utc)));

        Assert.AreEqual(94287082, o.GetCode(new DateTime(1970, 01, 01, 00, 00, 59, DateTimeKind.Utc).ToLocalTime()));
        Assert.AreEqual(07081804, o.GetCode(new DateTime(2005, 03, 18, 01, 58, 29, DateTimeKind.Utc).ToLocalTime()));
        Assert.AreEqual(14050471, o.GetCode(new DateTime(2005, 03, 18, 01, 58, 31, DateTimeKind.Utc).ToLocalTime()));
        Assert.AreEqual(89005924, o.GetCode(new DateTime(2009, 02, 13, 23, 31, 30, DateTimeKind.Utc).ToLocalTime()));
        Assert.AreEqual(69279037, o.GetCode(new DateTime(2033, 05, 18, 03, 33, 20, DateTimeKind.Utc).ToLocalTime()));
        Assert.AreEqual(65353130, o.GetCode(new DateTime(2603, 10, 11, 11, 33, 20, DateTimeKind.Utc).ToLocalTime()));

        Assert.AreEqual(o.GetCode(), o.GetCode(DateTime.UtcNow));
        Assert.AreEqual(o.GetCode(), o.GetCode(DateTime.Now));
    }

    [TestMethod]
    public void TimeBaedOtp_Validate_SHA1() {
        var o = new TimeBasedOtp(ASCIIEncoding.ASCII.GetBytes("12345678901234567890")) {
            Digits = 8
        };

        Assert.IsTrue(o.IsCodeValid(94287082, new DateTimeOffset(1970, 01, 01, 01, 00, 59, TimeSpan.FromHours(1))));
        Assert.IsTrue(o.IsCodeValid(07081804, new DateTimeOffset(2005, 03, 18, 02, 58, 29, TimeSpan.FromHours(1))));
        Assert.IsTrue(o.IsCodeValid(14050471, new DateTimeOffset(2005, 03, 18, 02, 58, 31, TimeSpan.FromHours(1))));
        Assert.IsTrue(o.IsCodeValid(89005924, new DateTimeOffset(2009, 02, 14, 00, 31, 30, TimeSpan.FromHours(1))));
        Assert.IsTrue(o.IsCodeValid(69279037, new DateTimeOffset(2033, 05, 18, 04, 33, 20, TimeSpan.FromHours(1))));
        Assert.IsTrue(o.IsCodeValid(65353130, new DateTimeOffset(2603, 10, 11, 12, 33, 20, TimeSpan.FromHours(1))));

        Assert.IsTrue(o.IsCodeValid(94287082, new DateTime(1970, 01, 01, 00, 00, 59, DateTimeKind.Utc)));
        Assert.IsTrue(o.IsCodeValid(07081804, new DateTime(2005, 03, 18, 01, 58, 29, DateTimeKind.Utc)));
        Assert.IsTrue(o.IsCodeValid(14050471, new DateTime(2005, 03, 18, 01, 58, 31, DateTimeKind.Utc)));
        Assert.IsTrue(o.IsCodeValid(89005924, new DateTime(2009, 02, 13, 23, 31, 30, DateTimeKind.Utc)));
        Assert.IsTrue(o.IsCodeValid(69279037, new DateTime(2033, 05, 18, 03, 33, 20, DateTimeKind.Utc)));
        Assert.IsTrue(o.IsCodeValid(65353130, new DateTime(2603, 10, 11, 11, 33, 20, DateTimeKind.Utc)));

        Assert.IsTrue(o.IsCodeValid(94287082, new DateTime(1970, 01, 01, 00, 00, 59, DateTimeKind.Utc).ToLocalTime()));
        Assert.IsTrue(o.IsCodeValid(07081804, new DateTime(2005, 03, 18, 01, 58, 29, DateTimeKind.Utc).ToLocalTime()));
        Assert.IsTrue(o.IsCodeValid(14050471, new DateTime(2005, 03, 18, 01, 58, 31, DateTimeKind.Utc).ToLocalTime()));
        Assert.IsTrue(o.IsCodeValid(89005924, new DateTime(2009, 02, 13, 23, 31, 30, DateTimeKind.Utc).ToLocalTime()));
        Assert.IsTrue(o.IsCodeValid(69279037, new DateTime(2033, 05, 18, 03, 33, 20, DateTimeKind.Utc).ToLocalTime()));
        Assert.IsTrue(o.IsCodeValid(65353130, new DateTime(2603, 10, 11, 11, 33, 20, DateTimeKind.Utc).ToLocalTime()));
    }


    [TestMethod]
    public void TimeBaedOtp_Generate_SHA256() {
        var o = new TimeBasedOtp(ASCIIEncoding.ASCII.GetBytes("12345678901234567890123456789012")) {
            Algorithm = OneTimePasswordAlgorithm.Sha256,
            Digits = 8
        };

        Assert.AreEqual(46119246, o.GetCode(new DateTimeOffset(1970, 01, 01, 01, 00, 59, TimeSpan.FromHours(1))));
        Assert.AreEqual(68084774, o.GetCode(new DateTimeOffset(2005, 03, 18, 02, 58, 29, TimeSpan.FromHours(1))));
        Assert.AreEqual(67062674, o.GetCode(new DateTimeOffset(2005, 03, 18, 02, 58, 31, TimeSpan.FromHours(1))));
        Assert.AreEqual(91819424, o.GetCode(new DateTimeOffset(2009, 02, 14, 00, 31, 30, TimeSpan.FromHours(1))));
        Assert.AreEqual(90698825, o.GetCode(new DateTimeOffset(2033, 05, 18, 04, 33, 20, TimeSpan.FromHours(1))));
        Assert.AreEqual(77737706, o.GetCode(new DateTimeOffset(2603, 10, 11, 12, 33, 20, TimeSpan.FromHours(1))));

        Assert.AreEqual(46119246, o.GetCode(new DateTime(1970, 01, 01, 00, 00, 59, DateTimeKind.Utc)));
        Assert.AreEqual(68084774, o.GetCode(new DateTime(2005, 03, 18, 01, 58, 29, DateTimeKind.Utc)));
        Assert.AreEqual(67062674, o.GetCode(new DateTime(2005, 03, 18, 01, 58, 31, DateTimeKind.Utc)));
        Assert.AreEqual(91819424, o.GetCode(new DateTime(2009, 02, 13, 23, 31, 30, DateTimeKind.Utc)));
        Assert.AreEqual(90698825, o.GetCode(new DateTime(2033, 05, 18, 03, 33, 20, DateTimeKind.Utc)));
        Assert.AreEqual(77737706, o.GetCode(new DateTime(2603, 10, 11, 11, 33, 20, DateTimeKind.Utc)));

        Assert.AreEqual(46119246, o.GetCode(new DateTime(1970, 01, 01, 00, 00, 59, DateTimeKind.Utc).ToLocalTime()));
        Assert.AreEqual(68084774, o.GetCode(new DateTime(2005, 03, 18, 01, 58, 29, DateTimeKind.Utc).ToLocalTime()));
        Assert.AreEqual(67062674, o.GetCode(new DateTime(2005, 03, 18, 01, 58, 31, DateTimeKind.Utc).ToLocalTime()));
        Assert.AreEqual(91819424, o.GetCode(new DateTime(2009, 02, 13, 23, 31, 30, DateTimeKind.Utc).ToLocalTime()));
        Assert.AreEqual(90698825, o.GetCode(new DateTime(2033, 05, 18, 03, 33, 20, DateTimeKind.Utc).ToLocalTime()));
        Assert.AreEqual(77737706, o.GetCode(new DateTime(2603, 10, 11, 11, 33, 20, DateTimeKind.Utc).ToLocalTime()));

        Assert.AreEqual(o.GetCode(), o.GetCode(DateTime.UtcNow));
        Assert.AreEqual(o.GetCode(), o.GetCode(DateTime.Now));
    }

    [TestMethod]
    public void TimeBaedOtp_Validate_SHA256() {
        var o = new TimeBasedOtp(ASCIIEncoding.ASCII.GetBytes("12345678901234567890123456789012")) {
            Algorithm = OneTimePasswordAlgorithm.Sha256,
            Digits = 8
        };

        Assert.IsTrue(o.IsCodeValid(46119246, new DateTimeOffset(1970, 01, 01, 01, 00, 59, TimeSpan.FromHours(1))));
        Assert.IsTrue(o.IsCodeValid(68084774, new DateTimeOffset(2005, 03, 18, 02, 58, 29, TimeSpan.FromHours(1))));
        Assert.IsTrue(o.IsCodeValid(67062674, new DateTimeOffset(2005, 03, 18, 02, 58, 31, TimeSpan.FromHours(1))));
        Assert.IsTrue(o.IsCodeValid(91819424, new DateTimeOffset(2009, 02, 14, 00, 31, 30, TimeSpan.FromHours(1))));
        Assert.IsTrue(o.IsCodeValid(90698825, new DateTimeOffset(2033, 05, 18, 04, 33, 20, TimeSpan.FromHours(1))));
        Assert.IsTrue(o.IsCodeValid(77737706, new DateTimeOffset(2603, 10, 11, 12, 33, 20, TimeSpan.FromHours(1))));

        Assert.IsTrue(o.IsCodeValid(46119246, new DateTime(1970, 01, 01, 00, 00, 59, DateTimeKind.Utc)));
        Assert.IsTrue(o.IsCodeValid(68084774, new DateTime(2005, 03, 18, 01, 58, 29, DateTimeKind.Utc)));
        Assert.IsTrue(o.IsCodeValid(67062674, new DateTime(2005, 03, 18, 01, 58, 31, DateTimeKind.Utc)));
        Assert.IsTrue(o.IsCodeValid(91819424, new DateTime(2009, 02, 13, 23, 31, 30, DateTimeKind.Utc)));
        Assert.IsTrue(o.IsCodeValid(90698825, new DateTime(2033, 05, 18, 03, 33, 20, DateTimeKind.Utc)));
        Assert.IsTrue(o.IsCodeValid(77737706, new DateTime(2603, 10, 11, 11, 33, 20, DateTimeKind.Utc)));

        Assert.IsTrue(o.IsCodeValid(46119246, new DateTime(1970, 01, 01, 00, 00, 59, DateTimeKind.Utc).ToLocalTime()));
        Assert.IsTrue(o.IsCodeValid(68084774, new DateTime(2005, 03, 18, 01, 58, 29, DateTimeKind.Utc).ToLocalTime()));
        Assert.IsTrue(o.IsCodeValid(67062674, new DateTime(2005, 03, 18, 01, 58, 31, DateTimeKind.Utc).ToLocalTime()));
        Assert.IsTrue(o.IsCodeValid(91819424, new DateTime(2009, 02, 13, 23, 31, 30, DateTimeKind.Utc).ToLocalTime()));
        Assert.IsTrue(o.IsCodeValid(90698825, new DateTime(2033, 05, 18, 03, 33, 20, DateTimeKind.Utc).ToLocalTime()));
        Assert.IsTrue(o.IsCodeValid(77737706, new DateTime(2603, 10, 11, 11, 33, 20, DateTimeKind.Utc).ToLocalTime()));
    }


    [TestMethod]
    public void TimeBaedOtp_Generate_SHA512() {
        var o = new TimeBasedOtp(ASCIIEncoding.ASCII.GetBytes("1234567890123456789012345678901234567890123456789012345678901234")) {
            Algorithm = OneTimePasswordAlgorithm.Sha512,
            Digits = 8
        };

        Assert.AreEqual(90693936, o.GetCode(new DateTimeOffset(1970, 01, 01, 01, 00, 59, TimeSpan.FromHours(1))));
        Assert.AreEqual(25091201, o.GetCode(new DateTimeOffset(2005, 03, 18, 02, 58, 29, TimeSpan.FromHours(1))));
        Assert.AreEqual(99943326, o.GetCode(new DateTimeOffset(2005, 03, 18, 02, 58, 31, TimeSpan.FromHours(1))));
        Assert.AreEqual(93441116, o.GetCode(new DateTimeOffset(2009, 02, 14, 00, 31, 30, TimeSpan.FromHours(1))));
        Assert.AreEqual(38618901, o.GetCode(new DateTimeOffset(2033, 05, 18, 04, 33, 20, TimeSpan.FromHours(1))));
        Assert.AreEqual(47863826, o.GetCode(new DateTimeOffset(2603, 10, 11, 12, 33, 20, TimeSpan.FromHours(1))));

        Assert.AreEqual(90693936, o.GetCode(new DateTime(1970, 01, 01, 00, 00, 59, DateTimeKind.Utc)));
        Assert.AreEqual(25091201, o.GetCode(new DateTime(2005, 03, 18, 01, 58, 29, DateTimeKind.Utc)));
        Assert.AreEqual(99943326, o.GetCode(new DateTime(2005, 03, 18, 01, 58, 31, DateTimeKind.Utc)));
        Assert.AreEqual(93441116, o.GetCode(new DateTime(2009, 02, 13, 23, 31, 30, DateTimeKind.Utc)));
        Assert.AreEqual(38618901, o.GetCode(new DateTime(2033, 05, 18, 03, 33, 20, DateTimeKind.Utc)));
        Assert.AreEqual(47863826, o.GetCode(new DateTime(2603, 10, 11, 11, 33, 20, DateTimeKind.Utc)));

        Assert.AreEqual(90693936, o.GetCode(new DateTime(1970, 01, 01, 00, 00, 59, DateTimeKind.Utc).ToLocalTime()));
        Assert.AreEqual(25091201, o.GetCode(new DateTime(2005, 03, 18, 01, 58, 29, DateTimeKind.Utc).ToLocalTime()));
        Assert.AreEqual(99943326, o.GetCode(new DateTime(2005, 03, 18, 01, 58, 31, DateTimeKind.Utc).ToLocalTime()));
        Assert.AreEqual(93441116, o.GetCode(new DateTime(2009, 02, 13, 23, 31, 30, DateTimeKind.Utc).ToLocalTime()));
        Assert.AreEqual(38618901, o.GetCode(new DateTime(2033, 05, 18, 03, 33, 20, DateTimeKind.Utc).ToLocalTime()));
        Assert.AreEqual(47863826, o.GetCode(new DateTime(2603, 10, 11, 11, 33, 20, DateTimeKind.Utc).ToLocalTime()));

        Assert.AreEqual(o.GetCode(), o.GetCode(DateTime.UtcNow));
        Assert.AreEqual(o.GetCode(), o.GetCode(DateTime.Now));
    }

    [TestMethod]
    public void TimeBaedOtp_Validate_SHA512() {
        var o = new TimeBasedOtp(ASCIIEncoding.ASCII.GetBytes("1234567890123456789012345678901234567890123456789012345678901234")) {
            Algorithm = OneTimePasswordAlgorithm.Sha512,
            Digits = 8
        };

        Assert.IsTrue(o.IsCodeValid(90693936, new DateTimeOffset(1970, 01, 01, 01, 00, 59, TimeSpan.FromHours(1))));
        Assert.IsTrue(o.IsCodeValid(25091201, new DateTimeOffset(2005, 03, 18, 02, 58, 29, TimeSpan.FromHours(1))));
        Assert.IsTrue(o.IsCodeValid(99943326, new DateTimeOffset(2005, 03, 18, 02, 58, 31, TimeSpan.FromHours(1))));
        Assert.IsTrue(o.IsCodeValid(93441116, new DateTimeOffset(2009, 02, 14, 00, 31, 30, TimeSpan.FromHours(1))));
        Assert.IsTrue(o.IsCodeValid(38618901, new DateTimeOffset(2033, 05, 18, 04, 33, 20, TimeSpan.FromHours(1))));
        Assert.IsTrue(o.IsCodeValid(47863826, new DateTimeOffset(2603, 10, 11, 12, 33, 20, TimeSpan.FromHours(1))));

        Assert.IsTrue(o.IsCodeValid(90693936, new DateTime(1970, 01, 01, 00, 00, 59, DateTimeKind.Utc)));
        Assert.IsTrue(o.IsCodeValid(25091201, new DateTime(2005, 03, 18, 01, 58, 29, DateTimeKind.Utc)));
        Assert.IsTrue(o.IsCodeValid(99943326, new DateTime(2005, 03, 18, 01, 58, 31, DateTimeKind.Utc)));
        Assert.IsTrue(o.IsCodeValid(93441116, new DateTime(2009, 02, 13, 23, 31, 30, DateTimeKind.Utc)));
        Assert.IsTrue(o.IsCodeValid(38618901, new DateTime(2033, 05, 18, 03, 33, 20, DateTimeKind.Utc)));
        Assert.IsTrue(o.IsCodeValid(47863826, new DateTime(2603, 10, 11, 11, 33, 20, DateTimeKind.Utc)));

        Assert.IsTrue(o.IsCodeValid(90693936, new DateTime(1970, 01, 01, 00, 00, 59, DateTimeKind.Utc).ToLocalTime()));
        Assert.IsTrue(o.IsCodeValid(25091201, new DateTime(2005, 03, 18, 01, 58, 29, DateTimeKind.Utc).ToLocalTime()));
        Assert.IsTrue(o.IsCodeValid(99943326, new DateTime(2005, 03, 18, 01, 58, 31, DateTimeKind.Utc).ToLocalTime()));
        Assert.IsTrue(o.IsCodeValid(93441116, new DateTime(2009, 02, 13, 23, 31, 30, DateTimeKind.Utc).ToLocalTime()));
        Assert.IsTrue(o.IsCodeValid(38618901, new DateTime(2033, 05, 18, 03, 33, 20, DateTimeKind.Utc).ToLocalTime()));
        Assert.IsTrue(o.IsCodeValid(47863826, new DateTime(2603, 10, 11, 11, 33, 20, DateTimeKind.Utc).ToLocalTime()));
    }

    #endregion


    [TestMethod]
    public void Otp_Parameter_Secret_MaxLength() {
        var secret = new byte[1024];
        var otp = new TimeBasedOtp(secret);
        Assert.AreEqual(599555, otp.GetCode(DateTimeOffset.UnixEpoch));
    }

}
